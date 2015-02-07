/*
 * lzms_compress.c
 *
 * A compressor for the LZMS compression format.
 */

/*
 * Copyright (C) 2013, 2014, 2015 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <limits.h>
#include <string.h>

#include "wimlib/compress_common.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lcpit_matchfinder.h"
#include "wimlib/lz_extend.h"
#include "wimlib/lzms_common.h"
#include "wimlib/unaligned.h"
#include "wimlib/util.h"

/*
 * The values defined below are not intrinsic to the LZMS format itself --- they
 * are specific to this compressor implementation.
 */

/*
 * LZMS_MAX_FAST_LENGTH is the maximum match length for which the length slot
 * can be looked up directly in the 'length_slot_fast' array.
 *
 * We also limit the 'nice_match_len' parameter to this value.  Consequently, if
 * the longest match found is shorter than 'nice_match_len', then it must also
 * be shorter than LZMS_MAX_FAST_LENGTH.  This makes it possible to do fast
 * lookups of length costs using the 'length_cost_fast' array without having to
 * keep checking whether the length exceeds LZMS_MAX_FAST_LENGTH or not.
 */
#define LZMS_MAX_FAST_LENGTH	255

/*
 * LZMS_MAX_FAST_OFFSET is the maximum match offset for which the offset slot
 * can be looked up directly in the 'offset_slot_fast' array.
 */
#define LZMS_MAX_FAST_OFFSET	32767

/*
 * LZMS_NUM_OPTIM_NODES is the maximum number of bytes the parsing algorithm
 * will step forward before forcing the pending items to be encoded.  If this
 * value is increased, then there will be fewer forced flushes, but the
 * probability entries and Huffman codes will be more likely to become outdated.
 */
#define LZMS_NUM_OPTIM_NODES	1024

/*
 * LZMS_COST_SHIFT is a scaling factor that makes it possible to consider
 * fractional bit costs.  A single bit has a cost of (1 << LZMS_COST_SHIFT).
 */
#define LZMS_COST_SHIFT		6

/* This structure tracks the state of writing bits as a series of 16-bit coding
 * units, starting at the end of the output buffer and proceeding backwards.  */
struct lzms_output_bitstream {

	/* Bits that haven't yet been written to the output buffer  */
	u64 bitbuf;

	/* Number of bits currently held in @bitbuf  */
	unsigned bitcount;

	/* Pointer to one past the next position in the output buffer at which
	 * to output a 16-bit coding unit  */
	le16 *next;

	/* Pointer to the beginning of the output buffer (this is the "end" when
	 * writing backwards!)  */
	le16 *begin;
};

/* This structure tracks the state of range encoding and its output, which
 * starts at the beginning of the output buffer and proceeds forwards.  */
struct lzms_range_encoder {

	/* The low boundary of the current range.  Logically, this is a 33-bit
	 * integer whose high bit is needed to detect carries.  */
	u64 low;

	/* The size of the current range  */
	u32 range_size;

	/* The next 16-bit coding unit to output  */
	u16 cache;

	/* The number of 16-bit coding units whose output has been delayed due
	 * to possible carrying.  The first such coding unit is @cache; all
	 * subsequent such coding units are 0xffff.  */
	u32 cache_size;

	/* Pointer to the beginning of the output buffer  */
	le16 *begin;

	/* Pointer to the position in the output buffer at which the next coding
	 * unit must be written  */
	le16 *next;

	/* Pointer just past the end of the output buffer  */
	le16 *end;
};

/* An encoder for bits in a specific context  */
struct lzms_bit_encoder {

	/* Pointer to the range encoder to use  */
	struct lzms_range_encoder *rc;

	/* The current state for this bit encoder, which identifies the entry in
	 * @prob_entries to use next.  The state consists of the most recently
	 * encoded bits by this bit encoder, where bit 0 is the most recent, bit
	 * 1 is the second most recent, etc.  */
	unsigned state;

	/* Bitmask for @state to prevent its value from exceeding the number of
	 * probability entries  */
	unsigned mask;

	/* Probability entries for this context  */
	struct lzms_probability_entry prob_entries[LZMS_MAX_NUM_STATES];
};

/* This structure manages Huffman encoding of symbols from an alphabet.  */
struct lzms_huffman_encoder {

	/* Bitstream to which the Huffman encoded symbols are written  */
	struct lzms_output_bitstream *os;

	/* Number of symbols in the alphabet  */
	unsigned num_syms;

	/* Each time this number of symbols have been encoded, the code is
	 * rebuilt.  */
	unsigned rebuild_freq;

	/* Symbol count until the next rebuild  */
	unsigned num_syms_until_rebuild;

	/* Running totals of symbol frequencies.  These are diluted slightly
	 * whenever the code is rebuilt.  */
	u32 freqs[LZMS_MAX_NUM_SYMS];

	/* The length, in bits, of each codeword in the current code  */
	u8 lens[LZMS_MAX_NUM_SYMS];

	/* The codewords in the current code  */
	u32 codewords[LZMS_MAX_NUM_SYMS];
};

/* The LRU queue for offsets of LZ-style matches  */
struct lzms_lz_lru_queue {
	u32 recent_offsets[LZMS_NUM_RECENT_OFFSETS + 1];
	u32 prev_offset;
	u32 upcoming_offset;
};

/*
 * This structure represents a byte position in the input buffer and a node in
 * the graph of possible match/literal choices.
 *
 * Logically, each incoming edge to this node is labeled with a literal or a
 * match that can be taken to reach this position from an earlier position; and
 * each outgoing edge from this node is labeled with a literal or a match that
 * can be taken to advance from this position to a later position.
 */
struct lzms_optimum_node {

	/* The cost, in bits, of the lowest-cost path that has been found to
	 * reach this position.  This can change as progressively lower cost
	 * paths are found to reach this position.  */
	u32 cost;
#define INFINITE_COST UINT32_MAX

	/*
	 * The match or literal that was taken to reach this position.  This can
	 * change as progressively lower cost paths are found to reach this
	 * position.
	 *
	 * This variable is divided into two bitfields.
	 *
	 * Literals:
	 *	Low bits are 1, high bits are the literal.
	 *
	 * Explicit offset matches:
	 *	Low bits are the match length, high bits are the offset plus 2.
	 *
	 * Repeat offset matches:
	 *	Low bits are the match length, high bits are the queue index.
	 */
	u64 item;
#define OPTIMUM_OFFSET_SHIFT 32
#define OPTIMUM_LEN_MASK (((u64)1 << OPTIMUM_OFFSET_SHIFT) - 1)

	/*
	 * The LZMS adaptive state that exists at this position.  This is filled
	 * in lazily, only after the minimum-cost path to this position is
	 * found.
	 *
	 * Note: the way we handle this adaptive state in the "minimum-cost"
	 * parse is actually only an approximation.  It's possible for the
	 * globally optimal, minimum cost path to contain a prefix, ending at a
	 * position, where that path prefix is *not* the minimum cost path to
	 * that position.  This can happen if such a path prefix results in a
	 * different adaptive state which results in lower costs later.  We do
	 * not solve this problem; we only consider the lowest cost to reach
	 * each position.
	 *
	 * Note: this adaptive state also does not include the probability
	 * entries or current Huffman codewords.  Those aren't maintained
	 * per-position and are only updated occassionally.
	 */
	struct lzms_adaptive_state {
		struct lzms_lz_lru_queue lru;
		u8 main_state;
		u8 match_state;
		u8 lz_match_state;
		u8 lz_repmatch_states[LZMS_NUM_RECENT_OFFSETS - 1];
	} state;
};

/* The main LZMS compressor structure  */
struct lzms_compressor {

	/* The matchfinder for LZ77-style matches  */
	struct lcpit_matchfinder mf;

	/* Temporary space to store matches found by the matchfinder  */
	struct lz_match matches[LZMS_MAX_FAST_LENGTH - LZMS_MIN_MATCH_LEN + 1];

	/* The preprocessed buffer of data being compressed  */
	u8 *in_buffer;

	/* The number of bytes of data to be compressed, which is the number of
	 * bytes of data in @in_buffer that are actually valid  */
	size_t in_nbytes;

	/* The per-byte graph nodes for near-optimal parsing  */
	struct lzms_optimum_node optimum_nodes[LZMS_NUM_OPTIM_NODES +
					       LZMS_MAX_FAST_LENGTH];

	/* Range encoder which outputs to the beginning of the compressed data
	 * buffer, proceeding forwards  */
	struct lzms_range_encoder rc;

	/* Bitstream which outputs to the end of the compressed data buffer,
	 * proceeding backwards  */
	struct lzms_output_bitstream os;

	/* Bit encoders for item type disambiguation  */
	struct lzms_bit_encoder main_bit_encoder;
	struct lzms_bit_encoder match_bit_encoder;
	struct lzms_bit_encoder lz_match_bit_encoder;
	struct lzms_bit_encoder lz_repmatch_bit_encoders[LZMS_NUM_RECENT_OFFSETS - 1];

	/* Huffman encoders, one per alphabet  */
	struct lzms_huffman_encoder literal_encoder;
	struct lzms_huffman_encoder lz_offset_encoder;
	struct lzms_huffman_encoder length_encoder;

	/* An array that is needed for preprocessing  */
	s32 last_target_usages[65536];

	/* Table: length => length slot for small match lengths  */
	u8 length_slot_fast[LZMS_MAX_FAST_LENGTH + 1];

	/* Table: length => current cost for small match lengths  */
	u32 length_cost_fast[LZMS_MAX_FAST_LENGTH + 1];

	/* Table: offset => offset slot for small match offsets  */
	u8 offset_slot_fast[LZMS_MAX_FAST_OFFSET + 1];
};

/* Generate a table that maps small lengths to length slots.  */
static void
lzms_init_fast_slots(struct lzms_compressor *c)
{
	u32 length;
	u32 offset;
	unsigned slot;

	/* Create a table mapping small lengths to length slots.  */
	slot = 0;
	for (length = LZMS_MIN_MATCH_LEN; length <= LZMS_MAX_FAST_LENGTH; length++) {
		while (length >= lzms_length_slot_base[slot + 1])
			slot++;
		c->length_slot_fast[length] = slot;
	}

	/* Create a table mapping small offsets to offset slots.  */
	slot = 0;
	for (offset = 1; offset <= LZMS_MAX_FAST_OFFSET; offset++) {
		while (offset >= lzms_offset_slot_base[slot + 1])
			slot++;
		c->offset_slot_fast[offset] = slot;
	}
}

static inline unsigned
lzms_get_length_slot_fast(const struct lzms_compressor *c, u32 length)
{
	if (likely(length <= LZMS_MAX_FAST_LENGTH))
		return c->length_slot_fast[length];
	else
		return lzms_get_length_slot(length);
}

static inline unsigned
lzms_get_offset_slot_fast(const struct lzms_compressor *c, u32 offset)
{
	if (offset <= LZMS_MAX_FAST_OFFSET)
		return c->offset_slot_fast[offset];
	else
		return lzms_get_offset_slot(offset);
}

/* Initialize the output bitstream @os to write backwards to the specified
 * buffer @out that is @count 16-bit integers long.  */
static void
lzms_output_bitstream_init(struct lzms_output_bitstream *os,
			   le16 *out, size_t count)
{
	os->bitbuf = 0;
	os->bitcount = 0;
	os->next = out + count;
	os->begin = out;
}

/*
 * Write some bits, contained in the low-order @num_bits bits of @bits, to the
 * output bitstream @os.
 *
 * @max_num_bits is a compile-time constant that specifies the maximum number of
 * bits that can ever be written at this call site.
 */
static inline void
lzms_output_bitstream_put_varbits(struct lzms_output_bitstream *os, u32 bits,
				  unsigned num_bits, unsigned max_num_bits)
{
	LZMS_ASSERT(num_bits <= 48);

	/* Add the bits to the bit buffer variable.  */
	os->bitcount += num_bits;
	os->bitbuf = (os->bitbuf << num_bits) | bits;

	/* Check whether any coding units need to be written.  */
	while (os->bitcount >= 16) {

		os->bitcount -= 16;

		/* Write a coding unit, unless it would underflow the buffer. */
		if (os->next != os->begin)
			put_unaligned_u16_le(os->bitbuf >> os->bitcount, --os->next);

		/* Optimization for call sites that never write more than 16
		 * bits at once.  */
		if (max_num_bits <= 16)
			break;
	}
}

/* Flush the output bitstream, ensuring that all bits written to it have been
 * written to memory.  Returns %true if all bits have been output successfully,
 * or %false if an overrun occurred.  */
static bool
lzms_output_bitstream_flush(struct lzms_output_bitstream *os)
{
	if (os->next == os->begin)
		return false;

	if (os->bitcount != 0)
		put_unaligned_u16_le(os->bitbuf << (16 - os->bitcount), --os->next);

	return true;
}

/* Initialize the range encoder @rc to write forwards to the specified buffer
 * @out that is @count 16-bit integers long.  */
static void
lzms_range_encoder_init(struct lzms_range_encoder *rc, le16 *out, size_t count)
{
	rc->low = 0;
	rc->range_size = 0xffffffff;
	rc->cache = 0;
	rc->cache_size = 1;
	rc->begin = out;
	rc->next = out - 1;
	rc->end = out + count;
}

/*
 * Attempt to flush bits from the range encoder.
 *
 * Note: this is based on the public domain code for LZMA written by Igor
 * Pavlov.  The only differences in this function are that in LZMS the bits must
 * be output in 16-bit coding units instead of 8-bit coding units, and that in
 * LZMS the first coding unit is not ignored by the decompressor, so the encoder
 * cannot output a dummy value to that position.
 *
 * The basic idea is that we're writing bits from @rc->low to the output.
 * However, due to carrying, the writing of coding units with value 0xffff, as
 * well as one prior coding unit, must be delayed until it is determined whether
 * a carry is needed.
 */
static void
lzms_range_encoder_shift_low(struct lzms_range_encoder *rc)
{
	if ((u32)(rc->low) < 0xffff0000 ||
	    (u32)(rc->low >> 32) != 0)
	{
		/* Carry not needed (rc->low < 0xffff0000), or carry occurred
		 * ((rc->low >> 32) != 0, a.k.a. the carry bit is 1).  */
		do {
			if (likely(rc->next >= rc->begin)) {
				if (rc->next != rc->end) {
					put_unaligned_u16_le(rc->cache +
							     (u16)(rc->low >> 32),
							     rc->next++);
				}
			} else {
				rc->next++;
			}
			rc->cache = 0xffff;
		} while (--rc->cache_size != 0);

		rc->cache = (rc->low >> 16) & 0xffff;
	}
	++rc->cache_size;
	rc->low = (rc->low & 0xffff) << 16;
}

static bool
lzms_range_encoder_flush(struct lzms_range_encoder *rc)
{
	for (unsigned i = 0; i < 4; i++)
		lzms_range_encoder_shift_low(rc);
	return rc->next != rc->end;
}

/* Encode the next bit using the range encoder.
 *
 * @prob is the chance out of LZMS_PROBABILITY_MAX that the next bit is 0.  */
static inline void
lzms_range_encode_bit(struct lzms_range_encoder *rc, int bit, u32 prob)
{
	/* Normalize if needed.  */
	if (rc->range_size <= 0xffff) {
		rc->range_size <<= 16;
		lzms_range_encoder_shift_low(rc);
	}

	u32 bound = (rc->range_size >> LZMS_PROBABILITY_BITS) * prob;
	if (bit == 0) {
		rc->range_size = bound;
	} else {
		rc->low += bound;
		rc->range_size -= bound;
	}
}

/* Encode a bit using the specified bit encoder.  This wraps around
 * lzms_range_encode_bit() to handle using and updating the appropriate state
 * and probability entry.  */
static void
lzms_encode_bit(struct lzms_bit_encoder *enc, int bit)
{
	struct lzms_probability_entry *prob_entry;
	u32 prob;

	/* Load the probability entry for the current state.  */
	prob_entry = &enc->prob_entries[enc->state];

	/* Update the state based on the next bit.  */
	enc->state = ((enc->state << 1) | bit) & enc->mask;

	/* Get the probability that the bit is 0.  */
	prob = lzms_get_probability(prob_entry);

	/* Update the probability entry.  */
	lzms_update_probability_entry(prob_entry, bit);

	/* Encode the bit using the range encoder.  */
	lzms_range_encode_bit(enc->rc, bit, prob);
}

static noinline void
lzms_rebuild_huffman_code(struct lzms_huffman_encoder *enc)
{
	make_canonical_huffman_code(enc->num_syms, LZMS_MAX_CODEWORD_LEN,
				    enc->freqs, enc->lens, enc->codewords);

	for (unsigned sym = 0; sym < enc->num_syms; sym++)
		enc->freqs[sym] = (enc->freqs[sym] >> 1) + 1;

	enc->num_syms_until_rebuild = enc->rebuild_freq;
}

/* Encode a symbol using the specified Huffman encoder.  If needed, the Huffman
 * code will be rebuilt.  Returns a boolean that indicates whether the Huffman
 * code was rebuilt or not.  */
static inline bool
lzms_huffman_encode_symbol(struct lzms_huffman_encoder *enc, unsigned sym)
{
	lzms_output_bitstream_put_varbits(enc->os,
					  enc->codewords[sym],
					  enc->lens[sym],
					  LZMS_MAX_CODEWORD_LEN);
	++enc->freqs[sym];
	if (--enc->num_syms_until_rebuild == 0) {
		lzms_rebuild_huffman_code(enc);
		return true;
	}
	return false;
}

static void
lzms_update_fast_length_costs(struct lzms_compressor *c);

/* Encode a match length.  If this causes the Huffman code for length symbols to
 * be rebuilt, also update the length costs array.  */
static void
lzms_encode_length(struct lzms_compressor *c, u32 length)
{
	unsigned slot;
	u32 extra_bits;
	unsigned num_extra_bits;

	slot = lzms_get_length_slot_fast(c, length);

	extra_bits = length - lzms_length_slot_base[slot];
	num_extra_bits = lzms_extra_length_bits[slot];

	if (lzms_huffman_encode_symbol(&c->length_encoder, slot))
		lzms_update_fast_length_costs(c);

	lzms_output_bitstream_put_varbits(c->length_encoder.os,
					  extra_bits, num_extra_bits, 30);
}

static void
lzms_encode_lz_offset(struct lzms_compressor *c, u32 offset)
{
	unsigned slot;
	u32 extra_bits;
	unsigned num_extra_bits;

	slot = lzms_get_offset_slot_fast(c, offset);

	extra_bits = offset - lzms_offset_slot_base[slot];
	num_extra_bits = lzms_extra_offset_bits[slot];

	lzms_huffman_encode_symbol(&c->lz_offset_encoder, slot);
	lzms_output_bitstream_put_varbits(c->lz_offset_encoder.os,
					  extra_bits, num_extra_bits, 30);
}

static void
lzms_encode_literal(struct lzms_compressor *c, unsigned literal)
{
	/* Main bit: 0 = a literal, not a match.  */
	lzms_encode_bit(&c->main_bit_encoder, 0);

	/* Encode the literal using the current literal Huffman code.  */
	lzms_huffman_encode_symbol(&c->literal_encoder, literal);
}

static void
lzms_encode_lz_repeat_offset_match(struct lzms_compressor *c,
				   u32 length, unsigned rep_idx)
{
	/* Main bit: 1 = a match, not a literal.  */
	lzms_encode_bit(&c->main_bit_encoder, 1);

	/* Match bit: 0 = an LZ match, not a delta match.  */
	lzms_encode_bit(&c->match_bit_encoder, 0);

	/* LZ match bit: 1 = repeat offset, not an explicit offset.  */
	lzms_encode_bit(&c->lz_match_bit_encoder, 1);

	/* Encode the repeat offset index.  A 1 bit is encoded for each index
	 * passed up.  This sequence of 1 bits is terminated by a 0 bit, or
	 * automatically when (LZMS_NUM_RECENT_OFFSETS - 1) 1 bits have been
	 * encoded.  */
	for (unsigned i = 0; i < rep_idx; i++)
		lzms_encode_bit(&c->lz_repmatch_bit_encoders[i], 1);

	if (rep_idx < LZMS_NUM_RECENT_OFFSETS - 1)
		lzms_encode_bit(&c->lz_repmatch_bit_encoders[rep_idx], 0);

	/* Encode the match length.  */
	lzms_encode_length(c, length);
}

static void
lzms_encode_lz_explicit_offset_match(struct lzms_compressor *c,
				     u32 length, u32 offset)
{
	/* Main bit: 1 = a match, not a literal.  */
	lzms_encode_bit(&c->main_bit_encoder, 1);

	/* Match bit: 0 = an LZ match, not a delta match.  */
	lzms_encode_bit(&c->match_bit_encoder, 0);

	/* LZ match bit: 0 = explicit offset, not a repeat offset.  */
	lzms_encode_bit(&c->lz_match_bit_encoder, 0);

	/* Encode the match offset.  */
	lzms_encode_lz_offset(c, offset);

	/* Encode the match length.  */
	lzms_encode_length(c, length);
}

static void
lzms_encode_item(struct lzms_compressor *c, u64 item)
{
	u32 len = item & OPTIMUM_LEN_MASK;
	u32 offset_data = item >> OPTIMUM_OFFSET_SHIFT;

	if (len == 1)
		lzms_encode_literal(c, offset_data);
	else if (offset_data < LZMS_NUM_RECENT_OFFSETS)
		lzms_encode_lz_repeat_offset_match(c, len, offset_data);
	else
		lzms_encode_lz_explicit_offset_match(c, len, offset_data - LZMS_OFFSET_ADJUSTMENT);
}

/* Encode a list of matches and literals chosen by the parsing algorithm.  */
static void
lzms_encode_item_list(struct lzms_compressor *c,
		      struct lzms_optimum_node *cur_node)
{
	struct lzms_optimum_node *end_node;
	u64 saved_item;
	u64 item;

	/* The list is currently in reverse order (last item to first item).
	 * Reverse it.  */
	end_node = cur_node;
	saved_item = cur_node->item;
	do {
		item = saved_item;
		cur_node -= item & OPTIMUM_LEN_MASK;
		saved_item = cur_node->item;
		cur_node->item = item;
	} while (cur_node != c->optimum_nodes);

	/* Walk the list of items from beginning to end, encoding each item.  */
	do {
		lzms_encode_item(c, cur_node->item);
		cur_node += (cur_node->item) & OPTIMUM_LEN_MASK;
	} while (cur_node != end_node);
}

/*
 * If p is the predicted probability of the next bit being a 0, then the number
 * of bits required to range encode a 0 bit is the real number -log2(p), and the
 * number of bits required to range encode a 1 bit is the real number
 * -log2(1 - p).  To avoid computing either of these expressions at runtime,
 * lzms_rc_costs is a precomputed table that stores a mapping from probability
 * to cost for each possible probability.  Specifically, the array indices are
 * the numerators of the possible probabilities in LZMS, where the denominators
 * are LZMS_PROBABILITY_MAX; and the stored costs are the bit costs multiplied
 * by 2**LZMS_COST_SHIFT and rounded down to the nearest integer.  Furthermore,
 * the values stored for 0/64 and 64/64 probabilities are equal to the adjacent
 * values, since these probabilities are not actually permitted.
 */
static const u32 lzms_rc_costs[LZMS_PROBABILITY_MAX + 1] = {
	384, 384, 320, 282, 256, 235, 218, 204,
	192, 181, 171, 162, 154, 147, 140, 133,
	128, 122, 117, 112, 107, 102, 98,  94,
	90,  86,  83,  79,  76,  73,  69,  66,
	64,  61,  58,  55,  53,  50,  48,  45,
	43,  41,  38,  36,  34,  32,  30,  28,
	26,  24,  22,  20,  19,  17,  15,  13,
	12,  10,  9,   7,   5,   4,   2,   1,
	1,
};

static inline void
lzms_check_cost_shift(void)
{
	/* lzms_rc_costs is hard-coded to the current LZMS_COST_SHIFT.  */
	BUILD_BUG_ON(LZMS_COST_SHIFT != 6);
}

#if 0
#include <math.h>

static void
lzms_init_rc_costs(void)
{
	for (u32 i = 0; i <= LZMS_PROBABILITY_MAX; i++) {
		u32 prob = i;
		if (prob == 0)
			prob++;
		else if (prob == LZMS_PROBABILITY_MAX)
			prob--;

		lzms_rc_costs[i] = -log2((double)prob / LZMS_PROBABILITY_MAX) *
					(1 << LZMS_COST_SHIFT);
	}
}
#endif

/* Return the cost to encode the specified bit using the specified bit encoder
 * when in the specified state.  */
static inline u32
lzms_bit_cost(const struct lzms_bit_encoder *enc, unsigned state, int bit)
{
	u32 prob = enc->prob_entries[state].num_recent_zero_bits;
	if (bit == 0)
		return lzms_rc_costs[prob];
	else
		return lzms_rc_costs[LZMS_PROBABILITY_MAX - prob];
}

/* Return the cost to encode the specified literal byte.  */
static inline u32
lzms_literal_cost(const struct lzms_compressor *c, unsigned literal,
		  const struct lzms_adaptive_state *state)
{
	return lzms_bit_cost(&c->main_bit_encoder, state->main_state, 0) +
	       ((u32)c->literal_encoder.lens[literal] << LZMS_COST_SHIFT);
}

/* Update the table that directly provides the costs for small lengths.  */
static void
lzms_update_fast_length_costs(struct lzms_compressor *c)
{
	u32 len;
	int slot = -1;
	u32 cost = 0;

	for (len = LZMS_MIN_MATCH_LEN; len <= LZMS_MAX_FAST_LENGTH; len++) {
		while (len >= lzms_length_slot_base[slot + 1]) {
			slot++;
			cost = (u32)(c->length_encoder.lens[slot] +
				     lzms_extra_length_bits[slot]) << LZMS_COST_SHIFT;
		}
		c->length_cost_fast[len] = cost;
	}
}

/* Return the cost to encode the specified match length, which must be less than
 * or equal to LZMS_MAX_FAST_LENGTH.  */
static inline u32
lzms_fast_length_cost(const struct lzms_compressor *c, u32 length)
{
	LZMS_ASSERT(length <= LZMS_MAX_FAST_LENGTH);
	return c->length_cost_fast[length];
}

/* Return the cost to encode the specified LZ match offset.  */
static inline u32
lzms_lz_offset_cost(const struct lzms_compressor *c, u32 offset)
{
	unsigned slot = lzms_get_offset_slot_fast(c, offset);

	return (u32)(c->lz_offset_encoder.lens[slot] +
		     lzms_extra_offset_bits[slot]) << LZMS_COST_SHIFT;
}

/*
 * Consider coding the LZ-style match at repeat offset index @rep_idx.  Consider
 * each length from the minimum (2) to the full match length (@rep_len).
 */
static inline void
lzms_consider_lz_repeat_offset_match(const struct lzms_compressor *c,
				     struct lzms_optimum_node *cur_node,
				     u32 rep_len, unsigned rep_idx)
{
	u32 base_cost = cur_node->cost +
			lzms_bit_cost(&c->main_bit_encoder,
				      cur_node->state.main_state, 1) +
			lzms_bit_cost(&c->match_bit_encoder,
				      cur_node->state.match_state, 0) +
			lzms_bit_cost(&c->lz_match_bit_encoder,
				      cur_node->state.lz_match_state, 1);

	for (unsigned i = 0; i < rep_idx; i++)
		base_cost += lzms_bit_cost(&c->lz_repmatch_bit_encoders[i],
					   cur_node->state.lz_repmatch_states[i], 1);

	if (rep_idx < LZMS_NUM_RECENT_OFFSETS - 1)
		base_cost += lzms_bit_cost(&c->lz_repmatch_bit_encoders[rep_idx],
					   cur_node->state.lz_repmatch_states[rep_idx], 0);

	u32 len = 2;
	do {
		u32 cost = base_cost + lzms_fast_length_cost(c, len);
		if (cost < (cur_node + len)->cost) {
			(cur_node + len)->item =
				((u64)rep_idx << OPTIMUM_OFFSET_SHIFT) | len;
			(cur_node + len)->cost = cost;
		}
	} while (++len <= rep_len);
}

/*
 * Consider coding each LZ-style match in @matches as an explicit offset match.
 *
 * @matches must be sorted by strictly decreasing length.  This is guaranteed by
 * the matchfinder.
 *
 * We consider each length from the minimum (2) to the longest
 * (matches[num_matches - 1].len).  For each length, we consider only the
 * smallest offset for which that length is available.  Although this is not
 * guaranteed to be optimal due to the possibility of a larger offset costing
 * less than a smaller offset to code, this is a very useful heuristic.
 */
static inline void
lzms_consider_lz_explicit_offset_matches(const struct lzms_compressor *c,
					 struct lzms_optimum_node *cur_node,
					 const struct lz_match matches[],
					 u32 num_matches)
{
	u32 base_cost = cur_node->cost +
			lzms_bit_cost(&c->main_bit_encoder,
				      cur_node->state.main_state, 1) +
			lzms_bit_cost(&c->match_bit_encoder,
				      cur_node->state.match_state, 0) +
			lzms_bit_cost(&c->lz_match_bit_encoder,
				      cur_node->state.lz_match_state, 0);
	u32 len = 2;
	u32 i = num_matches - 1;
	do {
		u32 position_cost = base_cost + lzms_lz_offset_cost(c, matches[i].offset);
		do {
			u32 cost = position_cost + lzms_fast_length_cost(c, len);
			if (cost < (cur_node + len)->cost) {
				(cur_node + len)->item =
					((u64)(matches[i].offset + LZMS_OFFSET_ADJUSTMENT)
						<< OPTIMUM_OFFSET_SHIFT) | len;
				(cur_node + len)->cost = cost;
			}
		} while (++len <= matches[i].length);
	} while (i--);
}

static void
lzms_init_lz_lru_queue(struct lzms_lz_lru_queue *queue)
{
	for (int i = 0; i < LZMS_NUM_RECENT_OFFSETS + 1; i++)
		queue->recent_offsets[i] = i + 1;

	queue->prev_offset = 0;
	queue->upcoming_offset = 0;
}

static void
lzms_init_adaptive_state(struct lzms_adaptive_state *state)
{
	lzms_init_lz_lru_queue(&state->lru);
	state->main_state = 0;
	state->match_state = 0;
	state->lz_match_state = 0;
	for (int i = 0; i < LZMS_NUM_RECENT_OFFSETS - 1; i++)
		state->lz_repmatch_states[i] = 0;
}

static void
lzms_update_lz_lru_queue(struct lzms_lz_lru_queue *queue)
{
	if (queue->prev_offset != 0) {
		for (int i = LZMS_NUM_RECENT_OFFSETS - 1; i >= 0; i--)
			queue->recent_offsets[i + 1] = queue->recent_offsets[i];
		queue->recent_offsets[0] = queue->prev_offset;
	}
	queue->prev_offset = queue->upcoming_offset;
}

static inline void
lzms_update_main_state(struct lzms_adaptive_state *state, int is_match)
{
	state->main_state =
		((state->main_state << 1) | is_match) % LZMS_NUM_MAIN_STATES;
}

static inline void
lzms_update_match_state(struct lzms_adaptive_state *state, int is_delta)
{
	state->match_state =
		((state->match_state << 1) | is_delta) % LZMS_NUM_MATCH_STATES;
}

static inline void
lzms_update_lz_match_state(struct lzms_adaptive_state *state, int is_repeat_offset)
{
	state->lz_match_state =
		((state->lz_match_state << 1) | is_repeat_offset) %
			LZMS_NUM_LZ_MATCH_STATES;
}

static inline void
lzms_update_lz_repmatch_states(struct lzms_adaptive_state *state, unsigned rep_idx)
{
	for (unsigned i = 0; i < rep_idx; i++)
		state->lz_repmatch_states[i] =
			((state->lz_repmatch_states[i] << 1) | 1) %
				LZMS_NUM_LZ_REPEAT_MATCH_STATES;

	if (rep_idx < LZMS_NUM_RECENT_OFFSETS - 1)
		state->lz_repmatch_states[rep_idx] =
			((state->lz_repmatch_states[rep_idx] << 1) | 0) %
				LZMS_NUM_LZ_REPEAT_MATCH_STATES;
}

/*
 * Find the longest LZ-style repeat offset match with the current sequence.  If
 * none is found, return 0; otherwise return its length and set
 * *best_rep_idx_ret to the index of its offset in the queue.
 */
static u32
lzms_find_longest_repeat_offset_match(const u8 * const in_next,
				      const u32 max_len,
				      const struct lzms_lz_lru_queue *queue,
				      unsigned *best_rep_idx_ret)
{
	u32 best_rep_len = 0;
	for (unsigned rep_idx = 0; rep_idx < LZMS_NUM_RECENT_OFFSETS; rep_idx++) {
		const u8 *matchptr = in_next - queue->recent_offsets[rep_idx];
		if (load_u16_unaligned(in_next) == load_u16_unaligned(matchptr)) {
			u32 rep_len = lz_extend(in_next, matchptr, 2, max_len);
			if (rep_len > best_rep_len) {
				best_rep_len = rep_len;
				*best_rep_idx_ret = rep_idx;
			}
		}
	}
	return best_rep_len;
}

/*
 * The main near-optimal parsing routine.
 *
 * Briefly, the algorithm does an approximate minimum-cost path search to find a
 * "near-optimal" sequence of matches and literals to output, based on the
 * current cost model.  The algorithm steps forward, position by position (byte
 * by byte), and updates the minimum cost path to reach each later position that
 * can be reached using a match or literal from the current position.  This is
 * essentially Dijkstra's algorithm in disguise: the graph nodes are positions,
 * the graph edges are possible matches/literals to code, and the cost of each
 * edge is the estimated number of bits that will be required to output the
 * corresponding match or literal.  But one difference is that we actually
 * compute the lowest-cost path in pieces, where each piece is terminated when
 * there are no choices to be made.
 *
 * Notes:
 *
 * - This does not output any delta matches.
 *
 * - The costs of literals and matches are estimated using the range encoder
 *   states and the semi-adaptive Huffman codes.  Except for range encoding
 *   states, costs are assumed to be constant throughout a single run of the
 *   parsing algorithm, which can parse up to LZMS_NUM_OPTIM_NODES bytes of
 *   data.  This introduces a source of inaccuracy because the probabilities and
 *   Huffman codes can change over this part of the data.
 */
static void
lzms_near_optimal_parse(struct lzms_compressor *c)
{
	const u8 *in_next = c->in_buffer;
	const u8 * const in_end = &c->in_buffer[c->in_nbytes];
	struct lzms_optimum_node *cur_node;
	struct lzms_optimum_node *end_node;

	/* Set initial length costs for lengths <= LZMS_MAX_FAST_LENGTH.  */
	lzms_update_fast_length_costs(c);

	/* Set up the initial adaptive state.  */
	lzms_init_adaptive_state(&c->optimum_nodes[0].state);

begin:
	/* Start building a new list of items, which will correspond to the next
	 * piece of the overall minimum-cost path.  */

	cur_node = c->optimum_nodes;
	cur_node->cost = 0;
	end_node = cur_node;

	/* States should currently be consistent with the encoders.  */
	LZMS_ASSERT(cur_node->state.main_state == c->main_bit_encoder.state);
	LZMS_ASSERT(cur_node->state.match_state == c->match_bit_encoder.state);
	LZMS_ASSERT(cur_node->state.lz_match_state == c->lz_match_bit_encoder.state);
	for (int i = 0; i < LZMS_NUM_RECENT_OFFSETS - 1; i++)
		LZMS_ASSERT(cur_node->state.lz_repmatch_states[i] ==
			    c->lz_repmatch_bit_encoders[i].state);

	if (in_next == in_end)
		return;

	/* The following loop runs once for each per byte in the input buffer,
	 * except in a couple shortcut cases.  */
	for (;;) {
		u32 num_matches;
		unsigned literal;
		u32 literal_cost;

		/* Find LZ-style matches with the current position.  */
		num_matches = lcpit_matchfinder_get_matches(&c->mf, c->matches);
		if (num_matches) {
			u32 best_len;
			u32 best_rep_len;
			unsigned best_rep_idx;

			/*
			 * Heuristics for repeat offset matches:
			 *
			 * - Only search for repeat offset matches if the
			 *   matchfinder already found at least one match.
			 *
			 * - Only consider the longest repeat offset match.  It
			 *   seems to be rare for the optimal parse to include a
			 *   repeat offset match that doesn't have the longest
			 *   length (allowing for the possibility that not all
			 *   of that length is actually used).
			 */
			if (likely(in_next - c->in_buffer >= LZMS_MAX_INIT_RECENT_OFFSET)) {
				best_rep_len = lzms_find_longest_repeat_offset_match(
							in_next,
							in_end - in_next,
							&cur_node->state.lru,
							&best_rep_idx);
			} else {
				best_rep_len = 0;
			}

			if (best_rep_len) {
				/* If there's a very long repeat offset match,
				 * then choose it immediately.  */
				if (best_rep_len >= c->mf.nice_match_len) {

					lcpit_matchfinder_skip_bytes(&c->mf, best_rep_len - 1);
					in_next += best_rep_len;

					if (cur_node != c->optimum_nodes)
						lzms_encode_item_list(c, cur_node);

					lzms_encode_lz_repeat_offset_match(c, best_rep_len, best_rep_idx);

					c->optimum_nodes[0].state = cur_node->state;

					lzms_update_main_state(&c->optimum_nodes[0].state, 1);
					lzms_update_match_state(&c->optimum_nodes[0].state, 0);
					lzms_update_lz_match_state(&c->optimum_nodes[0].state, 1);
					lzms_update_lz_repmatch_states(&c->optimum_nodes[0].state, best_rep_idx);

					c->optimum_nodes[0].state.lru.upcoming_offset =
						c->optimum_nodes[0].state.lru.recent_offsets[best_rep_idx];

					for (unsigned i = best_rep_idx; i < LZMS_NUM_RECENT_OFFSETS; i++)
						c->optimum_nodes[0].state.lru.recent_offsets[i] =
							c->optimum_nodes[0].state.lru.recent_offsets[i + 1];

					lzms_update_lz_lru_queue(&c->optimum_nodes[0].state.lru);
					goto begin;
				}

				/* If reaching any positions for the first time,
				 * initialize their costs to "infinity".  */
				while (end_node < cur_node + best_rep_len)
					(++end_node)->cost = INFINITE_COST;

				/* Consider coding a repeat offset match.  */
				lzms_consider_lz_repeat_offset_match(c, cur_node,
								     best_rep_len, best_rep_idx);
			}

			best_len = c->matches[0].length;

			/* If there's a very long explicit offset match, then
			 * choose it immediately.  */
			if (best_len >= c->mf.nice_match_len) {

				u32 offset = c->matches[0].offset;

				/* Extend the match as far as possible.  (The
				 * LCP-interval tree matchfinder only reports up
				 * to nice_match_len bytes.)  */
				best_len = lz_extend(in_next,
						     in_next - offset,
						     best_len,
						     in_end - in_next);

				lcpit_matchfinder_skip_bytes(&c->mf, best_len - 1);
				in_next += best_len;

				if (cur_node != c->optimum_nodes)
					lzms_encode_item_list(c, cur_node);

				lzms_encode_lz_explicit_offset_match(c, best_len, offset);

				c->optimum_nodes[0].state = cur_node->state;

				lzms_update_main_state(&c->optimum_nodes[0].state, 1);
				lzms_update_match_state(&c->optimum_nodes[0].state, 0);
				lzms_update_lz_match_state(&c->optimum_nodes[0].state, 0);

				c->optimum_nodes[0].state.lru.upcoming_offset = offset;

				lzms_update_lz_lru_queue(&c->optimum_nodes[0].state.lru);
				goto begin;
			}

			/* If reaching any positions for the first time,
			 * initialize their costs to "infinity".  */
			while (end_node < cur_node + best_len)
				(++end_node)->cost = INFINITE_COST;

			/* Consider coding an explicit offset match.  */
			lzms_consider_lz_explicit_offset_matches(c, cur_node,
								 c->matches, num_matches);
		} else {
			/* No matches found.  The only choice at this position
			 * is to code a literal.  */

			if (end_node == cur_node)
				(++end_node)->cost = INFINITE_COST;
		}

		/* Consider coding a literal.

		 * To avoid an extra unpredictable brench, actually checking the
		 * preferability of coding a literal is integrated into the
		 * adaptive state update code below.  */
		literal = *in_next++;
		literal_cost = cur_node->cost +
			       lzms_literal_cost(c, literal, &cur_node->state);

		/* Advance to the next position.  */
		cur_node++;

		/* The lowest-cost path to the current position is now known.
		 * Finalize the adaptive state that results from taking this
		 * lowest-cost path.  */

		if (literal_cost < cur_node->cost) {
			/* Literal  */
			cur_node->cost = literal_cost;
			cur_node->item = ((u64)literal << OPTIMUM_OFFSET_SHIFT) | 1;
			cur_node->state = (cur_node - 1)->state;
			lzms_update_main_state(&cur_node->state, 0);
			cur_node->state.lru.upcoming_offset = 0;
		} else {
			/* LZ match  */
			u32 len = cur_node->item & OPTIMUM_LEN_MASK;
			u32 offset_data = cur_node->item >> OPTIMUM_OFFSET_SHIFT;

			cur_node->state = (cur_node - len)->state;

			lzms_update_main_state(&cur_node->state, 1);
			lzms_update_match_state(&cur_node->state, 0);

			if (offset_data >= LZMS_NUM_RECENT_OFFSETS) {

				/* Explicit offset LZ match  */

				lzms_update_lz_match_state(&cur_node->state, 0);

				cur_node->state.lru.upcoming_offset =
					offset_data - LZMS_OFFSET_ADJUSTMENT;
			} else {
				/* Repeat offset LZ match  */

				lzms_update_lz_match_state(&cur_node->state, 1);
				lzms_update_lz_repmatch_states(&cur_node->state, offset_data);

				cur_node->state.lru.upcoming_offset =
					cur_node->state.lru.recent_offsets[offset_data];

				for (u32 i = offset_data; i < LZMS_NUM_RECENT_OFFSETS; i++)
					cur_node->state.lru.recent_offsets[i] =
						cur_node->state.lru.recent_offsets[i + 1];
			}
		}

		lzms_update_lz_lru_queue(&cur_node->state.lru);

		/*
		 * This loop will terminate when either of the following
		 * conditions is true:
		 *
		 * (1) cur_node == end_node
		 *
		 *	There are no paths that extend beyond the current
		 *	position.  In this case, any path to a later position
		 *	must pass through the current position, so we can go
		 *	ahead and choose the list of items that led to this
		 *	position.
		 *
		 * (2) cur_node == &c->optimum_nodes[LZMS_NUM_OPTIM_NODES]
		 *
		 *	This bounds the number of times the algorithm can step
		 *	forward before it is guaranteed to start choosing items.
		 *	This limits the memory usage.  It also guarantees that
		 *	the parser will not go too long without updating the
		 *	probability tables.
		 *
		 * Note: no check for end-of-buffer is needed because
		 * end-of-buffer will trigger condition (1).
		 */
		if (cur_node == end_node ||
		    cur_node == &c->optimum_nodes[LZMS_NUM_OPTIM_NODES])
		{
			lzms_encode_item_list(c, cur_node);
			c->optimum_nodes[0].state = cur_node->state;
			goto begin;
		}
	}
}

static void
lzms_init_bit_encoder(struct lzms_bit_encoder *enc,
		      struct lzms_range_encoder *rc, unsigned num_states)
{
	enc->rc = rc;
	enc->state = 0;
	LZMS_ASSERT(is_power_of_2(num_states));
	enc->mask = num_states - 1;
	lzms_init_probability_entries(enc->prob_entries, num_states);
}

static void
lzms_init_huffman_encoder(struct lzms_huffman_encoder *enc,
			  struct lzms_output_bitstream *os,
			  unsigned num_syms, unsigned rebuild_freq)
{
	enc->os = os;
	enc->num_syms = num_syms;
	enc->rebuild_freq = rebuild_freq;
	enc->num_syms_until_rebuild = rebuild_freq;
	for (unsigned i = 0; i < num_syms; i++)
		enc->freqs[i] = 1;

	make_canonical_huffman_code(enc->num_syms, LZMS_MAX_CODEWORD_LEN,
				    enc->freqs, enc->lens, enc->codewords);
}

static void
lzms_prepare_encoders(struct lzms_compressor *c, void *out,
		      size_t out_nbytes_avail, unsigned num_offset_slots)
{
	/* Initialize the range encoder (writing forwards).  */
	lzms_range_encoder_init(&c->rc, out, out_nbytes_avail / sizeof(le16));

	/* Initialize the output bitstream for Huffman symbols and verbatim bits
	 * (writing backwards).  */
	lzms_output_bitstream_init(&c->os, out, out_nbytes_avail / sizeof(le16));

	/* Initialize the Huffman encoders.  */

	lzms_init_huffman_encoder(&c->literal_encoder, &c->os,
				  LZMS_NUM_LITERAL_SYMS,
				  LZMS_LITERAL_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&c->lz_offset_encoder, &c->os,
				  num_offset_slots,
				  LZMS_LZ_OFFSET_CODE_REBUILD_FREQ);

	lzms_init_huffman_encoder(&c->length_encoder, &c->os,
				  LZMS_NUM_LENGTH_SYMS,
				  LZMS_LENGTH_CODE_REBUILD_FREQ);

	/* Initialize the bit encoders.  */

	lzms_init_bit_encoder(&c->main_bit_encoder,
			      &c->rc, LZMS_NUM_MAIN_STATES);

	lzms_init_bit_encoder(&c->match_bit_encoder,
			      &c->rc, LZMS_NUM_MATCH_STATES);

	lzms_init_bit_encoder(&c->lz_match_bit_encoder,
			      &c->rc, LZMS_NUM_LZ_MATCH_STATES);

	for (int i = 0; i < ARRAY_LEN(c->lz_repmatch_bit_encoders); i++)
		lzms_init_bit_encoder(&c->lz_repmatch_bit_encoders[i],
				      &c->rc, LZMS_NUM_LZ_REPEAT_MATCH_STATES);
}

/* Flush the output streams, prepare the final compressed data, and return its
 * size in bytes.
 *
 * A return value of 0 indicates that the data could not be compressed to fit in
 * the available space.  */
static size_t
lzms_finalize(struct lzms_compressor *c, u8 *out, size_t out_nbytes_avail)
{
	size_t num_forwards_bytes;
	size_t num_backwards_bytes;

	/* Flush both the forwards and backwards streams, and make sure they
	 * didn't cross each other and start overwriting each other's data.  */
	if (!lzms_output_bitstream_flush(&c->os))
		return 0;

	if (!lzms_range_encoder_flush(&c->rc))
		return 0;

	if (c->rc.next > c->os.next)
		return 0;

	/* Now the compressed buffer contains the data output by the forwards
	 * bitstream, then empty space, then data output by the backwards
	 * bitstream.  Move the data output by the backwards bitstream to be
	 * adjacent to the data output by the forward bitstream, and calculate
	 * the compressed size that this results in.  */
	num_forwards_bytes = (u8 *)c->rc.next - out;
	num_backwards_bytes = (out + out_nbytes_avail) - (u8 *)c->os.next;

	memmove(out + num_forwards_bytes, c->os.next, num_backwards_bytes);

	return num_forwards_bytes + num_backwards_bytes;
}

static u64
lzms_get_needed_memory(size_t max_bufsize, unsigned compression_level)
{
	u64 size = 0;

	if (max_bufsize > LZMS_MAX_BUFFER_SIZE)
		return 0;

	size += sizeof(struct lzms_compressor);

	/* in_buffer */
	size += max_bufsize;

	/* mf */
	size += lcpit_matchfinder_get_needed_memory(max_bufsize);

	return size;
}

static int
lzms_create_compressor(size_t max_bufsize, unsigned compression_level,
		       void **c_ret)
{
	struct lzms_compressor *c;
	u32 nice_match_len;

	if (max_bufsize > LZMS_MAX_BUFFER_SIZE)
		return WIMLIB_ERR_INVALID_PARAM;

	/* Scale nice_match_len with the compression level.  But to allow an
	 * optimization on length cost calculations, don't allow nice_match_len
	 * to exceed LZMS_MAX_FAST_LENGTH.  */
	nice_match_len = min(((u64)compression_level * 32) / 50,
			     LZMS_MAX_FAST_LENGTH);

	c = MALLOC(sizeof(struct lzms_compressor));
	if (!c)
		goto oom0;

	c->in_buffer = MALLOC(max_bufsize);
	if (!c->in_buffer)
		goto oom1;

	if (!lcpit_matchfinder_init(&c->mf, max_bufsize, 2, nice_match_len))
		goto oom2;

	lzms_init_fast_slots(c);

	*c_ret = c;
	return 0;

oom2:
	FREE(c->in_buffer);
oom1:
	FREE(c);
oom0:
	return WIMLIB_ERR_NOMEM;
}

static size_t
lzms_compress(const void *in, size_t in_nbytes,
	      void *out, size_t out_nbytes_avail, void *_c)
{
	struct lzms_compressor *c = _c;

	/* Don't bother trying to compress extremely small inputs.  */
	if (in_nbytes < 4)
		return 0;

	/* Cap the available compressed size to a 32-bit integer and it round
	 * down to the nearest multiple of 2 so it can be evenly divided into
	 * 16-bit integers.  */
	out_nbytes_avail = min(out_nbytes_avail, UINT32_MAX) & ~1;

	/* Copy the input data into the internal buffer and preprocess it.  */
	memcpy(c->in_buffer, in, in_nbytes);
	c->in_nbytes = in_nbytes;
	lzms_x86_filter(c->in_buffer, in_nbytes, c->last_target_usages, false);

	/* Load the buffer into the matchfinder.  */
	lcpit_matchfinder_load_buffer(&c->mf, c->in_buffer, c->in_nbytes);

	/* Initialize the encoder structures.  */
	lzms_prepare_encoders(c, out, out_nbytes_avail,
			      lzms_get_num_offset_slots(c->in_nbytes));

	/* Compute and encode a literal/match sequence that decompresses to the
	 * preprocessed data.  */
	lzms_near_optimal_parse(c);

	/* Return the compressed data size or 0.  */
	return lzms_finalize(c, out, out_nbytes_avail);
}

static void
lzms_free_compressor(void *_c)
{
	struct lzms_compressor *c = _c;

	FREE(c->in_buffer);
	lcpit_matchfinder_destroy(&c->mf);
	FREE(c);
}

const struct compressor_ops lzms_compressor_ops = {
	.get_needed_memory  = lzms_get_needed_memory,
	.create_compressor  = lzms_create_compressor,
	.compress	    = lzms_compress,
	.free_compressor    = lzms_free_compressor,
};
