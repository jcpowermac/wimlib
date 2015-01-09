/*
 * lzx_compress.c
 *
 * A compressor for the LZX compression format, as used in WIM files.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
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


/*
 * This file contains a compressor for the LZX ("Lempel-Ziv eXtended")
 * compression format, as used in the WIM (Windows IMaging) file format.
 *
 * Two different parsing algorithms are implemented: "near-optimal" and "lazy".
 * "Near-optimal" is significantly slower than "lazy", but results in a better
 * compression ratio.  The "near-optimal" algorithm is used at the default
 * compression level.
 *
 * This file may need some slight modifications to be used outside of the WIM
 * format.  In particular, in other situations the LZX block header might be
 * slightly different, and a sliding window rather than a fixed-size window
 * might be required.
 *
 * Note: LZX is a compression format derived from DEFLATE, the format used by
 * zlib and gzip.  Both LZX and DEFLATE use LZ77 matching and Huffman coding.
 * Certain details are quite similar, such as the method for storing Huffman
 * codes.  However, the main differences are:
 *
 * - LZX preprocesses the data to attempt to make x86 machine code slightly more
 *   compressible before attempting to compress it further.
 *
 * - LZX uses a "main" alphabet which combines literals and matches, with the
 *   match symbols containing a "length header" (giving all or part of the match
 *   length) and an "offset slot" (giving, roughly speaking, the order of
 *   magnitude of the match offset).
 *
 * - LZX does not have static Huffman blocks (that is, the kind with preset
 *   Huffman codes); however it does have two types of dynamic Huffman blocks
 *   ("verbatim" and "aligned").
 *
 * - LZX has a minimum match length of 2 rather than 3.  Length 2 matches can be
 *   useful, but generally only if the parser is smart about choosing them.
 *
 * - In LZX, offset slots 0 through 2 actually represent entries in an LRU queue
 *   of match offsets.  This is very useful for certain types of files, such as
 *   binary files that have repeating records.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

/*
 * Start a new LZX block (with new Huffman codes) after this many bytes.
 *
 * Note: actual block sizes may slightly exceed this value.
 *
 * TODO: recursive splitting and cost evaluation might be good for an extremely
 * high compression mode, but otherwise it is almost always far too slow for how
 * much it helps.  Perhaps some sort of heuristic would be useful?
 */
#define LZX_DIV_BLOCK_SIZE	32768

/*
 * LZX_CACHE_PER_POS is the number of lz_match structures to reserve in the
 * match cache for each byte position.  This value should be high enough so that
 * virtually the time, all matches found in a given block can fit in the match
 * cache.  However, fallback behavior on cache overflow is still required.
 */
#define LZX_CACHE_PER_POS	6

#define LZX_CACHE_LEN		(LZX_DIV_BLOCK_SIZE * (LZX_CACHE_PER_POS + 1))

#define LZX_MAX_MATCHES_PER_POS	(LZX_MAX_MATCH_LEN - LZX_MIN_MATCH_LEN + 1)

/*
 * LZX_COST_SHIFT is a scaling factor that makes it possible to consider
 * fractional bit costs.  A token requiring 'n' bits to represent has cost
 * 'n << LZX_COST_SHIFT'.
 *
 * Note: this is only useful as a statistical trick for when the true costs are
 * unknown.  In reality, each token in LZX requires a whole number of bits to
 * output.
 */
#define LZX_COST_SHIFT		4

/*
 * The maximum compression level at which we use the faster algorithm.
 */
#define LZX_MAX_FAST_LEVEL	34

/*
 * LZX_HASH2_ORDER is the log base 2 of the number of entries in the hash table
 * for finding length 2 matches.  This can be as high as 16 (in which case the
 * hash function is trivial), but using a smaller hash table speeds up
 * compression due to reduced cache pressure.
 */
#define LZX_HASH2_ORDER		12
#define LZX_HASH2_LENGTH	(1UL << LZX_HASH2_ORDER)

#include "wimlib/lzx_common.h"

/*
 * The maximum allowed window order for the matchfinder.
 */
#define MATCHFINDER_MAX_WINDOW_ORDER	LZX_MAX_WINDOW_ORDER

#include <limits.h>
#include <string.h>

#include "wimlib/bt_matchfinder.h"
#include "wimlib/compress_common.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/hc_matchfinder.h"
#include "wimlib/util.h"

struct lzx_output_bitstream;

/* Codewords for the LZX Huffman codes.  */
struct lzx_codewords {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Codeword lengths (in bits) for the LZX Huffman codes.
 * A zero length means the corresponding codeword has zero frequency.  */
struct lzx_lens {
	u8 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u8 len[LZX_LENCODE_NUM_SYMBOLS];
	u8 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Estimated cost to output each symbol in the LZX Huffman codes.  */
struct lzx_costs {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Codewords and lengths for the LZX Huffman codes.  */
struct lzx_codes {
	struct lzx_codewords codewords;
	struct lzx_lens lens;
};

/* Symbol frequency counters for the LZX Huffman codes.  */
struct lzx_freqs {
	u32 main[LZX_MAINCODE_MAX_NUM_SYMBOLS];
	u32 len[LZX_LENCODE_NUM_SYMBOLS];
	u32 aligned[LZX_ALIGNEDCODE_NUM_SYMBOLS];
};

/* Intermediate LZX match/literal format  */
struct lzx_item {

	/* Bits 0  -  9: Main symbol
	 * Bits 10 - 17: Length symbol
	 * Bits 18 - 22: Number of extra offset bits
	 * Bits 23+    : Extra offset bits  */
	u64 data;
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
struct lzx_optimum_node {

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
	u32 item;
#define OPTIMUM_OFFSET_SHIFT 9
#define OPTIMUM_LEN_MASK ((1 << OPTIMUM_OFFSET_SHIFT) - 1)
};

/*
 * Least-recently-used queue for match offsets.
 *
 * This is represented as a 64-bit integer for efficiency.  There are three
 * offsets of 21 bits each.  Bit 64 is garbage.
 */
struct lzx_lru_queue {
	u64 R;
};

#define LZX_QUEUE64_OFFSET_SHIFT 21
#define LZX_QUEUE64_OFFSET_MASK	(((u64)1 << LZX_QUEUE64_OFFSET_SHIFT) - 1)

#define LZX_QUEUE64_R0_SHIFT (0 * LZX_QUEUE64_OFFSET_SHIFT)
#define LZX_QUEUE64_R1_SHIFT (1 * LZX_QUEUE64_OFFSET_SHIFT)
#define LZX_QUEUE64_R2_SHIFT (2 * LZX_QUEUE64_OFFSET_SHIFT)

#define LZX_QUEUE64_R0_MASK (LZX_QUEUE64_OFFSET_MASK << LZX_QUEUE64_R0_SHIFT)
#define LZX_QUEUE64_R1_MASK (LZX_QUEUE64_OFFSET_MASK << LZX_QUEUE64_R1_SHIFT)
#define LZX_QUEUE64_R2_MASK (LZX_QUEUE64_OFFSET_MASK << LZX_QUEUE64_R2_SHIFT)

static inline void
lzx_lru_queue_init(struct lzx_lru_queue *queue)
{
	queue->R = ((u64)1 << LZX_QUEUE64_R0_SHIFT) |
		   ((u64)1 << LZX_QUEUE64_R1_SHIFT) |
		   ((u64)1 << LZX_QUEUE64_R2_SHIFT);
}

static inline u64
lzx_lru_queue_R0(struct lzx_lru_queue queue)
{
	return (queue.R >> LZX_QUEUE64_R0_SHIFT) & LZX_QUEUE64_OFFSET_MASK;
}

static inline u64
lzx_lru_queue_R1(struct lzx_lru_queue queue)
{
	return (queue.R >> LZX_QUEUE64_R1_SHIFT) & LZX_QUEUE64_OFFSET_MASK;
}

static inline u64
lzx_lru_queue_R2(struct lzx_lru_queue queue)
{
	return (queue.R >> LZX_QUEUE64_R2_SHIFT) & LZX_QUEUE64_OFFSET_MASK;
}

/* Push a match offset onto the front (most recently used) end of the queue.  */
static inline struct lzx_lru_queue
lzx_lru_queue_push(struct lzx_lru_queue queue, u32 offset)
{
	return (struct lzx_lru_queue) {
		.R = (queue.R << LZX_QUEUE64_OFFSET_SHIFT) | offset,
	};
}

/* Pop a match offset off the front (most recently used) end of the queue.  */
static inline u32
lzx_lru_queue_pop(struct lzx_lru_queue *queue_p)
{
	u32 offset = queue_p->R & LZX_QUEUE64_OFFSET_MASK;
	queue_p->R >>= LZX_QUEUE64_OFFSET_SHIFT;
	return offset;
}

/* Swap a match offset to the front of the queue.  */
static inline struct lzx_lru_queue
lzx_lru_queue_swap(struct lzx_lru_queue queue, unsigned idx)
{
	if (idx == 0)
		return queue;

	if (idx == 1)
		return (struct lzx_lru_queue) {
			.R = (lzx_lru_queue_R1(queue) << LZX_QUEUE64_R0_SHIFT) |
			     (lzx_lru_queue_R0(queue) << LZX_QUEUE64_R1_SHIFT) |
			     (queue.R & LZX_QUEUE64_R2_MASK),
		};

	return (struct lzx_lru_queue) {
		.R = (lzx_lru_queue_R2(queue) << LZX_QUEUE64_R0_SHIFT) |
		     (queue.R & LZX_QUEUE64_R1_MASK) |
		     (lzx_lru_queue_R0(queue) << LZX_QUEUE64_R2_SHIFT),
	};
}

/* The main LZX compressor structure  */
struct lzx_compressor {

	/* Pointer to the compress() implementation chosen at allocation time */
	void (*impl)(struct lzx_compressor *, struct lzx_output_bitstream *);

	/* The preprocessed buffer of data being compressed  */
	u8 *in_buffer;

	/* The number of bytes of data to be compressed, which is the number of
	 * bytes of data in @in_buffer that are actually valid.  */
	size_t in_nbytes;

	/* The log base 2 of the LZX window size for LZ match offset encoding
	 * purposes.  This will be >= LZX_MIN_WINDOW_ORDER and <=
	 * LZX_MAX_WINDOW_ORDER.  */
	unsigned window_order;

	/* The number of symbols in the main alphabet.  This depends on
	 * @window_order, since @window_order determines the maximum possible
	 * offset.  */
	unsigned num_main_syms;

	/* The Huffman symbol frequency counters for the current block.  */
	struct lzx_freqs freqs;

	/* The Huffman codes for the current and previous blocks.  The one with
	 * index 'codes_index' is for the current block, and the other one is
	 * for the previous block.  */
	struct lzx_codes codes[2];
	unsigned codes_index;

	/* The "nice" match length: if a match of this length is found, then
	 * choose it immediately without further consideration.  */
	unsigned nice_match_length;

	/* The maximum search depth: consider at most this many potential
	 * matches at each position.  */
	unsigned max_search_depth;

	/* The match/literal sequence the algorithm chose for the current block.
	 */
	struct lzx_item chosen_items[LZX_DIV_BLOCK_SIZE + LZX_MAX_MATCH_LEN + 1];

	/* Table mapping match offset => offset slot for small offsets  */
#define LZX_NUM_FAST_OFFSETS 32768
	u8 offset_slot_fast[LZX_NUM_FAST_OFFSETS];

	union {
		/* Data for greedy or lazy parsing  */
		struct {
			/* Hash chains matchfinder (MUST BE LAST!!!)  */
			struct hc_matchfinder hc_mf;
		};

		/* Data for near-optimal parsing  */
		struct {
			/* Hash table for finding length 2 matches  */
			pos_t hash2_tab[LZX_HASH2_LENGTH]
				_aligned_attribute(MATCHFINDER_ALIGNMENT);

			/* Cached matches for the current block  */
			struct lz_match match_cache[LZX_CACHE_LEN + 1 +
						    LZX_MAX_MATCHES_PER_POS];
			struct lz_match *cache_overflow_mark;

			/* The graph nodes for the current block  */
			struct lzx_optimum_node optimum_nodes[LZX_DIV_BLOCK_SIZE +
							      LZX_MAX_MATCH_LEN + 1];

			/* The cost model for the current block  */
			struct lzx_costs costs;

			/* Number of optimization passes per block  */
			unsigned num_optim_passes;

			/* Binary trees matchfinder (MUST BE LAST!!!)  */
			struct bt_matchfinder bt_mf;
		};
	};
};

/* Compute a hash value for the next 2 bytes of uncompressed data.  */
static inline u32
lz_hash_2_bytes(const u8 *in_next)
{
	u16 next_2_bytes = load_u16_unaligned(in_next);
	if (LZX_HASH2_ORDER == 16)
		return next_2_bytes;
	else
		return lz_hash(next_2_bytes, LZX_HASH2_ORDER);
}

/*
 * Structure to keep track of the current state of sending bits to the
 * compressed output buffer.
 *
 * The LZX bitstream is encoded as a sequence of 16-bit coding units.
 */
struct lzx_output_bitstream {

	/* Bits that haven't yet been written to the output buffer.  */
	u32 bitbuf;

	/* Number of bits currently held in @bitbuf.  */
	u32 bitcount;

	/* Pointer to the start of the output buffer.  */
	le16 *start;

	/* Pointer to the position in the output buffer at which the next coding
	 * unit should be written.  */
	le16 *next;

	/* Pointer past the end of the output buffer.  */
	le16 *end;
};

/*
 * Initialize the output bitstream.
 *
 * @os
 *	The output bitstream structure to initialize.
 * @buffer
 *	The buffer being written to.
 * @size
 *	Size of @buffer, in bytes.
 */
static void
lzx_init_output(struct lzx_output_bitstream *os, void *buffer, u32 size)
{
	os->bitbuf = 0;
	os->bitcount = 0;
	os->start = buffer;
	os->next = os->start;
	os->end = os->start + size / sizeof(le16);
}

/*
 * Write some bits to the output bitstream.
 *
 * The bits are given by the low-order @num_bits bits of @bits.  Higher-order
 * bits in @bits cannot be set.  At most 17 bits can be written at once.
 *
 * @max_num_bits is a compile-time constant that specifies the maximum number of
 * bits that can ever be written at the call site.  Currently, it is used to
 * optimize away the conditional code for writing a second 16-bit coding unit
 * when writing fewer than 17 bits.
 *
 * If the output buffer space is exhausted, then the bits will be ignored, and
 * lzx_flush_output() will return 0 when it gets called.
 */
static inline void
lzx_write_varbits(struct lzx_output_bitstream *os,
		  const u32 bits, const unsigned num_bits,
		  const unsigned max_num_bits)
{
	/* This code is optimized for LZX, which never needs to write more than
	 * 17 bits at once.  */
	LZX_ASSERT(num_bits <= 17);
	LZX_ASSERT(num_bits <= max_num_bits);
	LZX_ASSERT(os->bitcount <= 15);

	/* Add the bits to the bit buffer variable.  @bitcount will be at most
	 * 15, so there will be just enough space for the maximum possible
	 * @num_bits of 17.  */
	os->bitcount += num_bits;
	os->bitbuf = (os->bitbuf << num_bits) | bits;

	/* Check whether any coding units need to be written.  */
	if (os->bitcount >= 16) {

		os->bitcount -= 16;

		/* Write a coding unit, unless it would overflow the buffer.  */
		if (os->next != os->end)
			put_unaligned_u16_le(os->bitbuf >> os->bitcount, os->next++);

		/* If writing 17 bits, a second coding unit might need to be
		 * written.  But because 'max_num_bits' is a compile-time
		 * constant, the compiler will optimize away this code at most
		 * call sites.  */
		if (max_num_bits == 17 && os->bitcount == 16) {
			if (os->next != os->end)
				put_unaligned_u16_le(os->bitbuf, os->next++);
			os->bitcount = 0;
		}
	}
}

/* Use when @num_bits is a compile-time constant.  Otherwise use
 * lzx_write_varbits().  */
static inline void
lzx_write_bits(struct lzx_output_bitstream *os,
	       const u32 bits, const unsigned num_bits)
{
	lzx_write_varbits(os, bits, num_bits, num_bits);
}

/*
 * Flush the last coding unit to the output buffer if needed.  Return the total
 * number of bytes written to the output buffer, or 0 if an overflow occurred.
 */
static u32
lzx_flush_output(struct lzx_output_bitstream *os)
{
	if (os->next == os->end)
		return 0;

	if (os->bitcount != 0)
		put_unaligned_u16_le(os->bitbuf << (16 - os->bitcount), os->next++);

	return (const u8 *)os->next - (const u8 *)os->start;
}

/* Build the main, length, and aligned offset Huffman codes used in LZX.
 *
 * This takes as input the frequency tables for each code and produces as output
 * a set of tables that map symbols to codewords and codeword lengths.  */
static void
lzx_make_huffman_codes(struct lzx_compressor *c)
{
	const struct lzx_freqs *freqs = &c->freqs;
	struct lzx_codes *codes = &c->codes[c->codes_index];

	make_canonical_huffman_code(c->num_main_syms,
				    LZX_MAX_MAIN_CODEWORD_LEN,
				    freqs->main,
				    codes->lens.main,
				    codes->codewords.main);

	make_canonical_huffman_code(LZX_LENCODE_NUM_SYMBOLS,
				    LZX_MAX_LEN_CODEWORD_LEN,
				    freqs->len,
				    codes->lens.len,
				    codes->codewords.len);

	make_canonical_huffman_code(LZX_ALIGNEDCODE_NUM_SYMBOLS,
				    LZX_MAX_ALIGNED_CODEWORD_LEN,
				    freqs->aligned,
				    codes->lens.aligned,
				    codes->codewords.aligned);
}

/* Reset the symbol frequencies for the LZX Huffman codes.  */
static void
lzx_reset_symbol_frequencies(struct lzx_compressor *c)
{
	memset(&c->freqs, 0, sizeof(c->freqs));
}

static unsigned
lzx_compute_precode_items(const u8 lens[restrict],
			  const u8 prev_lens[restrict],
			  const unsigned num_lens,
			  u32 precode_freqs[restrict],
			  unsigned precode_items[restrict])
{
	unsigned *itemptr;
	unsigned run_start;
	unsigned run_end;
	unsigned extra_bits;
	int delta;
	u8 len;

	itemptr = precode_items;
	run_start = 0;
	do {
		/* Find the next run of codeword lengths.  */

		/* len = the length being repeated  */
		len = lens[run_start];

		run_end = run_start + 1;

		/* Fast case for a single length.  */
		if (likely(run_end == num_lens || len != lens[run_end])) {
			delta = prev_lens[run_start] - len;
			if (delta < 0)
				delta += 17;
			precode_freqs[delta]++;
			*itemptr++ = delta;
			run_start++;
			continue;
		}

		/* Extend the run.  */
		do {
			run_end++;
		} while (run_end != num_lens && len == lens[run_end]);

		if (len == 0) {
			/* Run of zeroes.  */

			/* Symbol 18: RLE 20 to 51 zeroes at a time.  */
			while ((run_end - run_start) >= 20) {
				extra_bits = min((run_end - run_start) - 20, 0x1f);
				precode_freqs[18]++;
				*itemptr++ = 18 | (extra_bits << 5);
				run_start += 20 + extra_bits;
			}

			/* Symbol 17: RLE 4 to 19 zeroes at a time.  */
			if ((run_end - run_start) >= 4) {
				extra_bits = min((run_end - run_start) - 4, 0xf);
				precode_freqs[17]++;
				*itemptr++ = 17 | (extra_bits << 5);
				run_start += 4 + extra_bits;
			}
		} else {

			/* A run of nonzero lengths. */

			/* Symbol 19: RLE 4 to 5 of any length at a time.  */
			while ((run_end - run_start) >= 4) {
				extra_bits = (run_end - run_start) > 4;
				delta = prev_lens[run_start] - len;
				if (delta < 0)
					delta += 17;
				precode_freqs[19]++;
				precode_freqs[delta]++;
				*itemptr++ = 19 | (extra_bits << 5) | (delta << 6);
				run_start += 4 + extra_bits;
			}
		}

		/* Output any remaining lengths without RLE.  */
		while (run_start != run_end) {
			delta = prev_lens[run_start] - len;
			if (delta < 0)
				delta += 17;
			precode_freqs[delta]++;
			*itemptr++ = delta;
			run_start++;
		}
	} while (run_start != num_lens);

	return itemptr - precode_items;
}

/*
 * Output a Huffman code in the compressed form used in LZX.
 *
 * The Huffman code is represented in the output as a logical series of codeword
 * lengths from which the Huffman code, which must be in canonical form, can be
 * reconstructed.
 *
 * The codeword lengths are themselves compressed using a separate Huffman code,
 * the "precode", which contains a symbol for each possible codeword length in
 * the larger code as well as several special symbols to represent repeated
 * codeword lengths (a form of run-length encoding).  The precode is itself
 * constructed in canonical form, and its codeword lengths are represented
 * literally in 20 4-bit fields that immediately precede the compressed codeword
 * lengths of the larger code.
 *
 * Furthermore, the codeword lengths of the larger code are actually represented
 * as deltas from the codeword lengths of the corresponding code in the previous
 * block.
 *
 * @os:
 *	Bitstream to which to write the compressed Huffman code.
 * @lens:
 *	The codeword lengths, indexed by symbol, in the Huffman code.
 * @prev_lens:
 *	The codeword lengths, indexed by symbol, in the corresponding Huffman
 *	code in the previous block, or all zeroes if this is the first block.
 * @num_lens:
 *	The number of symbols in the Huffman code.
 */
static void
lzx_write_compressed_code(struct lzx_output_bitstream *os,
			  const u8 lens[restrict],
			  const u8 prev_lens[restrict],
			  unsigned num_lens)
{
	u32 precode_freqs[LZX_PRECODE_NUM_SYMBOLS];
	u8 precode_lens[LZX_PRECODE_NUM_SYMBOLS];
	u32 precode_codewords[LZX_PRECODE_NUM_SYMBOLS];
	unsigned precode_items[num_lens];
	unsigned num_precode_items;
	unsigned precode_item;
	unsigned precode_sym;
	unsigned i;

	for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++)
		precode_freqs[i] = 0;

	/* Compute the "items" (RLE / literal tokens and extra bits) with which
	 * the codeword lengths in the larger code will be output.  */
	num_precode_items = lzx_compute_precode_items(lens,
						      prev_lens,
						      num_lens,
						      precode_freqs,
						      precode_items);

	/* Build the precode.  */
	make_canonical_huffman_code(LZX_PRECODE_NUM_SYMBOLS,
				    LZX_MAX_PRE_CODEWORD_LEN,
				    precode_freqs, precode_lens,
				    precode_codewords);

	/* Output the lengths of the codewords in the precode.  */
	for (i = 0; i < LZX_PRECODE_NUM_SYMBOLS; i++)
		lzx_write_bits(os, precode_lens[i], LZX_PRECODE_ELEMENT_SIZE);

	/* Output the encoded lengths of the codewords in the larger code.  */
	for (i = 0; i < num_precode_items; i++) {
		precode_item = precode_items[i];
		precode_sym = precode_item & 0x1F;
		lzx_write_varbits(os, precode_codewords[precode_sym],
				  precode_lens[precode_sym],
				  LZX_MAX_PRE_CODEWORD_LEN);
		if (precode_sym >= 17) {
			if (precode_sym == 17) {
				lzx_write_bits(os, precode_item >> 5, 4);
			} else if (precode_sym == 18) {
				lzx_write_bits(os, precode_item >> 5, 5);
			} else {
				lzx_write_bits(os, (precode_item >> 5) & 1, 1);
				precode_sym = precode_item >> 6;
				lzx_write_varbits(os, precode_codewords[precode_sym],
						  precode_lens[precode_sym],
						  LZX_MAX_PRE_CODEWORD_LEN);
			}
		}
	}
}

/* Output a match or literal.  */
static inline void
lzx_write_item(struct lzx_output_bitstream *os, struct lzx_item item,
	       unsigned ones_if_aligned, const struct lzx_codes *codes)
{
	u64 data = item.data;
	unsigned main_symbol;
	unsigned len_symbol;
	unsigned num_extra_bits;
	u32 extra_bits;

	main_symbol = data & 0x3FF;

	lzx_write_varbits(os, codes->codewords.main[main_symbol],
			  codes->lens.main[main_symbol],
			  LZX_MAX_MAIN_CODEWORD_LEN);

	if (main_symbol < LZX_NUM_CHARS)  /* Literal?  */
		return;

	len_symbol = (data >> 10) & 0xFF;

	if (len_symbol != LZX_LENCODE_NUM_SYMBOLS) {
		lzx_write_varbits(os, codes->codewords.len[len_symbol],
				  codes->lens.len[len_symbol],
				  LZX_MAX_LEN_CODEWORD_LEN);
	}

	num_extra_bits = (data >> 18) & 0x1F;
	if (num_extra_bits == 0)  /* Small offset or repeat offset match?  */
		return;

	extra_bits = data >> 23;

	/*if (block_type == LZX_BLOCKTYPE_ALIGNED && num_extra_bits >= 3) {*/
	if ((num_extra_bits & ones_if_aligned) >= 3) {

		/* Aligned offset blocks: The low 3 bits of the extra offset
		 * bits are Huffman-encoded using the aligned offset code.  The
		 * remaining bits are output literally.  */

		lzx_write_varbits(os, extra_bits >> 3, num_extra_bits - 3, 14);

		lzx_write_varbits(os, codes->codewords.aligned[extra_bits & 7],
				  codes->lens.aligned[extra_bits & 7],
				  LZX_MAX_ALIGNED_CODEWORD_LEN);
	} else {
		/* Verbatim blocks, or fewer than 3 extra bits:  All extra
		 * offset bits are output literally.  */
		lzx_write_varbits(os, extra_bits, num_extra_bits, 17);
	}
}

/*
 * Write all matches and literal bytes (which were precomputed) in an LZX
 * compressed block to the output bitstream in the final compressed
 * representation.
 *
 * @os
 *	The output bitstream.
 * @block_type
 *	The chosen type of the LZX compressed block (LZX_BLOCKTYPE_ALIGNED or
 *	LZX_BLOCKTYPE_VERBATIM).
 * @items
 *	The array of matches/literals to output.
 * @num_items
 *	Number of matches/literals to output (length of @items).
 * @codes
 *	The main, length, and aligned offset Huffman codes for the current
 *	LZX compressed block.
 */
static void
lzx_write_items(struct lzx_output_bitstream *os, int block_type,
		const struct lzx_item items[], u32 num_items,
		const struct lzx_codes *codes)
{
	unsigned ones_if_aligned = 0U - (block_type == LZX_BLOCKTYPE_ALIGNED);

	for (u32 i = 0; i < num_items; i++)
		lzx_write_item(os, items[i], ones_if_aligned, codes);
}

static void
lzx_write_compressed_block(int block_type,
			   u32 block_size,
			   unsigned window_order,
			   unsigned num_main_syms,
			   const struct lzx_item chosen_items[],
			   u32 num_chosen_items,
			   const struct lzx_codes * codes,
			   const struct lzx_lens * prev_lens,
			   struct lzx_output_bitstream * os)
{
	LZX_ASSERT(block_type == LZX_BLOCKTYPE_ALIGNED ||
		   block_type == LZX_BLOCKTYPE_VERBATIM);

	/* The first three bits indicate the type of block and are one of the
	 * LZX_BLOCKTYPE_* constants.  */
	lzx_write_bits(os, block_type, 3);

	/* Output the block size.
	 *
	 * The original LZX format seemed to always encode the block size in 3
	 * bytes.  However, the implementation in WIMGAPI, as used in WIM files,
	 * uses the first bit to indicate whether the block is the default size
	 * (32768) or a different size given explicitly by the next 16 bits.
	 *
	 * By default, this compressor uses a window size of 32768 and therefore
	 * follows the WIMGAPI behavior.  However, this compressor also supports
	 * window sizes greater than 32768 bytes, which do not appear to be
	 * supported by WIMGAPI.  In such cases, we retain the default size bit
	 * to mean a size of 32768 bytes but output non-default block size in 24
	 * bits rather than 16.  The compatibility of this behavior is unknown
	 * because WIMs created with chunk size greater than 32768 can seemingly
	 * only be opened by wimlib anyway.  */
	if (block_size == LZX_DEFAULT_BLOCK_SIZE) {
		lzx_write_bits(os, 1, 1);
	} else {
		lzx_write_bits(os, 0, 1);

		if (window_order >= 16)
			lzx_write_bits(os, block_size >> 16, 8);

		lzx_write_bits(os, block_size & 0xFFFF, 16);
	}

	/* If it's an aligned offset block, output the aligned offset code.  */
	if (block_type == LZX_BLOCKTYPE_ALIGNED) {
		for (int i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
			lzx_write_bits(os, codes->lens.aligned[i],
				       LZX_ALIGNEDCODE_ELEMENT_SIZE);
		}
	}

	/* Output the main code (two parts).  */
	lzx_write_compressed_code(os, codes->lens.main,
				  prev_lens->main,
				  LZX_NUM_CHARS);
	lzx_write_compressed_code(os, codes->lens.main + LZX_NUM_CHARS,
				  prev_lens->main + LZX_NUM_CHARS,
				  num_main_syms - LZX_NUM_CHARS);

	/* Output the length code.  */
	lzx_write_compressed_code(os, codes->lens.len,
				  prev_lens->len,
				  LZX_LENCODE_NUM_SYMBOLS);

	/* Output the compressed matches and literals.  */
	lzx_write_items(os, block_type, chosen_items, num_chosen_items, codes);
}

/* Given the frequencies of symbols in an LZX-compressed block and the
 * corresponding Huffman codes, return LZX_BLOCKTYPE_ALIGNED or
 * LZX_BLOCKTYPE_VERBATIM if an aligned offset or verbatim block, respectively,
 * will take fewer bits to output.  */
static int
lzx_choose_verbatim_or_aligned(const struct lzx_freqs * freqs,
			       const struct lzx_codes * codes)
{
	u32 aligned_cost = 0;
	u32 verbatim_cost = 0;

	/* A verbatim block requires 3 bits in each place that an aligned symbol
	 * would be used in an aligned offset block.  */
	for (unsigned i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++) {
		verbatim_cost += 3 * freqs->aligned[i];
		aligned_cost += codes->lens.aligned[i] * freqs->aligned[i];
	}

	/* Account for output of the aligned offset code.  */
	aligned_cost += LZX_ALIGNEDCODE_ELEMENT_SIZE * LZX_ALIGNEDCODE_NUM_SYMBOLS;

	if (aligned_cost < verbatim_cost)
		return LZX_BLOCKTYPE_ALIGNED;
	else
		return LZX_BLOCKTYPE_VERBATIM;
}

/*
 * Finish an LZX block:
 *
 * - make the Huffman codes
 * - decide whether to output the block as VERBATIM or ALIGNED
 * - output the block
 * - swap the indices of the current and previous Huffman codes
 */
static void
lzx_finish_block(struct lzx_compressor *c, struct lzx_output_bitstream *os,
		 u32 block_size, u32 num_chosen_items)
{
	int block_type;

	lzx_make_huffman_codes(c);

	block_type = lzx_choose_verbatim_or_aligned(&c->freqs,
						    &c->codes[c->codes_index]);
	lzx_write_compressed_block(block_type,
				   block_size,
				   c->window_order,
				   c->num_main_syms,
				   c->chosen_items,
				   num_chosen_items,
				   &c->codes[c->codes_index],
				   &c->codes[c->codes_index ^ 1].lens,
				   os);
	c->codes_index ^= 1;
}

/* Return the offset slot for the specified offset, which must be
 * less than LZX_NUM_FAST_OFFSETS.  */
static inline unsigned
lzx_get_offset_slot_fast(struct lzx_compressor *c, u32 offset)
{
	LZX_ASSERT(offset < LZX_NUM_FAST_OFFSETS);
	return c->offset_slot_fast[offset];
}

/* Tally, and optionally record, the specified literal byte.  */
static inline void
lzx_declare_literal(struct lzx_compressor *c, unsigned literal,
		    struct lzx_item **next_chosen_item)
{
	unsigned main_symbol = literal;

	c->freqs.main[main_symbol]++;

	if (next_chosen_item) {
		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = main_symbol,
		};
	}
}

/* Tally, and optionally record, the specified repeat offset match.  */
static inline void
lzx_declare_repeat_offset_match(struct lzx_compressor *c,
				unsigned len, unsigned rep_index,
				struct lzx_item **next_chosen_item)
{
	unsigned len_header;
	unsigned main_symbol;
	unsigned len_symbol;

	if (len - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS) {
		len_header = len - LZX_MIN_MATCH_LEN;
		len_symbol = LZX_LENCODE_NUM_SYMBOLS;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_symbol = len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS;
		c->freqs.len[len_symbol]++;
	}

	main_symbol = LZX_NUM_CHARS + ((rep_index << 3) | len_header);

	c->freqs.main[main_symbol]++;

	if (next_chosen_item) {
		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = (u64)main_symbol | ((u64)len_symbol << 10),
		};
	}
}

/* Tally, and optionally record, the specified explicit offset match.  */
static inline void
lzx_declare_explicit_offset_match(struct lzx_compressor *c, unsigned len, u32 offset,
				  struct lzx_item **next_chosen_item)
{
	unsigned len_header;
	unsigned main_symbol;
	unsigned len_symbol;
	unsigned offset_slot;
	unsigned num_extra_bits;
	u32 extra_bits;

	if (len - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS) {
		len_header = len - LZX_MIN_MATCH_LEN;
		len_symbol = LZX_LENCODE_NUM_SYMBOLS;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;
		len_symbol = len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS;
		c->freqs.len[len_symbol]++;
	}

	offset_slot = lzx_get_offset_slot_raw(offset + LZX_OFFSET_OFFSET);

	main_symbol = LZX_NUM_CHARS + ((offset_slot << 3) | len_header);

	c->freqs.main[main_symbol]++;

	if (offset_slot >= 8)
		c->freqs.aligned[(offset + LZX_OFFSET_OFFSET) & 7]++;

	if (next_chosen_item) {

		num_extra_bits = lzx_extra_offset_bits[offset_slot];

		extra_bits = (offset + LZX_OFFSET_OFFSET) -
			     lzx_offset_slot_base[offset_slot];

		*(*next_chosen_item)++ = (struct lzx_item) {
			.data = (u64)main_symbol |
				((u64)len_symbol << 10) |
				((u64)num_extra_bits << 18) |
				((u64)extra_bits << 23),
		};
	}
}


/* Tally, and optionally record, the specified match or literal.  */
static inline void
lzx_declare_item(struct lzx_compressor *c, u32 item,
		 struct lzx_item **next_chosen_item)
{
	u32 len = item & OPTIMUM_LEN_MASK;
	u32 offset_data = item >> OPTIMUM_OFFSET_SHIFT;

	if (len == 1)
		lzx_declare_literal(c, offset_data, next_chosen_item);
	else if (offset_data < LZX_NUM_RECENT_OFFSETS)
		lzx_declare_repeat_offset_match(c, len, offset_data,
						next_chosen_item);
	else
		lzx_declare_explicit_offset_match(c, len,
						  offset_data - LZX_OFFSET_OFFSET,
						  next_chosen_item);
}

static inline void
lzx_record_item_list(struct lzx_compressor *c,
		     struct lzx_optimum_node *cur_node,
		     struct lzx_item **next_chosen_item)
{
	struct lzx_optimum_node *end_node;
	u32 saved_item;
	u32 item;

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

	/* Walk the list of items from beginning to end, tallying and recording
	 * each item.  */
	do {
		lzx_declare_item(c, cur_node->item, next_chosen_item);
		cur_node += (cur_node->item) & OPTIMUM_LEN_MASK;
	} while (cur_node != end_node);
}

static inline void
lzx_tally_item_list(struct lzx_compressor *c, struct lzx_optimum_node *cur_node)
{
	/* Since we're just tallying the items, we don't need to reverse the
	 * list.  Processing the items in reverse order is fine.  */
	do {
		lzx_declare_item(c, cur_node->item, NULL);
		cur_node -= (cur_node->item & OPTIMUM_LEN_MASK);
	} while (cur_node != c->optimum_nodes);
}

/* Return the cost, in bits, to output a literal byte using the specified cost
 * model.  */
static inline u32
lzx_literal_cost(unsigned literal, const struct lzx_costs * costs)
{
	return costs->main[literal];
}

/* Return the cost, in bits, to output a match of the specified length and
 * offset slot using the specified cost model.  Does not take into account
 * extra offset bits.  */
static inline u32
lzx_match_cost_raw(unsigned len, unsigned offset_slot,
		   const struct lzx_costs *costs)
{
	u32 cost;
	unsigned len_header;
	unsigned main_symbol;

	if (len - LZX_MIN_MATCH_LEN < LZX_NUM_PRIMARY_LENS) {
		len_header = len - LZX_MIN_MATCH_LEN;
		cost = 0;
	} else {
		len_header = LZX_NUM_PRIMARY_LENS;

		/* Account for length symbol.  */
		cost = costs->len[len - LZX_MIN_MATCH_LEN - LZX_NUM_PRIMARY_LENS];
	}

	/* Account for main symbol.  */
	main_symbol = LZX_NUM_CHARS + ((offset_slot << 3) | len_header);
	cost += costs->main[main_symbol];

	return cost;
}

/* Equivalent to lzx_match_cost_raw(), but assumes the length is small enough
 * that it doesn't require a length symbol.  */
static inline u32
lzx_match_cost_raw_smalllen(unsigned len, unsigned offset_slot,
			    const struct lzx_costs *costs)
{
	LZX_ASSERT(len < LZX_MIN_MATCH_LEN + LZX_NUM_PRIMARY_LENS);
	return costs->main[LZX_NUM_CHARS +
			   ((offset_slot << 3) | (len - LZX_MIN_MATCH_LEN))];
}

/*
 * Consider coding the match at repeat offset index @rep_idx.  Consider each
 * length from the minimum (2) to the full match length (@rep_len).
 */
static inline void
lzx_consider_repeat_offset_match(struct lzx_compressor *c,
				 struct lzx_optimum_node *cur_node,
				 unsigned rep_len, unsigned rep_idx)
{
	u32 base_cost = cur_node->cost;
	u32 cost;
	unsigned len;

#if 1   /* Optimized version */

	if (rep_len < LZX_MIN_MATCH_LEN + LZX_NUM_PRIMARY_LENS) {
		/* All lengths being considered are small.  */
		len = 2;
		do {
			cost = base_cost +
			       lzx_match_cost_raw_smalllen(len, rep_idx, &c->costs);
			if (cost < (cur_node + len)->cost) {
				(cur_node + len)->item =
					(rep_idx << OPTIMUM_OFFSET_SHIFT) | len;
				(cur_node + len)->cost = cost;
			}
		} while (++len <= rep_len);
	} else {
		/* Some lengths being considered are small, and some are big.
		 * Start with the optimized loop for small lengths, then switch
		 * to the optimized loop for big lengths.  */
		len = 2;
		do {
			cost = base_cost +
			       lzx_match_cost_raw_smalllen(len, rep_idx, &c->costs);
			if (cost < (cur_node + len)->cost) {
				(cur_node + len)->item =
					(rep_idx << OPTIMUM_OFFSET_SHIFT) | len;
				(cur_node + len)->cost = cost;
			}
		} while (++len < LZX_MIN_MATCH_LEN + LZX_NUM_PRIMARY_LENS);

		/* The main symbol is now fixed.  */
		base_cost += c->costs.main[LZX_NUM_CHARS +
					   ((rep_idx << 3) | LZX_NUM_PRIMARY_LENS)];
		do {
			cost = base_cost +
			       c->costs.len[len - LZX_MIN_MATCH_LEN -
					    LZX_NUM_PRIMARY_LENS];
			if (cost < (cur_node + len)->cost) {
				(cur_node + len)->item =
					(rep_idx << OPTIMUM_OFFSET_SHIFT) | len;
				(cur_node + len)->cost = cost;
			}
		} while (++len <= rep_len);
	}

#else   /* Unoptimized version  */

	len = 2;
	do {
		cost = base_cost +
		       lzx_match_cost_raw(len, rep_idx, &c->costs);
		if (cost < (cur_node + len)->cost) {
			(cur_node + len)->item =
				(rep_idx << OPTIMUM_OFFSET_SHIFT) | len;
			(cur_node + len)->cost = cost;
		}
	} while (++len <= rep_len);
#endif
}

static inline void
lzx_consider_explicit_offset_matches_fast(struct lzx_compressor *c,
					  struct lzx_optimum_node *cur_node,
					  const struct lz_match matches[],
					  unsigned num_matches)
{
	unsigned i;
	unsigned len;
	unsigned offset_slot;
	u32 position_cost;
	u32 cost;
	u32 offset_data;

	/*
	 * Offset is small; the offset slot can be looked up directly in
	 * c->offset_slot_fast.
	 *
	 * Additional optimizations:
	 *
	 * - Since the offset is small, it falls in the exponential part of the
	 *   offset slot bases and the number of extra offset bits can be
	 *   calculated directly as (offset_slot >> 1) - 1.
	 *
	 * - Just consider the number of extra offset bits; don't account for
	 *   the aligned offset code.  Usually this has very little effect on
	 *   the compression ratio.
	 *
	 * - Start out in a loop optimized for small lengths.  When the length
	 *   becomes high enough that a length symbol will be needed, jump into
	 *   a loop optimized for big lengths.
	 */

	LZX_ASSERT(matches[num_matches - 1].offset < LZX_NUM_FAST_OFFSETS);
	LZX_ASSERT(offset_slot <= 37); /* for extra bits formula  */

	len = 2;
	i = 0;
	do {
		offset_slot = lzx_get_offset_slot_fast(c, matches[i].offset);
		position_cost = cur_node->cost +
				(((offset_slot >> 1) - 1) << LZX_COST_SHIFT);
		offset_data = matches[i].offset + LZX_OFFSET_OFFSET;
		do {
			if (len >= LZX_MIN_MATCH_LEN + LZX_NUM_PRIMARY_LENS)
				goto biglen;
			cost = position_cost +
			       lzx_match_cost_raw_smalllen(len, offset_slot,
							   &c->costs);
			if (cost < (cur_node + len)->cost) {
				(cur_node + len)->cost = cost;
				(cur_node + len)->item =
					(offset_data << OPTIMUM_OFFSET_SHIFT) | len;
			}
		} while (++len <= matches[i].length);
	} while (++i != num_matches);

	return;

	do {
		offset_slot = lzx_get_offset_slot_fast(c, matches[i].offset);
biglen:
		position_cost = cur_node->cost +
				(((offset_slot >> 1) - 1) << LZX_COST_SHIFT) +
				c->costs.main[LZX_NUM_CHARS +
					      ((offset_slot << 3) |
					       LZX_NUM_PRIMARY_LENS)];
		offset_data = matches[i].offset + LZX_OFFSET_OFFSET;
		do {
			cost = position_cost +
			       c->costs.len[len - LZX_MIN_MATCH_LEN -
					    LZX_NUM_PRIMARY_LENS];
			if (cost < (cur_node + len)->cost) {
				(cur_node + len)->cost = cost;
				(cur_node + len)->item =
					(offset_data << OPTIMUM_OFFSET_SHIFT) | len;
			}
		} while (++len <= matches[i].length);
	} while (++i != num_matches);
}

static inline void
lzx_consider_explicit_offset_matches_slow(struct lzx_compressor *c,
					  struct lzx_optimum_node *cur_node,
					  const struct lz_match matches[],
					  unsigned num_matches)
{
	unsigned len;
	unsigned i;
	u32 offset_data;
	unsigned offset_slot;
	u32 position_cost;
	u32 cost;

	len = 2;
	i = 0;
	do {

		offset_data = matches[i].offset + LZX_OFFSET_OFFSET;
		offset_slot = lzx_get_offset_slot_raw(offset_data);
		position_cost = cur_node->cost +
				(lzx_extra_offset_bits[offset_slot] << LZX_COST_SHIFT);
		do {
			cost = position_cost +
			       lzx_match_cost_raw(len, offset_slot, &c->costs);
			if (cost < (cur_node + len)->cost) {
				(cur_node + len)->cost = cost;
				(cur_node + len)->item =
					(offset_data << OPTIMUM_OFFSET_SHIFT) | len;
			}
		} while (++len <= matches[i].length);
	} while (++i != num_matches);
}

/*
 * Consider coding each match in @matches as an explicit offset match.
 *
 * @matches must be sorted by strictly increasing length and strictly increasing
 * offset.  This is guaranteed by the matchfinder.
 *
 * We consider each length from the minimum (2) to the longest
 * (matches[num_matches - 1].len).  For each length, we consider only the
 * smallest offset for which that length is available.  Although this is not
 * guaranteed to be optimal due to the possibility of a larger offset costing
 * less than a smaller offset to code, this is a very useful heuristic.
 */
static void
lzx_consider_explicit_offset_matches(struct lzx_compressor *c,
				     struct lzx_optimum_node *cur_node,
				     const struct lz_match matches[],
				     unsigned num_matches)
{
	LZX_ASSERT(num_matches > 0);

	if (matches[num_matches - 1].offset < LZX_NUM_FAST_OFFSETS)
		lzx_consider_explicit_offset_matches_fast(c, cur_node,
							  matches, num_matches);
	else
		lzx_consider_explicit_offset_matches_slow(c, cur_node,
							  matches, num_matches);
}

/*
 * Given a pointer to the current byte sequence and the current list of recent
 * (or "repeat") match offsets, find the longest repeat offset match.
 *
 * If no match of at least 2 bytes is found, then return 0.
 *
 * If a match of at least 2 bytes is found, then return its length and set
 * *rep_max_idx_ret to the index of its offset in @queue.
*/
static unsigned
lzx_find_longest_repeat_offset_match(const u8 * const in_next,
				     const u32 bytes_remaining,
				     struct lzx_lru_queue queue,
				     unsigned *rep_max_idx_ret)
{
	BUILD_BUG_ON(LZX_NUM_RECENT_OFFSETS != 3);
	LZX_ASSERT(bytes_remaining >= 2);

	const unsigned max_len = min(bytes_remaining, LZX_MAX_MATCH_LEN);
	const u16 next_2_bytes = load_u16_unaligned(in_next);
	const u8 *matchptr;
	unsigned rep_max_len;
	unsigned rep_max_idx;
	unsigned rep_len;

	matchptr = in_next - lzx_lru_queue_pop(&queue);
	if (load_u16_unaligned(matchptr) == next_2_bytes)
		rep_max_len = lz_extend(in_next, matchptr, 2, max_len);
	else
		rep_max_len = 0;
	rep_max_idx = 0;

	matchptr = in_next - lzx_lru_queue_pop(&queue);
	if (load_u16_unaligned(matchptr) == next_2_bytes) {
		rep_len = lz_extend(in_next, matchptr, 2, max_len);
		if (rep_len > rep_max_len) {
			rep_max_len = rep_len;
			rep_max_idx = 1;
		}
	}

	matchptr = in_next - lzx_lru_queue_pop(&queue);
	if (load_u16_unaligned(matchptr) == next_2_bytes) {
		rep_len = lz_extend(in_next, matchptr, 2, max_len);
		if (rep_len > rep_max_len) {
			rep_max_len = rep_len;
			rep_max_idx = 2;
		}
	}

	*rep_max_idx_ret = rep_max_idx;
	return rep_max_len;
}

/*
 * Find an inexpensive path through the graph of possible match/literal choices
 * for the current block.  The nodes of the graph are
 * c->optimum_nodes[0...block_size].  They correspond directly to the bytes in
 * the current block, plus one extra node for end-of-block.  The edges of the
 * graph are matches and literals.  The goal is to find the minimum cost path
 * from 'c->optimum_nodes[0]' to 'c->optimum_nodes[block_size]'.
 *
 * The algorithm works forwards, starting at 'c->optimum_nodes[0]' and
 * proceeding forwards one node at a time.  At each node, a selection of matches
 * (len >= 2), as well as the literal byte (len = 1), is considered.  An item of
 * length 'len' provides a new path to reach the node 'len' bytes later.  If
 * such a path is the lowest cost found so far to reach that later node, then
 * that later node is updated with the new path.
 *
 * Note that although this algorithm is based on minimum cost path search, due
 * to various simplifying assumptions the result is not guaranteed to be the
 * true minimum cost, or "optimal", path over the graph of all valid LZX
 * representations of this block.
 *
 * Also, note that because of the presence of the recent offsets queue (which is
 * a type of adaptive state), the algorithm cannot work backwards and compute
 * "cost to end" instead of "cost to beginning".  Furthermore, the way the
 * algorithm handles this adaptive state in the "minimum-cost" parse is actually
 * only an approximation.  It's possible for the globally optimal, minimum cost
 * path to contain a prefix, ending at a position, where that path prefix is
 * *not* the minimum cost path to that position.  This can happen if such a path
 * prefix results in a different adaptive state which results in lower costs
 * later.  The algorithm does not solve this problem; it only considers the
 * lowest cost to reach each individual position.
 */
static struct lzx_lru_queue
lzx_optim_pass(struct lzx_compressor * const restrict c,
	       const u8 * const restrict block_begin,
	       const u32 block_size,
	       const struct lzx_lru_queue initial_queue)
{
	struct lzx_optimum_node *cur_node = c->optimum_nodes;
	struct lzx_optimum_node * const end_node = &c->optimum_nodes[block_size];
	struct lz_match *cache_ptr = c->match_cache;
	const u8 *in_next = block_begin;
	const u8 * const block_end = block_begin + block_size;

	/* Instead of storing the match offset LRU queues in the
	 * 'lzx_optimum_node' structures, we save memory (and cache lines) by
	 * storing them in a smaller array.  This works because the algorithm
	 * only requires a limited history of the adaptive state.  Once a given
	 * state is more than LZX_MAX_MATCH_LEN bytes behind the current node,
	 * it is no longer needed.  */
	struct lzx_lru_queue queues[512];

	BUILD_BUG_ON(ARRAY_LEN(queues) < LZX_MAX_MATCH_LEN + 1);
#define QUEUE(in) (queues[(uintptr_t)(in) % ARRAY_LEN(queues)])

	/* Initially, the cost to reach each node is "infinity".  */
	for (u32 i = 0; i <= block_size; i++)
		c->optimum_nodes[i].cost = INFINITE_COST;

	QUEUE(block_begin) = initial_queue;

	/* The following loop runs 'block_size' iterations, one per node.  */
	do {
		unsigned num_matches;
		unsigned literal;
		u32 cost;
		unsigned len;
		u32 offset_data;

		/*
		 * The matches for the block were already saved in 'match_cache'
		 * so that we don't have to run the uncompressed data through
		 * the matchfinder on every optimization pass.
		 *
		 * However, we still search for repeat offset matches during
		 * each optimization pass because we cannot, in general, predict
		 * the state of the recent offsets queue.
		 */

		num_matches = cache_ptr->length;
		cache_ptr++;

		if (num_matches) {
			unsigned rep_max_len;
			unsigned rep_max_idx;

			if (cache_ptr[num_matches-1].offset == lzx_lru_queue_R0(QUEUE(in_next))) {
				lzx_consider_repeat_offset_match(c, cur_node,
								 cache_ptr[num_matches-1].length, 0);
			} else {

				/*
				 * Find the longest repeat offset match with the current
				 * position.
				 *
				 * Heuristics:
				 *
				 * - Only search for repeat offset matches if the
				 *   matchfinder already found at least one match.
				 *
				 * - Only consider the longest repeat offset match.  It
				 *   seems to be rare for the minimum cost path to
				 *   include a repeat offset match that doesn't have the
				 *   longest length (allowing for the possibility that
				 *   not all of that length is actually used).
				 */
				rep_max_len =
					lzx_find_longest_repeat_offset_match(in_next,
									     block_end - in_next,
									     QUEUE(in_next),
									     &rep_max_idx);
				/* If we found a repeat offset match, consider coding it.  */
				if (rep_max_len) {
					lzx_consider_repeat_offset_match(c,
									 cur_node,
									 rep_max_len,
									 rep_max_idx);
				}

				/* Consider coding an explicit offset match.  */
				lzx_consider_explicit_offset_matches(c, cur_node,
								     cache_ptr, num_matches);
			}


			cache_ptr += num_matches;
		}

		/* Consider coding a literal.

		 * To avoid an extra brench, actually checking the preferability
		 * of coding the literal is integrated into the queue update
		 * code below.  */
		literal = *in_next++;
		cost = cur_node->cost + lzx_literal_cost(literal, &c->costs);

		/* Advance to the next position.  */
		cur_node++;

		/* The lowest-cost path to the current position is now known.
		 * Finalize the recent offsets queue that results from taking
		 * this lowest-cost path.  */

		if (cost < cur_node->cost) {
			/* Literal: queue remains unchanged.  */
			cur_node->cost = cost;
			cur_node->item = (literal << OPTIMUM_OFFSET_SHIFT) | 1;
			QUEUE(in_next) = QUEUE(in_next - 1);
		} else {
			/* Match: queue update is needed.  */
			len = cur_node->item & OPTIMUM_LEN_MASK;
			offset_data = cur_node->item >> OPTIMUM_OFFSET_SHIFT;
			if (offset_data >= LZX_NUM_RECENT_OFFSETS) {
				/* Explicit offset match: offset is inserted at front  */
				QUEUE(in_next) =
					lzx_lru_queue_push(QUEUE(in_next - len),
							   offset_data - LZX_OFFSET_OFFSET);
			} else {
				/* Repeat offset match: offset is swapped to front  */
				QUEUE(in_next) =
					lzx_lru_queue_swap(QUEUE(in_next - len),
							   offset_data);
			}
		}
	} while (cur_node != end_node);

	/* Return the match offset queue at the end of the minimum-cost path. */
	return QUEUE(block_end);
}

/* Set default LZX Huffman symbol costs to bootstrap the iterative optimization
 * algorithm.  */
static void
lzx_set_default_costs(struct lzx_compressor *c, const u8 *block, u32 block_size)
{
	u32 i;
	bool have_byte[256];
	u32 num_used;

	/* The costs below are hard coded to use a scaling factor of 16.  */
	BUILD_BUG_ON(LZX_COST_SHIFT != 4);

	/*
	 * Heuristics:
	 *
	 * - Use smaller initial costs for literal symbols when the input buffer
	 *   contains fewer distinct bytes.
	 *
	 * - Assume that match symbols are more costly than literal symbols.
	 */

	for (i = 0; i < 256; i++)
		have_byte[i] = false;

	for (i = 0; i < block_size; i++)
		have_byte[block[i]] = true;

	num_used = 0;
	for (i = 0; i < 256; i++)
		num_used += have_byte[i];

	for (i = 0; i < 256; i++)
		c->costs.main[i] = 140 - (256 - num_used) / 4;

	for (; i < c->num_main_syms; i++)
		c->costs.main[i] = 170;

	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		c->costs.len[i] = 103 + (i / 4);

	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		c->costs.aligned[i] = 48;
}

/* Update the current cost model to reflect the computed Huffman codes.  */
static void
lzx_update_costs(struct lzx_compressor *c)
{
	unsigned i;
	const struct lzx_lens *lens = &c->codes[c->codes_index].lens;

	for (i = 0; i < c->num_main_syms; i++)
		c->costs.main[i] = (lens->main[i] ? lens->main[i] : 15)
				<< LZX_COST_SHIFT;

	for (i = 0; i < LZX_LENCODE_NUM_SYMBOLS; i++)
		c->costs.len[i] = (lens->len[i] ? lens->len[i] : 15)
				<< LZX_COST_SHIFT;

	for (i = 0; i < LZX_ALIGNEDCODE_NUM_SYMBOLS; i++)
		c->costs.aligned[i] = (lens->aligned[i] ? lens->aligned[i] : 7)
				<< LZX_COST_SHIFT;
}

static struct lzx_lru_queue
lzx_optimize_and_write_block(struct lzx_compressor *c,
			     struct lzx_output_bitstream *os,
			     const u8 *block_begin, const u32 block_size,
			     const struct lzx_lru_queue initial_queue)
{
	unsigned num_passes_remaining = c->num_optim_passes;
	struct lzx_item *next_chosen_item;
	struct lzx_lru_queue new_queue;

	/* The first optimization pass uses a default cost model.  Each
	 * additional optimization pass uses a cost model derived from the
	 * Huffman code computed in the previous pass.  */

	lzx_set_default_costs(c, block_begin, block_size);
	lzx_reset_symbol_frequencies(c);
	do {
		new_queue = lzx_optim_pass(c, block_begin, block_size,
					   initial_queue);
		if (num_passes_remaining > 1) {
			lzx_tally_item_list(c, c->optimum_nodes + block_size);
			lzx_make_huffman_codes(c);
			lzx_update_costs(c);
			lzx_reset_symbol_frequencies(c);
		}
	} while (--num_passes_remaining);

	next_chosen_item = c->chosen_items;
	lzx_record_item_list(c, c->optimum_nodes + block_size, &next_chosen_item);
	lzx_finish_block(c, os, block_size, next_chosen_item - c->chosen_items);
	return new_queue;
}

/*
 * This is the "near-optimal" LZX compressor.
 *
 * For each block, it performs a relatively thorough graph search to find an
 * inexpensive (in terms of compressed size) way to output that block.
 *
 * Note: there are actually many things this algorithm leaves on the table in
 * terms of compression ratio.  So although it may be "near-optimal", it is
 * certainly not "optimal".  The goal is not to produce the optimal compression
 * ratio, which for LZX is probably impossible within any practical amount of
 * time, but rather to produce a compression ratio significantly better than a
 * simpler "greedy" or "lazy" parse while still being relatively fast.
 */
static void
lzx_compress_near_optimal(struct lzx_compressor *c,
			  struct lzx_output_bitstream *os)
{
	const u8 * const in_begin = c->in_buffer;
	const u8 *	 in_next = in_begin;
	const u8 * const in_end  = in_begin + c->in_nbytes;
	unsigned max_len = LZX_MAX_MATCH_LEN;
	unsigned nice_len = min(c->nice_match_length, max_len);
	u32 next_hash;
	struct lzx_lru_queue queue;

	bt_matchfinder_init(&c->bt_mf);
	matchfinder_init(c->hash2_tab, LZX_HASH2_LENGTH);
	if (in_end - in_next >= 3)
		next_hash = bt_matchfinder_hash_3_bytes(in_next);
	lzx_lru_queue_init(&queue);

	do {
		/* Starting a new block  */
		const u8 * const in_block_begin = in_next;
		const u8 * const in_block_end =
			in_next + min(LZX_DIV_BLOCK_SIZE, in_end - in_next);

		/* Run the block through the matchfinder and cache the matches. */
		struct lz_match *cache_ptr = c->match_cache;
		do {
			struct lz_match *lz_matchptr;
			u32 hash2;
			pos_t cur_match;
			unsigned best_len;

			/* If approaching the end of the input buffer, adjust
			 * 'max_len' and 'nice_len' accordingly.  */
			if (unlikely(max_len > in_end - in_next)) {
				max_len = in_end - in_next;
				nice_len = min(max_len, nice_len);
				if (unlikely(max_len < LZ_HASH_REQUIRED_NBYTES + 1)) {
					in_next++;
					cache_ptr->length = 0;
					cache_ptr++;
					continue;
				}
			}

			lz_matchptr = cache_ptr + 1;

			/* Check for a length 2 match.  */
			hash2 = lz_hash_2_bytes(in_next);
			cur_match = c->hash2_tab[hash2];
			c->hash2_tab[hash2] = in_next - in_begin;
			if (matchfinder_node_valid(cur_match) &&
			    (LZX_HASH2_ORDER == 16 ||
			     load_u16_unaligned(&in_begin[cur_match]) ==
			     load_u16_unaligned(in_next)) &&
			    in_begin[cur_match + 2] != in_next[2])
			{
				lz_matchptr->length = 2;
				lz_matchptr->offset = in_next - &in_begin[cur_match];
				lz_matchptr++;
			}

			/* Check for matches of length >= 3.  */
			lz_matchptr = bt_matchfinder_get_matches(&c->bt_mf,
								 in_begin,
								 in_next,
								 3,
								 max_len,
								 nice_len,
								 c->max_search_depth,
								 &next_hash,
								 &best_len,
								 lz_matchptr);
			in_next++;
			cache_ptr->length = lz_matchptr - (cache_ptr + 1);
			cache_ptr = lz_matchptr;

			/*
			 * If there was a very long match found, then don't
			 * cache any matches for the bytes covered by that
			 * match.  This avoids degenerate behavior when
			 * compressing highly redundant data, where the number
			 * of matches can be very large.
			 *
			 * This heuristic doesn't actually hurt the compression
			 * ratio very much.  If there's a long match, then the
			 * data must be highly compressible, so it doesn't
			 * matter as much what we do.
			 */
			if (best_len >= nice_len) {
				--best_len;
				do {
					if (unlikely(max_len > in_end - in_next)) {
						max_len = in_end - in_next;
						nice_len = min(max_len, nice_len);
						if (unlikely(max_len < LZ_HASH_REQUIRED_NBYTES + 1)) {
							in_next++;
							cache_ptr->length = 0;
							cache_ptr++;
							continue;
						}
					}
					c->hash2_tab[lz_hash_2_bytes(in_next)] =
						in_next - in_begin;
					bt_matchfinder_skip_position(&c->bt_mf,
								     in_begin,
								     in_next,
								     in_end,
								     nice_len,
								     c->max_search_depth,
								     &next_hash);
					in_next++;
					cache_ptr->length = 0;
					cache_ptr++;
				} while (--best_len);
			}
		} while (in_next < in_block_end &&
			 likely(cache_ptr < c->cache_overflow_mark));

		/* We've finished running the block through the matchfinder.
		 * Now choose a match/literal sequence and write the block.  */

		queue = lzx_optimize_and_write_block(c, os, in_block_begin,
						     in_next - in_block_begin,
						     queue);
	} while (in_next != in_end);
}

/* Fast heuristic scoring for lazy parsing: how "good" is this match?  */
static inline unsigned
lzx_explicit_offset_match_score(unsigned len, u32 adjusted_offset)
{
	unsigned score = len;

	if (adjusted_offset < 4096)
		score++;

	if (adjusted_offset < 256)
		score++;

	return score;
}

static inline unsigned
lzx_repeat_offset_match_score(unsigned rep_len, unsigned rep_idx)
{
	return rep_len + 3;
}

/* This is the "lazy" LZX compressor.  */
static void
lzx_compress_lazy(struct lzx_compressor *c, struct lzx_output_bitstream *os)
{
	const u8 * const in_begin = c->in_buffer;
	const u8 *	 in_next = in_begin;
	const u8 * const in_end  = in_begin + c->in_nbytes;
	unsigned max_len = LZX_MAX_MATCH_LEN;
	unsigned nice_len = min(c->nice_match_length, max_len);
	struct lzx_lru_queue queue;

	hc_matchfinder_init(&c->hc_mf);
	lzx_lru_queue_init(&queue);

	do {
		/* Starting a new block  */

		const u8 * const in_block_begin = in_next;
		const u8 * const in_block_end =
			in_next + min(LZX_DIV_BLOCK_SIZE, in_end - in_next);
		struct lzx_item *next_chosen_item = c->chosen_items;
		unsigned cur_len;
		u32 cur_offset;
		u32 cur_offset_data;
		unsigned cur_score;
		unsigned next_len;
		u32 next_offset;
		u32 next_offset_data;
		unsigned next_score;
		unsigned rep_max_len;
		unsigned rep_max_idx;
		unsigned rep_score;
		unsigned skip_len;

		lzx_reset_symbol_frequencies(c);

		do {
			if (unlikely(max_len > in_end - in_next)) {
				max_len = in_end - in_next;
				nice_len = min(max_len, nice_len);
			}

			/* Find the longest match at the current position.  */

			cur_len = hc_matchfinder_longest_match(&c->hc_mf,
							       in_begin,
							       in_next,
							       2,
							       max_len,
							       nice_len,
							       c->max_search_depth,
							       &cur_offset);
			if (cur_len < 3 ||
			    (cur_len == 3 &&
			     cur_offset >= 8192 - LZX_OFFSET_OFFSET &&
			     cur_offset != lzx_lru_queue_R0(queue) &&
			     cur_offset != lzx_lru_queue_R1(queue) &&
			     cur_offset != lzx_lru_queue_R2(queue)))
			{
				/* There was no match found, or the only match found
				 * was a distant length 3 match.  Output a literal.  */
				lzx_declare_literal(c, *in_next++,
						    &next_chosen_item);
				continue;
			}

			if (cur_offset == lzx_lru_queue_R0(queue)) {
				in_next++;
				cur_offset_data = 0;
				skip_len = cur_len - 1;
				goto output_cur_match;
			}

			cur_offset_data = cur_offset + LZX_OFFSET_OFFSET;
			cur_score = lzx_explicit_offset_match_score(cur_len, cur_offset_data);

			/* Consider a repeat offset match  */
			rep_max_len = lzx_find_longest_repeat_offset_match(in_next,
									   in_end - in_next,
									   queue,
									   &rep_max_idx);
			in_next++;

			if (rep_max_len >= 3 &&
			    (rep_score = lzx_repeat_offset_match_score(rep_max_len,
								       rep_max_idx)) >= cur_score)
			{
				cur_len = rep_max_len;
				cur_offset_data = rep_max_idx;
				skip_len = rep_max_len - 1;
				goto output_cur_match;
			}

		have_cur_match:

			/* We have a match at the current position.  */

			/* If we have a very long match, choose it immediately.  */
			if (cur_len >= nice_len) {
				skip_len = cur_len - 1;
				goto output_cur_match;
			}

			/* See if there's a better match at the next position.  */

			if (unlikely(max_len > in_end - in_next)) {
				max_len = in_end - in_next;
				nice_len = min(max_len, nice_len);
			}

			next_len = hc_matchfinder_longest_match(&c->hc_mf,
								in_begin,
								in_next,
								cur_len - 2,
								max_len,
								nice_len,
								c->max_search_depth / 2,
								&next_offset);

			if (next_len <= cur_len - 2) {
				in_next++;
				skip_len = cur_len - 2;
				goto output_cur_match;
			}

			next_offset_data = next_offset + LZX_OFFSET_OFFSET;
			next_score = lzx_explicit_offset_match_score(next_len, next_offset_data);

			rep_max_len = lzx_find_longest_repeat_offset_match(in_next,
									   in_end - in_next,
									   queue,
									   &rep_max_idx);
			in_next++;

			if (rep_max_len >= 3 &&
			    (rep_score = lzx_repeat_offset_match_score(rep_max_len,
								       rep_max_idx)) >= next_score)
			{

				if (rep_score > cur_score) {
					/* Next match is better, and it's a
					 * repeat offset match.  */
					lzx_declare_literal(c, *(in_next - 2), &next_chosen_item);
					cur_len = rep_max_len;
					cur_offset_data = rep_max_idx;
					skip_len = cur_len - 1;
					goto output_cur_match;
				} else {
					/* Next match is a repeat offset matche,
					 * but it is *not* better.  */
					skip_len = cur_len - 2;
					goto output_cur_match;
				}
			} else {
				if (next_score > cur_score) {
					/* The next match is better.  */
					lzx_declare_literal(c, *(in_next - 2), &next_chosen_item);
					cur_len = next_len;
					cur_offset_data = next_offset_data;
					cur_score = next_score;
					goto have_cur_match;
				} else {
					/* The original match was better.  */
					skip_len = cur_len - 2;
					goto output_cur_match;
				}
			}

		output_cur_match:
			if (cur_offset_data < LZX_NUM_RECENT_OFFSETS) {
				lzx_declare_repeat_offset_match(c, cur_len,
								cur_offset_data,
								&next_chosen_item);
				queue = lzx_lru_queue_swap(queue, cur_offset_data);
			} else {
				lzx_declare_explicit_offset_match(c, cur_len,
								  cur_offset_data - LZX_OFFSET_OFFSET,
								  &next_chosen_item);
				queue = lzx_lru_queue_push(queue, cur_offset_data - LZX_OFFSET_OFFSET);
			}

			hc_matchfinder_skip_positions(&c->hc_mf,
						      in_begin,
						      in_next,
						      in_end,
						      skip_len);
			in_next += skip_len;
		} while (in_next < in_block_end);

		lzx_finish_block(c, os, in_next - in_block_begin,
				 next_chosen_item - c->chosen_items);
	} while (in_next != in_end);
}

static void
lzx_init_offset_slot_fast(struct lzx_compressor *c)
{
	u8 slot = 0;

	for (u32 offset = 0; offset < LZX_NUM_FAST_OFFSETS; offset++) {

		while (offset + LZX_OFFSET_OFFSET >= lzx_offset_slot_base[slot + 1])
			slot++;

		c->offset_slot_fast[offset] = slot;
	}
}

static size_t
lzx_get_compressor_size(size_t max_bufsize, unsigned compression_level)
{
	if (compression_level <= LZX_MAX_FAST_LEVEL) {
		return offsetof(struct lzx_compressor, hc_mf) +
			hc_matchfinder_size(max_bufsize);
	} else {
		return offsetof(struct lzx_compressor, bt_mf) +
			bt_matchfinder_size(max_bufsize);
	}
}

static u64
lzx_get_needed_memory(size_t max_bufsize, unsigned compression_level)
{
	u64 size = 0;

	if (max_bufsize > LZX_MAX_WINDOW_SIZE)
		return 0;

	size += lzx_get_compressor_size(max_bufsize, compression_level);
	size += max_bufsize; /* in_buffer */
	return size;
}

static int
lzx_create_compressor(size_t max_bufsize, unsigned compression_level,
		      void **c_ret)
{
	unsigned window_order;
	struct lzx_compressor *c;

	window_order = lzx_get_window_order(max_bufsize);
	if (window_order == 0)
		return WIMLIB_ERR_INVALID_PARAM;

	c = ALIGNED_MALLOC(lzx_get_compressor_size(max_bufsize,
						   compression_level),
			   MATCHFINDER_ALIGNMENT);
	if (!c)
		goto oom0;

	c->num_main_syms = lzx_get_num_main_syms(window_order);
	c->window_order = window_order;

	c->in_buffer = MALLOC(max_bufsize);
	if (!c->in_buffer)
		goto oom1;

	if (compression_level <= LZX_MAX_FAST_LEVEL) {

		/* Fast compression: Use lazy parsing.  */

		c->impl = lzx_compress_lazy;
		c->max_search_depth = (36 * compression_level) / 20;
		c->nice_match_length = (72 * compression_level) / 20;

	} else {

		/* Normal / high compression: Use near-optimal parsing.  */

		c->impl = lzx_compress_near_optimal;

		/* Scale nice_match_length and max_search_depth with the
		 * compression level.  */
		c->max_search_depth = (24 * compression_level) / 50;
		c->nice_match_length = min((32 * compression_level) / 50,
					   LZX_MAX_MATCH_LEN);

		/* Set a number of optimization passes appropriate for the
		 * compression level.  */

		c->num_optim_passes = 1;

		if (compression_level >= 45)
			c->num_optim_passes++;

		/* Use more optimization passes for higher compression levels.
		 * But the more passes there are, the less they help --- so
		 * don't add them linearly.  */
		if (compression_level >= 70) {
			c->num_optim_passes++;
			if (compression_level >= 100)
				c->num_optim_passes++;
			if (compression_level >= 150)
				c->num_optim_passes++;
			if (compression_level >= 200)
				c->num_optim_passes++;
			if (compression_level >= 300)
				c->num_optim_passes++;
		}

		c->cache_overflow_mark = &c->match_cache[LZX_CACHE_LEN];
	}

	lzx_init_offset_slot_fast(c);
	*c_ret = c;
	return 0;

oom1:
	ALIGNED_FREE(c);
oom0:
	return WIMLIB_ERR_NOMEM;
}

static size_t
lzx_compress(const void *in, size_t in_nbytes,
	     void *out, size_t out_nbytes_avail, void *_c)
{
	struct lzx_compressor *c = _c;
	struct lzx_output_bitstream os;

	/* Don't bother trying to compress very small inputs.  */
	if (out_nbytes_avail < 100)
		return 0;

	/* Copy the input data into the internal buffer and preprocess it.  */
	memcpy(c->in_buffer, in, in_nbytes);
	c->in_nbytes = in_nbytes;
	lzx_do_e8_preprocessing(c->in_buffer, in_nbytes);

	/* Initially, the previous Huffman codeword lengths are all zeroes.  */
	c->codes_index = 0;
	memset(&c->codes[1].lens, 0, sizeof(struct lzx_lens));

	/* Initialize the output bitstream.  */
	lzx_init_output(&os, out, out_nbytes_avail);

	/* Call the compression level-specific compress() function.  */
	(*c->impl)(c, &os);

	/* Flush the output bitstream and return the compressed size or 0.  */
	return lzx_flush_output(&os);
}

static void
lzx_free_compressor(void *_c)
{
	struct lzx_compressor *c = _c;

	FREE(c->in_buffer);
	ALIGNED_FREE(c);
}

const struct compressor_ops lzx_compressor_ops = {
	.get_needed_memory  = lzx_get_needed_memory,
	.create_compressor  = lzx_create_compressor,
	.compress	    = lzx_compress,
	.free_compressor    = lzx_free_compressor,
};
