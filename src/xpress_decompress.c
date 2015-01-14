/*
 * xpress_decompress.c
 *
 * A decompressor for the XPRESS compression format (Huffman variant).
 */

/*
 *
 * Copyright (C) 2012, 2013, 2015 Eric Biggers
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
 * The XPRESS compression format is an LZ77 and Huffman-code based algorithm.
 * That means it is fairly similar to LZX compression, but XPRESS is simpler, so
 * it is a little faster to compress and decompress.
 *
 * The XPRESS compression format is mostly documented in a file called "[MS-XCA]
 * Xpress Compression Algorithm".  In the MSDN library, it can currently be
 * found under Open Specifications => Protocols => Windows Protocols => Windows
 * Server Protocols => [MS-XCA] Xpress Compression Algorithm".  The format in
 * WIMs is specifically the algorithm labeled as the "LZ77+Huffman Algorithm"
 * (there apparently are some other versions of XPRESS as well).
 *
 * If you are already familiar with the LZ77 algorithm and Huffman coding, the
 * XPRESS format is fairly simple.  The compressed data begins with 256 bytes
 * that contain 512 4-bit integers that are the lengths of the symbols in the
 * Huffman code used for match/literal headers.  In contrast with more
 * complicated formats such as DEFLATE and LZX, this is the only Huffman code
 * that is used for the entirety of the XPRESS compressed data, and the codeword
 * lengths are not encoded with a pretree.
 *
 * The rest of the compressed data is Huffman-encoded symbols.  Values 0 through
 * 255 represent the corresponding literal bytes.  Values 256 through 511
 * represent matches and may require extra bits or bytes to be read to get the
 * match offset and match length.
 *
 * The trickiest part is probably the way in which literal bytes for match
 * lengths are interleaved in the bitstream.
 *
 * Also, a caveat--- according to Microsoft's documentation for XPRESS,
 *
 *	"Some implementation of the decompression algorithm expect an extra
 *	symbol to mark the end of the data.  Specifically, some implementations
 *	fail during decompression if the Huffman symbol 256 is not found after
 *	the actual data."
 *
 * This is the case for the implementation in WIMGAPI.  However, wimlib's
 * decompressor in this file currently does not care if this extra symbol is
 * there or not.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>

#include "wimlib/decompressor_ops.h"
#include "wimlib/error.h"
#include "wimlib/unaligned.h"
#include "wimlib/xpress_constants.h"

/* This value is chosen for fast decompression.  */
#define XPRESS_TABLEBITS 12

typedef u32 bitbuf_t;
#define BITBUF_NBITS (8 * sizeof(bitbuf_t))

#define ENSURE_BITS(n)							\
({									\
	if (bitsleft < (n)) {						\
		if (likely(in_end - in_next >= 2)) {			\
			bitbuf |=					\
 				(bitbuf_t)get_unaligned_u16_le(in_next) \
					<< (16 - bitsleft);		\
			in_next += 2;					\
		}							\
		bitsleft += 16;						\
	}								\
})

#define BITS(n)								\
({									\
	bitbuf_t bits = 0;						\
	if (n)								\
		bits = bitbuf >> (BITBUF_NBITS - (n));			\
	bits;								\
})

#define REMOVE_BITS(n)							\
({									\
 	bitbuf <<= (n);							\
	bitsleft -= (n);						\
})

#define POP_BITS(n)							\
({									\
	bitbuf_t bits = BITS(n);					\
	REMOVE_BITS(n);							\
	bits;								\
})

#define READ_BYTE()							\
({									\
	u8 v = 0;							\
	if (likely(in_end != in_next))					\
		v = *in_next++;						\
	v;								\
})

#define READ_U16()							\
({									\
	u16 v = 0;							\
	if (likely(in_end - in_next >= 2)) {				\
		v = get_unaligned_u16_le(in_next);			\
		in_next += 2;						\
	}								\
	v;								\
})

#define USE_WORD_FILL

#ifdef __GNUC__
#  ifdef __SSE2__
#    undef USE_WORD_FILL
#    define USE_SSE2_FILL
#    include <emmintrin.h>
#  endif
#endif

/* Construct a direct mapping entry in the lookup table.  */
#define MAKE_DIRECT_ENTRY(symbol, length) ((symbol) | ((length) << 11))

#define DECODE_TABLE_ALIGNMENT 16

static int
make_huffman_decode_table(u16 decode_table[const restrict],
			  const unsigned num_syms,
			  const unsigned table_bits,
			  const u8 lens[const restrict],
			  const unsigned max_codeword_len)
{
	const unsigned table_num_entries = 1 << table_bits;
	unsigned len_counts[max_codeword_len + 1];
	u16 sorted_syms[num_syms];
	int left;
	void *decode_table_ptr;
	unsigned sym_idx;
	unsigned codeword_len;
	unsigned stores_per_loop;
	unsigned decode_table_pos;

#ifdef USE_WORD_FILL
	const unsigned entries_per_word = WORDSIZE / sizeof(decode_table[0]);
#endif

#ifdef USE_SSE2_FILL
	const unsigned entries_per_xmm = sizeof(__m128i) / sizeof(decode_table[0]);
#endif

	/* Count how many symbols have each possible codeword length.
	 * Note that a length of 0 indicates the corresponding symbol is not
	 * used in the code and therefore does not have a codeword.  */
	for (unsigned len = 0; len <= max_codeword_len; len++)
		len_counts[len] = 0;
	for (unsigned sym = 0; sym < num_syms; sym++)
		len_counts[lens[sym]]++;

	/* We can assume all lengths are <= max_codeword_len, but we
	 * cannot assume they form a valid prefix code.  A codeword of
	 * length n should require a proportion of the codespace equaling
	 * (1/2)^n.  The code is valid if and only if the codespace is
	 * exactly filled by the lengths, by this measure.  */
	left = 1;
	for (unsigned len = 1; len <= max_codeword_len; len++) {
		left <<= 1;
		left -= len_counts[len];
		if (unlikely(left < 0)) {
			/* The lengths overflow the codespace; that is, the code
			 * is over-subscribed.  */
			return -1;
		}
	}

	if (unlikely(left != 0)) {
		/* The lengths do not fill the codespace; that is, they form an
		 * incomplete set.  */
		if (left == (1 << max_codeword_len)) {
			/* The code is completely empty.  This is arguably
			 * invalid, but in fact it is valid in LZX and XPRESS,
			 * so we must allow it.  By definition, no symbols can
			 * be decoded with an empty code.  Consequently, we
			 * technically don't even need to fill in the decode
			 * table.  However, to avoid accessing uninitialized
			 * memory if the algorithm nevertheless attempts to
			 * decode symbols using such a code, we zero out the
			 * decode table.  */
			memset(decode_table, 0,
			       table_num_entries * sizeof(decode_table[0]));
			return 0;
		}
		return -1;
	}

	/* Sort the symbols primarily by length and secondarily by symbol order.
	 */
	{
		unsigned offsets[max_codeword_len + 1];

		/* Initialize 'offsets' so that offsets[len] for 1 <= len <=
		 * max_codeword_len is the number of codewords shorter than
		 * 'len' bits.  */
		offsets[1] = 0;
		for (unsigned len = 1; len < max_codeword_len; len++)
			offsets[len + 1] = offsets[len] + len_counts[len];

		/* Use the 'offsets' array to sort the symbols.
		 * Note that we do not include symbols that are not used in the
		 * code.  Consequently, fewer than 'num_syms' entries in
		 * 'sorted_syms' may be filled.  */
		for (unsigned sym = 0; sym < num_syms; sym++)
			if (lens[sym] != 0)
				sorted_syms[offsets[lens[sym]]++] = sym;
	}

	/* Fill entries for codewords with length <= table_bits
	 * --- that is, those short enough for a direct mapping.
	 *
	 * The table will start with entries for the shortest codeword(s), which
	 * have the most entries.  From there, the number of entries per
	 * codeword will decrease.  As an optimization, we may begin filling
	 * entries with SSE2 vector accesses (8 entries/store), then change to
	 * 'machine_word_t' accesses (2 or 4 entries/store), then change to
	 * 16-bit accesses (1 entry/store).  */
	decode_table_ptr = decode_table;
	sym_idx = 0;
	codeword_len = 1;
#ifdef USE_SSE2_FILL
	/* Fill the entries one 128-bit vector at a time.
	 * This is 8 entries per store.  */
	stores_per_loop = (1 << (table_bits - codeword_len)) / entries_per_xmm;
	for (; stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1) {
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {
			/* Note: unlike in the machine_word_t version below, the
			 * __m128i type already has __attribute__((may_alias)),
			 * so using it to access the decode table, which is an
			 * array of unsigned shorts, will not violate strict
			 * aliasing.  */
			u16 entry;
			__m128i v;
			__m128i *p;
			unsigned n;

			entry = MAKE_DIRECT_ENTRY(sorted_syms[sym_idx], codeword_len);

			v = _mm_set1_epi16(entry);
			p = (__m128i*)decode_table_ptr;
			n = stores_per_loop;
			do {
				*p++ = v;
			} while (--n);
			decode_table_ptr = p;
		}
	}
#endif /* USE_SSE2_FILL */

#ifdef USE_WORD_FILL
	/* Fill the entries one machine word at a time.
	 * On 32-bit systems this is 2 entries per store, while on 64-bit
	 * systems this is 4 entries per store.  */
	stores_per_loop = (1 << (table_bits - codeword_len)) / entries_per_word;
	for (; stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1) {
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {

			/* Accessing the array of u16 as u32 or u64 would
			 * violate strict aliasing and would require compiling
			 * the code with -fno-strict-aliasing to guarantee
			 * correctness.  To work around this problem, use the
			 * gcc 'may_alias' extension.  */
			typedef machine_word_t _may_alias_attribute aliased_word_t;

			machine_word_t v;
			aliased_word_t *p;
			unsigned n;

			BUILD_BUG_ON(WORDSIZE != 4 && WORDSIZE != 8);

			v = MAKE_DIRECT_ENTRY(sorted_syms[sym_idx], codeword_len);
			v |= v << 16;
			v |= v << (WORDSIZE == 8 ? 32 : 0);

			p = (aliased_word_t *)decode_table_ptr;
			n = stores_per_loop;

			do {
				*p++ = v;
			} while (--n);
			decode_table_ptr = p;
		}
	}
#endif /* USE_WORD_FILL */

	/* Fill the entries one 16-bit integer at a time.  */
	stores_per_loop = (1 << (table_bits - codeword_len));
	for (; stores_per_loop != 0; codeword_len++, stores_per_loop >>= 1) {
		unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
		for (; sym_idx < end_sym_idx; sym_idx++) {
			u16 entry;
			u16 *p;
			unsigned n;

			entry = MAKE_DIRECT_ENTRY(sorted_syms[sym_idx], codeword_len);

			p = (u16*)decode_table_ptr;
			n = stores_per_loop;

			do {
				*p++ = entry;
			} while (--n);

			decode_table_ptr = p;
		}
	}

	/* If we've filled in the entire table, we are done.  Otherwise,
	 * there are codewords longer than table_bits for which we must
	 * generate binary trees.  */

	decode_table_pos = (u16*)decode_table_ptr - decode_table;
	if (decode_table_pos != table_num_entries) {
		unsigned j;
		unsigned next_free_tree_slot;
		unsigned cur_codeword;

		/* First, zero out the remaining entries.  This is
		 * necessary so that these entries appear as
		 * "unallocated" in the next part.  Each of these entries
		 * will eventually be filled with the representation of
		 * the root node of a binary tree.  */
		j = decode_table_pos;
		do {
			decode_table[j] = 0;
		} while (++j != table_num_entries);

		/* We allocate child nodes starting at the end of the
		 * direct lookup table.  Note that there should be
		 * 2*num_syms extra entries for this purpose, although
		 * fewer than this may actually be needed.  */
		next_free_tree_slot = table_num_entries;

		/* Iterate through each codeword with length greater than
		 * 'table_bits', primarily in order of codeword length
		 * and secondarily in order of symbol.  */
		for (cur_codeword = decode_table_pos << 1;
		     codeword_len <= max_codeword_len;
		     codeword_len++, cur_codeword <<= 1)
		{
			unsigned end_sym_idx = sym_idx + len_counts[codeword_len];
			for (; sym_idx < end_sym_idx; sym_idx++, cur_codeword++)
			{
				/* 'sym' is the symbol represented by the
				 * codeword.  */
				unsigned sym = sorted_syms[sym_idx];

				unsigned extra_bits = codeword_len - table_bits;

				unsigned node_idx = cur_codeword >> extra_bits;

				/* Go through each bit of the current codeword
				 * beyond the prefix of length @table_bits and
				 * walk the appropriate binary tree, allocating
				 * any slots that have not yet been allocated.
				 *
				 * Note that the 'pointer' entry to the binary
				 * tree, which is stored in the direct lookup
				 * portion of the table, is represented
				 * identically to other internal (non-leaf)
				 * nodes of the binary tree; it can be thought
				 * of as simply the root of the tree.  The
				 * representation of these internal nodes is
				 * simply the index of the left child combined
				 * with the special bits 0xC000 to distingush
				 * the entry from direct mapping and leaf node
				 * entries.  */
				do {

					/* At least one bit remains in the
					 * codeword, but the current node is an
					 * unallocated leaf.  Change it to an
					 * internal node.  */
					if (decode_table[node_idx] == 0) {
						decode_table[node_idx] =
							next_free_tree_slot | 0xC000;
						decode_table[next_free_tree_slot++] = 0;
						decode_table[next_free_tree_slot++] = 0;
					}

					/* Go to the left child if the next bit
					 * in the codeword is 0; otherwise go to
					 * the right child.  */
					node_idx = decode_table[node_idx] & 0x3FFF;
					--extra_bits;
					node_idx += (cur_codeword >> extra_bits) & 1;
				} while (extra_bits != 0);

				/* We've traversed the tree using the entire
				 * codeword, and we're now at the entry where
				 * the actual symbol will be stored.  This is
				 * distinguished from internal nodes by not
				 * having its high two bits set.  */
				decode_table[node_idx] = sym;
			}
		}
	}
	return 0;
}

static inline void
copy_word_unaligned(const void *src, void *dst)
{
	store_word_unaligned(load_word_unaligned(src), dst);
}

static inline machine_word_t
repeat_byte(u8 b)
{
	machine_word_t v;

	BUILD_BUG_ON(WORDSIZE != 4 && WORDSIZE != 8);

	v = b;
	v |= v << 8;
	v |= v << 16;
	v |= v << ((WORDSIZE == 8) ? 32 : 0);
	return v;
}

static inline void
lz_copy(u8 *dst, u32 length, u32 offset, const u8 *winend, u32 min_length)
{
	const u8 *src = dst - offset;
	const u8 * const end = dst + length;

	/*
	 * Try to copy one machine word at a time.  On i386 and x86_64 this is
	 * faster than copying one byte at a time, unless the data is
	 * near-random and all the matches have very short lengths.  Note that
	 * since this requires unaligned memory accesses, it won't necessarily
	 * be faster on every architecture.
	 *
	 * Also note that we might copy more than the length of the match.  For
	 * example, if a word is 8 bytes and the match is of length 5, then
	 * we'll simply copy 8 bytes.  This is okay as long as we don't write
	 * beyond the end of the output buffer, hence the check for (winend -
	 * end >= WORDSIZE - 1).
	 */
	if (UNALIGNED_ACCESS_IS_VERY_FAST &&
	    likely(winend - end >= WORDSIZE - 1))
	{

		if (offset >= WORDSIZE) {
			/* The source and destination words don't overlap.  */

			/* To improve branch prediction, one iteration of this
			 * loop is unrolled.  Most matches are short and will
			 * fail the first check.  But if that check passes, then
			 * it becomes increasing likely that the match is long
			 * and we'll need to continue copying.  */

			copy_word_unaligned(src, dst);
			src += WORDSIZE;
			dst += WORDSIZE;

			if (dst < end) {
				do {
					copy_word_unaligned(src, dst);
					src += WORDSIZE;
					dst += WORDSIZE;
				} while (dst < end);
			}
			return;
		} else if (offset == 1) {

			/* Offset 1 matches are equivalent to run-length
			 * encoding of the previous byte.  This case is common
			 * if the data contains many repeated bytes.  */

			machine_word_t v = repeat_byte(*(dst - 1));
			do {
				store_word_unaligned(v, dst);
				src += WORDSIZE;
				dst += WORDSIZE;
			} while (dst < end);
			return;
		}
		/*
		 * We don't bother with special cases for other 'offset <
		 * WORDSIZE', which are usually rarer than 'offset == 1'.  Extra
		 * checks will just slow things down.  Actually, it's possible
		 * to handle all the 'offset < WORDSIZE' cases using the same
		 * code, but it still becomes more complicated doesn't seem any
		 * faster overall; it definitely slows down the more common
		 * 'offset == 1' case.
		 */
	}

	/* Fall back to a bytewise copy.  */

	if (min_length >= 2) {
		*dst++ = *src++;
		length--;
	}
	if (min_length >= 3) {
		*dst++ = *src++;
		length--;
	}
	if (min_length >= 4) {
		*dst++ = *src++;
		length--;
	}
	do {
		*dst++ = *src++;
	} while (--length);
}

static int
xpress_decompress(const void *compressed_data, size_t compressed_size,
		  void *uncompressed_data, size_t uncompressed_size, void *_ctx)
{
	const u8 *in_next = compressed_data;
	const u8 *const in_end = in_next + compressed_size;
	u8 *const out_begin = uncompressed_data;
	u8 *out_next = out_begin;
	u8 *const out_end = out_next + uncompressed_size;
	union {
		u8 lens[XPRESS_NUM_SYMBOLS];
		u16 decode_table[(1 << XPRESS_TABLEBITS) + 2 * XPRESS_NUM_SYMBOLS]
				_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	} u;
	bitbuf_t bitbuf = 0;
	unsigned bitsleft = 0;
	unsigned sym;
	unsigned match_len;
	unsigned offset_high_bit;
	unsigned match_offset;

	if (in_end - in_next < XPRESS_NUM_SYMBOLS / 2)
		return -1;

	for (unsigned i = 0; i < XPRESS_NUM_SYMBOLS / 2; i++) {
		u.lens[i * 2] = *in_next & 0xf;
		u.lens[i * 2 + 1] = *in_next >> 4;
		in_next++;
	}

	if (make_huffman_decode_table(u.decode_table, XPRESS_NUM_SYMBOLS,
				      XPRESS_TABLEBITS, u.lens,
				      XPRESS_MAX_CODEWORD_LEN))
		return -1;

	while (out_next != out_end) {
		unsigned entry;
		unsigned key_bits;

		ENSURE_BITS(XPRESS_MAX_CODEWORD_LEN);
		key_bits = BITS(XPRESS_TABLEBITS);
		entry = u.decode_table[key_bits];
		if (likely(entry < 0xC000)) {
			REMOVE_BITS(entry >> 11);
			sym = entry & 0x7FF;
		} else {
			/* Slow case: The codeword for the symbol is longer than
			 * table_bits, so the symbol does not have an entry
			 * directly in the first (1 << table_bits) entries of the
			 * decode table.  Traverse the appropriate binary tree
			 * bit-by-bit to decode the symbol.  */
			REMOVE_BITS(XPRESS_TABLEBITS);
			do {
				key_bits = (entry & 0x3FFF) + POP_BITS(1);
			} while ((entry = u.decode_table[key_bits]) >= 0xC000);
			sym = entry;
		}

		if (sym < XPRESS_NUM_CHARS) {
			/* Literal  */
			*out_next++ = sym;
			continue;
		}

		/* Match  */
		match_len = sym & 0xf;
		offset_high_bit = (sym >> 4) & 0xf;

		ENSURE_BITS(16);

		match_offset = (1 << offset_high_bit) | POP_BITS(offset_high_bit);

		if (match_len == 0xf) {
			match_len += READ_BYTE();
			if (match_len == 0xf + 0xff)
				match_len = READ_U16();
		}
		match_len += XPRESS_MIN_MATCH_LEN;

		if (unlikely(match_offset > out_next - out_begin))
			return -1;

		if (unlikely(match_len > out_end - out_next))
			return -1;

		lz_copy(out_next, match_len, match_offset, out_end,
			XPRESS_MIN_MATCH_LEN);

		out_next += match_len;
	}

	return 0;
}

static int
xpress_create_decompressor(size_t max_block_size, void **dec_ret)
{
	if (max_block_size > XPRESS_MAX_OFFSET + 1)
		return WIMLIB_ERR_INVALID_PARAM;

	return 0;
}

const struct decompressor_ops xpress_decompressor_ops = {
	.create_decompressor = xpress_create_decompressor,
	.decompress	     = xpress_decompress,
};
