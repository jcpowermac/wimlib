/*
 * xpress_decompress.c
 *
 * A decompressor for the XPRESS compression format (Huffman variant).
 */

/*
 *
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include "wimlib/decompressor_ops.h"
#include "wimlib/decompress_common.h"
#include "wimlib/error.h"
#include "wimlib/xpress_constants.h"

/* This value is chosen for fast decompression.  */
#define XPRESS_TABLEBITS 12

typedef unsigned int bitbuf_t;
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
	if ((n) != 0)							\
		bits = bitbuf >> (BITBUF_NBITS - (n));			\
	bits;								\
})

#define REMOVE_BITS(n)							\
({									\
									\
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
