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

/* Decode the matches and literal bytes in a region of XPRESS-encoded data.  */
static int
xpress_decode_window(struct input_bitstream *istream, const u16 *decode_table,
		     u8 *window, unsigned window_size)
{
	u8 *window_ptr = window;
	u8 *window_end = &window[window_size];
	unsigned sym;
	unsigned match_len;
	unsigned offset_high_bit;
	unsigned match_offset;

	while (window_ptr != window_end) {

		sym = read_huffsym(istream, decode_table,
				   XPRESS_TABLEBITS, XPRESS_MAX_CODEWORD_LEN);
		if (sym < XPRESS_NUM_CHARS) {
			/* Literal  */
			*window_ptr++ = sym;
			continue;
		}

		/* Match  */
		match_len = sym & 0xf;
		offset_high_bit = (sym >> 4) & 0xf;

		bitstream_ensure_bits(istream, 16);

		match_offset = (1 << offset_high_bit) |
				bitstream_pop_bits(istream, offset_high_bit);

		if (match_len == 0xf) {
			match_len += bitstream_read_byte(istream);
			if (match_len == 0xf + 0xff)
				match_len = bitstream_read_u16(istream);
		}
		match_len += XPRESS_MIN_MATCH_LEN;

		if (unlikely(match_offset > window_ptr - window))
			return -1;

		if (unlikely(match_len > window_end - window_ptr))
			return -1;

		lz_copy(window_ptr, match_len, match_offset, window_end,
			XPRESS_MIN_MATCH_LEN);

		window_ptr += match_len;
	}
	return 0;
}

static int
xpress_decompress(const void *compressed_data, size_t compressed_size,
		  void *uncompressed_data, size_t uncompressed_size, void *_ctx)
{
	const u8 *cdata = compressed_data;
	u8 lens[XPRESS_NUM_SYMBOLS];
	u8 *lens_p;
	u16 decode_table[(1 << XPRESS_TABLEBITS) + 2 * XPRESS_NUM_SYMBOLS]
			_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	struct input_bitstream istream;

	/* XPRESS uses only one Huffman code.  It contains 512 symbols, and the
	 * code lengths of these symbols are given literally as 4-bit integers
	 * in the first 256 bytes of the compressed data.  */
	if (compressed_size < XPRESS_NUM_SYMBOLS / 2)
		return -1;

	lens_p = lens;
	for (unsigned i = 0; i < XPRESS_NUM_SYMBOLS / 2; i++) {
		*lens_p++ = cdata[i] & 0xf;
		*lens_p++ = cdata[i] >> 4;
	}

	if (make_huffman_decode_table(decode_table, XPRESS_NUM_SYMBOLS,
				      XPRESS_TABLEBITS, lens,
				      XPRESS_MAX_CODEWORD_LEN))
		return -1;

	init_input_bitstream(&istream, cdata + XPRESS_NUM_SYMBOLS / 2,
			     compressed_size - XPRESS_NUM_SYMBOLS / 2);

	return xpress_decode_window(&istream, decode_table,
				    uncompressed_data, uncompressed_size);
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
