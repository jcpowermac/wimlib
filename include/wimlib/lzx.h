#ifndef _WIMLIB_LZX_H
#define _WIMLIB_LZX_H

/* Constants for the LZX data compression format.  See the comments in
 * lzx-compress.c and lzx-decompress.c for more information about this format.
 * */

#include "wimlib/assert.h"
#include "wimlib/compiler.h"
#include "wimlib/util.h"
#include "wimlib/types.h"

//#define ENABLE_LZX_DEBUG
#ifdef ENABLE_LZX_DEBUG
#	define LZX_DEBUG DEBUG
#       define LZX_ASSERT wimlib_assert
#else
#	define LZX_DEBUG(format, ...)
#	define LZX_ASSERT(...)
#endif

/* Constants, most of which are defined by the LZX specification: */

/* The smallest and largest allowed match lengths. */
#define LZX_MIN_MATCH_LEN            2
#define LZX_MAX_MATCH_LEN            257

/* Number of values an uncompressed literal byte can represent. */
#define LZX_NUM_CHARS                256

/* Each LZX block begins with 3 bits that determines the block type.  Below are
 * the valid block types.  Values 0, and 4 through 7, are invalid. */
#define LZX_BLOCKTYPE_VERBATIM       1
#define LZX_BLOCKTYPE_ALIGNED        2
#define LZX_BLOCKTYPE_UNCOMPRESSED   3

#define LZX_NUM_PRIMARY_LENS         7

/* The number of position slots varies from 30 to 51 depending on the window
 * size (see comment in lzx-decompress.c).  */
#define LZX_MAX_POSITION_SLOTS		51

#define LZX_MIN_WINDOW_ORDER	15
#define LZX_MAX_WINDOW_ORDER	21
#define LZX_MIN_WINDOW_SIZE	(1U << LZX_MIN_WINDOW_ORDER)  /* 32768   */
#define LZX_MAX_WINDOW_SIZE	(1U << LZX_MAX_WINDOW_ORDER)  /* 2097152 */

/* Read the LZX specification for information about the Huffman trees used in
 * the LZX compression format.  Basically there are 4 of them: The main tree,
 * the length tree, the pre tree, and the aligned tree.  The main tree and
 * length tree are given at the beginning of VERBATIM and ALIGNED blocks as a
 * list of *_NUM_SYMBOLS code length values.  They are read using the
 * read_code_lens() function and built using the make_decode_table() function.
 * The decode table is not a real tree but rather a table that we can index by
 * some number of bits (*_TABLEBITS) of the input to quickly look up the symbol
 * corresponding to a Huffman code.
 *
 * The ALIGNED tree is only present on ALIGNED blocks.
 *
 * A PRECODE is used to encode the code lengths for the main tree and the length
 * tree.  There is a separate pretree for each half of the main tree.  */

#define LZX_MAINCODE_MAX_NUM_SYMBOLS	(LZX_NUM_CHARS + (LZX_MAX_POSITION_SLOTS << 3))
#define LZX_MAINCODE_TABLEBITS		11

#define LZX_LENCODE_NUM_SYMBOLS		249
#define LZX_LENCODE_TABLEBITS		10

#define LZX_PRECODE_NUM_SYMBOLS		20
#define LZX_PRECODE_TABLEBITS		6
#define LZX_PRECODE_ELEMENT_SIZE	4

#define LZX_ALIGNEDCODE_NUM_SYMBOLS	8
#define LZX_ALIGNEDCODE_TABLEBITS	7
#define LZX_ALIGNEDCODE_ELEMENT_SIZE	3

/* Maximum allowed length of Huffman codewords.  */
#define LZX_MAX_MAIN_CODEWORD_LEN	16
#define LZX_MAX_LEN_CODEWORD_LEN	16
#define LZX_MAX_PRE_CODEWORD_LEN	16
#define LZX_MAX_ALIGNED_CODEWORD_LEN	8

/* For the LZX-compressed blocks in WIM files, this value is always used as the
 * filesize parameter for the call instruction (0xe8 byte) preprocessing, even
 * though the blocks themselves are not this size, and the size of the actual
 * file resource in the WIM file is very likely to be something entirely
 * different as well.  */
#define LZX_WIM_MAGIC_FILESIZE		12000000

/* Assumed LZX block size when the encoded block size begins with a 0 bit.  */
#define LZX_DEFAULT_BLOCK_SIZE		32768

#define USE_LZX_EXTRA_BITS_ARRAY

#ifdef USE_LZX_EXTRA_BITS_ARRAY
extern const u8 lzx_extra_bits[LZX_MAX_POSITION_SLOTS];
#endif

/* Given the number of an LZX position slot, return the number of extra bits that
 * are needed to encode the match offset. */
static inline unsigned
lzx_get_num_extra_bits(unsigned position_slot)
{
#ifdef USE_LZX_EXTRA_BITS_ARRAY
	/* Use a table */
	return lzx_extra_bits[position_slot];
#else
	/* Calculate directly using a shift and subtraction. */
	LZX_ASSERT(position_slot >= 2 && position_slot <= 37);
	return (position_slot >> 1) - 1;
#endif
}

extern const u32 lzx_position_base[LZX_MAX_POSITION_SLOTS];

/* Returns the LZX position slot that corresponds to a given formatted offset.
 *
 * Logically, this returns the smallest i such that
 * formatted_offset >= lzx_position_base[i].
 *
 * The actual implementation below takes advantage of the regularity of the
 * numbers in the lzx_position_base array to calculate the slot directly from
 * the formatted offset without actually looking at the array.
 */
static inline unsigned
lzx_get_position_slot_raw(u32 formatted_offset)
{
	if (formatted_offset >= 196608) {
		return (formatted_offset >> 17) + 34;
	} else {
		LZX_ASSERT(2 <= formatted_offset && formatted_offset < 655360);
		unsigned mssb_idx = bsr32(formatted_offset);
		return (mssb_idx << 1) |
			((formatted_offset >> (mssb_idx - 1)) & 1);
	}
}

extern bool lzx_window_size_valid(size_t window_size);
extern unsigned lzx_get_num_main_syms(u32 window_size);

#define LZX_NUM_RECENT_OFFSETS	3

#ifdef __SSE2__
#include <emmintrin.h>
#include <assert.h>
struct lzx_lru_queue {
	__m128i R;
};

static inline void
lzx_fill_lru_queue(struct lzx_lru_queue *q, u32 R0, u32 R1, u32 R2)
{
	q->R = _mm_set_epi32(0, R2, R1, R0);
	assert(((u32 *)&q->R)[0] == R0);
	assert(((u32 *)&q->R)[1] == R1);
	assert(((u32 *)&q->R)[2] == R2);
}

static inline u32
lzx_reference_lru(struct lzx_lru_queue *q, unsigned idx)
{
#if 1
	__m128i R = q->R;

	switch (idx) {
	case 0:
		/* Nothing to do.  */
		break;
	case 1:
		/* 3 => 3:  11
		 * 2 => 2:  10
		 * 0 => 1:  00
		 * 1 => 0:  01
		 *
		 * 11100001 = 0xE1 */
		R = _mm_shuffle_epi32(R, 0xE1);
		break;
	default:
		/* 3 => 3:  11
		 * 0 => 2:  00
		 * 1 => 1:  01
		 * 2 => 0:  10
		 *
		 * 11000110 = 0xC6 */
		R = _mm_shuffle_epi32(R, 0xC6);
		break;
	}
	q->R = R;
	return ((u32 *)&q->R)[0];
#else
	u32 *R = (u32 *)&q->R;
	u32 offset = R[idx];
	R[idx] = R[0];
	R[0] = offset;
	return offset;
#endif
}

static void
lzx_insert_lru(struct lzx_lru_queue *q, u32 value)
{
#if 1
	__m128i R = q->R;
	R = _mm_slli_si128(R, 32);
	R = _mm_

	q->R = R;
#else
	u32 *R = (u32 *)&q->R;
	R[2] = R[1];
	R[1] = R[0];
	R[0] = value;
#endif
}

#else /* __SSE2__ */
/* Least-recently used queue for match offsets.  */
struct lzx_lru_queue {
	u32 R[LZX_NUM_RECENT_OFFSETS];
}
#ifdef __x86_64__
_aligned_attribute(8)  /* Improves performance of LZX compression by 1% - 2%;
			  specifically, this speeds up
			  lzx_get_near_optimal_match().  */
#endif
;

static inline void
lzx_fill_lru_queue(struct lzx_lru_queue *q, u32 R0, u32 R1, u32 R2)
{
	q->R[0] = R0;
	q->R[1] = R1;
	q->R[2] = R2;
}

static inline u32
lzx_reference_lru(struct lzx_lru_queue *q, unsigned idx)
{
	u32 offset = q->R[idx];
	q->R[idx] = q->R[0];
	q->R[0] = offset;
	return offset;
}

static void
lzx_insert_lru(struct lzx_lru_queue *q, u32 value)
{
	q->R[2] = q->R[1];
	q->R[1] = q->R[0];
	q->R[0] = value;
}

#endif /* !__SSE2__ */

/* In the LZX format, an offset of n bytes is actually encoded
 * as (n + LZX_OFFSET_OFFSET).  */
#define LZX_OFFSET_OFFSET	(LZX_NUM_RECENT_OFFSETS - 1)

/* Initialize the LZX least-recently-used match offset queue at the beginning of
 * a new window for either decompression or compression.  */
static inline void
lzx_lru_queue_init(struct lzx_lru_queue *queue)
{
	lzx_fill_lru_queue(queue, 1, 1, 1);
}

extern void
lzx_do_e8_preprocessing(u8 *data, s32 size);

extern void
lzx_undo_e8_preprocessing(u8 *data, s32 size);

#endif /* _WIMLIB_LZX_H */
