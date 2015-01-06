/*
 * lzx_common.h
 *
 * Declarations shared between LZX compression and decompression.
 */

#ifndef _LZX_COMMON_H
#define _LZX_COMMON_H

#include "wimlib/bitops.h"
#include "wimlib/lzx_constants.h"
#include "wimlib/types.h"

//#define ENABLE_LZX_DEBUG
#ifdef ENABLE_LZX_DEBUG
#  include "wimlib/assert.h"
#  define LZX_ASSERT wimlib_assert
#else
#  define LZX_ASSERT(...)
#endif

extern const u32 lzx_offset_slot_base[LZX_MAX_OFFSET_SLOTS];

extern const u8 lzx_extra_offset_bits[LZX_MAX_OFFSET_SLOTS];

/* Returns the LZX offset slot that corresponds to a given adjusted offset.
 *
 * Logically, this returns the smallest i such that
 * adjusted_offset >= lzx_offset_slot_base[i].
 *
 * The actual implementation below takes advantage of the regularity of the
 * numbers in the lzx_offset_slot_base array to calculate the slot directly from
 * the adjusted offset without actually looking at the array.
 */
static inline unsigned
lzx_get_offset_slot_raw(u32 adjusted_offset)
{
	if (adjusted_offset >= 196608) {
		return (adjusted_offset >> 17) + 34;
	} else {
		LZX_ASSERT(2 <= adjusted_offset && adjusted_offset < 655360);
		unsigned mssb_idx = fls32(adjusted_offset);
		return (mssb_idx << 1) |
			((adjusted_offset >> (mssb_idx - 1)) & 1);
	}
}

extern unsigned
lzx_get_window_order(size_t max_bufsize);

extern unsigned
lzx_get_num_main_syms(unsigned window_order);

extern void
lzx_do_e8_preprocessing(u8 *data, u32 size);

extern void
lzx_undo_e8_preprocessing(u8 *data, u32 size);

#endif /* _LZX_COMMON_H */
