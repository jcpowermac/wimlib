/*
 * lz_hash.h
 *
 * Hashing for Lempel-Ziv matchfinding.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_LZ_HASH3_H
#define _WIMLIB_LZ_HASH3_H

#include "wimlib/unaligned.h"

/* Constant for the multiplicative hash function.  */
#define LZ_HASH_MULTIPLIER 0x1E35A7BD

static inline u32
loaded_u32_to_u24(u32 v)
{
	if (CPU_IS_LITTLE_ENDIAN)
		return v & 0xFFFFFF;
	else
		return v >> 8;
}

static inline u32
load_u24_unaligned(const u8 *p)
{
	if (UNALIGNED_ACCESS_IS_FAST)
		return loaded_u32_to_u24(load_u32_unaligned(p));
	else
		return ((u32)p[0] << 0) | ((u32)p[1] << 8) | ((u32)p[2] << 16);
}

static inline u32
lz_hash(u32 str, unsigned num_bits)
{
	return (u32)(str * LZ_HASH_MULTIPLIER) >> (32 - num_bits);
}

/*
 * Hash the next 3-byte sequence in the window, producing a hash of length
 * 'num_bits' bits.  At least LZ_HASH_REQUIRED_NBYTES must be available at 'p';
 * this might be 4 bytes rather than 3 because an unaligned load is faster on
 * some architectures.
 */
static inline u32
lz_hash_3_bytes(const u8 *p, unsigned num_bits)
{
	return lz_hash(load_u24_unaligned(p), num_bits);
}

/* The number of bytes being hashed.  */
#define LZ_HASH_NBYTES 3

/* Number of bytes the hash function actually requires be available, due to the
 * possibility of an unaligned load.  */
#define LZ_HASH_REQUIRED_NBYTES (UNALIGNED_ACCESS_IS_FAST ? 4 : 3)

#endif /* _WIMLIB_LZ_HASH3_H */
