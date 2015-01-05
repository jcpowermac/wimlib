/*
 * matchfinder_common.h
 *
 * Common code for Lempel-Ziv matchfinding.
 *
 * Copyright (c) 2014 Eric Biggers.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MATCHFINDER_COMMON_H
#define _MATCHFINDER_COMMON_H

#include "wimlib/types.h"

#include <string.h>

#ifndef MATCHFINDER_WINDOW_ORDER
#  error "MATCHFINDER_WINDOW_ORDER must be defined!"
#endif

#define MATCHFINDER_WINDOW_SIZE ((size_t)1 << MATCHFINDER_WINDOW_ORDER)

#if MATCHFINDER_WINDOW_ORDER <= 16
typedef u16 pos_t;
#else
typedef u32 pos_t;
#endif

#if MATCHFINDER_WINDOW_ORDER != 16 && MATCHFINDER_WINDOW_ORDER != 32

/* Not all the bits of the position type are needed, so the sign bit can be
 * reserved to mean "out of bounds".  */
#define MATCHFINDER_INITVAL ((pos_t)-1)

static inline bool
matchfinder_match_in_window(pos_t cur_match)
{
	return !(cur_match & ((pos_t)1 << (sizeof(pos_t) * 8 - 1)));
}

#else

/* All bits of the position type are needed, so use 0 to mean "out of bounds".
 * This prevents the beginning of the buffer from matching anything; however,
 * this doesn't matter much.  */

#define MATCHFINDER_INITVAL ((pos_t)0)

static inline bool
matchfinder_match_in_window(pos_t cur_match)
{
	return cur_match != 0;
}

#endif

#define MATCHFINDER_ALIGNMENT 8

#ifdef __AVX2__
#  include "matchfinder_avx2.h"
#  if MATCHFINDER_ALIGNMENT < 32
#    undef MATCHFINDER_ALIGNMENT
#    define MATCHFINDER_ALIGNMENT 32
#  endif
#endif

#ifdef __SSE2__
#  include "matchfinder_sse2.h"
#  if MATCHFINDER_ALIGNMENT < 16
#    undef MATCHFINDER_ALIGNMENT
#    define MATCHFINDER_ALIGNMENT 16
#  endif
#endif

/*
 * Representation of a match.
 */
struct lz_match {

	/* The number of bytes matched.  */
	pos_t length;

	/* The offset back from the current position that was matched.  */
	pos_t offset;
};

static inline bool
matchfinder_memset_init_okay(void)
{
	/* All bytes must match in order to use memset.  */
	const pos_t v = MATCHFINDER_INITVAL;
	if (sizeof(pos_t) == 2)
		return (u8)v == (u8)(v >> 8);
	if (sizeof(pos_t) == 4)
		return (u8)v == (u8)(v >> 8) &&
		       (u8)v == (u8)(v >> 16) &&
		       (u8)v == (u8)(v >> 24);
	return false;
}

/*
 * Initialize the hash table portion of the matchfinder.
 *
 * Essentially, this is an optimized memset().
 *
 * 'data' must be aligned to a MATCHFINDER_ALIGNMENT boundary.
 */
static inline void
matchfinder_init(pos_t *data, size_t num_entries)
{
	const size_t size = num_entries * sizeof(data[0]);

#ifdef __AVX2__
	if (matchfinder_init_avx2(data, size))
		return;
#endif

#ifdef __SSE2__
	if (matchfinder_init_sse2(data, size))
		return;
#endif

	if (matchfinder_memset_init_okay()) {
		memset(data, (u8)MATCHFINDER_INITVAL, size);
		return;
	}

	for (size_t i = 0; i < num_entries; i++)
		data[i] = MATCHFINDER_INITVAL;
}

#endif /* _MATCHFINDER_COMMON_H */
