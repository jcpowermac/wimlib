/*
 * lz_hash_arrays_64.c
 *
 * Hash array match-finder for Lempel-Ziv compression.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lz_extend.h"
#include "wimlib/lz_hash3.h"
#include "wimlib/lz_mf.h"
#include "wimlib/util.h"

#define LZ_HA64_HASH_ORDER	16
#define LZ_HA64_HASH_LEN     (1 << 16)


/* TODO */
#define LZ_HA64_SLOT_BITS		5
#define LZ_HA64_SLOTS_PER_BUCKET	(1 << LZ_HA64_SLOT_BITS)
#define LZ_HA64_SLOT_MASK		(LZ_HA64_SLOTS_PER_BUCKET - 1)

#define LZ_HA64_POS_BITS		(32 - LZ_HA64_SLOT_BITS)
#define LZ_HA64_POS_MASK		(((u32)1 << LZ_HA64_POS_BITS) - 1)

static inline u32
lz_ha64_hash(const u8 *p)
{
	return lz_hash(p, LZ_HA64_HASH_ORDER);
}

struct lz_ha64 {
	struct lz_mf base;
	u64 *arrays;
	u32 next_hash;
};

static inline void
prefetch_array(u64 *array)
{
#if 0
	for (u32 i = 0; i < LZ_HA64_SLOTS_PER_BUCKET; i += 64 / sizeof(array[0]))
		prefetch(&array[i]);
#else
	prefetch(&array[0]);
#endif
}

static void
lz_ha64_set_default_params(struct lz_mf_params *params)
{
	if (params->min_match_len < LZ_HASH_NBYTES)
		params->min_match_len = LZ_HASH_NBYTES;

	if (params->max_match_len == 0)
		params->max_match_len = params->max_window_size;

	if (params->nice_match_len == 0)
		params->nice_match_len = 24;

	if (params->nice_match_len < params->min_match_len)
		params->nice_match_len = params->min_match_len;

	if (params->nice_match_len > params->max_match_len)
		params->nice_match_len = params->max_match_len;
}

static bool
lz_ha64_params_valid(const struct lz_mf_params *_params)
{
	struct lz_mf_params params = *_params;

	lz_ha64_set_default_params(&params);

	/* Avoid edge case where min_match_len = 4, max_match_len < 4 */
	return (params.min_match_len <= params.max_match_len);
}

static u64
lz_ha64_get_needed_memory(u32 max_window_size)
{
	return LZ_HA64_HASH_LEN * LZ_HA64_SLOTS_PER_BUCKET * sizeof(u64);
}

static bool
lz_ha64_init(struct lz_mf *_mf)
{
	struct lz_ha64 *mf = (struct lz_ha64 *)_mf;

	lz_ha64_set_default_params(&mf->base.params);

	mf->arrays = ALIGNED_MALLOC(lz_ha64_get_needed_memory(mf->base.params.max_window_size),
				    64);
	if (!mf->arrays)
		return false;

	return true;
}

static void
lz_ha64_load_window(struct lz_mf *_mf, const u8 window[], u32 size)
{
	struct lz_ha64 *mf = (struct lz_ha64 *)_mf;

	for (u32 i = 0; i < LZ_HA64_HASH_LEN; i++)
		mf->arrays[i << LZ_HA64_SLOT_BITS] = LZ_HA64_POS_MASK;
}

static u32
lz_ha64_get_matches(struct lz_mf *_mf, struct lz_match matches[])
{
	struct lz_ha64 *mf = (struct lz_ha64 *)_mf;
	const u32 bytes_remaining = lz_mf_get_bytes_remaining(&mf->base);
	const u8 * const strptr = lz_mf_get_window_ptr(&mf->base);
	const u32 max_len = min(bytes_remaining, mf->base.params.max_match_len);
	const u32 nice_len = min(max_len, mf->base.params.nice_match_len);
	u32 best_len = mf->base.params.min_match_len - 1;
	const u8 * const cur_window = mf->base.cur_window;
	u32 hash;
	u64 *array;
	u32 start_i;
	u32 next_i;
	u32 i;
	u32 cur_match;
	u32 prev_match;
	u64 sequence;
	struct lz_match *lz_matchptr = matches;

	if (bytes_remaining <= LZ_HASH_REQUIRED_NBYTES + 1)
		goto out;

	sequence = *(const u32 *)strptr;

#if LZ_HASH_NBYTES == 3
	sequence &= 0xFFFFFF;
#endif

	hash = mf->next_hash;
	mf->next_hash = lz_ha64_hash(strptr + 1);

	prefetch_array(&mf->arrays[(mf->next_hash << LZ_HA64_SLOT_BITS)]);
	array = &mf->arrays[hash << LZ_HA64_SLOT_BITS];

	start_i = ((u32)array[0] >> LZ_HA64_POS_BITS);

	i = start_i;
	prev_match = LZ_HA64_POS_MASK;

	for (;;) {

		u32 len;
		const u8 *matchptr;

		cur_match = (array[i] & LZ_HA64_POS_MASK);

		if (cur_match >= prev_match)
			break;

		if (sequence != (array[i] >> 32))
			goto next_match;

		matchptr = &cur_window[cur_match];

		if (matchptr[best_len] != strptr[best_len])
			goto next_match;

	#if HAVE_FAST_LZ_EXTEND
		len = lz_extend(strptr, matchptr, LZ_HASH_NBYTES, max_len);
		if (len > best_len) {
			best_len = len;

			*lz_matchptr++ = (struct lz_match) {
				.len = best_len,
				.offset = strptr - matchptr,
			};

			if (best_len >= nice_len)
				break;
		}

	#else
		for (len = LZ_HASH_NBYTES; len < best_len; len++)
			if (matchptr[len] != strptr[len])
				goto next_match;

		/* The match is the longest found so far ---
		 * at least 'best_len' + 1 bytes.  Continue extending it.  */

		while (++best_len != max_len)
			if (strptr[best_len] != matchptr[best_len])
				break;

		/* Record the match.  */
		*lz_matchptr++ = (struct lz_match) {
			.len = best_len,
			.offset = strptr - matchptr,
		};

		/* Terminate the search if 'nice_len' was reached.  */
		if (best_len >= nice_len)
			break;
	#endif

	next_match:
		prev_match = cur_match;
		i = (i - 1) & LZ_HA64_SLOT_MASK;
	}
	
	next_i = (start_i + 1) & LZ_HA64_SLOT_MASK;
	array[0] = (array[0] & ~((u64)LZ_HA64_SLOT_MASK << LZ_HA64_POS_BITS)) |
				(next_i << LZ_HA64_POS_BITS);
	array[next_i] = (sequence << 32) | (next_i << LZ_HA64_POS_BITS) |
				mf->base.cur_window_pos;
out:
	mf->base.cur_window_pos++;
	return lz_matchptr - matches;
}

static void
lz_ha64_skip_position(struct lz_ha64 *mf)
{
	const u32 bytes_remaining = lz_mf_get_bytes_remaining(&mf->base);
	const u8 * const strptr = lz_mf_get_window_ptr(&mf->base);
	u32 hash;
	u64 *array;
	u32 start_i;
	u32 next_i;
	u64 sequence;

	if (bytes_remaining <= LZ_HASH_REQUIRED_NBYTES + 1)
		goto out;

	sequence = *(const u32 *)strptr;

#if LZ_HASH_NBYTES == 3
	sequence &= 0xFFFFFF;
#endif

	hash = mf->next_hash;
	mf->next_hash = lz_ha64_hash(strptr + 1);
	prefetch_array(&mf->arrays[(mf->next_hash << LZ_HA64_SLOT_BITS)]);
	array = &mf->arrays[hash << LZ_HA64_SLOT_BITS];
	start_i = ((u32)array[0] >> LZ_HA64_POS_BITS);

	next_i = (start_i + 1) & LZ_HA64_SLOT_MASK;
	array[0] = (array[0] & ~((u64)LZ_HA64_SLOT_MASK << LZ_HA64_POS_BITS)) |
				(next_i << LZ_HA64_POS_BITS);
	array[next_i] = (sequence << 32) | (next_i << LZ_HA64_POS_BITS) |
				mf->base.cur_window_pos;
out:
	mf->base.cur_window_pos++;
}

static void
lz_ha64_skip_positions(struct lz_mf *_mf, u32 n)
{
	struct lz_ha64 *mf = (struct lz_ha64 *)_mf;

	do {
		lz_ha64_skip_position(mf);
	} while (--n);
}

static void
lz_ha64_destroy(struct lz_mf *_mf)
{
	struct lz_ha64 *mf = (struct lz_ha64 *)_mf;

	ALIGNED_FREE(mf->arrays);
}

const struct lz_mf_ops lz_hash_arrays_64_ops = {
	.params_valid      = lz_ha64_params_valid,
	.get_needed_memory = lz_ha64_get_needed_memory,
	.init		   = lz_ha64_init,
	.load_window       = lz_ha64_load_window,
	.get_matches       = lz_ha64_get_matches,
	.skip_positions    = lz_ha64_skip_positions,
	.destroy           = lz_ha64_destroy,
	.struct_size	   = sizeof(struct lz_ha64),
};
