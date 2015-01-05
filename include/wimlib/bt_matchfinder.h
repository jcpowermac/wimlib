/*
 * bt_matchfinder.h
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

#ifndef _BT_MATCHFINDER_H
#define _BT_MATCHFINDER_H

#include "wimlib/lz_extend.h"
#include "wimlib/lz_hash.h"
#include "wimlib/matchfinder_common.h"
#include "wimlib/util.h"

#define BT_MATCHFINDER_HASH_ORDER 16
#define BT_MATCHFINDER_HASH_LENGTH	(1UL << BT_MATCHFINDER_HASH_ORDER)

struct bt_matchfinder {
	pos_t hash_tab[BT_MATCHFINDER_HASH_LENGTH];
	pos_t child_tab[];
} _aligned_attribute(MATCHFINDER_ALIGNMENT);

static inline struct bt_matchfinder *
bt_matchfinder_alloc(unsigned actual_window_order)
{
	return ALIGNED_MALLOC((BT_MATCHFINDER_HASH_LENGTH +
				(2UL << actual_window_order)) * sizeof(pos_t),
			      MATCHFINDER_ALIGNMENT);
}

static inline void
bt_matchfinder_free(struct bt_matchfinder *mf)
{
	ALIGNED_FREE(mf);
}

static inline void
bt_matchfinder_init(struct bt_matchfinder *mf)
{
	matchfinder_init(mf->hash_tab, BT_MATCHFINDER_HASH_LENGTH);
}

static inline pos_t *
bt_child(struct bt_matchfinder *mf, pos_t node, int offset)
{
	if (MATCHFINDER_WINDOW_ORDER < sizeof(pos_t) * 8) {
		/* no cast needed */
		return &mf->child_tab[
			(matchfinder_slot_for_match(node) << 1) + offset];
	} else {
		return &mf->child_tab[(unsigned long)
			(matchfinder_slot_for_match(node) << 1) + offset];
	}
}

static inline pos_t *
bt_left_child(struct bt_matchfinder *mf, pos_t node)
{
	return bt_child(mf, node, 0);
}

static inline pos_t *
bt_right_child(struct bt_matchfinder *mf, pos_t node)
{
	return bt_child(mf, node, 1);
}

static inline struct lz_match *
bt_matchfinder_get_matches(struct bt_matchfinder * const restrict mf,
			   const u8 * const in_base,
			   const u8 * const in_next,
			   const unsigned min_len,
			   const unsigned max_len,
			   const unsigned nice_len,
			   const unsigned max_search_depth,
			   u32 * restrict prev_hash,
			   unsigned * restrict best_len_ret,
			   struct lz_match * restrict lz_matchptr)
{
	unsigned depth_remaining = max_search_depth;
	u32 hash;
	pos_t cur_match;
	const u8 *matchptr;
	pos_t *pending_lt_ptr, *pending_gt_ptr;
	unsigned best_lt_len, best_gt_len;
	unsigned len;
	unsigned best_len = min_len - 1;

	if (unlikely(max_len < LZ_HASH_REQUIRED_NBYTES + 1)) {
		*best_len_ret = best_len;
		return lz_matchptr;
	}

	hash = *prev_hash;
	*prev_hash = lz_hash_3_bytes(in_next + 1, BT_MATCHFINDER_HASH_ORDER);
	cur_match = mf->hash_tab[hash];
	mf->hash_tab[hash] = in_next - in_base;
	prefetch(&mf->hash_tab[*prev_hash]);

	pending_lt_ptr = bt_left_child(mf, in_next - in_base);
	pending_gt_ptr = bt_right_child(mf, in_next - in_base);
	best_lt_len = 0;
	best_gt_len = 0;
	len = 0;

	if (!matchfinder_match_in_window(cur_match, in_base, in_next)) {
		*pending_lt_ptr = MATCHFINDER_INITVAL;
		*pending_gt_ptr = MATCHFINDER_INITVAL;
		*best_len_ret = best_len;
		return lz_matchptr;
	}

	for (;;) {
		matchptr = &in_base[cur_match];

		if (matchptr[len] == in_next[len]) {
			len = lz_extend(in_next, matchptr, len + 1, max_len);
			if (len > best_len) {
				best_len = len;
				lz_matchptr->length = len;
				lz_matchptr->offset = in_next - matchptr;
				lz_matchptr++;
				if (len >= nice_len) {
					*pending_lt_ptr = *bt_left_child(mf, cur_match);
					*pending_gt_ptr = *bt_right_child(mf, cur_match);
					*best_len_ret = best_len;
					return lz_matchptr;
				}
			}
		}

		if (matchptr[len] < in_next[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = bt_right_child(mf, cur_match);
			cur_match = *pending_lt_ptr;
			best_lt_len = len;
			if (best_gt_len < len)
				len = best_gt_len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = bt_left_child(mf, cur_match);
			cur_match = *pending_gt_ptr;
			best_gt_len = len;
			if (best_lt_len < len)
				len = best_lt_len;
		}

		if (!matchfinder_match_in_window(cur_match,
						 in_base, in_next) ||
		    !--depth_remaining)
		{
			*pending_lt_ptr = MATCHFINDER_INITVAL;
			*pending_gt_ptr = MATCHFINDER_INITVAL;
			*best_len_ret = best_len;
			return lz_matchptr;
		}
	}
}

static inline void
bt_matchfinder_skip_position(struct bt_matchfinder * const restrict mf,
			     const u8 * const in_base,
			     const u8 * const in_next,
			     const u8 * const in_end,
			     const unsigned nice_len,
			     const unsigned max_search_depth,
			     u32 *prev_hash)
{
	unsigned depth_remaining = max_search_depth;
	u32 hash;
	pos_t cur_match;
	const u8 *matchptr;
	pos_t *pending_lt_ptr, *pending_gt_ptr;
	unsigned best_lt_len, best_gt_len;
	unsigned len;

	if (unlikely(in_end - in_next < LZ_HASH_REQUIRED_NBYTES + 1))
		return;

	hash = *prev_hash;
	*prev_hash = lz_hash_3_bytes(in_next + 1, BT_MATCHFINDER_HASH_ORDER);
	cur_match = mf->hash_tab[hash];
	mf->hash_tab[hash] = in_next - in_base;
	prefetch(&mf->hash_tab[*prev_hash]);

	depth_remaining = max_search_depth;
	pending_lt_ptr = bt_left_child(mf, in_next - in_base);
	pending_gt_ptr = bt_right_child(mf, in_next - in_base);
	best_lt_len = 0;
	best_gt_len = 0;
	len = 0;

	if (!matchfinder_match_in_window(cur_match, in_base, in_next)) {
		*pending_lt_ptr = MATCHFINDER_INITVAL;
		*pending_gt_ptr = MATCHFINDER_INITVAL;
		return;
	}

	for (;;) {

		matchptr = &in_base[cur_match];

		if (matchptr[len] == in_next[len]) {
			len = lz_extend(in_next, matchptr, len + 1, nice_len);
			if (len == nice_len) {
				*pending_lt_ptr = *bt_left_child(mf, cur_match);
				*pending_gt_ptr = *bt_right_child(mf, cur_match);
				return;
			}
		}

		if (matchptr[len] < in_next[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = bt_right_child(mf, cur_match);
			cur_match = *pending_lt_ptr;
			best_lt_len = len;
			if (best_gt_len < len)
				len = best_gt_len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = bt_left_child(mf, cur_match);
			cur_match = *pending_gt_ptr;
			best_gt_len = len;
			if (best_lt_len < len)
				len = best_lt_len;
		}

		if (!matchfinder_match_in_window(cur_match,
						 in_base, in_next) ||
		    !--depth_remaining)
		{
			*pending_lt_ptr = MATCHFINDER_INITVAL;
			*pending_gt_ptr = MATCHFINDER_INITVAL;
			return;
		}
	}
}

#endif /* _BT_MATCHFINDER_H */
