/*
 * bt_matchfinder.h
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

/*
 * This is a Binary Tree (bt) based matchfinder.
 *
 * The data structure is a hash table where each hash bucket contains a binary
 * tree of sequences, referenced by position.  The sequences in the binary tree
 * are ordered such that a left child is lexicographically lesser than its
 * parent, and a right child is lexicographically greater than its parent.
 *
 * For each sequence (position) in the input, the first 3 bytes are hashed and
 * the the appropriate binary tree is re-rooted at that sequence (position).
 * Since the sequences are inserted in order, each binary tree maintains the
 * invariant that each child node has greater match offset than its parent.
 *
 * While inserting a sequence, we may search the binary tree for matches with
 * that sequence.  At each step, the length of the match is computed.  The
 * search ends when the sequences get too far away (outside of the sliding
 * window), or when the binary tree ends (in the code this is the same check as
 * "too far away"), or when 'max_search_depth' positions have been searched, or
 * when a match of at least 'nice_len' bytes has been found.
 *
 * Notes:
 *
 *	- Typically, we need to search more nodes to find a given match in a
 *	  binary tree versus in a linked list.  However, a binary tree has more
 *	  overhead than a linked list: it needs to be kept sorted, and the inner
 *	  search loop is more complicated.  As a result, binary trees are best
 *	  suited for compression modes where the potential matches are searched
 *	  more thoroughly.
 *
 *	- Since no attempt is made to keep the binary trees balanced, it's
 *	  essential to have the 'max_search_depth' cutoff.  Otherwise it could
 *	  take quadratic time to run data through the matchfinder.
 */

#ifndef _BT_MATCHFINDER_H
#define _BT_MATCHFINDER_H

#include "wimlib/lz_extend.h"
#include "wimlib/lz_hash.h"
#include "wimlib/matchfinder_common.h"
#include "wimlib/util.h"

#if MATCHFINDER_MAX_WINDOW_ORDER < 13
#  define BT_MATCHFINDER_HASH_ORDER 14
#elif MATCHFINDER_MAX_WINDOW_ORDER < 15
#  define BT_MATCHFINDER_HASH_ORDER 15
#else
#  define BT_MATCHFINDER_HASH_ORDER 16
#endif

#define BT_MATCHFINDER_HASH_LENGTH	(1UL << BT_MATCHFINDER_HASH_ORDER)

struct bt_matchfinder {
	pos_t hash_tab[BT_MATCHFINDER_HASH_LENGTH];
	pos_t child_tab[];
} _aligned_attribute(MATCHFINDER_ALIGNMENT);

static inline size_t
bt_matchfinder_size(unsigned long window_size)
{
	return sizeof(pos_t) * (BT_MATCHFINDER_HASH_LENGTH + (2 * window_size));
}

static inline void
bt_matchfinder_init(struct bt_matchfinder *mf)
{
	matchfinder_init(mf->hash_tab, BT_MATCHFINDER_HASH_LENGTH);
}

static inline pos_t *
bt_child(struct bt_matchfinder *mf, pos_t node, int offset)
{
	if (MATCHFINDER_MAX_WINDOW_ORDER < sizeof(pos_t) * 8) {
		/* no cast needed */
		return &mf->child_tab[(node << 1) + offset];
	} else {
		return &mf->child_tab[((unsigned long)node << 1) + offset];
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

	if (!matchfinder_match_in_window(cur_match)) {
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

		if (!matchfinder_match_in_window(cur_match) ||
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

	if (!matchfinder_match_in_window(cur_match)) {
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

		if (!matchfinder_match_in_window(cur_match) ||
		    !--depth_remaining)
		{
			*pending_lt_ptr = MATCHFINDER_INITVAL;
			*pending_gt_ptr = MATCHFINDER_INITVAL;
			return;
		}
	}
}

#endif /* _BT_MATCHFINDER_H */
