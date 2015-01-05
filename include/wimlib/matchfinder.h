/*
 * matchfinder.h
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _MATCHFINDER_H
#define _MATCHFINDER_H

#include "wimlib/lz_hash.h"
#include "wimlib/lz_extend.h"
#include "wimlib/unaligned.h"
#include "wimlib/util.h"

#include <string.h>

#ifndef MATCHFINDER_MAX_WINDOW_ORDER
#  error "MATCHFINDER_MAX_WINDOW_ORDER must be defined!"
#endif

#if MATCHFINDER_MAX_WINDOW_ORDER <= 16
typedef u16 pos_t;
#else
typedef u32 pos_t;
#endif

struct matchfinder {
	pos_t data[0];
};

#if MATCHFINDER_MAX_WINDOW_ORDER != 16 && MATCHFINDER_MAX_WINDOW_ORDER != 32

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

static inline void
matchfinder_init(struct matchfinder *mf, unsigned hash_order)
{
	const size_t num_entries = 1UL << hash_order;
	const size_t size = num_entries * sizeof(pos_t);

#ifdef __AVX2__
	if (matchfinder_init_avx2(mf->data, size))
		return;
#endif

#ifdef __SSE2__
	if (matchfinder_init_sse2(mf->data, size))
		return;
#endif

	if (matchfinder_memset_init_okay()) {
		memset(mf->data, (u8)MATCHFINDER_INITVAL, size);
		return;
	}

	for (size_t i = 0; i < num_entries; i++)
		mf->data[i] = MATCHFINDER_INITVAL;
}

static inline struct matchfinder *
matchfinder_alloc(size_t num_entries)
{
	return ALIGNED_MALLOC(num_entries * sizeof(pos_t),
			      MATCHFINDER_ALIGNMENT);
}

static inline struct matchfinder *
hc_matchfinder_alloc(unsigned hash_order, unsigned window_order)
{
	return matchfinder_alloc((1UL << hash_order) + (1UL << window_order));
}

static inline struct matchfinder *
bt_matchfinder_alloc(unsigned hash_order, unsigned window_order)
{
	return matchfinder_alloc((1UL << hash_order) + (2UL << window_order));
}

static inline void
matchfinder_free(struct matchfinder *mf)
{
	ALIGNED_FREE(mf);
}

static inline unsigned
hc_matchfinder_longest_match(struct matchfinder * const restrict mf,
			     const unsigned hash_order,
			     const u8 * const in_base,
			     const u8 * const in_next,
			     unsigned best_len,
			     const unsigned max_len,
			     const unsigned nice_len,
			     const unsigned max_search_depth,
			     unsigned *offset_ret)
{
	pos_t * const hash_tab = mf->data;
	pos_t * const next_tab = mf->data + (1UL << hash_order);
	unsigned depth_remaining = max_search_depth;
	const u8 *best_matchptr = best_matchptr; /* uninitialized */
	const u8 *matchptr;
	unsigned len;
	unsigned hash;
	pos_t cur_match;
	u32 first_3_bytes;

	/* Insert the current sequence into the appropriate hash chain.  */
	if (unlikely(max_len < LZ_HASH_REQUIRED_NBYTES))
		goto out;
	first_3_bytes = load_u24_unaligned(in_next);
	hash = lz_hash(first_3_bytes, hash_order);
	cur_match = hash_tab[hash];
	next_tab[in_next - in_base] = cur_match;
	hash_tab[hash] = in_next - in_base;

	if (unlikely(best_len >= max_len))
		goto out;

	/* Search the appropriate hash chain for matches.  */

	if (!(matchfinder_match_in_window(cur_match)))
		goto out;

	if (best_len < 3) {
		for (;;) {
			/* No length 3 match found yet.
			 * Check the first 3 bytes.  */
			matchptr = &in_base[cur_match];

			if (load_u24_unaligned(matchptr) == first_3_bytes)
				break;

			/* Not a match; keep trying.  */
			cur_match = next_tab[cur_match];
			if (!matchfinder_match_in_window(cur_match))
				goto out;
			if (!--depth_remaining)
				goto out;
		}

		/* Found a length 3 match.  */
		best_matchptr = matchptr;
		best_len = lz_extend(in_next, best_matchptr, 3, max_len);
		if (best_len >= nice_len)
			goto out;
		cur_match = next_tab[cur_match];
		if (!matchfinder_match_in_window(cur_match))
			goto out;
		if (!--depth_remaining)
			goto out;
	}

	for (;;) {
		for (;;) {
			matchptr = &in_base[cur_match];

			/* Already found a length 3 match.  Try for a longer match;
			 * start by checking the last 2 bytes and the first 4 bytes.  */
		#if UNALIGNED_ACCESS_IS_FAST
			if ((load_u32_unaligned(matchptr + best_len - 3) ==
			     load_u32_unaligned(in_next + best_len - 3)) &&
			    (load_u32_unaligned(matchptr) ==
			     load_u32_unaligned(in_next)))
		#else
			if (matchptr[best_len] == in_next[best_len])
		#endif
				break;

			cur_match = next_tab[cur_match];
			if (!matchfinder_match_in_window(cur_match))
				goto out;
			if (!--depth_remaining)
				goto out;
		}

		if (UNALIGNED_ACCESS_IS_FAST)
			len = 4;
		else
			len = 0;
		len = lz_extend(in_next, matchptr, len, max_len);
		if (len > best_len) {
			best_len = len;
			best_matchptr = matchptr;
			if (best_len >= nice_len)
				goto out;
		}
		cur_match = next_tab[cur_match];
		if (!matchfinder_match_in_window(cur_match))
			goto out;
		if (!--depth_remaining)
			goto out;
	}
out:
	*offset_ret = in_next - best_matchptr;
	return best_len;
}

static inline void
hc_matchfinder_skip_positions(struct matchfinder * const restrict mf,
			      const unsigned hash_order,
			      const u8 * const in_base,
			      const u8 *in_next,
			      const u8 * const in_end,
			      unsigned count)
{
	pos_t * const hash_tab = mf->data;
	pos_t * const next_tab = mf->data + (1UL << hash_order);
	unsigned hash;

	if (unlikely(in_next + count >= in_end - LZ_HASH_REQUIRED_NBYTES))
		return;

	do {
		hash = lz_hash_3_bytes(in_next, hash_order);
		next_tab[in_next - in_base] = hash_tab[hash];
		hash_tab[hash] = in_next - in_base;
		in_next++;
	} while (--count);
}

static inline pos_t *
bt_child(pos_t *child_tab, pos_t node, int offset)
{
	if (MATCHFINDER_MAX_WINDOW_ORDER < sizeof(pos_t) * 8) {
		/* no cast needed */
		return &child_tab[(node << 1) + offset];
	} else {
		return &child_tab[((unsigned long)node << 1) + offset];
	}
}

static inline pos_t *
bt_left_child(pos_t *child_tab, pos_t node)
{
	return bt_child(child_tab, node, 0);
}

static inline pos_t *
bt_right_child(pos_t *child_tab, pos_t node)
{
	return bt_child(child_tab, node, 1);
}

static inline struct lz_match *
bt_matchfinder_get_matches(struct matchfinder * const restrict mf,
			   const unsigned hash_order,
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
	pos_t * const hash_tab = mf->data;
	pos_t * const child_tab = mf->data + (1UL << hash_order);
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
	*prev_hash = lz_hash_3_bytes(in_next + 1, hash_order);
	cur_match = hash_tab[hash];
	hash_tab[hash] = in_next - in_base;
	prefetch(&hash_tab[*prev_hash]);

	pending_lt_ptr = bt_left_child(child_tab, in_next - in_base);
	pending_gt_ptr = bt_right_child(child_tab, in_next - in_base);
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
					*pending_lt_ptr = *bt_left_child(child_tab, cur_match);
					*pending_gt_ptr = *bt_right_child(child_tab, cur_match);
					*best_len_ret = best_len;
					return lz_matchptr;
				}
			}
		}

		if (matchptr[len] < in_next[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = bt_right_child(child_tab, cur_match);
			cur_match = *pending_lt_ptr;
			best_lt_len = len;
			if (best_gt_len < len)
				len = best_gt_len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = bt_left_child(child_tab, cur_match);
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
bt_matchfinder_skip_position(struct matchfinder * const restrict mf,
			     const unsigned hash_order,
			     const u8 * const in_base,
			     const u8 * const in_next,
			     const u8 * const in_end,
			     const unsigned nice_len,
			     const unsigned max_search_depth,
			     u32 *prev_hash)
{
	pos_t * const hash_tab = mf->data;
	pos_t * const child_tab = mf->data + (1UL << hash_order);
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
	*prev_hash = lz_hash_3_bytes(in_next + 1, hash_order);
	cur_match = hash_tab[hash];
	hash_tab[hash] = in_next - in_base;
	prefetch(&hash_tab[*prev_hash]);

	depth_remaining = max_search_depth;
	pending_lt_ptr = bt_left_child(child_tab, in_next - in_base);
	pending_gt_ptr = bt_right_child(child_tab, in_next - in_base);
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
				*pending_lt_ptr = *bt_left_child(child_tab, cur_match);
				*pending_gt_ptr = *bt_right_child(child_tab, cur_match);
				return;
			}
		}

		if (matchptr[len] < in_next[len]) {
			*pending_lt_ptr = cur_match;
			pending_lt_ptr = bt_right_child(child_tab, cur_match);
			cur_match = *pending_lt_ptr;
			best_lt_len = len;
			if (best_gt_len < len)
				len = best_gt_len;
		} else {
			*pending_gt_ptr = cur_match;
			pending_gt_ptr = bt_left_child(child_tab, cur_match);
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

#endif /* _MATCHFINDER_H */
