/*
 * lz77.c
 *
 * This file provides the code to analyze a buffer of uncompressed data for
 * matches, as per the LZ77 algorithm.  It uses a hash table to accelerate the
 * process.  This is based on code from zlib (v. 1.2.5).
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 * Copyright (C) 1995-2010 Jean-loup Gailly and Mark Adler
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/assert.h"
#include "wimlib/error.h"
#include "wimlib/compress.h"
#include "wimlib/util.h"

#include <string.h>

#define LZ_MIN_MATCH 3

#define HASH_BITS	15
#define HASH_SIZE	(1 << HASH_BITS)
#define HASH_MASK	(HASH_SIZE - 1)

#if LZ_MIN_MATCH == 2
#	define HASH_SHIFT	8
#elif LZ_MIN_MATCH == 3
#	define HASH_SHIFT	5
#else
#error "Invalid LZ_MIN_MATCH"
#endif

/*
 * Returns the longest match for a given input position.
 *
 * @window:		The window of uncompressed data.
 * @bytes_remaining:	The number of bytes remaining in the window.
 * @strstart:		The index of the start of the string in the window that
 * 				we are trying to find a match for.
 * @prev_tab:		The array of prev pointers for the hash table.
 * @cur_match:		The index of the head of the hash chain for matches
 * 				having the hash value of the string beginning
 * 				at index @strstart.
 * @prev_len:		The length of the match that was found for the string
 * 				beginning at (@strstart - 1).
 * @match_offset_ret:	A location into which the offset of the match be returned.
 * @params:		Parameters that affect how long the search will proceed
 * 				before going with the best that has been found
 * 				so far.
 *
 * Returns the length of the match that was found.
 */
static unsigned
longest_match(const u8 window[], unsigned bytes_remaining,
	      unsigned strstart, const u16 prev_tab[],
	      unsigned cur_match, unsigned prev_len,
	      unsigned *match_offset_ret,
	      unsigned * chain_len,
	      const struct lz_params *params)
{
	const u8 *scan = window + strstart;
	const u8 *match;
	unsigned len;
	unsigned best_len = prev_len;
	unsigned best_match_offset = strstart;
	unsigned match_start = cur_match;

	unsigned nice_match = min(params->nice_match, bytes_remaining);

	const u8 *strend = scan + min(params->max_match, bytes_remaining);

	u8 scan_end1 = scan[best_len - 1];
	u8 scan_end = scan[best_len];

#if 0
	/* Do not waste too much time if we already have a good match: */
	if (best_len >= params->good_match)
		chain_len >>= 2;
#endif

	do {
		match = &window[cur_match];

		/* Skip to next match if the match length cannot increase or if
		 * the match length is less than 2.  Note that the checks below
		 * for insufficient lookahead only occur occasionally for
		 * performance reasons.  Therefore uninitialized memory will be
		 * accessed, and conditional jumps will be made that depend on
		 * those values.  However the length of the match is limited to
		 * the lookahead, so the output of deflate is not affected by
		 * the uninitialized values.
		 */

		if (match[best_len] != scan_end
		    /*|| match[best_len - 1] != scan_end1*/
		    || *match != *scan
		    || *++match != scan[1])
			continue;
		scan++;

	#if 0
		do {
		} while (scan < strend && *++match == *++scan);
	#else


		do {
		} while (
			 *++match == *++scan && *++match == *++scan &&
			 *++match == *++scan && *++match == *++scan &&
			 *++match == *++scan && *++match == *++scan &&
			 *++match == *++scan && *++match == *++scan &&
			 scan < strend);
	#endif
		len = match - &window[cur_match];

		scan = &window[strstart];

		if (len > best_len) {
			match_start = cur_match;
			best_len = len;
			best_match_offset = strstart - match_start;
			if (len >= nice_match)
				break;
			scan_end1  = scan[best_len - 1];
			scan_end   = scan[best_len];
		}
	} while (--*chain_len != 0 && (cur_match = prev_tab[cur_match]) != 0);
	*match_offset_ret = best_match_offset;
	return min(min(best_len, bytes_remaining), params->max_match);
}

static inline unsigned
update_hash1(unsigned hash1, u8 c)
{
	return ((hash1 << HASH_SHIFT) ^ c) & HASH_MASK;
}

static inline unsigned
update_hash2(unsigned hash2, u8 c)
{
	return (hash2 << 2) | (c & 3);
}

static void
lz_init_hash_tabs(u16 hash1_tab[restrict], u16 hash2_tab[restrict],
		  u8 hash2_nchars_tab[restrict],
		  const u8 window[restrict], unsigned window_size)
{
	unsigned hash1;
	unsigned i;
	u16 hash_freq_tab[HASH_SIZE];
	unsigned hash2_pos;

	/* Count the frequency of each level-1 hash code within the window.  */
	hash1 = 0;
	ZERO_ARRAY(hash_freq_tab);
	for (i = 0; i < window_size; i++)
	{
		hash1 = update_hash1(hash1, window[i]);
		hash_freq_tab[hash1]++;
	}

	/* Allocate blocks in the level-2 hash table.
	 *
	 * Set up hash1_tab to map each level-1 hash code to the index of the
	 * corresponding block in the level-2 hash table.  Choose the size of
	 * each block in the level-2 hash table to be proportional to the base-2
	 * logarithm of the number of times the corresponding level-1 hash code
	 * appears in the window.  */
	hash2_pos = 0;
	for (hash1 = 0; hash1 < HASH_SIZE; hash1++) {
		if (hash_freq_tab[hash1]) {
			unsigned hash2_nchars;

			hash1_tab[hash1] = hash2_pos;
			hash2_nchars = bsr32(hash_freq_tab[hash1]) >> 1;
			hash2_nchars_tab[hash1] = hash2_nchars;
			hash2_pos += 1U << (hash2_nchars << 1);
		}
	}

	/* Initialize the level-2 hash table to all 0s, indicating that all hash
	 * chains are empty.  */
	memset(hash2_tab, 0, window_size * sizeof(hash2_tab[0]));
}

/*
 * Determines the sequence of matches and literals that a block of data will be
 * compressed to.
 *
 * @window:	The data that is to be compressed.
 * @window_size:	The length of @window, in bytes.
 * @match_tab:		An array for the intermediate representation of matches.
 * @record_match:	A function that will be called to produce the
 * 				intermediate representation of a match, given
 * 				the offset and length.  This function should also
 * 				update the appropriate symbol frequency counts
 * 				so that any needed Huffman codes can be made
 * 				later.
 * @record_literal:	A function that will be called to produce the
 * 				intermediate representation of a literal, given
 * 				the character of the literal.  This function
 * 				should also update the appropriate symbol
 * 				frequency counts so that any needed Huffman
 * 				codes can be made later.
 * @record_match_arg_1:
 * @record_match_arg_2:	Extra arguments to be passed to @record_match.
 * @record_literal_arg:	Extra arguments to be passed to @record_literal.
 * @params:		Structure that contains parameters that affect how the
 * 				analysis proceeds (mainly how good the matches
 * 				have to be).
 *
 * Returns the total number of matches and literal bytes that were found; this
 * is the number of slots in @match_tab that have been filled with the
 * intermediate representation of a match or literal byte.
 */
unsigned
lz_analyze_block(const u8 window[],
		 unsigned window_size,
		 u32 match_tab[],
		 lz_record_match_t record_match,
		 lz_record_literal_t record_literal,
		 void *record_match_arg1,
		 void *record_match_arg2,
		 void *record_literal_arg,
		 const struct lz_params *params)
{
	u16 hash1_tab[HASH_SIZE];
	u8  hash2_nchars_tab[HASH_SIZE];
	u16 hash2_tab[window_size];
	u16 prev_tab[window_size];
	unsigned hash1;
	unsigned hash2;
	const unsigned hash2_lookahead = LZ_MIN_MATCH + sizeof(hash2) * (8 / 2);
	unsigned inserts_remaining;
	unsigned match_offset;
	unsigned match_len;
	unsigned prev_offset;
	unsigned prev_len;
	bool match_available;
	unsigned cur_match_pos;

	lz_init_hash_tabs(hash1_tab, hash2_tab, hash2_nchars_tab,
			  window, window_size);

	hash1 = 0;
	for (unsigned i = 0; i < min(window_size, LZ_MIN_MATCH - 1); i++)
	{
		hash1 = update_hash1(hash1, window[i]);
	}

	hash2 = 0;
	for (unsigned i = LZ_MIN_MATCH; i < min(window_size, hash2_lookahead - 1); i++)
	{
		hash2 = update_hash2(hash2, window[i]);
	}

	match_available = false;
	inserts_remaining = 0;
	match_len = 0;
	cur_match_pos = 0;

	for (unsigned i = 0; i < window_size; i++)
	{
		unsigned base, offset;

		/* Update level-2 hash code.  */
		if (window_size - i >= hash2_lookahead)
			hash2 = update_hash2(hash2, window[i + hash2_lookahead - 1]);
		else
			hash2 <<= 2;

		/* Update level-1 hash code.  */
		if (window_size - i >= LZ_MIN_MATCH)
			hash1 = update_hash1(hash1, window[i + LZ_MIN_MATCH - 1]);

		/* Prepare base and offset in level 2-table.  */
		if (window_size - i >= LZ_MIN_MATCH) {
			base = hash1_tab[hash1];

			if (hash2_nchars_tab[hash1] == 0)
				offset = 0;
			else
				offset = hash2 >> (2 * (hash2_lookahead -
							LZ_MIN_MATCH -
							hash2_nchars_tab[hash1]));
		}

		/* If a match is already covering this position, update the
		 * level-2 hash table, but don't look for a match at this
		 * position.  */
		if (inserts_remaining) {
			prev_tab[i] = hash2_tab[base + offset];
			hash2_tab[base + offset] = i;
			--inserts_remaining;
			continue;
		}

		/* Save previous match.  */
		prev_len = match_len;
		prev_offset = match_offset;

		match_len = 0;

		/* Look for longest match at this position.  */
		if (prev_len < params->max_lazy_match &&
		    window_size - i >= LZ_MIN_MATCH)
		{
			unsigned xor_mask = 0;
			unsigned xor_limit = 1;
			unsigned maxlen = min(params->max_match, window_size - i);
			unsigned num_hash2_chars = hash2_nchars_tab[hash1];
			unsigned best_len = 1;
			unsigned best_offset = 0;
			unsigned hash_head;
			unsigned chain_len = params->max_chain_len;

			for (;;) {
				for (; xor_mask < xor_limit; xor_mask++) {

					hash_head = hash2_tab[base + (offset ^ xor_mask)];

					if (hash_head == 0)
						continue;

					match_len = longest_match(window,
								  window_size - i,
								  i,
								  prev_tab,
								  hash_head,
								  best_len,
								  &match_offset,
								  &chain_len,
								  params);
					if (match_len >= best_len &&
					    (match_len > best_len ||
					     match_offset < best_offset))
					{
						best_len = match_len;
						best_offset = match_offset;
					}
					if (chain_len == 0)
						goto matchend;
				}
				if (best_len >= maxlen)
					break;

				if (num_hash2_chars == 0)
					break;

				--num_hash2_chars;

				xor_limit <<= 2;

				maxlen = LZ_MIN_MATCH + num_hash2_chars;
			}
		matchend:

			match_len = best_len;
			match_offset = best_offset;

			if (match_offset == 0)
				match_len = 0;

			if (match_len == params->min_match &&
			    match_offset > params->too_far)
				match_len = 0;
		}

		/* Update the level-2 hash table.  */
		prev_tab[i] = hash2_tab[base + offset];
		hash2_tab[base + offset] = i;

		/* If there was a match at the previous step and the current
		 * match is not better, output the previous match:
		 */
		if (prev_len >= params->min_match && match_len <= prev_len) {

			match_tab[cur_match_pos++] =
				(*record_match)(prev_offset,
						prev_len,
						record_match_arg1,
						record_match_arg2);
			inserts_remaining = prev_len - 2;
			match_available = false;
			match_len = 0;
		} else if (match_available) {
			match_tab[cur_match_pos++] =
				(*record_literal)(window[i - 1],
						  record_literal_arg);
		} else {
			match_available = true;
		}
	}
	if (match_available) {
		match_tab[cur_match_pos++] =
			(*record_literal)(window[window_size - 1], record_literal_arg);
	}
	return cur_match_pos;
}
