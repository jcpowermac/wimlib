/*
 * lzms_common.h
 *
 * Declarations shared between LZMS compression and decompression.
 */

#ifndef _LZMS_COMMON_H
#define _LZMS_COMMON_H

#include "wimlib/compiler.h"
#include "wimlib/lzms_constants.h"
#include "wimlib/types.h"

/* Offset slot tables  */
extern const u32 lzms_offset_slot_base[LZMS_MAX_NUM_OFFSET_SYMS + 1];
extern const u8 lzms_extra_offset_bits[LZMS_MAX_NUM_OFFSET_SYMS];

/* Length slot tables  */
extern const u32 lzms_length_slot_base[LZMS_NUM_LENGTH_SYMS + 1];
extern const u8 lzms_extra_length_bits[LZMS_NUM_LENGTH_SYMS];

extern unsigned
lzms_get_slot(u32 value, const u32 slot_base_tab[], unsigned num_slots);

/* Return the offset slot for the specified offset  */
static inline unsigned
lzms_get_offset_slot(u32 offset)
{
	return lzms_get_slot(offset, lzms_offset_slot_base, LZMS_MAX_NUM_OFFSET_SYMS);
}

/* Return the length slot for the specified length  */
static inline unsigned
lzms_get_length_slot(u32 length)
{
	return lzms_get_slot(length, lzms_length_slot_base, LZMS_NUM_LENGTH_SYMS);
}

extern unsigned
lzms_get_num_offset_slots(size_t uncompressed_size);


/* Probability entry for use by the range coder when in a specific state  */
struct lzms_probability_entry {

	/* The probability value, with an implied denominator of
	 * LZMS_PROBABILITY_DENOMINATOR.  This is equal to the number of zeroes
	 * in the most recent LZMS_PROBABILITY_DENOMINATOR bits that have been
	 * coded using this probability entry.  This is a cached value because
	 * it can be computed as the number of zeroes in @recent_bits.  */
	u32 prob;

	/* The most recent LZMS_PROBABILITY_DENOMINATOR bits that have been
	 * coded using this probability entry.  The bits are ordered such that
	 * low order is newest and high order is oldest.  */
	u64 recent_bits;
};

extern void
lzms_init_probability_entries(struct lzms_probability_entry *entries, size_t count);

/* Given a decoded or encoded bit, update the probability entry.  */
static inline void
lzms_update_probability_entry(struct lzms_probability_entry *entry, int bit)
{
	BUILD_BUG_ON(LZMS_PROBABILITY_DENOMINATOR != sizeof(entry->recent_bits) * 8);

	s32 delta_zero_bits = (s32)(entry->recent_bits >>
				    (LZMS_PROBABILITY_DENOMINATOR - 1)) - bit;

	entry->prob += delta_zero_bits;
	entry->recent_bits <<= 1;
	entry->recent_bits |= bit;
}

/* Given a probability entry, return the chance out of
 * LZMS_PROBABILITY_DENOMINATOR that the next decoded bit will be a 0.  */
static inline u32
lzms_get_probability(const struct lzms_probability_entry *prob_entry)
{
	u32 prob = prob_entry->prob;

	/* 0% and 100% probabilities aren't allowed.  */
	if (prob == 0)
		prob++;
	if (prob == LZMS_PROBABILITY_DENOMINATOR)
		prob--;
	return prob;
}

extern void
lzms_init_symbol_frequencies(u32 freqs[], unsigned num_syms);

extern void
lzms_dilute_symbol_frequencies(u32 freqs[], unsigned num_syms);

/* Pre/post-processing  */
extern void
lzms_x86_filter(u8 data[], s32 size, s32 last_target_usages[], bool undo);

#endif /* _LZMS_COMMON_H */
