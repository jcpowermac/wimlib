/*
 * lzms_constants.h
 *
 * Constants for the LZMS compression format.
 */

#ifndef _LZMS_CONSTANTS_H
#define _LZMS_CONSTANTS_H

/* The smallest and largest allowed match lengths, in bytes  */
#define LZMS_MIN_MATCH_LEN			1
#define LZMS_MAX_MATCH_LEN			1073809578

/* The largest allowed match offset, in bytes.  (The smallest is 1.)  */
#define LZMS_MAX_MATCH_OFFSET			1180427428

/* The value to which buffer sizes should be limited.  Microsoft's
 * implementation seems to use only 67108864 (2^26) bytes as the limit, even
 * though the format itself supports much higher match lengths and offsets.
 * We'll use 2^30 as our limit.  */
#define LZMS_MAX_BUFFER_SIZE			1073741824

/* The number of entries in the LRU queue for offsets of LZ matches  */
#define LZMS_NUM_LZ_REPS			3

/* The number of entries in the LRU queue for (power, raw_offset) pairs of delta
 * matches  */
#define LZMS_NUM_DELTA_REPS			3

/* The maximum number of bits (binary decisions) that are needed to encode an
 * index in the LRU queue for offsets of LZ matches  */
#define LZMS_NUM_LZ_REP_DECISIONS		(LZMS_NUM_LZ_REPS - 1)

/* The maximum number of bits (binary decisions) that are needed to encode an
 * index in the LRU queue for (power, raw offset) pairs of LZ matches  */
#define LZMS_NUM_DELTA_REP_DECISIONS		(LZMS_NUM_DELTA_REPS - 1)

/* These values define the precision for probabilities in LZMS, which are always
 * given as a numerator; the implied denominator is LZMS_PROBABILITY_MAX.  */
#define LZMS_PROBABILITY_BITS			6
#define LZMS_PROBABILITY_MAX			(1 << LZMS_PROBABILITY_BITS)

/* These values define the initial state of each probability entry.  */
#define LZMS_INITIAL_PROBABILITY		48
#define LZMS_INITIAL_RECENT_BITS		0x0000000055555555

/* The number of states within each of the various bit contexts  */
#define LZMS_NUM_MAIN_PROBS			16
#define LZMS_NUM_MATCH_PROBS			32
#define LZMS_NUM_LZ_PROBS			64
#define LZMS_NUM_LZ_REP_PROBS			64
#define LZMS_NUM_DELTA_PROBS			64
#define LZMS_NUM_DELTA_REP_PROBS		64

/* The number of symbols in each alphabet  */
#define LZMS_NUM_LITERAL_SYMS			256
#define LZMS_NUM_LENGTH_SYMS			54
#define LZMS_NUM_DELTA_POWER_SYMS		8
#define LZMS_MAX_NUM_OFFSET_SYMS		799
#define LZMS_MAX_NUM_SYMS			799

/* Codeword lengths will never exceed this value.  */
#define LZMS_MAX_CODEWORD_LEN			15

/* The rebuild frequencies (in symbols) for each Huffman code  */
#define LZMS_LITERAL_CODE_REBUILD_FREQ		1024
#define LZMS_LZ_OFFSET_CODE_REBUILD_FREQ	1024
#define LZMS_LENGTH_CODE_REBUILD_FREQ		512
#define LZMS_DELTA_OFFSET_CODE_REBUILD_FREQ	1024
#define LZMS_DELTA_POWER_CODE_REBUILD_FREQ	512

/* The maximum number of "extra bits" needed to encode a match length  */
#define LZMS_MAX_EXTRA_LENGTH_BITS		30

/* The maximum number of "extra bits" needed to encode a match offset  */
#define LZMS_MAX_EXTRA_OFFSET_BITS		30

#define LZMS_X86_ID_WINDOW_SIZE			65535
#define LZMS_X86_MAX_TRANSLATION_OFFSET		1023

#endif /* _LZMS_CONSTANTS_H */
