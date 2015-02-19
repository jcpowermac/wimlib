#include <stddef.h>
#include <limits.h>

/* The documented compression types.  */
static const int compression_types[] = {
	WIMLIB_COMPRESSION_TYPE_XPRESS,
	WIMLIB_COMPRESSION_TYPE_LZX,
	WIMLIB_COMPRESSION_TYPE_LZMS,
};

/* The compression type with the greatest enumeration value.  */
#define MAX_COMPRESSION_TYPE WIMLIB_COMPRESSION_TYPE_LZMS

/* The documented maximum block size of each compression type.  */
static const size_t max_block_sizes[] = {
	[WIMLIB_COMPRESSION_TYPE_XPRESS] = 1 << 16,
	[WIMLIB_COMPRESSION_TYPE_LZX] = 1 << 21,
	[WIMLIB_COMPRESSION_TYPE_LZMS] = 1 << 30,
};
