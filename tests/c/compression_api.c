/*
 * compression_api.c
 *
 * Test the compression API.  (But not compression itself.)
 */

#include "testsuite.h"
#include "compression.h"

TEST(wimlib_create_compressor_fails_if_compressor_ret_not_specified)
{
	int ret;

	ret = wimlib_create_compressor(WIMLIB_COMPRESSION_TYPE_LZX, 32768, 0, NULL);
	assert_eq(WIMLIB_ERR_INVALID_PARAM, ret);
}

TEST(wimlib_create_compressor__fails_if_ctype_is_invalid)
{
	struct wimlib_compressor *c;
	int ret;

	/* Clearly invalid */
	ret = wimlib_create_compressor(848284, 32768, 0, &c);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	/* Check bounds */
	ret = wimlib_create_compressor(-1, 32768, 0, &c);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	ret = wimlib_create_compressor(MAX_COMPRESSION_TYPE + 1, 32768, 0, &c);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	/* NONE is also not valid  */
	ret = wimlib_create_compressor(WIMLIB_COMPRESSION_TYPE_NONE, 32768, 0, &c);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);
}

TEST(wimlib_create_compressor__test_max_block_sizes)
{
	/* Try each compression type.  */
	for (int i = 0; i < ARRAY_LEN(compression_types); i++) {

		int ctype = compression_types[i];
		size_t max_block_size = max_block_sizes[ctype];

		struct wimlib_compressor *c;
		int ret;

		/* 0 is always bad.  */
		ret = wimlib_create_compressor(ctype, 0, 0, &c);
		assert_eq(WIMLIB_ERR_INVALID_PARAM, ret);

		/* Any other number from 1 to the maximum should be okay, even
		 * not a power of 2.  */
		ret = wimlib_create_compressor(ctype, 1, 0, &c);
		if (ret != 0)
			fail("ctype=%d", ctype);
		if (ret == 0)
			wimlib_free_compressor(c);

		ret = wimlib_create_compressor(ctype, max_block_size, 0, &c);
		if (ret != 0 && ret != WIMLIB_ERR_NOMEM)
			fail("ctype=%d", ctype);
		if (ret == 0)
			wimlib_free_compressor(c);

		ret = wimlib_create_compressor(ctype, max_block_size + 1, 0, &c);
		if (ret != WIMLIB_ERR_INVALID_PARAM)
			fail("ctype=%d", ctype);

		ret = wimlib_create_compressor(ctype, max_block_size / 2, 0, &c);
		if (ret != 0 && ret != WIMLIB_ERR_NOMEM)
			fail("ctype=%d", ctype);
		if (ret == 0)
			wimlib_free_compressor(c);

		ret = wimlib_create_compressor(ctype, max_block_size / 2 + 1, 0, &c);
		if (ret != 0 && ret != WIMLIB_ERR_NOMEM)
			fail("ctype=%d", ctype);
		if (ret == 0)
			wimlib_free_compressor(c);
	}
}

TEST(wimlib_get_compressor_needed_memory__test_max_block_sizes)
{
	/* Try each compression type.  */
	for (int i = 0; i < ARRAY_LEN(compression_types); i++) {

		int ctype = compression_types[i];
		size_t max_block_size = max_block_sizes[ctype];
		uint64_t size;

		/* 0 is always bad.  */
		size = wimlib_get_compressor_needed_memory(ctype, 0, 0);
		if (size != 0)
			fail("ctype=%d", ctype);

		/* Any other number from 1 to the maximum should be okay, even
		 * not a power of 2.  */
		size = wimlib_get_compressor_needed_memory(ctype, 1, 0);
		if (size == 0)
			fail("ctype=%d", ctype);

		size = wimlib_get_compressor_needed_memory(ctype, max_block_size / 2, 0);
		if (size == 0)
			fail("ctype=%d", ctype);

		size = wimlib_get_compressor_needed_memory(ctype, max_block_size / 2 + 1, 0);
		if (size == 0)
			fail("ctype=%d", ctype);

		size = wimlib_get_compressor_needed_memory(ctype, max_block_size, 0);
		if (size == 0)
			fail("ctype=%d", ctype);

		size = wimlib_get_compressor_needed_memory(ctype, max_block_size + 1, 0);
		if (size != 0)
			fail("ctype=%d", ctype);
	}
}

TEST(wimlib_set_default_compression_level__fails_if_ctype_is_invalid)
{
	int ret;

	/* Clearly invalid */
	ret = wimlib_set_default_compression_level(848284, 80);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	/* Check bounds */
	ret = wimlib_set_default_compression_level(-2, 80);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	ret = wimlib_set_default_compression_level(MAX_COMPRESSION_TYPE + 1, 80);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	/* NONE is also not valid  */
	ret = wimlib_set_default_compression_level(WIMLIB_COMPRESSION_TYPE_NONE, 80);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	/* But -1 is valid (means "all")  */
	ret = wimlib_set_default_compression_level(-1, 80);
	assert_eq(0, ret);

	/* Reset before continuing */
	ret = wimlib_set_default_compression_level(-1, 0);
	assert_eq(0, ret);
}

TEST(wimlib_get_compressor_needed_memory__is_sane)
{
	uint64_t size;
	uint64_t fastsize, slowsize;

	/* Sanity checks for specific compression types  */

	size = wimlib_get_compressor_needed_memory(WIMLIB_COMPRESSION_TYPE_XPRESS, 32768, 50);
	assert_bounded(32768 * 4, 32768 * 20, size);

	size = wimlib_get_compressor_needed_memory(WIMLIB_COMPRESSION_TYPE_XPRESS, 65536, 50);
	assert_bounded(65536 * 4, 65536 * 20, size);

	size = wimlib_get_compressor_needed_memory(WIMLIB_COMPRESSION_TYPE_LZX, 2097152, 50);
	assert_bounded(2097152 * 4, 2097152 * 15, size);

	size = wimlib_get_compressor_needed_memory(WIMLIB_COMPRESSION_TYPE_LZMS, 32768, 50);
	assert_bounded(32768 * 4, 32768 * 51, size);

	size = wimlib_get_compressor_needed_memory(WIMLIB_COMPRESSION_TYPE_LZMS, 67108864, 50);
	assert_bounded(67108864 * 4, 67108864 * 20, size);

	/* Lower compression levels should, as a general rule, require less
	 * memory than higher compression levels.  */
	for (int i = 0; i < ARRAY_LEN(compression_types); i++) {

		int ctype = compression_types[i];

		fastsize = wimlib_get_compressor_needed_memory(ctype, 32768, 20);
		slowsize = wimlib_get_compressor_needed_memory(ctype, 32768, 100);
		assert_le(slowsize, fastsize);
	}
}

TEST(wimlib_get_compressor_needed_memory__works_with_default_compression_level)
{
	uint64_t expected;
	uint64_t actual;

	wimlib_set_default_compression_level(WIMLIB_COMPRESSION_TYPE_LZX, 100);
	expected = wimlib_get_compressor_needed_memory(WIMLIB_COMPRESSION_TYPE_LZX, 32768, 100);
	actual = wimlib_get_compressor_needed_memory(WIMLIB_COMPRESSION_TYPE_LZX, 32768, 0);
	assert_eq(expected, actual);

	wimlib_set_default_compression_level(WIMLIB_COMPRESSION_TYPE_LZX, 0);
}

TEST(wimlib_compress__fails_if_uncompressed_size_exceeds_max_block_size)
{
	int ret;
	struct wimlib_compressor *c;
	char ubuf[1];
	char cbuf[1];
	size_t csize;

	ret = wimlib_create_compressor(WIMLIB_COMPRESSION_TYPE_LZX, 32767, 0, &c);
	assert_eq(ret, 0);

	/* Buffers shouldn't even be accessed.  (Will be detected when running
	 * with valgrind.)  */
	csize = wimlib_compress(ubuf, 32768, cbuf, 20000, c);
	assert_eq(0, csize);

	wimlib_free_compressor(c);
}

TEST(wimlib_free_compressor__ignores_null)
{
	wimlib_free_compressor(NULL);
}
