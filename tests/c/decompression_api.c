/*
 * decompression_api.c
 *
 * Test the decompression API.  (But not decompression itself.)
 */

#include "testsuite.h"
#include "compression.h"

TEST(wimlib_create_decompressor__fails_if_decompressor_ret_not_specified)
{
	int ret;

	ret = wimlib_create_decompressor(WIMLIB_COMPRESSION_TYPE_LZX, 32768, NULL);
	assert_eq(WIMLIB_ERR_INVALID_PARAM, ret);
}

TEST(wimlib_create_decompressor__fails_if_ctype_is_invalid)
{
	struct wimlib_decompressor *c;
	int ret;

	/* Clearly invalid */
	ret = wimlib_create_decompressor(848284, 32768, &c);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	/* Check bounds */
	ret = wimlib_create_decompressor(-1, 32768, &c);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	ret = wimlib_create_decompressor(MAX_COMPRESSION_TYPE + 1, 32768, &c);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);

	/* NONE is also not valid  */
	ret = wimlib_create_decompressor(WIMLIB_COMPRESSION_TYPE_NONE, 32768, &c);
	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE, ret);
}

TEST(wimlib_create_decompressor__test_max_block_sizes)
{
	/* Try each compression type.  */
	for (int i = 0; i < ARRAY_LEN(compression_types); i++) {

		int ctype = compression_types[i];
		size_t max_block_size = max_block_sizes[ctype];

		struct wimlib_decompressor *d;
		int ret;

		/* 0 is always bad.  */
		ret = wimlib_create_decompressor(ctype, 0, &d);
		assert_eq(WIMLIB_ERR_INVALID_PARAM, ret);

		/* Any other number from 1 to the maximum should be okay, even
		 * not a power of 2.  */
		ret = wimlib_create_decompressor(ctype, 1, &d);
		if (ret != 0)
			fail("ctype=%d", ctype);
		if (ret == 0)
			wimlib_free_decompressor(d);

		ret = wimlib_create_decompressor(ctype, max_block_size, &d);
		if (ret != 0 && ret != WIMLIB_ERR_NOMEM)
			fail("ctype=%d", ctype);
		if (ret == 0)
			wimlib_free_decompressor(d);

		ret = wimlib_create_decompressor(ctype, max_block_size + 1, &d);
		if (ret != WIMLIB_ERR_INVALID_PARAM)
			fail("ctype=%d", ctype);

		ret = wimlib_create_decompressor(ctype, max_block_size / 2, &d);
		if (ret != 0 && ret != WIMLIB_ERR_NOMEM)
			fail("ctype=%d", ctype);
		if (ret == 0)
			wimlib_free_decompressor(d);

		ret = wimlib_create_decompressor(ctype, max_block_size / 2 + 1, &d);
		if (ret != 0 && ret != WIMLIB_ERR_NOMEM)
			fail("ctype=%d", ctype);
		if (ret == 0)
			wimlib_free_decompressor(d);
	}
}

TEST(wimlib_decompress__fails_if_uncompressed_size_exceeds_max_block_size)
{
	int ret;
	struct wimlib_decompressor *d;
	char cbuf[1];
	char ubuf[1];

	ret = wimlib_create_decompressor(WIMLIB_COMPRESSION_TYPE_LZX, 32767, &d);
	assert_eq(ret, 0);

	/* Buffers shouldn't even be accessed.  (Will be detected when running
	 * with valgrind.)  */
	ret = wimlib_decompress(cbuf, 20000, ubuf, 32768, d);
	assert_neq(ret, 0);

	wimlib_free_decompressor(d);
}

TEST(wimlib_free_decompressor__ignores_null)
{
	wimlib_free_decompressor(NULL);
}
