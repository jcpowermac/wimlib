#include "testsuite.h"
#include <string.h>
#include <stdlib.h>

static int
do_xpress_decompress(const void *cdata, size_t csize, void *udata,
		     size_t usize)
{
	int ret;
	struct wimlib_decompressor *d;

	ret = wimlib_create_decompressor(WIMLIB_COMPRESSION_TYPE_XPRESS, 32768, &d);
	assert_eq(0, ret);

	ret = wimlib_decompress(cdata, csize, udata, usize, d);

	wimlib_free_decompressor(d);

	return ret;
}

TEST(xpress_decompression_succeeds_on_control)
{
	size_t csize, usize;
	void *cdata, *udata;
	void *tmpbuf;
	int ret;

	cdata = load_data_file("compress_bad/xpress_1024_control", &csize);
	udata = load_data_file("compress_bad/1024_orig", &usize);

	tmpbuf = xmalloc(usize);
	memcpy(tmpbuf, udata, usize);

	ret = do_xpress_decompress(cdata, csize, tmpbuf, usize);
	assert_eq(0, ret);

	ret = memcmp(udata, tmpbuf, usize);
	assert_eq(0, ret);

	free(cdata);
	free(udata);
	free(tmpbuf);
}

TEST(xpress_decompression_fails_when_compressed_data_too_small)
{
	size_t csize, usize;
	void *cdata, *udata;
	int ret;

	cdata = load_data_file("compress_bad/xpress_1024_control", &csize);
	usize = 1024;
	udata = malloc(usize);

	ret = do_xpress_decompress(cdata, 255, udata, usize);
	assert_neq(0, ret);

	free(cdata);
	free(udata);
}

TEST(xpress_decompression_fails_when_huffman_code_undersubscribed)
{
	size_t csize, usize;
	void *cdata, *udata;
	int ret;

	cdata = load_data_file("compress_bad/xpress_1024_huffman_undersubscribed", &csize);
	usize = 1024;
	udata = malloc(usize);

	ret = do_xpress_decompress(cdata, csize, udata, usize);
	assert_neq(0, ret);

	free(cdata);
	free(udata);
}

TEST(xpress_decompression_fails_when_huffman_code_oversubscribed)
{
	size_t csize, usize;
	void *cdata, *udata;
	int ret;

	cdata = load_data_file("compress_bad/xpress_1024_huffman_oversubscribed", &csize);
	usize = 1024;
	udata = malloc(usize);

	ret = do_xpress_decompress(cdata, csize, udata, usize);
	assert_neq(0, ret);

	free(cdata);
	free(udata);
}

TEST(xpress_decompression_fails_when_match_underruns_buffer)
{
	size_t csize, usize;
	void *cdata, *udata;
	int ret;

	cdata = load_data_file("compress_bad/xpress_1024_match_underrun", &csize);
	usize = 1024;
	udata = malloc(usize);

	ret = do_xpress_decompress(cdata, csize, udata, usize);
	assert_neq(0, ret);

	free(cdata);
	free(udata);
}

TEST(xpress_decompression_fails_when_match_overruns_buffer)
{
	size_t csize, usize;
	void *cdata, *udata;
	int ret;

	cdata = load_data_file("compress_bad/xpress_1024_match_overrun", &csize);
	usize = 1024;
	udata = malloc(usize);

	ret = do_xpress_decompress(cdata, csize, udata, usize);
	assert_neq(0, ret);

	free(cdata);
	free(udata);
}
