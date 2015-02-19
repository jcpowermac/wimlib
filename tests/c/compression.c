/*
 * compression.c
 *
 * Test compression and decompression.
 */

#include "testsuite.h"
#include "compression.h"
#include <stdlib.h>
#include <string.h>

static size_t
compress_data(const void *udata, const size_t usize,
	      const int ctype, const unsigned int clevel,
	      const char *data_file_name)
{
	struct wimlib_compressor *c;
	void *cdata;
	size_t csize;
	int ret;

	ret = wimlib_create_compressor(ctype, usize, clevel, &c);
	assert_eq(0, ret);

	cdata = xmalloc(usize - 1);
	csize = wimlib_compress(udata, usize, cdata, usize - 1, c);
	assert_le(usize - 1, csize);

	if (csize == 0) {
		csize = usize;
	} else {
		void *tmpbuf;
		struct wimlib_decompressor *d;

		ret = wimlib_create_decompressor(ctype, usize, &d);
		assert_eq(0, ret);

		tmpbuf = xmalloc(usize);

		ret = wimlib_decompress(cdata, csize, tmpbuf, usize, d);
		if (ret != 0)
			fail("Failed to decompress compressed data "
			     "(file=\"%s\", type=%s, level=%u)",
			     data_file_name,
			     wimlib_get_compression_type_string(ctype), clevel);

		if (memcmp(udata, tmpbuf, usize))
			fail("Data did not decompress to original "
			     "(file=\"%s\", type=%s, level=%u)",
			     data_file_name,
			     wimlib_get_compression_type_string(ctype), clevel);

		wimlib_free_decompressor(d);
		free(tmpbuf);
	}

	free(cdata);
	wimlib_free_compressor(c);
	return csize;
}

/*#define GEN_COMPRESS_TAB*/

#ifdef GEN_COMPRESS_TAB

static void
gen_file_stat(FILE *tab,
	      const char *data_file_name, int ctype, unsigned clevel)
{
	void *udata;
	size_t usize;
	size_t csize;

	udata = load_data_file(data_file_name, &usize);
	csize = compress_data(udata, usize, ctype, clevel, data_file_name);
	free(udata);

	fprintf(tab, "%s\t%d\t%u\t%zu\n", data_file_name, ctype, clevel, csize);

	printf("\t\t[%s:%u] %s: %zu => %zu\n",
	       wimlib_get_compression_type_string(ctype),
	       clevel, data_file_name,  usize, csize);
}

static void
gen_file_stats(FILE *tab, const char *data_file_name)
{

	for (int i = 0; i < ARRAY_LEN(compression_types); i++) {
		int ctype = compression_types[i];

		gen_file_stat(tab, data_file_name, ctype, 1);
		gen_file_stat(tab, data_file_name, ctype, 20);
		gen_file_stat(tab, data_file_name, ctype, 40);
		gen_file_stat(tab, data_file_name, ctype, 50);
		gen_file_stat(tab, data_file_name, ctype, 60);
		gen_file_stat(tab, data_file_name, ctype, 80);
		gen_file_stat(tab, data_file_name, ctype, 100);
	}
}

TEST(gen_compress_tab)
{
	FILE *tab = fopen("compress.tab", "w");
	assert_neq(NULL, tab);


	gen_file_stats(tab, "corpus/english_text_32768");
	gen_file_stats(tab, "corpus/dna_32768");
	gen_file_stats(tab, "corpus/spreadsheet_32768");
	gen_file_stats(tab, "corpus/x86_64_32768");
	gen_file_stats(tab, "corpus/zeroes_32768");
	gen_file_stats(tab, "corpus/xml_32768");
	gen_file_stats(tab, "corpus/random_32768");

	fclose(tab);
}
#endif /* GEN_COMPRESS_TAB */

static void
do_standard_test(const char *data_file_name, int ctype, unsigned clevel,
		 size_t expected_csize)
{
	void *udata;
	size_t usize;
	size_t csize;

	udata = load_data_file(data_file_name, &usize);
	csize = compress_data(udata, usize, ctype, clevel, data_file_name);
	free(udata);

	if (csize != expected_csize) {
		fprintf(stderr, "%s: Expected <= %zu bytes, got %zu bytes "
		     "(file=\"%s\", type=%s, level=%u)\n",
		     (csize > expected_csize) ? "REGRESSION" : "improvement",
		     expected_csize, csize, data_file_name,
		     wimlib_get_compression_type_string(ctype), clevel);
	}

#if 0
	printf("\t\t[%s:%u] %s: %zu => %zu (baseline: %zu)\n",
	       wimlib_get_compression_type_string(ctype),
	       clevel, data_file_name,  usize, csize, expected_csize);
#endif
}

TEST(compression_and_decompression_of_sample_data)
{
	FILE *tab;
	char data_file_name[256];
	int ctype;
	unsigned clevel;
	size_t expected_csize;
	int ret;

	tab = fopen("compress.tab", "r");
	assert_neq(NULL, tab);

	while ((ret = fscanf(tab, "%s\t%d\t%u\t%zu\n",
			     data_file_name, &ctype, &clevel, &expected_csize)) != EOF)
	{
		assert_eq(4, ret);

		do_standard_test(data_file_name, ctype, clevel, expected_csize);
	}

	fclose(tab);
}
