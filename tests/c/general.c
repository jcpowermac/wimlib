#include "testsuite.h"
#include "compression.h"
#include <string.h>

TEST(wimlib_free__ignores_null)
{
	wimlib_free(NULL);
}

TEST(wimlib_get_compression_type_string__is_sane)
{
	const char *s;

	s = wimlib_get_compression_type_string(WIMLIB_COMPRESSION_TYPE_XPRESS);
	assert_eq(0, strcmp(s, "XPRESS"));

	s = wimlib_get_compression_type_string(WIMLIB_COMPRESSION_TYPE_NONE);
	assert_eq(0, strcmp(s, "None"));

	s = wimlib_get_compression_type_string(-1);
	assert_eq(0, strcmp(s, "Invalid"));

	s = wimlib_get_compression_type_string(MAX_COMPRESSION_TYPE + 1);
	assert_eq(0, strcmp(s, "Invalid"));
}

TEST(wimlib_get_error_string__is_sane)
{
	const char *s;

	s = wimlib_get_error_string(WIMLIB_ERR_INVALID_PARAM);
	assert_eq(0, strcmp(s, "An invalid parameter was given"));

	s = wimlib_get_error_string(0);
	assert_eq(0, strcmp(s, "Success"));

	s = wimlib_get_error_string(-1);
	assert_eq(0, strcmp(s, "Unknown error"));

	s = wimlib_get_error_string(99999999);
	assert_eq(0, strcmp(s, "Unknown error"));
}

TEST(wimlib_get_version__is_sane)
{
	assert_ge((1 << 20) | (7 << 10) | (1 << 0), wimlib_get_version());
}
