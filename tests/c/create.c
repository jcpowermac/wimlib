#include "testsuite.h"
#include "compression.h"

TEST(wimlib_create_new_wim__fails_if_wim_ret_is_null)
{
	assert_eq(WIMLIB_ERR_INVALID_PARAM,
		  wimlib_create_new_wim(WIMLIB_COMPRESSION_TYPE_NONE, NULL));
}

TEST(wimlib_create_new_wim__fails_if_ctype_is_invalid)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE,
		  wimlib_create_new_wim(-1, &wim));

	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE,
		  wimlib_create_new_wim(MAX_COMPRESSION_TYPE + 1, &wim));
}
