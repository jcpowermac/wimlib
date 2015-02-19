#include "testsuite.h"

TEST(wimlib_global_init__fails_if_flags_are_unrecognized)
{
	assert_neq(0, wimlib_global_init(~0));
}

TEST(wimlib_can_be_initialized_multiple_times)
{
	int i;

	for (i = 0; i < 5; i++) {
		assert_eq(0, wimlib_global_init(0));
		wimlib_global_cleanup();
	}
}
