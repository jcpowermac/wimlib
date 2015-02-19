#ifndef _TESTSUITE_H_
#define _TESTSUITE_H_

#include "wimlib.h"

#define ARRAY_LEN(A) (sizeof(A) / sizeof((A)[0]))

extern void
do_fail(const char *filename, int lineno,
	const char *msg, ...) __attribute__((noreturn)) __attribute__((cold));

typedef void (*test_func_t)(void);

extern void
register_test_function(test_func_t func, const char *name);

/* Declare a test function that will be executed automatically by the test
 * runner.  */
#define TEST(func)						\
static void func(void);						\
static void __attribute__((constructor)) register_##func()	\
{								\
	register_test_function(func, #func);			\
}								\
static void func(void)


/* Fail the test with the specified message.  */
#define fail(msg, ...) do_fail(__FILE__, __LINE__, msg, ##__VA_ARGS__)

/* Assertion macros  */

#define assert_eq(expected, actual)					\
({									\
	if ((expected) != (actual))					\
		fail("Expected %ld, got %ld",				\
		     (long)(expected), (long)(actual));			\
})

#define assert_neq(expected, actual)					\
({									\
	if ((expected) == (actual))					\
		fail("Expected != %ld, but got %ld",			\
		     (long)(expected), (long)(actual));			\
})

#define assert_le(bound, actual)					\
({									\
	if ((actual) > (bound))						\
		fail("Expected <= %ld, but got %ld",			\
		     (long)(bound), (long)(actual));			\
})

#define assert_ge(bound, actual)					\
({									\
	if ((actual) < (bound))						\
		fail("Expected >= %ld, but got %ld",			\
		     (long)(bound), (long)(actual));			\
})

#define assert_gt(bound, actual)					\
({									\
	if ((actual) <= (bound))					\
		fail("Expected > %ld, but got %ld",			\
		     (long)(bound), (long)(actual));			\
})

#define assert_lt(bound, actual)					\
({									\
	if ((actual) >= (bound))					\
		fail("Expected < %ld, but got %ld",			\
		     (long)(bound), (long)(actual));			\
})

#define assert_bounded(lower, upper, actual)				\
({									\
	if ((actual) < (lower) || (actual) > (upper))			\
		fail("Expected >= %ld and <= %ld, but got %ld",		\
		     (long)(lower), (long)(upper), (long)(actual));	\
})

/* Utility functions  */

extern void *
load_data_file(const char *name, size_t *size_ret);

extern void *
xmalloc(size_t size);

#endif /* _TESTSUITE_H_ */
