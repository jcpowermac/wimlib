#include "testsuite.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static struct test {
	test_func_t func;
	const char *name;
} tests[1024];

static size_t cur_test;
static size_t num_tests;

void
register_test_function(test_func_t func, const char *name)
{
	if (num_tests == ARRAY_LEN(tests))
		abort();
	tests[num_tests].func = func;
	tests[num_tests].name = name;
	num_tests++;
}

void
do_fail(const char *filename, int lineno, const char *msg, ...)
{
	va_list va;
	const char *name = tests[cur_test].name;

	va_start(va, msg);
	fprintf(stderr, "\n");
	fprintf(stderr, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "                     TEST FAILURE                      \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Location:  %s:%d\n", filename, lineno);
	fprintf(stderr, "Test name: %s\n", name);
	fprintf(stderr, "Detail:    ");
	vfprintf(stderr, msg, va);
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	fprintf(stderr, "\n");
	va_end(va);
	exit(1);
}

int
main(void)
{
	for (cur_test = 0; cur_test < num_tests; cur_test++) {
		printf("\tExecuting test: %s\n", tests[cur_test].name);
		(*tests[cur_test].func)();
	}
	printf("\tAll %zu tests passed!\n", num_tests);
	wimlib_global_cleanup();
	return 0;
}
