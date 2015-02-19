
SUPPORT_SRC := testrunner.c testutil.c
SUPPORT_HEADER := testsuite.h
SUPPORT_OBJ := $(SUPPORT_SRC:%.c=%.o)

TEST_SRC := $(filter-out $(SUPPORT_SRC), $(wildcard *.c))
TEST_EXE := $(TEST_SRC:%.c=%)

LIBDIR := ../../.libs
INCLUDE := ../../include

CFLAGS := -Wall -I $(INCLUDE) -std=c99 -D_GNU_SOURCE
TEST_CFLAGS := $(CFLAGS) -O0
TEST_LDLIBS := -lwim
TEST_LDFLAGS := -L $(LIBDIR)
SUPPORT_CFLAGS := $(CFLAGS) -O2

USE_VALGRIND := no

ifeq ($(USE_VALGRIND),yes)
VALGRIND := valgrind --quiet --error-exitcode=2 --leak-check=full
else
VALGRIND :=
endif

default: check

$(SUPPORT_OBJ): %.o: %.c
	$(CC) -o $@ $+ -c $(SUPPORT_CFLAGS)


$(TEST_EXE): % : %.c $(SUPPORT_OBJ) $(SUPPORT_HEADER)
	$(CC) -o $@ $< $(SUPPORT_OBJ) $(TEST_CFLAGS) $(TEST_LDFLAGS) $(TEST_LDLIBS)

check: $(TEST_EXE)
	chmod -w ./data/wims/empty-readonly-fs.wim
	@for exe in $(TEST_EXE); do	\
		echo "";		\
		echo "$$exe";		\
		LD_LIBRARY_PATH=$(LIBDIR) $(VALGRIND) ./$$exe || exit $$?;	\
	done
	@echo "All tests from all files passed!"

clean:
	rm -f $(TEST_EXE) $(SUPPORT_OBJ)

.PHONY: default check clean
