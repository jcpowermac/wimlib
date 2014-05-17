CFLAGS := -O0 -Wall -municode -Wextra
CPPFLAGS := -DUNICODE -D_UNICODE
LDLIBS := -lntdll
CC := x86_64-w64-mingw32-gcc

wintest.exe:rd.c common.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $+ $(LDLIBS) -o $@
