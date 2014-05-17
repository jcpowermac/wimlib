#pragma once

#include <wchar.h>
#include <inttypes.h>
#include <stddef.h>
#include <windows.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

extern void *
xmalloc(size_t size);

extern void *
xrealloc(void *ptr, size_t size);

extern wchar_t *
win32_error_string(DWORD err);

extern void
fail(const wchar_t *format, ...) __attribute__((noreturn));

extern void
fail_win32(const wchar_t *format, ...) __attribute__((noreturn));

extern HANDLE
winopen(const wchar_t *path,
	DWORD dwDesiredAccess, DWORD dwCreationDisposition);

extern WIN32_FIND_STREAM_DATA *
get_streams(const wchar_t *path, size_t *count_ret);

extern WIN32_FIND_DATA *
get_children(const wchar_t *path, size_t *count_ret);

#define REPARSE_POINT_MAX_SIZE 16384

extern u16
get_reparse_data(const wchar_t *path, void *data_ret);

extern void
enable_privilege(const wchar_t *privilege);


extern void
create_file(const wchar_t *path, const void *contents, size_t size);

extern void
create_ads(const wchar_t *path, const wchar_t *name,
	   const void *contents, size_t size);

extern void
create_directory(const wchar_t *path);

extern void
create_hard_link(const wchar_t *source, const wchar_t *dest);

extern void
set_file_attributes(const wchar_t *path, DWORD attributes);

extern void
set_reparse_point(const wchar_t *path, const void *rpdata);
