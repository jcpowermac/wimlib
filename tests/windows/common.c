#include "common.h"
#include <windows.h>

wchar_t *
win32_error_string(DWORD err_code)
{
	static wchar_t buf[1024];

	buf[0] = L'\0';
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err_code, 0,
		      buf, 1024, NULL);
	return buf;
}

void *
xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		fail(L"out of memory");
	return ptr;
}

void *
xrealloc(void *ptr, size_t size)
{
	if (!size)
		size = 1;
	ptr = realloc(ptr, size);
	if (!ptr)
		fail(L"out of memory");
	return ptr;
}

void
fail(const wchar_t *format, ...)
{
	va_list va;

	va_start(va, format);
	vfwprintf(stderr, format, va);
	va_end(va);
	putwc(L'\n', stderr);
	exit(1);
}

void
fail_win32(const wchar_t *format, ...)
{
	va_list va;
	DWORD err = GetLastError();

	va_start(va, format);
	vfwprintf(stderr, format, va);
	fwprintf(stderr, L": %ls\n", win32_error_string(err));
	va_end(va);
	exit(1);
}

void
enable_privilege(const wchar_t *privilege)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES newState;

	if (!OpenProcessToken(GetCurrentProcess(),
			      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		fail_win32(L"Failed to open process token");

	if (!LookupPrivilegeValueW(NULL, privilege, &luid))
		fail_win32(L"Failed to look up privilege %ls", privilege);

	newState.PrivilegeCount = 1;
	newState.Privileges[0].Luid = luid;
	newState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL))
		fail_win32(L"Failed to acquire privilege %ls", privilege);
	CloseHandle(hToken);
}

HANDLE
winopen(const wchar_t *path, DWORD dwDesiredAccess, DWORD dwCreationDisposition)
{
	HANDLE h;

	h = CreateFile(path,
		       dwDesiredAccess,
		       FILE_SHARE_VALID_FLAGS,
		       NULL,
		       dwCreationDisposition,
		       FILE_FLAG_BACKUP_SEMANTICS |
		       		FILE_FLAG_OPEN_REPARSE_POINT |
				FILE_FLAG_SEQUENTIAL_SCAN,
		       NULL);
	if (h == INVALID_HANDLE_VALUE) {
		fail_win32(L"Can't open \"%ls\" (dwDesiredAccess=0x%08"PRIx32", "
			    "dwCreationDisposition=0x%08"PRIx32")",
			    path, (u32)dwDesiredAccess, (u32)dwCreationDisposition);
	}
	return h;
}

static int
cmp_streams_by_name(const void *p1, const void *p2)
{
	const WIN32_FIND_STREAM_DATA *s1 = p1;
	const WIN32_FIND_STREAM_DATA *s2 = p2;

	return wcscmp(s1->cStreamName, s2->cStreamName);
}

WIN32_FIND_STREAM_DATA *
get_streams(const wchar_t *path, size_t *count_ret)
{
	WIN32_FIND_STREAM_DATA *array;
	size_t count = 0;
	size_t alloc_count = 4;
	DWORD err;
	HANDLE h;

	array = xmalloc(alloc_count * sizeof(array[0]));

	h = FindFirstStreamW(path, FindStreamInfoStandard, &array[0], 0);
	if (h == INVALID_HANDLE_VALUE)
		fail_win32(L"Can't get first stream from \"%ls\"", path);

	do {
		if (++count == alloc_count) {
			alloc_count *= 2;
			array = xrealloc(array, alloc_count * sizeof(array[0]));
		}
	} while (FindNextStreamW(h, &array[count]));
	err = GetLastError();
	FindClose(h);

	if (err != ERROR_HANDLE_EOF) {
		SetLastError(err);
		fail_win32(L"Can't get streams from \"%ls\"", path);
	}

	qsort(array, count, sizeof(array[0]), cmp_streams_by_name);
	*count_ret = count;
	return array;
}

static int
cmp_dentries_by_name(const void *p1, const void *p2)
{
	const WIN32_FIND_DATA *d1 = p1;
	const WIN32_FIND_DATA *d2 = p2;
	return wcscmp(d1->cFileName, d2->cFileName);
}

WIN32_FIND_DATA *
get_children(const wchar_t *path, size_t *count_ret)
{
	WIN32_FIND_DATA *array;
	size_t count = 0;
	size_t alloc_count = 4;
	DWORD err;
	HANDLE h;

	array = xmalloc(alloc_count * sizeof(array[0]));

	{
		wchar_t pattern[wcslen(path) + 3];
		wsprintf(pattern, "%ls\\*", path);

		h = FindFirstFile(pattern, &array[0]);
	}
	if (h == INVALID_HANDLE_VALUE)
		fail_win32(L"Can't get first child of \"%ls\"", path);

	do {
		if (++count == alloc_count) {
			alloc_count *= 2;
			array = xrealloc(array, alloc_count * sizeof(array[0]));
		}
	} while (FindNextFile(h, &array[count]));
	err = GetLastError();
	FindClose(h);

	if (err != ERROR_NO_MORE_FILES) {
		SetLastError(err);
		fail_win32(L"Can't get children of \"%ls\"", path);
	}

	qsort(array, count, sizeof(array[0]), cmp_dentries_by_name);
	*count_ret = count;
	return array;
}

u16
get_reparse_data(const wchar_t *path, void *data_ret)
{
	HANDLE h;
	DWORD bytes_returned;

	h = winopen(path, GENERIC_READ, OPEN_EXISTING);

	if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT,
			     NULL, 0,
			     data_ret, REPARSE_POINT_MAX_SIZE,
			     &bytes_returned, NULL))
		fail_win32(L"Can't get reparse data of \"%ls\"", path);

	CloseHandle(h);

	return bytes_returned;
}

void
create_file(const wchar_t *path, const void *contents, size_t size)
{
	HANDLE h;
	DWORD bytes_written;

	h = winopen(path, FILE_WRITE_DATA, CREATE_NEW);

	if (!WriteFile(h, contents, size, &bytes_written, NULL) ||
	    (bytes_written != size))
		fail_win32(L"Can't write \"%ls\"", path);
	CloseHandle(h);
}

void
create_ads(const wchar_t *path, const wchar_t *name,
	   const void *contents, size_t size)
{
	size_t len = wcslen(path) + 1 + wcslen(name);

	wchar_t buf[len + 1];

	wsprintf(buf, "%ls:%ls", path, name);

	create_file(buf, contents, size);
}

void
create_directory(const wchar_t *path)
{
	if (!CreateDirectory(path, NULL))
		fail_win32(L"Can't create directory \"%ls\"", path);
}

void
create_hard_link(const wchar_t *source, const wchar_t *dest)
{
	if (!CreateHardLink(source, dest, NULL)) {
		fail_win32(L"Can't create \"%ls\" => \"%ls\"",
			   source, dest);
	}
}

void
set_file_attributes(const wchar_t *path, DWORD attribs)
{
	if (!SetFileAttributes(path, attribs)) {
		fail_win32(L"Can't set attributes 0x%08"PRIx32" on \"%ls\"",
			   (u32)attribs, path);
	}
}

void
set_reparse_point(const wchar_t *path, const void *rpdata)
{
	HANDLE h;
	u16 len = 8 + *((const u16 *)rpdata + 2);
	DWORD bytes_returned;

	h = winopen(path, GENERIC_WRITE, OPEN_EXISTING);
	if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT,
			     (void *)rpdata, len,
			     NULL, 0, &bytes_returned, NULL))
		fail_win32(L"Can't set reparse data on \"%ls\"", path);
	CloseHandle(h);
}
