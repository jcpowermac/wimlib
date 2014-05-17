#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

#include "rd.h"
#include "common.h"

extern WINAPI NTSTATUS NtQueryDirectoryFile (HANDLE FileHandle,
					     HANDLE Event,
					     PIO_APC_ROUTINE ApcRoutine,
					     PVOID ApcContext,
					     PIO_STATUS_BLOCK IoStatusBlock,
					     PVOID FileInformation,
					     ULONG Length,
					     FILE_INFORMATION_CLASS FileInformationClass,
					     BOOLEAN ReturnSingleEntry,
					     PUNICODE_STRING FileName,
					     BOOLEAN RestartScan);

#define MAXDEPTH 32768
#define BUFSIZE 8192

static void *buffers[MAXDEPTH];
static int depth;
static OBJECT_ATTRIBUTES attr = {
	.Length = sizeof(attr),
};
static IO_STATUS_BLOCK iosb;

static FILE_BASIC_INFORMATION basic = {
	.FileAttributes = FILE_ATTRIBUTE_NORMAL,
};

static void
rmr(HANDLE cur_dir, UNICODE_STRING *name)
{
	HANDLE h;
	void *buf;
	NTSTATUS status;
	ULONG perms;
	ULONG flags;

	flags = FILE_DELETE_ON_CLOSE |
		      FILE_OPEN_REPARSE_POINT |
		      FILE_OPEN_FOR_BACKUP_INTENT |
		      FILE_SYNCHRONOUS_IO_NONALERT |
		      FILE_SEQUENTIAL_ONLY;

	name->MaximumLength = name->Length;

	attr.RootDirectory = cur_dir;
	attr.ObjectName = name;

	perms = DELETE | SYNCHRONIZE |
		FILE_LIST_DIRECTORY | FILE_TRAVERSE;
retry:
	status = NtOpenFile(&h, perms, &attr, &iosb, FILE_SHARE_VALID_FLAGS, flags);
	if (!NT_SUCCESS(status)) {
		if (status == STATUS_CANNOT_DELETE && (perms & DELETE)) {
			perms &= ~DELETE;
			flags &= ~FILE_DELETE_ON_CLOSE;
			perms |= FILE_WRITE_ATTRIBUTES;
			goto retry;
		}
		return;
	}
	if (perms & FILE_WRITE_ATTRIBUTES) {
		status = NtSetInformationFile(h, &iosb, &basic,
					      sizeof(basic), FileBasicInformation);
		if (NT_SUCCESS(status)) {
			perms &= ~FILE_WRITE_ATTRIBUTES;
			perms |= DELETE;
			flags |= FILE_DELETE_ON_CLOSE;
			goto retry;
		}
	}

	buf = buffers[depth];
	if (!buf)
		buf = buffers[depth] = xmalloc(BUFSIZE);

	++depth;
	while (NT_SUCCESS(NtQueryDirectoryFile(h, NULL, NULL, NULL,
					       &iosb, buf, BUFSIZE,
					       FileNamesInformation,
					       FALSE, NULL, FALSE)))
	{
		const FILE_NAMES_INFORMATION *info = buf;
		for (;;) {
			if (!(info->FileNameLength == 2 && info->FileName[0] == L'.') &&
			    !(info->FileNameLength == 4 && info->FileName[0] == L'.' &&
							   info->FileName[1] == L'.'))
			{
				name->Buffer = (wchar_t *)info->FileName;
				name->Length = info->FileNameLength;
				rmr(h, name);
			}
			if (info->NextEntryOffset == 0)
				break;
			info = (const FILE_NAMES_INFORMATION *)
					((const char *)info + info->NextEntryOffset);
		}
	}
	--depth;
	NtClose(h);
}

void
rd(const wchar_t *path)
{
	wchar_t ntpath[32768];
	DWORD dret;

	wmemcpy(ntpath, L"\\??\\", 4);
	dret = GetFullPathName(path, ntpath + 4, 32768 - 4, NULL);
	rmr(NULL, &(UNICODE_STRING){
	    .Length = dret + 4,
	    .Buffer = ntpath,
	});
}
