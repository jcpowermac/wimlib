/*
 * Compare directory trees (Windows version)
 */

#include "common.h"
#include "avl_tree.h"

#include <assert.h>
#include <sddl.h>
#include <stdarg.h>
#include <windows.h>

struct inode_map_node {
	u64 ino_from;
	u64 ino_to;
	struct avl_tree_node index_node;
};

#define NODE(avl_node) \
	avl_tree_entry((avl_node), struct inode_map_node, index_node)

static struct avl_tree_node *inode_map;

static int
_avl_cmp_by_ino_from(const struct avl_tree_node *node1,
		     const struct avl_tree_node *node2)
{
	u64 n1 = NODE(node1)->ino_from;
	u64 n2 = NODE(node2)->ino_from;
	return n1 < n2 ? -1 : (n1 > n2 ? 1 : 0);
}

static u64 lookup_ino(u64 ino_from)
{
	struct avl_tree_node dummy;
	struct avl_tree_node *res;

	dummy.ino_from = ino_from;
	res = avl_tree_lookup_node(inode_map, &dummy, _avl_cmp_by_ino_from);
	if (!res)
		return 
}

static void insert_ino(u64 ino_from, u64 ino_to)
{
	struct node *node = malloc(sizeof(struct node));
	if (!node)
		error(L"Out of memory");
	node->ino_from = ino_from;
	node->ino_to   = ino_to;
	node->left     = NULL;
	node->right    = NULL;
	if (!tree)
		tree = node;
	else
		do_insert(tree, node);
}

static void
cmp_reparse_data(HANDLE hFile_1, const wchar_t *path_1,
		 HANDLE hFile_2, const wchar_t *path_2)
{
	char rpdata_1[REPARSE_POINT_MAX_SIZE];
	char rpdata_2[REPARSE_POINT_MAX_SIZE];
	size_t len_1;
	size_t len_2;

	len_1 = get_reparse_data(hFile_1, path_1, rpdata_1);
	len_2 = get_reparse_data(hFile_2, path_2, rpdata_2);
	if (len_1 != len_2 || memcmp(rpdata_1, rpdata_2, len_1)) {
		error(L"Reparse point data for %ls and %ls differs",
		      path_1, path_2);
	}
}


static const wchar_t *
fix_stream_name(wchar_t *stream_name)
{
	wchar_t *colon;

	/* The stream name should be returned as :NAME:TYPE */
	if (stream_name[0] != L':')
		return NULL;
	colon = wcschr(stream_name + 1, L':');
	if (!colon)
		return NULL;
	if (wcscmp(colon + 1, L"$DATA"))
		return NULL;
	*colon = L'\0';
	if (stream_name == colon - 1)
		stream_name = colon;
	return stream_name;
}

#define BUFSIZE 32768

static void
cmp_data(HANDLE hFile_1, const wchar_t *path_1,
	 HANDLE hFile_2, const wchar_t *path_2, u64 size)
{
	u8 buf_1[BUFSIZE];
	u8 buf_2[BUFSIZE];
	u64 bytes_remaining = size;
	DWORD bytesRead;
	DWORD bytesToRead;

	while (bytes_remaining) {
		bytesToRead = BUFSIZE;
		if (bytesToRead > bytes_remaining)
			bytesToRead = bytes_remaining;
		if (!ReadFile(hFile_1, buf_1, bytesToRead, &bytesRead, NULL) ||
		    bytesRead != bytesToRead)
		{
			win32_error(L"Error reading from %ls", path_1);
		}
		if (!ReadFile(hFile_2, buf_2, bytesToRead, &bytesRead, NULL) ||
		    bytesRead != bytesToRead)
		{
			win32_error(L"Error reading from %ls", path_2);
		}
		if (memcmp(buf_1, buf_2, bytesToRead))
			error(L"Data of %ls and %ls differs", path_1, path_2);
		bytes_remaining -= bytesToRead;
	}
}

static void
cmp_stream(wchar_t *path_1, size_t path_1_len, WIN32_FIND_STREAM_DATA *dat_1,
	   wchar_t *path_2, size_t path_2_len, WIN32_FIND_STREAM_DATA *dat_2)
{
	const wchar_t *stream_name;

	if (wcscmp(dat_1->cStreamName, dat_2->cStreamName)) {
		error(L"%ls%ls and %ls%ls are not named the same",
		      path_1, dat_1->cStreamName,
		      path_2, dat_2->cStreamName);
	}
	if (dat_1->StreamSize.QuadPart != dat_2->StreamSize.QuadPart) {
		error(L"%ls%ls (%"PRIu64" bytes) and %ls%ls "
		      "(%"PRIu64" bytes) are not the same size",
		      path_1, dat_1->cStreamName, dat_1->StreamSize.QuadPart,
		      path_2, dat_2->cStreamName, dat_2->StreamSize.QuadPart);
	}

	stream_name = fix_stream_name(dat_1->cStreamName);

	if (!stream_name)
		return;

	wcscpy(&path_1[path_1_len], stream_name);
	wcscpy(&path_2[path_2_len], stream_name);

	HANDLE hFile_1 = win32_open_file_readonly(path_1);
	HANDLE hFile_2 = win32_open_file_readonly(path_2);

	cmp_data(hFile_1, path_1, hFile_2, path_2,
		 dat_1->StreamSize.QuadPart);

	CloseHandle(hFile_1);
	CloseHandle(hFile_2);
	path_1[path_1_len] = L'\0';
	path_2[path_2_len] = L'\0';
}

static void
cmp_streams(wchar_t *path_1, size_t path_1_len,
	    wchar_t *path_2, size_t path_2_len)
{
	WIN32_FIND_STREAM_DATA *streams_1, *streams_2;
	size_t nstreams_1, nstreams_2;
	size_t i;

	streams_1 = get_stream_array(path_1, &nstreams_1);
	streams_2 = get_stream_array(path_2, &nstreams_2);

	if (nstreams_1 != nstreams_2) {
		error(L"%ls and %ls do not have the same number of streams",
		      path_1, path_2);
	}

	for (i = 0; i < nstreams_1; i++)
		cmp_stream(path_1, path_1_len, &streams_1[i],
			   path_2, path_2_len, &streams_2[i]);
	free(streams_1);
	free(streams_2);
}

static void
tree_cmp(wchar_t *path_1, size_t path_1_len, wchar_t *path_2, size_t path_2_len);

static void
recurse_directory(wchar_t *path_1, size_t path_1_len,
		  wchar_t *path_2, size_t path_2_len)
{
	WIN32_FIND_DATA *dentries_1, *dentries_2;
	size_t ndentries_1, ndentries_2;
	size_t i;

	dentries_1 = get_dentry_array(path_1, path_1_len, &ndentries_1);
	dentries_2 = get_dentry_array(path_2, path_2_len, &ndentries_2);

	if (ndentries_1 != ndentries_2) {
		error(L"%ls and %ls do not have the same number of dentries",
		      path_1, path_2);
	}

	path_1[path_1_len] = L'\\';
	path_2[path_2_len] = L'\\';
	for (i = 0; i < ndentries_1; i++) {
		size_t name_1_len, name_2_len;

		name_1_len = wcslen(dentries_1[i].cFileName);
		name_2_len = wcslen(dentries_2[i].cFileName);
		wmemcpy(&path_1[path_1_len + 1], dentries_1[i].cFileName, name_1_len + 1);
		wmemcpy(&path_2[path_2_len + 1], dentries_2[i].cFileName, name_2_len + 1);

		if (wcscmp(dentries_1[i].cFileName,
			   dentries_2[i].cFileName))
			error(L"%ls and %ls do not have the same name",
			      path_1, path_2);

		if (wcscmp(dentries_1[i].cAlternateFileName,
			   dentries_2[i].cAlternateFileName))
			error(L"%ls and %ls do not have the same short name",
			      path_1, path_2);

		if (!wcscmp(dentries_1[i].cFileName, L".") ||
		    !wcscmp(dentries_2[i].cFileName, L".."))
			continue;
		tree_cmp(path_1, path_1_len + 1 + name_1_len,
			 path_2, path_2_len + 1 + name_2_len);
	}
	path_1[path_1_len] = L'\0';
	path_2[path_2_len] = L'\0';
	free(dentries_1);
	free(dentries_2);
}

static int
file_times_equal(const FILETIME *t1, const FILETIME *t2)
{
	return t1->dwLowDateTime == t2->dwLowDateTime &&
	       t1->dwHighDateTime == t2->dwHighDateTime;
}

static void *
get_security(const wchar_t *path, size_t *len_ret)
{
	DWORD lenNeeded;
	DWORD requestedInformation = DACL_SECURITY_INFORMATION |
				     SACL_SECURITY_INFORMATION |
				     OWNER_SECURITY_INFORMATION |
				     GROUP_SECURITY_INFORMATION;
	void *descr;
	BOOL bret;


	bret = GetFileSecurity(path, requestedInformation,
			       NULL, 0, &lenNeeded);

	if (bret || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		goto err;
	descr = malloc(lenNeeded);
	if (!descr)
		error(L"out of memory");
	if (!GetFileSecurity(path, requestedInformation, descr, lenNeeded,
			     &lenNeeded))
		goto err;
	*len_ret = lenNeeded;
	return descr;
err:
	win32_error(L"Can't read security descriptor of %ls", path);
}

static wchar_t *
get_security_descriptor_string(PSECURITY_DESCRIPTOR desc)
{
	wchar_t *str;
	ULONG len;
	ConvertSecurityDescriptorToStringSecurityDescriptor(desc,
							    SDDL_REVISION_1,
							    OWNER_SECURITY_INFORMATION |
								    GROUP_SECURITY_INFORMATION |
								    DACL_SECURITY_INFORMATION |
								    SACL_SECURITY_INFORMATION,
							    &str,
							    NULL);
	return str;
}

static void
cmp_security(const wchar_t *path_1, const wchar_t *path_2)
{
	void *descr_1, *descr_2;
	size_t len_1, len_2;
	const wchar_t *str_1, *str_2;

	descr_1 = get_security(path_1, &len_1);
	descr_2 = get_security(path_2, &len_2);

	if (len_1 != len_2 || memcmp(descr_1, descr_2, len_1)) {
		str_1 = get_security_descriptor_string(descr_1);
		str_2 = get_security_descriptor_string(descr_2);
		error(L"%ls and %ls do not have the same security "
		      "descriptor:\n\t%ls\nvs.\n\t%ls",
		      path_1, path_2, str_1, str_2);
	}
	free(descr_1);
	free(descr_2);
}

static void
tree_cmp(wchar_t *path_1, size_t path_1_len, wchar_t *path_2, size_t path_2_len)
{
	HANDLE hFile_1, hFile_2;
	BY_HANDLE_FILE_INFORMATION file_info_1, file_info_2;
	u64 size_1, size_2;
	u64 ino_1, ino_2;
	u64 ino_to;
	DWORD attribs;

	hFile_1 = win32_open_file_readonly(path_1);
	hFile_2 = win32_open_file_readonly(path_2);
	if (!GetFileInformationByHandle(hFile_1, &file_info_1))
		win32_error(L"Failed to get file information for %ls", path_1);
	if (!GetFileInformationByHandle(hFile_2, &file_info_2))
		win32_error(L"Failed to get file information for %ls", path_2);

	if (file_info_1.dwFileAttributes != file_info_2.dwFileAttributes) {
		error(L"Attributes for %ls (%#x) differ from attributes for %ls (%#x)",
		      path_1, (unsigned)file_info_1.dwFileAttributes,
		      path_2, (unsigned)file_info_2.dwFileAttributes);
	}

	attribs = file_info_1.dwFileAttributes;

	if (!(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
		size_1 = ((u64)file_info_1.nFileSizeHigh << 32) |
				file_info_1.nFileSizeLow;
		size_2 = ((u64)file_info_2.nFileSizeHigh << 32) |
				file_info_2.nFileSizeLow;
		if (size_1 != size_2) {
			error(L"Size for %ls (%"PRIu64") differs from size for %ls (%"PRIu64")",
			      path_1, size_1, path_2, size_2);
		}
	}
	if (file_info_1.nNumberOfLinks != file_info_2.nNumberOfLinks) {
		error(L"Number of links for %ls (%u) differs from number "
		      "of links for %ls (%u)",
		      path_1, (unsigned)file_info_1.nNumberOfLinks,
		      path_2, (unsigned)file_info_2.nNumberOfLinks);
	}
	ino_1 = ((u64)file_info_1.nFileIndexHigh << 32) |
			file_info_1.nFileIndexLow;
	ino_2 = ((u64)file_info_2.nFileIndexHigh << 32) |
			file_info_2.nFileIndexLow;
	ino_to = lookup_ino(ino_1);
	if (ino_to == -1)
		insert_ino(ino_1, ino_2);
	else if (ino_to != ino_2)
		error(L"Inode number on %ls is wrong", path_2);

	if (!file_times_equal(&file_info_1.ftCreationTime, &file_info_2.ftCreationTime))
		error(L"Creation times on %ls and %ls differ",
		      path_1, path_2);

	if (!file_times_equal(&file_info_1.ftLastWriteTime, &file_info_2.ftLastWriteTime))
		error(L"Last write times on %ls and %ls differ",
		      path_1, path_2);

	cmp_security(path_1, path_2);
	cmp_streams(path_1, path_1_len, path_2, path_2_len);
	if (attribs & FILE_ATTRIBUTE_REPARSE_POINT)
		cmp_reparse_data(hFile_1, path_1, hFile_2, path_2);
	else if (attribs & FILE_ATTRIBUTE_DIRECTORY)
		recurse_directory(path_1, path_1_len, path_2, path_2_len);
	CloseHandle(hFile_1);
	CloseHandle(hFile_2);
}

void assert_trees_equal(const wchar_t *tree_1, const wchar_t *tree_2)
{
	wchar_t path_1[32768];
	wchar_t path_2[32768];
	size_t len_1;
	size_t len_2;

	len_1 = wcslen(tree_1);
	len_2 = wcslen(tree_2);
	wmemcpy(path_1, tree_1, len_1 + 1);
	wmemcpy(path_2, tree_2, len_2 + 1);
	tree_cmp(path_1, len_1, path_2, len_2);
}
