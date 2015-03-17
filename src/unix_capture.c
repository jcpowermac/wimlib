/*
 * unix_capture.c:  Capture a directory tree on UNIX.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifndef __WIN32__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h> /* for PATH_MAX */
#include <sys/stat.h>
#include <unistd.h>

#include "wimlib/capture.h"
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/blob_table.h"
#include "wimlib/reparse.h"
#include "wimlib/timestamp.h"
#include "wimlib/unix_data.h"

#ifdef HAVE_FDOPENDIR
#  define my_fdopendir(dirfd_p) fdopendir(*(dirfd_p))
#else
static DIR *
my_fdopendir(int *dirfd_p)
{
	DIR *dir = NULL;
	int old_pwd;

	old_pwd = open(".", O_RDONLY);
	if (old_pwd >= 0) {
		if (!fchdir(*dirfd_p)) {
			dir = opendir(".");
			if (dir) {
				close(*dirfd_p);
				*dirfd_p = dirfd(dir);
			}
			fchdir(old_pwd);
		}
		close(old_pwd);
	}
	return dir;
}
#endif

#ifdef HAVE_OPENAT
#  define my_openat(full_path, dirfd, relpath, flags) \
		openat((dirfd), (relpath), (flags))
#else
#  define my_openat(full_path, dirfd, relpath, flags) \
		open((full_path), (flags))
#endif

#ifdef HAVE_READLINKAT
#  define my_readlinkat(full_path, dirfd, relpath, buf, bufsize) \
		readlinkat((dirfd), (relpath), (buf), (bufsize))
#else
#  define my_readlinkat(full_path, dirfd, relpath, buf, bufsize) \
		readlink((full_path), (buf), (bufsize))
#endif

#ifdef HAVE_FSTATAT
#  define my_fstatat(full_path, dirfd, relpath, stbuf, flags)	\
	fstatat((dirfd), (relpath), (stbuf), (flags))
#else
#  define my_fstatat(full_path, dirfd, relpath, stbuf, flags)	\
	((flags) & AT_SYMLINK_NOFOLLOW) ? \
		lstat((full_path), (stbuf)) : \
		stat((full_path), (stbuf))
#endif

#ifndef AT_FDCWD
#  define AT_FDCWD	-100
#endif

#ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW	0x100
#endif

static int
unix_scan_regular_file(const char *path, u64 size, struct wim_inode *inode,
		       struct list_head *unhashed_streams)
{
	struct blob *blob;
	char *file_on_disk;

	inode->i_attributes = FILE_ATTRIBUTE_NORMAL;

	/* Empty files do not have to have a lookup table entry. */
	if (!size)
		return 0;

	file_on_disk = STRDUP(path);
	if (!file_on_disk)
		return WIMLIB_ERR_NOMEM;
	blob = new_blob();
	if (!blob) {
		FREE(file_on_disk);
		return WIMLIB_ERR_NOMEM;
	}
	blob->file_on_disk = file_on_disk;
	blob->file_inode = inode;
	blob->resource_location = RESOURCE_IN_FILE_ON_DISK;
	blob->size = size;
	add_unhashed_blob(blob, inode, 0, unhashed_streams);
	inode->i_lte = blob;
	return 0;
}

static int
unix_build_dentry_tree_recursive(struct wim_dentry **tree_ret,
				 char *path, size_t path_len,
				 int dirfd, const char *relpath,
				 struct capture_params *params);

static int
unix_scan_directory(struct wim_dentry *dir_dentry,
		    char *full_path, size_t full_path_len,
		    int parent_dirfd, const char *dir_relpath,
		    struct capture_params *params)
{

	int dirfd;
	DIR *dir;
	int ret;

	dirfd = my_openat(full_path, parent_dirfd, dir_relpath, O_RDONLY);
	if (dirfd < 0) {
		ERROR_WITH_ERRNO("\"%s\": Can't open directory", full_path);
		return WIMLIB_ERR_OPENDIR;
	}

	dir_dentry->d_inode->i_attributes = FILE_ATTRIBUTE_DIRECTORY;
	dir = my_fdopendir(&dirfd);
	if (!dir) {
		ERROR_WITH_ERRNO("\"%s\": Can't open directory", full_path);
		close(dirfd);
		return WIMLIB_ERR_OPENDIR;
	}

	ret = 0;
	for (;;) {
		struct dirent *entry;
		struct wim_dentry *child;
		size_t name_len;

		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			if (errno) {
				ret = WIMLIB_ERR_READ;
				ERROR_WITH_ERRNO("\"%s\": Error reading directory",
						 full_path);
			}
			break;
		}

		if (entry->d_name[0] == '.' &&
		    (entry->d_name[1] == '\0' ||
		     (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
			continue;

		full_path[full_path_len] = '/';
		name_len = strlen(entry->d_name);
		memcpy(&full_path[full_path_len + 1], entry->d_name, name_len + 1);
		ret = unix_build_dentry_tree_recursive(&child,
						       full_path,
						       full_path_len + 1 + name_len,
						       dirfd,
						       &full_path[full_path_len + 1],
						       params);
		full_path[full_path_len] = '\0';
		if (ret)
			break;
		if (child)
			dentry_add_child(dir_dentry, child);
	}
	closedir(dir);
	return ret;
}

/* Given an absolute symbolic link target @dest (UNIX-style, beginning
 * with '/'), determine whether it points into the directory specified by
 * @ino and @dev.  If so, return the target modified to be "absolute"
 * relative to this directory.  Otherwise, return NULL.  */
static char *
unix_fixup_abslink(char *dest, u64 ino, u64 dev)
{
	char *p = dest;

	do {
		char save;
		struct stat stbuf;
		int ret;

		/* Skip non-slashes.  */
		while (*p && *p != '/')
			p++;

		/* Skip slashes.  */
		while (*p && *p == '/')
			p++;

		/* Get inode and device for this prefix.  */
		save = *p;
		*p = '\0';
		ret = stat(dest, &stbuf);
		*p = save;

		if (ret) {
			/* stat() failed.  Assume the link points outside the
			 * directory tree being captured.  */
			break;
		}

		if (stbuf.st_ino == ino && stbuf.st_dev == dev) {
			/* Link points inside directory tree being captured.
			 * Return abbreviated path.  */
			*--p = '/';
			while (p > dest && *(p - 1) == '/')
				p--;
			return p;
		}
	} while (*p);

	/* Link does not point inside directory tree being captured.  */
	return NULL;
}

static int
unix_scan_symlink(const char *full_path, int dirfd, const char *relpath,
		  struct wim_inode *inode, struct capture_params *params)
{
	char deref_name_buf[4096];
	ssize_t deref_name_len;
	char *dest;
	int ret;

	inode->i_attributes = FILE_ATTRIBUTE_REPARSE_POINT;
	inode->i_reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;

	/* The idea here is to call readlink() to get the UNIX target of the
	 * symbolic link, then turn the target into a reparse point data buffer
	 * that contains a relative or absolute symbolic link. */
	deref_name_len = my_readlinkat(full_path, dirfd, relpath,
				       deref_name_buf, sizeof(deref_name_buf) - 1);
	if (deref_name_len < 0) {
		ERROR_WITH_ERRNO("\"%s\": Can't read target of symbolic link",
				 full_path);
		return WIMLIB_ERR_READLINK;
	}

	dest = deref_name_buf;

	dest[deref_name_len] = '\0';

	if ((params->add_flags & WIMLIB_ADD_FLAG_RPFIX) &&
	     dest[0] == '/')
	{
		char *fixed_dest;

		/* RPFIX (reparse point fixup) mode:  Change target of absolute
		 * symbolic link to be "absolute" relative to the tree being
		 * captured.  */
		fixed_dest = unix_fixup_abslink(dest,
						params->capture_root_ino,
						params->capture_root_dev);
		params->progress.scan.cur_path = full_path;
		params->progress.scan.symlink_target = deref_name_buf;
		if (fixed_dest) {
			/* Link points inside the tree being captured, so it was
			 * fixed.  */
			inode->i_not_rpfixed = 0;
			dest = fixed_dest;
			ret = do_capture_progress(params,
						  WIMLIB_SCAN_DENTRY_FIXED_SYMLINK,
						  NULL);
		} else {
			/* Link points outside the tree being captured, so it
			 * was not fixed.  */
			ret = do_capture_progress(params,
						  WIMLIB_SCAN_DENTRY_NOT_FIXED_SYMLINK,
						  NULL);
		}
		if (ret)
			return ret;
	}
	ret = wim_inode_set_symlink(inode, dest, params->blob_table);
	if (ret)
		return ret;

	/* Unfortunately, Windows seems to have the concept of "file" symbolic
	 * links as being different from "directory" symbolic links...  so
	 * FILE_ATTRIBUTE_DIRECTORY needs to be set on the symbolic link if the
	 * *target* of the symbolic link is a directory.  */
	struct stat stbuf;
	if (my_fstatat(full_path, dirfd, relpath, &stbuf, 0) == 0 &&
	    S_ISDIR(stbuf.st_mode))
		inode->i_attributes |= FILE_ATTRIBUTE_DIRECTORY;
	return 0;
}

static int
unix_build_dentry_tree_recursive(struct wim_dentry **tree_ret,
				 char *full_path, size_t full_path_len,
				 int dirfd, const char *relpath,
				 struct capture_params *params)
{
	struct wim_dentry *tree = NULL;
	struct wim_inode *inode = NULL;
	int ret;
	struct stat stbuf;
	int stat_flags;

	ret = try_exclude(full_path, full_path_len, params);
	if (ret < 0) /* Excluded? */
		goto out_progress;
	if (ret > 0) /* Error? */
		goto out;

	if (params->add_flags & (WIMLIB_ADD_FLAG_DEREFERENCE |
				 WIMLIB_ADD_FLAG_ROOT))
		stat_flags = 0;
	else
		stat_flags = AT_SYMLINK_NOFOLLOW;

	ret = my_fstatat(full_path, dirfd, relpath, &stbuf, stat_flags);

	if (ret) {
		ERROR_WITH_ERRNO("\"%s\": Can't read metadata", full_path);
		ret = WIMLIB_ERR_STAT;
		goto out;
	}

	if (!(params->add_flags & WIMLIB_ADD_FLAG_UNIX_DATA)) {
		if (unlikely(!S_ISREG(stbuf.st_mode) &&
			     !S_ISDIR(stbuf.st_mode) &&
			     !S_ISLNK(stbuf.st_mode)))
		{
			if (params->add_flags &
			    WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE)
			{
				ERROR("\"%s\": File type is unsupported",
				      full_path);
				ret = WIMLIB_ERR_UNSUPPORTED_FILE;
				goto out;
			}
			params->progress.scan.cur_path = full_path;
			ret = do_capture_progress(params,
						  WIMLIB_SCAN_DENTRY_UNSUPPORTED,
						  NULL);
			goto out;
		}
	}

	ret = inode_table_new_dentry(params->inode_table, relpath,
				     stbuf.st_ino, stbuf.st_dev,
				     S_ISDIR(stbuf.st_mode), &tree);
	if (ret)
		goto out;

	inode = tree->d_inode;

	/* Already seen this inode?  */
	if (inode->i_nlink > 1)
		goto out_progress;

#ifdef HAVE_STAT_NANOSECOND_PRECISION
	inode->i_creation_time = timespec_to_wim_timestamp(&stbuf.st_mtim);
	inode->i_last_write_time = timespec_to_wim_timestamp(&stbuf.st_mtim);
	inode->i_last_access_time = timespec_to_wim_timestamp(&stbuf.st_atim);
#else
	inode->i_creation_time = time_t_to_wim_timestamp(stbuf.st_mtime);
	inode->i_last_write_time = time_t_to_wim_timestamp(stbuf.st_mtime);
	inode->i_last_access_time = time_t_to_wim_timestamp(stbuf.st_atime);
#endif
	inode->i_resolved = 1;
	if (params->add_flags & WIMLIB_ADD_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;

		unix_data.uid = stbuf.st_uid;
		unix_data.gid = stbuf.st_gid;
		unix_data.mode = stbuf.st_mode;
		unix_data.rdev = stbuf.st_rdev;
		if (!inode_set_unix_data(inode, &unix_data, UNIX_DATA_ALL)) {
			ret = WIMLIB_ERR_NOMEM;
			goto out;
		}
	}

	if (params->add_flags & WIMLIB_ADD_FLAG_ROOT) {
		params->capture_root_ino = stbuf.st_ino;
		params->capture_root_dev = stbuf.st_dev;
		params->add_flags &= ~WIMLIB_ADD_FLAG_ROOT;
	}

	if (S_ISREG(stbuf.st_mode)) {
		ret = unix_scan_regular_file(full_path, stbuf.st_size,
					     inode, params->unhashed_streams);
	} else if (S_ISDIR(stbuf.st_mode)) {
		ret = unix_scan_directory(tree, full_path, full_path_len,
					  dirfd, relpath, params);
	} else if (S_ISLNK(stbuf.st_mode)) {
		ret = unix_scan_symlink(full_path, dirfd, relpath,
					inode, params);
	}

	if (ret)
		goto out;

out_progress:
	params->progress.scan.cur_path = full_path;
	if (likely(tree))
		ret = do_capture_progress(params, WIMLIB_SCAN_DENTRY_OK, inode);
	else
		ret = do_capture_progress(params, WIMLIB_SCAN_DENTRY_EXCLUDED, NULL);
out:
	if (unlikely(ret)) {
		free_dentry_tree(tree, params->blob_table);
		tree = NULL;
		ret = report_capture_error(params, ret, full_path);
	}
	*tree_ret = tree;
	return ret;
}

/*
 * unix_build_dentry_tree():
 *	Builds a tree of WIM dentries from an on-disk directory tree (UNIX
 *	version; no NTFS-specific data is captured).
 *
 * @root_ret:   Place to return a pointer to the root of the dentry tree.  Only
 *		modified if successful.  Set to NULL if the file or directory was
 *		excluded from capture.
 *
 * @root_disk_path:  The path to the root of the directory tree on disk.
 *
 * @params:     See doc for `struct capture_params'.
 *
 * @return:	0 on success, nonzero on failure.  It is a failure if any of
 *		the files cannot be `stat'ed, or if any of the needed
 *		directories cannot be opened or read.  Failure to add the files
 *		to the WIM may still occur later when trying to actually read
 *		the on-disk files during a call to wimlib_write() or
 *		wimlib_overwrite().
 */
int
unix_build_dentry_tree(struct wim_dentry **root_ret,
		       const char *root_disk_path,
		       struct capture_params *params)
{
	size_t path_len;
	size_t path_bufsz;
	char *path_buf;
	int ret;

	path_len = strlen(root_disk_path);
	path_bufsz = min(32790, PATH_MAX + 1);

	if (path_len >= path_bufsz)
		return WIMLIB_ERR_INVALID_PARAM;

	path_buf = MALLOC(path_bufsz);
	if (!path_buf)
		return WIMLIB_ERR_NOMEM;
	memcpy(path_buf, root_disk_path, path_len + 1);

	params->capture_root_nchars = path_len;

	ret = unix_build_dentry_tree_recursive(root_ret, path_buf, path_len,
					       AT_FDCWD, path_buf, params);
	FREE(path_buf);
	return ret;
}

#endif /* !__WIN32__ */
