/*
 * ntfs-3g_capture.c
 *
 * Capture a WIM image directly from an NTFS volume using libntfs-3g.  We capture
 * everything we can, including security data and alternate data streams.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef WITH_NTFS_3G

#include <errno.h>

#include <ntfs-3g/attrib.h>
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/security.h>
#include <ntfs-3g/volume.h>

#include "wimlib/alloca.h"
#include "wimlib/assert.h"
#include "wimlib/capture.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/blob_table.h"
#include "wimlib/ntfs_3g.h"
#include "wimlib/paths.h"
#include "wimlib/security.h"

static inline ntfschar *
attr_record_name(ATTR_RECORD *ar)
{
	return (ntfschar*)((u8*)ar + le16_to_cpu(ar->name_offset));
}

static ntfs_attr *
open_ntfs_attr(ntfs_inode *ni, struct ntfs_location *loc)
{
	ntfs_attr *na;

	na = ntfs_attr_open(ni,
			    (ATTR_TYPES)loc->ntfs_attr_type,
			    loc->ntfs_attr_name,
			    loc->ntfs_attr_name_nchars);
	if (!na) {
		ERROR_WITH_ERRNO("Failed to open attribute of \"%"TS"\" in "
				 "NTFS volume", loc->ntfs_inode_path);
	}
	return na;
}

int
read_ntfs_file_prefix(const struct blob_descriptor *blob, u64 size,
		      consume_data_callback_t cb, void *cb_ctx)
{
	struct ntfs_location *loc = blob->ntfs_loc;
	ntfs_volume *vol = loc->ntfs_vol;
	ntfs_inode *ni;
	ntfs_attr *na;
	s64 pos;
	s64 bytes_remaining;
	int ret;
	u8 buf[BUFFER_SIZE];

	ni = ntfs_pathname_to_inode(vol, NULL, loc->ntfs_inode_path);
	if (!ni) {
		ERROR_WITH_ERRNO("Can't find NTFS inode for \"%"TS"\"",
				 loc->ntfs_inode_path);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	na = open_ntfs_attr(ni, loc);
	if (!na) {
		ret = WIMLIB_ERR_NTFS_3G;
		goto out_close_ntfs_inode;
	}

	pos = (loc->ntfs_attr_type == AT_REPARSE_POINT) ? 8 : 0;
	bytes_remaining = size;
	while (bytes_remaining) {
		s64 to_read = min(bytes_remaining, sizeof(buf));
		if (ntfs_attr_pread(na, pos, to_read, buf) != to_read) {
			ERROR_WITH_ERRNO("Error reading \"%"TS"\"",
					 loc->ntfs_inode_path);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out_close_ntfs_attr;
		}
		pos += to_read;
		bytes_remaining -= to_read;
		ret = cb(buf, to_read, cb_ctx);
		if (ret)
			goto out_close_ntfs_attr;
	}
	ret = 0;
out_close_ntfs_attr:
	ntfs_attr_close(na);
out_close_ntfs_inode:
	ntfs_inode_close(ni);
out:
	return ret;
}

static int
read_reparse_tag(ntfs_inode *ni, struct ntfs_location *loc,
		 u32 *reparse_tag_ret)
{
	int ret;
	le32 reparse_tag;
	ntfs_attr *na;

	na = open_ntfs_attr(ni, loc);
	if (!na) {
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	if (ntfs_attr_pread(na, 0, sizeof(reparse_tag),
			    &reparse_tag) != sizeof(reparse_tag))
	{
		ERROR_WITH_ERRNO("Error reading reparse data");
		ret = WIMLIB_ERR_NTFS_3G;
		goto out_close_ntfs_attr;
	}
	*reparse_tag_ret = le32_to_cpu(reparse_tag);
	DEBUG("ReparseTag = %#x", *reparse_tag_ret);
	ret = 0;
out_close_ntfs_attr:
	ntfs_attr_close(na);
out:
	return ret;

}

static int
ntfs_3g_attr_type_to_wimlib_attr_type(ATTR_TYPES type)
{
	switch (type) {
	case AT_DATA:
		return ATTR_DATA;
	case AT_REPARSE_POINT:
		return ATTR_REPARSE_POINT;
	default:
		wimlib_assert(0);
		return -1;
	}
}

/* Load attributes of the specified type from a file in the NTFS volume  */
static int
capture_ntfs_attrs_with_type(struct wim_inode *inode,
			     ntfs_inode *ni,
			     char *path,
			     size_t path_len,
			     struct list_head *unhashed_blobs,
			     ntfs_volume *vol,
			     ATTR_TYPES type)
{
	ntfs_attr_search_ctx *actx;
	struct ntfs_location *ntfs_loc;
	int ret;
	struct blob_descriptor *blob;

	DEBUG("Capturing NTFS attributes from `%s'", path);

	/* Get context to search the attributes of the NTFS file. */
	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		ERROR_WITH_ERRNO("Cannot get NTFS attribute search "
				 "context for \"%s\"", path);
		return WIMLIB_ERR_NTFS_3G;
	}

	/* Save each attribute  */
	while (!ntfs_attr_lookup(type, NULL, 0,
				 CASE_SENSITIVE, 0, NULL, 0, actx))
	{
		u64 data_size = ntfs_get_attribute_value_length(actx->attr);
		size_t name_nchars = actx->attr->name_length;
		struct wim_inode_attribute *attr;
		const utf16lechar *wimlib_attr_name = NO_NAME;

		if (data_size == 0) {
			/* Empty attribute.  No blob is needed. */
			blob = NULL;
			ntfs_loc = NULL;
		} else {
			ntfs_loc = CALLOC(1, sizeof(*ntfs_loc));
			if (!ntfs_loc) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_put_actx;
			}
			ntfs_loc->ntfs_vol = vol;
			ntfs_loc->ntfs_attr_type = type;
			ntfs_loc->ntfs_inode_path = memdup(path, path_len + 1);
			if (!ntfs_loc->ntfs_inode_path) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_ntfs_loc;
			}
			if (name_nchars) {
				ntfs_loc->ntfs_attr_name =
					utf16le_dupz(attr_record_name(actx->attr),
						     name_nchars * sizeof(ntfschar));
				if (!ntfs_loc->ntfs_attr_name) {
					ret = WIMLIB_ERR_NOMEM;
					goto out_free_ntfs_loc;
				}
				ntfs_loc->ntfs_attr_name_nchars = name_nchars;
				wimlib_attr_name = ntfs_loc->ntfs_attr_name;
			}

			blob = new_blob_descriptor();
			if (!blob) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_ntfs_loc;
			}
			blob->blob_location = BLOB_IN_NTFS_VOLUME;
			blob->ntfs_loc = ntfs_loc;
			blob->size = data_size;
			ntfs_loc = NULL;
			if (type == AT_REPARSE_POINT) {
				if (data_size < 8) {
					ERROR("Invalid reparse data on \"%s\" "
					      "(only %u bytes)!", path,
					      (unsigned)data_size);
					ret = WIMLIB_ERR_NTFS_3G;
					goto out_free_blob;
				}
				blob->size -= 8;
				ret = read_reparse_tag(ni, blob->ntfs_loc,
						       &inode->i_reparse_tag);
				if (ret)
					goto out_free_blob;
			}
		}

		attr = inode_add_attribute_utf16le_with_blob(
				     inode,
				     ntfs_3g_attr_type_to_wimlib_attr_type(type),
				     wimlib_attr_name,
				     blob);
		if (!attr) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_blob;
		}
		prepare_unhashed_blob(blob, inode, attr->attr_id, unhashed_blobs);
	}
	if (errno == ENOENT) {
		ret = 0;
	} else {
		ERROR_WITH_ERRNO("Error listing NTFS attributes of \"%s\"", path);
		ret = WIMLIB_ERR_NTFS_3G;
	}
	goto out_put_actx;
out_free_blob:
	free_blob_descriptor(blob);
out_free_ntfs_loc:
	if (ntfs_loc) {
		FREE(ntfs_loc->ntfs_inode_path);
		FREE(ntfs_loc->ntfs_attr_name);
		FREE(ntfs_loc);
	}
out_put_actx:
	ntfs_attr_put_search_ctx(actx);
	if (ret == 0)
		DEBUG("Successfully captured NTFS attributes from \"%s\"", path);
	else
		ERROR("Failed to capture NTFS attributes from \"%s\"", path);
	return ret;
}

/* Binary tree that maps NTFS inode numbers to DOS names */
struct dos_name_map {
	struct avl_tree_node *root;
};

struct dos_name_node {
	struct avl_tree_node index_node;
	char dos_name[24];
	int name_nbytes;
	le64 ntfs_ino;
};

#define DOS_NAME_NODE(avl_node) \
	avl_tree_entry(avl_node, struct dos_name_node, index_node)

static int
_avl_cmp_by_ntfs_ino(const struct avl_tree_node *n1,
		     const struct avl_tree_node *n2)
{
	return cmp_u64(DOS_NAME_NODE(n1)->ntfs_ino,
		       DOS_NAME_NODE(n2)->ntfs_ino);
}

/* Inserts a new DOS name into the map */
static int
insert_dos_name(struct dos_name_map *map, const ntfschar *dos_name,
		size_t name_nbytes, le64 ntfs_ino)
{
	struct dos_name_node *new_node;

	DEBUG("DOS name_len = %zu", name_nbytes);
	new_node = MALLOC(sizeof(struct dos_name_node));
	if (!new_node)
		return WIMLIB_ERR_NOMEM;

	/* DOS names are supposed to be 12 characters max (that's 24 bytes,
	 * assuming 2-byte ntfs characters) */
	wimlib_assert(name_nbytes <= sizeof(new_node->dos_name));

	/* Initialize the DOS name, DOS name length, and NTFS inode number of
	 * the search tree node */
	memcpy(new_node->dos_name, dos_name, name_nbytes);
	new_node->name_nbytes = name_nbytes;
	new_node->ntfs_ino = ntfs_ino;

	/* Insert the search tree node */
	if (avl_tree_insert(&map->root, &new_node->index_node,
			    _avl_cmp_by_ntfs_ino))
	{
		/* This should be impossible since an NTFS inode cannot
		 * have multiple DOS names, and we only should get each
		 * DOS name entry once from the ntfs_readdir() calls. */
		ERROR("NTFS inode %"PRIu64" has multiple DOS names",
			le64_to_cpu(ntfs_ino));
		FREE(new_node);
		return WIMLIB_ERR_NOMEM;
	}
	DEBUG("Inserted DOS name for inode %"PRIu64, le64_to_cpu(ntfs_ino));
	return 0;
}

/* Returns a structure that contains the DOS name and its length for an NTFS
 * inode, or NULL if the inode has no DOS name. */
static struct dos_name_node *
lookup_dos_name(const struct dos_name_map *map, u64 ntfs_ino)
{
	struct dos_name_node dummy;
	struct avl_tree_node *res;

	dummy.ntfs_ino = cpu_to_le64(ntfs_ino);

	res = avl_tree_lookup_node(map->root, &dummy.index_node,
				   _avl_cmp_by_ntfs_ino);
	if (!res)
		return NULL;
	return DOS_NAME_NODE(res);
}

static int
set_dentry_dos_name(struct wim_dentry *dentry, const struct dos_name_map *map)
{
	const struct dos_name_node *node;

	if (dentry->is_win32_name) {
		node = lookup_dos_name(map, dentry->d_inode->i_ino);
		if (node) {
			dentry->short_name = utf16le_dupz(node->dos_name,
							  node->name_nbytes);
			if (!dentry->short_name)
				return WIMLIB_ERR_NOMEM;
			dentry->short_name_nbytes = node->name_nbytes;
			DEBUG("Assigned DOS name to ino %"PRIu64,
			      dentry->d_inode->i_ino);
		} else {
			WARNING("NTFS inode %"PRIu64" has Win32 name with no "
				"corresponding DOS name",
				dentry->d_inode->i_ino);
		}
	}
	return 0;
}

static void
free_dos_name_tree(struct avl_tree_node *node) {
	if (node) {
		free_dos_name_tree(node->left);
		free_dos_name_tree(node->right);
		FREE(DOS_NAME_NODE(node));
	}
}

static void
destroy_dos_name_map(struct dos_name_map *map)
{
	free_dos_name_tree(map->root);
}

struct readdir_ctx {
	struct wim_dentry *parent;
	char *path;
	size_t path_len;
	struct dos_name_map *dos_name_map;
	ntfs_volume *vol;
	struct capture_params *params;
	int ret;
};

static int
build_dentry_tree_ntfs_recursive(struct wim_dentry **root_p,
				 ntfs_inode *ni,
				 char *path,
				 size_t path_len,
				 int name_type,
				 ntfs_volume *ntfs_vol,
				 struct capture_params *params);

static int
wim_ntfs_capture_filldir(void *dirent, const ntfschar *name,
			 const int name_nchars, const int name_type,
			 const s64 pos, const MFT_REF mref,
			 const unsigned dt_type)
{
	struct readdir_ctx *ctx;
	size_t mbs_name_nbytes;
	char *mbs_name;
	struct wim_dentry *child;
	int ret;
	size_t path_len;
	size_t name_nbytes = name_nchars * sizeof(ntfschar);

	ctx = dirent;
	if (name_type & FILE_NAME_DOS) {
		/* If this is the entry for a DOS name, store it for later. */
		ret = insert_dos_name(ctx->dos_name_map, name,
				      name_nbytes, mref & MFT_REF_MASK_CPU);

		/* Return now if an error occurred or if this is just a DOS name
		 * and not a Win32+DOS name. */
		if (ret != 0 || name_type == FILE_NAME_DOS)
			goto out;
	}
	ret = utf16le_to_tstr(name, name_nbytes,
			      &mbs_name, &mbs_name_nbytes);
	if (ret)
		goto out;

	if (mbs_name[0] == '.' &&
	     (mbs_name[1] == '\0' ||
	      (mbs_name[1] == '.' && mbs_name[2] == '\0'))) {
		/* . or .. entries
		 *
		 * note: name_type is POSIX for these, so DOS names will not
		 * have been inserted for them.  */
		ret = 0;
		goto out_free_mbs_name;
	}

	/* Open the inode for this directory entry and recursively capture the
	 * directory tree rooted at it */
	ntfs_inode *ni = ntfs_inode_open(ctx->vol, mref);
	if (!ni) {
		/* XXX This used to be treated as an error, but NTFS-3g seemed
		 * to be unable to read some inodes on a Windows 8 image for
		 * some reason. */
		WARNING_WITH_ERRNO("Failed to open NTFS file \"%s/%s\"",
				   ctx->path, mbs_name);
		ret = 0;
		goto out_free_mbs_name;
	}
	path_len = ctx->path_len;
	if (path_len != 1)
		ctx->path[path_len++] = '/';
	memcpy(ctx->path + path_len, mbs_name, mbs_name_nbytes + 1);
	path_len += mbs_name_nbytes;
	child = NULL;
	ret = build_dentry_tree_ntfs_recursive(&child, ni, ctx->path,
					       path_len, name_type,
					       ctx->vol, ctx->params);
	path_len -= mbs_name_nbytes + 1;
	if (child)
		dentry_add_child(ctx->parent, child);
	ntfs_inode_close(ni);
out_free_mbs_name:
	FREE(mbs_name);
out:
	ctx->path[ctx->path_len] = '\0';
	ctx->ret = ret;
	return ret;
}

/* Recursive scan routine for NTFS volumes  */
static int
build_dentry_tree_ntfs_recursive(struct wim_dentry **root_ret,
				 ntfs_inode *ni,
				 char *path,
				 size_t path_len,
				 int name_type,
				 ntfs_volume *vol,
				 struct capture_params *params)
{
	u32 attributes;
	int ret;
	struct wim_dentry *root = NULL;
	struct wim_inode *inode = NULL;

	ret = try_exclude(path, path_len, params);
	if (ret < 0) /* Excluded? */
		goto out_progress;
	if (ret > 0) /* Error? */
		goto out;

	/* Get file attributes */
	ret = ntfs_get_ntfs_attrib(ni, (char*)&attributes, sizeof(attributes));
	if (ret != sizeof(attributes)) {
		ERROR_WITH_ERRNO("Failed to get NTFS attributes from \"%s\"", path);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	if ((attributes & (FILE_ATTRIBUTE_DIRECTORY |
			   FILE_ATTRIBUTE_ENCRYPTED)) == FILE_ATTRIBUTE_ENCRYPTED)
	{
		if (params->add_flags & WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE)
		{
			ERROR("Can't archive unsupported encrypted file \"%s\"", path);
			ret = WIMLIB_ERR_UNSUPPORTED_FILE;
			goto out;
		}
		params->progress.scan.cur_path = path;
		ret = do_capture_progress(params, WIMLIB_SCAN_DENTRY_UNSUPPORTED, NULL);
		goto out;
	}

	/* Create a WIM dentry with an associated inode, which may be shared */
	ret = inode_table_new_dentry(params->inode_table,
				     path_basename_with_len(path, path_len),
				     ni->mft_no, 0, false, &root);
	if (ret)
		goto out;

	if (name_type & FILE_NAME_WIN32) /* Win32 or Win32+DOS name (rather than POSIX) */
		root->is_win32_name = 1;

	inode = root->d_inode;

	if (inode->i_nlink > 1) {
		/* Shared inode; nothing more to do */
		goto out_progress;
	}

	inode->i_creation_time    = le64_to_cpu(ni->creation_time);
	inode->i_last_write_time  = le64_to_cpu(ni->last_data_change_time);
	inode->i_last_access_time = le64_to_cpu(ni->last_access_time);
	inode->i_file_flags       = attributes;

	if (attributes & FILE_ATTR_REPARSE_POINT) {
		/* Capture reparse point attribute  */
		ret = capture_ntfs_attrs_with_type(inode, ni, path, path_len,
						   params->unhashed_blobs,
						   vol, AT_REPARSE_POINT);
		if (ret)
			goto out;
	}

	/* Capture data streams.
	 *
	 * Directories should not have an unnamed data stream, but they may have
	 * named data streams.  Nondirectories (including reparse points) can
	 * have an unnamed data stream as well as named data streams.  */
	ret = capture_ntfs_attrs_with_type(inode, ni, path, path_len,
					   params->unhashed_blobs, vol, AT_DATA);
	if (ret)
		goto out;

	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {

		/* Recurse to directory children */
		s64 pos = 0;
		struct dos_name_map dos_name_map = { .root = NULL };
		struct readdir_ctx ctx = {
			.parent          = root,
			.path            = path,
			.path_len        = path_len,
			.dos_name_map    = &dos_name_map,
			.vol             = vol,
			.params          = params,
			.ret 		 = 0,
		};
		ret = ntfs_readdir(ni, &pos, &ctx, wim_ntfs_capture_filldir);
		if (ret) {
			if (ctx.ret) {
				/* wimlib error  */
				ret = ctx.ret;
			} else {
				/* error from ntfs_readdir() itself  */
				ERROR_WITH_ERRNO("Error reading directory \"%s\"", path);
				ret = WIMLIB_ERR_NTFS_3G;
			}
		} else {
			struct wim_dentry *child;

			ret = 0;
			for_dentry_child(child, root) {
				ret = set_dentry_dos_name(child, &dos_name_map);
				if (ret)
					break;
			}
		}
		destroy_dos_name_map(&dos_name_map);
		if (ret)
			goto out;
	}
	path[path_len] = '\0';

	/* Reparse-point fixups are a no-op because in NTFS-3g capture mode we
	 * only allow capturing an entire volume. */
	if (params->add_flags & WIMLIB_ADD_FLAG_RPFIX &&
	    inode_is_symlink(inode))
		inode->i_not_rpfixed = 0;

	if (!(params->add_flags & WIMLIB_ADD_FLAG_NO_ACLS)) {
		struct SECURITY_CONTEXT sec_ctx;
		char _sd[4096];
		char *sd;

		/* Get security descriptor */
		memset(&sec_ctx, 0, sizeof(sec_ctx));
		sec_ctx.vol = vol;

		errno = 0;
		sd = _sd;
		ret = ntfs_get_ntfs_acl(&sec_ctx, ni, sd, sizeof(_sd));
		if (ret > sizeof(_sd)) {
			sd = alloca(ret);
			ret = ntfs_get_ntfs_acl(&sec_ctx, ni, sd, ret);
		}
		if (ret > 0) {
			inode->i_security_id = sd_set_add_sd(params->sd_set,
							     sd, ret);
			if (inode->i_security_id == -1) {
				ERROR("Out of memory");
				ret = WIMLIB_ERR_NOMEM;
				goto out;
			}
			DEBUG("Added security ID = %u for `%s'",
			      inode->i_security_id, path);
			ret = 0;
		} else if (ret < 0) {
			ERROR_WITH_ERRNO("Failed to get security information from "
					 "`%s'", path);
			ret = WIMLIB_ERR_NTFS_3G;
		} else {
			inode->i_security_id = -1;
			DEBUG("No security ID for `%s'", path);
		}
	}
	if (ret)
		goto out;

out_progress:
	params->progress.scan.cur_path = path;
	if (root == NULL)
		ret = do_capture_progress(params, WIMLIB_SCAN_DENTRY_EXCLUDED, NULL);
	else
		ret = do_capture_progress(params, WIMLIB_SCAN_DENTRY_OK, inode);
out:
	if (unlikely(ret)) {
		free_dentry_tree(root, params->blob_table);
		root = NULL;
		ret = report_capture_error(params, ret, path);
	}
	*root_ret = root;
	return ret;
}


int
do_ntfs_umount(struct _ntfs_volume *vol)
{
	DEBUG("Unmounting NTFS volume");
	if (ntfs_umount(vol, FALSE))
		return WIMLIB_ERR_NTFS_3G;
	else
		return 0;
}

int
build_dentry_tree_ntfs(struct wim_dentry **root_p,
		       const char *device,
		       struct capture_params *params)
{
	ntfs_volume *vol;
	ntfs_inode *root_ni;
	int ret;

	DEBUG("Mounting NTFS volume `%s' read-only", device);

/* NTFS-3g 2013 renamed the "read-only" mount flag from MS_RDONLY to
 * NTFS_MNT_RDONLY.
 *
 * Unfortunately we can't check for defined(NTFS_MNT_RDONLY) because
 * NTFS_MNT_RDONLY is an enumerated constant.  Also, the NTFS-3g headers don't
 * seem to contain any explicit version information.  So we have to rely on a
 * test done at configure time to detect whether NTFS_MNT_RDONLY should be used.
 * */
#ifdef HAVE_NTFS_MNT_RDONLY
	/* NTFS-3g 2013 */
	vol = ntfs_mount(device, NTFS_MNT_RDONLY);
#elif defined(MS_RDONLY)
	/* NTFS-3g 2011, 2012 */
	vol = ntfs_mount(device, MS_RDONLY);
#else
  #error "Can't find NTFS_MNT_RDONLY or MS_RDONLY flags"
#endif
	if (!vol) {
		ERROR_WITH_ERRNO("Failed to mount NTFS volume `%s' read-only",
				 device);
		return WIMLIB_ERR_NTFS_3G;
	}
	ntfs_open_secure(vol);

	/* We don't want to capture the special NTFS files such as $Bitmap.  Not
	 * to be confused with "hidden" or "system" files which are real files
	 * that we do need to capture.  */
	NVolClearShowSysFiles(vol);

	DEBUG("Opening root NTFS dentry");
	root_ni = ntfs_inode_open(vol, FILE_root);
	if (!root_ni) {
		ERROR_WITH_ERRNO("Failed to open root inode of NTFS volume "
				 "`%s'", device);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	/* Currently we assume that all the paths fit into this length and there
	 * is no check for overflow. */
	char *path = MALLOC(32768);
	if (!path) {
		ERROR("Could not allocate memory for NTFS pathname");
		ret = WIMLIB_ERR_NOMEM;
		goto out_cleanup;
	}

	path[0] = '/';
	path[1] = '\0';
	ret = build_dentry_tree_ntfs_recursive(root_p, root_ni, path, 1,
					       FILE_NAME_POSIX, vol, params);
out_cleanup:
	FREE(path);
	ntfs_inode_close(root_ni);
out:
	ntfs_index_ctx_put(vol->secure_xsii);
	ntfs_index_ctx_put(vol->secure_xsdh);
	ntfs_inode_close(vol->secure_ni);

	if (ret) {
		if (do_ntfs_umount(vol)) {
			ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%s'",
					 device);
		}
	} else {
		/* We need to leave the NTFS volume mounted so that we can read
		 * the NTFS files again when we are actually writing the WIM */
		*(ntfs_volume**)params->extra_arg = vol;
	}
	return ret;
}
#endif /* WITH_NTFS_3G */
