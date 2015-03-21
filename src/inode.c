/*
 * inode.c
 *
 * Functions that operate on WIM inodes.
 *
 * See dentry.c for a description of the relationship between WIM dentries and
 * WIM inodes.
 */

/*
 * Copyright (C) 2012, 2013, 2014, 2015 Eric Biggers
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

#include <errno.h>

#include "wimlib/assert.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/inode.h"
#include "wimlib/blob_table.h"
#include "wimlib/timestamp.h"

/*
 * The 'stream_name' field of unnamed streams always points to this array, which
 * is an empty UTF-16 string.
 */
const utf16lechar NO_STREAM_NAME[1];

/* Allocate a new inode.  Set the timestamps to the current time.  */
struct wim_inode *
new_inode(void)
{
	struct wim_inode *inode = new_timeless_inode();
	if (inode) {
		u64 now = now_as_wim_timestamp();
		inode->i_creation_time = now;
		inode->i_last_access_time = now;
		inode->i_last_write_time = now;
	}
	return inode;
}

/* Allocate a new inode.  Leave the timestamps zeroed out.  */
struct wim_inode *
new_timeless_inode(void)
{
	struct wim_inode *inode = CALLOC(1, sizeof(struct wim_inode));
	if (inode) {
		inode->i_security_id = -1;
		/*inode->i_nlink = 0;*/
		inode->i_next_stream_id = 1;
		inode->i_not_rpfixed = 1;
		INIT_LIST_HEAD(&inode->i_list);
		INIT_LIST_HEAD(&inode->i_dentry);
	}
	return inode;
}

static void
free_inode(struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++)
		if (inode->i_streams[i].stream_name != NO_STREAM_NAME)
			FREE(inode->i_streams[i].stream_name);
	if (inode->i_streams != inode->i_embedded_streams)
		FREE(inode->i_streams);
	if (unlikely(inode->i_extra))
		FREE(inode->i_extra);
	/* HACK: This may instead delete the inode from i_list, but hlist_del()
	 * behaves the same as list_del(). */
	if (!hlist_unhashed(&inode->i_hlist))
		hlist_del(&inode->i_hlist);
	FREE(inode);
}

static inline void
free_inode_if_unneeded(struct wim_inode *inode)
{
	if (inode->i_nlink)
		return;
#ifdef WITH_FUSE
	if (inode->i_num_opened_fds)
		return;
#endif
	free_inode(inode);
}

/* Associate a dentry with the specified inode.  */
void
d_associate(struct wim_dentry *dentry, struct wim_inode *inode)
{
	wimlib_assert(!dentry->d_inode);

	list_add_tail(&dentry->d_alias, &inode->i_dentry);
	dentry->d_inode = inode;
	inode->i_nlink++;
}

/* Disassociate a dentry from its inode, if any.  Following this, free the inode
 * if it is no longer in use.  */
void
d_disassociate(struct wim_dentry *dentry)
{
	struct wim_inode *inode = dentry->d_inode;

	if (unlikely(!inode))
		return;

	wimlib_assert(inode->i_nlink > 0);

	list_del(&dentry->d_alias);
	dentry->d_inode = NULL;
	inode->i_nlink--;

	free_inode_if_unneeded(inode);
}

#ifdef WITH_FUSE
void
inode_dec_num_opened_fds(struct wim_inode *inode)
{
	wimlib_assert(inode->i_num_opened_fds > 0);

	if (--inode->i_num_opened_fds == 0) {
		/* The last file descriptor to this inode was closed.  */
		FREE(inode->i_fds);
		inode->i_fds = NULL;
		inode->i_num_allocated_fds = 0;

		free_inode_if_unneeded(inode);
	}
}
#endif

struct wim_inode_stream *
inode_get_stream_utf16le(const struct wim_inode *inode, int stream_type,
			 const utf16lechar *stream_name)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++)
		if (inode->i_streams[i].stream_type == stream_type &&
		    !cmp_utf16le_strings_z(inode->i_streams[i].stream_name, stream_name,
					   default_ignore_case))
			return &inode->i_streams[i];
	return NULL;
}

struct wim_inode_stream *
inode_get_unnamed_data_stream(const struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++)
		if (inode->i_streams[i].stream_type == STREAM_TYPE_DATA &&
		    !*inode->i_streams[i].stream_name)
			return &inode->i_streams[i];
	return NULL;
}

struct wim_inode_stream *
inode_get_stream(const struct wim_inode *inode, int stream_type,
		 const tchar *stream_name)
{
	const utf16lechar *ustr;
	struct wim_inode_stream *strm;

	if (tstr_get_utf16le(stream_name, &ustr))
		return NULL;

	strm = inode_get_stream_utf16le(inode, stream_type, ustr);

	tstr_put_utf16le(ustr);

	return strm;
}

struct wim_inode_stream *
inode_add_stream_utf16le(struct wim_inode *inode, int stream_type,
			 const utf16lechar *stream_name)
{
	struct wim_inode_stream *streams;
	struct wim_inode_stream *new_stream;

	if (inode->i_num_streams < ARRAY_LEN(inode->i_embedded_streams)) {
		streams = inode->i_embedded_streams;
	} else {
		if (inode->i_num_streams == ARRAY_LEN(inode->i_embedded_streams)) {
			streams = MALLOC((ARRAY_LEN(inode->i_embedded_streams) + 1) *
				       sizeof(inode->i_streams[0]));
			if (!streams)
				return NULL;
			memcpy(streams, inode->i_embedded_streams,
			       (ARRAY_LEN(inode->i_embedded_streams) * sizeof(inode->i_streams[0])));
		} else {
			streams = REALLOC(inode->i_streams,
					(inode->i_num_streams + 1) * sizeof(inode->i_streams[0]));
			if (!streams)
				return NULL;
			inode->i_streams = streams;
		}
	}
	new_stream = &streams[inode->i_num_streams];

	memset(new_stream, 0, sizeof(*new_stream));

	new_stream->stream_type = stream_type;
	if (!*stream_name) {
		/* Unnamed stream  */
		new_stream->stream_name = (utf16lechar *)NO_STREAM_NAME;
	} else {
		/* Named stream  */
		new_stream->stream_name = utf16le_dup(stream_name);
		if (!new_stream->stream_name)
			return NULL;
	}
	new_stream->stream_id = inode->i_next_stream_id++;

	inode->i_streams = streams;
	inode->i_num_streams++;

	return new_stream;
}

struct wim_inode_stream *
inode_add_stream(struct wim_inode *inode, int stream_type,
		 const tchar *stream_name)
{
	const utf16lechar *ustr;
	struct wim_inode_stream *strm;

	if (tstr_get_utf16le(stream_name, &ustr))
		return NULL;

	strm = inode_add_stream_utf16le(inode, stream_type, ustr);

	tstr_put_utf16le(ustr);

	return strm;
}

void
inode_remove_stream(struct wim_inode *inode, struct wim_inode_stream *strm,
		    struct blob_table *blob_table)
{
	struct blob_descriptor *blob;
	unsigned idx = strm - inode->i_streams;

	wimlib_assert(idx < inode->i_num_streams);
	wimlib_assert(strm->stream_resolved);

	blob = stream_blob(strm, blob_table);
	if (blob)
		blob_decrement_refcnt(blob, blob_table);

	FREE(strm->stream_name);

	memmove(&inode->i_streams[idx],
		&inode->i_streams[idx + 1],
		(inode->i_num_streams - idx - 1) * sizeof(inode->i_streams[0]));
	inode->i_num_streams--;
}

struct wim_inode_stream *
inode_add_stream_utf16le_with_blob(struct wim_inode *inode,
				   int stream_type,
				   const utf16lechar *stream_name,
				   struct blob_descriptor *blob)
{
	struct wim_inode_stream *strm;

	strm = inode_add_stream_utf16le(inode, stream_type, stream_name);
	if (strm)
		stream_set_blob(strm, blob);
	return strm;
}

struct wim_inode_stream *
inode_add_stream_with_blob(struct wim_inode *inode,
			   int stream_type, const tchar *stream_name,
			   struct blob_descriptor *blob)
{
	struct wim_inode_stream *strm;

	strm = inode_add_stream(inode, stream_type, stream_name);
	if (strm)
		stream_set_blob(strm, blob);
	return strm;
}

struct wim_inode_stream *
inode_add_stream_with_data(struct wim_inode *inode,
			   int stream_type, const tchar *stream_name,
			   const void *data, size_t size,
			   struct blob_table *blob_table)
{
	struct blob_descriptor *blob;
	struct wim_inode_stream *strm;

	blob = new_blob_from_data_buffer(data, size, blob_table);
	if (!blob)
		return NULL;

	strm = inode_add_stream_with_blob(inode, stream_type, stream_name, blob);

	if (!strm)
		blob_decrement_refcnt(blob, blob_table);

	return strm;
}

bool
inode_has_named_data_stream(const struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++)
		if (inode->i_streams[i].stream_type == STREAM_TYPE_DATA &&
		    *inode->i_streams[i].stream_name)
			return true;
	return false;
}

/*
 * Resolve an inode's streams.
 *
 * For each stream, this replaces the SHA-1 message digest of the blob data with
 * a pointer to the 'struct blob_descriptor' for the blob.  Blob descriptors are
 * looked up in @table.
 *
 * If @force is %false:
 *	If any of the needed blobs do not exist in @table, return
 *	WIMLIB_ERR_RESOURCE_NOT_FOUND and leave the inode unmodified.
 * If @force is %true:
 *	If any of the needed blobs do not exist in @table, allocate new blob
 *	descriptors for them and insert them into @table.  This does not, of
 *	course, cause the data of these blobs to magically exist, but this is
 *	needed by the code for extraction from a pipe.
 *
 * Returns 0 on success; WIMLIB_ERR_NOMEM if out of memory; or
 * WIMLIB_ERR_RESOURCE_NOT_FOUND if @force is %false and at least one blob
 * referenced by the inode was missing.
 */
int
inode_resolve_streams(struct wim_inode *inode, struct blob_table *table,
			 bool force)
{
	struct blob_descriptor *blobs[inode->i_num_streams];

	for (unsigned i = 0; i < inode->i_num_streams; i++) {

		if (inode->i_streams[i].stream_resolved)
			continue;

		const u8 *hash = stream_hash(&inode->i_streams[i]);
		struct blob_descriptor *blob = NULL;

		if (!is_zero_hash(hash)) {
			blob = lookup_blob(table, hash);
			if (!blob) {
				if (!force)
					return blob_not_found_error(inode, hash);
				blob = new_blob_descriptor();
				if (!blob)
					return WIMLIB_ERR_NOMEM;
				copy_hash(blob->hash, hash);
				blob_table_insert(table, blob);
			}
		}
		blobs[i] = blob;
	}

	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		if (inode->i_streams[i].stream_resolved)
			continue;
		stream_set_blob(&inode->i_streams[i], blobs[i]);
	}
	return 0;
}

/*
 * Undo the effects of inode_resolve_streams().
 */
void
inode_unresolve_streams(struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++) {

		if (!inode->i_streams[i].stream_resolved)
			continue;

		copy_hash(inode->i_streams[i]._stream_hash,
			  stream_hash(&inode->i_streams[i]));
		inode->i_streams[i].stream_resolved = 0;
	}
}

int
blob_not_found_error(const struct wim_inode *inode, const u8 *hash)
{
	if (wimlib_print_errors) {
		tchar hashstr[SHA1_HASH_SIZE * 2 + 1];

		sprint_hash(hash, hashstr);

		ERROR("\"%"TS"\": blob not found\n"
		      "        SHA-1 message digest of missing blob:\n"
		      "        %"TS"",
		      inode_first_full_path(inode), hashstr);
	}
	return WIMLIB_ERR_RESOURCE_NOT_FOUND;
}

struct blob_descriptor *
stream_blob(const struct wim_inode_stream *strm, const struct blob_table *table)
{
	if (strm->stream_resolved)
		return strm->_stream_blob;
	else
		return lookup_blob(table, strm->_stream_hash);
}

/* Return the SHA-1 message digest of the data of the specified stream, or a
 * void SHA-1 of all zeroes if the specified stream is empty.   */
const u8 *
stream_hash(const struct wim_inode_strm *strm)
{
	if (strm->stream_resolved)
		return strm->_stream_blob ? strm->_stream_blob->hash : zero_hash;
	else
		return strm->_stream_hash;
}

/*
 * Return the blob descriptor for the unnamed data stream of an inode, or NULL
 * if the blob for the inode's unnamed data stream is empty or not available.
 */
struct blob_descriptor *
inode_get_blob_for_unnamed_data_stream(const struct wim_inode *inode,
				       const struct blob_table *blob_table)
{
	struct wim_inode_stream *strm;

	strm = inode_get_unnamed_data_stream(inode);
	if (!strm)
		return NULL;

	return stream_blob(strm, blob_table);
}

/* Return the SHA-1 message digest of the unnamed data stream of the inode, or a
 * void SHA-1 of all zeroes if the inode's unnamed data stream is empty.   */
const u8 *
inode_get_hash_of_unnamed_data_stream(const struct wim_inode *inode)
{
	const struct wim_inode_stream *strm;

	strm = inode_get_unnamed_data_stream(inode);
	if (!strm)
		return zero_hash;

	return stream_hash(strm);
}

/* Acquire another reference to each blob referenced by this inode.  This is
 * necessary when creating a hard link to this inode.
 *
 * All streams of the inode must be resolved.  */
void
inode_ref_streams(struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		struct blob_descriptor *blob;

		blob = stream_blob_resolved(&inode->i_streams[i]);
		if (blob)
			blob->refcnt++;
	}
}

/* Drop a reference to each blob referenced by this inode.  This is necessary
 * when deleting a hard link to this inode.  */
void
inode_unref_streams(struct wim_inode *inode, struct blob_table *blob_table)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		struct blob_descriptor *blob;

		blob = stream_blob(&inode->i_streams[i], blob_table);
		if (blob)
			blob_decrement_refcnt(blob, blob_table);
	}
}

/*
 * Given a blob descriptor, return the pointer contained in the stream that
 * references it.
 *
 * This is only possible for "unhashed" blobs, which are guaranteed to have only
 * one referencing stream, and that reference is guaranteed to be in a resolved
 * stream.  (It can't be in an unresolved stream, since that would imply the
 * hash is known!)
 */
struct blob_descriptor **
retrieve_blob_pointer(struct blob_descriptor *blob)
{
	wimlib_assert(blob->unhashed);

	struct wim_inode *inode = blob->back_inode;
	for (unsigned i = 0; i < inode->i_num_streams; i++)
		if (inode->i_streams[i].stream_id == blob->back_stream_id)
			return &inode->i_streams[i]._stream_blob;

	wimlib_assert(0);
	return NULL;
}
