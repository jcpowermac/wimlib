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
		inode->i_next_attr_id = 1;
		inode->i_not_rpfixed = 1;
		INIT_LIST_HEAD(&inode->i_list);
		INIT_LIST_HEAD(&inode->i_dentry);
	}
	return inode;
}

static void
free_inode(struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_attrs; i++)
		if (inode->i_attrs[i].attr_name != NO_NAME)
			FREE(inode->i_attrs[i].attr_name);
	if (inode->i_attrs != inode->i_embedded_attrs)
		FREE(inode->i_attrs);
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

struct wim_inode_attribute *
inode_get_attribute_utf16le(const struct wim_inode *inode, int attr_type,
			    const utf16lechar *attr_name)
{
	for (unsigned i = 0; i < inode->i_num_attrs; i++)
		if (inode->i_attrs[i].attr_type == attr_type &&
		    !cmp_utf16le_strings_z(inode->i_attrs[i].attr_name, attr_name,
					   default_ignore_case))
			return &inode->i_attrs[i];
	return NULL;
}

struct wim_inode_attribute *
inode_get_unnamed_data_attribute(const struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_attrs; i++)
		if (inode->i_attrs[i].attr_type == ATTR_DATA &&
		    !*inode->i_attrs[i].attr_name)
			return &inode->i_attrs[i];
	return NULL;
}

struct wim_inode_attribute *
inode_get_attribute(const struct wim_inode *inode, int attr_type,
		    const tchar *attr_name)
{
	const utf16lechar *ustr;
	struct wim_inode_attribute *attr;

	if (tstr_get_utf16le(attr_name, &ustr))
		return NULL;

	attr = inode_get_attribute_utf16le(inode, attr_type, ustr);

	tstr_put_utf16le(ustr);

	return attr;
}

struct wim_inode_attribute *
inode_add_attribute_utf16le(struct wim_inode *inode, int attr_type,
			    const utf16lechar *attr_name)
{
	struct wim_inode_attribute *attrs;
	struct wim_inode_attribute *new_attr;

	if (inode_get_attribute_utf16le(inode, attr_type, attr_name)) {
		errno = EEXIST;
		return NULL;
	}

	if (inode->i_num_attrs < INODE_NUM_EMBEDDED_ATTRS) {
		attrs = inode->i_embedded_attrs;
	} else {
		if (inode->i_num_attrs == INODE_NUM_EMBEDDED_ATTRS) {
			attrs = MALLOC((INODE_NUM_EMBEDDED_ATTRS + 1) *
				       sizeof(inode->i_attrs[0]));
			if (!attrs)
				return NULL;
			memcpy(attrs, inode->i_embedded_attrs,
			       (INODE_NUM_EMBEDDED_ATTRS * sizeof(inode->i_attrs[0])));
		} else {
			attrs = REALLOC(inode->i_attrs,
					(inode->i_num_attrs + 1) * sizeof(inode->i_attrs[0]));
			if (!attrs)
				return NULL;
			inode->i_attrs = attrs;
		}
	}
	new_attr = &attrs[inode->i_num_attrs];

	memset(new_attr, 0, sizeof(*new_attr));

	new_attr->attr_type = attr_type;
	if (attr_name == NO_NAME) {
		new_attr->attr_name = NO_NAME;
	} else {
		new_attr->attr_name = utf16le_dup(attr_name);
		if (!new_attr->attr_name)
			return NULL;
	}
	new_attr->attr_id = inode->i_next_attr_id++;

	inode->i_attrs = attrs;
	inode->i_num_attrs++;

	return new_attr;
}

struct wim_inode_attribute *
inode_add_attribute(struct wim_inode *inode, int attr_type,
		    const tchar *attr_name)
{
	const utf16lechar *ustr;
	struct wim_inode_attribute *attr;

	if (tstr_get_utf16le(attr_name, &ustr))
		return NULL;

	attr = inode_add_attribute_utf16le(inode, attr_type, ustr);

	tstr_put_utf16le(ustr);

	return attr;
}

void
inode_remove_attribute(struct wim_inode *inode, struct wim_inode_attribute *attr,
		       struct blob_table *blob_table)
{
	struct blob_descriptor *blob;
	unsigned idx = attr - inode->i_attrs;

	wimlib_assert(idx < inode->i_num_attrs);
	wimlib_assert(inode->i_resolved);

	blob = attr->attr_blob;
	if (blob)
		blob_decrement_refcnt(blob, blob_table);

	FREE(attr->attr_name);

	memmove(&inode->i_attrs[idx],
		&inode->i_attrs[idx + 1],
		(inode->i_num_attrs - idx - 1) * sizeof(inode->i_attrs[0]));
	inode->i_num_attrs--;
}

struct wim_inode_attribute *
inode_add_attribute_with_data(struct wim_inode *inode,
			      int attr_type, const tchar *attr_name,
			      const void *data, size_t size,
			      struct blob_table *blob_table)
{
	struct wim_inode_attribute *new_attr;

	wimlib_assert(inode->i_resolved);

	new_attr = inode_add_attribute(inode, attr_type, attr_name);
	if (unlikely(!new_attr))
		return NULL;

	new_attr->attr_blob = new_blob_from_data_buffer(data, size, blob_table);
	if (unlikely(!new_attr->attr_blob)) {
		inode_remove_attribute(inode, new_attr, NULL);
		return NULL;
	}
	return new_attr;
}

bool
inode_has_named_data_stream(const struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_attrs; i++)
		if (inode->i_attrs[i].attr_type == ATTR_DATA &&
		    *inode->i_attrs[i].attr_name)
			return true;
	return false;
}

/*
 * Resolve an inode's attributes.
 *
 * For each attribute, this replaces the SHA-1 message digest of the blob data
 * with a pointer to the 'struct blob_descriptor' for the blob.  Blob
 * descriptors are looked up in @table.
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
 * If the inode is already resolved, this function does nothing.
 *
 * Returns 0 on success; WIMLIB_ERR_NOMEM if out of memory; or
 * WIMLIB_ERR_RESOURCE_NOT_FOUND if @force is %false and at least one blob
 * referenced by the inode was missing.
 */
int
inode_resolve_attributes(struct wim_inode *inode, struct blob_table *table,
			 bool force)
{
	struct blob_descriptor *blobs[inode->i_num_attrs];

	if (inode->i_resolved)
		return 0;

	for (unsigned i = 0; i < inode->i_num_attrs; i++) {

		const u8 *hash = inode->i_attrs[i].attr_hash;
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

	for (unsigned i = 0; i < inode->i_num_attrs; i++) {
		inode->i_attrs[i].attr_blob = blobs[i];
		inode->i_attrs[i].attr_resolved = 1;
	}
	inode->i_resolved = 1;
	return 0;
}

/*
 * Undo the effects of inode_resolve_attributes().
 *
 * If the inode is not resolved, this function does nothing.
 */
void
inode_unresolve_attributes(struct wim_inode *inode)
{
	if (!inode->i_resolved)
		return;

	for (unsigned i = 0; i < inode->i_num_attrs; i++) {
		if (inode->i_attrs[i].attr_blob)
			copy_hash(inode->i_attrs[i].attr_hash,
				  inode->i_attrs[i].attr_blob->hash);
		else
			zero_out_hash(inode->i_attrs[i].attr_hash);
		inode->i_attrs[i].attr_resolved = 0;
	}
	inode->i_resolved = 0;
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
attribute_blob(const struct wim_inode_attribute *attr, const struct blob_table *table)
{
	if (attr->attr_resolved)
		return attr->attr_blob;
	else
		return lookup_blob(table, attr->attr_hash);
}

/* Return the SHA-1 message digest of the data of the specified attribute, or a
 * void SHA-1 of all zeroes if the specified attribute is empty.   */
const u8 *
attribute_hash(const struct wim_inode_attribute *attr)
{
	if (attr->attr_resolved)
		return attr->attr_blob ? attr->attr_blob->hash : zero_hash;
	else
		return attr->attr_hash;
}

/*
 * Return the blob descriptor for the unnamed data stream of an inode, or NULL
 * if the blob for the inode's unnamed data stream is empty or not available.
 */
struct blob_descriptor *
inode_get_blob_for_unnamed_data_stream(const struct wim_inode *inode,
				       const struct blob_table *table)
{
	struct wim_inode_attribute *attr;

	attr = inode_get_unnamed_data_attribute(inode);
	if (!attr)
		return NULL;

	if (inode->i_resolved)
		return attr->attr_blob;
	else
		return lookup_blob(table, attr->attr_hash);
}

/* Return the SHA-1 message digest of the unnamed data stream of the inode, or a
 * void SHA-1 of all zeroes if the inode's unnamed data stream is empty.   */
const u8 *
inode_get_hash_of_unnamed_data_stream(const struct wim_inode *inode)
{
	const struct wim_inode_attribute *attr;
	
	attr = inode_get_unnamed_data_attribute(inode);
	if (!attr)
		return zero_hash;

	return attribute_hash(attr);
}

/* Acquire another reference to each blob referenced by this inode.  This is
 * necessary when creating a hard link to this inode.
 *
 * The inode must be resolved.  */
void
inode_ref_attributes(struct wim_inode *inode)
{
	wimlib_assert(inode->i_resolved);

	for (unsigned i = 0; i < inode->i_num_attrs; i++)
		if (inode->i_attrs[i].attr_blob)
			inode->i_attrs[i].attr_blob->refcnt++;
}

/* Drop a reference to each blob referenced by this inode.  This is necessary
 * when deleting a hard link to this inode.  */
void
inode_unref_attributes(struct wim_inode *inode, struct blob_table *blob_table)
{
	for (unsigned i = 0; i < inode->i_num_attrs; i++) {
		struct blob_descriptor *blob;

		blob = attribute_blob(&inode->i_attrs[i], blob_table);
		if (blob)
			blob_decrement_refcnt(blob, blob_table);
	}
}

/*
 * Given a blob descriptor, return the pointer contained in the attribute that
 * references it.
 *
 * This is only possible for "unhashed" blobs, which are guaranteed to have only
 * one referencing attribute, and that reference is guaranteed to be in a
 * resolved attribute.  (It can't be in an unresolved attribute, since that
 * would imply the hash is known!)
 */
struct blob_descriptor **
retrieve_blob_pointer(struct blob_descriptor *blob)
{
	wimlib_assert(blob->unhashed);

	struct wim_inode *inode = blob->back_inode;
	for (unsigned i = 0; i < inode->i_num_attrs; i++)
		if (inode->i_attrs[i].attr_id == blob->back_attr_id)
			return &inode->i_attrs[i].attr_blob;

	wimlib_assert(0);
	return NULL;
}
