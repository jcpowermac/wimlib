/*
 * blob_table.c
 *
 * The blob table maps SHA-1 message digests to "blobs", which are nonempty
 * sequences of binary data.  Within a WIM file, blobs are single-instanced.
 *
 * This file also contains code to read and write the corresponding on-disk
 * representation of this table in the WIM file format.
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* for unlink()  */

#include "wimlib/assert.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/blob_table.h"
#include "wimlib/metadata.h"
#include "wimlib/ntfs_3g.h"
#include "wimlib/resource.h"
#include "wimlib/unaligned.h"
#include "wimlib/util.h"
#include "wimlib/write.h"

/* A hash table mapping SHA-1 message digests to blob descriptors  */
struct blob_table {
	struct hlist_head *array;
	size_t num_blobs;
	size_t capacity;
};

struct blob_table *
new_blob_table(size_t capacity)
{
	struct blob_table *table;
	struct hlist_head *array;

	table = MALLOC(sizeof(struct blob_table));
	if (table == NULL)
		goto oom;

	array = CALLOC(capacity, sizeof(array[0]));
	if (array == NULL) {
		FREE(table);
		goto oom;
	}

	table->num_blobs = 0;
	table->capacity = capacity;
	table->array = array;
	return table;

oom:
	ERROR("Failed to allocate memory for blob table "
	      "with capacity %zu", capacity);
	return NULL;
}

static int
do_free_blob_descriptor(struct blob_descriptor *blob, void *_ignore)
{
	free_blob_descriptor(blob);
	return 0;
}

void
free_blob_table(struct blob_table *table)
{
	if (table) {
		for_blob_in_table(table, do_free_blob_descriptor, NULL);
		FREE(table->array);
		FREE(table);
	}
}

struct blob_descriptor *
new_blob_descriptor(void)
{
	struct blob_descriptor *blob;

	blob = CALLOC(1, sizeof(struct blob_descriptor));
	if (blob == NULL)
		return NULL;

	blob->refcnt = 1;

	/* blob->blob_location = BLOB_NONEXISTENT  */
	BUILD_BUG_ON(BLOB_NONEXISTENT != 0);

	return blob;
}

struct blob_descriptor *
clone_blob_descriptor(const struct blob_descriptor *old)
{
	struct blob_descriptor *new;

	new = memdup(old, sizeof(struct blob_descriptor));
	if (new == NULL)
		return NULL;

	switch (new->blob_location) {
	case BLOB_IN_WIM:
		list_add(&new->rdesc_node, &new->rdesc->blob_list);
		break;

	case BLOB_IN_FILE_ON_DISK:
#ifdef __WIN32__
	case BLOB_IN_WINNT_FILE_ON_DISK:
	case BLOB_WIN32_ENCRYPTED:
#endif
#ifdef WITH_FUSE
	case BLOB_IN_STAGING_FILE:
		BUILD_BUG_ON((void*)&old->file_on_disk !=
			     (void*)&old->staging_file_name);
#endif
		new->file_on_disk = TSTRDUP(old->file_on_disk);
		if (new->file_on_disk == NULL)
			goto out_free;
		break;
	case BLOB_IN_ATTACHED_BUFFER:
		new->attached_buffer = memdup(old->attached_buffer, old->size);
		if (new->attached_buffer == NULL)
			goto out_free;
		break;
#ifdef WITH_NTFS_3G
	case BLOB_IN_NTFS_VOLUME:
		if (old->ntfs_loc) {
			struct ntfs_location *loc;
			loc = memdup(old->ntfs_loc, sizeof(struct ntfs_location));
			if (loc == NULL)
				goto out_free;
			loc->path = NULL;
			loc->attr_name = NULL;
			new->ntfs_loc = loc;
			loc->path = STRDUP(old->ntfs_loc->path);
			if (loc->path == NULL)
				goto out_free;
			if (loc->attr_name_nchars != 0) {
				loc->attr_name = utf16le_dup(old->ntfs_loc->attr_name);
				if (loc->attr_name == NULL)
					goto out_free;
			}
		}
		break;
#endif
	default:
		break;
	}
	return new;

out_free:
	free_blob_descriptor(new);
	return NULL;
}

void
blob_release_location(struct blob_descriptor *blob)
{
	switch (blob->blob_location) {
	case BLOB_IN_WIM:
		list_del(&blob->rdesc_node);
		if (list_empty(&blob->rdesc->blob_list))
			FREE(blob->rdesc);
		break;
	case BLOB_IN_FILE_ON_DISK:
#ifdef __WIN32__
	case BLOB_IN_WINNT_FILE_ON_DISK:
	case BLOB_WIN32_ENCRYPTED:
#endif
#ifdef WITH_FUSE
	case BLOB_IN_STAGING_FILE:
		BUILD_BUG_ON((void*)&blob->file_on_disk !=
			     (void*)&blob->staging_file_name);
#endif
	case BLOB_IN_ATTACHED_BUFFER:
		BUILD_BUG_ON((void*)&blob->file_on_disk !=
			     (void*)&blob->attached_buffer);
		FREE(blob->file_on_disk);
		break;
#ifdef WITH_NTFS_3G
	case BLOB_IN_NTFS_VOLUME:
		if (blob->ntfs_loc) {
			FREE(blob->ntfs_loc->path);
			FREE(blob->ntfs_loc->attr_name);
			FREE(blob->ntfs_loc);
		}
		break;
#endif
	default:
		break;
	}
}

void
free_blob_descriptor(struct blob_descriptor *blob)
{
	if (blob) {
		blob_release_location(blob);
		FREE(blob);
	}
}

/* Should this blob be retained even if it has no references?  */
static bool
should_retain_blob(const struct blob_descriptor *blob)
{
	return blob->blob_location == BLOB_IN_WIM;
}

static void
finalize_blob(struct blob_descriptor *blob)
{
	if (!should_retain_blob(blob))
		free_blob_descriptor(blob);
}

/*
 * Decrements the reference count of the specified blob, which must be inserted
 * in the specified blob table.
 *
 * If the blob's reference count reaches 0, we may unlink it from @table and
 * free it.  However, we retain blobs with 0 reference count that originated
 * from WIM files (BLOB_IN_WIM).  We do this for two reasons:
 *
 * 1. This prevents information about valid blobs in a WIM file --- blobs which
 *    will continue to be present after appending to the WIM file --- from being
 *    lost merely because we dropped all references to them.
 *
 * 2. Blob reference counts we read from WIM files can't be trusted.  It's
 *    possible that a WIM has reference counts that are too low; WIMGAPI
 *    sometimes creates WIMs where this is the case.  It's also possible that
 *    blobs have been referenced from an external WIM; those blobs can
 *    potentially have any reference count at all, either lower or higher than
 *    would be expected for this WIM ("this WIM" meaning the owner of @table) if
 *    it were a standalone WIM.
 *
 * So we can't take the reference counts too seriously.  But at least, we do
 * recalculate by default when writing a new WIM file.
 */
void
blob_decrement_refcnt(struct blob_descriptor *blob, struct blob_table *table)
{
	if (unlikely(blob->refcnt == 0))  /* See comment above  */
		return;

	if (--blob->refcnt == 0) {
		if (blob->unhashed) {
			list_del(&blob->unhashed_list);
		#ifdef WITH_FUSE
			/* If the blob has been extracted to a staging file
			 * for a FUSE mount, unlink the staging file.  (Note
			 * that there still may be open file descriptors to it.)
			 * */
			if (blob->blob_location == BLOB_IN_STAGING_FILE)
				unlinkat(blob->staging_dir_fd,
					 blob->staging_file_name, 0);
		#endif
		} else {
			if (!should_retain_blob(blob))
				blob_table_unlink(table, blob);
		}

		/* If FUSE mounts are enabled, we don't actually free the blob
		 * until the last file descriptor has been closed by
		 * blob_decrement_num_opened_fds().  */
#ifdef WITH_FUSE
		if (blob->num_opened_fds == 0)
#endif
			finalize_blob(blob);
	}
}

#ifdef WITH_FUSE
void
blob_decrement_num_opened_fds(struct blob_descriptor *blob)
{
	wimlib_assert(blob->num_opened_fds != 0);

	if (--blob->num_opened_fds == 0 && blob->refcnt == 0)
		finalize_blob(blob);
}
#endif

static void
blob_table_insert_raw(struct blob_table *table, struct blob_descriptor *blob)
{
	size_t i = blob->hash_short % table->capacity;

	hlist_add_head(&blob->hash_list, &table->array[i]);
}

static void
enlarge_blob_table(struct blob_table *table)
{
	size_t old_capacity, new_capacity;
	struct hlist_head *old_array, *new_array;
	struct blob_descriptor *blob;
	struct hlist_node *cur, *tmp;
	size_t i;

	old_capacity = table->capacity;
	new_capacity = old_capacity * 2;
	new_array = CALLOC(new_capacity, sizeof(struct hlist_head));
	if (new_array == NULL)
		return;
	old_array = table->array;
	table->array = new_array;
	table->capacity = new_capacity;

	for (i = 0; i < old_capacity; i++) {
		hlist_for_each_entry_safe(blob, cur, tmp, &old_array[i], hash_list) {
			hlist_del(&blob->hash_list);
			blob_table_insert_raw(table, blob);
		}
	}
	FREE(old_array);
}

/* Insert a blob into the blob table.  */
void
blob_table_insert(struct blob_table *table, struct blob_descriptor *blob)
{
	blob_table_insert_raw(table, blob);
	if (++table->num_blobs > table->capacity)
		enlarge_blob_table(table);
}

/* Unlinks a blob from the blob table; does not free it.  */
void
blob_table_unlink(struct blob_table *table, struct blob_descriptor *blob)
{
	wimlib_assert(!blob->unhashed);
	wimlib_assert(table->num_blobs != 0);

	hlist_del(&blob->hash_list);
	table->num_blobs--;
}

/* Given a SHA-1 message digest, return the corresponding blob descriptor from
 * the specified blob table, or NULL if there is none.  */
struct blob_descriptor *
lookup_blob(const struct blob_table *table, const u8 *hash)
{
	size_t i;
	struct blob_descriptor *blob;
	struct hlist_node *pos;

	i = load_size_t_unaligned(hash) % table->capacity;
	hlist_for_each_entry(blob, pos, &table->array[i], hash_list)
		if (hashes_equal(hash, blob->hash))
			return blob;
	return NULL;
}

/* Call a function on all blob descriptors in the specified blob table.  Stop
 * early and return nonzero if any call to the function returns nonzero.  */
int
for_blob_in_table(struct blob_table *table,
		  int (*visitor)(struct blob_descriptor *, void *), void *arg)
{
	struct blob_descriptor *blob;
	struct hlist_node *pos, *tmp;
	int ret;

	for (size_t i = 0; i < table->capacity; i++) {
		hlist_for_each_entry_safe(blob, pos, tmp, &table->array[i],
					  hash_list)
		{
			ret = visitor(blob, arg);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/*
 * This is a qsort() callback that sorts blobs into an order optimized for
 * reading.  Sorting is done primarily by blob location, then secondarily by a
 * location-dependent order.  Most importantly, blobs in WIM files are sorted
 * such that the WIM files will be read sequentially.  This is especially
 * importont for WIM files containing solid resources.
 */
int
cmp_blobs_by_sequential_order(const void *p1, const void *p2)
{
	const struct blob_descriptor *blob1, *blob2;
	int v;
	WIMStruct *wim1, *wim2;

	blob1 = *(const struct blob_descriptor**)p1;
	blob2 = *(const struct blob_descriptor**)p2;

	v = (int)blob1->blob_location - (int)blob2->blob_location;

	/* Different resource locations?  */
	if (v)
		return v;

	switch (blob1->blob_location) {
	case BLOB_IN_WIM:
		wim1 = blob1->rdesc->wim;
		wim2 = blob2->rdesc->wim;

		/* Different (possibly split) WIMs?  */
		if (wim1 != wim2) {
			v = memcmp(wim1->hdr.guid, wim2->hdr.guid, WIM_GUID_LEN);
			if (v)
				return v;
		}

		/* Different part numbers in the same WIM?  */
		v = (int)wim1->hdr.part_number - (int)wim2->hdr.part_number;
		if (v)
			return v;

		if (blob1->rdesc->offset_in_wim != blob2->rdesc->offset_in_wim)
			return cmp_u64(blob1->rdesc->offset_in_wim,
				       blob2->rdesc->offset_in_wim);

		return cmp_u64(blob1->offset_in_res, blob2->offset_in_res);

	case BLOB_IN_FILE_ON_DISK:
#ifdef WITH_FUSE
	case BLOB_IN_STAGING_FILE:
#endif
#ifdef __WIN32__
	case BLOB_IN_WINNT_FILE_ON_DISK:
	case BLOB_WIN32_ENCRYPTED:
#endif
		/* Compare files by path: just a heuristic that will place files
		 * in the same directory next to each other.  */
		return tstrcmp(blob1->file_on_disk, blob2->file_on_disk);
#ifdef WITH_NTFS_3G
	case BLOB_IN_NTFS_VOLUME:
		return tstrcmp(blob1->ntfs_loc->path,
			       blob2->ntfs_loc->path);
#endif
	default:
		/* No additional sorting order defined for this resource
		 * location (e.g. BLOB_IN_ATTACHED_BUFFER); simply compare
		 * everything equal to each other.  */
		return 0;
	}
}

int
sort_blob_list(struct list_head *blob_list, size_t list_head_offset,
	       int (*compar)(const void *, const void*))
{
	struct list_head *cur;
	struct blob_descriptor **array;
	size_t i;
	size_t array_size;
	size_t num_blobs = 0;

	list_for_each(cur, blob_list)
		num_blobs++;

	if (num_blobs <= 1)
		return 0;

	array_size = num_blobs * sizeof(array[0]);
	array = MALLOC(array_size);
	if (array == NULL)
		return WIMLIB_ERR_NOMEM;

	cur = blob_list->next;
	for (i = 0; i < num_blobs; i++) {
		array[i] = (struct blob_descriptor*)((u8*)cur - list_head_offset);
		cur = cur->next;
	}

	qsort(array, num_blobs, sizeof(array[0]), compar);

	INIT_LIST_HEAD(blob_list);
	for (i = 0; i < num_blobs; i++) {
		list_add_tail((struct list_head*)
			       ((u8*)array[i] + list_head_offset),
			      blob_list);
	}
	FREE(array);
	return 0;
}

/* Sort the specified list of blobs in an order optimized for sequential
 * reading.  */
int
sort_blob_list_by_sequential_order(struct list_head *blob_list,
				   size_t list_head_offset)
{
	return sort_blob_list(blob_list, list_head_offset,
			      cmp_blobs_by_sequential_order);
}

static int
add_blob_to_array(struct blob_descriptor *blob, void *_pp)
{
	struct blob_descriptor ***pp = _pp;
	*(*pp)++ = blob;
	return 0;
}

/* Iterate through the blob descriptors in the specified blob table, but first
 * sort them in an order optimized for sequential reading.  */
int
for_blob_in_table_sorted_by_sequential_order(struct blob_table *table,
					     int (*visitor)(struct blob_descriptor *, void *),
					     void *arg)
{
	struct blob_descriptor **blob_array, **p;
	size_t num_blobs = table->num_blobs;
	int ret;

	blob_array = MALLOC(num_blobs * sizeof(blob_array[0]));
	if (!blob_array)
		return WIMLIB_ERR_NOMEM;
	p = blob_array;
	for_blob_in_table(table, add_blob_to_array, &p);

	wimlib_assert(p == blob_array + num_blobs);

	qsort(blob_array, num_blobs, sizeof(blob_array[0]),
	      cmp_blobs_by_sequential_order);
	ret = 0;
	for (size_t i = 0; i < num_blobs; i++) {
		ret = visitor(blob_array[i], arg);
		if (ret)
			break;
	}
	FREE(blob_array);
	return ret;
}

/* On-disk format of a blob descriptor in a WIM file  */
struct blob_descriptor_disk {

	/* Size, offset, and flags of the blob.  */
	struct wim_reshdr_disk reshdr;

	/* Which part of the split WIM this blob is in; indexed from 1. */
	le16 part_number;

	/* Reference count of this blob over all WIM images.  (But see comment
	 * above blob_decrement_refcnt().)  */
	le32 refcnt;

	/* SHA-1 message digest of the uncompressed data of this blob, or all
	 * zeroes if this blob is of zero length.  */
	u8 hash[SHA1_HASH_SIZE];
} _packed_attribute;

/* Given a nonempty run of consecutive blob descriptors with the SOLID flag set,
 * count how many specify resources (as opposed to blobs within those
 * resources).
 *
 * Returns the resulting count.  */
static size_t
count_solid_resources(const struct blob_descriptor_disk *entries, size_t max)
{
	size_t count = 0;
	do {
		struct wim_reshdr reshdr;

		get_wim_reshdr(&(entries++)->reshdr, &reshdr);

		if (!(reshdr.flags & WIM_RESHDR_FLAG_SOLID)) {
			/* Run was terminated by a stand-alone blob entry.  */
			break;
		}

		if (reshdr.uncompressed_size == SOLID_RESOURCE_MAGIC_NUMBER) {
			/* This is a resource entry.  */
			count++;
		}
	} while (--max);
	return count;
}

/*
 * Given a run of consecutive blob descriptors with the SOLID flag set and
 * having @num_rdescs resource entries, load resource information from them into
 * the resource specifications in the @rdescs array.
 *
 * Returns 0 on success, or a nonzero error code on failure.
 */
static int
do_load_solid_info(WIMStruct *wim, struct wim_resource_descriptor **rdescs,
		   size_t num_rdescs,
		   const struct blob_descriptor_disk *entries)
{
	for (size_t i = 0; i < num_rdescs; i++) {
		struct wim_reshdr reshdr;
		struct alt_chunk_table_header_disk hdr;
		struct wim_resource_descriptor *rdesc;
		int ret;

		/* Advance to next resource entry.  */

		do {
			get_wim_reshdr(&(entries++)->reshdr, &reshdr);
		} while (reshdr.uncompressed_size != SOLID_RESOURCE_MAGIC_NUMBER);

		rdesc = rdescs[i];

		wim_res_hdr_to_spec(&reshdr, wim, rdesc);

		/* For solid resources, the uncompressed size, compression type,
		 * and chunk size are stored in the resource itself, not in the
		 * blob table.  */

		ret = full_pread(&wim->in_fd, &hdr,
				 sizeof(hdr), reshdr.offset_in_wim);
		if (ret) {
			ERROR("Failed to read header of solid resource "
			      "(offset_in_wim=%"PRIu64")",
			      reshdr.offset_in_wim);
			return ret;
		}

		rdesc->uncompressed_size = le64_to_cpu(hdr.res_usize);

		/* Compression format numbers must be the same as in
		 * WIMGAPI to be compatible here.  */
		BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_NONE != 0);
		BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_XPRESS != 1);
		BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_LZX != 2);
		BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_LZMS != 3);
		rdesc->compression_type = le32_to_cpu(hdr.compression_format);

		rdesc->chunk_size = le32_to_cpu(hdr.chunk_size);

		DEBUG("Solid resource %zu/%zu: %"PRIu64" => %"PRIu64" "
		      "(%"TS"/%"PRIu32") @ +%"PRIu64"",
		      i + 1, num_rdescs,
		      rdesc->uncompressed_size,
		      rdesc->size_in_wim,
		      wimlib_get_compression_type_string(rdesc->compression_type),
		      rdesc->chunk_size,
		      rdesc->offset_in_wim);

	}
	return 0;
}

/*
 * Given a nonempty run of consecutive blob descriptors with the SOLID flag set,
 * allocate a 'struct wim_resource_descriptor' for each resource within that run.
 *
 * Returns 0 on success, or a nonzero error code on failure.
 * Returns the pointers and count in *rdescs_ret and *num_rdescs_ret.
 */
static int
load_solid_info(WIMStruct *wim,
		const struct blob_descriptor_disk *entries,
		size_t num_remaining_entries,
		struct wim_resource_descriptor ***rdescs_ret,
		size_t *num_rdescs_ret)
{
	size_t num_rdescs;
	struct wim_resource_descriptor **rdescs;
	size_t i;
	int ret;

	num_rdescs = count_solid_resources(entries, num_remaining_entries);
	rdescs = CALLOC(num_rdescs, sizeof(rdescs[0]));
	if (!rdescs)
		return WIMLIB_ERR_NOMEM;

	for (i = 0; i < num_rdescs; i++) {
		rdescs[i] = MALLOC(sizeof(struct wim_resource_descriptor));
		if (!rdescs[i]) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_rdescs;
		}
	}

	ret = do_load_solid_info(wim, rdescs, num_rdescs, entries);
	if (ret)
		goto out_free_rdescs;

	*rdescs_ret = rdescs;
	*num_rdescs_ret = num_rdescs;
	return 0;

out_free_rdescs:
	for (i = 0; i < num_rdescs; i++)
		FREE(rdescs[i]);
	FREE(rdescs);
	return ret;
}

/* Given a 'struct blob_descriptor' allocated for an on-disk blob descriptor
 * with the SOLID flag set, try to bind it to resource in the current solid run.
 */
static int
bind_blob_to_solid_resource(const struct wim_reshdr *reshdr,
			    struct blob_descriptor *blob,
			    struct wim_resource_descriptor **rdescs,
			    size_t num_rdescs)
{
	u64 offset = reshdr->offset_in_wim;

	/* XXX: This linear search will be slow in the degenerate case where the
	 * number of solid resources in the run is huge.  */
	blob->size = reshdr->size_in_wim;
	blob->flags = reshdr->flags;
	for (size_t i = 0; i < num_rdescs; i++) {
		if (offset + blob->size <= rdescs[i]->uncompressed_size) {
			blob->offset_in_res = offset;
			blob_set_is_located_in_wim_resource(blob, rdescs[i]);
			return 0;
		}
		offset -= rdescs[i]->uncompressed_size;
	}
	ERROR("blob could not be assigned to a solid resource");
	return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
}

static void
free_solid_rdescs(struct wim_resource_descriptor **rdescs, size_t num_rdescs)
{
	if (rdescs) {
		for (size_t i = 0; i < num_rdescs; i++)
			if (list_empty(&rdescs[i]->blob_list))
				FREE(rdescs[i]);
		FREE(rdescs);
	}
}

static int
cmp_blobs_by_offset_in_res(const void *p1, const void *p2)
{
	const struct blob_descriptor *blob1, *blob2;

	blob1 = *(const struct blob_descriptor**)p1;
	blob2 = *(const struct blob_descriptor**)p2;

	return cmp_u64(blob1->offset_in_res, blob2->offset_in_res);
}

/* Validate the size and location of a WIM resource.  */
static int
validate_resource(struct wim_resource_descriptor *rdesc)
{
	struct blob_descriptor *blob;
	bool out_of_order;
	u64 expected_next_offset;
	int ret;

	/* Verify that the resource itself has a valid offset and size.  */
	if (rdesc->offset_in_wim + rdesc->size_in_wim < rdesc->size_in_wim)
		goto invalid_due_to_overflow;

	/* Verify that each blob in the resource has a valid offset and size.
	 */
	expected_next_offset = 0;
	out_of_order = false;
	list_for_each_entry(blob, &rdesc->blob_list, rdesc_node) {
		if (blob->offset_in_res + blob->size < blob->size ||
		    blob->offset_in_res + blob->size > rdesc->uncompressed_size)
			goto invalid_due_to_overflow;

		if (blob->offset_in_res >= expected_next_offset)
			expected_next_offset = blob->offset_in_res + blob->size;
		else
			out_of_order = true;
	}

	/* If the blobs were not located at strictly increasing positions (not
	 * allowing for overlap), sort them.  Then make sure that none overlap.
	 */
	if (out_of_order) {
		ret = sort_blob_list(&rdesc->blob_list,
				       offsetof(struct blob_descriptor,
						rdesc_node),
				       cmp_blobs_by_offset_in_res);
		if (ret)
			return ret;

		expected_next_offset = 0;
		list_for_each_entry(blob, &rdesc->blob_list, rdesc_node) {
			if (blob->offset_in_res >= expected_next_offset)
				expected_next_offset = blob->offset_in_res + blob->size;
			else
				goto invalid_due_to_overlap;
		}
	}

	return 0;

invalid_due_to_overflow:
	ERROR("Invalid blob table (offset overflow)");
	return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;

invalid_due_to_overlap:
	ERROR("Invalid blob table (blobs in solid resource overlap)");
	return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
}

static int
finish_solid_rdescs(struct wim_resource_descriptor **rdescs, size_t num_rdescs)
{
	int ret = 0;
	for (size_t i = 0; i < num_rdescs; i++) {
		ret = validate_resource(rdescs[i]);
		if (ret)
			break;
	}
	free_solid_rdescs(rdescs, num_rdescs);
	return ret;
}

/*
 * Reads the blob table from a WIM file.  Usually, each entry in this table
 * specifies a blob that the WIM file contains, along with its location and
 * SHA-1 message digest.
 *
 * Descriptors for non-metadata blobs will be saved in the in-memory blob table
 * (wim->blob_table), whereas descriptors for metadata blobs will be saved in a
 * special location per-image (the wim->image_metadata array).
 *
 * This works for both version WIM_VERSION_DEFAULT (68864) and version
 * WIM_VERSION_SOLID (3584) WIMs.  In the latter, a consecutive run of blob
 * descriptors that all have flag WIM_RESHDR_FLAG_SOLID (0x10) set is a "solid
 * run".  A solid run logically contains zero or more resources, each of which
 * logically contains zero or more blobs.  Physically, in such a run, a "blob
 * descriptor" with uncompressed size SOLID_RESOURCE_MAGIC_NUMBER (0x100000000)
 * specifies a resource, whereas any other blob descriptor actually does specify
 * a blob.  Within such a run, real blob descriptors and resource entries need
 * not be in any particular order, except that the order of the resource entries
 * is important, as it affects how blobs are assigned to resources.  See the
 * code for details.
 *
 * Possible return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY
 *	WIMLIB_ERR_NOMEM
 *
 *	Or an error code caused by failure to read the blob table from the WIM
 *	file.
 */
int
read_blob_table(WIMStruct *wim)
{
	int ret;
	size_t num_entries;
	void *buf = NULL;
	struct blob_table *table = NULL;
	struct blob_descriptor *cur_entry = NULL;
	size_t num_duplicate_blobs = 0;
	size_t num_wrong_part_blobs = 0;
	u32 image_index = 0;
	struct wim_resource_descriptor **cur_solid_rdescs = NULL;
	size_t cur_num_solid_rdescs = 0;

	DEBUG("Reading blob table.");

	/* Calculate the number of entries in the blob table.  */
	num_entries = wim->hdr.blob_table_reshdr.uncompressed_size /
		      sizeof(struct blob_descriptor_disk);

	/* Read the blob table into a buffer.  */
	ret = wim_reshdr_to_data(&wim->hdr.blob_table_reshdr, wim, &buf);
	if (ret)
		goto out;

	/* Allocate a hash table to map SHA-1 message digests into blob
	 * specifications.  This is the in-memory "blob table".  */
	table = new_blob_table(num_entries * 2 + 1);
	if (!table)
		goto oom;

	/* Allocate and initalize blob descriptors from the raw blob table
	 * buffer.  */
	for (size_t i = 0; i < num_entries; i++) {
		const struct blob_descriptor_disk *disk_entry =
			&((const struct blob_descriptor_disk*)buf)[i];
		struct wim_reshdr reshdr;
		u16 part_number;

		/* Get the resource header  */
		get_wim_reshdr(&disk_entry->reshdr, &reshdr);

		DEBUG("reshdr: size_in_wim=%"PRIu64", "
		      "uncompressed_size=%"PRIu64", "
		      "offset_in_wim=%"PRIu64", "
		      "flags=0x%02x",
		      reshdr.size_in_wim, reshdr.uncompressed_size,
		      reshdr.offset_in_wim, reshdr.flags);

		/* Ignore SOLID flag if it isn't supposed to be used in this WIM
		 * version.  */
		if (wim->hdr.wim_version == WIM_VERSION_DEFAULT)
			reshdr.flags &= ~WIM_RESHDR_FLAG_SOLID;

		/* Allocate a new 'struct blob_descriptor'.  */
		cur_entry = new_blob_descriptor();
		if (!cur_entry)
			goto oom;

		/* Get the part number, reference count, and hash.  */
		part_number = le16_to_cpu(disk_entry->part_number);
		cur_entry->refcnt = le32_to_cpu(disk_entry->refcnt);
		copy_hash(cur_entry->hash, disk_entry->hash);

		if (reshdr.flags & WIM_RESHDR_FLAG_SOLID) {

			/* SOLID entry  */

			if (!cur_solid_rdescs) {
				/* Starting new run  */
				ret = load_solid_info(wim, disk_entry,
						      num_entries - i,
						      &cur_solid_rdescs,
						      &cur_num_solid_rdescs);
				if (ret)
					goto out;
			}

			if (reshdr.uncompressed_size == SOLID_RESOURCE_MAGIC_NUMBER) {
				/* Resource entry, not blob entry  */
				goto free_cur_entry_and_continue;
			}

			/* Blob entry  */

			ret = bind_blob_to_solid_resource(&reshdr,
							  cur_entry,
							  cur_solid_rdescs,
							  cur_num_solid_rdescs);
			if (ret)
				goto out;

		} else {
			/* Normal blob/resource entry; SOLID not set.  */

			struct wim_resource_descriptor *rdesc;

			if (unlikely(cur_solid_rdescs)) {
				/* This entry terminated a solid run.  */
				ret = finish_solid_rdescs(cur_solid_rdescs,
							  cur_num_solid_rdescs);
				cur_solid_rdescs = NULL;
				if (ret)
					goto out;
			}

			/* How to handle an uncompressed resource with its
			 * uncompressed size different from its compressed size?
			 *
			 * Based on a simple test, WIMGAPI seems to handle this
			 * as follows:
			 *
			 * if (size_in_wim > uncompressed_size) {
			 *	Ignore uncompressed_size; use size_in_wim
			 *	instead.
			 * } else {
			 *	Honor uncompressed_size, but treat the part of
			 *	the file data above size_in_wim as all zeros.
			 * }
			 *
			 * So we will do the same.  */
			if (unlikely(!(reshdr.flags &
				       WIM_RESHDR_FLAG_COMPRESSED) &&
				     (reshdr.size_in_wim >
				      reshdr.uncompressed_size)))
			{
				reshdr.uncompressed_size = reshdr.size_in_wim;
			}

			/* Set up a resource specification for this blob.  */

			rdesc = MALLOC(sizeof(struct wim_resource_descriptor));
			if (!rdesc)
				goto oom;

			wim_res_hdr_to_spec(&reshdr, wim, rdesc);

			cur_entry->offset_in_res = 0;
			cur_entry->size = reshdr.uncompressed_size;
			cur_entry->flags = reshdr.flags;

			blob_set_is_located_in_wim_resource(cur_entry, rdesc);
		}

		/* cur_entry is now a blob bound to a resource.  */

		/* Ignore entries with all zeroes in the hash field.  */
		if (is_zero_hash(cur_entry->hash))
			goto free_cur_entry_and_continue;

		/* Verify that the part number matches that of the underlying
		 * WIM file.  */
		if (part_number != wim->hdr.part_number) {
			num_wrong_part_blobs++;
			goto free_cur_entry_and_continue;
		}

		if (reshdr.flags & WIM_RESHDR_FLAG_METADATA) {

			/* Blob table entry for a metadata resource.  */

			/* Metadata entries with no references must be ignored.
			 * See, for example, the WinPE WIMs from the WAIK v2.1.
			 */
			if (cur_entry->refcnt == 0)
				goto free_cur_entry_and_continue;

			if (cur_entry->refcnt != 1) {
				/* We don't currently support this case due to
				 * the complications of multiple images sharing
				 * the same metadata resource or a metadata
				 * resource also being referenced by files.  */
				ERROR("Found metadata resource with refcnt != 1");
				ret = WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;
				goto out;
			}

			if (wim->hdr.part_number != 1) {
				WARNING("Ignoring metadata resource found in a "
					"non-first part of the split WIM");
				goto free_cur_entry_and_continue;
			}

			/* The number of entries in the blob table with
			 * WIM_RESHDR_FLAG_METADATA set should be the same as
			 * the image_count field in the WIM header.  */
			if (image_index == wim->hdr.image_count) {
				WARNING("Found more metadata resources than images");
				goto free_cur_entry_and_continue;
			}

			/* Notice very carefully:  We are assigning the metadata
			 * resources to images in the same order in which their
			 * blob table entries occur on disk.  (This is also the
			 * behavior of Microsoft's software.)  In particular,
			 * this overrides the actual locations of the metadata
			 * resources themselves in the WIM file as well as any
			 * information written in the XML data.  */
			DEBUG("Found metadata resource for image %"PRIu32" at "
			      "offset %"PRIu64".",
			      image_index + 1,
			      reshdr.offset_in_wim);

			wim->image_metadata[image_index++]->metadata_blob = cur_entry;
		} else {
			/* Blob table entry for a non-metadata blob.  */

			/* Ignore this blob if it's a duplicate.  */
			if (lookup_blob(table, cur_entry->hash)) {
				num_duplicate_blobs++;
				goto free_cur_entry_and_continue;
			}

			/* Insert the blob into the in-memory blob table, keyed
			 * by its SHA-1 message digest.  */
			blob_table_insert(table, cur_entry);
		}

		continue;

	free_cur_entry_and_continue:
		if (cur_solid_rdescs &&
		    cur_entry->blob_location == BLOB_IN_WIM)
			blob_unset_is_located_in_wim_resource(cur_entry);
		free_blob_descriptor(cur_entry);
	}
	cur_entry = NULL;

	if (cur_solid_rdescs) {
		/* End of blob table terminated a solid run.  */
		ret = finish_solid_rdescs(cur_solid_rdescs, cur_num_solid_rdescs);
		cur_solid_rdescs = NULL;
		if (ret)
			goto out;
	}

	if (wim->hdr.part_number == 1 && image_index != wim->hdr.image_count) {
		WARNING("Could not find metadata resources for all images");
		for (u32 i = image_index; i < wim->hdr.image_count; i++)
			put_image_metadata(wim->image_metadata[i], NULL);
		wim->hdr.image_count = image_index;
	}

	if (num_duplicate_blobs > 0)
		WARNING("Ignoring %zu duplicate blobs", num_duplicate_blobs);

	if (num_wrong_part_blobs > 0) {
		WARNING("Ignoring %zu blobs with wrong part number",
			num_wrong_part_blobs);
	}

	DEBUG("Done reading blob table.");
	wim->blob_table = table;
	ret = 0;
	goto out_free_buf;

oom:
	ERROR("Not enough memory to read blob table!");
	ret = WIMLIB_ERR_NOMEM;
out:
	free_solid_rdescs(cur_solid_rdescs, cur_num_solid_rdescs);
	free_blob_descriptor(cur_entry);
	free_blob_table(table);
out_free_buf:
	FREE(buf);
	return ret;
}

static void
write_blob_descriptor(struct blob_descriptor_disk *disk_entry,
		      const struct wim_reshdr *out_reshdr,
		      u16 part_number, u32 refcnt, const u8 *hash)
{
	put_wim_reshdr(out_reshdr, &disk_entry->reshdr);
	disk_entry->part_number = cpu_to_le16(part_number);
	disk_entry->refcnt = cpu_to_le32(refcnt);
	copy_hash(disk_entry->hash, hash);
}

/* Note: the list of blob descriptors must be sorted so that all entries for the
 * same solid resource are consecutive.  In addition, blob descriptors with
 * WIM_RESHDR_FLAG_METADATA set must be in the same order as the indices of the
 * underlying images.  */
int
write_blob_table_from_blob_list(struct list_head *blob_list,
				struct filedes *out_fd,
				u16 part_number,
				struct wim_reshdr *out_reshdr,
				int write_resource_flags)
{
	size_t table_size;
	struct blob_descriptor *blob;
	struct blob_descriptor_disk *table_buf;
	struct blob_descriptor_disk *table_buf_ptr;
	int ret;
	u64 prev_res_offset_in_wim = ~0ULL;
	u64 prev_uncompressed_size;
	u64 logical_offset;

	table_size = 0;
	list_for_each_entry(blob, blob_list, blob_table_list) {
		table_size += sizeof(struct blob_descriptor_disk);

		if (blob->out_reshdr.flags & WIM_RESHDR_FLAG_SOLID &&
		    blob->out_res_offset_in_wim != prev_res_offset_in_wim)
		{
			table_size += sizeof(struct blob_descriptor_disk);
			prev_res_offset_in_wim = blob->out_res_offset_in_wim;
		}
	}

	DEBUG("Writing WIM blob table (size=%zu, offset=%"PRIu64")",
	      table_size, out_fd->offset);

	table_buf = MALLOC(table_size);
	if (table_buf == NULL) {
		ERROR("Failed to allocate %zu bytes for temporary blob table",
		      table_size);
		return WIMLIB_ERR_NOMEM;
	}
	table_buf_ptr = table_buf;

	prev_res_offset_in_wim = ~0ULL;
	prev_uncompressed_size = 0;
	logical_offset = 0;
	list_for_each_entry(blob, blob_list, blob_table_list) {
		if (blob->out_reshdr.flags & WIM_RESHDR_FLAG_SOLID) {
			struct wim_reshdr tmp_reshdr;

			/* Eww.  When WIMGAPI sees multiple solid resources, it
			 * expects the offsets to be adjusted as if there were
			 * really only one solid resource.  */

			if (blob->out_res_offset_in_wim != prev_res_offset_in_wim) {
				/* Put the resource entry for solid resource  */
				tmp_reshdr.offset_in_wim = blob->out_res_offset_in_wim;
				tmp_reshdr.size_in_wim = blob->out_res_size_in_wim;
				tmp_reshdr.uncompressed_size = SOLID_RESOURCE_MAGIC_NUMBER;
				tmp_reshdr.flags = WIM_RESHDR_FLAG_SOLID;

				write_blob_descriptor(table_buf_ptr++, &tmp_reshdr,
						      part_number, 1, zero_hash);

				logical_offset += prev_uncompressed_size;

				prev_res_offset_in_wim = blob->out_res_offset_in_wim;
				prev_uncompressed_size = blob->out_res_uncompressed_size;
			}
			tmp_reshdr = blob->out_reshdr;
			tmp_reshdr.offset_in_wim += logical_offset;
			write_blob_descriptor(table_buf_ptr++, &tmp_reshdr,
					      part_number, blob->out_refcnt, blob->hash);
		} else {
			write_blob_descriptor(table_buf_ptr++, &blob->out_reshdr,
					      part_number, blob->out_refcnt, blob->hash);
		}

	}
	wimlib_assert((u8*)table_buf_ptr - (u8*)table_buf == table_size);

	/* Write the blob table uncompressed.  Although wimlib can handle a
	 * compressed blob table, MS software cannot.  */
	ret = write_wim_resource_from_buffer(table_buf,
					     table_size,
					     WIM_RESHDR_FLAG_METADATA,
					     out_fd,
					     WIMLIB_COMPRESSION_TYPE_NONE,
					     0,
					     out_reshdr,
					     NULL,
					     write_resource_flags);
	FREE(table_buf);
	DEBUG("ret=%d", ret);
	return ret;
}

/* Allocate a blob descriptor for the contents of the buffer, or re-use an
 * existing descriptor in @blob_table for an identical blob.  */
struct blob_descriptor *
new_blob_from_data_buffer(const void *buffer, size_t size,
			  struct blob_table *blob_table)
{
	u8 hash[SHA1_HASH_SIZE];
	struct blob_descriptor *blob, *existing_blob;

	sha1_buffer(buffer, size, hash);
	existing_blob = lookup_blob(blob_table, hash);
	if (existing_blob) {
		wimlib_assert(existing_blob->size == size);
		blob = existing_blob;
		blob->refcnt++;
	} else {
		void *buffer_copy;
		blob = new_blob_descriptor();
		if (blob == NULL)
			return NULL;
		buffer_copy = memdup(buffer, size);
		if (buffer_copy == NULL) {
			free_blob_descriptor(blob);
			return NULL;
		}
		blob->blob_location = BLOB_IN_ATTACHED_BUFFER;
		blob->attached_buffer = buffer_copy;
		blob->size = size;
		copy_hash(blob->hash, hash);
		blob_table_insert(blob_table, blob);
	}
	return blob;
}

/*
 * Calculate the SHA-1 message digest of a blob and move its descriptor from the
 * list of unhashed blobs to the blob table, possibly joining it with an
 * identical blob.
 *
 * @blob:
 *	An unhashed blob.
 * @blob_table:
 *	The blob table.
 * @blob_ret:
 *	On success, write a pointer to the resulting blob descriptor to this
 *	location.  This will be the same as @blob if it was inserted into the
 *	blob table, or different if a duplicate blob was found.
 *
 * Returns 0 on success; nonzero if there is an error reading the blob data.
 */
int
hash_unhashed_blob(struct blob_descriptor *blob, struct blob_table *blob_table,
		   struct blob_descriptor **blob_ret)
{
	int ret;
	struct blob_descriptor *duplicate_blob;
	struct blob_descriptor **back_ptr;

	wimlib_assert(blob->unhashed);

	/* back_ptr must be saved because @back_inode and @back_attr_id are in
	 * union with the SHA-1 message digest and will no longer be valid once
	 * the SHA-1 has been calculated. */
	back_ptr = retrieve_blob_pointer(blob);

	ret = sha1_blob(blob);
	if (ret)
		return ret;

	/* Look for a duplicate blob  */
	duplicate_blob = lookup_blob(blob_table, blob->hash);
	list_del(&blob->unhashed_list);
	if (duplicate_blob) {
		/* We have a duplicate blob.  Transfer the reference counts from
		 * this blob to the duplicate and update the reference to this
		 * blob (from an attribute) to point to the duplicate.  The
		 * caller is responsible for freeing @blob if needed.  */
		wimlib_assert(!(duplicate_blob->unhashed));
		wimlib_assert(duplicate_blob->size == blob->size);
		duplicate_blob->refcnt += blob->refcnt;
		blob->refcnt = 0;
		*back_ptr = duplicate_blob;
		blob = duplicate_blob;
	} else {
		/* No duplicate blob, so we need to insert this blob into the
		 * blob table and treat it as a hashed blob. */
		blob_table_insert(blob_table, blob);
		blob->unhashed = 0;
	}
	*blob_ret = blob;
	return 0;
}

void
blob_to_wimlib_resource_entry(const struct blob_descriptor *blob,
			      struct wimlib_resource_entry *wentry)
{
	memset(wentry, 0, sizeof(*wentry));

	wentry->uncompressed_size = blob->size;
	if (blob->blob_location == BLOB_IN_WIM) {
		wentry->part_number = blob->rdesc->wim->hdr.part_number;
		if (blob->flags & WIM_RESHDR_FLAG_SOLID) {
			wentry->compressed_size = 0;
			wentry->offset = blob->offset_in_res;
		} else {
			wentry->compressed_size = blob->rdesc->size_in_wim;
			wentry->offset = blob->rdesc->offset_in_wim;
		}
		wentry->raw_resource_offset_in_wim = blob->rdesc->offset_in_wim;
		/*wentry->raw_resource_uncompressed_size = blob->rdesc->uncompressed_size;*/
		wentry->raw_resource_compressed_size = blob->rdesc->size_in_wim;
	}
	copy_hash(wentry->sha1_hash, blob->hash);
	wentry->reference_count = blob->refcnt;
	wentry->is_compressed = (blob->flags & WIM_RESHDR_FLAG_COMPRESSED) != 0;
	wentry->is_metadata = (blob->flags & WIM_RESHDR_FLAG_METADATA) != 0;
	wentry->is_free = (blob->flags & WIM_RESHDR_FLAG_FREE) != 0;
	wentry->is_spanned = (blob->flags & WIM_RESHDR_FLAG_SPANNED) != 0;
	wentry->packed = (blob->flags & WIM_RESHDR_FLAG_SOLID) != 0;
}

struct iterate_blob_context {
	wimlib_iterate_lookup_table_callback_t cb;
	void *user_ctx;
};

static int
do_iterate_blob(struct blob_descriptor *blob, void *_ctx)
{
	struct iterate_blob_context *ctx = _ctx;
	struct wimlib_resource_entry entry;

	blob_to_wimlib_resource_entry(blob, &entry);
	return (*ctx->cb)(&entry, ctx->user_ctx);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_iterate_lookup_table(WIMStruct *wim, int flags,
			    wimlib_iterate_lookup_table_callback_t cb,
			    void *user_ctx)
{
	if (flags != 0)
		return WIMLIB_ERR_INVALID_PARAM;

	struct iterate_blob_context ctx = {
		.cb = cb,
		.user_ctx = user_ctx,
	};
	if (wim_has_metadata(wim)) {
		int ret;
		for (int i = 0; i < wim->hdr.image_count; i++) {
			ret = do_iterate_blob(wim->image_metadata[i]->metadata_blob,
					      &ctx);
			if (ret)
				return ret;
		}
	}
	return for_blob_in_table(wim->blob_table, do_iterate_blob, &ctx);
}
