/*
 * metadata_resource.c
 */

/*
 * Copyright (C) 2012, 2013 Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "wimlib_internal.h"
#include "dentry.h"
#include "lookup_table.h"

/*
 * Reads the metadata metadata resource from the WIM file.  The metadata
 * resource consists of the security data, followed by the directory entry for
 * the root directory, followed by all the other directory entries in the
 * filesystem.  The subdir_offset field of each directory entry gives the start
 * of its child entries from the beginning of the metadata resource.  An
 * end-of-directory is signaled by a directory entry of length '0', really of
 * length 8, because that's how long the 'length' field is.
 *
 * @fp:		The FILE* for the input WIM file.
 * @wim_ctype:	The compression type of the WIM file.
 * @imd:	Pointer to the image metadata structure.  Its `metadata_lte'
 * 		member specifies the lookup table entry for the metadata
 * 		resource.  The rest of the image metadata entry will be filled
 * 		in by this function.
 *
 * @return:	Zero on success, nonzero on failure.
 */
int read_metadata_resource(WIMStruct *w, struct wim_image_metadata *imd)
{
	u8 *buf;
	u32 dentry_offset;
	int ret;
	struct wim_dentry *dentry;
	const struct wim_lookup_table_entry *metadata_lte;
	u64 metadata_len;
	struct hlist_head inode_list;

	metadata_lte = imd->metadata_lte;
	metadata_len = wim_resource_size(metadata_lte);

	DEBUG("Reading metadata resource: length = %"PRIu64", "
	      "offset = %"PRIu64"", metadata_len,
	      metadata_lte->resource_entry.offset);

	/* There is no way the metadata resource could possibly be less than (8
	 * + WIM_DENTRY_DISK_SIZE) bytes, where the 8 is for security data (with
	 * no security descriptors) and WIM_DENTRY_DISK_SIZE is for the root
	 * dentry. */
	if (metadata_len < 8 + WIM_DENTRY_DISK_SIZE) {
		ERROR("Expected at least %u bytes for the metadata resource",
		      8 + WIM_DENTRY_DISK_SIZE);
		return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
	}

	if (sizeof(size_t) < 8 && metadata_len > 0xffffffff) {
		ERROR("Metadata resource is too large (%"PRIu64" bytes",
		      metadata_len);
		return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
	}

	/* Allocate memory for the uncompressed metadata resource. */
	buf = MALLOC(metadata_len);

	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for uncompressed "
		      "metadata resource", metadata_len);
		return WIMLIB_ERR_NOMEM;
	}

	/* Read the metadata resource into memory.  (It may be compressed.) */
	ret = read_full_wim_resource(metadata_lte, buf, 0);
	if (ret != 0)
		goto out_free_buf;

	DEBUG("Finished reading metadata resource into memory.");

	/* The root directory entry starts after security data, aligned on an
	 * 8-byte boundary within the metadata resource.
	 *
	 * The security data starts with a 4-byte integer giving its total
	 * length, so if we round that up to an 8-byte boundary that gives us
	 * the offset of the root dentry.
	 *
	 * Here we read the security data into a wim_security_data structure,
	 * and if successful, go ahead and calculate the offset in the metadata
	 * resource of the root dentry. */

	wimlib_assert(imd->security_data == NULL);
	ret = read_security_data(buf, metadata_len, &imd->security_data);
	if (ret != 0)
		goto out_free_buf;

	dentry_offset = (imd->security_data->total_length + 7) & ~7;

	if (dentry_offset == 0) {
		ERROR("Integer overflow while reading metadata resource");
		ret = WIMLIB_ERR_INVALID_SECURITY_DATA;
		goto out_free_security_data;
	}

	DEBUG("Reading root dentry");

	/* Allocate memory for the root dentry and read it into memory */
	dentry = MALLOC(sizeof(struct wim_dentry));
	if (!dentry) {
		ERROR("Failed to allocate %zu bytes for root dentry",
		      sizeof(struct wim_dentry));
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_security_data;
	}

	ret = read_dentry(buf, metadata_len, dentry_offset, dentry);

	/* This is the root dentry, so set its parent to itself. */
	dentry->parent = dentry;

	if (ret == 0 && dentry->length == 0) {
		ERROR("Metadata resource cannot begin with end-of-directory entry!");
		ret = WIMLIB_ERR_INVALID_DENTRY;
	}

	if (ret != 0) {
		FREE(dentry);
		goto out_free_security_data;
	}

	inode_add_dentry(dentry, dentry->d_inode);

	/* Now read the entire directory entry tree into memory. */
	DEBUG("Reading dentry tree");
	ret = read_dentry_tree(buf, metadata_len, dentry);
	if (ret != 0)
		goto out_free_dentry_tree;

	/* Calculate the full paths in the dentry tree. */
	DEBUG("Calculating dentry full paths");
	ret = for_dentry_in_tree(dentry, calculate_dentry_full_path, NULL);
	if (ret != 0)
		goto out_free_dentry_tree;

	/* Build hash table that maps hard link group IDs to dentry sets */
	ret = dentry_tree_fix_inodes(dentry, &inode_list);
	if (ret != 0)
		goto out_free_dentry_tree;

	if (!w->all_images_verified) {
		DEBUG("Running miscellaneous verifications on the dentry tree");
		for_lookup_table_entry(w->lookup_table, lte_zero_real_refcnt, NULL);
		ret = for_dentry_in_tree(dentry, verify_dentry, w);
		if (ret != 0)
			goto out_free_dentry_tree;
	}

	DEBUG("Done reading image metadata");

	imd->root_dentry = dentry;
	imd->inode_list  = inode_list;
	if (imd->inode_list.first)
		imd->inode_list.first->pprev = &imd->inode_list.first;
	goto out_free_buf;
out_free_dentry_tree:
	free_dentry_tree(dentry, NULL);
out_free_security_data:
	free_security_data(imd->security_data);
	imd->security_data = NULL;
out_free_buf:
	FREE(buf);
	return ret;
}

static void recalculate_security_data_length(struct wim_security_data *sd)
{
	u32 total_length = sizeof(u64) * sd->num_entries + 2 * sizeof(u32);
	for (u32 i = 0; i < sd->num_entries; i++)
		total_length += sd->sizes[i];
	sd->total_length = total_length;
}

/* Like write_wim_resource(), but the resource is specified by a buffer of
 * uncompressed data rather a lookup table entry; also writes the SHA1 hash of
 * the buffer to @hash.  */
static int write_wim_resource_from_buffer(const u8 *buf, u64 buf_size,
					  FILE *out_fp, int out_ctype,
					  struct resource_entry *out_res_entry,
					  u8 hash[SHA1_HASH_SIZE])
{
	/* Set up a temporary lookup table entry to provide to
	 * write_wim_resource(). */
	struct wim_lookup_table_entry lte;
	int ret;
	lte.resource_entry.flags         = 0;
	lte.resource_entry.original_size = buf_size;
	lte.resource_entry.size          = buf_size;
	lte.resource_entry.offset        = 0;
	lte.resource_location            = RESOURCE_IN_ATTACHED_BUFFER;
	lte.attached_buffer              = (u8*)buf;

	zero_out_hash(lte.hash);
	ret = write_wim_resource(&lte, out_fp, out_ctype, out_res_entry, 0);
	if (ret != 0)
		return ret;
	copy_hash(hash, lte.hash);
	return 0;
}

/* Write the metadata resource for the current WIM image. */
int write_metadata_resource(WIMStruct *w)
{
	u8 *buf;
	u8 *p;
	int ret;
	u64 subdir_offset;
	struct wim_dentry *root;
	struct wim_lookup_table_entry *lte;
	u64 metadata_original_size;
	struct wim_security_data *sd;

	DEBUG("Writing metadata resource for image %d (offset = %"PRIu64")",
	      w->current_image, ftello(w->out_fp));

	root = wim_root_dentry(w);
	sd = wim_security_data(w);

	/* Offset of first child of the root dentry.  It's equal to:
	 * - The total length of the security data, rounded to the next 8-byte
	 *   boundary,
	 * - plus the total length of the root dentry,
	 * - plus 8 bytes for an end-of-directory entry following the root
	 *   dentry (shouldn't really be needed, but just in case...)
	 */
	recalculate_security_data_length(sd);
	subdir_offset = (((u64)sd->total_length + 7) & ~7) +
			dentry_correct_total_length(root) + 8;

	/* Calculate the subdirectory offsets for the entire dentry tree. */
	calculate_subdir_offsets(root, &subdir_offset);

	/* Total length of the metadata resource (uncompressed) */
	metadata_original_size = subdir_offset;

	/* Allocate a buffer to contain the uncompressed metadata resource */
	buf = MALLOC(metadata_original_size);
	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for "
		      "metadata resource", metadata_original_size);
		return WIMLIB_ERR_NOMEM;
	}

	/* Write the security data into the resource buffer */
	p = write_security_data(sd, buf);

	/* Write the dentry tree into the resource buffer */
	p = write_dentry_tree(root, p);

	/* We MUST have exactly filled the buffer; otherwise we calculated its
	 * size incorrectly or wrote the data incorrectly. */
	wimlib_assert(p - buf == metadata_original_size);

	/* Get the lookup table entry for the metadata resource so we can update
	 * it. */
	lte = w->image_metadata[w->current_image - 1].metadata_lte;

	/* Write the metadata resource to the output WIM using the proper
	 * compression type.  The lookup table entry for the metadata resource
	 * is updated. */
	ret = write_wim_resource_from_buffer(buf, metadata_original_size,
					     w->out_fp,
					     wimlib_get_compression_type(w),
					     &lte->output_resource_entry,
					     lte->hash);
	if (ret != 0)
		goto out;

	/* It's very likely the SHA1 message digest of the metadata resource
	 * changed, so re-insert the lookup table entry into the lookup table.
	 *
	 * We do not check for other lookup table entries having the same SHA1
	 * message digest.  It's possible for 2 absolutely identical images to
	 * be added, therefore causing 2 identical metadata resources to be in
	 * the WIM.  However, in this case, it's expected for 2 separate lookup
	 * table entries to be created, even though this doesn't make a whole
	 * lot of sense since they will share the same SHA1 message digest.
	 * */
	lookup_table_unlink(w->lookup_table, lte);
	lookup_table_insert(w->lookup_table, lte);
	lte->out_refcnt = 1;

	/* Make sure that the lookup table entry for this metadata resource is
	 * marked with the metadata flag. */
	lte->output_resource_entry.flags |= WIM_RESHDR_FLAG_METADATA;
out:
	/* All the data has been written to the new WIM; no need for the buffer
	 * anymore */
	FREE(buf);
	return ret;
}
