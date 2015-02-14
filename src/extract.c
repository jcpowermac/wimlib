/*
 * extract.c
 *
 * Support for extracting WIM images, or files or directories contained in a WIM
 * image.
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

/*
 * This file provides the API functions wimlib_extract_image(),
 * wimlib_extract_image_from_pipe(), wimlib_extract_paths(), and
 * wimlib_extract_pathlist().  Internally, all end up calling
 * do_wimlib_extract_paths() and extract_trees().
 *
 * Although wimlib supports multiple extraction modes/backends (NTFS-3g, UNIX,
 * Win32), this file does not itself have code to extract files or directories
 * to any specific target; instead, it handles generic functionality and relies
 * on lower-level callback functions declared in `struct apply_operations' to do
 * the actual extraction.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wimlib/apply.h"
#include "wimlib/assert.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/blob_table.h"
#include "wimlib/metadata.h"
#include "wimlib/pathlist.h"
#include "wimlib/paths.h"
#include "wimlib/reparse.h"
#include "wimlib/resource.h"
#include "wimlib/security.h"
#include "wimlib/unix_data.h"
#ifdef __WIN32__
#  include "wimlib/win32.h" /* for realpath() equivalent */
#endif
#include "wimlib/xml.h"
#include "wimlib/wildcard.h"
#include "wimlib/wim.h"

#define WIMLIB_EXTRACT_FLAG_FROM_PIPE   0x80000000
#define WIMLIB_EXTRACT_FLAG_IMAGEMODE   0x40000000

/* Keep in sync with wimlib.h  */
#define WIMLIB_EXTRACT_MASK_PUBLIC				\
	(WIMLIB_EXTRACT_FLAG_NTFS			|	\
	 WIMLIB_EXTRACT_FLAG_UNIX_DATA			|	\
	 WIMLIB_EXTRACT_FLAG_NO_ACLS			|	\
	 WIMLIB_EXTRACT_FLAG_STRICT_ACLS		|	\
	 WIMLIB_EXTRACT_FLAG_RPFIX			|	\
	 WIMLIB_EXTRACT_FLAG_NORPFIX			|	\
	 WIMLIB_EXTRACT_FLAG_TO_STDOUT			|	\
	 WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES	|	\
	 WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS		|	\
	 WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS		|	\
	 WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES		|	\
	 WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS		|	\
	 WIMLIB_EXTRACT_FLAG_GLOB_PATHS			|	\
	 WIMLIB_EXTRACT_FLAG_STRICT_GLOB		|	\
	 WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES		|	\
	 WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE  |	\
	 WIMLIB_EXTRACT_FLAG_WIMBOOT)

/* Send WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE or
 * WIMLIB_PROGRESS_MSG_EXTRACT_METADATA.  */
int
do_file_extract_progress(struct apply_ctx *ctx, enum wimlib_progress_msg msg)
{
	ctx->count_until_file_progress = 500;  /* Arbitrary value to limit calls  */
	return extract_progress(ctx, msg);
}

static int
start_file_phase(struct apply_ctx *ctx, uint64_t end_file_count, enum wimlib_progress_msg msg)
{
	ctx->progress.extract.current_file_count = 0;
	ctx->progress.extract.end_file_count = end_file_count;
	return do_file_extract_progress(ctx, msg);
}

int
start_file_structure_phase(struct apply_ctx *ctx, uint64_t end_file_count)
{
	return start_file_phase(ctx, end_file_count, WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE);
}

int
start_file_metadata_phase(struct apply_ctx *ctx, uint64_t end_file_count)
{
	return start_file_phase(ctx, end_file_count, WIMLIB_PROGRESS_MSG_EXTRACT_METADATA);
}

static int
end_file_phase(struct apply_ctx *ctx, enum wimlib_progress_msg msg)
{
	ctx->progress.extract.current_file_count = ctx->progress.extract.end_file_count;
	return do_file_extract_progress(ctx, msg);
}

int
end_file_structure_phase(struct apply_ctx *ctx)
{
	return end_file_phase(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE);
}

int
end_file_metadata_phase(struct apply_ctx *ctx)
{
	return end_file_phase(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_METADATA);
}

/* Check whether the extraction of a dentry should be skipped completely.  */
static bool
dentry_is_supported(struct wim_dentry *dentry,
		    const struct wim_features *supported_features)
{
	struct wim_inode *inode = dentry->d_inode;

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		if (!(supported_features->reparse_points ||
		      (inode_is_symlink(inode) &&
		       supported_features->symlink_reparse_points)))
			return false;
	}

	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED) {
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (!supported_features->encrypted_directories)
				return false;
		} else {
			if (!supported_features->encrypted_files)
				return false;
		}
	}

	return true;
}


#define PWM_ALLOW_WIM_HDR 0x00001

/* Read the header from a stream in a pipable WIM.  */
static int
read_pwm_stream_header(WIMStruct *pwm, struct blob_info *blob,
		       struct wim_resource_spec *rspec,
		       int flags, struct wim_header_disk *hdr_ret)
{
	union {
		struct pwm_stream_hdr stream_hdr;
		struct wim_header_disk pwm_hdr;
	} buf;
	struct wim_reshdr reshdr;
	int ret;

	ret = full_read(&pwm->in_fd, &buf.stream_hdr, sizeof(buf.stream_hdr));
	if (ret)
		goto read_error;

	if ((flags & PWM_ALLOW_WIM_HDR) &&
	    le64_to_cpu(buf.stream_hdr.magic) == PWM_MAGIC)
	{
		BUILD_BUG_ON(sizeof(buf.pwm_hdr) < sizeof(buf.stream_hdr));
		ret = full_read(&pwm->in_fd, &buf.stream_hdr + 1,
				sizeof(buf.pwm_hdr) - sizeof(buf.stream_hdr));

		if (ret)
			goto read_error;
		blob->resource_location = RESOURCE_NONEXISTENT;
		memcpy(hdr_ret, &buf.pwm_hdr, sizeof(buf.pwm_hdr));
		return 0;
	}

	if (le64_to_cpu(buf.stream_hdr.magic) != PWM_STREAM_MAGIC) {
		ERROR("Data read on pipe is invalid (expected stream header).");
		return WIMLIB_ERR_INVALID_PIPABLE_WIM;
	}

	copy_hash(blob->hash, buf.stream_hdr.hash);

	reshdr.size_in_wim = 0;
	reshdr.flags = le32_to_cpu(buf.stream_hdr.flags);
	reshdr.offset_in_wim = pwm->in_fd.offset;
	reshdr.uncompressed_size = le64_to_cpu(buf.stream_hdr.uncompressed_size);
	wim_res_hdr_to_spec(&reshdr, pwm, rspec);
	blob_bind_wim_resource_spec(blob, rspec);
	blob->flags = rspec->flags;
	blob->size = rspec->uncompressed_size;
	blob->offset_in_res = 0;
	return 0;

read_error:
	ERROR_WITH_ERRNO("Error reading pipable WIM from pipe");
	return ret;
}

static int
load_streams_from_pipe(struct apply_ctx *ctx,
		       const struct read_stream_list_callbacks *cbs)
{
	struct blob_info *found_blob = NULL;
	struct wim_resource_spec *rspec = NULL;
	struct wim_blob_table *blob_table;
	int ret;

	ret = WIMLIB_ERR_NOMEM;
	found_blob = new_blob_table_entry();
	if (!found_blob)
		goto out;

	rspec = MALLOC(sizeof(struct wim_resource_spec));
	if (!rspec)
		goto out;

	blob_table = ctx->wim->blob_table;
	memcpy(ctx->progress.extract.guid, ctx->wim->hdr.guid, WIM_GUID_LEN);
	ctx->progress.extract.part_number = ctx->wim->hdr.part_number;
	ctx->progress.extract.total_parts = ctx->wim->hdr.total_parts;
	ret = extract_progress(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN);
	if (ret)
		goto out;

	while (ctx->num_streams_remaining) {
		struct wim_header_disk pwm_hdr;
		struct blob_info *needed_blob;

		if (found_blob->resource_location != RESOURCE_NONEXISTENT)
			blob_unbind_wim_resource_spec(found_blob);
		ret = read_pwm_stream_header(ctx->wim, found_blob, rspec,
					     PWM_ALLOW_WIM_HDR, &pwm_hdr);
		if (ret)
			goto out;

		if ((found_blob->resource_location != RESOURCE_NONEXISTENT)
		    && !(found_blob->flags & WIM_RESHDR_FLAG_METADATA)
		    && (needed_blob = lookup_stream(blob_table, found_blob->hash))
		    && (needed_blob->out_refcnt))
		{
			needed_blob->offset_in_res = found_blob->offset_in_res;
			needed_blob->flags = found_blob->flags;
			needed_blob->size = found_blob->size;

			blob_unbind_wim_resource_spec(found_blob);
			blob_bind_wim_resource_spec(needed_blob, rspec);

			ret = (*cbs->begin_stream)(needed_blob,
						   cbs->begin_stream_ctx);
			if (ret) {
				blob_unbind_wim_resource_spec(needed_blob);
				goto out;
			}

			ret = extract_stream(needed_blob, needed_blob->size,
					     cbs->consume_chunk,
					     cbs->consume_chunk_ctx);

			ret = (*cbs->end_stream)(needed_blob, ret,
						 cbs->end_stream_ctx);
			blob_unbind_wim_resource_spec(needed_blob);
			if (ret)
				goto out;
			ctx->num_streams_remaining--;
		} else if (found_blob->resource_location != RESOURCE_NONEXISTENT) {
			ret = skip_wim_stream(found_blob);
			if (ret)
				goto out;
		} else {
			u16 part_number = le16_to_cpu(pwm_hdr.part_number);
			u16 total_parts = le16_to_cpu(pwm_hdr.total_parts);

			if (part_number != ctx->progress.extract.part_number ||
			    total_parts != ctx->progress.extract.total_parts ||
			    memcmp(pwm_hdr.guid, ctx->progress.extract.guid,
				   WIM_GUID_LEN))
			{
				ctx->progress.extract.part_number = part_number;
				ctx->progress.extract.total_parts = total_parts;
				memcpy(ctx->progress.extract.guid,
				       pwm_hdr.guid, WIM_GUID_LEN);
				ret = extract_progress(ctx,
						       WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN);
				if (ret)
					goto out;
			}
		}
	}
	ret = 0;
out:
	if (found_blob && found_blob->resource_location != RESOURCE_IN_WIM)
		FREE(rspec);
	free_blob_table_entry(found_blob);
	return ret;
}

/* Creates a temporary file opened for writing.  The open file descriptor is
 * returned in @fd_ret and its name is returned in @name_ret (dynamically
 * allocated).  */
static int
create_temporary_file(struct filedes *fd_ret, tchar **name_ret)
{
	tchar *name;
	int open_flags;
	int raw_fd;

retry:
	name = ttempnam(NULL, T("wimlib"));
	if (!name) {
		ERROR_WITH_ERRNO("Failed to create temporary filename");
		return WIMLIB_ERR_NOMEM;
	}

	open_flags = O_WRONLY | O_CREAT | O_EXCL | O_BINARY;
#ifdef __WIN32__
	open_flags |= _O_SHORT_LIVED;
#endif
	raw_fd = topen(name, open_flags, 0600);

	if (raw_fd < 0) {
		if (errno == EEXIST) {
			FREE(name);
			goto retry;
		}
		ERROR_WITH_ERRNO("Failed to create temporary file "
				 "\"%"TS"\"", name);
		FREE(name);
		return WIMLIB_ERR_OPEN;
	}

	filedes_init(fd_ret, raw_fd);
	*name_ret = name;
	return 0;
}

static int
begin_extract_stream_wrapper(struct blob_info *blob, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;

	ctx->cur_stream = blob;
	ctx->cur_stream_offset = 0;

	if (unlikely(blob->out_refcnt > MAX_OPEN_STREAMS))
		return create_temporary_file(&ctx->tmpfile_fd, &ctx->tmpfile_name);
	else
		return (*ctx->saved_cbs->begin_stream)(blob, ctx->saved_cbs->begin_stream_ctx);
}

static int
extract_chunk_wrapper(const void *chunk, size_t size, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;
	union wimlib_progress_info *progress = &ctx->progress;
	int ret;

	ctx->cur_stream_offset += size;

	if (likely(ctx->supported_features.hard_links)) {
		progress->extract.completed_bytes +=
			(u64)size * ctx->cur_stream->out_refcnt;
		if (ctx->cur_stream_offset == ctx->cur_stream->size)
			progress->extract.completed_streams += ctx->cur_stream->out_refcnt;
	} else {
		const struct stream_owner *owners = stream_owners(ctx->cur_stream);
		for (u32 i = 0; i < ctx->cur_stream->out_refcnt; i++) {
			const struct wim_inode *inode = owners[i].inode;
			const struct wim_dentry *dentry;

			list_for_each_entry(dentry,
					    &inode->i_extraction_aliases,
					    d_extraction_alias_node)
			{
				progress->extract.completed_bytes += size;
				if (ctx->cur_stream_offset == ctx->cur_stream->size)
					progress->extract.completed_streams++;
			}
		}
	}
	if (progress->extract.completed_bytes >= ctx->next_progress) {

		ret = extract_progress(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS);
		if (ret)
			return ret;

		if (progress->extract.completed_bytes >=
		    progress->extract.total_bytes)
		{
			ctx->next_progress = UINT64_MAX;
		} else {
			/* Send new message as soon as another 1/128 of the
			 * total has been extracted.  (Arbitrary number.)  */
			ctx->next_progress =
				progress->extract.completed_bytes +
					progress->extract.total_bytes / 128;

			/* ... Unless that would be more than 5000000 bytes, in
			 * which case send the next after the next 5000000
			 * bytes.  (Another arbitrary number.)  */
			if (progress->extract.completed_bytes + 5000000 <
			    ctx->next_progress)
				ctx->next_progress =
					progress->extract.completed_bytes + 5000000;

			/* ... But always send a message as soon as we're
			 * completely done.  */
			if (progress->extract.total_bytes < ctx->next_progress)
				ctx->next_progress = progress->extract.total_bytes;
		}
	}

	if (unlikely(filedes_valid(&ctx->tmpfile_fd))) {
		/* Just extracting to temporary file for now.  */
		ret = full_write(&ctx->tmpfile_fd, chunk, size);
		if (ret) {
			ERROR_WITH_ERRNO("Error writing data to "
					 "temporary file \"%"TS"\"",
					 ctx->tmpfile_name);
		}
		return ret;
	} else {
		return (*ctx->saved_cbs->consume_chunk)(chunk, size,
							ctx->saved_cbs->consume_chunk_ctx);
	}
}

static int
extract_from_tmpfile(const tchar *tmpfile_name, struct apply_ctx *ctx)
{
	struct blob_info tmpfile_blob;
	struct blob_info *orig_blob = ctx->cur_stream;
	const struct read_stream_list_callbacks *cbs = ctx->saved_cbs;
	int ret;
	const u32 orig_refcnt = orig_blob->out_refcnt;

	BUILD_BUG_ON(MAX_OPEN_STREAMS < ARRAY_LEN(orig_blob->inline_stream_owners));

	struct stream_owner *owners = orig_blob->stream_owners;

	/* Copy the stream's data from the temporary file to each of its
	 * destinations.
	 *
	 * This is executed only in the very uncommon case that a
	 * single-instance stream is being extracted to more than
	 * MAX_OPEN_STREAMS locations!  */

	memcpy(&tmpfile_blob, orig_blob, sizeof(struct blob_info));
	tmpfile_blob.resource_location = RESOURCE_IN_FILE_ON_DISK;
	tmpfile_blob.file_on_disk = ctx->tmpfile_name;
	ret = 0;
	for (u32 i = 0; i < orig_refcnt; i++) {

		/* Note: it usually doesn't matter whether we pass the original
		 * stream entry to callbacks provided by the extraction backend
		 * as opposed to the tmpfile stream entry, since they shouldn't
		 * actually read data from the stream other than through the
		 * read_stream_prefix() call below.  But for
		 * WIMLIB_EXTRACT_FLAG_WIMBOOT mode on Windows it does matter
		 * because it needs the original stream location in order to
		 * create the external backing reference.  */

		orig_blob->out_refcnt = 1;
		orig_blob->inline_stream_owners[0] = owners[i];

		ret = (*cbs->begin_stream)(orig_blob, cbs->begin_stream_ctx);
		if (ret)
			break;

		/* Extra SHA-1 isn't necessary here, but it shouldn't hurt as
		 * this case is very rare anyway.  */
		ret = extract_stream(&tmpfile_blob, tmpfile_blob.size,
				     cbs->consume_chunk,
				     cbs->consume_chunk_ctx);

		ret = (*cbs->end_stream)(orig_blob, ret, cbs->end_stream_ctx);
		if (ret)
			break;
	}
	FREE(owners);
	orig_blob->out_refcnt = 0;
	return ret;
}

static int
end_extract_stream_wrapper(struct blob_info *stream,
			   int status, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;

	if (unlikely(filedes_valid(&ctx->tmpfile_fd))) {
		filedes_close(&ctx->tmpfile_fd);
		if (!status)
			status = extract_from_tmpfile(ctx->tmpfile_name, ctx);
		filedes_invalidate(&ctx->tmpfile_fd);
		tunlink(ctx->tmpfile_name);
		FREE(ctx->tmpfile_name);
		return status;
	} else {
		return (*ctx->saved_cbs->end_stream)(stream, status,
						     ctx->saved_cbs->end_stream_ctx);
	}
}

/*
 * Read the list of single-instance streams to extract and feed their data into
 * the specified callback functions.
 *
 * This handles checksumming each stream.
 *
 * This also handles sending WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS.
 *
 * This also works if the WIM is being read from a pipe, whereas attempting to
 * read streams directly (e.g. with read_full_stream_into_buf()) will not.
 *
 * This also will split up streams that will need to be extracted to more than
 * MAX_OPEN_STREAMS locations, as measured by the 'out_refcnt' of each stream.
 * Therefore, the apply_operations implementation need not worry about running
 * out of file descriptors, unless it might open more than one file descriptor
 * per nominal destination (e.g. Win32 currently might because the destination
 * file system might not support hard links).
 */
int
extract_stream_list(struct apply_ctx *ctx,
		    const struct read_stream_list_callbacks *cbs)
{
	struct read_stream_list_callbacks wrapper_cbs = {
		.begin_stream      = begin_extract_stream_wrapper,
		.begin_stream_ctx  = ctx,
		.consume_chunk     = extract_chunk_wrapper,
		.consume_chunk_ctx = ctx,
		.end_stream        = end_extract_stream_wrapper,
		.end_stream_ctx    = ctx,
	};
	ctx->saved_cbs = cbs;
	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_FROM_PIPE) {
		return load_streams_from_pipe(ctx, &wrapper_cbs);
	} else {
		return read_stream_list(&ctx->stream_list,
					offsetof(struct blob_info,
						 extraction_list),
					&wrapper_cbs, VERIFY_STREAM_HASHES);
	}
}

/* Extract a WIM dentry to standard output.
 *
 * This obviously doesn't make sense in all cases.  We return an error if the
 * dentry does not correspond to a regular file.  Otherwise we extract the
 * unnamed data stream only.  */
static int
extract_dentry_to_stdout(struct wim_dentry *dentry,
			 const struct wim_blob_table *blob_table)
{
	struct wim_inode *inode = dentry->d_inode;
	struct blob_info *blob;
	struct filedes _stdout;

	if (inode->i_attributes & (FILE_ATTRIBUTE_REPARSE_POINT |
				   FILE_ATTRIBUTE_DIRECTORY))
	{
		ERROR("\"%"TS"\" is not a regular file and therefore cannot be "
		      "extracted to standard output", dentry_full_path(dentry));
		return WIMLIB_ERR_NOT_A_REGULAR_FILE;
	}

	blob = inode_get_blob_for_unnamed_stream(inode, blob_table);
	if (!blob) {
		const u8 *hash = inode_unnamed_stream_hash(inode);
		if (!is_zero_hash(hash))
			return stream_not_found_error(inode, hash);
		return 0;
	}

	filedes_init(&_stdout, STDOUT_FILENO);
	return extract_full_stream_to_fd(blob, &_stdout);
}

static int
extract_dentries_to_stdout(struct wim_dentry **dentries, size_t num_dentries,
			   const struct wim_blob_table *blob_table)
{
	for (size_t i = 0; i < num_dentries; i++) {
		int ret = extract_dentry_to_stdout(dentries[i], blob_table);
		if (ret)
			return ret;
	}
	return 0;
}

/**********************************************************************/

/*
 * Removes duplicate dentries from the array.
 *
 * Returns the new number of dentries, packed at the front of the array.
 */
static size_t
remove_duplicate_trees(struct wim_dentry **trees, size_t num_trees)
{
	size_t i, j = 0;
	for (i = 0; i < num_trees; i++) {
		if (!trees[i]->tmp_flag) {
			/* Found distinct dentry.  */
			trees[i]->tmp_flag = 1;
			trees[j++] = trees[i];
		}
	}
	for (i = 0; i < j; i++)
		trees[i]->tmp_flag = 0;
	return j;
}

/*
 * Remove dentries that are descendants of other dentries in the array.
 *
 * Returns the new number of dentries, packed at the front of the array.
 */
static size_t
remove_contained_trees(struct wim_dentry **trees, size_t num_trees)
{
	size_t i, j = 0;
	for (i = 0; i < num_trees; i++)
		trees[i]->tmp_flag = 1;
	for (i = 0; i < num_trees; i++) {
		struct wim_dentry *d = trees[i];
		while (!dentry_is_root(d)) {
			d = d->d_parent;
			if (d->tmp_flag)
				goto tree_contained;
		}
		trees[j++] = trees[i];
		continue;

	tree_contained:
		trees[i]->tmp_flag = 0;
	}

	for (i = 0; i < j; i++)
		trees[i]->tmp_flag = 0;
	return j;
}

static int
dentry_append_to_list(struct wim_dentry *dentry, void *_dentry_list)
{
	struct list_head *dentry_list = _dentry_list;
	list_add_tail(&dentry->d_extraction_list_node, dentry_list);
	return 0;
}

static void
dentry_reset_extraction_list_node(struct wim_dentry *dentry)
{
	dentry->d_extraction_list_node = (struct list_head){NULL, NULL};
}

static int
dentry_delete_from_list(struct wim_dentry *dentry, void *_ignore)
{
	list_del(&dentry->d_extraction_list_node);
	dentry_reset_extraction_list_node(dentry);
	return 0;
}

/*
 * Build the preliminary list of dentries to be extracted.
 *
 * The list maintains the invariant that if d1 and d2 are in the list and d1 is
 * an ancestor of d2, then d1 appears before d2 in the list.
 */
static void
build_dentry_list(struct list_head *dentry_list, struct wim_dentry **trees,
		  size_t num_trees, bool add_ancestors)
{
	INIT_LIST_HEAD(dentry_list);

	/* Add the trees recursively.  */
	for (size_t i = 0; i < num_trees; i++)
		for_dentry_in_tree(trees[i], dentry_append_to_list, dentry_list);

	/* If requested, add ancestors of the trees.  */
	if (add_ancestors) {
		for (size_t i = 0; i < num_trees; i++) {
			struct wim_dentry *dentry = trees[i];
			struct wim_dentry *ancestor;
			struct list_head *place_after;

			if (dentry_is_root(dentry))
				continue;

			place_after = dentry_list;
			ancestor = dentry;
			do {
				ancestor = ancestor->d_parent;
				if (will_extract_dentry(ancestor)) {
					place_after = &ancestor->d_extraction_list_node;
					break;
				}
			} while (!dentry_is_root(ancestor));

			ancestor = dentry;
			do {
				ancestor = ancestor->d_parent;
				if (will_extract_dentry(ancestor))
					break;
				list_add(&ancestor->d_extraction_list_node, place_after);
			} while (!dentry_is_root(ancestor));
		}
	}
}

static void
destroy_dentry_list(struct list_head *dentry_list)
{
	struct wim_dentry *dentry, *tmp;
	struct wim_inode *inode;

	list_for_each_entry_safe(dentry, tmp, dentry_list, d_extraction_list_node) {
		inode = dentry->d_inode;
		dentry_reset_extraction_list_node(dentry);
		inode->i_visited = 0;
		inode->i_can_externally_back = 0;
		if ((void *)dentry->d_extraction_name != (void *)dentry->file_name)
			FREE(dentry->d_extraction_name);
		dentry->d_extraction_name = NULL;
		dentry->d_extraction_name_nchars = 0;
	}
}

static void
destroy_stream_list(struct list_head *stream_list)
{
	struct blob_info *blob;

	list_for_each_entry(blob, stream_list, extraction_list)
		if (blob->out_refcnt > ARRAY_LEN(blob->inline_stream_owners))
			FREE(blob->stream_owners);
}

#ifdef __WIN32__
static const utf16lechar replacement_char = cpu_to_le16(0xfffd);
#else
static const utf16lechar replacement_char = cpu_to_le16('?');
#endif

static bool
file_name_valid(utf16lechar *name, size_t num_chars, bool fix)
{
	size_t i;

	if (num_chars == 0)
		return true;
	for (i = 0; i < num_chars; i++) {
		switch (name[i]) {
	#ifdef __WIN32__
		case cpu_to_le16('\\'):
		case cpu_to_le16(':'):
		case cpu_to_le16('*'):
		case cpu_to_le16('?'):
		case cpu_to_le16('"'):
		case cpu_to_le16('<'):
		case cpu_to_le16('>'):
		case cpu_to_le16('|'):
	#endif
		case cpu_to_le16('/'):
		case cpu_to_le16('\0'):
			if (fix)
				name[i] = replacement_char;
			else
				return false;
		}
	}

#ifdef __WIN32__
	if (name[num_chars - 1] == cpu_to_le16(' ') ||
	    name[num_chars - 1] == cpu_to_le16('.'))
	{
		if (fix)
			name[num_chars - 1] = replacement_char;
		else
			return false;
	}
#endif
	return true;
}

static int
dentry_calculate_extraction_name(struct wim_dentry *dentry,
				 struct apply_ctx *ctx)
{
	int ret;

	if (unlikely(!dentry_is_supported(dentry, &ctx->supported_features)))
		goto skip_dentry;

	if (dentry_is_root(dentry))
		return 0;

#ifdef WITH_NTFS_3G
	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		dentry->d_extraction_name = dentry->file_name;
		dentry->d_extraction_name_nchars = dentry->file_name_nbytes /
						   sizeof(utf16lechar);
		return 0;
	}
#endif

	if (!ctx->supported_features.case_sensitive_filenames) {
		struct wim_dentry *other;
		list_for_each_entry(other, &dentry->d_ci_conflict_list,
				    d_ci_conflict_list)
		{
			if (will_extract_dentry(other)) {
				if (ctx->extract_flags &
				    WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS) {
					WARNING("\"%"TS"\" has the same "
						"case-insensitive name as "
						"\"%"TS"\"; extracting "
						"dummy name instead",
						dentry_full_path(dentry),
						dentry_full_path(other));
					goto out_replace;
				} else {
					WARNING("Not extracting \"%"TS"\": "
						"has same case-insensitive "
						"name as \"%"TS"\"",
						dentry_full_path(dentry),
						dentry_full_path(other));
					goto skip_dentry;
				}
			}
		}
	}

	if (file_name_valid(dentry->file_name, dentry->file_name_nbytes / 2, false)) {
		ret = utf16le_get_tstr(dentry->file_name,
				       dentry->file_name_nbytes,
				       (const tchar **)&dentry->d_extraction_name,
				       &dentry->d_extraction_name_nchars);
		dentry->d_extraction_name_nchars /= sizeof(tchar);
		return ret;
	} else {
		if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES)
		{
			WARNING("\"%"TS"\" has an invalid filename "
				"that is not supported on this platform; "
				"extracting dummy name instead",
				dentry_full_path(dentry));
			goto out_replace;
		} else {
			WARNING("Not extracting \"%"TS"\": has an invalid filename "
				"that is not supported on this platform",
				dentry_full_path(dentry));
			goto skip_dentry;
		}
	}

out_replace:
	{
		utf16lechar utf16_name_copy[dentry->file_name_nbytes / 2];

		memcpy(utf16_name_copy, dentry->file_name, dentry->file_name_nbytes);
		file_name_valid(utf16_name_copy, dentry->file_name_nbytes / 2, true);

		const tchar *tchar_name;
		size_t tchar_nchars;

		ret = utf16le_get_tstr(utf16_name_copy,
				       dentry->file_name_nbytes,
				       &tchar_name, &tchar_nchars);
		if (ret)
			return ret;

		tchar_nchars /= sizeof(tchar);

		size_t fixed_name_num_chars = tchar_nchars;
		tchar fixed_name[tchar_nchars + 50];

		tmemcpy(fixed_name, tchar_name, tchar_nchars);
		fixed_name_num_chars += tsprintf(fixed_name + tchar_nchars,
						 T(" (invalid filename #%lu)"),
						 ++ctx->invalid_sequence);

		utf16le_put_tstr(tchar_name);

		dentry->d_extraction_name = memdup(fixed_name,
						   2 * fixed_name_num_chars + 2);
		if (!dentry->d_extraction_name)
			return WIMLIB_ERR_NOMEM;
		dentry->d_extraction_name_nchars = fixed_name_num_chars;
	}
	return 0;

skip_dentry:
	for_dentry_in_tree(dentry, dentry_delete_from_list, NULL);
	return 0;
}

/*
 * Calculate the actual filename component at which each WIM dentry will be
 * extracted, with special handling for dentries that are unsupported by the
 * extraction backend or have invalid names.
 *
 * ctx->supported_features must be filled in.
 *
 * Possible error codes: WIMLIB_ERR_NOMEM, WIMLIB_ERR_INVALID_UTF16_STRING
 */
static int
dentry_list_calculate_extraction_names(struct list_head *dentry_list,
				       struct apply_ctx *ctx)
{
	struct list_head *prev, *cur;

	/* Can't use list_for_each_entry() because a call to
	 * dentry_calculate_extraction_name() may delete the current dentry and
	 * its children from the list.  */

	prev = dentry_list;
	for (;;) {
		struct wim_dentry *dentry;
		int ret;

		cur = prev->next;
		if (cur == dentry_list)
			break;

		dentry = list_entry(cur, struct wim_dentry, d_extraction_list_node);

		ret = dentry_calculate_extraction_name(dentry, ctx);
		if (ret)
			return ret;

		if (prev->next == cur)
			prev = cur;
		else
			; /* Current dentry and its children (which follow in
			     the list) were deleted.  prev stays the same.  */
	}
	return 0;
}

static int
dentry_resolve_streams(struct wim_dentry *dentry, int extract_flags,
		       struct wim_blob_table *blob_table)
{
	struct wim_inode *inode = dentry->d_inode;
	struct blob_info *blob;
	int ret;
	bool force = false;

	/* Special case:  when extracting from a pipe, the WIM lookup table is
	 * initially empty, so "resolving" an inode's streams is initially not
	 * possible.  However, we still need to keep track of which streams,
	 * identified by SHA1 message digests, need to be extracted, so we
	 * "resolve" the inode's streams anyway by allocating new entries.  */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_FROM_PIPE)
		force = true;
	ret = inode_resolve_streams(inode, blob_table, force);
	if (ret)
		return ret;
	for (u32 i = 0; i <= inode->i_num_ads; i++) {
		blob = inode_get_blob_for_stream_resolved(inode, i);
		if (blob)
			blob->out_refcnt = 0;
	}
	return 0;
}

/*
 * For each dentry to be extracted, resolve all streams in the corresponding
 * inode and set 'out_refcnt' in each to 0.
 *
 * Possible error codes: WIMLIB_ERR_RESOURCE_NOT_FOUND, WIMLIB_ERR_NOMEM.
 */
static int
dentry_list_resolve_streams(struct list_head *dentry_list,
			    struct apply_ctx *ctx)
{
	struct wim_dentry *dentry;
	int ret;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		ret = dentry_resolve_streams(dentry,
					     ctx->extract_flags,
					     ctx->wim->blob_table);
		if (ret)
			return ret;
	}
	return 0;
}

static int
ref_stream(struct blob_info *blob, unsigned stream_idx,
	   struct wim_dentry *dentry, struct apply_ctx *ctx)
{
	struct wim_inode *inode = dentry->d_inode;
	struct stream_owner *stream_owners;

	if (!blob)
		return 0;

	/* Tally the size only for each extraction of the stream (not hard
	 * links).  */
	if (inode->i_visited && ctx->supported_features.hard_links)
		return 0;

	ctx->progress.extract.total_bytes += blob->size;
	ctx->progress.extract.total_streams++;

	if (inode->i_visited)
		return 0;

	/* Add stream to the dentry_list only one time, even if it's going
	 * to be extracted to multiple inodes.  */
	if (blob->out_refcnt == 0) {
		list_add_tail(&blob->extraction_list, &ctx->stream_list);
		ctx->num_streams_remaining++;
	}

	/* If inode not yet been visited, append it to the stream_owners array.  */
	if (blob->out_refcnt < ARRAY_LEN(blob->inline_stream_owners)) {
		stream_owners = blob->inline_stream_owners;
	} else {
		struct stream_owner *prev_stream_owners;
		size_t alloc_stream_owners;

		if (blob->out_refcnt == ARRAY_LEN(blob->inline_stream_owners)) {
			prev_stream_owners = NULL;
			alloc_stream_owners = ARRAY_LEN(blob->inline_stream_owners);
		} else {
			prev_stream_owners = blob->stream_owners;
			alloc_stream_owners = blob->alloc_stream_owners;
		}

		if (blob->out_refcnt == alloc_stream_owners) {
			alloc_stream_owners *= 2;
			stream_owners = REALLOC(prev_stream_owners,
					       alloc_stream_owners *
						sizeof(stream_owners[0]));
			if (!stream_owners)
				return WIMLIB_ERR_NOMEM;
			if (!prev_stream_owners) {
				memcpy(stream_owners,
				       blob->inline_stream_owners,
				       sizeof(blob->inline_stream_owners));
			}
			blob->stream_owners = stream_owners;
			blob->alloc_stream_owners = alloc_stream_owners;
		}
		stream_owners = blob->stream_owners;
	}
	stream_owners[blob->out_refcnt].inode = inode;
	if (stream_idx == 0) {
		stream_owners[blob->out_refcnt].stream_name = NULL;
	} else {
		stream_owners[blob->out_refcnt].stream_name =
			inode->i_ads_entries[stream_idx - 1].stream_name;
	}
	blob->out_refcnt++;
	return 0;
}

static int
ref_unnamed_stream(struct wim_dentry *dentry, struct apply_ctx *ctx)
{
	struct wim_inode *inode = dentry->d_inode;
	int ret;
	unsigned stream_idx;
	struct blob_info *stream;

	if (unlikely(ctx->apply_ops->will_externally_back)) {
		ret = (*ctx->apply_ops->will_externally_back)(dentry, ctx);
		if (ret >= 0) {
			if (ret) /* Error */
				return ret;
			/* Will externally back */
			return 0;
		}
		/* Won't externally back */
	}

	stream = inode_unnamed_stream_resolved(inode, &stream_idx);
	return ref_stream(stream, stream_idx, dentry, ctx);
}

static int
dentry_ref_streams(struct wim_dentry *dentry, struct apply_ctx *ctx)
{
	struct wim_inode *inode = dentry->d_inode;
	int ret;

	/* The unnamed data stream will almost always be extracted, but there
	 * exist cases in which it won't be.  */
	ret = ref_unnamed_stream(dentry, ctx);
	if (ret)
		return ret;

	/* Named data streams will be extracted only if supported in the current
	 * extraction mode and volume, and to avoid complications, if not doing
	 * a linked extraction.  */
	if (ctx->supported_features.named_data_streams) {
		for (unsigned i = 0; i < inode->i_num_ads; i++) {
			if (!inode->i_ads_entries[i].stream_name_nbytes)
				continue;
			ret = ref_stream(inode->i_ads_entries[i].blob, i + 1,
					 dentry, ctx);
			if (ret)
				return ret;
		}
	}
	inode->i_visited = 1;
	return 0;
}

/*
 * For each dentry to be extracted, iterate through the data streams of the
 * corresponding inode.  For each such stream that is not to be ignored due to
 * the supported features or extraction flags, add it to the list of streams to
 * be extracted (ctx->stream_list) if not already done so.
 *
 * Also builds a mapping from each stream to the inodes referencing it.
 *
 * This also initializes the extract progress info with byte and stream
 * information.
 *
 * ctx->supported_features must be filled in.
 *
 * Possible error codes: WIMLIB_ERR_NOMEM.
 */
static int
dentry_list_ref_streams(struct list_head *dentry_list, struct apply_ctx *ctx)
{
	struct wim_dentry *dentry;
	int ret;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		ret = dentry_ref_streams(dentry, ctx);
		if (ret)
			return ret;
	}
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node)
		dentry->d_inode->i_visited = 0;
	return 0;
}

static void
dentry_list_build_inode_alias_lists(struct list_head *dentry_list)
{
	struct wim_dentry *dentry;
	struct wim_inode *inode;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		inode = dentry->d_inode;
		if (!inode->i_visited)
			INIT_LIST_HEAD(&inode->i_extraction_aliases);
		list_add_tail(&dentry->d_extraction_alias_node,
			      &inode->i_extraction_aliases);
		inode->i_visited = 1;
	}
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node)
		dentry->d_inode->i_visited = 0;
}

static void
inode_tally_features(const struct wim_inode *inode,
		     struct wim_features *features)
{
	if (inode->i_attributes & FILE_ATTRIBUTE_ARCHIVE)
		features->archive_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_HIDDEN)
		features->hidden_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_SYSTEM)
		features->system_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_COMPRESSED)
		features->compressed_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED) {
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
			features->encrypted_directories++;
		else
			features->encrypted_files++;
	}
	if (inode->i_attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
		features->not_context_indexed_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_SPARSE_FILE)
		features->sparse_files++;
	if (inode_has_named_stream(inode))
		features->named_data_streams++;
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		features->reparse_points++;
		if (inode_is_symlink(inode))
			features->symlink_reparse_points++;
		else
			features->other_reparse_points++;
	}
	if (inode->i_security_id != -1)
		features->security_descriptors++;
	if (inode_has_unix_data(inode))
		features->unix_data++;
}

/* Tally features necessary to extract a dentry and the corresponding inode.  */
static void
dentry_tally_features(struct wim_dentry *dentry, struct wim_features *features)
{
	struct wim_inode *inode = dentry->d_inode;

	if (dentry_has_short_name(dentry))
		features->short_names++;

	if (inode->i_visited) {
		features->hard_links++;
	} else {
		inode_tally_features(inode, features);
		inode->i_visited = 1;
	}
}

/* Tally the features necessary to extract the specified dentries.  */
static void
dentry_list_get_features(struct list_head *dentry_list,
			 struct wim_features *features)
{
	struct wim_dentry *dentry;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node)
		dentry_tally_features(dentry, features);

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node)
		dentry->d_inode->i_visited = 0;
}

static int
do_feature_check(const struct wim_features *required_features,
		 const struct wim_features *supported_features,
		 int extract_flags)
{
	/* File attributes.  */
	if (!(extract_flags & WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES)) {
		/* Note: Don't bother the user about FILE_ATTRIBUTE_ARCHIVE.
		 * We're an archive program, so theoretically we can do what we
		 * want with it.  */

		if (required_features->hidden_files &&
		    !supported_features->hidden_files)
			WARNING("Ignoring FILE_ATTRIBUTE_HIDDEN of %lu files",
				required_features->hidden_files);

		if (required_features->system_files &&
		    !supported_features->system_files)
			WARNING("Ignoring FILE_ATTRIBUTE_SYSTEM of %lu files",
				required_features->system_files);

		if (required_features->compressed_files &&
		    !supported_features->compressed_files)
			WARNING("Ignoring FILE_ATTRIBUTE_COMPRESSED of %lu files",
				required_features->compressed_files);

		if (required_features->not_context_indexed_files &&
		    !supported_features->not_context_indexed_files)
			WARNING("Ignoring FILE_ATTRIBUTE_NOT_CONTENT_INDEXED of %lu files",
				required_features->not_context_indexed_files);

		if (required_features->sparse_files &&
		    !supported_features->sparse_files)
			WARNING("Ignoring FILE_ATTRIBUTE_SPARSE_FILE of %lu files",
				required_features->sparse_files);

		if (required_features->encrypted_directories &&
		    !supported_features->encrypted_directories)
			WARNING("Ignoring FILE_ATTRIBUTE_ENCRYPTED of %lu directories",
				required_features->encrypted_directories);
	}

	/* Encrypted files.  */
	if (required_features->encrypted_files &&
	    !supported_features->encrypted_files)
		WARNING("Ignoring %lu encrypted files",
			required_features->encrypted_files);

	/* Named data streams.  */
	if (required_features->named_data_streams &&
	    (!supported_features->named_data_streams))
		WARNING("Ignoring named data streams of %lu files",
			required_features->named_data_streams);

	/* Hard links.  */
	if (required_features->hard_links && !supported_features->hard_links)
		WARNING("Extracting %lu hard links as independent files",
			required_features->hard_links);

	/* Symbolic links and reparse points.  */
	if ((extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS) &&
	    required_features->symlink_reparse_points &&
	    !supported_features->symlink_reparse_points &&
	    !supported_features->reparse_points)
	{
		ERROR("Extraction backend does not support symbolic links!");
		return WIMLIB_ERR_UNSUPPORTED;
	}
	if (required_features->reparse_points &&
	    !supported_features->reparse_points)
	{
		if (supported_features->symlink_reparse_points) {
			if (required_features->other_reparse_points) {
				WARNING("Ignoring %lu non-symlink/junction "
					"reparse point files",
					required_features->other_reparse_points);
			}
		} else {
			WARNING("Ignoring %lu reparse point files",
				required_features->reparse_points);
		}
	}

	/* Security descriptors.  */
	if (((extract_flags & (WIMLIB_EXTRACT_FLAG_STRICT_ACLS |
			       WIMLIB_EXTRACT_FLAG_UNIX_DATA))
	     == WIMLIB_EXTRACT_FLAG_STRICT_ACLS) &&
	    required_features->security_descriptors &&
	    !supported_features->security_descriptors)
	{
		ERROR("Extraction backend does not support security descriptors!");
		return WIMLIB_ERR_UNSUPPORTED;
	}
	if (!(extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS) &&
	    required_features->security_descriptors &&
	    !supported_features->security_descriptors)
		WARNING("Ignoring Windows NT security descriptors of %lu files",
			required_features->security_descriptors);

	/* UNIX data.  */
	if ((extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) &&
	    required_features->unix_data && !supported_features->unix_data)
	{
		ERROR("Extraction backend does not support UNIX data!");
		return WIMLIB_ERR_UNSUPPORTED;
	}

	if (required_features->unix_data &&
	    !(extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA))
	{
		WARNING("Ignoring UNIX metadata of %lu files",
			required_features->unix_data);
	}

	/* DOS Names.  */
	if (required_features->short_names &&
	    !supported_features->short_names)
	{
		if (extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES) {
			ERROR("Extraction backend does not support DOS names!");
			return WIMLIB_ERR_UNSUPPORTED;
		}
		WARNING("Ignoring DOS names of %lu files",
			required_features->short_names);
	}

	/* Timestamps.  */
	if ((extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS) &&
	    !supported_features->timestamps)
	{
		ERROR("Extraction backend does not support timestamps!");
		return WIMLIB_ERR_UNSUPPORTED;
	}

	return 0;
}

static const struct apply_operations *
select_apply_operations(int extract_flags)
{
#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS)
		return &ntfs_3g_apply_ops;
#endif
#ifdef __WIN32__
	return &win32_apply_ops;
#else
	return &unix_apply_ops;
#endif
}

static int
extract_trees(WIMStruct *wim, struct wim_dentry **trees, size_t num_trees,
	      const tchar *target, int extract_flags)
{
	const struct apply_operations *ops;
	struct apply_ctx *ctx;
	int ret;
	LIST_HEAD(dentry_list);

	if (extract_flags & WIMLIB_EXTRACT_FLAG_TO_STDOUT) {
		ret = extract_dentries_to_stdout(trees, num_trees,
						 wim->blob_table);
		goto out;
	}

	num_trees = remove_duplicate_trees(trees, num_trees);
	num_trees = remove_contained_trees(trees, num_trees);

	ops = select_apply_operations(extract_flags);

	if (num_trees > 1 && ops->single_tree_only) {
		ERROR("Extracting multiple directory trees "
		      "at once is not supported in %s extraction mode!",
		      ops->name);
		ret = WIMLIB_ERR_UNSUPPORTED;
		goto out;
	}

	ctx = CALLOC(1, ops->context_size);
	if (!ctx) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	ctx->wim = wim;
	ctx->target = target;
	ctx->target_nchars = tstrlen(target);
	ctx->extract_flags = extract_flags;
	if (ctx->wim->progfunc) {
		ctx->progfunc = ctx->wim->progfunc;
		ctx->progctx = ctx->wim->progctx;
		ctx->progress.extract.image = wim->current_image;
		ctx->progress.extract.extract_flags = (extract_flags &
						       WIMLIB_EXTRACT_MASK_PUBLIC);
		ctx->progress.extract.wimfile_name = wim->filename;
		ctx->progress.extract.image_name = wimlib_get_image_name(wim,
									 wim->current_image);
		ctx->progress.extract.target = target;
	}
	INIT_LIST_HEAD(&ctx->stream_list);
	filedes_invalidate(&ctx->tmpfile_fd);
	ctx->apply_ops = ops;

	ret = (*ops->get_supported_features)(target, &ctx->supported_features);
	if (ret)
		goto out_cleanup;

	build_dentry_list(&dentry_list, trees, num_trees,
			  !(extract_flags &
			    WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE));

	dentry_list_get_features(&dentry_list, &ctx->required_features);

	ret = do_feature_check(&ctx->required_features, &ctx->supported_features,
			       ctx->extract_flags);
	if (ret)
		goto out_cleanup;

	ret = dentry_list_calculate_extraction_names(&dentry_list, ctx);
	if (ret)
		goto out_cleanup;

	if (unlikely(list_empty(&dentry_list))) {
		WARNING("There is nothing to extract!");
		goto out_cleanup;
	}

	ret = dentry_list_resolve_streams(&dentry_list, ctx);
	if (ret)
		goto out_cleanup;

	dentry_list_build_inode_alias_lists(&dentry_list);

	ret = dentry_list_ref_streams(&dentry_list, ctx);
	if (ret)
		goto out_cleanup;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_FROM_PIPE) {
		/* When extracting from a pipe, the number of bytes of data to
		 * extract can't be determined in the normal way (examining the
		 * lookup table), since at this point all we have is a set of
		 * SHA1 message digests of streams that need to be extracted.
		 * However, we can get a reasonably accurate estimate by taking
		 * <TOTALBYTES> from the corresponding <IMAGE> in the WIM XML
		 * data.  This does assume that a full image is being extracted,
		 * but currently there is no API for doing otherwise.  (Also,
		 * subtract <HARDLINKBYTES> from this if hard links are
		 * supported by the extraction mode.)  */
		ctx->progress.extract.total_bytes =
			wim_info_get_image_total_bytes(wim->wim_info,
						       wim->current_image);
		if (ctx->supported_features.hard_links) {
			ctx->progress.extract.total_bytes -=
				wim_info_get_image_hard_link_bytes(wim->wim_info,
								   wim->current_image);
		}
	}

	ret = extract_progress(ctx,
			       ((extract_flags & WIMLIB_EXTRACT_FLAG_IMAGEMODE) ?
				       WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN :
				       WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN));
	if (ret)
		goto out_cleanup;

	ret = (*ops->extract)(&dentry_list, ctx);
	if (ret)
		goto out_cleanup;

	if (ctx->progress.extract.completed_bytes <
	    ctx->progress.extract.total_bytes)
	{
		ctx->progress.extract.completed_bytes =
			ctx->progress.extract.total_bytes;
		ret = extract_progress(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS);
		if (ret)
			goto out_cleanup;
	}

	ret = extract_progress(ctx,
			       ((extract_flags & WIMLIB_EXTRACT_FLAG_IMAGEMODE) ?
				       WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END :
				       WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END));
out_cleanup:
	destroy_stream_list(&ctx->stream_list);
	destroy_dentry_list(&dentry_list);
	FREE(ctx);
out:
	return ret;
}

static int
mkdir_if_needed(const tchar *target)
{
	if (!tmkdir(target, 0755))
		return 0;

	if (errno == EEXIST)
		return 0;

#ifdef __WIN32__
	/* _wmkdir() fails with EACCES if called on a drive root directory.  */
	if (errno == EACCES)
		return 0;
#endif

	ERROR_WITH_ERRNO("Failed to create directory \"%"TS"\"", target);
	return WIMLIB_ERR_MKDIR;
}

/* Make sure the extraction flags make sense, and update them if needed.  */
static int
check_extract_flags(const WIMStruct *wim, int *extract_flags_p)
{
	int extract_flags = *extract_flags_p;

	/* Check for invalid flag combinations  */

	if ((extract_flags &
	     (WIMLIB_EXTRACT_FLAG_NO_ACLS |
	      WIMLIB_EXTRACT_FLAG_STRICT_ACLS)) == (WIMLIB_EXTRACT_FLAG_NO_ACLS |
						    WIMLIB_EXTRACT_FLAG_STRICT_ACLS))
		return WIMLIB_ERR_INVALID_PARAM;

	if ((extract_flags &
	     (WIMLIB_EXTRACT_FLAG_RPFIX |
	      WIMLIB_EXTRACT_FLAG_NORPFIX)) == (WIMLIB_EXTRACT_FLAG_RPFIX |
						WIMLIB_EXTRACT_FLAG_NORPFIX))
		return WIMLIB_ERR_INVALID_PARAM;

#ifndef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		ERROR("wimlib was compiled without support for NTFS-3g, so\n"
		      "        it cannot apply a WIM image directly to an NTFS volume.");
		return WIMLIB_ERR_UNSUPPORTED;
	}
#endif

	if (extract_flags & WIMLIB_EXTRACT_FLAG_WIMBOOT) {
#ifdef __WIN32__
		if (!wim->filename)
			return WIMLIB_ERR_NO_FILENAME;
#else
		ERROR("WIMBoot extraction is only supported on Windows!");
		return WIMLIB_ERR_UNSUPPORTED;
#endif
	}


	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_RPFIX |
			      WIMLIB_EXTRACT_FLAG_NORPFIX |
			      WIMLIB_EXTRACT_FLAG_IMAGEMODE)) ==
					WIMLIB_EXTRACT_FLAG_IMAGEMODE)
	{
		/* For full-image extraction, do reparse point fixups by default
		 * if the WIM header says they are enabled.  */
		if (wim->hdr.flags & WIM_HDR_FLAG_RP_FIX)
			extract_flags |= WIMLIB_EXTRACT_FLAG_RPFIX;
	}

	*extract_flags_p = extract_flags;
	return 0;
}

static u32
get_wildcard_flags(int extract_flags)
{
	u32 wildcard_flags = 0;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_GLOB)
		wildcard_flags |= WILDCARD_FLAG_ERROR_IF_NO_MATCH;
	else
		wildcard_flags |= WILDCARD_FLAG_WARN_IF_NO_MATCH;

	if (default_ignore_case)
		wildcard_flags |= WILDCARD_FLAG_CASE_INSENSITIVE;

	return wildcard_flags;
}

struct append_dentry_ctx {
	struct wim_dentry **dentries;
	size_t num_dentries;
	size_t num_alloc_dentries;
};

static int
append_dentry_cb(struct wim_dentry *dentry, void *_ctx)
{
	struct append_dentry_ctx *ctx = _ctx;

	if (ctx->num_dentries == ctx->num_alloc_dentries) {
		struct wim_dentry **new_dentries;
		size_t new_length;

		new_length = max(ctx->num_alloc_dentries + 8,
				 ctx->num_alloc_dentries * 3 / 2);
		new_dentries = REALLOC(ctx->dentries,
				       new_length * sizeof(ctx->dentries[0]));
		if (new_dentries == NULL)
			return WIMLIB_ERR_NOMEM;
		ctx->dentries = new_dentries;
		ctx->num_alloc_dentries = new_length;
	}
	ctx->dentries[ctx->num_dentries++] = dentry;
	return 0;
}

static int
do_wimlib_extract_paths(WIMStruct *wim, int image, const tchar *target,
			const tchar * const *paths, size_t num_paths,
			int extract_flags)
{
	int ret;
	struct wim_dentry **trees;
	size_t num_trees;

	if (wim == NULL || target == NULL || target[0] == T('\0') ||
	    (num_paths != 0 && paths == NULL))
		return WIMLIB_ERR_INVALID_PARAM;

	ret = check_extract_flags(wim, &extract_flags);
	if (ret)
		return ret;

	ret = select_wim_image(wim, image);
	if (ret)
		return ret;

	ret = wim_checksum_unhashed_streams(wim);
	if (ret)
		return ret;

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_NTFS |
			      WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE)) ==
	    (WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE))
	{
		ret = mkdir_if_needed(target);
		if (ret)
			return ret;
	}

	if (extract_flags & WIMLIB_EXTRACT_FLAG_GLOB_PATHS) {

		struct append_dentry_ctx append_dentry_ctx = {
			.dentries = NULL,
			.num_dentries = 0,
			.num_alloc_dentries = 0,
		};

		u32 wildcard_flags = get_wildcard_flags(extract_flags);

		for (size_t i = 0; i < num_paths; i++) {
			tchar *path = canonicalize_wim_path(paths[i]);
			if (path == NULL) {
				ret = WIMLIB_ERR_NOMEM;
				trees = append_dentry_ctx.dentries;
				goto out_free_trees;
			}
			ret = expand_wildcard(wim, path,
					      append_dentry_cb,
					      &append_dentry_ctx,
					      wildcard_flags);
			FREE(path);
			if (ret) {
				trees = append_dentry_ctx.dentries;
				goto out_free_trees;
			}
		}
		trees = append_dentry_ctx.dentries;
		num_trees = append_dentry_ctx.num_dentries;
	} else {
		trees = MALLOC(num_paths * sizeof(trees[0]));
		if (trees == NULL)
			return WIMLIB_ERR_NOMEM;

		for (size_t i = 0; i < num_paths; i++) {

			tchar *path = canonicalize_wim_path(paths[i]);
			if (path == NULL) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_trees;
			}

			trees[i] = get_dentry(wim, path,
					      WIMLIB_CASE_PLATFORM_DEFAULT);
			FREE(path);
			if (trees[i] == NULL) {
				  ERROR("Path \"%"TS"\" does not exist "
					"in WIM image %d",
					paths[i], wim->current_image);
				  ret = WIMLIB_ERR_PATH_DOES_NOT_EXIST;
				  goto out_free_trees;
			}
		}
		num_trees = num_paths;
	}

	if (num_trees == 0) {
		ret = 0;
		goto out_free_trees;
	}

	ret = extract_trees(wim, trees, num_trees, target, extract_flags);
out_free_trees:
	FREE(trees);
	return ret;
}

static int
extract_single_image(WIMStruct *wim, int image,
		     const tchar *target, int extract_flags)
{
	const tchar *path = WIMLIB_WIM_ROOT_PATH;
	extract_flags |= WIMLIB_EXTRACT_FLAG_IMAGEMODE;
	return do_wimlib_extract_paths(wim, image, target, &path, 1, extract_flags);
}

static const tchar * const filename_forbidden_chars =
T(
#ifdef __WIN32__
"<>:\"/\\|?*"
#else
"/"
#endif
);

/* This function checks if it is okay to use a WIM image's name as a directory
 * name.  */
static bool
image_name_ok_as_dir(const tchar *image_name)
{
	return image_name && *image_name &&
		!tstrpbrk(image_name, filename_forbidden_chars) &&
		tstrcmp(image_name, T(".")) &&
		tstrcmp(image_name, T(".."));
}

/* Extracts all images from the WIM to the directory @target, with the images
 * placed in subdirectories named by their image names. */
static int
extract_all_images(WIMStruct *wim, const tchar *target, int extract_flags)
{
	size_t image_name_max_len = max(xml_get_max_image_name_len(wim), 20);
	size_t output_path_len = tstrlen(target);
	tchar buf[output_path_len + 1 + image_name_max_len + 1];
	int ret;
	int image;
	const tchar *image_name;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		ERROR("Cannot extract multiple images in NTFS extraction mode.");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	ret = mkdir_if_needed(target);
	if (ret)
		return ret;
	tmemcpy(buf, target, output_path_len);
	buf[output_path_len] = OS_PREFERRED_PATH_SEPARATOR;
	for (image = 1; image <= wim->hdr.image_count; image++) {
		image_name = wimlib_get_image_name(wim, image);
		if (image_name_ok_as_dir(image_name)) {
			tstrcpy(buf + output_path_len + 1, image_name);
		} else {
			/* Image name is empty or contains forbidden characters.
			 * Use image number instead. */
			tsprintf(buf + output_path_len + 1, T("%d"), image);
		}
		ret = extract_single_image(wim, image, buf, extract_flags);
		if (ret)
			return ret;
	}
	return 0;
}

static int
do_wimlib_extract_image(WIMStruct *wim, int image, const tchar *target,
			int extract_flags)
{
	if (extract_flags & (WIMLIB_EXTRACT_FLAG_NO_PRESERVE_DIR_STRUCTURE |
			     WIMLIB_EXTRACT_FLAG_TO_STDOUT |
			     WIMLIB_EXTRACT_FLAG_GLOB_PATHS))
		return WIMLIB_ERR_INVALID_PARAM;

	if (image == WIMLIB_ALL_IMAGES)
		return extract_all_images(wim, target, extract_flags);
	else
		return extract_single_image(wim, image, target, extract_flags);
}


/****************************************************************************
 *                          Extraction API                                  *
 ****************************************************************************/

WIMLIBAPI int
wimlib_extract_paths(WIMStruct *wim, int image, const tchar *target,
		     const tchar * const *paths, size_t num_paths,
		     int extract_flags)
{
	if (extract_flags & ~WIMLIB_EXTRACT_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;

	return do_wimlib_extract_paths(wim, image, target, paths, num_paths,
				       extract_flags);
}

WIMLIBAPI int
wimlib_extract_pathlist(WIMStruct *wim, int image, const tchar *target,
			const tchar *path_list_file, int extract_flags)
{
	int ret;
	tchar **paths;
	size_t num_paths;
	void *mem;

	ret = read_path_list_file(path_list_file, &paths, &num_paths, &mem);
	if (ret) {
		ERROR("Failed to read path list file \"%"TS"\"",
		      path_list_file);
		return ret;
	}

	ret = wimlib_extract_paths(wim, image, target,
				   (const tchar * const *)paths, num_paths,
				   extract_flags);
	FREE(paths);
	FREE(mem);
	return ret;
}

WIMLIBAPI int
wimlib_extract_image_from_pipe_with_progress(int pipe_fd,
					     const tchar *image_num_or_name,
					     const tchar *target,
					     int extract_flags,
					     wimlib_progress_func_t progfunc,
					     void *progctx)
{
	int ret;
	WIMStruct *pwm;
	struct filedes *in_fd;
	int image;
	unsigned i;

	if (extract_flags & ~WIMLIB_EXTRACT_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;

	/* Read the WIM header from the pipe and get a WIMStruct to represent
	 * the pipable WIM.  Caveats:  Unlike getting a WIMStruct with
	 * wimlib_open_wim(), getting a WIMStruct in this way will result in
	 * an empty lookup table, no XML data read, and no filename set.  */
	ret = open_wim_as_WIMStruct(&pipe_fd, WIMLIB_OPEN_FLAG_FROM_PIPE, &pwm,
				    progfunc, progctx);
	if (ret)
		return ret;

	/* Sanity check to make sure this is a pipable WIM.  */
	if (pwm->hdr.magic != PWM_MAGIC) {
		ERROR("The WIM being read from file descriptor %d "
		      "is not pipable!", pipe_fd);
		ret = WIMLIB_ERR_NOT_PIPABLE;
		goto out_wimlib_free;
	}

	/* Sanity check to make sure the first part of a pipable split WIM is
	 * sent over the pipe first.  */
	if (pwm->hdr.part_number != 1) {
		ERROR("The first part of the split WIM must be "
		      "sent over the pipe first.");
		ret = WIMLIB_ERR_INVALID_PIPABLE_WIM;
		goto out_wimlib_free;
	}

	in_fd = &pwm->in_fd;
	wimlib_assert(in_fd->offset == WIM_HEADER_DISK_SIZE);

	/* As mentioned, the WIMStruct we created from the pipe does not have
	 * XML data yet.  Fix this by reading the extra copy of the XML data
	 * that directly follows the header in pipable WIMs.  (Note: see
	 * write_pipable_wim() for more details about the format of pipable
	 * WIMs.)  */
	{
		struct blob_info xml_blob;
		struct wim_resource_spec xml_rspec;
		ret = read_pwm_stream_header(pwm, &xml_blob, &xml_rspec, 0, NULL);
		if (ret)
			goto out_wimlib_free;

		if (!(xml_blob.flags & WIM_RESHDR_FLAG_METADATA))
		{
			ERROR("Expected XML data, but found non-metadata "
			      "stream.");
			ret = WIMLIB_ERR_INVALID_PIPABLE_WIM;
			goto out_wimlib_free;
		}

		wim_res_spec_to_hdr(&xml_rspec, &pwm->hdr.xml_data_reshdr);

		ret = read_wim_xml_data(pwm);
		if (ret)
			goto out_wimlib_free;

		if (wim_info_get_num_images(pwm->wim_info) != pwm->hdr.image_count) {
			ERROR("Image count in XML data is not the same as in WIM header.");
			ret = WIMLIB_ERR_IMAGE_COUNT;
			goto out_wimlib_free;
		}
	}

	/* Get image index (this may use the XML data that was just read to
	 * resolve an image name).  */
	if (image_num_or_name) {
		image = wimlib_resolve_image(pwm, image_num_or_name);
		if (image == WIMLIB_NO_IMAGE) {
			ERROR("\"%"TS"\" is not a valid image in the pipable WIM!",
			      image_num_or_name);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out_wimlib_free;
		} else if (image == WIMLIB_ALL_IMAGES) {
			ERROR("Applying all images from a pipe is not supported!");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out_wimlib_free;
		}
	} else {
		if (pwm->hdr.image_count != 1) {
			ERROR("No image was specified, but the pipable WIM "
			      "did not contain exactly 1 image");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out_wimlib_free;
		}
		image = 1;
	}

	/* Load the needed metadata resource.  */
	for (i = 1; i <= pwm->hdr.image_count; i++) {
		struct blob_info *metadata_blob;
		struct wim_image_metadata *imd;
		struct wim_resource_spec *metadata_rspec;

		metadata_blob = new_blob_table_entry();
		if (metadata_blob == NULL) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_wimlib_free;
		}
		metadata_rspec = MALLOC(sizeof(struct wim_resource_spec));
		if (metadata_rspec == NULL) {
			ret = WIMLIB_ERR_NOMEM;
			free_blob_table_entry(metadata_blob);
			goto out_wimlib_free;
		}

		ret = read_pwm_stream_header(pwm, metadata_blob, metadata_rspec, 0, NULL);
		imd = pwm->image_metadata[i - 1];
		imd->metadata_blob = metadata_blob;
		if (ret) {
			FREE(metadata_rspec);
			goto out_wimlib_free;
		}

		if (!(metadata_blob->flags & WIM_RESHDR_FLAG_METADATA)) {
			ERROR("Expected metadata resource, but found "
			      "non-metadata stream.");
			ret = WIMLIB_ERR_INVALID_PIPABLE_WIM;
			goto out_wimlib_free;
		}

		if (i == image) {
			/* Metadata resource is for the image being extracted.
			 * Parse it and save the metadata in memory.  */
			ret = read_metadata_resource(imd);
			if (ret)
				goto out_wimlib_free;
			imd->modified = 1;
		} else {
			/* Metadata resource is not for the image being
			 * extracted.  Skip over it.  */
			ret = skip_wim_stream(metadata_blob);
			if (ret)
				goto out_wimlib_free;
		}
	}
	/* Extract the image.  */
	extract_flags |= WIMLIB_EXTRACT_FLAG_FROM_PIPE;
	ret = do_wimlib_extract_image(pwm, image, target, extract_flags);
	/* Clean up and return.  */
out_wimlib_free:
	wimlib_free(pwm);
	return ret;
}


WIMLIBAPI int
wimlib_extract_image_from_pipe(int pipe_fd, const tchar *image_num_or_name,
			       const tchar *target, int extract_flags)
{
	return wimlib_extract_image_from_pipe_with_progress(pipe_fd,
							    image_num_or_name,
							    target,
							    extract_flags,
							    NULL,
							    NULL);
}

WIMLIBAPI int
wimlib_extract_image(WIMStruct *wim, int image, const tchar *target,
		     int extract_flags)
{
	if (extract_flags & ~WIMLIB_EXTRACT_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;
	return do_wimlib_extract_image(wim, image, target, extract_flags);
}
