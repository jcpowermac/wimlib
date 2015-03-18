/*
 * wim.h - WIMStruct definition and helper functions
 */

#ifndef _WIMLIB_WIM_H
#define _WIMLIB_WIM_H

#include "wimlib.h"
#include "wimlib/file_io.h"
#include "wimlib/header.h"
#include "wimlib/list.h"

struct wim_image_metadata;
struct wim_info;
struct blob_table;

/*
 * WIMStruct - represents a WIM, or a part of a non-standalone WIM
 *
 * Note 1: there are three ways in which a WIMStruct can be created:
 *
 *	1. open an on-disk WIM file
 *	2. start to extract a pipable WIM from a file descriptor
 *	3. create a new WIMStruct directly
 *
 * For (1) and (2), the WIMStruct has a backing file; for (3) it does not.  For
 * (1), the backing file is a real "on-disk" file from the filesystem, whereas
 * for (2) the backing file is a file descriptor which may be a pipe.
 *
 * Note 2: although this is the top-level data structure in wimlib, there do
 * exist cases in which a WIMStruct is not standalone:
 *	- streams have been referenced from another WIMStruct
 *	- an image has been imported into this WIMStruct from another
 *	  (as this references the metadata rather than copies it)
 *
 * Note 3: It is unsafe for multiple threads to operate on the same WIMStruct at
 * the same time.  This extends to references to other WIMStructs as noted
 * above.  But besides this, it is safe to operate on *different* WIMStructs in
 * different threads concurrently.
 */
struct WIMStruct {

	/* Information from the header of the WIM file.
	 *
	 * This is also maintained for a WIMStruct not backed by a file, but the
	 * 'reshdr' fields have no meaning.  */
	struct wim_header hdr;

	/* Array of image metadata, one for each image in the WIM (array length
	 * hdr.image_count).  Or, this will be NULL if this WIM does not contain
	 * metadata, which implies that this WIMStruct either represents part of
	 * a non-standalone WIM, or represents a standalone WIM that, oddly
	 * enough, actually contains 0 images.  */
	struct wim_image_metadata **image_metadata;

	/* Information from the XML data of the WIM file.  This information is
	 * also maintained for a WIMStruct not backed by a file.  */
	struct wim_info *wim_info;

	/* The blob table for this WIMStruct.  If this WIMStruct has a backing
	 * file, then this table will index the streams contained in that file.
	 * In addition, this table may index streams that were added by updates
	 * or referenced from other WIMStructs.  */
	struct blob_table *blob_table;

	/*
	 * The 1-based index of the currently selected image in this WIMStruct,
	 * or WIMLIB_NO_IMAGE if no image is currently selected.
	 *
	 * The metadata for the current image is image_metadata[current_image -
	 * 1].  Since we load image metadata lazily, only the metadata for the
	 * current image is guaranteed to actually be present in memory.
	 */
	int current_image;

	/* The absolute path to the on-disk file backing this WIMStruct, or NULL
	 * if this WIMStruct is not backed by an on-disk file.  */
	tchar *filename;

	/* If this WIMStruct has a backing file, then this is a file descriptor
	 * open to that file with read access.  Otherwise, this field is invalid
	 * (!filedes_valid(&in_fd)).  */
	struct filedes in_fd;

	/* If the library is currently writing this WIMStruct out to a file,
	 * then this is a file descriptor open to that file with write access.
	 * Otherwise, this field is invalid (!filedes_valid(&out_fd)).  */
	struct filedes out_fd;

	/*
	 * This is the cached decompressor for this WIM file, or NULL if no
	 * decompressor is cached yet.  Normally, all the compressed data in a
	 * WIM file has the same compression type and chunk size, so the same
	 * decompressor can be used for all data --- and that decompressor will
	 * be cached here.  However, if we do encounter any data with a
	 * different compression type or chunk size (this is possible in solid
	 * resources), then this cached decompressor will be replaced with a new
	 * one.
	 */
	struct wimlib_decompressor *decompressor;
	u8 decompressor_ctype;
	u32 decompressor_max_block_size;

	/*
	 * 'subwims' is the list of dependent WIMStructs (linked by
	 * 'subwim_node') that have been opened by calls to
	 * wimlib_reference_resource_files().  These WIMStructs must be retained
	 * so that resources from them can be used.  They are internal to the
	 * library and are not visible to API users.
	 */
	struct list_head subwims;
	struct list_head subwim_node;

	/* Temporary field; use sparingly  */
	void *private;

	/* 1 if any images have been deleted from this WIMStruct, otherwise 0 */
	u8 image_deletion_occurred : 1;

	/* 1 if the WIM file has been locked for appending, otherwise 0  */
	u8 locked_for_append : 1;

	/* If this WIM is backed by a file, then this is the compression type
	 * for non-solid resources in that file.  */
	u8 compression_type;

	/* Overridden compression type for wimlib_overwrite() or wimlib_write().
	 * Can be changed by wimlib_set_output_compression_type(); otherwise is
	 * the same as compression_type.  */
	u8 out_compression_type;

	/* Compression type for writing solid resources; can be set with
	 * wimlib_set_output_pack_compression_type().  */
	u8 out_solid_compression_type;

	/* If this WIM is backed by a file, then this is the compression chunk
	 * size for non-solid resources in that file.  */
	u32 chunk_size;

	/* Overridden chunk size for wimlib_overwrite() or wimlib_write().  Can
	 * be changed by wimlib_set_output_chunk_size(); otherwise is the same
	 * as chunk_size.  */
	u32 out_chunk_size;

	/* Chunk size for writing solid resources; can be set with
	 * wimlib_set_output_pack_chunk_size().  */
	u32 out_solid_chunk_size;

	/* Currently registered progress function for this WIMStruct, or NULL if
	 * no progress function is currently registered for this WIMStruct.  */
	wimlib_progress_func_t progfunc;
	void *progctx;
};

/*
 * Return true if and only if the WIM contains image metadata (actual directory
 * trees, not just a collection of streams and their checksums).
 *
 * See the description of the 'image_metadata' field.  Note that we return true
 * when the image count is 0 because it could be a WIM with 0 images.  It's only
 * when the WIM does not contain the metadata described by its image count that
 * we return false.
 */
static inline bool wim_has_metadata(const WIMStruct *wim)
{
	return (wim->image_metadata != NULL || wim->hdr.image_count == 0);
}

/* Return true if and only if the WIM has an integrity table.
 *
 * If the WIM is not backed by a file, then this always returns false.  */
static inline bool wim_has_integrity_table(const WIMStruct *wim)
{
	return (wim->hdr.integrity_table_reshdr.offset_in_wim != 0);
}

/* Return true if and only if the WIM is in pipable format.
 *
 * If the WIM is not backed by a file, then this always returns false.  */
static inline bool wim_is_pipable(const WIMStruct *wim)
{
	return (wim->hdr.magic == PWM_MAGIC);
}

extern int
set_wim_hdr_cflags(int ctype, struct wim_header *hdr);

extern int
init_wim_header(struct wim_header *hdr, int ctype, u32 chunk_size);

extern int
read_wim_header(WIMStruct *wim, struct wim_header *hdr);

extern int
write_wim_header(const struct wim_header *hdr, struct filedes *out_fd);

extern int
write_wim_header_at_offset(const struct wim_header *hdr, struct filedes *out_fd,
			   off_t offset);

extern int
write_wim_header_flags(u32 hdr_flags, struct filedes *out_fd);

extern int
select_wim_image(WIMStruct *wim, int image);

extern void
deselect_current_wim_image(WIMStruct *wim);

extern int
for_image(WIMStruct *wim, int image, int (*visitor)(WIMStruct *));

extern int
wim_checksum_unhashed_blobs(WIMStruct *wim);

extern int
delete_wim_image(WIMStruct *wim, int image);

/* Internal open flags (pass to open_wim_as_WIMStruct(), not wimlib_open_wim())
 */
#define WIMLIB_OPEN_FLAG_FROM_PIPE	0x80000000

extern int
open_wim_as_WIMStruct(const void *wim_filename_or_fd, int open_flags,
		      WIMStruct **wim_ret,
		      wimlib_progress_func_t progfunc, void *progctx);

extern int
can_modify_wim(WIMStruct *wim);

#endif /* _WIMLIB_WIM_H */
