#ifndef _WIMLIB_LOOKUP_TABLE_H
#define _WIMLIB_LOOKUP_TABLE_H

#include "wimlib/list.h"
#include "wimlib/resource.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

/* An enumerated type that identifies where the stream corresponding to this
 * blob table entry is actually located.
 *
 * If we open a WIM and read its lookup table, the location is set to
 * RESOURCE_IN_WIM since all the streams will initially be located in the WIM.
 * However, to handle situations such as image capture and image mount, we allow
 * the actual location of the stream to be somewhere else, such as an external
 * file.  */
enum resource_location {
	/* The blob table entry does not yet correspond to a stream; this is a
	 * temporary state only.  */
	RESOURCE_NONEXISTENT = 0,

	/* The stream is located in a resource in a WIM file identified by the
	 * `struct wim_resource_spec' pointed to by @rspec.  @offset_in_res
	 * identifies the offset at which this particular stream begins in the
	 * uncompressed data of the resource; this is normally 0, but in general
	 * a WIM resource may be "solid" and potentially contain multiple
	 * streams.  */
	RESOURCE_IN_WIM,

	/* The stream is located in the external file named by @file_on_disk.
	 */
	RESOURCE_IN_FILE_ON_DISK,

	/* The stream is directly attached in the in-memory buffer pointed to by
	 * @attached_buffer.  */
	RESOURCE_IN_ATTACHED_BUFFER,

#ifdef WITH_FUSE
	/* The stream is located in the external file named by
	 * @staging_file_name, located in the staging directory for a read-write
	 * mount.  */
	RESOURCE_IN_STAGING_FILE,
#endif

#ifdef WITH_NTFS_3G
	/* The stream is located in an NTFS volume.  It is identified by volume,
	 * filename, data stream name, and by whether it is a reparse point or
	 * not.  @ntfs_loc points to a structure containing this information.
	 * */
	RESOURCE_IN_NTFS_VOLUME,
#endif

#ifdef __WIN32__
	/* Windows only: the stream is located in the external file named by
	 * @file_on_disk, which is in the Windows NT namespace and may specify a
	 * named data stream.  */
	RESOURCE_IN_WINNT_FILE_ON_DISK,

	/* Windows only: the stream is located in the external file named by
	 * @file_on_disk, but the file is encrypted and must be read using the
	 * appropriate Windows API.  */
	RESOURCE_WIN32_ENCRYPTED,
#endif
};

struct stream_owner {
	struct wim_inode *inode;
	const utf16lechar *stream_name;
};

/* Specification for a stream, which may be the contents of a file (unnamed data
 * stream), a named data stream, reparse point data, or a WIM metadata resource.
 *
 * One instance of this structure is created for each entry in the WIM's lookup
 * table, hence the name of the struct.  Each of these entries contains the SHA1
 * message digest of a stream and the location of the stream data in the WIM
 * file (size, location, flags).  The in-memory lookup table is a map from SHA1
 * message digests to stream locations.  */
struct blob_info {

	/* List node for a hash bucket of the lookup table.  */
	struct hlist_node b_hash_list;

	/* Uncompressed size of this stream.  */
	u64 b_size;

	/* Stream flags (WIM_RESHDR_FLAG_*).  */
	u32 b_flags : 8;

	/* One of the `enum resource_location' values documented above.  */
	u32 resource_location : 4;

	/* 1 if this stream has not had a SHA1 message digest calculated for it
	 * yet.  */
	u32 b_unhashed : 1;

	/* Temoorary fields used when writing streams; set as documented for
	 * prepare_blob_list_for_write().  */
	u32 unique_size : 1;
	u32 will_be_in_output_wim : 1;

	/* Set to 1 when a metadata entry has its checksum changed; in such
	 * cases the hash cannot be used to verify the data if the metadata
	 * resource is read again.  (This could be avoided if we used separate
	 * fields for input/output checksum, but most stream entries wouldn't
	 * need this.)  */
	u32 dont_check_metadata_hash : 1;

	u32 may_send_done_with_file : 1;

	/* Only used by wimlib_export_image() */
	u32 was_exported : 1;

	union {
		/* (On-disk field) SHA1 message digest of the stream referenced
		 * by this blob table entry.  */
		u8  hash[SHA1_HASH_SIZE];

		/* First 4 or 8 bytes of the SHA1 message digest, used for
		 * inserting the entry into the hash table.  Since the SHA1
		 * message digest can be considered random, we don't really need
		 * the full 20 byte hash just to insert the entry in a hash
		 * table.  */
		size_t hash_short;

		/* Unhashed entries only (unhashed == 1): these variables make
		 * it possible to find the pointer to this 'struct
		 * blob_info' contained in either 'struct
		 * wim_ads_entry' or 'struct wim_inode'.  There can be at most 1
		 * such pointer, as we can only join duplicate streams after
		 * they have been hashed.  */
		struct {
			struct wim_inode *back_inode;
			u32 back_stream_id;
		};
	};

	/* Number of times this blob table entry is referenced by dentries in
	 * the WIM.  When a WIM's lookup table is read, this field is
	 * initialized from a corresponding entry.
	 *
	 * However, see blob_decrement_refcnt() for information about the
	 * limitations of this field.  */
	u32 refcnt;

	/* When a WIM file is written, this is set to the number of references
	 * (by dentries) to this stream in the output WIM file.
	 *
	 * During extraction, this is the number of slots in stream_owners (or
	 * inline_stream_owners) that have been filled.
	 *
	 * During image export, this is set to the number of references of this
	 * stream that originated from the source WIM.
	 *
	 * When mounting a WIM image read-write, this is set to the number of
	 * extra references to this stream preemptively taken to allow later
	 * saving the modified image as a new image and leaving the original
	 * image alone.  */
	u32 out_refcnt;

#ifdef WITH_FUSE
	/* Number of open file descriptors to this stream during a FUSE mount of
	 * the containing image.  */
	u16 num_opened_fds;
#endif

	/* Specification of where this stream is actually located.  Which member
	 * is valid is determined by the @resource_location field.  */
	union {
		struct {
			struct wim_resource_spec *rspec;
			u64 offset_in_res;
		};
		struct {
			tchar *file_on_disk;
			struct wim_inode *file_inode;
		};
		void *attached_buffer;
	#ifdef WITH_FUSE
		struct {
			char *staging_file_name;
			int staging_dir_fd;
		};
	#endif
	#ifdef WITH_NTFS_3G
		struct ntfs_location *ntfs_loc;
	#endif
	};

	/* Links together streams that share the same underlying WIM resource.
	 * The head is the `blob_list' member of `struct wim_resource_spec'.
	 */
	struct list_head rspec_node;

	/* Temporary fields  */
	union {
		/* Fields used temporarily during WIM file writing.  */
		struct {
			union {
				/* List node used for stream size table.  */
				struct hlist_node hash_list_2;

				/* Metadata for the underlying solid resource in
				 * the WIM being written (only valid if
				 * WIM_RESHDR_FLAG_SOLID set in
				 * out_reshdr.flags).  */
				struct {
					u64 out_res_offset_in_wim;
					u64 out_res_size_in_wim;
					u64 out_res_uncompressed_size;
				};
			};

			/* Links streams being written to the WIM.  */
			struct list_head write_streams_list;

			/* Metadata for this stream in the WIM being written.
			 */
			struct wim_reshdr out_reshdr;
		};

		/* Used temporarily during extraction.  This is an array of
		 * pointers to the inodes being extracted that use this stream.
		 */
		union {
			/* Inodes to extract that reference this stream.
			 * out_refcnt tracks the number of slots filled.  */
			struct stream_owner inline_stream_owners[3];
			struct {
				struct stream_owner *stream_owners;
				u32 alloc_stream_owners;
			};
		};
	};

	/* Temporary list fields.  */
	union {
		/* Links streams for writing lookup table.  */
		struct list_head blob_table_list;

		/* Links streams being extracted.  */
		struct list_head extraction_list;

		/* Links streams being exported.  */
		struct list_head export_blob_list;

		/* Links original list of streams in the read-write mounted image.  */
		struct list_head orig_blob_list;
	};

	/* Links streams that are still unhashed after being been added to a
	 * WIM.  */
	struct list_head b_unhashed_list;
};

/* Functions to allocate and free lookup tables  */

extern struct blob_table *
new_blob_table(size_t capacity) _malloc_attribute;

extern void
free_blob_table(struct blob_table *table);

/* Functions to read or write the lookup table from/to a WIM file  */

extern int
read_blob_table(WIMStruct *wim);

extern int
write_blob_table_from_blob_list(struct list_head *blob_list,
					struct filedes *out_fd,
					u16 part_number,
					struct wim_reshdr *out_reshdr,
					int write_resource_flags);

/* Functions to create, clone, print, and free lookup table entries  */

extern struct blob_info *
new_blob_info(void) _malloc_attribute;

extern struct blob_info *
clone_blob_info(const struct blob_info *blob)
			_malloc_attribute;

extern void
blob_decrement_refcnt(struct blob_info *blob,
		     struct blob_table *table);
#ifdef WITH_FUSE
extern void
blob_decrement_num_opened_fds(struct blob_info *blob);
#endif

extern void
free_blob_info(struct blob_info *blob);

/* Functions to insert and delete entries from a lookup table  */

extern void
blob_table_insert(struct blob_table *table,
		struct blob_info *blob);

extern void
blob_table_unlink(struct blob_table *table,
		    struct blob_info *blob);

/* Function to lookup a stream by SHA1 message digest  */
extern struct blob_info *
lookup_blob(const struct blob_table *table, const u8 hash[]);

/* Functions to iterate through the entries of a lookup table  */

extern int
for_blob_info(struct blob_table *table,
		       int (*visitor)(struct blob_info *, void *),
		       void *arg);

extern int
for_blob_info_pos_sorted(struct blob_table *table,
				  int (*visitor)(struct blob_info *,
						 void *),
				  void *arg);



/* Function to get a resource entry in stable format  */

struct wimlib_resource_entry;

extern void
blob_to_wimlib_resource_entry(const struct blob_info *blob,
			     struct wimlib_resource_entry *wentry);

/* Functions to sort a list of lookup table entries  */
extern int
sort_blob_list(struct list_head *blob_list,
		 size_t list_head_offset,
		 int (*compar)(const void *, const void*));

extern int
sort_blob_list_by_sequential_order(struct list_head *blob_list,
				     size_t list_head_offset);

/* Utility functions  */

extern int
blob_zero_out_refcnt(struct blob_info *blob, void *ignore);

static inline bool
blob_is_partial(const struct blob_info * blob)
{
	return blob->resource_location == RESOURCE_IN_WIM &&
	       blob->b_size != blob->rspec->uncompressed_size;
}

static inline const struct stream_owner *
stream_owners(struct blob_info *stream)
{
	if (stream->out_refcnt <= ARRAY_LEN(stream->inline_stream_owners))
		return stream->inline_stream_owners;
	else
		return stream->stream_owners;
}

static inline void
blob_bind_wim_resource_spec(struct blob_info *blob,
			   struct wim_resource_spec *rspec)
{
	blob->resource_location = RESOURCE_IN_WIM;
	blob->rspec = rspec;
	list_add_tail(&blob->rspec_node, &rspec->blob_list);
}

static inline void
blob_unbind_wim_resource_spec(struct blob_info *blob)
{
	list_del(&blob->rspec_node);
	blob->resource_location = RESOURCE_NONEXISTENT;
}

extern void
blob_put_resource(struct blob_info *blob);

extern struct blob_info *
new_stream_from_data_buffer(const void *buffer, size_t size,
			    struct blob_table *blob_table);

static inline void
add_unhashed_blob(struct blob_info *blob,
		    struct wim_inode *back_inode,
		    u32 back_stream_id,
		    struct list_head *unhashed_blobs)
{
	blob->b_unhashed = 1;
	blob->back_inode = back_inode;
	blob->back_stream_id = back_stream_id;
	list_add_tail(&blob->b_unhashed_list, unhashed_blobs);
}

extern int
hash_unhashed_blob(struct blob_info *blob,
		     struct blob_table *blob_table,
		     struct blob_info **blob_ret);

extern struct blob_info **
retrieve_blob_pointer(struct blob_info *blob);

#endif /* _WIMLIB_LOOKUP_TABLE_H */
