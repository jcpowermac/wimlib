#ifndef _WIMLIB_BLOB_TABLE_H
#define _WIMLIB_BLOB_TABLE_H

#include "wimlib/list.h"
#include "wimlib/resource.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

/* An enumerated type that identifies where the blob's data is actually located.
 *
 * If we open a WIM and read its blob table, the location is set to
 * RESOURCE_IN_WIM since all the blobs will initially be located in the WIM.
 * However, to handle situations such as image capture and image mount, we allow
 * the actual location of the blob to be somewhere else, such as an external
 * file.  */
enum resource_location {
	/* The blob's data does not exist.  This is a temporary state only.  */
	RESOURCE_NONEXISTENT = 0,

	/* The blob is located in a resource in a WIM file identified by the
	 * `struct wim_resource_spec' pointed to by @rspec.  @offset_in_res
	 * identifies the offset at which this particular blob begins in the
	 * uncompressed data of the resource; this is normally 0, but a WIM
	 * resource can be "solid" and contain multiple blobs.  */
	RESOURCE_IN_WIM,

	/* The blob is located in the external file named by @file_on_disk.
	 */
	RESOURCE_IN_FILE_ON_DISK,

	/* The blob is directly attached in the in-memory buffer pointed to by
	 * @attached_buffer.  */
	RESOURCE_IN_ATTACHED_BUFFER,

#ifdef WITH_FUSE
	/* The blob is located in the external file named by @staging_file_name,
	 * located in the staging directory for a read-write mount.  */
	RESOURCE_IN_STAGING_FILE,
#endif

#ifdef WITH_NTFS_3G
	/* The blob is located in an NTFS volume.  It is identified by volume,
	 * filename, data stream name, and by whether it is a reparse point or
	 * not.  @ntfs_loc points to a structure containing this information.
	 */
	RESOURCE_IN_NTFS_VOLUME,
#endif

#ifdef __WIN32__
	/* Windows only: the blob is located in the external file named by
	 * @file_on_disk, which is in the Windows NT namespace and may specify a
	 * named data stream.  */
	RESOURCE_IN_WINNT_FILE_ON_DISK,

	/* Windows only: the blob is located in the external file named by
	 * @file_on_disk, but the file is encrypted and must be read using the
	 * appropriate Windows API.  */
	RESOURCE_WIN32_ENCRYPTED, 
#endif
};

struct blob_owner {
	struct wim_inode *inode;
	struct wim_attribute *attr;
};

/*
 * Specification for a blob, which is a nonempty sequence of binary data with a
 * fixed size.
 */
struct blob {

	/* List node for a hash bucket of the blob table.  */
	struct hlist_node hash_list;

	/* Uncompressed size of this blob.  */
	u64 size;

	/* Blob flags (WIM_RESHDR_FLAG_*).  */
	u32 flags : 8;

	/* One of the `enum resource_location' values documented above.  */
	u32 resource_location : 4;

	/* 1 if this blob has not had a SHA-1 message digest calculated for it
	 * yet.  */
	u32 unhashed : 1;

	/* Temoorary fields used when writing blobs; set as documented for
	 * prepare_blob_list_for_write().  */
	u32 unique_size : 1;
	u32 will_be_in_output_wim : 1;

	/* Set to 1 when a metadata entry has its checksum changed; in such
	 * cases the hash cannot be used to verify the data if the metadata
	 * resource is read again.  (This could be avoided if we used separate
	 * fields for input/output checksum, but most blobs wouldn't need this.)
	 * */
	u32 dont_check_metadata_hash : 1;

	u32 may_send_done_with_file : 1;

	/* Only used by wimlib_export_image() */
	u32 was_exported : 1;

	union {
		/* SHA-1 message digest of the blob's data.  */
		u8 hash[SHA1_HASH_SIZE];

		/* First 4 or 8 bytes of the SHA-1 message digest, used for
		 * inserting the entry into the hash table.  Since the SHA-1
		 * message digest can be considered random, we don't really need
		 * the full 20 byte hash just to insert the entry in a hash
		 * table.  */
		size_t hash_short;

		/* Unhashed entries only (unhashed == 1): these variables make
		 * it possible to find the attribute that references this blob.
		 * There can be at most 1 such pointer, as we can only join
		 * duplicate blobs after they have been hashed.  */
		struct {
			struct wim_inode *back_inode;
			u32 back_attr_id;
		};
	};

	/* Number of times this blob is referenced by dentries in the WIM.  See
	 * blob_decrement_refcnt() for information about the limitations of this
	 * field.  */
	u32 refcnt;

	/* When a WIM file is written, this is set to the number of references
	 * (by dentries) to this blob in the output WIM file.
	 *
	 * During extraction, this is the number of slots in blob_owners (or
	 * inline_blob_owners) that have been filled.
	 *
	 * During image export, this is set to the number of references of this
	 * blob that originated from the source WIM.
	 *
	 * When mounting a WIM image read-write, this is set to the number of
	 * extra references to this blob preemptively taken to allow later
	 * saving the modified image as a new image and leaving the original
	 * image alone.  */
	u32 out_refcnt;

#ifdef WITH_FUSE
	/* Number of open file descriptors to this blob during a FUSE mount of
	 * the containing image.  */
	u16 num_opened_fds;
#endif

	/* Specification of where this blob is actually located.  Which member
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

	/* Links together blobs that share the same underlying WIM resource.
	 * The head is the `blob_list' member of `struct wim_resource_spec'.
	 */
	struct list_head rspec_node;

	/* Temporary fields  */
	union {
		/* Fields used temporarily during WIM file writing.  */
		struct {
			union {
				/* List node used for blob size table.  */
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

			/* Links blobs being written to the WIM.  */
			struct list_head write_blobs_list;

			union {
				/* Metadata for this blob in the WIM being
				 * written.  */
				struct wim_reshdr out_reshdr;

				struct {
					/* Name under which this blob is being
					 * sorted; used only when sorting blobs
					 * for solid compression.  */
					utf16lechar *solid_sort_name;
					size_t solid_sort_name_nbytes;
				};
			};
		};

		/* Used temporarily during extraction.  This is an array of
		 * references to the attributes being extracted that use this
		 * blob.  out_refcnt tracks the number of slots filled.  */
		union {
			struct blob_owner inline_blob_owners[3];
			struct {
				struct blob_owner *blob_owners;
				u32 alloc_blob_owners;
			};
		};
	};

	/* Temporary list fields.  */
	union {
		/* Links blobs for writing blob table.  */
		struct list_head blob_table_list;

		/* Links blobs being extracted.  */
		struct list_head extraction_list;

		/* Links blobs being exported.  */
		struct list_head export_blob_list;

		/* Links original list of blobs in the read-write mounted image.  */
		struct list_head orig_blob_list;
	};

	/* Links blobs that are still unhashed after being been added to a WIM.
	 */
	struct list_head unhashed_list;
};

/* Functions to allocate and free blob tables  */

extern struct blob_table *
new_blob_table(size_t capacity) _malloc_attribute;

extern void
free_blob_table(struct blob_table *table);

/* Functions to read or write the blob table from/to a WIM file  */

extern int
read_blob_table(WIMStruct *wim);

extern int
write_blob_table_from_blob_list(struct list_head *blob_list,
					struct filedes *out_fd,
					u16 part_number,
					struct wim_reshdr *out_reshdr,
					int write_resource_flags);

/* Functions to create, clone, print, and free blob table entries  */

extern struct blob *
new_blob(void) _malloc_attribute;

extern struct blob *
clone_blob(const struct blob *blob)
			_malloc_attribute;

extern void
blob_decrement_refcnt(struct blob *blob,
		     struct blob_table *table);
#ifdef WITH_FUSE
extern void
blob_decrement_num_opened_fds(struct blob *blob);
#endif

extern void
free_blob(struct blob *blob);

/* Functions to insert and delete entries from a blob table  */

extern void
blob_table_insert(struct blob_table *table, struct blob *blob);

extern void
blob_table_unlink(struct blob_table *table, struct blob *blob);

/* Function to lookup a blob by SHA-1 message digest  */
extern struct blob *
lookup_blob(const struct blob_table *table, const u8 hash[]);

/* Functions to iterate through the entries of a blob table  */

extern int
for_blob_in_table(struct blob_table *table,
	 int (*visitor)(struct blob *, void *), void *arg);

extern int
for_blob_pos_sorted(struct blob_table *table,
		    int (*visitor)(struct blob *, void *), void *arg);

/* Function to get a "resource entry" (should be called "blob entry") in stable
 * format  */

struct wimlib_resource_entry;

extern void
blob_to_wimlib_resource_entry(const struct blob *blob,
			      struct wimlib_resource_entry *wentry);

/* Functions to sort a list of blobs  */
extern int
sort_blob_list(struct list_head *blob_list,
	       size_t list_head_offset,
	       int (*compar)(const void *, const void*));

extern int
sort_blob_list_by_sequential_order(struct list_head *blob_list,
				   size_t list_head_offset);

extern int
cmp_blobs_by_sequential_order(const void *p1, const void *p2);

/* Utility functions  */

extern int
blob_zero_out_refcnt(struct blob *blob, void *ignore);

static inline bool
blob_is_in_solid_wim_resource(const struct blob * blob)
{
	return blob->resource_location == RESOURCE_IN_WIM &&
	       blob->size != blob->rspec->uncompressed_size;
}

static inline bool
blob_is_in_file(const struct blob *blob)
{
	return blob->resource_location == RESOURCE_IN_FILE_ON_DISK
#ifdef __WIN32__
	    || blob->resource_location == RESOURCE_IN_WINNT_FILE_ON_DISK
	    || blob->resource_location == RESOURCE_WIN32_ENCRYPTED
#endif
	   ;
}

static inline const struct blob_owner *
blob_owners(struct blob *blob)
{
	if (blob->out_refcnt <= ARRAY_LEN(blob->inline_blob_owners))
		return blob->inline_blob_owners;
	else
		return blob->blob_owners;
}

static inline void
blob_bind_wim_resource_spec(struct blob *blob, struct wim_resource_spec *rspec)
{
	blob->resource_location = RESOURCE_IN_WIM;
	blob->rspec = rspec;
	list_add_tail(&blob->rspec_node, &rspec->blob_list);
}

static inline void
blob_unbind_wim_resource_spec(struct blob *blob)
{
	list_del(&blob->rspec_node);
	blob->resource_location = RESOURCE_NONEXISTENT;
}

extern void
blob_put_resource(struct blob *blob);

extern struct blob *
new_blob_from_data_buffer(const void *buffer, size_t size,
			  struct blob_table *blob_table);

static inline void
add_unhashed_blob(struct blob *blob,
		  struct wim_inode *back_inode,
		  u32 back_attr_id,
		  struct list_head *unhashed_blobs)
{
	blob->unhashed = 1;
	blob->back_inode = back_inode;
	blob->back_attr_id = back_attr_id;
	list_add_tail(&blob->unhashed_list, unhashed_blobs);
}

extern int
hash_unhashed_blob(struct blob *blob,
		   struct blob_table *blob_table,
		   struct blob **lte_ret);

extern struct blob **
retrieve_blob_pointer(struct blob *blob);

#endif /* _WIMLIB_BLOB_TABLE_H */
