#ifndef _WIMLIB_INODE_H
#define _WIMLIB_INODE_H

#include "wimlib/list.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

struct avl_tree_node;
struct wim_ads_entry;
struct wim_dentry;
struct wim_blob_table;
struct blob_info;
struct wim_security_data;
struct wimfs_fd;

/*
 * WIM inode.
 *
 * As mentioned in the comment above `struct wim_dentry', in WIM files there
 * is no on-disk analogue of a real inode, as most of these fields are
 * duplicated in the dentries.  Instead, a `struct wim_inode' is something we
 * create ourselves to simplify the handling of hard links.
 */
struct wim_inode {
	/* If i_resolved == 0:
	 *	SHA1 message digest of the contents of the unnamed-data stream
	 *	of this inode.
	 *
	 * If i_resolved == 1:
	 *	Pointer to the lookup table entry for the unnamed data stream
	 *	of this inode, or NULL.
	 *
	 * i_hash corresponds to the 'unnamed_stream_hash' field of the `struct
	 * wim_dentry_on_disk' and the additional caveats documented about that
	 * field apply here (for example, the quirks regarding all-zero hashes).
	 */
	union {
		u8 i_hash[SHA1_HASH_SIZE];
		struct blob_info *i_blob;
	};

	/* Corresponds to the 'attributes' field of `struct wim_dentry_on_disk';
	 * bitwise OR of the FILE_ATTRIBUTE_* flags that give the attributes of
	 * this inode. */
	u32 i_attributes;

	/* Root of a balanced binary search tree storing the child directory
	 * entries of this inode, if any.  Keyed by wim_dentry->file_name, case
	 * sensitively.  If this inode is not a directory or if it has no
	 * children then this will be an empty tree (NULL).  */
	struct avl_tree_node *i_children;

	/* Root of a balanced binary search tree storing the child directory
	 * entries of this inode, if any.  Keyed by wim_dentry->file_name, case
	 * insensitively.  If this inode is not a directory or if it has no
	 * children then this will be an empty tree (NULL).  */
	struct avl_tree_node *i_children_ci;

	/* List of dentries that are aliases for this inode.  There will be
	 * i_nlink dentries in this list.  */
	struct list_head i_dentry;

	/* Field to place this inode into a list. */
	union {
		/* Hash list node- used in inode_fixup.c when the inodes are
		 * placed into a hash table keyed by inode number and optionally
		 * device number, in order to detect dentries that are aliases
		 * for the same inode. */
		struct hlist_node i_hlist;

		/* Normal list node- used to connect all the inodes of a WIM
		 * image into a single linked list referenced from the `struct
		 * wim_image_metadata' for that image. */
		struct list_head i_list;
	};

	/* Number of dentries that are aliases for this inode.  */
	u32 i_nlink;

	/* Number of alternate data streams (ADS) associated with this inode */
	u16 i_num_ads;

	/* Flag that indicates whether this inode's streams have been
	 * "resolved".  By default, the inode starts as "unresolved", meaning
	 * that the i_hash field, along with the hash field of any associated
	 * wim_ads_entry's, are valid and should be used as keys in the WIM
	 * lookup table to find the associated `struct blob_info'.  But if the
	 * inode has been resolved, then each of these fields is replaced with a
	 * pointer directly to the appropriate `struct blob_info', or NULL if
	 * the stream is empty.  */
	u8 i_resolved : 1;

	/* Flag used to mark this inode as visited; this is used when visiting
	 * all the inodes in a dentry tree exactly once.  It will be 0 by
	 * default and must be cleared following the tree traversal, even in
	 * error paths.  */
	u8 i_visited : 1;

	/* 1 iff all ADS entries of this inode are named or if this inode
	 * has no ADS entries  */
	u8 i_canonical_streams : 1;

	/* Cached value  */
	u8 i_can_externally_back : 1;

	/* Pointer to a malloc()ed array of i_num_ads alternate data stream
	 * entries for this inode.  */
	struct wim_ads_entry *i_ads_entries;

	/* If not NULL, a pointer to the extra data that was read from the
	 * dentry.  This should be a series of tagged items, each of which
	 * represents a bit of extra metadata, such as the file's object ID.
	 * See tagged_items.c for more information.  */
	void *i_extra;

	/* Size of @i_extra buffer in bytes.  If 0, there is no extra data.  */
	size_t i_extra_size;

	/* Creation time, last access time, and last write time for this inode,
	 * in 100-nanosecond intervals since 12:00 a.m UTC January 1, 1601.
	 * They should correspond to the times gotten by calling GetFileTime()
	 * on Windows. */
	u64 i_creation_time;
	u64 i_last_access_time;
	u64 i_last_write_time;

	/* Corresponds to 'security_id' in `struct wim_dentry_on_disk':  The
	 * index of this inode's security descriptor in the WIM image's table of
	 * security descriptors, or -1.  Note: when a WIM image is loaded,
	 * wimlib sets out-of-bounds indices and values less than -1 in this
	 * field to -1.  So the extraction code need not do an upper bound check
	 * after checking for -1 (or equivalently < 0).  */
	int32_t i_security_id;

	/* Identity of a reparse point.  See
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa365503(v=vs.85).aspx
	 * for what a reparse point is. */
	u32 i_reparse_tag;

	/* Unused/unknown fields that we just read into memory so we can
	 * re-write them unchanged.  */
	u32 i_rp_unknown_1;
	u16 i_rp_unknown_2;

	/* Corresponds to not_rpfixed in `struct wim_dentry_on_disk':  Set to 0
	 * if reparse point fixups have been done.  Otherwise set to 1.  Note:
	 * this actually may reflect the SYMBOLIC_LINK_RELATIVE flag.
	 */
	u16 i_not_rpfixed;

	/* Inode number; corresponds to hard_link_group_id in the `struct
	 * wim_dentry_on_disk'.  */
	u64 i_ino;

	union {
		/* Device number, used only during image capture, so we can
		 * identify hard linked files by the combination of inode number
		 * and device number (rather than just inode number, which could
		 * be ambigious if the captured tree spans a mountpoint).  Set
		 * to 0 otherwise.  */
		u64 i_devno;

		/* Fields used only during extraction  */
		struct {
			/* List of aliases of this dentry that are being
			 * extracted in the current extraction operation.  This
			 * will be a (possibly nonproper) subset of the dentries
			 * in the i_dentry list.  This list will be constructed
			 * regardless of whether the extraction backend supports
			 * hard links or not.  */
			struct list_head i_extraction_aliases;

		#ifdef WITH_NTFS_3G
			/* In NTFS-3g extraction mode, this is set to the Master
			 * File Table (MFT) number of the NTFS file that was
			 * created for this inode.  */
			u64 i_mft_no;
		#endif
		};

		/* Used during WIM writing with
		 * WIMLIB_WRITE_FLAG_SEND_DONE_WITH_FILE_MESSAGES:  the number
		 * of data streams this inode has that have not yet been fully
		 * read.  */
		u32 num_remaining_streams;

#ifdef WITH_FUSE
		struct {
			/* Used only during image mount:  Table of file
			 * descriptors that have been opened to this inode.
			 * This table is freed when the last file descriptor is
			 * closed.  */
			struct wimfs_fd **i_fds;

			/* Lower bound on the index of the next available entry
			 * in 'i_fds'.  */
			u16 i_next_fd;
		};
#endif
	};

#ifdef WITH_FUSE
	u16 i_num_opened_fds;
	u16 i_num_allocated_fds;
#endif

	/* Next alternate data stream ID to be assigned */
	u32 i_next_stream_id;
};

/* Alternate data stream entry.
 *
 * We read this from disk in the read_ads_entries() function; see that function
 * for more explanation. */
struct wim_ads_entry {
	union {
		/* SHA-1 message digest of stream contents */
		u8 hash[SHA1_HASH_SIZE];

		/* The corresponding lookup table entry (only for resolved
		 * inodes) */
		struct blob_info *blob;
	};

	/* Length of UTF16-encoded stream name, in bytes, not including the
	 * terminating null character; or 0 if the stream is unnamed. */
	u16 stream_name_nbytes;

	/* Number to identify an alternate data stream even after it's possibly
	 * been moved or renamed. */
	u32 stream_id;

	/* Stream name (UTF-16LE), null-terminated, or NULL if the stream is
	 * unnamed.  */
	utf16lechar *stream_name;

	/* Reserved field.  We read it into memory so we can write it out
	 * unchanged. */
	u64 reserved;
};

/* WIM alternate data stream entry (on-disk format) */
struct wim_ads_entry_on_disk {
	/* Length of the entry, in bytes.  This includes all fixed-length
	 * fields, plus the stream name and null terminator if present, and the
	 * padding up to an 8 byte boundary.  wimlib is a little less strict
	 * when reading the entries, and only requires that the number of bytes
	 * from this field is at least as large as the size of the fixed length
	 * fields and stream name without null terminator.  */
	le64 length;

	le64 reserved;

	/* SHA1 message digest of the uncompressed stream; or, alternatively,
	 * can be all zeroes if the stream has zero length.  */
	u8 hash[SHA1_HASH_SIZE];

	/* Length of the stream name, in bytes.  0 if the stream is unnamed.  */
	le16 stream_name_nbytes;

	/* Stream name in UTF-16LE.  It is @stream_name_nbytes bytes long,
	 * excluding the null terminator.  There is a null terminator character
	 * if @stream_name_nbytes != 0; i.e., if this stream is named.  */
	utf16lechar stream_name[];
} _packed_attribute;

#define WIM_ADS_ENTRY_DISK_SIZE 38

/*
 * Reparse tags documented at
 * http://msdn.microsoft.com/en-us/library/dd541667(v=prot.10).aspx
 */
#define WIM_IO_REPARSE_TAG_RESERVED_ZERO	0x00000000
#define WIM_IO_REPARSE_TAG_RESERVED_ONE		0x00000001
#define WIM_IO_REPARSE_TAG_MOUNT_POINT		0xA0000003
#define WIM_IO_REPARSE_TAG_HSM			0xC0000004
#define WIM_IO_REPARSE_TAG_HSM2			0x80000006
#define WIM_IO_REPARSE_TAG_DRIVER_EXTENDER	0x80000005
#define WIM_IO_REPARSE_TAG_SIS			0x80000007
#define WIM_IO_REPARSE_TAG_DFS			0x8000000A
#define WIM_IO_REPARSE_TAG_DFSR			0x80000012
#define WIM_IO_REPARSE_TAG_FILTER_MANAGER	0x8000000B
#define WIM_IO_REPARSE_TAG_SYMLINK		0xA000000C

#define FILE_ATTRIBUTE_READONLY            0x00000001
#define FILE_ATTRIBUTE_HIDDEN              0x00000002
#define FILE_ATTRIBUTE_SYSTEM              0x00000004
#define FILE_ATTRIBUTE_DIRECTORY           0x00000010
#define FILE_ATTRIBUTE_ARCHIVE             0x00000020
#define FILE_ATTRIBUTE_DEVICE              0x00000040
#define FILE_ATTRIBUTE_NORMAL              0x00000080
#define FILE_ATTRIBUTE_TEMPORARY           0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE         0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT       0x00000400
#define FILE_ATTRIBUTE_COMPRESSED          0x00000800
#define FILE_ATTRIBUTE_OFFLINE             0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED           0x00004000
#define FILE_ATTRIBUTE_VIRTUAL             0x00010000

extern struct wim_inode *
new_inode(void) _malloc_attribute;

extern struct wim_inode *
new_timeless_inode(void) _malloc_attribute;

/* Iterate through each alias of the specified inode.  */
#define inode_for_each_dentry(dentry, inode) \
	list_for_each_entry((dentry), &(inode)->i_dentry, d_alias)

/* Return an alias of the specified inode.  */
#define inode_first_dentry(inode) \
	container_of(inode->i_dentry.next, struct wim_dentry, d_alias)

/* Return the full path of an alias of the specified inode, or NULL if a full
 * path could not be determined.  */
#define inode_first_full_path(inode) \
	dentry_full_path(inode_first_dentry(inode))

extern void
d_associate(struct wim_dentry *dentry, struct wim_inode *inode);

extern void
d_disassociate(struct wim_dentry *dentry);

#ifdef WITH_FUSE
extern void
inode_dec_num_opened_fds(struct wim_inode *inode);
#endif

/* Is the inode a directory?
 * This doesn't count directories with reparse data.
 * wimlib only allows inodes of this type to have children.
 */
static inline bool
inode_is_directory(const struct wim_inode *inode)
{
	return (inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				       FILE_ATTRIBUTE_REPARSE_POINT))
			== FILE_ATTRIBUTE_DIRECTORY;
}

/* Is the inode a directory with the encrypted attribute set?
 * This returns true for encrypted directories even if they have reparse data
 * (I'm not sure if such files can even exist!).  */
static inline bool
inode_is_encrypted_directory(const struct wim_inode *inode)
{
	return ((inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
					FILE_ATTRIBUTE_ENCRYPTED))
		== (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ENCRYPTED));
}

/* Is the inode a symbolic link?
 * This returns true iff the inode is a reparse point that is either a "real"
 * symbolic link or a junction point.  */
static inline bool
inode_is_symlink(const struct wim_inode *inode)
{
	return (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		&& (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
		    inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT);
}

/* Does the inode have children?
 * Currently (based on read_dentry_tree()), this can only return true for inodes
 * for which inode_is_directory() returns true.  (This also returns false on
 * empty directories.)  */
static inline bool
inode_has_children(const struct wim_inode *inode)
{
	return inode->i_children != NULL;
}

extern struct wim_ads_entry *
inode_get_ads_entry(struct wim_inode *inode, const tchar *stream_name);

extern struct wim_ads_entry *
inode_add_ads_utf16le(struct wim_inode *inode, const utf16lechar *stream_name,
		      size_t stream_name_nbytes);

extern struct wim_ads_entry *
inode_add_ads(struct wim_inode *dentry, const tchar *stream_name);

extern struct wim_ads_entry *
inode_add_ads_with_data(struct wim_inode *inode, const tchar *name,
			const void *value, size_t size,
			struct wim_blob_table *blob_table);

extern void
inode_remove_ads(struct wim_inode *inode, struct wim_ads_entry *entry,
		 struct wim_blob_table *blob_table);

extern bool
inode_has_named_stream(const struct wim_inode *inode);

extern int
inode_set_unnamed_stream(struct wim_inode *inode, const void *data, size_t len,
			 struct wim_blob_table *blob_table);

extern int
inode_resolve_streams(struct wim_inode *inode, struct wim_blob_table *table,
		      bool force);

extern void
inode_unresolve_streams(struct wim_inode *inode);

extern int
stream_not_found_error(const struct wim_inode *inode, const u8 *hash);

static inline struct blob_info *
inode_get_blob_for_stream_resolved(const struct wim_inode *inode, unsigned stream_idx)
{
	if (stream_idx == 0)
		return inode->i_blob;
	return inode->i_ads_entries[stream_idx - 1].blob;
}

extern struct blob_info *
inode_get_blob_for_stream(const struct wim_inode *inode, unsigned stream_idx,
		 const struct wim_blob_table *table);

extern struct blob_info *
inode_unnamed_stream_resolved(const struct wim_inode *inode,
			      unsigned *stream_idx_ret);

static inline struct blob_info *
inode_get_blob_for_unnamed_stream_resolved(const struct wim_inode *inode)
{
	unsigned stream_idx;
	return inode_unnamed_stream_resolved(inode, &stream_idx);
}

extern struct blob_info *
inode_get_blob_for_unnamed_stream(const struct wim_inode *inode,
		  const struct wim_blob_table *table);

extern const u8 *
inode_stream_hash(const struct wim_inode *inode, unsigned stream_idx);

extern const u8 *
inode_unnamed_stream_hash(const struct wim_inode *inode);

static inline unsigned
inode_stream_name_nbytes(const struct wim_inode *inode, unsigned stream_idx)
{
	if (stream_idx == 0)
		return 0;
	return inode->i_ads_entries[stream_idx - 1].stream_name_nbytes;
}

static inline u32
inode_stream_idx_to_id(const struct wim_inode *inode, unsigned stream_idx)
{
	if (stream_idx == 0)
		return 0;
	return inode->i_ads_entries[stream_idx - 1].stream_id;
}

extern void
inode_ref_blobs(struct wim_inode *inode);

extern void
inode_unref_blobs(struct wim_inode *inode,
		    struct wim_blob_table *blob_table);

extern int
read_ads_entries(const u8 * restrict p, struct wim_inode * restrict inode,
		 size_t *nbytes_remaining_p);

extern void
check_inode(struct wim_inode *inode, const struct wim_security_data *sd);

/* inode_fixup.c  */
extern int
dentry_tree_fix_inodes(struct wim_dentry *root, struct list_head *inode_list);

#endif /* _WIMLIB_INODE_H  */
