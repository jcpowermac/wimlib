#ifndef _WIMLIB_INODE_H
#define _WIMLIB_INODE_H

#include "wimlib/assert.h"
#include "wimlib/list.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

struct avl_tree_node;
struct blob_descriptor;
struct blob_table;
struct wim_dentry;
struct wim_security_data;
struct wimfs_fd;

/* Valid values for the 'stream_type' field of a 'struct wim_inode_stream'  */
enum {
	/* Data stream, may be unnamed (usual case) or named  */
	STREAM_TYPE_DATA,

	/* Reparse point stream, always unnamed.  */
	STREAM_TYPE_REPARSE_POINT,

	/* Stream type could not be determined.  */
	STREAM_TYPE_UNKNOWN,
};

/*
 * The 'stream_name' field of unnamed streams always points to this array, which
 * is an empty UTF-16 string.
 */
extern const utf16lechar NO_STREAM_NAME[1];

/*
 * 'struct wim_inode_stream' describes an NTFS-style stream, which is a blob of
 * data associated with an inode.  Each stream has a type and optionally a name.
 *
 * The most frequently used stream type is the "unnamed data stream"
 * (stream_type == STREAM_TYPE_DATA && stream_name == NO_STREAM_NAME), which is
 * the "default file contents".  Many inodes just have an unnamed data stream
 * and no other streams.
 *
 * A "reparse point" is an inode with reparse data set.  The reparse data is
 * stored in a stream of type STREAM_TYPE_REPARSE_POINT.  There should be only
 * one such stream, and it should be unnamed.  However, it is possible for an
 * inode to have both a reparse point stream and an unnamed data stream, and
 * even named data streams as well.
 */
struct wim_inode_stream {

	/* The name of the stream, or NO_STREAM_NAME if the stream is unnamed.*/
	utf16lechar *stream_name;

	/*
	 * If 'stream_resolved' = 0, then 'stream_hash' is the SHA-1 message
	 * digest of the uncompressed data of this stream, or all zeroes if this
	 * stream is empty.
	 *
	 * If 'stream_resolved' = 1, then 'stream_blob' is a pointer directly to
	 * the blob descriptor for this blob, or NULL if this stream is empty.
	 */
	union {
		u8 _stream_hash[SHA1_HASH_SIZE];
		struct blob_descriptor *_stream_blob;
	};

	/* 'stream_resolved' determines whether 'stream_hash' or 'stream_blob'
	 * is valid as described above.  */
	u32 stream_resolved : 1;

	/* A unique identifier for this stream within the context of its inode.
	 * This stays constant even if the streams array is reallocated.  */
	u32 stream_id : 27;

	/* The type of this stream as one of the STREAM_TYPE_* values  */
	u32 stream_type : 4;
};

/*
 * WIM inode - a "file" in a WIM image.  An inode may have multiple names.
 *
 * As mentioned in the comment above 'struct wim_dentry', in WIM files there is
 * no on-disk analogue of a real inode, as most of these fields are duplicated
 * in the dentries.  Instead, a 'struct wim_inode' is something we create
 * ourselves to simplify the handling of hard links.
 */
struct wim_inode {

	/*
	 * The NTFS-style collection of streams for this inode.  If
	 * 'i_num_streams' is not more than the length of 'i_embedded_streams',
	 * then 'i_streams' points to 'i_embedded_streams'.  Otherwise,
	 * 'i_streams' points to an allocated array.
	 *
	 * The most common case is that 'i_num_streams == 1' and the only stream
	 * is the unnamed data stream.
	 */
	struct wim_inode_stream *i_streams;
	struct wim_inode_stream i_embedded_streams[1];
	unsigned i_num_streams;

	/* Windows file attribute flags (FILE_ATTRIBUTE_*).  */
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

	/* Flag used to mark this inode as visited; this is used when visiting
	 * all the inodes in a dentry tree exactly once.  It will be 0 by
	 * default and must be cleared following the tree traversal, even in
	 * error paths.  */
	u8 i_visited : 1;

	/* Cached value  */
	u8 i_can_externally_back : 1;

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
		 * of streams this inode has that have not yet been fully read.
		 * */
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

	/* Next stream ID to be assigned  */
	u32 i_next_stream_id;
};

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

extern struct wim_inode_stream *
inode_get_stream(const struct wim_inode *inode, int stream_type,
		 const utf16lechar *stream_name);

extern struct wim_inode_stream *
inode_get_unnamed_stream(const struct wim_inode *inode, int stream_type);

extern struct wim_inode_stream *
inode_add_stream(struct wim_inode *inode, int stream_type,
		 const utf16lechar *stream_name, struct blob_descriptor *blob);

extern struct wim_inode_stream *
inode_add_stream_with_data(struct wim_inode *inode, int stream_type,
			   const utf16lechar *stream_name,
			   const void *data, size_t size,
			   struct blob_table *blob_table);

extern void
inode_remove_stream(struct wim_inode *inode, struct wim_inode_stream *strm,
		    struct blob_table *blob_table);

static inline struct blob_descriptor *
stream_blob_resolved(const struct wim_inode_stream *strm)
{
	wimlib_assert(strm->stream_resolved);
	return strm->_stream_blob;
}

static inline void
stream_set_blob(struct wim_inode_stream *strm, struct blob_descriptor *blob)
{
	strm->_stream_blob = blob;
	strm->stream_resolved = 1;
}

static inline bool
stream_is_named(const struct wim_inode_stream *strm)
{
	return strm->stream_name != NO_STREAM_NAME;
}

static inline bool
stream_is_named_data_stream(const struct wim_inode_stream *strm)
{
	return strm->stream_type == STREAM_TYPE_DATA && stream_is_named(strm);
}

extern bool
inode_has_named_data_stream(const struct wim_inode *inode);

extern int
inode_resolve_streams(struct wim_inode *inode,
		      struct blob_table *table, bool force);

extern void
inode_unresolve_streams(struct wim_inode *inode);

extern int
blob_not_found_error(const struct wim_inode *inode, const u8 *hash);

extern struct blob_descriptor *
stream_blob(const struct wim_inode_stream *strm, const struct blob_table *table);

extern struct blob_descriptor *
inode_get_blob_for_unnamed_data_stream(const struct wim_inode *inode,
				       const struct blob_table *blob_table);

extern const u8 *
stream_hash(const struct wim_inode_stream *strm);

extern const u8 *
inode_get_hash_of_unnamed_data_stream(const struct wim_inode *inode);

extern void
inode_ref_blobs(struct wim_inode *inode);

extern void
inode_unref_blobs(struct wim_inode *inode, struct blob_table *blob_table);

/* inode_fixup.c  */
extern int
dentry_tree_fix_inodes(struct wim_dentry *root, struct list_head *inode_list);

#endif /* _WIMLIB_INODE_H  */
