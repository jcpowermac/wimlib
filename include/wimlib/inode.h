#ifndef _WIMLIB_INODE_H
#define _WIMLIB_INODE_H

#include "wimlib/list.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

struct avl_tree_node;
struct wim_dentry;
struct blob_table;
struct blob;
struct wim_security_data;
struct wimfs_fd;

enum {
	/* Data attribute, may be unnamed (usual case) or named  */
	ATTR_DATA,

	/* Reparse point attribute, always unnamed.  */
	ATTR_REPARSE_POINT,

	/* Attribute type could not be determined.  */
	ATTR_UNKNOWN,
};

static const utf16lechar NO_NAME[] = { 0 };

/*
 * 'struct wim_attribute' represents an NTFS-style attribute, which is a blob of
 * data associated with an inode.  Each attribute has a type and optionally a
 * name.
 */
struct wim_attribute {
	utf16lechar *attr_name;
	union {
		u8 attr_hash[SHA1_HASH_SIZE];
		struct blob *attr_blob;
	};
	u32 attr_id : 28;
	u32 attr_type : 4;
};

/*
 * WIM inode.
 *
 * As mentioned in the comment above `struct wim_dentry', in WIM files there
 * is no on-disk analogue of a real inode, as most of these fields are
 * duplicated in the dentries.  Instead, a `struct wim_inode' is something we
 * create ourselves to simplify the handling of hard links.
 */
struct wim_inode {

	/*
	 * The NTFS-style collection of attributes for this inode.  If
	 * i_num_attrs == 1, then i_attrs points to i_embedded_attr.  Otherwise,
	 * i_attrs points to an allocated array.
	 */
	struct wim_attribute *i_attrs;
#define INODE_NUM_EMBEDDED_ATTRS 1
	struct wim_attribute i_embedded_attrs[INODE_NUM_EMBEDDED_ATTRS];
	u32 i_num_attrs;

	/* Corresponds to the 'attributes' field of `struct wim_dentry_on_disk';
	 * bitwise OR of the FILE_ATTRIBUTE_* flags that give the attributes of
	 * this inode. 
	 *
	 * TODO: rename this to i_flags to distinguish this from the NTFS-style
	 * attributes?  */
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

	/* Flag that indicates whether this inode's streams have been
	 * "resolved".  By default, the inode starts as "unresolved", meaning
	 * that the i_hash field, along with the hash field of any associated
	 * wim_attribute's, are valid and should be used as keys in the WIM
	 * lookup table to find the associated `struct blob'.
	 * But if the inode has been resolved, then each of these fields is
	 * replaced with a pointer directly to the appropriate `struct
	 * blob', or NULL if the stream is empty.  */
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

	/* Next attribute ID to be assigned  */
	u32 i_next_attr_id;
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

extern struct wim_attribute *
inode_get_attribute_utf16le(const struct wim_inode *inode, int attr_type,
			    const utf16lechar *attr_name);

extern struct wim_attribute *
inode_get_attribute(struct wim_inode *inode, int attr_type,
		    const tchar *attr_name);

extern struct wim_attribute *
inode_add_attribute_utf16le(struct wim_inode *inode, int attr_type,
			    const utf16lechar *attr_name);

extern struct wim_attribute *
inode_add_attribute(struct wim_inode *inode, int attr_type,
		    const tchar *attr_name);

extern void
inode_remove_attribute(struct wim_inode *inode, struct wim_attribute *attr,
		       struct blob_table *blob_table);

extern struct wim_attribute *
inode_add_attribute_with_data(struct wim_inode *inode, int attr_type,
			      const tchar *attr_name,
			      const void *data, size_t size,
			      struct blob_table *blob_table);

extern bool
inode_has_named_data_stream(const struct wim_inode *inode);

extern int
inode_resolve_attributes(struct wim_inode *inode,
			 struct blob_table *table, bool force);

extern void
inode_unresolve_attributes(struct wim_inode *inode);

extern int
blob_not_found_error(const struct wim_inode *inode, const u8 *hash);

extern struct blob *
inode_attribute_blob(const struct wim_inode *inode, unsigned attr_idx,
		     const struct blob_table *table);

extern struct blob *
inode_unnamed_stream_resolved(const struct wim_inode *inode,
			      unsigned *attr_idx_ret);

extern struct blob *
inode_unnamed_stream(const struct wim_inode *inode,
		     const struct blob_table *table);

extern const u8 *
inode_attribute_hash(const struct wim_inode *inode, unsigned attr_idx);

extern const u8 *
inode_unnamed_stream_hash(const struct wim_inode *inode);

extern void
inode_ref_attributes(struct wim_inode *inode);

extern void
inode_unref_attributes(struct wim_inode *inode,
		       struct blob_table *blob_table);

/* inode_fixup.c  */
extern int
dentry_tree_fix_inodes(struct wim_dentry *root, struct list_head *inode_list);

#endif /* _WIMLIB_INODE_H  */
