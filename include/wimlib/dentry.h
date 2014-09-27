#ifndef _WIMLIB_DENTRY_H
#define _WIMLIB_DENTRY_H

#include "wimlib/avl_tree.h"
#include "wimlib/case.h"
#include "wimlib/compiler.h"
#include "wimlib/inode.h"
#include "wimlib/list.h"
#include "wimlib/types.h"

struct wim_inode;
struct wim_lookup_table;

/* Base size of a WIM dentry in the on-disk format, up to and including the file
 * name length.  This does not include the variable-length file name, short
 * name, alternate data stream entries, and padding to 8-byte boundaries.  */
#define WIM_DENTRY_DISK_SIZE 102

/*
 * In-memory structure for a WIM directory entry (dentry).  There is a directory
 * tree for each image in the WIM.
 *
 * Note that this is a directory entry and not an inode.  Since NTFS allows hard
 * links, it's possible for an NTFS inode to correspond to multiple WIM dentries.
 * The hard link group ID field of the on-disk WIM dentry tells us the number of
 * the NTFS inode that the dentry corresponds to (and this gets placed in
 * d_inode->i_ino).
 *
 * Unfortunately, WIM files do not have an analogue to an inode; instead certain
 * information, such as file attributes, the security descriptor, and file
 * streams is replicated in each hard-linked dentry, even though this
 * information really is associated with an inode.  In-memory, we fix up this
 * flaw by allocating a `struct wim_inode' for each dentry that contains some of
 * this duplicated information, then combining the inodes for each hard link
 * group together.
 *
 * Confusingly, it's possible for stream information to be missing from a dentry
 * in a hard link set, in which case the stream information needs to be gotten
 * from one of the other dentries in the hard link set.  In addition, it is
 * possible for dentries to have inconsistent security IDs, file attributes, or
 * file streams when they share the same hard link ID (don't even ask.  I hope
 * that Microsoft may have fixed this problem, since I've only noticed it in the
 * 'install.wim' for Windows 7).  For those dentries, we have to use the
 * conflicting fields to split up the hard link groups.  (See
 * dentry_tree_fix_inodes() in inode_fixup.c.)
 */
struct wim_dentry {

	void * raw_data;
	size_t raw_data_size;

	/* Pointer to the inode for this dentry.  This will contain some
	 * information that was factored out of the on-disk WIM dentry as common
	 * to all dentries in a hard link group.  */
	struct wim_inode *d_inode;

	/* Node for the parent's balanced binary search tree of child dentries
	 * sorted by case sensitive long name (root i_children).  */
	struct avl_tree_node d_index_node;

	/* Node for the parent's balanced binary search tree of child dentries,
	 * sorted by case insensitive long name (root i_children_ci). */
	struct avl_tree_node d_index_node_ci;

	/* List of dentries in a directory that have different case sensitive
	 * long names but share the same case insensitive long name.  */
	struct list_head d_ci_conflict_list;

	/* The parent of this directory entry. */
	struct wim_dentry *d_parent;

	/* Linked list node that places this dentry in the list of aliases for
	 * its inode (d_inode) */
	struct list_head d_alias;

	/* Pointer to the UTF-16LE short filename (malloc()ed buffer), or NULL
	 * if this dentry has no short name.  */
	utf16lechar *short_name;

	/* Pointer to the UTF-16LE filename (malloc()ed buffer), or NULL if this
	 * dentry has no filename.  */
	utf16lechar *file_name;

	/* Length of UTF-16LE encoded short filename, in bytes, not including
	 * the terminating zero wide-character. */
	u16 short_name_nbytes;

	/* Length of UTF-16LE encoded "long" file name, in bytes, not including
	 * the terminating null character. */
	u16 file_name_nbytes;

	/* When capturing from an NTFS volume using NTFS-3g, this flag is set on
	 * dentries that were created from a filename in the WIN32 or WIN32+DOS
	 * namespaces rather than the POSIX namespace.  Otherwise this will
	 * always be 0.  */
	u8 is_win32_name : 1;

	/* Temporary flag; always reset to 0 when done using.  */
	u8 tmp_flag : 1;

	/* Used by wimlib_update_image()  */
	u8 is_orphan : 1;

	union {
		/* 'subdir_offset' is only used while reading and writing this
		 * dentry.  See the corresponding field in `struct
		 * wim_dentry_on_disk' for explanation.  */
		u64 subdir_offset;

		/* Temporary list field  */
		struct list_head tmp_list;
	};

	/* Full path to this dentry in the WIM, in platform-dependent tchars
	 * that can be printed without conversion.  By default this field will
	 * be NULL and will only be calculated on-demand by the
	 * calculate_dentry_full_path() or dentry_full_path() functions.  */
	tchar *_full_path;

	/* (Extraction only) Actual name to extract this dentry as.  This may be
	 * either in 'tchars' or in 'utf16lechars', depending on what encoding
	 * the extraction backend needs.  This may alias 'file_name'.  If it
	 * doesn't, it is an allocated buffer which must be freed.  */
	void *d_extraction_name;

	/* (Extraction only) Number of characters in d_extraction_name.  */
	size_t d_extraction_name_nchars;

	/* (Extraction only) Linked list node that connects all dentries being
	 * extracted as part of the current extraction operation.  */
	struct list_head d_extraction_list_node;

	/* (Extraction only) Linked list node that connects all dentries being
	 * extracted as aliases of the same inode as part of the current
	 * extraction operation.  */
	struct list_head d_extraction_alias_node;
};

static inline bool
dentry_is_first_in_inode(const struct wim_dentry *dentry)
{
	return inode_first_dentry(dentry->d_inode) == dentry;
}

static inline bool
will_extract_dentry(const struct wim_dentry *dentry)
{
	return dentry->d_extraction_list_node.next != NULL;
}

extern u64
dentry_out_total_length(const struct wim_dentry *dentry);

extern int
for_dentry_in_tree(struct wim_dentry *root,
		   int (*visitor)(struct wim_dentry*, void*),
		   void *args);

/* Iterate through each @child dentry of the @dir directory inode,
 * in sorted order (by case sensitive name).  */
#define for_inode_child(child, dir)						\
	avl_tree_for_each_in_order((child), (dir)->i_children,			\
				   struct wim_dentry, d_index_node)

/* Iterate through each @child dentry of the @parent dentry,
 * in sorted order (by case sensitive name).  */
#define for_dentry_child(child, parent) \
	for_inode_child((child), (parent)->d_inode)

/* Iterate through each @child dentry of the @dir directory inode,
 * in postorder (safe for freeing the child dentries).  */
#define for_inode_child_postorder(child, dir)				\
	avl_tree_for_each_in_postorder((child), (dir)->i_children,	\
				       struct wim_dentry, d_index_node)

/* Iterate through each @child dentry of the @parent dentry,
 * in postorder (safe for freeing the child dentries).  */
#define for_dentry_child_postorder(child, parent) \
	for_inode_child_postorder((child), (parent)->d_inode)

/* Get any child dentry of the @dir directory inode.  Requires
 * inode_has_children(@dir) == true.  */
#define inode_any_child(dir)	\
	avl_tree_entry((dir)->i_children, struct wim_dentry, d_index_node)

/* Get any child dentry of the @parent dentry.  Requires
 * dentry_has_children(@parent) == true.  */
#define dentry_any_child(parent) \
	inode_any_child((parent)->d_inode)

extern void
calculate_subdir_offsets(struct wim_dentry *root, u64 *subdir_offset_p);

extern int
dentry_set_name(struct wim_dentry *dentry, const tchar *new_name);

extern int
dentry_set_name_utf16le(struct wim_dentry *dentry, const utf16lechar *new_name,
			size_t new_name_nbytes);

extern struct wim_dentry *
get_dentry(struct WIMStruct *wim, const tchar *path,
	   CASE_SENSITIVITY_TYPE case_type);

extern struct wim_dentry *
get_dentry_child_with_name(const struct wim_dentry *dentry,
			   const tchar *name,
			   CASE_SENSITIVITY_TYPE case_type);

extern struct wim_dentry *
get_dentry_child_with_utf16le_name(const struct wim_dentry *dentry,
				   const utf16lechar *name,
				   size_t name_nbytes,
				   CASE_SENSITIVITY_TYPE case_type);

extern struct wim_dentry *
get_parent_dentry(struct WIMStruct *wim, const tchar *path,
		  CASE_SENSITIVITY_TYPE case_type);

extern int
calculate_dentry_full_path(struct wim_dentry *dentry);

extern tchar *
dentry_full_path(struct wim_dentry *dentry);

extern int
new_dentry(const tchar *name, struct wim_dentry **dentry_ret);

extern int
new_dentry_with_inode(const tchar *name, struct wim_dentry **dentry_ret);

extern int
new_dentry_with_timeless_inode(const tchar *name, struct wim_dentry **dentry_ret);

extern void
dentry_tree_clear_inode_visited(struct wim_dentry *root);

extern int
new_filler_directory(struct wim_dentry **dentry_ret);

extern void
free_dentry(struct wim_dentry *dentry);

extern void
free_dentry_tree(struct wim_dentry *root,
		 struct wim_lookup_table *lookup_table);

extern void
unlink_dentry(struct wim_dentry *dentry);

extern struct wim_dentry *
dentry_add_child(struct wim_dentry *parent, struct wim_dentry *child);

struct update_command_journal;

extern int
rename_wim_path(WIMStruct *wim, const tchar *from, const tchar *to,
		CASE_SENSITIVITY_TYPE case_type,
		struct update_command_journal *j);


extern int
read_dentry_tree(const u8 *buf, size_t buf_len,
		 u64 root_offset, struct wim_dentry **root_ret);

extern u8 *
write_dentry_tree(struct wim_dentry *root, u8 *p);

static inline bool
dentry_is_root(const struct wim_dentry *dentry)
{
	return dentry->d_parent == dentry;
}

static inline bool
dentry_is_directory(const struct wim_dentry *dentry)
{
	return inode_is_directory(dentry->d_inode);
}

static inline bool
dentry_has_children(const struct wim_dentry *dentry)
{
	return inode_has_children(dentry->d_inode);
}

static inline bool
dentry_has_short_name(const struct wim_dentry *dentry)
{
	return dentry->short_name_nbytes != 0;
}

static inline bool
dentry_has_long_name(const struct wim_dentry *dentry)
{
	return dentry->file_name_nbytes != 0;
}
#endif /* _WIMLIB_DENTRY_H */
