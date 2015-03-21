#ifndef _WIMLIB_NTFS_3G_H
#define _WIMLIB_NTFS_3G_H

#include "wimlib/callback.h"
#include "wimlib/types.h"

struct blob_descriptor;
struct _ntfs_volume;

#ifdef WITH_NTFS_3G
struct _ntfs_volume;
struct ntfs_location {
	struct _ntfs_volume *ntfs_vol;
	char *ntfs_inode_path;
	utf16lechar *ntfs_attr_name;
	unsigned ntfs_attr_name_nchars;
	unsigned ntfs_attr_type;
};
#endif

extern void
libntfs3g_global_init(void);

extern int
read_ntfs_file_prefix(const struct blob_descriptor *blob, u64 size,
		      consume_data_callback_t cb, void *cb_ctx);

extern int
do_ntfs_umount(struct _ntfs_volume *vol);

#endif
