#ifndef _WIMLIB_APPLY_H
#define _WIMLIB_APPLY_H

#include "wimlib.h"
#include "wimlib/types.h"

#ifdef WITH_NTFS_3G
struct _ntfs_volume;
#endif

struct apply_args {
	WIMStruct *w;

	/* Directory to which we're extracting the WIM image or directory tree,
	 * in user-specified form (may be slightly altered) */
	const tchar *target;
	unsigned target_nchars;

#ifdef __WIN32__
	/* \\?\-prefixed full path to the above directory; needed to work around
	 * lack of default support for long paths on Windoze. */
	tchar *target_lowlevel_path;
	unsigned target_lowlevel_path_nchars;
#endif

	/* Absolute path to the above directory; on UNIX this is simply a path
	 * beginning with /, while on Windoze this will be a path beginning with
	 * a drive letter followed by a backslash, but not with \\?\. */
	tchar *target_realpath;
	unsigned target_realpath_len;

	struct wim_dentry *extract_root;
	unsigned long invalid_sequence;
	int extract_flags;
	union wimlib_progress_info progress;
	wimlib_progress_func_t progress_func;
	int (*apply_dentry)(struct wim_dentry *, void *);
	union {
	#ifdef WITH_NTFS_3G
		struct {
			/* NTFS apply only */
			struct _ntfs_volume *vol;
		};
	#endif
	#ifdef __WIN32__
		struct {
			/* Normal apply only (Win32) */
			unsigned long num_set_sacl_priv_notheld;
			unsigned long num_set_sd_access_denied;
			unsigned vol_flags;
			unsigned long num_hard_links_failed;
			unsigned long num_soft_links_failed;
			unsigned long num_long_paths;
			bool have_vol_flags;
		};
	#else
		struct {
			/* Normal apply only (UNIX) */
			unsigned long num_utime_warnings;
		};
	#endif
	};
};

#ifdef WITH_NTFS_3G
extern int
apply_dentry_ntfs(struct wim_dentry *dentry, void *arg);

extern int
apply_dentry_timestamps_ntfs(struct wim_dentry *dentry, void *arg);
#endif

#ifdef __WIN32__
extern int
win32_do_apply_dentry(const tchar *output_path,
		      size_t output_path_nbytes,
		      struct wim_dentry *dentry,
		      struct apply_args *args);

extern int
win32_do_apply_dentry_timestamps(const tchar *output_path,
				 size_t output_path_nbytes,
				 struct wim_dentry *dentry,
				 struct apply_args *args);
#else /* __WIN32__ */
extern int
unix_do_apply_dentry(const tchar *output_path, size_t output_path_nbytes,
		     struct wim_dentry *dentry, struct apply_args *args);
extern int
unix_do_apply_dentry_timestamps(const tchar *output_path,
				size_t output_path_nbytes,
				struct wim_dentry *dentry,
				struct apply_args *args);
#endif /* !__WIN32__ */

/* Internal use only */
#define WIMLIB_EXTRACT_FLAG_MULTI_IMAGE		0x80000000
#define WIMLIB_EXTRACT_FLAG_NO_STREAMS		0x40000000
#define WIMLIB_EXTRACT_MASK_PUBLIC		0x3fffffff


#endif /* _WIMLIB_APPLY_H */
