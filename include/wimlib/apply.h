#ifndef _WIMLIB_APPLY_H
#define _WIMLIB_APPLY_H

#include "wimlib/compiler.h"
#include "wimlib/file_io.h"
#include "wimlib/list.h"
#include "wimlib/progress.h"
#include "wimlib/types.h"
#include "wimlib.h"

/* These can be treated as counts (for required_features) or booleans (for
 * supported_features).  */
struct wim_features {
	unsigned long archive_files;
	unsigned long hidden_files;
	unsigned long system_files;
	unsigned long compressed_files;
	unsigned long encrypted_files;
	unsigned long encrypted_directories;
	unsigned long not_context_indexed_files;
	unsigned long sparse_files;
	unsigned long named_data_streams;
	unsigned long hard_links;
	unsigned long reparse_points;
	unsigned long symlink_reparse_points;
	unsigned long other_reparse_points;
	unsigned long security_descriptors;
	unsigned long short_names;
	unsigned long unix_data;
	unsigned long timestamps;
	unsigned long case_sensitive_filenames;
};

struct blob_descriptor;
struct read_blob_list_callbacks;
struct apply_operations;
struct wim_dentry;

struct apply_ctx {
	/* The WIMStruct from which files are being extracted from the currently
	 * selected image.  */
	WIMStruct *wim;

	/* The target of the extraction, usually the path to a directory.  */
	const tchar *target;

	/* Length of @target in tchars.  */
	size_t target_nchars;

	/* Extraction flags (WIMLIB_EXTRACT_FLAG_*)  */
	int extract_flags;

	/* User-provided progress function, or NULL if not specified.  */
	wimlib_progress_func_t progfunc;
	void *progctx;

	/* Progress data buffer, with progress.extract initialized.  */
	union wimlib_progress_info progress;

	/* Features required to extract the files (with counts)  */
	struct wim_features required_features;

	/* Features supported by the extraction mode (with booleans)  */
	struct wim_features supported_features;

	/* The members below should not be used outside of extract.c  */
	const struct apply_operations *apply_ops;
	u64 next_progress;
	unsigned long invalid_sequence;
	unsigned long num_blobs_remaining;
	struct list_head blob_list;
	const struct read_blob_list_callbacks *saved_cbs;
	struct blob_descriptor *cur_blob;
	u64 cur_blob_offset;
	struct filedes tmpfile_fd;
	tchar *tmpfile_name;
	unsigned int count_until_file_progress;
};

/* Maximum number of UNIX file descriptors, NTFS attributes, or Windows file
 * handles that can be opened simultaneously to extract a single-instance
 * stream to multiple destinations.  */
#define MAX_OPEN_FILES 512

static inline int
extract_progress(struct apply_ctx *ctx, enum wimlib_progress_msg msg)
{
	return call_progress(ctx->progfunc, msg, &ctx->progress, ctx->progctx);
}

extern int
do_file_extract_progress(struct apply_ctx *ctx, enum wimlib_progress_msg msg);

#define COUNT_PER_FILE_PROGRESS 256

static inline int
maybe_do_file_progress(struct apply_ctx *ctx, enum wimlib_progress_msg msg)
{
	ctx->progress.extract.current_file_count++;
	if (unlikely(!--ctx->count_until_file_progress))
		return do_file_extract_progress(ctx, msg);
	return 0;
}

extern int
start_file_structure_phase(struct apply_ctx *ctx, uint64_t end_file_count);

extern int
start_file_metadata_phase(struct apply_ctx *ctx, uint64_t end_file_count);

/* Report that a file was created, prior to stream extraction.  */
static inline int
report_file_created(struct apply_ctx *ctx)
{
	return maybe_do_file_progress(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE);
}

/* Report that file metadata was applied, after stream extraction.  */
static inline int
report_file_metadata_applied(struct apply_ctx *ctx)
{
	return maybe_do_file_progress(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_METADATA);
}

extern int
end_file_structure_phase(struct apply_ctx *ctx);

extern int
end_file_metadata_phase(struct apply_ctx *ctx);

static inline int
report_apply_error(struct apply_ctx *ctx, int error_code, const tchar *path)
{
	return report_error(ctx->progfunc, ctx->progctx, error_code, path);
}

/* Returns any of the aliases of an inode that are being extracted.  */
#define inode_first_extraction_dentry(inode)		\
	list_first_entry(&(inode)->i_extraction_aliases,	\
			 struct wim_dentry, d_extraction_alias_node)

extern int
extract_blob_list(struct apply_ctx *ctx,
		    const struct read_blob_list_callbacks *cbs);

/*
 * Represents an extraction backend.
 */
struct apply_operations {

	/* Name of the extraction backend.  */
	const char *name;

	/*
	 * Query the features supported by the extraction backend.
	 *
	 * @target
	 *	The target string that was provided by the user.  (Often a
	 *	directory, but extraction backends are free to interpret this
	 *	differently.)
	 *
	 * @supported_features
	 *	A structure, each of whose members represents a feature that may
	 *	be supported by the extraction backend.  For each feature that
	 *	the extraction backend supports, this routine must set the
	 *	corresponding member to a nonzero value.
	 *
	 * Return 0 if successful; otherwise a positive wimlib error code.
	 */
	int (*get_supported_features)(const tchar *target,
				      struct wim_features *supported_features);

	/*
	 * Main extraction routine.
	 *
	 * The extraction backend is provided a list of dentries that have been
	 * prepared for extraction.  It is free to extract them in any way that
	 * it chooses.  Ideally, it should choose a method that maximizes
	 * performance.
	 *
	 * The target string will be provided in ctx->common.target.  This might
	 * be a directory, although extraction backends are free to interpret it
	 * as they wish.  TODO: in some cases, the common extraction code also
	 * interprets the target string.  This should be completely isolated to
	 * extraction backends.
	 *
	 * The extraction flags will be provided in ctx->common.extract_flags.
	 * Extraction backends should examine them and implement the behaviors
	 * for as many flags as possible.  Some flags are already handled by the
	 * common extraction code.  TODO: this needs to be better formalized.
	 *
	 * @dentry_list, the list of dentries, will be ordered such that the
	 * ancestor of any dentry always precedes any descendents.  Unless
	 * @single_tree_only is set, it's possible that the dentries consist of
	 * multiple disconnected trees.
	 *
	 * 'd_extraction_name' and 'd_extraction_name_nchars' of each dentry
	 * will be set to indicate the actual name with which the dentry should
	 * be extracted.  This may or may not be the same as 'file_name'.
	 * TODO: really, the extraction backends should be responsible for
	 * generating 'd_extraction_name'.
	 *
	 * Each dentry will refer to a valid inode in 'd_inode'.
	 * 'd_inode->i_extraction_aliases' will contain a list of just the
	 * dentries of that inode being extracted.  This will be a (possibly
	 * nonproper) subset of the 'd_inode->i_dentry' list.
	 *
	 * The streams required to be extracted will already be prepared in
	 * 'apply_ctx'.  The extraction backend should call
	 * extract_blob_list() to extract them.
	 *
	 * The will_extract_dentry() utility function, given an arbitrary dentry
	 * in the WIM image (which may not be in the extraction list), can be
	 * used to determine if that dentry is in the extraction list.
	 *
	 * Return 0 if successful; otherwise a positive wimlib error code.
	 */
	int (*extract)(struct list_head *dentry_list, struct apply_ctx *ctx);

	/*
	 * Query whether the unnamed data stream of the specified file will be
	 * extracted as "externally backed".  If so, the extraction backend is
	 * assumed to handle this separately, and the common extraction code
	 * will not register a usage of that stream.
	 *
	 * This routine is optional.
	 *
	 * Return:
	 *	< 0 if the file will *not* be externally backed.
	 *	= 0 if the file will be externally backed.
	 *	> 0 (wimlib error code) if another error occurred.
	 */
	int (*will_externally_back)(struct wim_dentry *dentry, struct apply_ctx *ctx);

	/*
	 * Size of the backend-specific extraction context.  It must contain
	 * 'struct apply_ctx' as its first member.
	 */
	size_t context_size;

	/*
	 * Set this if the extraction backend only supports extracting dentries
	 * that form a single tree, not multiple trees.
	 */
	bool single_tree_only;
};

#ifdef __WIN32__
  extern const struct apply_operations win32_apply_ops;
#else
  extern const struct apply_operations unix_apply_ops;
#endif

#ifdef WITH_NTFS_3G
  extern const struct apply_operations ntfs_3g_apply_ops;
#endif

#endif /* _WIMLIB_APPLY_H */
