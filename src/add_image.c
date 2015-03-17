/*
 * add_image.c - Add an image to a WIM file.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/blob_table.h"
#include "wimlib/error.h"
#include "wimlib/metadata.h"
#include "wimlib/security.h"
#include "wimlib/xml.h"

/* Creates and appends a 'struct wim_image_metadata' for an empty image.
 *
 * The resulting image will be the last in the WIM, so its index will be
 * the new value of wim->hdr.image_count.  */
static int
add_empty_image_metadata(WIMStruct *wim)
{
	int ret;
	struct blob *metadata_blob;
	struct wim_security_data *sd;
	struct wim_image_metadata *imd;

	/* Create blob table entry for this metadata resource (for now really
	 * just a dummy entry).  */
	ret = WIMLIB_ERR_NOMEM;
	metadata_blob = new_blob();
	if (!metadata_blob)
		goto out;

	metadata_blob->flags = WIM_RESHDR_FLAG_METADATA;
	metadata_blob->unhashed = 1;

	/* Create empty security data (no security descriptors).  */
	sd = new_wim_security_data();
	if (!sd)
		goto out_free_metadata_blob;

	imd = new_image_metadata();
	if (!imd)
		goto out_free_security_data;

	/* A NULL root_dentry indicates a completely empty image, without even a
	 * root directory.  */
	imd->root_dentry = NULL;
	imd->metadata_blob = metadata_blob;
	imd->security_data = sd;
	imd->modified = 1;

	/* Append as next image index.  */
	ret = append_image_metadata(wim, imd);
	if (ret)
		put_image_metadata(imd, NULL);
	goto out;

out_free_security_data:
	free_wim_security_data(sd);
out_free_metadata_blob:
	free_blob(metadata_blob);
out:
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_add_empty_image(WIMStruct *wim, const tchar *name, int *new_idx_ret)
{
	int ret;

	if (!name)
		name = T("");

	if (wimlib_image_name_in_use(wim, name)) {
		ERROR("There is already an image named \"%"TS"\" in the WIM!",
		      name);
		return WIMLIB_ERR_IMAGE_NAME_COLLISION;
	}

	ret = add_empty_image_metadata(wim);
	if (ret)
		return ret;

	ret = xml_add_image(wim, name);
	if (ret) {
		put_image_metadata(wim->image_metadata[--wim->hdr.image_count],
				   NULL);
		return ret;
	}

	if (new_idx_ret)
		*new_idx_ret = wim->hdr.image_count;
	return 0;
}

/* Translate the 'struct wimlib_capture_source's passed to
 * wimlib_add_image_multisource() into 'struct wimlib_update_command's for
 * wimlib_update_image().  */
static struct wimlib_update_command *
capture_sources_to_add_cmds(const struct wimlib_capture_source *sources,
			    size_t num_sources,
			    int add_flags,
			    const tchar *config_file)
{
	struct wimlib_update_command *add_cmds;

	add_cmds = CALLOC(num_sources, sizeof(add_cmds[0]));
	if (!add_cmds)
		return NULL;

	/* WIMLIB_ADD_FLAG_BOOT is handled by wimlib_add_image_multisource(),
	 * not wimlib_update_image(), so mask it out.
	 *
	 * However, WIMLIB_ADD_FLAG_WIMBOOT is handled by both.  */
	add_flags &= ~WIMLIB_ADD_FLAG_BOOT;

	for (size_t i = 0; i < num_sources; i++) {
		add_cmds[i].op = WIMLIB_UPDATE_OP_ADD;
		add_cmds[i].add.fs_source_path = sources[i].fs_source_path;
		add_cmds[i].add.wim_target_path = sources[i].wim_target_path;
		add_cmds[i].add.add_flags = add_flags;
		add_cmds[i].add.config_file = (tchar *)config_file;
	}
	return add_cmds;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_add_image_multisource(WIMStruct *wim,
			     const struct wimlib_capture_source *sources,
			     size_t num_sources,
			     const tchar *name,
			     const tchar *config_file,
			     int add_flags)
{
	int ret;
	struct wimlib_update_command *add_cmds;

	/* Make sure no reserved fields are set.  */
	for (size_t i = 0; i < num_sources; i++)
		if (sources[i].reserved != 0)
			return WIMLIB_ERR_INVALID_PARAM;

	/* Add the new image (initially empty).  */
	ret = wimlib_add_empty_image(wim, name, NULL);
	if (ret)
		return ret;

	/* Translate the "capture sources" into generic update commands.  */
	ret = WIMLIB_ERR_NOMEM;
	add_cmds = capture_sources_to_add_cmds(sources, num_sources,
					       add_flags, config_file);
	if (!add_cmds)
		goto out_delete_image;

	/* Delegate the work to wimlib_update_image().  */
	ret = wimlib_update_image(wim, wim->hdr.image_count, add_cmds,
				  num_sources, 0);
	FREE(add_cmds);
	if (ret)
		goto out_delete_image;

	/* If requested, set this image as the WIM's bootable image.  */
	if (add_flags & WIMLIB_ADD_FLAG_BOOT)
		wim->hdr.boot_idx = wim->hdr.image_count;

	/* If requested, mark new image as WIMBoot-compatible.  */
	if (add_flags & WIMLIB_ADD_FLAG_WIMBOOT)
		wim_info_set_wimboot(wim->wim_info, wim->hdr.image_count, true);

	return 0;

out_delete_image:
	/* Unsuccessful; rollback by removing the new image.  */
	delete_wim_image(wim, wim->hdr.image_count);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_add_image(WIMStruct *wim,
		 const tchar *source,
		 const tchar *name,
		 const tchar *config_file,
		 int add_flags)
{
	/* Use the more general wimlib_add_image_multisource().  */
	const struct wimlib_capture_source capture_src = {
		.fs_source_path = (tchar *)source,
		.wim_target_path = WIMLIB_WIM_ROOT_PATH,
		.reserved = 0,
	};
	return wimlib_add_image_multisource(wim, &capture_src, 1, name,
					    config_file, add_flags);
}
