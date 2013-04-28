/*
 * reparse.c
 *
 * Handle reparse data.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "dentry.h"
#include "buffer_io.h"
#include "lookup_table.h"
#include "sha1.h"
#include <errno.h>

static const utf16lechar volume_junction_prefix[11] = {
	cpu_to_le16('\\'),
	cpu_to_le16('\\'),
	cpu_to_le16('?'),
	cpu_to_le16('\\'),
	cpu_to_le16('V'),
	cpu_to_le16('o'),
	cpu_to_le16('l'),
	cpu_to_le16('u'),
	cpu_to_le16('m'),
	cpu_to_le16('e'),
	cpu_to_le16('{'),
};

/* Parse the "substitute name" (link target) from a symbolic link or junction
 * reparse point.
 *
 * Return value is:
 *
 * Non-negative integer:
 * 	The name is an absolute symbolic link in one of several formats,
 * 	and the return value is the number of UTF-16LE characters that need to
 * 	be advanced to reach a simple "absolute" path starting with a backslash
 * 	(i.e. skip over \??\ and/or drive letter)
 * Negative integer:
 *	SUBST_NAME_IS_VOLUME_JUNCTION:
 * 		The name is a volume junction.
 *	SUBST_NAME_IS_RELATIVE_LINK:
 * 		The name is a relative symbolic link.
 *	SUBST_NAME_IS_UNKNOWN:
 *		The name does not appear to be a valid symbolic link, junction,
 *		or mount point.
 */
int
parse_substitute_name(const utf16lechar *substitute_name,
		      u16 substitute_name_nbytes, u32 rptag)
{
	u16 substitute_name_nchars = substitute_name_nbytes / 2;

	if (substitute_name_nchars >= 7 &&
	    substitute_name[0] == cpu_to_le16('\\') &&
	    substitute_name[1] == cpu_to_le16('?') &&
	    substitute_name[2] == cpu_to_le16('?') &&
	    substitute_name[3] == cpu_to_le16('\\') &&
	    substitute_name[4] != cpu_to_le16('\0') &&
	    substitute_name[5] == cpu_to_le16(':') &&
	    substitute_name[6] == cpu_to_le16('\\'))
	{
		/* "Full" symlink or junction (\??\x:\ prefixed path) */
		return 6;
	} else if (rptag == WIM_IO_REPARSE_TAG_MOUNT_POINT &&
		   substitute_name_nchars >= 12 &&
		   memcmp(substitute_name, volume_junction_prefix,
			  sizeof(volume_junction_prefix)) == 0 &&
		   substitute_name[substitute_name_nchars - 1] == cpu_to_le16('\\'))
	{
		/* Volume junction.  Can't really do anything with it. */
		return SUBST_NAME_IS_VOLUME_JUNCTION;
	} else if (rptag == WIM_IO_REPARSE_TAG_SYMLINK &&
		   substitute_name_nchars >= 3 &&
		   substitute_name[0] != cpu_to_le16('\0') &&
		   substitute_name[1] == cpu_to_le16(':') &&
		   substitute_name[2] == cpu_to_le16('\\'))
	{
		/* "Absolute" symlink, with drive letter */
		return 2;
	} else if (rptag == WIM_IO_REPARSE_TAG_SYMLINK &&
		   substitute_name_nchars >= 1)
	{
		if (substitute_name[0] == cpu_to_le16('\\'))
			/* "Absolute" symlink, without drive letter */
			return 0;
		else
			/* "Relative" symlink, without drive letter */
			return SUBST_NAME_IS_RELATIVE_LINK;
	} else {
		return SUBST_NAME_IS_UNKNOWN;
	}
}

/*
 * Read the data from a symbolic link, junction, or mount point reparse point
 * buffer into a `struct reparse_data'.
 *
 * See http://msdn.microsoft.com/en-us/library/cc232006(v=prot.10).aspx for a
 * description of the format of the reparse point buffers.
 */
int
parse_reparse_data(const u8 *rpbuf, u16 rpbuflen, struct reparse_data *rpdata)
{
	const u8 *p = rpbuf;
	u16 substitute_name_offset;
	u16 print_name_offset;

	memset(rpdata, 0, sizeof(*rpdata));
	if (rpbuflen < 16)
		goto out_invalid;
	p = get_u32(p, &rpdata->rptag);
	wimlib_assert(rpdata->rptag == WIM_IO_REPARSE_TAG_SYMLINK ||
		      rpdata->rptag == WIM_IO_REPARSE_TAG_MOUNT_POINT);
	p = get_u16(p, &rpdata->rpdatalen);
	p = get_u16(p, &rpdata->rpreserved);
	p = get_u16(p, &substitute_name_offset);
	p = get_u16(p, &rpdata->substitute_name_nbytes);
	p = get_u16(p, &print_name_offset);
	p = get_u16(p, &rpdata->print_name_nbytes);
	if (rpdata->rptag == WIM_IO_REPARSE_TAG_SYMLINK) {
		if (rpbuflen < 20)
			goto out_invalid;
		p = get_u32(p, &rpdata->rpflags);
	}
	if ((size_t)substitute_name_offset + rpdata->substitute_name_nbytes +
	    (p - rpbuf) > rpbuflen)
		goto out_invalid;
	if ((size_t)print_name_offset + rpdata->print_name_nbytes +
	    (p - rpbuf) > rpbuflen)
		goto out_invalid;
	rpdata->substitute_name = (utf16lechar*)&p[substitute_name_offset];
	rpdata->print_name = (utf16lechar*)&p[print_name_offset];
	return 0;
out_invalid:
	ERROR("Invalid reparse data");
	return WIMLIB_ERR_INVALID_REPARSE_DATA;
}

/*
 * Create a reparse point data buffer.
 *
 * @rpdata:  Structure that contains the data we need.
 *
 * @rpbuf:     Buffer into which to write the reparse point data buffer.  Must be
 *		at least REPARSE_POINT_MAX_SIZE bytes long.
 */
int
make_reparse_buffer(const struct reparse_data *rpdata, u8 *rpbuf)
{
	u8 *p = rpbuf;

	p = put_u32(p, rpdata->rptag);
	p += 2; /* We set ReparseDataLength later */
	p = put_u16(p, rpdata->rpreserved);
	p = put_u16(p, 0); /* substitute name offset */
	p = put_u16(p, rpdata->substitute_name_nbytes); /* substitute name nbytes */
	p = put_u16(p, rpdata->substitute_name_nbytes + 2); /* print name offset */
	p = put_u16(p, rpdata->print_name_nbytes); /* print name nbytes */
	if (rpdata->rptag == WIM_IO_REPARSE_TAG_SYMLINK)
		p = put_u32(p, rpdata->rpflags);
	/* We null-terminate the substitute and print names, although this may
	 * not be strictly necessary.  Note that the byte counts should not
	 * include the null terminators. */
	if (p + rpdata->substitute_name_nbytes +
	    rpdata->print_name_nbytes +
	    2 * sizeof(utf16lechar) - rpbuf > REPARSE_POINT_MAX_SIZE)
	{
		ERROR("Reparse data is too long!");
		return WIMLIB_ERR_INVALID_REPARSE_DATA;
	}
	p = put_bytes(p, rpdata->substitute_name_nbytes, rpdata->substitute_name);
	p = put_u16(p, 0);
	p = put_bytes(p, rpdata->print_name_nbytes, rpdata->print_name);
	p = put_u16(p, 0);
	put_u16(rpbuf + 4, p - rpbuf - 8); /* Set ReparseDataLength */
	return 0;
}

/*
 * Read the reparse data from a WIM inode that is a reparse point.
 *
 * @rpbuf points to a buffer at least REPARSE_POINT_MAX_SIZE bytes into which
 * the reparse point data buffer will be reconstructed.
 *
 * Note: in the WIM format, the first 8 bytes of the reparse point data buffer
 * are omitted, presumably because we already know the reparse tag from the
 * dentry, and we already know the reparse tag length from the lookup table
 * entry resource length.  However, we reconstruct the first 8 bytes in the
 * buffer returned by this function.
 */
int
wim_inode_get_reparse_data(const struct wim_inode *inode, u8 *rpbuf)
{
	struct wim_lookup_table_entry *lte;
	int ret;

	wimlib_assert(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT);

	lte = inode_unnamed_lte_resolved(inode);
	if (!lte) {
		ERROR("Reparse point has no reparse data!");
		return WIMLIB_ERR_INVALID_REPARSE_DATA;
	}
	if (wim_resource_size(lte) > REPARSE_POINT_MAX_SIZE - 8) {
		ERROR("Reparse data is too long!");
		return WIMLIB_ERR_INVALID_REPARSE_DATA;
	}

	/* Read the data from the WIM file */
	ret = read_full_resource_into_buf(lte, rpbuf + 8, true);
	if (ret)
		return ret;

	/* Reconstruct the first 8 bytes of the reparse point buffer */

	/* ReparseTag */
	put_u32(rpbuf, inode->i_reparse_tag);

	/* ReparseDataLength */
	put_u16(rpbuf + 4, wim_resource_size(lte));

	/* ReparseReserved
	 * XXX this could be one of the unknown fields in the WIM dentry. */
	put_u16(rpbuf + 6, 0);
	return 0;
}

/* UNIX version of getting and setting the data in reparse points */
#if !defined(__WIN32__)

/* Get the UNIX symlink target from a WIM inode.  The inode may be either a
 * "real" symlink (reparse tag WIM_IO_REPARSE_TAG_SYMLINK), or it may be a
 * junction point (reparse tag WIM_IO_REPARSE_TAG_MOUNT_POINT).
 *
 * This has similar semantics to the UNIX readlink() function, except the path
 * argument is swapped out with the `struct wim_inode' for a reparse point, and
 * on failure a negated error code is returned rather than -1 with errno set.  */
ssize_t
wim_inode_readlink(const struct wim_inode *inode, char *buf, size_t bufsize)
{
	int ret;
	u8 rpbuf[REPARSE_POINT_MAX_SIZE];
	u16 rpdatalen;
	struct reparse_data rpdata;
	char *link_target;
	char *translated_target;
	size_t link_target_len;

	wimlib_assert(inode_is_symlink(inode));

	if (wim_inode_get_reparse_data(inode, rpbuf))
		return -EIO;

	get_u16(rpbuf + 4, &rpdatalen);

	if (parse_reparse_data(rpbuf, rpdatalen + 8, &rpdata))
		return -EIO;

	ret = utf16le_to_tstr(rpdata.substitute_name,
			      rpdata.substitute_name_nbytes,
			      &link_target, &link_target_len);
	if (ret)
		return -errno;

	translated_target = link_target;
	ret = parse_substitute_name(rpdata.substitute_name,
				    rpdata.substitute_name_nbytes,
				    rpdata.rptag);
	switch (ret) {
	case SUBST_NAME_IS_RELATIVE_LINK:
		goto out_translate_slashes;
	case SUBST_NAME_IS_VOLUME_JUNCTION:
		goto out_have_link;
	case SUBST_NAME_IS_UNKNOWN:
		ERROR("Can't understand reparse point "
		      "substitute name \"%s\"", link_target);
		return -EIO;
	default:
		translated_target += ret;
		link_target_len -= ret;
		break;
	}

out_translate_slashes:
	for (size_t i = 0; i < link_target_len; i++)
		if (translated_target[i] == '\\')
			translated_target[i] = '/';
out_have_link:
	if (link_target_len > bufsize) {
		link_target_len = bufsize;
		ret = -ENAMETOOLONG;
	} else {
		ret = link_target_len;
	}
	memcpy(buf, translated_target, link_target_len);
	FREE(link_target);
	return ret;
}

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif

int
wim_inode_set_symlink(struct wim_inode *inode,
		      const char *target,
		      struct wim_lookup_table *lookup_table)

{
	u8 rpbuf[REPARSE_POINT_MAX_SIZE];
	u16 rpdatalen;
	struct reparse_data rpdata;
	static const char abs_subst_name_prefix[12] = "\\\0?\0?\0\\\0C\0:\0";
	static const char abs_print_name_prefix[4] = "C\0:\0";
	utf16lechar *name_utf16le;
	size_t name_utf16le_nbytes;
	int ret;

	DEBUG("Creating reparse point data buffer for UNIX "
	      "symlink target \"%s\"", target);
	memset(&rpdata, 0, sizeof(rpdata));
	ret = tstr_to_utf16le(target, strlen(target),
			      &name_utf16le, &name_utf16le_nbytes);
	if (ret)
		return ret;

	for (size_t i = 0; i < name_utf16le_nbytes / 2; i++)
		if (name_utf16le[i] == cpu_to_le16('/'))
			name_utf16le[i] = cpu_to_le16('\\');

	/* Compatability notes:
	 *
	 * On UNIX, an absolute symbolic link begins with '/'; everything else
	 * is a relative symbolic link.  (Quite simple compared to the various
	 * ways to provide Windows paths.)
	 *
	 * To change a UNIX relative symbolic link to Windows format, we only
	 * need to translate it to UTF-16LE and replace backslashes with forward
	 * slashes.  We do not make any attempt to handle filename character
	 * problems, such as a link target that itself contains backslashes on
	 * UNIX.  Then, for these relative links, we set the reparse header
	 * @flags field to SYMBOLIC_LINK_RELATIVE.
	 *
	 * For UNIX absolute symbolic links, we must set the @flags field to 0.
	 * Then, there are multiple options as to actually represent the
	 * absolute link targets:
	 *
	 * (1) An absolute path beginning with one backslash character. similar
	 * to UNIX-style, just with a different path separator.  Print name same
	 * as substitute name.
	 *
	 * (2) Absolute path beginning with drive letter followed by a
	 * backslash.  Print name same as substitute name.
	 *
	 * (3) Absolute path beginning with drive letter followed by a
	 * backslash; substitute name prefixed with \??\, otherwise same as
	 * print name.
	 *
	 * We choose option (3) here, and we just assume C: for the drive
	 * letter.  The reasoning for this is:
	 *
	 * (1) Microsoft imagex.exe has a bug where it does not attempt to do
	 * reparse point fixups for these links, even though they are valid
	 * absolute links.  (Note: in this case prefixing the substitute name
	 * with \??\ does not work; it just makes the data unable to be restored
	 * at all.)
	 * (2) Microsoft imagex.exe will fail when doing reparse point fixups
	 * for these.  It apparently contains a bug that causes it to create an
	 * invalid reparse point, which then cannot be restored.
	 * (3) This is the only option I tested for which reparse point fixups
	 * worked properly in Microsoft imagex.exe.
	 *
	 * So option (3) it is.
	 */

	rpdata.rptag = inode->i_reparse_tag;
	if (target[0] == '/') {
		rpdata.substitute_name_nbytes = name_utf16le_nbytes +
						sizeof(abs_subst_name_prefix);
		rpdata.print_name_nbytes = name_utf16le_nbytes +
					   sizeof(abs_print_name_prefix);
		rpdata.substitute_name = alloca(rpdata.substitute_name_nbytes);
		rpdata.print_name = alloca(rpdata.print_name_nbytes);
		memcpy(rpdata.substitute_name, abs_subst_name_prefix,
		       sizeof(abs_subst_name_prefix));
		memcpy(rpdata.print_name, abs_print_name_prefix,
		       sizeof(abs_print_name_prefix));
		memcpy((void*)rpdata.substitute_name + sizeof(abs_subst_name_prefix),
		       name_utf16le, name_utf16le_nbytes);
		memcpy((void*)rpdata.print_name + sizeof(abs_print_name_prefix),
		       name_utf16le, name_utf16le_nbytes);
	} else {
		rpdata.substitute_name_nbytes = name_utf16le_nbytes;
		rpdata.print_name_nbytes = name_utf16le_nbytes;
		rpdata.substitute_name = name_utf16le;
		rpdata.print_name = name_utf16le;
		rpdata.rpflags = SYMBOLIC_LINK_RELATIVE;
	}

	ret = make_reparse_buffer(&rpdata, rpbuf);
	if (ret == 0) {
		get_u16(rpbuf + 4, &rpdatalen);
		ret = inode_set_unnamed_stream(inode, rpbuf + 8, rpdatalen,
					       lookup_table);
	}
	FREE(name_utf16le);
	return ret;
}

#include <sys/stat.h>

static int
unix_get_ino_and_dev(const char *path, u64 *ino_ret, u64 *dev_ret)
{
	struct stat stbuf;
	if (stat(path, &stbuf)) {
		if (errno != ENOENT)
			WARNING_WITH_ERRNO("Failed to stat \"%s\"", path);
		/* Treat as a link pointing outside the capture root (it
		 * most likely is). */
		return WIMLIB_ERR_STAT;
	} else {
		*ino_ret = stbuf.st_ino;
		*dev_ret = stbuf.st_dev;
		return 0;
	}
}

#endif /* !defined(__WIN32__) */

#ifdef __WIN32__
#  include "win32.h"
#  define RP_PATH_SEPARATOR L'\\'
#  define is_rp_path_separator(c) ((c) == L'\\' || (c) == L'/')
#  define os_get_ino_and_dev win32_get_file_and_vol_ids
#else
#  define RP_PATH_SEPARATOR '/'
#  define is_rp_path_separator(c) ((c) == '/')
#  define os_get_ino_and_dev unix_get_ino_and_dev
#endif

/* Fix up absolute symbolic link targets--- mostly shared between UNIX and
 * Windows */
tchar *
capture_fixup_absolute_symlink(tchar *dest,
			       u64 capture_root_ino, u64 capture_root_dev)
{
	tchar *p = dest;

#ifdef __WIN32__
	/* Skip drive letter */
	if (!is_rp_path_separator(*dest))
		p += 2;
#endif

	DEBUG("Fixing symlink or junction \"%"TS"\"", dest);
	for (;;) {
		tchar save;
		int ret;
		u64 ino;
		u64 dev;

		while (is_rp_path_separator(*p))
			p++;

		save = *p;
		*p = T('\0');
		ret = os_get_ino_and_dev(dest, &ino, &dev);
		*p = save;

		if (ret) /* stat() failed before we got to the capture root---
			    assume the link points outside it. */
			return NULL;

		if (ino == capture_root_ino && dev == capture_root_dev) {
			/* Link points inside capture root.  Return abbreviated
			 * path. */
			if (*p == T('\0'))
				*(p - 1) = RP_PATH_SEPARATOR;
			while (p - 1 >= dest && is_rp_path_separator(*(p - 1)))
				p--;
		#ifdef __WIN32__
			if (!is_rp_path_separator(dest[0])) {
				*--p = dest[1];
				*--p = dest[0];
			}
		#endif
			wimlib_assert(p >= dest);
			return p;
		}

		if (*p == T('\0')) {
			/* Link points outside capture root. */
			return NULL;
		}

		do {
			p++;
		} while (!is_rp_path_separator(*p) && *p != T('\0'));
	}
}