/*
 * header.c
 *
 * Read, write, or create a WIM header.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "wimlib.h"
#include "wimlib/alloca.h"
#include "wimlib/assert.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/header.h"
#include "wimlib/util.h"
#include "wimlib/wim.h"

/*
 * Reads the header from a WIM file.
 *
 * @wim
 *	WIM to read the header from.  @wim->in_fd must be positioned at the
 *	beginning of the file.
 *
 * @hdr
 *	Structure to read the header into.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_IMAGE_COUNT
 *	WIMLIB_ERR_INVALID_PART_NUMBER
 *	WIMLIB_ERR_NOT_A_WIM_FILE
 *	WIMLIB_ERR_READ
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 *	WIMLIB_ERR_UNKNOWN_VERSION
 */
int
read_wim_header(WIMStruct *wim, struct wim_header *hdr)
{
	struct wim_header_disk disk_hdr _aligned_attribute(8);
	struct filedes *in_fd = &wim->in_fd;
	const tchar *filename = wim->filename;
	int ret;
	tchar *pipe_str;

	wimlib_assert(in_fd->offset == 0);

	if (filename == NULL) {
		pipe_str = alloca(40);
		tsprintf(pipe_str, T("[fd %d]"), in_fd->fd);
		filename = pipe_str;
	}

	BUILD_BUG_ON(sizeof(struct wim_header_disk) != WIM_HEADER_DISK_SIZE);

	DEBUG("Reading WIM header from \"%"TS"\"", filename);

	ret = full_read(in_fd, &disk_hdr, sizeof(disk_hdr));
	if (ret)
		goto read_error;

	hdr->magic = le64_to_cpu(disk_hdr.magic);

	if (hdr->magic != WIM_MAGIC) {
		if (hdr->magic == PWM_MAGIC) {
			/* Pipable WIM:  Use header at end instead, unless
			 * actually reading from a pipe.  */
			if (!in_fd->is_pipe) {
				ret = WIMLIB_ERR_READ;
				if (-1 == lseek(in_fd->fd, -WIM_HEADER_DISK_SIZE, SEEK_END))
					goto read_error;
				ret = full_read(in_fd, &disk_hdr, sizeof(disk_hdr));
				if (ret)
					goto read_error;
			}
		} else {
			ERROR("\"%"TS"\": Invalid magic characters in header", filename);
			return WIMLIB_ERR_NOT_A_WIM_FILE;
		}
	}

	if (le32_to_cpu(disk_hdr.hdr_size) != sizeof(struct wim_header_disk)) {
		ERROR("\"%"TS"\": Header size is invalid (%u bytes)",
		      filename, le32_to_cpu(disk_hdr.hdr_size));
		return WIMLIB_ERR_INVALID_HEADER;
	}

	hdr->wim_version = le32_to_cpu(disk_hdr.wim_version);
	if (hdr->wim_version != WIM_VERSION_DEFAULT &&
	    hdr->wim_version != WIM_VERSION_SOLID)
	{
		ERROR("\"%"TS"\": Unknown WIM version: %u",
		      filename, hdr->wim_version);
		return WIMLIB_ERR_UNKNOWN_VERSION;
	}

	hdr->flags = le32_to_cpu(disk_hdr.wim_flags);
	hdr->chunk_size = le32_to_cpu(disk_hdr.chunk_size);
	memcpy(hdr->guid, disk_hdr.guid, WIM_GUID_LEN);
	hdr->part_number = le16_to_cpu(disk_hdr.part_number);
	hdr->total_parts = le16_to_cpu(disk_hdr.total_parts);

	if (hdr->total_parts == 0 || hdr->part_number == 0 ||
	    hdr->part_number > hdr->total_parts)
	{
		ERROR("\"%"TS"\": Invalid WIM part number: %hu of %hu",
		      filename, hdr->part_number, hdr->total_parts);
		return WIMLIB_ERR_INVALID_PART_NUMBER;
	}

	hdr->image_count = le32_to_cpu(disk_hdr.image_count);

	DEBUG("part_number = %u, total_parts = %u, image_count = %u",
	      hdr->part_number, hdr->total_parts, hdr->image_count);

	if (unlikely(hdr->image_count > MAX_IMAGES)) {
		ERROR("\"%"TS"\": Invalid image count (%u)",
		      filename, hdr->image_count);
		return WIMLIB_ERR_IMAGE_COUNT;
	}

	get_wim_reshdr(&disk_hdr.lookup_table_reshdr, &hdr->lookup_table_reshdr);
	get_wim_reshdr(&disk_hdr.xml_data_reshdr, &hdr->xml_data_reshdr);
	get_wim_reshdr(&disk_hdr.boot_metadata_reshdr, &hdr->boot_metadata_reshdr);
	hdr->boot_idx = le32_to_cpu(disk_hdr.boot_idx);
	get_wim_reshdr(&disk_hdr.integrity_table_reshdr, &hdr->integrity_table_reshdr);
	return 0;

read_error:
	ERROR_WITH_ERRNO("\"%"TS"\": Error reading header", filename);
	return ret;
}

/* Writes the header for a WIM file at the specified offset.  If the offset
 * specified is the current one, the position is advanced by the size of the
 * header.  */
int
write_wim_header_at_offset(const struct wim_header *hdr, struct filedes *out_fd,
			   off_t offset)
{
	struct wim_header_disk disk_hdr _aligned_attribute(8);
	int ret;

	DEBUG("Writing %sWIM header at offset %"PRIu64,
	      ((hdr->magic == PWM_MAGIC) ? "pipable " : ""),
	      offset);

	disk_hdr.magic = cpu_to_le64(hdr->magic);
	disk_hdr.hdr_size = cpu_to_le32(sizeof(struct wim_header_disk));
	disk_hdr.wim_version = cpu_to_le32(hdr->wim_version);
	disk_hdr.wim_flags = cpu_to_le32(hdr->flags);
	if (hdr->flags & WIM_HDR_FLAG_COMPRESSION)
		disk_hdr.chunk_size = cpu_to_le32(hdr->chunk_size);
	else
		disk_hdr.chunk_size = 0;
	memcpy(disk_hdr.guid, hdr->guid, WIM_GUID_LEN);

	disk_hdr.part_number = cpu_to_le16(hdr->part_number);
	disk_hdr.total_parts = cpu_to_le16(hdr->total_parts);
	disk_hdr.image_count = cpu_to_le32(hdr->image_count);
	put_wim_reshdr(&hdr->lookup_table_reshdr, &disk_hdr.lookup_table_reshdr);
	put_wim_reshdr(&hdr->xml_data_reshdr, &disk_hdr.xml_data_reshdr);
	put_wim_reshdr(&hdr->boot_metadata_reshdr, &disk_hdr.boot_metadata_reshdr);
	disk_hdr.boot_idx = cpu_to_le32(hdr->boot_idx);
	put_wim_reshdr(&hdr->integrity_table_reshdr, &disk_hdr.integrity_table_reshdr);
	memset(disk_hdr.unused, 0, sizeof(disk_hdr.unused));

	if (offset == out_fd->offset)
		ret = full_write(out_fd, &disk_hdr, sizeof(disk_hdr));
	else
		ret = full_pwrite(out_fd, &disk_hdr, sizeof(disk_hdr), offset);
	if (ret)
		ERROR_WITH_ERRNO("Failed to write WIM header");
	return ret;
}

/* Writes the header for a WIM file at the output file descriptor's current
 * offset.  */
int
write_wim_header(const struct wim_header *hdr, struct filedes *out_fd)
{
	return write_wim_header_at_offset(hdr, out_fd, out_fd->offset);
}

/* Update just the wim_flags field. */
int
write_wim_header_flags(u32 hdr_flags, struct filedes *out_fd)
{
	le32 flags = cpu_to_le32(hdr_flags);

	return full_pwrite(out_fd, &flags, sizeof(flags),
			   offsetof(struct wim_header_disk, wim_flags));
}

int
set_wim_hdr_cflags(int ctype, struct wim_header *hdr)
{
	hdr->flags &= ~(WIM_HDR_FLAG_COMPRESSION |
			WIM_HDR_FLAG_COMPRESS_LZX |
			WIM_HDR_FLAG_COMPRESS_RESERVED |
			WIM_HDR_FLAG_COMPRESS_XPRESS |
			WIM_HDR_FLAG_COMPRESS_LZMS |
			WIM_HDR_FLAG_COMPRESS_XPRESS_2);
	switch (ctype) {

	case WIMLIB_COMPRESSION_TYPE_NONE:
		return 0;

	case WIMLIB_COMPRESSION_TYPE_LZX:
		hdr->flags |= WIM_HDR_FLAG_COMPRESSION | WIM_HDR_FLAG_COMPRESS_LZX;
		return 0;

	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		hdr->flags |= WIM_HDR_FLAG_COMPRESSION | WIM_HDR_FLAG_COMPRESS_XPRESS;
		return 0;

	case WIMLIB_COMPRESSION_TYPE_LZMS:
		hdr->flags |= WIM_HDR_FLAG_COMPRESSION | WIM_HDR_FLAG_COMPRESS_LZMS;
		return 0;

	default:
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
	}
}

/*
 * Initializes the header for a WIM file.
 */
int
init_wim_header(struct wim_header *hdr, int ctype, u32 chunk_size)
{
	memset(hdr, 0, sizeof(struct wim_header));
	hdr->magic = WIM_MAGIC;

	if (ctype == WIMLIB_COMPRESSION_TYPE_LZMS)
		hdr->wim_version = WIM_VERSION_SOLID;
	else
		hdr->wim_version = WIM_VERSION_DEFAULT;
	if (set_wim_hdr_cflags(ctype, hdr)) {
		ERROR("Invalid compression type specified (%d)", ctype);
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
	}
	hdr->chunk_size = chunk_size;
	hdr->total_parts = 1;
	hdr->part_number = 1;
	randomize_byte_array(hdr->guid, sizeof(hdr->guid));
	return 0;
}

struct hdr_flag {
	u32 flag;
	const char *name;
};
struct hdr_flag hdr_flags[] = {
	{WIM_HDR_FLAG_RESERVED,		"RESERVED"},
	{WIM_HDR_FLAG_COMPRESSION,	"COMPRESSION"},
	{WIM_HDR_FLAG_READONLY,		"READONLY"},
	{WIM_HDR_FLAG_SPANNED,		"SPANNED"},
	{WIM_HDR_FLAG_RESOURCE_ONLY,	"RESOURCE_ONLY"},
	{WIM_HDR_FLAG_METADATA_ONLY,	"METADATA_ONLY"},
	{WIM_HDR_FLAG_WRITE_IN_PROGRESS,"WRITE_IN_PROGRESS"},
	{WIM_HDR_FLAG_RP_FIX,		"RP_FIX"},
	{WIM_HDR_FLAG_COMPRESS_RESERVED,"COMPRESS_RESERVED"},
	{WIM_HDR_FLAG_COMPRESS_LZX,	"COMPRESS_LZX"},
	{WIM_HDR_FLAG_COMPRESS_XPRESS,	"COMPRESS_XPRESS"},
	{WIM_HDR_FLAG_COMPRESS_LZMS,	"COMPRESS_LZMS"},
	{WIM_HDR_FLAG_COMPRESS_XPRESS_2,"COMPRESS_XPRESS_2"},
};

/* API function documented in wimlib.h  */
WIMLIBAPI void
wimlib_print_header(const WIMStruct *wim)
{
	const struct wim_header *hdr = &wim->hdr;

	tprintf(T("Magic Characters            = MSWIM\\000\\000\\000\n"));
	tprintf(T("Header Size                 = %u\n"), WIM_HEADER_DISK_SIZE);
	tprintf(T("Version                     = 0x%x\n"), hdr->wim_version);

	tprintf(T("Flags                       = 0x%x\n"), hdr->flags);
	for (size_t i = 0; i < ARRAY_LEN(hdr_flags); i++)
		if (hdr_flags[i].flag & hdr->flags)
			tprintf(T("    WIM_HDR_FLAG_%s is set\n"), hdr_flags[i].name);

	tprintf(T("Chunk Size                  = %u\n"), hdr->chunk_size);
	tfputs (T("GUID                        = "), stdout);
	print_byte_field(hdr->guid, WIM_GUID_LEN, stdout);
	tputchar(T('\n'));
	tprintf(T("Part Number                 = %hu\n"), hdr->part_number);
	tprintf(T("Total Parts                 = %hu\n"), hdr->total_parts);
	tprintf(T("Image Count                 = %u\n"), hdr->image_count);
	tprintf(T("Lookup Table Size           = %"PRIu64"\n"),
				(u64)hdr->lookup_table_reshdr.size_in_wim);
	tprintf(T("Lookup Table Flags          = 0x%hhx\n"),
				(u8)hdr->lookup_table_reshdr.flags);
	tprintf(T("Lookup Table Offset         = %"PRIu64"\n"),
				hdr->lookup_table_reshdr.offset_in_wim);
	tprintf(T("Lookup Table Original_size  = %"PRIu64"\n"),
				hdr->lookup_table_reshdr.uncompressed_size);
	tprintf(T("XML Data Size               = %"PRIu64"\n"),
				(u64)hdr->xml_data_reshdr.size_in_wim);
	tprintf(T("XML Data Flags              = 0x%hhx\n"),
				(u8)hdr->xml_data_reshdr.flags);
	tprintf(T("XML Data Offset             = %"PRIu64"\n"),
				hdr->xml_data_reshdr.offset_in_wim);
	tprintf(T("XML Data Original Size      = %"PRIu64"\n"),
				hdr->xml_data_reshdr.uncompressed_size);
	tprintf(T("Boot Metadata Size          = %"PRIu64"\n"),
				(u64)hdr->boot_metadata_reshdr.size_in_wim);
	tprintf(T("Boot Metadata Flags         = 0x%hhx\n"),
				(u8)hdr->boot_metadata_reshdr.flags);
	tprintf(T("Boot Metadata Offset        = %"PRIu64"\n"),
				hdr->boot_metadata_reshdr.offset_in_wim);
	tprintf(T("Boot Metadata Original Size = %"PRIu64"\n"),
				hdr->boot_metadata_reshdr.uncompressed_size);
	tprintf(T("Boot Index                  = %u\n"), hdr->boot_idx);
	tprintf(T("Integrity Size              = %"PRIu64"\n"),
				(u64)hdr->integrity_table_reshdr.size_in_wim);
	tprintf(T("Integrity Flags             = 0x%hhx\n"),
				(u8)hdr->integrity_table_reshdr.flags);
	tprintf(T("Integrity Offset            = %"PRIu64"\n"),
				hdr->integrity_table_reshdr.offset_in_wim);
	tprintf(T("Integrity Original_size     = %"PRIu64"\n"),
				hdr->integrity_table_reshdr.uncompressed_size);
}
