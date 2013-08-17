#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef WITH_NTFS_3G

#include "wimlib/endianness.h"
#include "wimlib/header.h"
#include "wimlib/lookup_table.h"
#include "wimlib/resource.h"
#include "wimlib/types.h"

#include <string.h>

/* The following structures define the layout of encrypted data as stored in WIM
 * files.  The format is that produced by the ReadEncryptedFileRaw() function on
 * Windows.  The format is not specifically documented, but it seems to be the
 * same as the raw data format used in the EFS RPC protocol, documented in
 * [MS-EFSR].
 */

/* [MS-EFSR] 2.2.3 "EFSRPC Raw Data Format"  */
struct efsrpc_raw_data_hdr {
	u8 magic[12];	   /* 0x00, 0x01, 0x00, 0x00,
			      0x52 ('R'), 0x00, 0x4f ('O'), 0x00,
			      0x42 ('B'), 0x00, 0x53 ('S), 0x00 */

	le32 reserved[2];  /* Must be 0  */

	/* Followed by marshaled streams, including:
	 *
	 * - EFSRPC metadata stream (variable length)
	 * - Additional streams (each of variable length)  */
} _packed_attribute;

static const u8 efsrpc_raw_data_hdr_magic[12] = {
	0x00, 0x01, 0x00, 0x00,
	0x52, 0x00, 0x4f, 0x00,
	0x42, 0x00, 0x53, 0x00,
};

/* [MS-EFSR] 2.2.3.1 "Marshaled Stream"  */
struct efsrpc_marshaled_stream_hdr {
	le32		hdr_nbytes;	/* Offset of first stream data segment
					   from this field, in bytes  */

	u8		magic[8];	/* 0x4e ('N'), 0x00, 0x54 ('T'), 0x00,
					   0x46 ('F'), 0x00, 0x53 ('S'), 0x00 */

	le32		flag;		/* 0 if stream data encrypted with FEK
					   or this is the EFSRPC metadata; 1
					   otherwise  */

	le32		reserved[2];	/* Must be 0  */

	le32		stream_name_nbytes;	/* Length, in bytes, of
						   following stream name, not
						   including null terminator; or
						   2 for EFSRPC metadata
						   streams.  */

	utf16lechar	stream_name[];	/* null-terminated UTF-16LE name of the
					   stream, or 0x1910 for EFSRPC metadata
					   streams  */

	/* Followed by one or more stream data segments  */
} _packed_attribute;

static const u8 efsrpc_marshaled_stream_hdr_magic[8] = {
	0x4e, 0x00, 0x54, 0x00,
	0x46, 0x00, 0x53, 0x00,
};

static const u8 efsrpc_metadata_stream_name[2] = {
	0x19, 0x10,
};

static const u8 efsrpc_data_stream_name[14] = {
	':', '\0', ':', '\0', '$', '\0',
	'D', '\0', 'A', '\0', 'T', '\0', 'A', '\0',
};

/* [MS-EFSR] 2.2.3.2 "Stream Data Segment"  */
struct efsrpc_data_segment_hdr {
	le32	segment_nbytes;		/* Size of this segment in bytes, from
					   beginning of this field to end of
					   stream data.  */
	u8	magic[8];		/* 0x47 ('G'), 0x00, 0x55 ('U'), 0x00,
					   0x52 ('R'), 0x00, 0x45 ('E'), 0x00 */
	le32	reserved;

	/* If stream data is encrypted and this is not the EFSRPC metadata
	 * stream, followed by data segment encryption header.  */
} _packed_attribute;

static const u8 efsrpc_data_segment_hdr_magic[8] = {
	0x47, 0x00, 0x55, 0x00,
	0x52, 0x00, 0x45, 0x00,
};

/* [MS-EFSR] 2.2.3.3 "Data Segment Encryption Header"  */
struct efsrpc_data_segment_encryption_hdr {
	le64	starting_file_offset;	/* Offset of this segment, in bytes,
					   into the stream being serialized  */
	le32	hdr_nbytes;		/* Size of this header, from beginning
					   of starting_file_offset to end of
					   header.  */
	le32	bytes_within_stream_size;	/* Number of bytes in this
						   stream data segment that fall
						   within the stream size  */
	le32	bytes_within_vdl;	/* Number of bytes in this stream data
					   segment that fall in the "valid data
					   length"  */

	le16	zero;			/* 0x0000  */

	u8	data_unit_shift;	/* Base-2 logarithm of data unit size.
					   Non-sparse files:  data unit size =
							size of data in segment
					   Sparse files:  data unix size =
						size of compression unit  */

	u8	chunk_shift;		/* Base-2 logarithm of chunk size (chunk
					   size must be same as data unit size)
					   */

	u8	cluster_shift;		/* Base-2 logarithm of cluster size, in
					   bytes, in the underlying filesystem
					  */
	u8	one;			/* 0x01  */

	le16	num_data_blocks;	/* Number of data blocks in segment  */

	le32	data_block_sizes[0];	/* Array of length num_data_blocks
					   containing the sizes of the following
					   data blocks.  */

	/* (optional) extended header  */
} _packed_attribute;

struct efsrpc_extended_header {
	u8 magic[8];	/* 0x45, 0x58, 0x54, 0x44, 0x10, 0x00, 0x00, 0x00  */

	le32 flags;	/* 0x00000001 if stream contained in sparse file; 0
			   otherwise  */

	le32 reserved;
} _packed_attribute;

struct efs_extract_raw_ctx {
	consume_data_callback_t efsdata_cb;
	consume_data_callback_t efsinfo_cb;
	void *caller_ctx;
	u8 buf[WIM_CHUNK_SIZE * 2];
	size_t buf_pos;
	size_t buf_filled;
	u64 resource_bytes_remaining;
	u64 file_offset;
	enum {
		EFS_STATE_BEGIN_RAW_DATA,
		EFS_STATE_BEGIN_MARSHALED_STREAM,
		EFS_STATE_BEGIN_DATA_SEGMENT,
		EFS_STATE_BEGIN_ENCRYPTED_DATA_SEGMENT,
		EFS_STATE_CONTINUE_DATA_SEGMENT,
		EFS_STATE_DONE,
	} state;
	u32 segment_bytes_remaining;
	bool found_data_stream;
	bool found_efsrpc_metadata_stream;
	bool stream_encrypted;
};

#define EFS_NEEDMORE (-1)

static int
efs_begin_raw_data(struct efs_extract_raw_ctx *ctx)
{
	const struct efsrpc_raw_data_hdr *hdr;

	if (ctx->buf_filled < sizeof(*hdr))
		return EFS_NEEDMORE;
	hdr = (const struct efsrpc_raw_data_hdr*)&ctx->buf[ctx->buf_pos];
	if (memcmp(hdr->magic, efsrpc_raw_data_hdr_magic, sizeof(hdr->magic)))
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;
	ctx->buf_pos += sizeof(*hdr);
	ctx->buf_filled -= sizeof(*hdr);
	ctx->state = EFS_STATE_BEGIN_MARSHALED_STREAM;
	return 0;
}

static int
efs_begin_marshaled_stream(struct efs_extract_raw_ctx *ctx)
{
	const struct efsrpc_marshaled_stream_hdr *hdr;

	if (ctx->found_data_stream && ctx->found_data_stream) {
		ctx->state = EFS_STATE_DONE;
		return 0;
	}

	if (ctx->buf_filled < sizeof(*hdr))
		return EFS_NEEDMORE;

	hdr = (const struct efsrpc_marshaled_stream_hdr*)&ctx->buf[ctx->buf_pos];

	if (le32_to_cpu(hdr->hdr_nbytes) >= WIM_CHUNK_SIZE)
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;

	if (le32_to_cpu(hdr->hdr_nbytes) > ctx->buf_filled)
		return EFS_NEEDMORE;

	if (memcmp(hdr->magic, efsrpc_marshaled_stream_hdr_magic, sizeof(hdr->magic)))
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;

	ctx->stream_encrypted = !(le32_to_cpu(hdr->flag) & 0x00000001);
	if (le16_to_cpu(hdr->stream_name_nbytes) == 0 ||
	    le16_to_cpu(hdr->stream_name_nbytes) + sizeof(*hdr) > 
		    le16_to_cpu(hdr->hdr_nbytes) ||
	    (le16_to_cpu(hdr->stream_name_nbytes) & 1))
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;

	if (le16_to_cpu(hdr->stream_name_nbytes) == sizeof(efsrpc_metadata_stream_name) &&
	    !memcmp(hdr->stream_name, efsrpc_metadata_stream_name,
		    sizeof(efsrpc_metadata_stream_name)))
	{
		if (ctx->found_efsrpc_metadata_stream)
			return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;
		ctx->stream_encrypted = false;
		ctx->found_efsrpc_metadata_stream = true;
	} else if (le16_to_cpu(hdr->stream_name_nbytes) == sizeof(efsrpc_data_stream_name) &&
	    !memcmp(hdr->stream_name, efsrpc_data_stream_name,
		    sizeof(efsrpc_data_stream_name)))
	{
		if (ctx->found_data_stream || !ctx->stream_encrypted)
			return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;
		ctx->found_data_stream = true;
	} else {
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;
	}

	ctx->state = EFS_STATE_BEGIN_DATA_SEGMENT;
	ctx->file_offset = 0;
	ctx->buf_pos += le32_to_cpu(hdr->hdr_nbytes);
	ctx->buf_filled -= le32_to_cpu(hdr->hdr_nbytes);
	return 0;
}

static int
efs_begin_data_segment(struct efs_extract_raw_ctx *ctx)
{
	const struct efsrpc_data_segment_hdr *hdr;

	if (ctx->buf_filled < sizeof(*hdr))
		return EFS_NEEDMORE;

	hdr = (const struct efsrpc_data_segment_hdr*)&ctx->buf[ctx->buf_pos];

	if (memcmp(hdr->magic, efsrpc_data_segment_hdr_magic, sizeof(hdr->magic)))
	{
		if (!memcmp(hdr->magic, efsrpc_marshaled_stream_hdr_magic,
			    sizeof(hdr->magic)))
		{
			ctx->state = EFS_STATE_BEGIN_MARSHALED_STREAM;
			return 0;
		}
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;
	}

	ctx->segment_bytes_remaining = le32_to_cpu(hdr->segment_nbytes);
	if (ctx->segment_bytes_remaining < sizeof(*hdr))
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;
	ctx->segment_bytes_remaining -= sizeof(*hdr);

	ctx->buf_filled -= sizeof(*hdr);
	ctx->buf_pos += sizeof(*hdr);

	if (ctx->stream_encrypted) {
		ctx->state = EFS_STATE_BEGIN_ENCRYPTED_DATA_SEGMENT;
	} else {
		ctx->state = EFS_STATE_CONTINUE_DATA_SEGMENT;
		if (ctx->segment_bytes_remaining >
		    ctx->resource_bytes_remaining + ctx->buf_filled)
			return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;
	}
	return 0;
}

static int
efs_begin_encrypted_data_segment(struct efs_extract_raw_ctx *ctx)
{
	const struct efsrpc_data_segment_encryption_hdr *hdr;

	if (ctx->buf_filled < sizeof(*hdr))
		return EFS_NEEDMORE;

	hdr = (const struct efsrpc_data_segment_encryption_hdr)&ctx->buf[ctx->buf_pos];

	if (le32_to_cpu(hdr->hdr_nbytes) >= WIM_CHUNK_SIZE)
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;

	if (le32_to_cpu(hdr->hdr_nbytes) > ctx->buf_filled)
		return EFS_NEEDMORE;

	if (le64_to_cpu(hdr->starting_file_offset) != ctx->file_offset)
		return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;

}

static int
efs_continue_data_segment(struct efs_extract_raw_ctx *ctx)
{
	size_t len_to_provide;
	int ret;

	len_to_provide = min(ctx->segment_bytes_remaining, ctx->buf_filled);
	ret = (*ctx->efsdata_cb)(&ctx->buf[ctx->buf_pos], len_to_provide,
				 ctx->caller_ctx);
	if (ret)
		return ret;
	ctx->buf_pos += len_to_provide;
	ctx->buf_filled -= len_to_provide;
	ctx->segment_bytes_remaining -= len_to_provide;
	ctx->file_offset += len_to_provide;
	if (ctx->segment_bytes_remaining == 0)
		ctx->state = EFS_STATE_BEGIN_DATA_SEGMENT;
	return 0;
}

static int
efs_extract_raw_cb(const void *buf, size_t len, void *_ctx)
{
	struct efs_extract_raw_ctx *ctx = _ctx;
	int ret;

	wimlib_assert(len <= WIM_CHUNK_SIZE);
	wimlib_assert(ctx->buf_filled < WIM_CHUNK_SIZE);
	wimlib_assert(len <= ctx->resource_bytes_remaining);

	ctx->resource_bytes_remaining -= len;

	if (ctx->buf_pos >= WIM_CHUNK_SIZE) {
		memcpy(ctx->buf, ctx->buf + ctx->buf_pos, ctx->buf_filled);
		ctx->buf_pos = 0;
	}

	memcpy(ctx->buf + ctx->buf_pos, buf, len);
	ctx->buf_filled += len;

	for (;;) {
		switch (ctx->state) {
		case EFS_STATE_BEGIN_RAW_DATA:
			ret = efs_begin_raw_data(ctx);
			break;
		case EFS_STATE_BEGIN_MARSHALED_STREAM:
			ret = efs_begin_marshaled_stream(ctx);
			break;
		case EFS_STATE_BEGIN_DATA_SEGMENT:
			ret = efs_begin_data_segment(ctx);
			break;
		case EFS_STATE_BEGIN_ENCRYPTED_DATA_SEGMENT:
			ret = efs_begin_encrypted_data_segment(ctx);
			break;
		case EFS_STATE_CONTINUE_DATA_SEGMENT:
			ret = efs_continue_data_segment(ctx);
			break;
		case EFS_STATE_DONE:
			return 0;
		default:
			wimlib_assert(0);
		}
		if (ret) {
			if (ret == EFS_NEEDMORE) {
				if (ctx->buf_filled >= WIM_CHUNK_SIZE ||
				    ctx->resource_bytes_remaining == 0)
					return WIMLIB_ERR_INVALID_ENCRYPTED_STREAM;
				return 0;
			}
			return ret;
		}
	}
}

int
extract_wim_efs_resource(struct wim_lookup_table_entry *lte,
			 consume_data_callback_t efsdata_cb,
			 consume_data_callback_t efsinfo_cb,
			 void *caller_ctx)
{
	struct efs_extract_raw_ctx ctx = {
		.efsdata_cb = efsdata_cb,
		.efsinfo_cb = efsinfo_cb,
		.caller_ctx = caller_ctx,
		.buf_pos = 0,
		.buf_filled = 0,
		.resource_bytes_remaining = wim_resource_size(lte),
		.state = EFS_STATE_BEGIN_RAW_DATA,
	};
	return read_resource_prefix(lte, wim_resource_size(lte),
				    efs_extract_raw_cb, &ctx, 0);
}

#endif /* WITH_NTFS_3G */
