#include "testsuite.h"

TEST(wimlib_open_wim__fails_if_wim_ret_is_null)
{
	assert_eq(WIMLIB_ERR_INVALID_PARAM,
		  wimlib_open_wim("NONEXISTENT", 0, NULL));
}

TEST(wimlib_open_wim__fails_if_filename_is_null)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_PARAM,
		  wimlib_open_wim(NULL, 0, &wim));
}

TEST(wimlib_open_wim__fails_if_filename_is_empty)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_PARAM,
		  wimlib_open_wim("", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_flags_are_unrecognized)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_PARAM,
		  wimlib_open_wim("NONEXISTENT", 0xFFFFFFFF, &wim));
}

TEST(wimlib_open_wim__fails_if_file_does_not_exist)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_OPEN,
		  wimlib_open_wim("NONEXISTENT", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_file_is_directory)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_READ,
		  wimlib_open_wim("data/wims", 0, &wim));
}

TEST(wimlib_open_wim__succeeds_on_control)
{
	WIMStruct *wim;

	assert_eq(0, wimlib_open_wim("data/wims/empty-control.wim", 0, &wim));
	wimlib_free(wim);
}

TEST(wimlib_open_wim__fails_if_magic_chars_are_bad)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_NOT_A_WIM_FILE,
		  wimlib_open_wim("data/wims/empty-bad-magic.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_version_is_unknown)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_UNKNOWN_VERSION,
		  wimlib_open_wim("data/wims/empty-unknown-version.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_part_number_and_total_parts_not_set)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_PART_NUMBER,
		  wimlib_open_wim("data/wims/empty-part-number-and-total-parts-not-set.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_part_number_exceeds_total_parts)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_PART_NUMBER,
		  wimlib_open_wim("data/wims/empty-part-number-exceeds-total-parts.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_image_count_is_insane)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_IMAGE_COUNT,
		  wimlib_open_wim("data/wims/empty-insane-image-count.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_header_size_is_too_small)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_HEADER,
		  wimlib_open_wim("data/wims/empty-header-too-small.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_header_size_is_too_large)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_HEADER,
		  wimlib_open_wim("data/wims/empty-header-too-large.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_compression_type_is_unrecognized)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_COMPRESSION_TYPE,
		  wimlib_open_wim("data/wims/empty-bad-ctype.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_if_chunk_size_is_unrecognized)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INVALID_CHUNK_SIZE,
		  wimlib_open_wim("data/wims/empty-bad-chunk-size.wim", 0, &wim));
}

TEST(wimlib_open_wim__fails_to_open_filesystem_readonly_wim_for_write)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_WIM_IS_READONLY,
		  wimlib_open_wim("data/wims/empty-readonly-fs.wim",
				  WIMLIB_OPEN_FLAG_WRITE_ACCESS,
				  &wim));
}

TEST(wimlib_open_wim__fails_to_open_flag_readonly_wim_for_write)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_WIM_IS_READONLY,
		  wimlib_open_wim("data/wims/empty-readonly-flag.wim",
				  WIMLIB_OPEN_FLAG_WRITE_ACCESS,
				  &wim));
}

TEST(wimlib_open_wim__fails_to_open_split_wim_part1_for_write)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_WIM_IS_READONLY,
		  wimlib_open_wim("data/wims/test.swm",
				  WIMLIB_OPEN_FLAG_WRITE_ACCESS,
				  &wim));
}

TEST(wimlib_open_wim__fails_to_open_split_wim_part2_for_write)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_WIM_IS_READONLY,
		  wimlib_open_wim("data/wims/test2.swm",
				  WIMLIB_OPEN_FLAG_WRITE_ACCESS,
				  &wim));
}

TEST(wimlib_open_wim__fails_to_open_split_wim_with_error_if_split)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_IS_SPLIT_WIM,
		  wimlib_open_wim("data/wims/test2.swm",
				  WIMLIB_OPEN_FLAG_ERROR_IF_SPLIT,
				  &wim));
}

TEST(wimlib_open_wim__succeeds_with_integrity_check)
{
	WIMStruct *wim;

	assert_eq(0,
		  wimlib_open_wim("data/wims/test-with-integrity.wim",
				  WIMLIB_OPEN_FLAG_CHECK_INTEGRITY,
				  &wim));
	wimlib_free(wim);
}

TEST(wimlib_open_wim__fails_if_integrity_check_fails)
{
	WIMStruct *wim;

	assert_eq(WIMLIB_ERR_INTEGRITY,
		  wimlib_open_wim("data/wims/test-with-integrity-corrupted.wim",
				  WIMLIB_OPEN_FLAG_CHECK_INTEGRITY,
				  &wim));
}
