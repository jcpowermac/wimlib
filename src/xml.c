/*
 * xml.c
 *
 * Deals with the XML information in WIM files.  Uses the C library libxml2.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/timestamp.h"
#include "wimlib/xml.h"
#include "wimlib/write.h"

#include <libxml/encoding.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

struct wim_info {
	xmlDocPtr doc;
};

struct xml_string_spec {
	const char *name;
	size_t offset;
};


/* Architecture constants are from w64 mingw winnt.h  */
#define PROCESSOR_ARCHITECTURE_INTEL 0
#define PROCESSOR_ARCHITECTURE_MIPS 1
#define PROCESSOR_ARCHITECTURE_ALPHA 2
#define PROCESSOR_ARCHITECTURE_PPC 3
#define PROCESSOR_ARCHITECTURE_SHX 4
#define PROCESSOR_ARCHITECTURE_ARM 5
#define PROCESSOR_ARCHITECTURE_IA64 6
#define PROCESSOR_ARCHITECTURE_ALPHA64 7
#define PROCESSOR_ARCHITECTURE_MSIL 8
#define PROCESSOR_ARCHITECTURE_AMD64 9
#define PROCESSOR_ARCHITECTURE_IA32_ON_WIN64 10

/* Returns a statically allocated string that is a string representation of the
 * architecture number. */
static const tchar *
get_arch(int arch)
{
	switch (arch) {
	case PROCESSOR_ARCHITECTURE_INTEL:
		return T("x86");
	case PROCESSOR_ARCHITECTURE_MIPS:
		return T("MIPS");
	case PROCESSOR_ARCHITECTURE_ARM:
		return T("ARM");
	case PROCESSOR_ARCHITECTURE_IA64:
		return T("ia64");
	case PROCESSOR_ARCHITECTURE_AMD64:
		return T("x86_64");
	default:
		return T("unknown");
	}
}


/* Iterate through the children of an xmlNode. */
#define for_xml_node_child(parent, child)	\
	for (child = parent->children; child != NULL; child = child->next)

/* Utility functions for xmlNodes */
static inline bool
xml_node_is_element(const xmlNode *node)
{
	return node->type == XML_ELEMENT_NODE;
}

static inline bool
xml_node_is_text(const xmlNode *node)
{
	return node->type == XML_TEXT_NODE;
}

static inline bool
xml_node_name_is(const xmlNode *node, const char *name)
{
	return 0 == strcmp((const char *)node->name, name);
}

static u64
xml_node_get_number(const xmlNode *u64_node, int base)
{
	xmlNode *child;

	for_xml_node_child(u64_node, child)
		if (xml_node_is_text(child))
			return strtoull((const char *)child->content, NULL, base);
	return 0;
}

/* Finds the text node that is a child of an element node and returns its
 * content converted to a 64-bit unsigned integer.  Returns 0 if no text node is
 * found. */
static u64
xml_node_get_u64(const xmlNode *u64_node)
{
	return xml_node_get_number(u64_node, 10);
}

/* Like node_get_u64(), but expects a number in base 16. */
static u64
xml_node_get_hex_u64(const xmlNode *u64_node)
{
	return xml_node_get_number(u64_node, 16);
}

static int
xml_node_get_string(const xmlNode *string_node, tchar **tstr_ret)
{
	xmlNode *child;
	tchar *tstr = NULL;
	int ret;

	for_node_child(string_node, child) {
		if (xml_node_is_text(child) && child->content) {
			ret = utf8_to_tstr_simple(child->content, &tstr);
			if (ret)
				return ret;
			break;
		}
	}
	*tstr_ret = tstr;
	return 0;
}

/* Returns the timestamp from a time node.  It has child elements <HIGHPART> and
 * <LOWPART> that are then used to construct a 64-bit timestamp.  */
static u64
node_get_timestamp(const xmlNode *time_node)
{
	u32 high_part = 0;
	u32 low_part = 0;
	xmlNode *child;
	for_xml_node_child(time_node, child) {
		if (!xml_node_is_element(child))
			continue;
		if (xml_node_name_is(child, "HIGHPART"))
			high_part = node_get_hex_u64(child);
		else if (xml_node_name_is(child, "LOWPART"))
			low_part = node_get_hex_u64(child);
	}
	return (u64)low_part | ((u64)high_part << 32);
}

/* Removes an image from the XML information. */
void
xml_delete_image(struct wim_info **wim_info_p, int image)
{
	wimlib_set_xml_string();
}

size_t
xml_get_max_image_name_len(const WIMStruct *wim)
{
	size_t max_len = 0;
	for (u32 i = 0; i < wim->hdr.image_count; i++)
		max_len = max(max_len, tstrlen(wim->wim_info->images[i].name));
	return max_len;
}

void
xml_set_memory_allocator(void *(*malloc_func)(size_t),
			 void (*free_func)(void *),
			 void *(*realloc_func)(void *, size_t))
{
	xmlMemSetup(free_func, malloc_func, realloc_func, STRDUP);
}

struct image_stats {
	u64 dir_count;
	u64 file_count;
	u64 total_bytes;
	u64 hard_link_bytes;
	struct wim_lookup_table *lookup_table;
};

static int
calculate_dentry_statistics(struct wim_dentry *dentry, void *arg)
{
	struct image_stats *stats = arg;
	const struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;

	/* Update directory count and file count.
	 *
	 * Each dentry counts as either a file or a directory, but not both.
	 * The root directory is an exception: it is not counted at all.
	 *
	 * Symbolic links and junction points (and presumably other reparse
	 * points) count as regular files.  This is despite the fact that
	 * junction points have FILE_ATTRIBUTE_DIRECTORY set.
	 */
	if (dentry_is_root(dentry))
		return 0;

	if (inode_is_directory(inode))
		stats->dir_count++;
	else
		stats->file_count++;

	/*
	 * Update total bytes and hard link bytes.
	 *
	 * Unfortunately there are some inconsistencies/bugs in the way this is
	 * done.
	 *
	 * If there are no alternate data streams in the image, the "total
	 * bytes" is the sum of the size of the un-named data stream of each
	 * inode times the link count of that inode.  In other words, it would
	 * be the total number of bytes of regular files you would have if you
	 * extracted the full image without any hard-links.  The "hard link
	 * bytes" is equal to the "total bytes" minus the size of the un-named
	 * data stream of each inode.  In other words, the "hard link bytes"
	 * counts the size of the un-named data stream for all the links to each
	 * inode except the first one.
	 *
	 * Reparse points and directories don't seem to be counted in either the
	 * total bytes or the hard link bytes.
	 *
	 * And now we get to the most confusing part, the alternate data
	 * streams.  They are not counted in the "total bytes".  However, if the
	 * link count of an inode with alternate data streams is 2 or greater,
	 * the size of all the alternate data streams is included in the "hard
	 * link bytes", and this size is multiplied by the link count (NOT one
	 * less than the link count).
	 */
	lte = inode_unnamed_lte(inode, stats->lookup_table);
	if (lte) {
		stats->total_bytes += lte->size;
		if (!dentry_is_first_in_inode(dentry))
			stats->hard_link_bytes += lte->size;
	}

	if (inode->i_nlink >= 2 && dentry_is_first_in_inode(dentry)) {
		for (unsigned i = 0; i < inode->i_num_ads; i++) {
			if (inode->i_ads_entries[i].stream_name_nbytes) {
				lte = inode_stream_lte(inode, i + 1, stats->lookup_table);
				if (lte) {
					stats->hard_link_bytes += inode->i_nlink *
								  lte->size;
				}
			}
		}
	}
	return 0;
}

static int
set_image_property(WIMStruct *wim, int image, const char *property,
		   const char *value)
{
	char path[128];
	sprintf(path, "/WIM/IMAGE[@INDEX=%d]/%s", image, property);
	return wimlib_set_xml_string(wim, path, value);
}

/*
 * Calculate what to put in the <FILECOUNT>, <DIRCOUNT>, <TOTALBYTES>, and
 * <HARDLINKBYTES> elements of each <IMAGE>.
 *
 * Please note there is no official documentation for exactly how this is done.
 * But, see calculate_dentry_statistics().
 */
void
xml_update_image_info(WIMStruct *wim, int image)
{
	DEBUG("Updating the image info for image %d", image);

	struct image_stats stats = {
		.file_count = 0,
		.dir_count = 0,
		.total_bytes = 0,
		.hard_link_bytes = 0,
		.lookup_table = wim->lookup_table,
	};

	for_dentry_in_tree(wim->image_metadata[image - 1]->root_dentry,
			   calculate_dentry_statistics, &stats);

	char path[128];
	wimlib_set_xml_string(wim, "/WIM/IMAGE=%d/%s", 
	image_info->last_modification_time = get_wim_timestamp();
}

/* Adds an image to the XML information. */
int
xml_add_image(WIMStruct *wim, const tchar *name)
{
}

void
libxml_global_init(void)
{
	xmlInitParser();
	xmlInitCharEncodingHandlers();
}

void
libxml_global_cleanup(void)
{
	xmlCleanupParser();
	xmlCleanupCharEncodingHandlers();
}

void
free_wim_info(struct wim_info *info)
{
	if (info)
		xmlFreeDoc(info->doc);
}

static int
init_wim_info(xmlDocPtr doc, struct wim_info **info)
{
	struct wim_info *info;

	info = CALLOC(1, sizeof(struct wim_info));
	if (info == NULL)
		return WIMLIB_ERR_NOMEM;

	info->doc = doc;
	return 0;
}

/* Reads the XML data from a WIM file.  */
int
read_wim_xml_data(WIMStruct *wim)
{
	void *buf;
	size_t bufsize;
	u8 *xml_data;
	xmlDocPtr doc;
	int ret;

	ret = wimlib_get_xml_data(wim, &buf, &bufsize);
	if (ret)
		return ret;
	xml_data = buf;

	doc = xmlReadMemory((const char *)xml_data, bufsize,
			    NULL, "UTF-16LE", 0);
	FREE(buf);

	if (doc == NULL) {
		ERROR("Failed to parse XML data");
		return WIMLIB_ERR_XML;
	}

	ret = init_wim_info(doc, &wim->wim_info);
	if (ret) {
		xmlFreeDoc(doc);
		return ret;
	}

	return 0;
}

/* Writes the XML data to a WIM file.  */
int
write_wim_xml_data(WIMStruct *wim, int image, u64 total_bytes,
		   struct wim_reshdr *out_reshdr,
		   int write_resource_flags)
{
	int ret;
	xmlChar *xml_data;
	int xml_len;

	DEBUG("Writing WIM XML data (image=%d, offset=%"PRIu64")",
	      image, total_bytes, wim->out_fd.offset);

	xmlDocDumpFormatMemoryEnc(wim->wim_info->doc,
				  &xml_data, &xml_len, "UTF-16LE", 0);

	/* Write the XML data uncompressed.  Although wimlib can handle
	 * compressed XML data, MS software cannot.  */
	ret = write_wim_resource_from_buffer(xml_data,
					     xml_len,
					     WIM_RESHDR_FLAG_METADATA,
					     &wim->out_fd,
					     WIMLIB_COMPRESSION_TYPE_NONE,
					     0,
					     out_reshdr,
					     NULL,
					     write_resource_flags);
	FREE(xml_data);
	DEBUG("ret=%d", ret);
	return ret;
}

xmlNode *
xml_query_node(xmlDoc *doc, const char *xpathExpr)
{
	xmlXPathContext *xpathCtx;
	xmlXPathObject *xpathObj;
	xmlNodeSet *nodes;
	xmlNode *res = NULL;

	xpathCtx = xmlXPathNewContext(doc);
	if (xpathCtx == NULL) {
		ERROR("Failed to create XPath context");
		goto out;
	}

	xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
	if (xpathObj == NULL) {
		ERROR("Failed to evaluate XPath expression \"%s\"",
		      xpathExpr);
		goto out_free_xpathCtx;
	}

	nodes = xpathObj->nodesetval;
	if (nodes == NULL || nodes->nodeNr < 1) {
		DEBUG("No results found for XPath expression \"%s\"",
		      xpathExpr);
		goto out_free_xpathObj;
	}

	res = nodes->nodeTab[0];
out_free_xpathObj:
	xmlXPathFreeObject(xpathObj);
out_free_xpathCtx:
	xmlXPathFreeContext(xpathCtx);
out:
	return res;
}

/* API function documented in wimlib.h  */
WIMLIBAPI char *
wimlib_query_xml_string_utf8(const WIMStruct *wim, const char *xpathExpr)
{
	xmlDoc *doc;
	xmlNode *node;
	xmlChar *content = NULL;

	doc = wim->wim_info->doc;
	node = xml_query_node(doc, xpathExpr);
	if (node)
		content = xmlNodeListGetString(doc, node, 1);
	return (char*)content;
}

/* API function documented in wimlib.h  */
WIMLIBAPI tchar *
wimlib_query_xml_string(const WIMStruct *wim, const char *xpathExpr)
{
	char *utf8str;
	tchar *str = NULL;

	utf8str = wimlib_query_xml_string_utf8(wim, xpathExpr);
	if (utf8str) {
		utf8_to_tstr_simple(utf8str, &str);
		FREE(utf8str);
	}
	return str;
}

WIMLIBAPI int
wimlib_set_xml_string(WIMStruct *wim, const char *path,
		      const tchar *string)
{
	xmlDoc *doc;
	xmlNode *node;


	doc = wim->wim_info->doc;

	if (path == NULL || path[0] != '/')
		return WIMLIB_ERR_INVALID_PARAM;

	if (string == NULL) {
		node = xml_query_node(doc, path);
		if (node) {
			xmlUnlinkNode(node);
			xmlFreeNode(node);
		}
		return 0;
	}

	node = xmlDocGetRootElement(doc);

	if (path
	}
}

/* API function documented in wimlib.h  */
WIMLIBAPI bool
wimlib_image_name_in_use(const WIMStruct *wim, const tchar *name)
{
	if (name == NULL || name[0] == T('\0'))
		return false;
	for (int i = 1; i <= wim->hdr.image_count; i++) {
		tchar *other = wimlib_get_image_name(wim, i);
		if (other != NULL) {
			int res = tstrcmp(other, name);
			FREE(other);
			if (res == 0)
				return true;
		}
	}
	return false;
}

/* API function documented in wimlib.h  */
WIMLIBAPI tchar *
wimlib_get_image_name(const WIMStruct *wim, int image)
{
	char query[128];
	sprintf(query, "/WIM/IMAGE[@INDEX=%d]/NAME", image);
	return wimlib_query_xml_string(wim, query);
}

/* API function documented in wimlib.h  */
WIMLIBAPI tchar *
wimlib_get_image_description(const WIMStruct *wim, int image)
{
	char query[128];
	sprintf(query, "/WIM/IMAGE[@INDEX=%d]/DESCRIPTION", image);
	return wimlib_query_xml_string(wim, query);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_name(WIMStruct *wim, int image, const tchar *name)
{
	if (wimlib_image_name_in_use(wim, name))
		return WIMLIB_ERR_IMAGE_NAME_COLLISION;
	char path[128];
	sprintf(path, "/WIM/IMAGE[@INDEX=%d]/NAME", image);
	return wimlib_set_xml_string(wim, path, name);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_descripton(WIMStruct *wim, int image,
			    const tchar *description)
{
	char path[128];
	sprintf(path, "/WIM/IMAGE[INDEX=%d]/DESCRIPTION", image);
	return wimlib_set_xml_string(wim, path, description);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_set_image_flags(WIMStruct *wim, int image, const tchar *flags)
{
	char path[128];
	sprintf(path, "/WIM/IMAGE[INDEX=%d]/FLAGS", image);
	return wimlib_set_xml_string(wim, path, flags);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_get_xml_data(WIMStruct *wim, void **buf_ret, size_t *bufsize_ret)
{
	const struct wim_reshdr *xml_reshdr;

	if (wim->filename == NULL && filedes_is_seekable(&wim->in_fd))
		return WIMLIB_ERR_INVALID_PARAM;

	if (buf_ret == NULL || bufsize_ret == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	xml_reshdr = &wim->hdr.xml_data_reshdr;

	DEBUG("Reading XML data.");
	*bufsize_ret = xml_reshdr->uncompressed_size;
	return wim_reshdr_to_data(xml_reshdr, wim, buf_ret);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_extract_xml_data(WIMStruct *wim, FILE *fp)
{
	int ret;
	void *buf;
	size_t bufsize;

	ret = wimlib_get_xml_data(wim, &buf, &bufsize);
	if (ret)
		return ret;

	if (fwrite(buf, 1, bufsize, fp) != bufsize) {
		ERROR_WITH_ERRNO("Failed to extract XML data");
		ret = WIMLIB_ERR_WRITE;
	}
	FREE(buf);
	return ret;
}
