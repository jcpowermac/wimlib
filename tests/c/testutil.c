#include "testsuite.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Loads the contents of the file @name from the data directory.  */
void *
load_data_file(const char *name, size_t *size_ret)
{
	char namebuf[256];
	struct stat st;
	int fd;
	void *buf;

	sprintf(namebuf, "data/%s", name);

	fd = open(namebuf, O_RDONLY);
	if (fd < 0)
		fail("Can't open data file %s", namebuf);

	if (fstat(fd, &st))
		fail("Error reading data file %s", namebuf);

	buf = xmalloc(st.st_size);

	if (read(fd, buf, st.st_size) != st.st_size)
		fail("Error reading data file %s", namebuf);

	*size_ret = st.st_size;
	return buf;
}

void *
xmalloc(size_t size)
{
	void *p;

	p = malloc(size);
	if (!p)
		fail("Out of memory");
	return p;
}

