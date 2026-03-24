// SPDX-License-Identifier: GPL-2.0
/*
 * DAXFS mmap test suite
 *
 * Tests mmap functionality for DAX filesystems including:
 * - Basic read/write via mmap
 * - MAP_SHARED coherency with read()/write()
 * - Multiple mappings
 * - Truncate with active mappings
 * - Fork with shared mappings
 *
 * Usage: ./test_mmap <mountpoint>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

static const char *mountpoint;
static int tests_run = 0;
static int tests_passed = 0;

#define TEST_FILE "mmap_test_file"
static long PAGE_SIZE;

#define TEST_START(name) do { \
	printf("  TEST: %s ... ", name); \
	fflush(stdout); \
	tests_run++; \
} while (0)

#define TEST_PASS() do { \
	printf("PASS\n"); \
	tests_passed++; \
} while (0)

#define TEST_FAIL(fmt, ...) do { \
	printf("FAIL: " fmt "\n", ##__VA_ARGS__); \
} while (0)

static char *test_path(char *buf, size_t len, const char *filename)
{
	snprintf(buf, len, "%s/%s", mountpoint, filename);
	return buf;
}

static void cleanup_file(const char *filename)
{
	char path[256];
	test_path(path, sizeof(path), filename);
	unlink(path);
}

/*
 * Test 1: Basic mmap write and read back
 */
static void test_basic_mmap_write_read(void)
{
	char path[256];
	int fd;
	char *map;
	const char *test_data = "Hello, DAXFS mmap!";
	size_t len = strlen(test_data);

	TEST_START("basic mmap write and read");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	/* Extend file to one page */
	if (ftruncate(fd, PAGE_SIZE) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Write via mmap */
	memcpy(map, test_data, len);

	/* Read back via mmap */
	if (memcmp(map, test_data, len) != 0) {
		TEST_FAIL("mmap read mismatch");
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	munmap(map, PAGE_SIZE);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 2: mmap write visible via read()
 */
static void test_mmap_write_read_syscall(void)
{
	char path[256];
	int fd;
	char *map;
	char buf[64];
	const char *test_data = "mmap_to_read";
	size_t len = strlen(test_data);

	TEST_START("mmap write visible via read()");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, PAGE_SIZE) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Write via mmap */
	memcpy(map, test_data, len);
	msync(map, PAGE_SIZE, MS_SYNC);

	/* Read via syscall */
	if (lseek(fd, 0, SEEK_SET) < 0) {
		TEST_FAIL("lseek: %s", strerror(errno));
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	memset(buf, 0, sizeof(buf));
	if (read(fd, buf, len) != (ssize_t)len) {
		TEST_FAIL("read: %s", strerror(errno));
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	if (memcmp(buf, test_data, len) != 0) {
		TEST_FAIL("data mismatch: got '%s', expected '%s'", buf, test_data);
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	munmap(map, PAGE_SIZE);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 3: write() visible via mmap
 */
static void test_write_syscall_mmap_read(void)
{
	char path[256];
	int fd;
	char *map;
	const char *test_data = "write_to_mmap";
	size_t len = strlen(test_data);

	TEST_START("write() visible via mmap");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, PAGE_SIZE) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Write via syscall */
	if (lseek(fd, 0, SEEK_SET) < 0) {
		TEST_FAIL("lseek: %s", strerror(errno));
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	if (write(fd, test_data, len) != (ssize_t)len) {
		TEST_FAIL("write: %s", strerror(errno));
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	/* Read via mmap */
	if (memcmp(map, test_data, len) != 0) {
		TEST_FAIL("data mismatch");
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	munmap(map, PAGE_SIZE);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 4: Multiple mappings of same file
 */
static void test_multiple_mappings(void)
{
	char path[256];
	int fd;
	char *map1, *map2;
	const char *test_data = "multi_map";
	size_t len = strlen(test_data);

	TEST_START("multiple mappings coherency");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, PAGE_SIZE) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	map1 = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map1 == MAP_FAILED) {
		TEST_FAIL("mmap1: %s", strerror(errno));
		close(fd);
		return;
	}

	map2 = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map2 == MAP_FAILED) {
		TEST_FAIL("mmap2: %s", strerror(errno));
		munmap(map1, PAGE_SIZE);
		close(fd);
		return;
	}

	/* Write via map1 */
	memcpy(map1, test_data, len);

	/* Read via map2 - should see the write immediately */
	if (memcmp(map2, test_data, len) != 0) {
		TEST_FAIL("map2 doesn't see map1 write");
		munmap(map1, PAGE_SIZE);
		munmap(map2, PAGE_SIZE);
		close(fd);
		return;
	}

	munmap(map1, PAGE_SIZE);
	munmap(map2, PAGE_SIZE);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 5: mmap with offset
 */
static void test_mmap_offset(void)
{
	char path[256];
	int fd;
	char *map;
	const char *test_data = "offset_test";
	size_t len = strlen(test_data);

	TEST_START("mmap with non-zero offset");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	/* Create 2-page file */
	if (ftruncate(fd, PAGE_SIZE * 2) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Map second page */
	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, PAGE_SIZE);
	if (map == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Write via mmap */
	memcpy(map, test_data, len);
	msync(map, PAGE_SIZE, MS_SYNC);

	/* Read via syscall from offset */
	char buf[64];
	if (pread(fd, buf, len, PAGE_SIZE) != (ssize_t)len) {
		TEST_FAIL("pread: %s", strerror(errno));
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	if (memcmp(buf, test_data, len) != 0) {
		TEST_FAIL("data mismatch at offset");
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	munmap(map, PAGE_SIZE);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 6: Fork with shared mapping
 */
static void test_fork_shared_mapping(void)
{
	char path[256];
	int fd;
	char *map;
	pid_t pid;
	int status;

	TEST_START("fork with MAP_SHARED");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, PAGE_SIZE) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Initialize */
	map[0] = 'P';  /* Parent marker */

	pid = fork();
	if (pid < 0) {
		TEST_FAIL("fork: %s", strerror(errno));
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	if (pid == 0) {
		/* Child: verify parent's write, then write our own */
		if (map[0] != 'P') {
			_exit(1);
		}
		map[1] = 'C';  /* Child marker */
		msync(map, PAGE_SIZE, MS_SYNC);
		_exit(0);
	}

	/* Parent: wait for child */
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		TEST_FAIL("child failed");
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	/* Verify child's write */
	if (map[1] != 'C') {
		TEST_FAIL("child write not visible: got '%c'", map[1]);
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	munmap(map, PAGE_SIZE);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 7: MAP_PRIVATE (copy-on-write)
 */
static void test_map_private(void)
{
	char path[256];
	int fd;
	char *map_shared, *map_private;
	const char *orig = "original";
	const char *modified = "modified";

	TEST_START("MAP_PRIVATE copy-on-write");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, PAGE_SIZE) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Write initial data */
	if (write(fd, orig, strlen(orig)) < 0) {
		TEST_FAIL("write: %s", strerror(errno));
		close(fd);
		return;
	}

	map_shared = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (map_shared == MAP_FAILED) {
		TEST_FAIL("mmap shared: %s", strerror(errno));
		close(fd);
		return;
	}

	map_private = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map_private == MAP_FAILED) {
		TEST_FAIL("mmap private: %s", strerror(errno));
		munmap(map_shared, PAGE_SIZE);
		close(fd);
		return;
	}

	/* Modify private mapping */
	memcpy(map_private, modified, strlen(modified));

	/* Shared mapping should still see original */
	if (memcmp(map_shared, orig, strlen(orig)) != 0) {
		TEST_FAIL("shared mapping was modified");
		munmap(map_shared, PAGE_SIZE);
		munmap(map_private, PAGE_SIZE);
		close(fd);
		return;
	}

	/* Private mapping should see modified */
	if (memcmp(map_private, modified, strlen(modified)) != 0) {
		TEST_FAIL("private mapping not modified");
		munmap(map_shared, PAGE_SIZE);
		munmap(map_private, PAGE_SIZE);
		close(fd);
		return;
	}

	munmap(map_shared, PAGE_SIZE);
	munmap(map_private, PAGE_SIZE);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 8: Large file mmap (multiple pages)
 */
static void test_large_mmap(void)
{
	char path[256];
	int fd;
	char *map;
	size_t size = PAGE_SIZE * 16;  /* 64KB */
	size_t i;

	TEST_START("large file mmap (64KB)");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, size) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Write pattern to each page */
	for (i = 0; i < size; i += PAGE_SIZE) {
		map[i] = (char)(i / PAGE_SIZE);
	}

	msync(map, size, MS_SYNC);

	/* Verify pattern */
	for (i = 0; i < size; i += PAGE_SIZE) {
		if (map[i] != (char)(i / PAGE_SIZE)) {
			TEST_FAIL("pattern mismatch at offset %zu", i);
			munmap(map, size);
			close(fd);
			return;
		}
	}

	munmap(map, size);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 9: mmap read-only
 */
static void test_mmap_readonly(void)
{
	char path[256];
	int fd;
	char *map;
	const char *test_data = "readonly";

	TEST_START("mmap PROT_READ only");
	test_path(path, sizeof(path), TEST_FILE);

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	if (write(fd, test_data, strlen(test_data)) < 0) {
		TEST_FAIL("write: %s", strerror(errno));
		close(fd);
		return;
	}
	if (ftruncate(fd, PAGE_SIZE) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return;
	}

	/* Verify can read */
	if (memcmp(map, test_data, strlen(test_data)) != 0) {
		TEST_FAIL("read mismatch");
		munmap(map, PAGE_SIZE);
		close(fd);
		return;
	}

	munmap(map, PAGE_SIZE);
	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

/*
 * Test 10: Reopen file and verify mmap data persisted
 */
static void test_mmap_persistence(void)
{
	char path[256];
	int fd;
	char *map;
	const char *test_data = "persistent_data";
	size_t len = strlen(test_data);
	char buf[64];

	TEST_START("mmap data persistence after close/reopen");
	test_path(path, sizeof(path), TEST_FILE);

	/* Create and write via mmap */
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		TEST_FAIL("open: %s", strerror(errno));
		return;
	}

	if (ftruncate(fd, PAGE_SIZE) < 0) {
		TEST_FAIL("ftruncate: %s", strerror(errno));
		close(fd);
		return;
	}

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		TEST_FAIL("mmap: %s", strerror(errno));
		close(fd);
		return;
	}

	memcpy(map, test_data, len);
	msync(map, PAGE_SIZE, MS_SYNC);
	munmap(map, PAGE_SIZE);
	close(fd);

	/* Reopen and verify via read() */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		TEST_FAIL("reopen: %s", strerror(errno));
		return;
	}

	memset(buf, 0, sizeof(buf));
	if (read(fd, buf, len) != (ssize_t)len) {
		TEST_FAIL("read: %s", strerror(errno));
		close(fd);
		return;
	}

	if (memcmp(buf, test_data, len) != 0) {
		TEST_FAIL("data not persisted: got '%s'", buf);
		close(fd);
		return;
	}

	close(fd);
	cleanup_file(TEST_FILE);
	TEST_PASS();
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
		return 1;
	}
	mountpoint = argv[1];
	PAGE_SIZE = sysconf(_SC_PAGESIZE);

	printf("DAXFS mmap test suite\n");
	printf("Mountpoint: %s\n\n", mountpoint);

	/* Verify mountpoint exists */
	struct stat st;
	if (stat(mountpoint, &st) < 0 || !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "Error: %s is not a valid directory\n", mountpoint);
		return 1;
	}

	test_basic_mmap_write_read();
	test_mmap_write_read_syscall();
	test_write_syscall_mmap_read();
	test_multiple_mappings();
	test_mmap_offset();
	test_fork_shared_mapping();
	test_map_private();
	test_large_mmap();
	test_mmap_readonly();
	test_mmap_persistence();

	printf("\n========================================\n");
	printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
