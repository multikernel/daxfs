// SPDX-License-Identifier: GPL-2.0
/*
 * mkdaxfs - Create daxfs filesystem images
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * Creates a daxfs image from a directory tree. Can write to a file,
 * directly to physical memory via /dev/mem, or allocate from a DMA
 * heap and mount immediately.
 *
 * Usage:
 *   mkdaxfs -d /path/to/rootfs -o image.daxfs
 *   mkdaxfs -d /path/to/rootfs -H /dev/dma_heap/multikernel -s 256M -m /mnt
 *   mkdaxfs -d /path/to/rootfs -p 0x100000000 -s 256M
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <sys/ioctl.h>

#include "daxfs_format.h"

#define DAXFS_BRANCH_TABLE_SIZE		(DAXFS_MAX_BRANCHES * sizeof(struct daxfs_branch))
#define DAXFS_DEFAULT_DELTA_SIZE	(64 * 1024 * 1024)  /* 64MB default delta region */

/* From linux/dma-heap.h */
struct dma_heap_allocation_data {
	uint64_t len;
	uint32_t fd;
	uint32_t fd_flags;
	uint64_t heap_flags;
};
#define DMA_HEAP_IOC_MAGIC	'H'
#define DMA_HEAP_IOCTL_ALLOC	_IOWR(DMA_HEAP_IOC_MAGIC, 0x0, \
				      struct dma_heap_allocation_data)

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

struct file_entry {
	char path[PATH_MAX];
	char name[DAXFS_NAME_MAX + 1];  /* 128 + null */
	struct stat st;
	uint32_t ino;
	uint32_t parent_ino;
	uint64_t data_offset;		/* For files: file data; for dirs: dirent array */
	uint32_t child_count;		/* Number of direct children (for dirs) */
	struct file_entry *next;
};

static struct file_entry *files_head;
static struct file_entry *files_tail;
static uint32_t file_count;
static uint32_t next_ino = 1;

static struct file_entry *find_by_path(const char *path)
{
	struct file_entry *e;

	for (e = files_head; e; e = e->next) {
		if (strcmp(e->path, path) == 0)
			return e;
	}
	return NULL;
}

static struct file_entry *add_file(const char *path, struct stat *st)
{
	struct file_entry *e;
	char *slash;
	size_t name_len;

	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	strncpy(e->path, path, sizeof(e->path) - 1);
	e->st = *st;
	e->ino = next_ino++;

	slash = strrchr(path, '/');
	if (slash && slash[1])
		name_len = strlen(slash + 1);
	else
		name_len = strlen(path);

	if (name_len > DAXFS_NAME_MAX) {
		fprintf(stderr, "Warning: name too long, truncating: %s\n",
			slash ? slash + 1 : path);
		name_len = DAXFS_NAME_MAX;
	}

	if (slash && slash[1])
		strncpy(e->name, slash + 1, DAXFS_NAME_MAX);
	else
		strncpy(e->name, path, DAXFS_NAME_MAX);
	e->name[DAXFS_NAME_MAX] = '\0';

	if (!files_head) {
		files_head = files_tail = e;
	} else {
		files_tail->next = e;
		files_tail = e;
	}
	file_count++;

	return e;
}

static int scan_directory_recursive(const char *base, const char *relpath)
{
	char fullpath[PATH_MAX * 2];
	char newrel[PATH_MAX];
	DIR *dir;
	struct dirent *de;
	struct stat st;

	if (relpath[0])
		snprintf(fullpath, sizeof(fullpath), "%s/%s", base, relpath);
	else
		snprintf(fullpath, sizeof(fullpath), "%s", base);

	dir = opendir(fullpath);
	if (!dir) {
		perror(fullpath);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		if (relpath[0])
			snprintf(newrel, sizeof(newrel), "%s/%s", relpath, de->d_name);
		else
			snprintf(newrel, sizeof(newrel), "%s", de->d_name);

		snprintf(fullpath, sizeof(fullpath), "%s/%s", base, newrel);

		if (lstat(fullpath, &st) < 0) {
			perror(fullpath);
			continue;
		}

		add_file(newrel, &st);

		if (S_ISDIR(st.st_mode))
			scan_directory_recursive(base, newrel);
	}

	closedir(dir);
	return 0;
}

static int scan_directory(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		perror(path);
		return -1;
	}

	add_file("", &st);

	return scan_directory_recursive(path, "");
}

static void build_tree(void)
{
	struct file_entry *e, *parent;
	char parent_path[PATH_MAX];
	char *slash;

	for (e = files_head; e; e = e->next) {
		if (e->path[0] == '\0') {
			e->parent_ino = 0;
			continue;
		}

		snprintf(parent_path, sizeof(parent_path), "%s", e->path);
		slash = strrchr(parent_path, '/');
		if (slash)
			*slash = '\0';
		else
			parent_path[0] = '\0';

		parent = find_by_path(parent_path);
		if (parent) {
			e->parent_ino = parent->ino;
			parent->child_count++;
		}
	}
}

static void calculate_offsets(void)
{
	struct file_entry *e;
	uint64_t inode_offset = DAXFS_BLOCK_SIZE;
	/* v3 format: no string table, data area directly after inodes */
	uint64_t data_offset = ALIGN(inode_offset + file_count * DAXFS_INODE_SIZE,
				     DAXFS_BLOCK_SIZE);

	for (e = files_head; e; e = e->next) {
		if (S_ISREG(e->st.st_mode)) {
			e->data_offset = data_offset;
			data_offset += ALIGN(e->st.st_size, DAXFS_BLOCK_SIZE);
		} else if (S_ISLNK(e->st.st_mode)) {
			e->data_offset = data_offset;
			/* +1 for null terminator */
			data_offset += ALIGN(e->st.st_size + 1, DAXFS_BLOCK_SIZE);
		} else if (S_ISDIR(e->st.st_mode) && e->child_count > 0) {
			/* Directories store dirent array in data area */
			e->data_offset = data_offset;
			data_offset += ALIGN(e->child_count * DAXFS_DIRENT_SIZE,
					     DAXFS_BLOCK_SIZE);
		}
	}
}

/*
 * Write the base image portion (embedded read-only snapshot)
 * v3 format: flat directories with inline names, no string table
 */
static int write_base_image(void *mem, size_t mem_size, const char *src_dir)
{
	struct file_entry *e, *child;
	struct daxfs_base_super *base_super = mem;
	struct daxfs_base_inode *inodes;
	uint64_t inode_offset = DAXFS_BLOCK_SIZE;
	uint64_t data_offset = ALIGN(inode_offset + file_count * DAXFS_INODE_SIZE,
				     DAXFS_BLOCK_SIZE);

	memset(mem, 0, mem_size);

	/* v3 base superblock - no string table */
	base_super->magic = htole32(DAXFS_BASE_MAGIC);
	base_super->version = htole32(DAXFS_VERSION);
	base_super->flags = htole32(0);
	base_super->block_size = htole32(DAXFS_BLOCK_SIZE);
	base_super->inode_count = htole32(file_count);
	base_super->root_inode = htole32(DAXFS_ROOT_INO);
	base_super->inode_offset = htole64(inode_offset);
	base_super->data_offset = htole64(data_offset);

	inodes = mem + inode_offset;

	for (e = files_head; e; e = e->next) {
		struct daxfs_base_inode *di = &inodes[e->ino - 1];

		di->ino = htole32(e->ino);
		di->mode = htole32(e->st.st_mode);
		di->uid = htole32(e->st.st_uid);
		di->gid = htole32(e->st.st_gid);
		di->nlink = htole32(e->st.st_nlink);

		if (S_ISREG(e->st.st_mode)) {
			char fullpath[PATH_MAX * 2];
			int fd;
			ssize_t n;

			di->size = htole64(e->st.st_size);
			di->data_offset = htole64(e->data_offset);

			snprintf(fullpath, sizeof(fullpath), "%s/%s", src_dir, e->path);
			fd = open(fullpath, O_RDONLY);
			if (fd < 0) {
				perror(fullpath);
				continue;
			}
			n = read(fd, mem + e->data_offset, e->st.st_size);
			if (n < 0)
				perror(fullpath);
			close(fd);
		} else if (S_ISLNK(e->st.st_mode)) {
			char fullpath[PATH_MAX * 2];
			ssize_t n;

			di->size = htole64(e->st.st_size);
			di->data_offset = htole64(e->data_offset);

			snprintf(fullpath, sizeof(fullpath), "%s/%s", src_dir, e->path);
			n = readlink(fullpath, mem + e->data_offset, e->st.st_size);
			if (n < 0)
				perror(fullpath);
			else
				/* Ensure null-termination for kernel safety */
				((char *)(mem + e->data_offset))[n] = '\0';
		} else if (S_ISDIR(e->st.st_mode)) {
			/* Directory: write dirent array */
			struct daxfs_dirent *dirents;
			uint32_t dirent_idx = 0;

			/* Size = number of entries * DAXFS_DIRENT_SIZE */
			di->size = htole64((uint64_t)e->child_count * DAXFS_DIRENT_SIZE);
			di->data_offset = htole64(e->data_offset);

			if (e->child_count > 0) {
				dirents = mem + e->data_offset;

				/* Find all children and write dirents */
				for (child = files_head; child; child = child->next) {
					if (child->parent_ino == e->ino) {
						struct daxfs_dirent *de = &dirents[dirent_idx++];
						size_t name_len = strlen(child->name);

						de->ino = htole32(child->ino);
						de->mode = htole32(child->st.st_mode);
						de->name_len = htole16(name_len);
						memcpy(de->name, child->name, name_len);
					}
				}
			}
		}
	}

	/* Calculate and set total size */
	{
		uint64_t total = data_offset;
		for (e = files_head; e; e = e->next) {
			if (S_ISREG(e->st.st_mode))
				total = e->data_offset + ALIGN(e->st.st_size, DAXFS_BLOCK_SIZE);
			else if (S_ISLNK(e->st.st_mode))
				total = e->data_offset + ALIGN(e->st.st_size + 1, DAXFS_BLOCK_SIZE);
			else if (S_ISDIR(e->st.st_mode) && e->child_count > 0)
				total = e->data_offset + ALIGN(e->child_count * DAXFS_DIRENT_SIZE,
							       DAXFS_BLOCK_SIZE);
		}
		base_super->total_size = htole64(total);
	}

	return 0;
}

static size_t calculate_base_size(void)
{
	struct file_entry *e;
	uint64_t inode_offset = DAXFS_BLOCK_SIZE;
	/* v3 format: no string table, data area directly after inodes */
	uint64_t data_offset = ALIGN(inode_offset + file_count * DAXFS_INODE_SIZE,
				     DAXFS_BLOCK_SIZE);
	size_t total = data_offset;

	for (e = files_head; e; e = e->next) {
		if (S_ISREG(e->st.st_mode))
			total += ALIGN(e->st.st_size, DAXFS_BLOCK_SIZE);
		else if (S_ISLNK(e->st.st_mode))
			total += ALIGN(e->st.st_size + 1, DAXFS_BLOCK_SIZE);  /* +1 for null */
		else if (S_ISDIR(e->st.st_mode) && e->child_count > 0)
			total += ALIGN(e->child_count * DAXFS_DIRENT_SIZE, DAXFS_BLOCK_SIZE);
	}

	return total;
}

/* New mount API constants (may not be in older headers) */
#ifndef FSCONFIG_SET_FD
#define FSCONFIG_SET_FD		5
#endif
#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE	6
#endif
#ifndef FSCONFIG_SET_FLAG
#define FSCONFIG_SET_FLAG	0
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH	0x00000004
#endif
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY	0x00000001
#endif

static inline int sys_fsopen(const char *fstype, unsigned int flags)
{
	return syscall(__NR_fsopen, fstype, flags);
}

static inline int sys_fsconfig(int fd, unsigned int cmd, const char *key,
			       const void *value, int aux)
{
	return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}

static inline int sys_fsmount(int fd, unsigned int flags, unsigned int attr_flags)
{
	return syscall(__NR_fsmount, fd, flags, attr_flags);
}

static inline int sys_move_mount(int from_dfd, const char *from_path,
				 int to_dfd, const char *to_path,
				 unsigned int flags)
{
	return syscall(__NR_move_mount, from_dfd, from_path,
		       to_dfd, to_path, flags);
}

/*
 * Mount a daxfs filesystem backed by a dma-buf fd using the new mount API.
 */
static int mount_daxfs_dmabuf(int dmabuf_fd, const char *mountpoint,
			      bool writable, bool validate)
{
	int fs_fd, mnt_fd;

	fs_fd = sys_fsopen("daxfs", 0);
	if (fs_fd < 0) {
		perror("fsopen(daxfs)");
		return -1;
	}

	if (sys_fsconfig(fs_fd, FSCONFIG_SET_FD, "dmabuf", NULL, dmabuf_fd) < 0) {
		perror("fsconfig(FSCONFIG_SET_FD, dmabuf)");
		close(fs_fd);
		return -1;
	}

	if (writable) {
		if (sys_fsconfig(fs_fd, FSCONFIG_SET_FLAG, "rw", NULL, 0) < 0) {
			perror("fsconfig(FSCONFIG_SET_FLAG, rw)");
			close(fs_fd);
			return -1;
		}
	}

	if (validate) {
		if (sys_fsconfig(fs_fd, FSCONFIG_SET_FLAG, "validate", NULL, 0) < 0) {
			perror("fsconfig(FSCONFIG_SET_FLAG, validate)");
			close(fs_fd);
			return -1;
		}
	}

	if (sys_fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
		perror("fsconfig(FSCONFIG_CMD_CREATE)");
		close(fs_fd);
		return -1;
	}

	mnt_fd = sys_fsmount(fs_fd, 0, writable ? 0 : MOUNT_ATTR_RDONLY);
	if (mnt_fd < 0) {
		perror("fsmount");
		close(fs_fd);
		return -1;
	}
	close(fs_fd);

	if (sys_move_mount(mnt_fd, "", AT_FDCWD, mountpoint,
			   MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		perror("move_mount");
		close(mnt_fd);
		return -1;
	}
	close(mnt_fd);

	return 0;
}

/*
 * Write static daxfs image (read-only, no branching)
 * Layout: [Superblock (4KB)] [Base Image]
 */
static int write_static_image(void *mem, size_t mem_size, const char *src_dir,
			      size_t base_size)
{
	struct daxfs_super *super = mem;
	uint64_t base_offset = DAXFS_BLOCK_SIZE;

	if (base_offset + base_size > mem_size) {
		fprintf(stderr, "Error: image too large for allocated space\n");
		return -1;
	}

	memset(mem, 0, mem_size);

	/* Write superblock */
	super->magic = htole32(DAXFS_SUPER_MAGIC);
	super->version = htole32(DAXFS_VERSION);
	super->flags = htole32(0);
	super->block_size = htole32(DAXFS_BLOCK_SIZE);
	super->total_size = htole64(base_offset + base_size);

	super->base_offset = htole64(base_offset);
	super->base_size = htole64(base_size);

	/* No branch table or delta region for static images */
	super->branch_table_offset = htole64(0);
	super->branch_table_entries = htole32(0);
	super->active_branches = htole32(0);
	super->next_branch_id = htole64(0);
	super->next_inode_id = htole64(file_count + 1);

	super->delta_region_offset = htole64(0);
	super->delta_region_size = htole64(0);
	super->delta_alloc_offset = htole64(0);

	/* Write embedded base image */
	write_base_image(mem + base_offset, base_size, src_dir);

	printf("Image layout (static):\n");
	printf("  Superblock:    0x%x - 0x%x\n", 0, DAXFS_BLOCK_SIZE);
	printf("  Base image:    0x%lx - 0x%lx (%zu bytes)\n",
	       (unsigned long)base_offset,
	       (unsigned long)(base_offset + base_size),
	       base_size);

	return 0;
}

/*
 * Write daxfs image with branching support (read-write)
 * Layout: [Superblock (4KB)] [Branch Table] [Base Image] [Delta Region]
 */
static int write_image(void *mem, size_t mem_size, const char *src_dir,
		       size_t base_size, size_t delta_size)
{
	struct daxfs_super *super = mem;
	uint64_t branch_table_offset;
	uint64_t delta_region_offset;
	uint64_t base_offset;

	branch_table_offset = DAXFS_BLOCK_SIZE;
	base_offset = ALIGN(branch_table_offset + DAXFS_BRANCH_TABLE_SIZE, DAXFS_BLOCK_SIZE);
	delta_region_offset = ALIGN(base_offset + base_size, DAXFS_BLOCK_SIZE);

	if (delta_region_offset + delta_size > mem_size) {
		fprintf(stderr, "Error: image too large for allocated space\n");
		return -1;
	}

	memset(mem, 0, mem_size);

	/* Write superblock */
	super->magic = htole32(DAXFS_SUPER_MAGIC);
	super->version = htole32(DAXFS_VERSION);
	super->flags = htole32(0);
	super->block_size = htole32(DAXFS_BLOCK_SIZE);
	super->total_size = htole64(delta_region_offset + delta_size);

	super->base_offset = htole64(base_offset);
	super->base_size = htole64(base_size);

	super->branch_table_offset = htole64(branch_table_offset);
	super->branch_table_entries = htole32(DAXFS_MAX_BRANCHES);
	super->active_branches = htole32(0);  /* No branches yet, created on mount */
	super->next_branch_id = htole64(1);
	super->next_inode_id = htole64(file_count + 1);

	super->delta_region_offset = htole64(delta_region_offset);
	super->delta_region_size = htole64(delta_size);
	super->delta_alloc_offset = htole64(delta_region_offset);

	/* Branch table is already zeroed (FREE state) */

	/* Write embedded base image */
	write_base_image(mem + base_offset, base_size, src_dir);

	printf("Image layout (with branching):\n");
	printf("  Superblock:    0x%x - 0x%x\n", 0, DAXFS_BLOCK_SIZE);
	printf("  Branch table:  0x%lx - 0x%lx (%u entries)\n",
	       (unsigned long)branch_table_offset,
	       (unsigned long)(branch_table_offset + DAXFS_BRANCH_TABLE_SIZE),
	       DAXFS_MAX_BRANCHES);
	printf("  Base image:    0x%lx - 0x%lx (%zu bytes)\n",
	       (unsigned long)base_offset,
	       (unsigned long)(base_offset + base_size),
	       base_size);
	printf("  Delta region:  0x%lx - 0x%lx (%zu bytes)\n",
	       (unsigned long)delta_region_offset,
	       (unsigned long)(delta_region_offset + delta_size),
	       delta_size);

	return 0;
}

static size_t calculate_static_size(size_t base_size)
{
	return DAXFS_BLOCK_SIZE + base_size;
}

static size_t calculate_total_size(size_t base_size, size_t delta_size)
{
	uint64_t branch_table_offset = DAXFS_BLOCK_SIZE;
	uint64_t base_offset = ALIGN(branch_table_offset + DAXFS_BRANCH_TABLE_SIZE,
				     DAXFS_BLOCK_SIZE);
	uint64_t delta_region_offset = ALIGN(base_offset + base_size, DAXFS_BLOCK_SIZE);

	return delta_region_offset + delta_size;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -d, --directory DIR    Source directory\n");
	fprintf(stderr, "  -o, --output FILE      Output file\n");
	fprintf(stderr, "  -H, --heap PATH        Allocate from DMA heap (e.g., /dev/dma_heap/multikernel)\n");
	fprintf(stderr, "  -m, --mountpoint DIR   Mount after creating (required with -H)\n");
	fprintf(stderr, "  -p, --phys ADDR        Write to physical address via /dev/mem\n");
	fprintf(stderr, "  -s, --size SIZE        Size to allocate (required with -H or -p)\n");
	fprintf(stderr, "  -w, --writable         Enable branching and mount read-write\n");
	fprintf(stderr, "  -V, --validate         Validate image on mount\n");
	fprintf(stderr, "  -D, --delta SIZE       Delta region size (default: 64M, only with -w)\n");
	fprintf(stderr, "  -h, --help             Show this help\n");
	fprintf(stderr, "\nBy default, creates a static read-only image without branching support.\n");
	fprintf(stderr, "Use -w to enable branching (adds branch table and delta region).\n");
	fprintf(stderr, "\nExamples:\n");
	fprintf(stderr, "  %s -d /path/to/rootfs -o image.daxfs\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -H /dev/dma_heap/system -s 64M -m /mnt\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -H /dev/dma_heap/system -s 256M -m /mnt -w\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -p 0x100000000 -s 256M\n", prog);
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"directory", required_argument, 0, 'd'},
		{"output", required_argument, 0, 'o'},
		{"heap", required_argument, 0, 'H'},
		{"mountpoint", required_argument, 0, 'm'},
		{"phys", required_argument, 0, 'p'},
		{"size", required_argument, 0, 's'},
		{"delta", required_argument, 0, 'D'},
		{"writable", no_argument, 0, 'w'},
		{"validate", no_argument, 0, 'V'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	char *src_dir = NULL;
	char *output_file = NULL;
	char *heap_path = NULL;
	char *mountpoint = NULL;
	unsigned long long phys_addr = 0;
	size_t max_size = 0;
	int dmabuf_fd = -1;
	void *mem = NULL;
	size_t total_size;
	size_t base_size;
	int opt;
	int ret = 1;
	size_t delta_size = DAXFS_DEFAULT_DELTA_SIZE;
	bool writable = false;
	bool validate = false;

	while ((opt = getopt_long(argc, argv, "d:o:H:m:p:s:D:wVh", long_options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			src_dir = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'H':
			heap_path = optarg;
			break;
		case 'm':
			mountpoint = optarg;
			break;
		case 'p':
			phys_addr = strtoull(optarg, NULL, 0);
			break;
		case 's':
			max_size = strtoull(optarg, NULL, 0);
			if (strchr(optarg, 'M') || strchr(optarg, 'm'))
				max_size *= 1024 * 1024;
			else if (strchr(optarg, 'G') || strchr(optarg, 'g'))
				max_size *= 1024 * 1024 * 1024;
			break;
		case 'D':
			delta_size = strtoull(optarg, NULL, 0);
			if (strchr(optarg, 'M') || strchr(optarg, 'm'))
				delta_size *= 1024 * 1024;
			else if (strchr(optarg, 'G') || strchr(optarg, 'g'))
				delta_size *= 1024 * 1024 * 1024;
			break;
		case 'w':
			writable = true;
			break;
		case 'V':
			validate = true;
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (!src_dir) {
		fprintf(stderr, "Error: -d/--directory is required\n");
		print_usage(argv[0]);
		return 1;
	}

	if (!output_file && !phys_addr && !heap_path) {
		fprintf(stderr, "Error: -o/--output, -H/--heap, or -p/--phys is required\n");
		print_usage(argv[0]);
		return 1;
	}

	if ((phys_addr || heap_path) && !max_size) {
		fprintf(stderr, "Error: -s/--size is required with -p/--phys or -H/--heap\n");
		print_usage(argv[0]);
		return 1;
	}

	if (heap_path && !mountpoint) {
		fprintf(stderr, "Error: -m/--mountpoint is required with -H/--heap\n");
		print_usage(argv[0]);
		return 1;
	}

	printf("Scanning %s...\n", src_dir);
	if (scan_directory(src_dir) < 0)
		return 1;

	printf("Found %u files\n", file_count);

	build_tree();
	calculate_offsets();

	base_size = calculate_base_size();
	if (writable)
		total_size = calculate_total_size(base_size, delta_size);
	else
		total_size = calculate_static_size(base_size);

	printf("Base image size: %zu bytes (%.2f MB)\n", base_size,
	       (double)base_size / (1024 * 1024));
	if (writable) {
		printf("Delta region size: %zu bytes (%.2f MB)\n", delta_size,
		       (double)delta_size / (1024 * 1024));
	}
	printf("Total image size: %zu bytes (%.2f MB)\n", total_size,
	       (double)total_size / (1024 * 1024));
	printf("Mode: %s\n", writable ? "read-write (with branching)" : "read-only (static)");

	if (heap_path) {
		/* Allocate from DMA heap and write */
		int heap_fd;
		struct dma_heap_allocation_data alloc = {
			.len = max_size,
			.fd_flags = O_RDWR | O_CLOEXEC,
		};

		if (total_size > max_size) {
			fprintf(stderr, "Error: image size %zu exceeds requested size %zu\n",
				total_size, max_size);
			return 1;
		}

		heap_fd = open(heap_path, O_RDWR);
		if (heap_fd < 0) {
			perror(heap_path);
			return 1;
		}

		if (ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &alloc) < 0) {
			perror("DMA_HEAP_IOCTL_ALLOC");
			close(heap_fd);
			return 1;
		}
		close(heap_fd);

		dmabuf_fd = alloc.fd;
		printf("Allocated %zu bytes from %s, dma-buf fd=%d\n",
		       max_size, heap_path, dmabuf_fd);

		mem = mmap(NULL, max_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, dmabuf_fd, 0);

		if (mem == MAP_FAILED) {
			perror("mmap dmabuf");
			close(dmabuf_fd);
			return 1;
		}

		printf("Writing daxfs image...\n");
		if (writable) {
			if (write_image(mem, max_size, src_dir, base_size, delta_size) < 0) {
				munmap(mem, max_size);
				close(dmabuf_fd);
				return 1;
			}
		} else {
			if (write_static_image(mem, max_size, src_dir, base_size) < 0) {
				munmap(mem, max_size);
				close(dmabuf_fd);
				return 1;
			}
		}

		munmap(mem, max_size);

		/* Mount using the dma-buf fd via the new mount API */
		printf("Mounting on %s (%s%s)...\n", mountpoint,
		       writable ? "read-write" : "read-only",
		       validate ? ", validating" : "");
		if (mount_daxfs_dmabuf(dmabuf_fd, mountpoint, writable, validate) < 0) {
			close(dmabuf_fd);
			return 1;
		}
		close(dmabuf_fd);

		printf("Done. Mounted daxfs on %s\n", mountpoint);
		ret = 0;
	} else if (phys_addr) {
		int fd;

		if (total_size > max_size) {
			fprintf(stderr, "Error: image size %zu exceeds max size %zu\n",
				total_size, max_size);
			return 1;
		}

		fd = open("/dev/mem", O_RDWR | O_SYNC);
		if (fd < 0) {
			perror("/dev/mem");
			return 1;
		}

		mem = mmap(NULL, max_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, phys_addr);
		close(fd);

		if (mem == MAP_FAILED) {
			perror("mmap");
			return 1;
		}

		printf("Writing to physical address 0x%llx...\n", phys_addr);
		if (writable) {
			if (write_image(mem, max_size, src_dir, base_size, delta_size) < 0) {
				munmap(mem, max_size);
				return 1;
			}
		} else {
			if (write_static_image(mem, max_size, src_dir, base_size) < 0) {
				munmap(mem, max_size);
				return 1;
			}
		}

		munmap(mem, max_size);
		printf("Done\n");
		ret = 0;
	} else {
		int fd;

		fd = open(output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			perror(output_file);
			return 1;
		}

		if (ftruncate(fd, total_size) < 0) {
			perror("ftruncate");
			close(fd);
			return 1;
		}

		mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED, fd, 0);
		close(fd);

		if (mem == MAP_FAILED) {
			perror("mmap");
			return 1;
		}

		printf("Writing to %s...\n", output_file);
		if (writable) {
			if (write_image(mem, total_size, src_dir, base_size, delta_size) < 0) {
				munmap(mem, total_size);
				return 1;
			}
		} else {
			if (write_static_image(mem, total_size, src_dir, base_size) < 0) {
				munmap(mem, total_size);
				return 1;
			}
		}

		munmap(mem, total_size);
		printf("Done\n");
		ret = 0;
	}

	return ret;
}
