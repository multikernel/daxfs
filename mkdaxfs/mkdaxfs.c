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
	char name[256];
	struct stat st;
	uint32_t ino;
	uint32_t parent_ino;
	uint32_t first_child;
	uint32_t next_sibling;
	uint64_t data_offset;
	uint32_t name_strtab_offset;
	struct file_entry *next;
};

static struct file_entry *files_head;
static struct file_entry *files_tail;
static uint32_t file_count;
static uint32_t next_ino = 1;
static size_t strtab_size;

static struct file_entry *find_by_path(const char *path)
{
	struct file_entry *e;

	for (e = files_head; e; e = e->next) {
		if (strcmp(e->path, path) == 0)
			return e;
	}
	return NULL;
}

static struct file_entry *find_by_ino(uint32_t ino)
{
	struct file_entry *e;

	for (e = files_head; e; e = e->next) {
		if (e->ino == ino)
			return e;
	}
	return NULL;
}

static struct file_entry *add_file(const char *path, struct stat *st)
{
	struct file_entry *e;
	char *slash;

	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	strncpy(e->path, path, sizeof(e->path) - 1);
	e->st = *st;
	e->ino = next_ino++;

	slash = strrchr(path, '/');
	if (slash && slash[1])
		strncpy(e->name, slash + 1, sizeof(e->name) - 1);
	else
		strncpy(e->name, path, sizeof(e->name) - 1);

	strtab_size += strlen(e->name) + 1;

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

			if (parent->first_child == 0) {
				parent->first_child = e->ino;
			} else {
				struct file_entry *sibling = find_by_ino(parent->first_child);
				while (sibling && sibling->next_sibling)
					sibling = find_by_ino(sibling->next_sibling);
				if (sibling)
					sibling->next_sibling = e->ino;
			}
		}
	}
}

static void calculate_offsets(void)
{
	struct file_entry *e;
	uint64_t inode_offset = DAXFS_BLOCK_SIZE;
	uint64_t strtab_offset = inode_offset + file_count * DAXFS_INODE_SIZE;
	uint64_t data_offset = ALIGN(strtab_offset + strtab_size, DAXFS_BLOCK_SIZE);
	uint32_t str_off = 0;

	for (e = files_head; e; e = e->next) {
		e->name_strtab_offset = str_off;
		str_off += strlen(e->name) + 1;

		if (S_ISREG(e->st.st_mode) || S_ISLNK(e->st.st_mode)) {
			e->data_offset = data_offset;
			data_offset += ALIGN(e->st.st_size, DAXFS_BLOCK_SIZE);
		}
	}
}

static int write_image(void *mem, size_t mem_size, const char *src_dir)
{
	struct file_entry *e;
	struct daxfs_super *super = mem;
	struct daxfs_inode *inodes;
	char *strtab;
	uint64_t inode_offset = DAXFS_BLOCK_SIZE;
	uint64_t strtab_offset = inode_offset + file_count * DAXFS_INODE_SIZE;
	uint64_t data_offset = ALIGN(strtab_offset + strtab_size, DAXFS_BLOCK_SIZE);

	memset(mem, 0, mem_size);

	super->magic = htole32(DAXFS_MAGIC);
	super->version = htole32(DAXFS_VERSION);
	super->flags = htole32(0);
	super->block_size = htole32(DAXFS_BLOCK_SIZE);
	super->inode_count = htole32(file_count);
	super->root_inode = htole32(DAXFS_ROOT_INO);
	super->inode_offset = htole64(inode_offset);
	super->strtab_offset = htole64(strtab_offset);
	super->strtab_size = htole64(strtab_size);
	super->data_offset = htole64(data_offset);

	inodes = mem + inode_offset;
	strtab = mem + strtab_offset;

	for (e = files_head; e; e = e->next) {
		struct daxfs_inode *di = &inodes[e->ino - 1];

		di->ino = htole32(e->ino);
		di->mode = htole32(e->st.st_mode);
		di->uid = htole32(e->st.st_uid);
		di->gid = htole32(e->st.st_gid);
		di->size = htole64(e->st.st_size);
		di->data_offset = htole64(e->data_offset);
		di->name_offset = htole32(e->name_strtab_offset);
		di->name_len = htole32(strlen(e->name));
		di->parent_ino = htole32(e->parent_ino);
		di->nlink = htole32(e->st.st_nlink);
		di->first_child = htole32(e->first_child);
		di->next_sibling = htole32(e->next_sibling);

		strcpy(strtab + e->name_strtab_offset, e->name);

		if (S_ISREG(e->st.st_mode)) {
			char fullpath[PATH_MAX * 2];
			int fd;
			ssize_t n;

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

			snprintf(fullpath, sizeof(fullpath), "%s/%s", src_dir, e->path);
			n = readlink(fullpath, mem + e->data_offset, e->st.st_size);
			if (n < 0)
				perror(fullpath);
		}
	}

	return 0;
}

static size_t calculate_total_size(void)
{
	struct file_entry *e;
	uint64_t inode_offset = DAXFS_BLOCK_SIZE;
	uint64_t strtab_offset = inode_offset + file_count * DAXFS_INODE_SIZE;
	uint64_t data_offset = ALIGN(strtab_offset + strtab_size, DAXFS_BLOCK_SIZE);
	size_t total = data_offset;

	for (e = files_head; e; e = e->next) {
		if (S_ISREG(e->st.st_mode) || S_ISLNK(e->st.st_mode))
			total += ALIGN(e->st.st_size, DAXFS_BLOCK_SIZE);
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
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH	0x00000004
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
static int mount_daxfs_dmabuf(int dmabuf_fd, const char *mountpoint)
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

	if (sys_fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
		perror("fsconfig(FSCONFIG_CMD_CREATE)");
		close(fs_fd);
		return -1;
	}

	mnt_fd = sys_fsmount(fs_fd, 0, 0);
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
	fprintf(stderr, "  -h, --help             Show this help\n");
	fprintf(stderr, "\nExamples:\n");
	fprintf(stderr, "  %s -d /path/to/rootfs -o image.daxfs\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -H /dev/dma_heap/multikernel -s 256M -m /mnt\n", prog);
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
	int opt;
	int ret = 1;

	while ((opt = getopt_long(argc, argv, "d:o:H:m:p:s:h", long_options, NULL)) != -1) {
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

	total_size = calculate_total_size();
	printf("Total image size: %zu bytes (%.2f MB)\n", total_size,
	       (double)total_size / (1024 * 1024));

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
		write_image(mem, max_size, src_dir);

		struct daxfs_super *super = mem;
		super->total_size = htole64(total_size);

		munmap(mem, max_size);

		/* Mount using the dma-buf fd via the new mount API */
		printf("Mounting on %s...\n", mountpoint);
		if (mount_daxfs_dmabuf(dmabuf_fd, mountpoint) < 0) {
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
		write_image(mem, max_size, src_dir);

		struct daxfs_super *super = mem;
		super->total_size = htole64(total_size);

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
		write_image(mem, total_size, src_dir);

		struct daxfs_super *super = mem;
		super->total_size = htole64(total_size);

		munmap(mem, total_size);
		printf("Done\n");
		ret = 0;
	}

	return ret;
}
