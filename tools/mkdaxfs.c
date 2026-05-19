// SPDX-License-Identifier: GPL-2.0
/*
 * mkdaxfs - Create daxfs filesystem images
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * Creates a daxfs image from a directory tree. Can write to a file,
 * directly to physical memory via /dev/mem, allocate from a DMA
 * heap, or use a Device-DAX device (e.g., CXL memory) and mount
 * immediately.
 *
 * Modes:
 *   Static:  mkdaxfs -d /path/to/rootfs -o image.daxfs
 *   Split:   mkdaxfs -d /path/to/rootfs -H /dev/dma_heap/mk -m /mnt -o /data/rootfs.img
 *   Empty:   mkdaxfs --empty -H /dev/dma_heap/mk -m /mnt -s 256M
 *   DAX:     mkdaxfs -d /path/to/rootfs -D /dev/dax0.0 -m /mnt
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

#define DAXFS_DEFAULT_OVERLAY_POOL	(64ULL * 1024 * 1024)	/* 64MB default pool */
#define DAXFS_DEFAULT_BUCKET_COUNT	65536			/* 64K buckets = 1MB */

/* Block size = native page size (stored in superblock, validated at mount) */
static uint32_t block_size;

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

/* From lazy_cma.h */
#define LAZY_CMA_IOC_MAGIC	'H'
#define LAZY_CMA_NAME_MAX	64

struct lazy_cma_allocation_data {
	uint64_t len;
	uint64_t phys_addr;
	int32_t node;
	uint32_t pad;
	char name[LAZY_CMA_NAME_MAX];
};

#define LAZY_CMA_IOCTL_ALLOC	_IOWR(LAZY_CMA_IOC_MAGIC, 0x0, \
				      struct lazy_cma_allocation_data)

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

struct file_entry {
	char path[PATH_MAX];
	char name[DAXFS_NAME_MAX + 1];
	struct stat st;
	uint32_t ino;
	uint32_t parent_ino;
	uint64_t data_offset;
	uint32_t child_count;
	bool is_hardlink;
	struct file_entry *next;
};

struct hardlink_entry {
	dev_t dev;
	ino_t src_ino;
	uint32_t daxfs_ino;
	uint64_t data_offset;
	struct hardlink_entry *next;
};

static struct file_entry *files_head;
static struct file_entry *files_tail;
static uint32_t file_count;
static uint32_t next_ino = 1;
static struct hardlink_entry *hardlink_map;
static uint64_t backing_file_size;

static struct file_entry *find_by_path(const char *path)
{
	struct file_entry *e;

	for (e = files_head; e; e = e->next) {
		if (strcmp(e->path, path) == 0)
			return e;
	}
	return NULL;
}

static struct hardlink_entry *find_hardlink(dev_t dev, ino_t ino)
{
	struct hardlink_entry *e;

	for (e = hardlink_map; e; e = e->next) {
		if (e->dev == dev && e->src_ino == ino)
			return e;
	}
	return NULL;
}

static void add_hardlink(dev_t dev, ino_t ino, uint32_t daxfs_ino)
{
	struct hardlink_entry *e = calloc(1, sizeof(*e));

	if (!e)
		return;
	e->dev = dev;
	e->src_ino = ino;
	e->daxfs_ino = daxfs_ino;
	e->next = hardlink_map;
	hardlink_map = e;
}

static struct file_entry *add_file(const char *path, struct stat *st)
{
	struct file_entry *e;
	struct hardlink_entry *hl;
	char *slash;
	size_t name_len;

	e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	strncpy(e->path, path, sizeof(e->path) - 1);
	e->st = *st;

	if (S_ISREG(st->st_mode) && st->st_nlink > 1) {
		hl = find_hardlink(st->st_dev, st->st_ino);
		if (hl) {
			e->ino = hl->daxfs_ino;
			e->is_hardlink = true;
		} else {
			e->ino = next_ino++;
			add_hardlink(st->st_dev, st->st_ino, e->ino);
		}
	} else {
		e->ino = next_ino++;
	}

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

/*
 * Unified offset calculation for both static and split modes.
 * In split mode, regular file data goes to backing file offsets.
 */
static void calculate_offsets(bool split, bool export)
{
	struct file_entry *e;
	struct hardlink_entry *hl;
	uint64_t inode_offset = 0;  /* relative to base start */
	uint64_t base_data_offset = ALIGN(inode_offset + file_count * DAXFS_INODE_SIZE,
					  block_size);
	uint64_t back_offset = 0;

	for (e = files_head; e; e = e->next) {
		if (S_ISREG(e->st.st_mode)) {
			if (e->is_hardlink) {
				hl = find_hardlink(e->st.st_dev, e->st.st_ino);
				if (hl)
					e->data_offset = hl->data_offset;
			} else if (split && export) {
				/* Export mode: each file read from offset 0 */
				e->data_offset = 0;
			} else if (split) {
				e->data_offset = back_offset;
				back_offset += ALIGN(e->st.st_size, block_size);
				hl = find_hardlink(e->st.st_dev, e->st.st_ino);
				if (hl)
					hl->data_offset = e->data_offset;
			} else {
				e->data_offset = base_data_offset;
				base_data_offset += ALIGN(e->st.st_size, block_size);
				hl = find_hardlink(e->st.st_dev, e->st.st_ino);
				if (hl)
					hl->data_offset = e->data_offset;
			}
		} else if (S_ISLNK(e->st.st_mode)) {
			e->data_offset = base_data_offset;
			base_data_offset += ALIGN(e->st.st_size + 1, block_size);
		} else if (S_ISDIR(e->st.st_mode) && e->child_count > 0) {
			e->data_offset = base_data_offset;
			base_data_offset += ALIGN(e->child_count * DAXFS_DIRENT_SIZE,
						  block_size);
		}
	}

	if (split)
		backing_file_size = back_offset;
}

/*
 * Unified base size calculation.
 * In split mode, excludes regular file data size.
 */
static size_t calculate_base_size(bool split)
{
	struct file_entry *e;
	uint64_t inode_offset = 0;
	uint64_t data_offset = ALIGN(inode_offset + file_count * DAXFS_INODE_SIZE,
				     block_size);
	size_t total = data_offset;

	for (e = files_head; e; e = e->next) {
		if (S_ISREG(e->st.st_mode)) {
			if (!split && !e->is_hardlink)
				total += ALIGN(e->st.st_size, block_size);
		} else if (S_ISLNK(e->st.st_mode)) {
			total += ALIGN(e->st.st_size + 1, block_size);
		} else if (S_ISDIR(e->st.st_mode) && e->child_count > 0) {
			total += ALIGN(e->child_count * DAXFS_DIRENT_SIZE, block_size);
		}
	}

	return total;
}

static uint32_t prev_power_of_2(uint32_t v)
{
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	return v - (v >> 1);
}

static uint32_t calc_ilog2(uint32_t v)
{
	uint32_t r = 0;

	while (v >>= 1)
		r++;
	return r;
}

static size_t calculate_pcache_region_size(uint32_t slot_count)
{
	uint64_t meta_size = ALIGN((uint64_t)slot_count * sizeof(struct daxfs_pcache_slot),
				   block_size);
	uint64_t data_size = (uint64_t)slot_count * block_size;

	return block_size + meta_size + data_size;
}

static size_t calculate_overlay_region_size(uint32_t bucket_count, size_t pool_size)
{
	uint64_t bucket_array_size = ALIGN((uint64_t)bucket_count *
					   sizeof(struct daxfs_overlay_bucket),
					   block_size);
	return block_size + bucket_array_size + pool_size;
}

static int write_overlay_region(void *overlay_mem, uint32_t bucket_count,
				size_t pool_size, uint64_t next_ino_val)
{
	struct daxfs_overlay_header *hdr = overlay_mem;
	uint64_t bucket_array_size = ALIGN((uint64_t)bucket_count *
					   sizeof(struct daxfs_overlay_bucket),
					   block_size);
	size_t total = block_size + bucket_array_size + pool_size;

	memset(overlay_mem, 0, total);

	hdr->magic = htole32(DAXFS_OVERLAY_MAGIC);
	hdr->version = htole32(DAXFS_OVERLAY_VERSION);
	hdr->bucket_offset = htole64(block_size);
	hdr->pool_offset = htole64(block_size + bucket_array_size);
	hdr->pool_size = htole64(pool_size);
	hdr->pool_alloc = htole64(0);
	hdr->next_ino = htole64(next_ino_val);
	hdr->free_inode = htole64(DAXFS_OVL_FREE_END);
	hdr->free_data = htole64(DAXFS_OVL_FREE_END);
	hdr->free_dirent = htole64(DAXFS_OVL_FREE_END);

	return 0;
}

/*
 * Unified base image writer for both static and split modes.
 * No sub-header — inode table starts at offset 0 within the base region.
 * In split mode, regular file data is not written inline.
 */
static int write_base_image(void *mem, size_t mem_size, const char *src_dir,
			    bool split)
{
	struct file_entry *e, *child;
	struct daxfs_base_inode *inodes;
	uint64_t inode_offset = 0;

	memset(mem, 0, mem_size);

	inodes = mem + inode_offset;

	for (e = files_head; e; e = e->next) {
		struct daxfs_base_inode *di = &inodes[e->ino - 1];

		di->ino = htole32(e->ino);
		di->mode = htole32(e->st.st_mode);
		di->uid = htole32(e->st.st_uid);
		di->gid = htole32(e->st.st_gid);
		di->nlink = htole32(e->st.st_nlink);

		if (S_ISREG(e->st.st_mode)) {
			di->size = htole64(e->st.st_size);
			di->data_offset = htole64(e->data_offset);

			if (!split && !e->is_hardlink) {
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
			}
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
				((char *)(mem + e->data_offset))[n] = '\0';
		} else if (S_ISDIR(e->st.st_mode)) {
			struct daxfs_dirent *dirents;
			uint32_t dirent_idx = 0;

			di->size = htole64((uint64_t)e->child_count * DAXFS_DIRENT_SIZE);
			di->data_offset = htole64(e->data_offset);

			if (e->child_count > 0) {
				dirents = mem + e->data_offset;

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

	return 0;
}

static int write_backing_file(const char *backing_path, const char *src_dir)
{
	struct file_entry *e;
	int fd;
	void *mem;

	if (backing_file_size == 0) {
		printf("No regular file data to write to backing file\n");
		return 0;
	}

	fd = open(backing_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror(backing_path);
		return -1;
	}

	if (ftruncate(fd, backing_file_size) < 0) {
		perror("ftruncate backing file");
		close(fd);
		return -1;
	}

	mem = mmap(NULL, backing_file_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, fd, 0);
	close(fd);

	if (mem == MAP_FAILED) {
		perror("mmap backing file");
		return -1;
	}

	memset(mem, 0, backing_file_size);

	for (e = files_head; e; e = e->next) {
		if (S_ISREG(e->st.st_mode) && !e->is_hardlink && e->st.st_size > 0) {
			char fullpath[PATH_MAX * 2];
			int src_fd;
			ssize_t n;

			snprintf(fullpath, sizeof(fullpath), "%s/%s", src_dir, e->path);
			src_fd = open(fullpath, O_RDONLY);
			if (src_fd < 0) {
				perror(fullpath);
				continue;
			}
			n = read(src_fd, (char *)mem + e->data_offset, e->st.st_size);
			if (n < 0)
				perror(fullpath);
			close(src_fd);
		}
	}

	munmap(mem, backing_file_size);
	return 0;
}

/*
 * Write pcache region — header + zero-initialized slots + data area.
 * The runtime fill kthread handles population on demand.
 */
static int write_pcache_region(void *pcache_mem, uint32_t slot_count)
{
	struct daxfs_pcache_header *hdr = pcache_mem;
	uint64_t meta_size = ALIGN((uint64_t)slot_count * sizeof(struct daxfs_pcache_slot),
				   block_size);
	uint64_t slot_meta_offset = block_size;
	uint64_t slot_data_offset = block_size + meta_size;
	size_t total = slot_data_offset + (uint64_t)slot_count * block_size;

	memset(pcache_mem, 0, total);

	hdr->magic = htole32(DAXFS_PCACHE_MAGIC);
	hdr->version = htole32(DAXFS_PCACHE_VERSION);
	hdr->slot_meta_offset = htole64(slot_meta_offset);
	hdr->slot_data_offset = htole64(slot_data_offset);
	hdr->evict_hand = htole32(0);
	hdr->pending_count = htole32(0);

	return 0;
}

/*
 * Fill superblock fields common to all modes.
 */
static void fill_super_common(struct daxfs_super *super, uint64_t total_size)
{
	super->magic = htole32(DAXFS_SUPER_MAGIC);
	super->version = htole32(DAXFS_VERSION);
	super->block_size = htole32(block_size);  /* Native page size */
	super->total_size = htole64(total_size);
}

/*
 * Fill superblock base image fields.
 */
static void fill_super_base(struct daxfs_super *super, uint64_t base_offset,
			    uint64_t base_size)
{
	uint64_t inode_offset = 0;
	uint64_t data_offset = ALIGN(inode_offset + file_count * DAXFS_INODE_SIZE,
				     block_size);

	super->base_offset = htole64(base_offset);
	super->base_size = htole64(base_size);
	super->inode_offset = htole64(inode_offset);
	super->inode_count = htole32(file_count);
	super->root_inode = htole32(DAXFS_ROOT_INO);
	super->data_offset = htole64(data_offset);
}

/*
 * Write split-mode daxfs image to DAX memory.
 * Layout: [Superblock] [Base Image (no sub-header)] [Overlay] [PCache]
 */
static int write_split_image(void *mem, size_t mem_size, const char *src_dir,
			     size_t base_size, uint32_t overlay_buckets,
			     size_t overlay_pool_size, uint32_t pcache_slots)
{
	struct daxfs_super *super = mem;
	uint64_t base_offset = block_size;
	uint64_t overlay_offset = ALIGN(base_offset + base_size, block_size);
	size_t overlay_region_size = calculate_overlay_region_size(overlay_buckets,
								  overlay_pool_size);
	uint64_t pcache_offset = ALIGN(overlay_offset + overlay_region_size,
				       block_size);
	size_t pcache_region_size = calculate_pcache_region_size(pcache_slots);
	uint64_t total = pcache_offset + pcache_region_size;

	if (total > mem_size) {
		fprintf(stderr, "Error: split image too large for allocated space "
			"(%llu > %zu)\n", (unsigned long long)total, mem_size);
		return -1;
	}

	memset(mem, 0, mem_size);

	/* Write superblock */
	fill_super_common(super, total);
	fill_super_base(super, base_offset, base_size);

	super->overlay_offset = htole64(overlay_offset);
	super->overlay_size = htole64(overlay_region_size);
	super->overlay_bucket_count = htole32(overlay_buckets);
	super->overlay_bucket_shift = htole32(calc_ilog2(overlay_buckets));

	super->pcache_offset = htole64(pcache_offset);
	super->pcache_size = htole64(pcache_region_size);
	super->pcache_slot_count = htole32(pcache_slots);
	super->pcache_hash_shift = htole32(calc_ilog2(pcache_slots));

	/* Write base image (no sub-header) */
	write_base_image(mem + base_offset, base_size, src_dir, true);

	/* Write overlay region */
	write_overlay_region(mem + overlay_offset, overlay_buckets,
			     overlay_pool_size, file_count + 1);

	/* Write pcache region */
	write_pcache_region(mem + pcache_offset, pcache_slots);

	printf("Image layout (split mode):\n");
	printf("  Superblock:    0x%x - 0x%x\n", 0, block_size);
	printf("  Base image:    0x%lx - 0x%lx (%zu bytes, metadata only)\n",
	       (unsigned long)base_offset,
	       (unsigned long)(base_offset + base_size),
	       base_size);
	printf("  Overlay:       0x%lx - 0x%lx (%zu bytes, %u buckets, %zu pool)\n",
	       (unsigned long)overlay_offset,
	       (unsigned long)(overlay_offset + overlay_region_size),
	       overlay_region_size, overlay_buckets, overlay_pool_size);
	printf("  Page cache:    0x%lx - 0x%lx (%zu bytes, %u slots)\n",
	       (unsigned long)pcache_offset,
	       (unsigned long)(pcache_offset + pcache_region_size),
	       pcache_region_size, pcache_slots);

	return 0;
}

static size_t calculate_split_dax_size(size_t base_size, uint32_t overlay_buckets,
				       size_t overlay_pool_size,
				       uint32_t pcache_slots)
{
	uint64_t base_offset = block_size;
	uint64_t overlay_offset = ALIGN(base_offset + base_size, block_size);
	size_t overlay_region_size = calculate_overlay_region_size(overlay_buckets,
								  overlay_pool_size);
	uint64_t pcache_offset = ALIGN(overlay_offset + overlay_region_size,
				       block_size);
	size_t pcache_region_size = calculate_pcache_region_size(pcache_slots);

	return pcache_offset + pcache_region_size;
}

/*
 * Write empty daxfs image (no base image, overlay + optional pcache).
 * Layout: [Superblock] [Overlay] [PCache (optional)]
 */
static int write_empty_image(void *mem, size_t mem_size,
			     uint32_t overlay_buckets, size_t overlay_pool_size,
			     uint32_t pcache_slots)
{
	struct daxfs_super *super = mem;
	uint64_t overlay_offset = block_size;
	size_t overlay_region_size = calculate_overlay_region_size(overlay_buckets,
								  overlay_pool_size);
	uint64_t pcache_offset = 0;
	size_t pcache_region_size = 0;
	uint64_t total;

	if (pcache_slots) {
		pcache_offset = ALIGN(overlay_offset + overlay_region_size,
				      block_size);
		pcache_region_size = calculate_pcache_region_size(pcache_slots);
		total = pcache_offset + pcache_region_size;
	} else {
		total = overlay_offset + overlay_region_size;
	}

	if (total > mem_size) {
		fprintf(stderr, "Error: empty image too large for allocated space "
			"(%llu > %zu)\n", (unsigned long long)total, mem_size);
		return -1;
	}

	memset(mem, 0, mem_size);

	/* Write superblock */
	fill_super_common(super, total);

	/* No base image */
	super->base_offset = htole64(0);
	super->base_size = htole64(0);

	super->overlay_offset = htole64(overlay_offset);
	super->overlay_size = htole64(overlay_region_size);
	super->overlay_bucket_count = htole32(overlay_buckets);
	super->overlay_bucket_shift = htole32(calc_ilog2(overlay_buckets));

	if (pcache_slots) {
		super->pcache_offset = htole64(pcache_offset);
		super->pcache_size = htole64(pcache_region_size);
		super->pcache_slot_count = htole32(pcache_slots);
		super->pcache_hash_shift = htole32(calc_ilog2(pcache_slots));
	}

	/* Write overlay (next_ino starts at 2: root=1 is reserved) */
	write_overlay_region(mem + overlay_offset, overlay_buckets,
			     overlay_pool_size, DAXFS_ROOT_INO + 1);

	/*
	 * Create root directory inode in the overlay so daxfs_iget(ROOT_INO)
	 * can find it during mount (there's no base image in empty mode).
	 */
	{
		struct daxfs_overlay_header *ohdr = mem + overlay_offset;
		uint64_t bucket_array_size = ALIGN(
			(uint64_t)overlay_buckets *
			sizeof(struct daxfs_overlay_bucket),
			block_size);
		void *pool_base = mem + overlay_offset +
			block_size + bucket_array_size;
		struct daxfs_ovl_inode_entry *ie;
		struct daxfs_overlay_bucket *buckets;
		uint64_t key, pool_off;
		uint32_t idx;

		/* Bump-allocate inode entry from pool */
		pool_off = 0;
		ie = pool_base + pool_off;
		ie->type = htole32(DAXFS_OVL_INODE);
		ie->mode = htole32(S_IFDIR | 0755);
		ie->uid = htole32(0);
		ie->gid = htole32(0);
		ie->size = htole64(0);
		ie->nlink = htole32(2);
		ie->flags = 0;
		ohdr->pool_alloc = htole64(
			ALIGN(sizeof(struct daxfs_ovl_inode_entry), 8));

		/* Insert into hash table */
		key = DAXFS_OVL_KEY_INODE(DAXFS_ROOT_INO);
		buckets = mem + overlay_offset + block_size;
		idx = (uint32_t)(key & (overlay_buckets - 1));
		buckets[idx].state_key = htole64(DAXFS_OVL_MAKE(
			DAXFS_OVL_USED, key));
		buckets[idx].value = htole64(pool_off);
	}

	if (pcache_slots)
		write_pcache_region(mem + pcache_offset, pcache_slots);

	printf("Image layout (empty mode):\n");
	printf("  Superblock:    0x%x - 0x%x\n", 0, block_size);
	printf("  Overlay:       0x%lx - 0x%lx (%zu bytes, %u buckets, %zu pool)\n",
	       (unsigned long)overlay_offset,
	       (unsigned long)(overlay_offset + overlay_region_size),
	       overlay_region_size, overlay_buckets, overlay_pool_size);
	if (pcache_slots)
		printf("  Page cache:    0x%lx - 0x%lx (%zu bytes, %u slots)\n",
		       (unsigned long)pcache_offset,
		       (unsigned long)(pcache_offset + pcache_region_size),
		       pcache_region_size, pcache_slots);

	return 0;
}

static size_t calculate_empty_size(uint32_t overlay_buckets,
				   size_t overlay_pool_size,
				   uint32_t pcache_slots)
{
	uint64_t overlay_offset = block_size;
	size_t overlay_region_size = calculate_overlay_region_size(overlay_buckets,
								  overlay_pool_size);

	if (pcache_slots) {
		uint64_t pcache_offset = ALIGN(overlay_offset + overlay_region_size,
					       block_size);
		return pcache_offset + calculate_pcache_region_size(pcache_slots);
	}

	return overlay_offset + overlay_region_size;
}

/* New mount API constants (may not be in older headers) */
#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING	1
#endif
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

static int mount_daxfs_dmabuf(int dmabuf_fd, const char *mountpoint,
			      bool writable, bool validate,
			      const char *backing_path,
			      const char *export_path)
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

	if (backing_path) {
		if (sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, "backing",
				 backing_path, 0) < 0) {
			perror("fsconfig(FSCONFIG_SET_STRING, backing)");
			close(fs_fd);
			return -1;
		}
	}

	if (export_path) {
		if (sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, "export",
				 export_path, 0) < 0) {
			perror("fsconfig(FSCONFIG_SET_STRING, export)");
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

static int mount_daxfs_phys(unsigned long long phys_addr, size_t size,
			    const char *mountpoint, bool writable, bool validate,
			    const char *backing_path, const char *export_path)
{
	int fs_fd, mnt_fd;
	char buf[64];

	fs_fd = sys_fsopen("daxfs", 0);
	if (fs_fd < 0) {
		perror("fsopen(daxfs)");
		return -1;
	}

	snprintf(buf, sizeof(buf), "0x%llx", phys_addr);
	if (sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, "phys", buf, 0) < 0) {
		perror("fsconfig(phys)");
		close(fs_fd);
		return -1;
	}

	snprintf(buf, sizeof(buf), "%zu", size);
	if (sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, "size", buf, 0) < 0) {
		perror("fsconfig(size)");
		close(fs_fd);
		return -1;
	}

	if (backing_path) {
		if (sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, "backing",
				 backing_path, 0) < 0) {
			perror("fsconfig(backing)");
			close(fs_fd);
			return -1;
		}
	}

	if (export_path) {
		if (sys_fsconfig(fs_fd, FSCONFIG_SET_STRING, "export",
				 export_path, 0) < 0) {
			perror("fsconfig(export)");
			close(fs_fd);
			return -1;
		}
	}

	if (validate) {
		if (sys_fsconfig(fs_fd, FSCONFIG_SET_FLAG, "validate", NULL, 0) < 0) {
			perror("fsconfig(validate)");
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
 * Read physical address and size of a Device-DAX device from sysfs.
 * For /dev/daxX.Y, reads /sys/bus/dax/devices/daxX.Y/resource and size.
 * Returns 0 on success, -1 if not a DAX device (no sysfs entry).
 */
static int dax_device_info(const char *dev_path, unsigned long long *phys_out,
			   size_t *size_out)
{
	const char *devname;
	char sysfs_path[PATH_MAX];
	char buf[64];
	FILE *f;

	/* Extract device name: "/dev/dax0.0" -> "dax0.0" */
	devname = strrchr(dev_path, '/');
	devname = devname ? devname + 1 : dev_path;

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/dax/devices/%s/resource", devname);
	f = fopen(sysfs_path, "r");
	if (!f)
		return -1;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	*phys_out = strtoull(buf, NULL, 0);

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/dax/devices/%s/size", devname);
	f = fopen(sysfs_path, "r");
	if (!f)
		return -1;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	*size_out = strtoull(buf, NULL, 0);

	return 0;
}

/*
 * Write static daxfs image (read-only, no overlay)
 * Layout: [Superblock (4KB)] [Base Image (no sub-header)]
 */
static int write_static_image(void *mem, size_t mem_size, const char *src_dir,
			      size_t base_size)
{
	struct daxfs_super *super = mem;
	uint64_t base_offset = block_size;

	if (base_offset + base_size > mem_size) {
		fprintf(stderr, "Error: image too large for allocated space\n");
		return -1;
	}

	memset(mem, 0, mem_size);

	/* Write superblock */
	fill_super_common(super, base_offset + base_size);
	fill_super_base(super, base_offset, base_size);

	/* overlay_offset, overlay_size, pcache fields all zero */

	/* Write embedded base image (no sub-header) */
	write_base_image(mem + base_offset, base_size, src_dir, false);

	printf("Image layout (static):\n");
	printf("  Superblock:    0x%x - 0x%x\n", 0, block_size);
	printf("  Base image:    0x%lx - 0x%lx (%zu bytes)\n",
	       (unsigned long)base_offset,
	       (unsigned long)(base_offset + base_size),
	       base_size);

	return 0;
}

static size_t calculate_static_size(size_t base_size)
{
	return block_size + base_size;
}

static void print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -d, --directory DIR    Source directory\n");
	fprintf(stderr, "  -o, --output FILE      Output file (backing file in split mode)\n");
	fprintf(stderr, "  -H, --heap PATH        Allocate from DMA heap (e.g., /dev/dma_heap/multikernel)\n");
	fprintf(stderr, "  -m, --mountpoint DIR   Mount after creating (required with -H)\n");
	fprintf(stderr, "  -D, --dax PATH         Use device for DAX storage (e.g., /dev/dax0.0, /dev/lazy_cma)\n");
	fprintf(stderr, "  -p, --phys ADDR        Use pre-existing physical address (skip auto-detection/allocation)\n");
	fprintf(stderr, "  -s, --size SIZE        Override allocation size (default: auto-calculated)\n");
	fprintf(stderr, "  -V, --validate         Validate image on mount\n");
	fprintf(stderr, "  -C, --pcache-slots N   Page cache slot count (power of 2)\n");
	fprintf(stderr, "  -O, --overlay SIZE     Overlay pool size (enables writes, default 64M in split/empty)\n");
	fprintf(stderr, "  -B, --buckets N        Overlay bucket count (power of 2, default 65536)\n");
	fprintf(stderr, "  -E, --empty            Empty mode (no base image, overlay + pcache only)\n");
	fprintf(stderr, "  -X, --export           Export mode (metadata+overlay+pcache in DAX, files from source dir)\n");
	fprintf(stderr, "  -h, --help             Show this help\n");
	fprintf(stderr, "\nBy default, creates a static read-only image.\n");
	fprintf(stderr, "Use -O/--overlay to add a writable overlay region.\n");
	fprintf(stderr, "\nSplit mode: when both -H/-D AND -o are given, metadata+overlay+cache go to DAX\n");
	fprintf(stderr, "and file data goes to the backing file (-o). Overlay is auto-enabled.\n");
	fprintf(stderr, "\nEmpty mode: creates a writable filesystem with no base image.\n");
	fprintf(stderr, "\nExamples:\n");
	fprintf(stderr, "  %s -d /path/to/rootfs -o image.daxfs\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -H /dev/dma_heap/system -m /mnt\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -H /dev/dma_heap/mk -m /mnt -o /data/rootfs.img\n", prog);
	fprintf(stderr, "  %s --empty -H /dev/dma_heap/mk -m /mnt -s 256M\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -D /dev/dax0.0 -m /mnt\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -D /dev/lazy_cma -m /mnt -s 256M\n", prog);
	fprintf(stderr, "  %s -d /path/to/rootfs -D /dev/mem -p 0x100000000 -s 256M\n", prog);
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"directory", required_argument, 0, 'd'},
		{"output", required_argument, 0, 'o'},
		{"heap", required_argument, 0, 'H'},
		{"dax", required_argument, 0, 'D'},
		{"mountpoint", required_argument, 0, 'm'},
		{"phys", required_argument, 0, 'p'},
		{"size", required_argument, 0, 's'},
		{"validate", no_argument, 0, 'V'},
		{"pcache-slots", required_argument, 0, 'C'},
		{"overlay", required_argument, 0, 'O'},
		{"buckets", required_argument, 0, 'B'},
		{"empty", no_argument, 0, 'E'},
		{"export", no_argument, 0, 'X'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	char *src_dir = NULL;
	char *output_file = NULL;
	char *heap_path = NULL;
	char *dax_path = NULL;
	char *mountpoint = NULL;
	unsigned long long phys_addr = 0;
	size_t max_size = 0;
	int dmabuf_fd = -1;
	void *mem = NULL;
	size_t total_size;
	size_t base_size = 0;
	int opt;
	int ret = 1;
	bool validate = false;
	bool empty_mode = false;
	bool export_mode = false;
	bool split_mode = false;
	bool has_overlay = false;
	uint32_t pcache_slots = 0;
	size_t overlay_pool_size = 0;
	uint32_t overlay_buckets = 0;

	/* Set block_size to native page size */
	{
		long ps = sysconf(_SC_PAGESIZE);

		if (ps <= 0) {
			fprintf(stderr, "Warning: sysconf(_SC_PAGESIZE) failed, "
				"defaulting to %u\n", DAXFS_MIN_BLOCK_SIZE);
			ps = DAXFS_MIN_BLOCK_SIZE;
		}
		block_size = (uint32_t)ps;
		if (block_size < DAXFS_MIN_BLOCK_SIZE)
			block_size = DAXFS_MIN_BLOCK_SIZE;
	}

	while ((opt = getopt_long(argc, argv, "d:o:H:D:m:p:s:C:O:B:EXVh", long_options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			src_dir = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'D':
			dax_path = optarg;
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
		case 'V':
			validate = true;
			break;
		case 'C':
			pcache_slots = strtoul(optarg, NULL, 0);
			break;
		case 'O':
			overlay_pool_size = strtoull(optarg, NULL, 0);
			if (strchr(optarg, 'M') || strchr(optarg, 'm'))
				overlay_pool_size *= 1024 * 1024;
			else if (strchr(optarg, 'G') || strchr(optarg, 'g'))
				overlay_pool_size *= 1024 * 1024 * 1024;
			break;
		case 'B':
			overlay_buckets = strtoul(optarg, NULL, 0);
			break;
		case 'E':
			empty_mode = true;
			break;
		case 'X':
			export_mode = true;
			break;
		case 'h':
		default:
			print_usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	/* Detect split mode: DAX target + output backing file + source dir */
	if ((heap_path || dax_path) && output_file && src_dir)
		split_mode = true;

	/* Validate export mode */
	if (export_mode) {
		if (!src_dir) {
			fprintf(stderr, "Error: --export requires -d/--directory\n");
			print_usage(argv[0]);
			return 1;
		}
		if (output_file) {
			fprintf(stderr, "Error: --export does not use -o/--output\n");
			print_usage(argv[0]);
			return 1;
		}
		if (!heap_path && !dax_path) {
			fprintf(stderr, "Error: --export requires -H/--heap or -D/--dax\n");
			print_usage(argv[0]);
			return 1;
		}
		split_mode = false;
	}

	/* Validate options */
	if (empty_mode) {
		if (src_dir) {
			fprintf(stderr, "Error: --empty and -d are mutually exclusive\n");
			print_usage(argv[0]);
			return 1;
		}
		if (!heap_path && !dax_path && !output_file) {
			fprintf(stderr, "Error: output target required (-o, -H, or -D)\n");
			print_usage(argv[0]);
			return 1;
		}
		/* Default overlay settings for empty mode */
		if (!overlay_pool_size)
			overlay_pool_size = DAXFS_DEFAULT_OVERLAY_POOL;
		if (!overlay_buckets)
			overlay_buckets = DAXFS_DEFAULT_BUCKET_COUNT;
	} else if (!src_dir) {
		fprintf(stderr, "Error: -d/--directory is required (or use --empty)\n");
		print_usage(argv[0]);
		return 1;
	}

	if (!output_file && !heap_path && !dax_path) {
		fprintf(stderr, "Error: -o/--output, -H/--heap, or -D/--dax is required\n");
		print_usage(argv[0]);
		return 1;
	}

	if (heap_path && !mountpoint) {
		fprintf(stderr, "Error: -m/--mountpoint is required with -H/--heap\n");
		print_usage(argv[0]);
		return 1;
	}

	/* Default overlay for split/export mode */
	if (split_mode || export_mode) {
		if (!overlay_pool_size)
			overlay_pool_size = DAXFS_DEFAULT_OVERLAY_POOL;
		if (!overlay_buckets)
			overlay_buckets = DAXFS_DEFAULT_BUCKET_COUNT;
	}

	/* Default bucket count when overlay specified */
	if (overlay_pool_size && !overlay_buckets)
		overlay_buckets = DAXFS_DEFAULT_BUCKET_COUNT;

	has_overlay = (overlay_pool_size > 0);

	/* Validate overlay bucket count is power of 2 */
	if (overlay_buckets && (overlay_buckets & (overlay_buckets - 1))) {
		fprintf(stderr, "Error: --buckets must be a power of 2\n");
		return 1;
	}

	if (empty_mode) {
		/* Empty mode: overlay + optional pcache, no base image */
		total_size = calculate_empty_size(overlay_buckets, overlay_pool_size,
						  pcache_slots);
		printf("Empty mode: overlay + pcache\n");
		printf("Overlay: %u buckets, %zu byte pool (%.2f MB)\n",
		       overlay_buckets, overlay_pool_size,
		       (double)overlay_pool_size / (1024 * 1024));
		if (pcache_slots)
			printf("Page cache: %u slots (%zu bytes)\n",
			       pcache_slots,
			       calculate_pcache_region_size(pcache_slots));
		printf("Total size: %zu bytes (%.2f MB)\n", total_size,
		       (double)total_size / (1024 * 1024));
	} else {
		printf("Scanning %s...\n", src_dir);
		if (scan_directory(src_dir) < 0)
			return 1;

		printf("Found %u files\n", file_count);

		build_tree();

		if (split_mode || export_mode) {
			calculate_offsets(true, export_mode);
			base_size = calculate_base_size(true);

			/* Auto-calculate pcache slots if not specified */
			if (pcache_slots == 0) {
				if (export_mode) {
					/* No backing blob; estimate from file count */
					pcache_slots = file_count > 16 ?
						prev_power_of_2(file_count) : 16;
				} else {
					uint32_t backing_pages = (backing_file_size +
								  block_size - 1) /
								 block_size;
					pcache_slots = backing_pages > 0 ?
						prev_power_of_2(backing_pages) : 16;
				}
				if (pcache_slots < 16)
					pcache_slots = 16;
			}

			/* Validate pcache_slots is power of 2 */
			if (pcache_slots & (pcache_slots - 1)) {
				fprintf(stderr, "Error: --pcache-slots must be a power of 2\n");
				return 1;
			}

			total_size = calculate_split_dax_size(base_size, overlay_buckets,
							      overlay_pool_size,
							      pcache_slots);

			if (export_mode) {
				printf("Export mode: metadata+overlay+cache -> DAX, files from %s\n",
				       src_dir);
			} else {
				printf("Split mode: metadata+overlay+cache -> DAX, file data -> %s\n",
				       output_file);
				printf("Backing file size: %llu bytes (%.2f MB)\n",
				       (unsigned long long)backing_file_size,
				       (double)backing_file_size / (1024 * 1024));
			}
			printf("Base image size: %zu bytes (%.2f MB, metadata only)\n",
			       base_size, (double)base_size / (1024 * 1024));
			printf("Overlay: %u buckets, %zu byte pool (%.2f MB)\n",
			       overlay_buckets, overlay_pool_size,
			       (double)overlay_pool_size / (1024 * 1024));
			printf("Page cache: %u slots (%zu bytes)\n",
			       pcache_slots,
			       calculate_pcache_region_size(pcache_slots));
			printf("Total DAX size: %zu bytes (%.2f MB)\n", total_size,
			       (double)total_size / (1024 * 1024));
		} else {
			calculate_offsets(false, false);
			base_size = calculate_base_size(false);
			total_size = calculate_static_size(base_size);

			printf("Base image size: %zu bytes (%.2f MB)\n", base_size,
			       (double)base_size / (1024 * 1024));
			printf("Total image size: %zu bytes (%.2f MB)\n", total_size,
			       (double)total_size / (1024 * 1024));
			printf("Mode: static (read-only)\n");
		}
	}

	/* Use calculated size if -s not specified, otherwise validate */
	if (!max_size) {
		max_size = total_size;
	} else if (total_size > max_size) {
		fprintf(stderr, "Error: image size %zu exceeds requested size %zu\n",
			total_size, max_size);
		return 1;
	}

	if (heap_path) {
		/* Allocate from DMA heap and write */
		int heap_fd;
		struct dma_heap_allocation_data alloc = {
			.len = max_size,
			.fd_flags = O_RDWR | O_CLOEXEC,
		};

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
		if (empty_mode) {
			if (write_empty_image(mem, max_size, overlay_buckets,
					      overlay_pool_size, pcache_slots) < 0) {
				munmap(mem, max_size);
				close(dmabuf_fd);
				return 1;
			}
		} else if (export_mode) {
			if (write_split_image(mem, max_size, src_dir, base_size,
					      overlay_buckets, overlay_pool_size,
					      pcache_slots) < 0) {
				munmap(mem, max_size);
				close(dmabuf_fd);
				return 1;
			}
		} else if (split_mode) {
			printf("Writing backing file to %s...\n", output_file);
			if (write_backing_file(output_file, src_dir) < 0) {
				munmap(mem, max_size);
				close(dmabuf_fd);
				return 1;
			}

			if (write_split_image(mem, max_size, src_dir, base_size,
					      overlay_buckets, overlay_pool_size,
					      pcache_slots) < 0) {
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
		printf("Mounting on %s (%s%s%s)...\n", mountpoint,
		       has_overlay ? "writable" : "read-only",
		       validate ? ", validating" : "",
		       (split_mode || export_mode) ? ", backing-store" : "");
		if (mount_daxfs_dmabuf(dmabuf_fd, mountpoint, has_overlay, validate,
				       split_mode ? output_file : NULL,
				       export_mode ? src_dir : NULL) < 0) {
			close(dmabuf_fd);
			return 1;
		}
		close(dmabuf_fd);

		printf("Done. Mounted daxfs on %s\n", mountpoint);
		ret = 0;
	} else if (dax_path) {
		unsigned long long dax_phys = 0;
		size_t dax_size = 0;
		bool is_dax_device;
		int fd;

		is_dax_device = (dax_device_info(dax_path, &dax_phys, &dax_size) == 0);

		if (is_dax_device) {
			printf("DAX device %s: phys=0x%llx size=%zu (%.0f MB)\n",
			       dax_path, dax_phys, dax_size,
			       (double)dax_size / (1024 * 1024));

			if (max_size && max_size > dax_size) {
				fprintf(stderr, "Error: requested size %zu exceeds device size %zu\n",
					max_size, dax_size);
				return 1;
			}
			if (!max_size)
				max_size = total_size;
			if (max_size > dax_size) {
				fprintf(stderr, "Error: image size %zu exceeds device size %zu\n",
					max_size, dax_size);
				return 1;
			}

			fd = open(dax_path, O_RDWR);
			if (fd < 0) {
				perror(dax_path);
				return 1;
			}

			mem = mmap(NULL, max_size, PROT_READ | PROT_WRITE,
				   MAP_SHARED, fd, 0);
			close(fd);
		} else if (phys_addr) {
			/* Pre-existing physical address (e.g. /dev/mem, FPGA BAR) */
			dax_phys = phys_addr;

			fd = open(dax_path, O_RDWR | O_SYNC);
			if (fd < 0) {
				perror(dax_path);
				return 1;
			}

			printf("Device %s: mapping at phys=0x%llx\n",
			       dax_path, dax_phys);

			mem = mmap(NULL, max_size, PROT_READ | PROT_WRITE,
				   MAP_SHARED, fd, dax_phys);
			close(fd);
		} else {
			/* Allocator device (e.g. /dev/lazy_cma): alloc via ioctl, then mmap */
			struct lazy_cma_allocation_data alloc = { 0 };

			if (!max_size) {
				fprintf(stderr, "Error: -s/--size is required with %s\n",
					dax_path);
				return 1;
			}

			fd = open(dax_path, O_RDWR | O_SYNC);
			if (fd < 0) {
				perror(dax_path);
				return 1;
			}

			alloc.len = max_size;
			alloc.node = -1;
			snprintf(alloc.name, sizeof(alloc.name), "daxfs");
			if (ioctl(fd, LAZY_CMA_IOCTL_ALLOC, &alloc) < 0) {
				perror("LAZY_CMA_IOCTL_ALLOC");
				close(fd);
				return 1;
			}
			dax_phys = alloc.phys_addr;
			printf("Allocated %zu bytes from %s at phys=0x%llx\n",
			       max_size, dax_path, dax_phys);

			mem = mmap(NULL, max_size, PROT_READ | PROT_WRITE,
				   MAP_SHARED, fd, dax_phys);
			close(fd);
		}

		if (mem == MAP_FAILED) {
			perror("mmap");
			return 1;
		}

		printf("Writing daxfs image to %s...\n", dax_path);
		if (empty_mode) {
			if (write_empty_image(mem, max_size, overlay_buckets,
					      overlay_pool_size, pcache_slots) < 0) {
				munmap(mem, max_size);
				return 1;
			}
		} else if (export_mode) {
			if (write_split_image(mem, max_size, src_dir, base_size,
					      overlay_buckets, overlay_pool_size,
					      pcache_slots) < 0) {
				munmap(mem, max_size);
				return 1;
			}
		} else if (split_mode) {
			printf("Writing backing file to %s...\n", output_file);
			if (write_backing_file(output_file, src_dir) < 0) {
				munmap(mem, max_size);
				return 1;
			}

			if (write_split_image(mem, max_size, src_dir, base_size,
					      overlay_buckets, overlay_pool_size,
					      pcache_slots) < 0) {
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

		if (mountpoint) {
			/* Mount using phys+size via the new mount API */
			printf("Mounting on %s (%s%s%s)...\n", mountpoint,
			       has_overlay ? "writable" : "read-only",
			       validate ? ", validating" : "",
			       (split_mode || export_mode) ? ", backing-store" : "");
			if (mount_daxfs_phys(dax_phys, max_size, mountpoint,
					     has_overlay, validate,
					     split_mode ? output_file : NULL,
					     export_mode ? src_dir : NULL) < 0)
				return 1;

			printf("Done. Mounted daxfs on %s\n", mountpoint);
		} else {
			printf("Done. Use mount -t daxfs -o phys=0x%llx,size=%zu none /mnt\n",
			       dax_phys, max_size);
		}
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
		if (empty_mode) {
			if (write_empty_image(mem, total_size, overlay_buckets,
					      overlay_pool_size, pcache_slots) < 0) {
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
