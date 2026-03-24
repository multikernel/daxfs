/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */
#ifndef _FS_DAXFS_H
#define _FS_DAXFS_H

#include <linux/fs.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/dma-buf.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
#include <linux/iosys-map.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <linux/dma-buf-map.h>
#define iosys_map dma_buf_map
#endif
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/xarray.h>
#include "daxfs_format.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
static inline unsigned int inode_state_read_once(struct inode *inode)
{
	return READ_ONCE(inode->i_state);
}
#endif

struct daxfs_pcache;
struct daxfs_overlay;

/*
 * Page cache runtime state
 */
struct daxfs_pcache {
	struct daxfs_pcache_header *header;  /* On-DAX header */
	struct daxfs_pcache_slot *slots;     /* On-DAX slot metadata */
	void *data;                          /* On-DAX slot data area */
	u32 slot_count;
	u32 hash_mask;                       /* slot_count - 1 */
	u32 block_size;                      /* Cached from daxfs_info */
	u32 block_shift;                     /* ilog2(block_size) */
	struct list_head backing_files;      /* List of daxfs_pcache_backing */
	struct task_struct *fill_thread;     /* Host kthread, NULL for spawn */
	struct file **backing_array;         /* O(1) lookup by ino, [0..max_ino] */
	u32 backing_array_size;              /* Number of entries in array */
};

/*
 * Per-file backing file tracking for multi-file pcache
 */
struct daxfs_pcache_backing {
	u64 ino;
	struct file *file;
	struct list_head list;
};

/*
 * Overlay runtime state
 */
struct daxfs_overlay {
	struct daxfs_overlay_header *header; /* On-DAX header */
	struct daxfs_overlay_bucket *buckets; /* On-DAX bucket array */
	void *pool;                          /* On-DAX pool area */
	u32 bucket_count;
	u32 bucket_mask;                     /* bucket_count - 1 */
};

/*
 * Filesystem info - runtime state
 */
struct daxfs_info {
	/* Storage layer fields */
	void *mem;			/* Mapped memory base */
	phys_addr_t phys_addr;		/* Physical address */
	size_t size;			/* Total size */
	struct dma_buf *dmabuf;		/* held dma-buf reference (if mounted via fd) */
	struct iosys_map dma_map;	/* vmap of dma-buf */
	char *name;			/* Mount name for identification */

	/* VFS superblock back-pointer (for inode iteration) */
	struct super_block *sb;

	/* On-DAX Superblock */
	struct daxfs_super *super;

	/* Cached block_size from superblock (== PAGE_SIZE, validated at mount) */
	u32 block_size;

	/* Base image access */
	struct daxfs_base_inode *base_inodes;
	u64 base_data_offset;		/* Absolute offset to data region */
	u32 base_inode_count;

	/* Hash overlay (NULL if read-only) */
	struct daxfs_overlay *overlay;

	/* Page cache for backing store mode */
	struct daxfs_pcache *pcache;

	/* Export mode: serve file data from local directory tree */
	bool export_mode;
};

struct daxfs_inode_info {
	struct inode vfs_inode;		/* VFS inode (must be first) */
	struct daxfs_base_inode *raw;	/* On-disk inode (base image) */
	u64 data_offset;		/* Cached data offset */
	struct xarray ovl_pages;	/* Local cache: pgoff → overlay page ptr */
};

static inline struct daxfs_info *DAXFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct daxfs_inode_info *DAXFS_I(struct inode *inode)
{
	return container_of(inode, struct daxfs_inode_info, vfs_inode);
}

/* super.c */
extern const struct super_operations daxfs_super_ops;
extern struct inode *daxfs_iget(struct super_block *sb, u64 ino);

/* dir.c */
extern const struct inode_operations daxfs_dir_inode_ops;
extern const struct file_operations daxfs_dir_ops;

/* file.c */
extern const struct inode_operations daxfs_file_inode_ops;
extern const struct file_operations daxfs_file_ops;
extern const struct address_space_operations daxfs_aops;
extern long daxfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* file.c - base image data access */
extern void *daxfs_base_file_data(struct daxfs_info *info,
				  struct inode *inode,
				  loff_t pos, size_t len, size_t *out_len,
				  s32 *pinned_slot);

/* inode.c */
extern struct inode *daxfs_alloc_inode(struct super_block *sb);
extern void daxfs_free_inode(struct inode *inode);
extern int __init daxfs_inode_cache_init(void);
extern void daxfs_inode_cache_destroy(void);

/*
 * ============================================================================
 * Storage Layer (dax_mem.c)
 * ============================================================================
 */

/* Memory mapping initialization */
extern int daxfs_mem_init_dmabuf(struct daxfs_info *info,
				 struct file *dmabuf_file);
extern int daxfs_mem_init_phys(struct daxfs_info *info, phys_addr_t phys_addr,
			       size_t size);
extern void daxfs_mem_exit(struct daxfs_info *info);

/* Pointer/offset conversion */
extern void *daxfs_mem_ptr(struct daxfs_info *info, u64 offset);
extern u64 daxfs_mem_offset(struct daxfs_info *info, void *ptr);
extern phys_addr_t daxfs_mem_phys(struct daxfs_info *info, u64 offset);

/* Persistence */
extern void daxfs_mem_sync(struct daxfs_info *info, void *ptr, size_t size);

/*
 * ============================================================================
 * Validation Helpers
 * ============================================================================
 */

/* Check if an inode number is valid for the base image */
static inline bool daxfs_valid_base_ino(struct daxfs_info *info, u64 ino)
{
	return ino >= 1 && ino <= info->base_inode_count;
}

/* Check if an offset is within the mapped memory region */
static inline bool daxfs_valid_offset(struct daxfs_info *info, u64 offset,
				      size_t len)
{
	/* Check for overflow */
	if (offset > SIZE_MAX - len)
		return false;
	return offset + len <= info->size;
}

/* Check if an offset is within the base image region */
static inline bool daxfs_valid_base_offset(struct daxfs_info *info,
					   u64 offset, size_t len)
{
	u64 base_size;

	if (!info->super || !le64_to_cpu(info->super->base_offset))
		return false;

	base_size = le64_to_cpu(info->super->base_size);

	/* Check for overflow */
	if (offset > SIZE_MAX - len)
		return false;
	return offset + len <= base_size;
}

/* pcache.c - shared page cache for backing store mode */
extern int daxfs_pcache_init(struct daxfs_info *info, const char *backing_path);
extern void daxfs_pcache_exit(struct daxfs_info *info);
extern void *daxfs_pcache_get_page(struct daxfs_info *info, u64 ino,
				   u64 pgoff, s32 *pinned_slot);
extern void daxfs_pcache_put_page(struct daxfs_info *info, s32 slot_idx);
extern bool daxfs_is_pcache_data(struct daxfs_info *info, void *ptr);
extern int daxfs_pcache_add_backing(struct daxfs_info *info, u64 ino,
				    const char *path);
extern int daxfs_pcache_init_export(struct daxfs_info *info,
				    const char *export_path);

/* overlay.c - CAS-based hash overlay for writes */
extern int daxfs_overlay_init(struct daxfs_info *info);
extern void daxfs_overlay_exit(struct daxfs_info *info);

extern struct daxfs_ovl_inode_entry *daxfs_overlay_get_inode(
	struct daxfs_info *info, u64 ino);
extern int daxfs_overlay_set_inode(struct daxfs_info *info, u64 ino,
				   const struct daxfs_ovl_inode_entry *ie);
extern void *daxfs_overlay_get_page(struct daxfs_info *info, u64 ino,
				    u64 pgoff);
extern void *daxfs_overlay_alloc_page(struct daxfs_info *info, u64 ino,
				      u64 pgoff, u64 *pool_off_out);
extern void *daxfs_overlay_publish_page(struct daxfs_info *info, u64 ino,
					u64 pgoff, u64 pool_off, void *page);
extern int daxfs_overlay_alloc_pages_batch(struct daxfs_info *info, u64 ino,
					   u64 start_pgoff, u32 count,
					   void **pages, u64 *pool_offs);
extern struct daxfs_ovl_dirent_entry *daxfs_overlay_lookup_dirent(
	struct daxfs_info *info, u64 parent_ino,
	const char *name, u16 name_len);
extern int daxfs_overlay_create_dirent(struct daxfs_info *info,
				       u64 parent_ino, u64 child_ino,
				       u32 child_mode,
				       const char *name, u16 name_len);
extern int daxfs_overlay_delete_dirent(struct daxfs_info *info,
				       u64 parent_ino,
				       const char *name, u16 name_len);
extern u64 daxfs_overlay_alloc_ino(struct daxfs_info *info);
extern int daxfs_overlay_iterate_dir(struct daxfs_info *info,
				     u64 parent_ino,
				     struct dir_context *ctx,
				     loff_t *pos);
extern bool daxfs_overlay_dir_has_entries(struct daxfs_info *info,
					  u64 parent_ino);

/* validate.c - image validation for untrusted images */
extern int daxfs_validate_super(struct daxfs_info *info);
extern int daxfs_validate_base_image(struct daxfs_info *info);

#endif /* _FS_DAXFS_H */
