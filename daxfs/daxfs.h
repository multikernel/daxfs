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
#include <linux/iosys-map.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include "daxfs_format.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
static inline unsigned int inode_state_read_once(struct inode *inode)
{
	return READ_ONCE(inode->i_state);
}
#endif

struct daxfs_branch_ctx;

/*
 * Write extent entry - tracks a single write to an inode
 * Stored in a list per inode, newest first for fast lookup
 */
struct daxfs_write_extent {
	struct list_head list;
	u64 offset;			/* File offset of write */
	u32 len;			/* Length of write */
	void *data;			/* Pointer to data in delta log */
};

/*
 * Delta index entry - tracks latest delta for an inode
 */
struct daxfs_delta_inode_entry {
	struct rb_node rb_node;
	u64 ino;
	struct daxfs_delta_hdr *hdr;	/* Latest delta entry for this inode */
	u64 size;			/* Current size after all deltas */
	u32 mode;			/* Current mode */
	bool deleted;			/* Tombstone marker */
	struct list_head write_extents;	/* List of writes, newest first */
	char *symlink_target;		/* For symlinks: target path (in delta log) */
};

/*
 * Delta index entry - tracks directory entries
 */
struct daxfs_delta_dirent_entry {
	struct rb_node rb_node;
	u64 parent_ino;
	u32 name_hash;
	char *name;
	u16 name_len;
	struct daxfs_delta_hdr *hdr;	/* Latest delta entry */
	bool deleted;			/* Tombstone marker */
};

/*
 * Branch context - runtime state for a branch
 */
struct daxfs_branch_ctx {
	struct list_head list;		/* In daxfs_info.active_branches */
	struct daxfs_info *info;	/* Back pointer to fs info */
	u64 branch_id;
	char name[32];			/* Branch name */
	struct daxfs_branch *on_dax;	/* Pointer to on-DAX record */
	struct daxfs_branch_ctx *parent; /* Parent branch context */

	/* Delta log state */
	void *delta_log;		/* Mapped delta log start */
	u64 delta_size;			/* Current size (bytes used) */
	u64 delta_capacity;		/* Allocated capacity */

	/* In-memory index for fast lookup (rebuilt on mount) */
	struct rb_root inode_index;	/* ino -> latest delta entry */
	struct rb_root dirent_index;	/* (parent_ino, name_hash) -> entry */
	spinlock_t index_lock;

	/* Inode allocation */
	u64 next_ino;			/* Next inode number to allocate */

	atomic_t refcount;		/* Child branches + active mounts */
	bool committed;			/* True if commit was requested */

	/* Generation tracking for invalidation detection */
	u32 cached_generation;		/* Cached from on_dax->generation */
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

	/* Superblock */
	struct daxfs_super *super;

	/* Branch management */
	struct daxfs_branch *branch_table;
	u32 branch_table_entries;
	struct daxfs_branch_ctx *current_branch;

	/* Base image access */
	struct daxfs_base_super *base_super;
	struct daxfs_base_inode *base_inodes;
	u64 base_data_offset;		/* Absolute offset to data region */
	u32 base_inode_count;

	/* Static image mode (no branching) */
	bool static_image;

	/* Allocation lock for delta region */
	spinlock_t alloc_lock;
	u64 delta_alloc_offset;		/* Next free byte in delta region */

	/* Branch management */
	struct mutex branch_lock;
	struct list_head active_branches;

	/* Open file tracking for mmap safety */
	atomic_t open_files;		/* Count of open regular files */

	/* Global coordination for cross-mount synchronization */
	struct daxfs_global_coord *coord;  /* Pointer to DAX coordination area */
	u64 cached_commit_seq;		   /* Last observed commit sequence */
};

struct daxfs_inode_info {
	struct inode vfs_inode;		/* VFS inode (must be first) */
	struct daxfs_base_inode *raw;	/* On-disk inode (base image) */
	u64 data_offset;		/* Cached data offset */
	u64 delta_size;			/* Size from delta log (if modified) */
	bool from_delta;		/* True if inode created in delta */
};

static inline struct daxfs_info *DAXFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct daxfs_inode_info *DAXFS_I(struct inode *inode)
{
	return container_of(inode, struct daxfs_inode_info, vfs_inode);
}

static inline struct daxfs_branch_ctx *daxfs_get_branch(struct super_block *sb)
{
	struct daxfs_info *info = DAXFS_SB(sb);
	return info->current_branch;
}

/* super.c */
extern const struct super_operations daxfs_super_ops;
extern struct inode *daxfs_iget(struct super_block *sb, u64 ino);

/* dir.c */
extern const struct inode_operations daxfs_dir_inode_ops;
extern const struct file_operations daxfs_dir_ops;

/* dir.c - read-only ops */
extern const struct inode_operations daxfs_dir_inode_ops_ro;
extern const struct file_operations daxfs_dir_ops_ro;

/* file.c */
extern const struct inode_operations daxfs_file_inode_ops;
extern const struct file_operations daxfs_file_ops;
extern const struct address_space_operations daxfs_aops;
extern long daxfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* file.c - read-only ops */
extern const struct inode_operations daxfs_file_inode_ops_ro;
extern const struct file_operations daxfs_file_ops_ro;
extern const struct address_space_operations daxfs_aops_ro;

/* inode.c */
extern struct inode *daxfs_alloc_inode(struct super_block *sb);
extern void daxfs_free_inode(struct inode *inode);
extern int __init daxfs_inode_cache_init(void);
extern void daxfs_inode_cache_destroy(void);
extern struct inode *daxfs_new_inode(struct super_block *sb, umode_t mode,
				     u64 ino);
extern u64 daxfs_alloc_ino(struct daxfs_branch_ctx *branch);

/* delta.c */
extern int daxfs_delta_init_branch(struct daxfs_info *info,
				   struct daxfs_branch_ctx *branch);
extern void daxfs_delta_destroy_branch(struct daxfs_branch_ctx *branch);
extern void *daxfs_delta_alloc(struct daxfs_info *info,
			       struct daxfs_branch_ctx *branch, size_t size);
extern int daxfs_delta_append(struct daxfs_branch_ctx *branch, u32 type,
			      u64 ino, void *data, size_t data_len);
extern int daxfs_delta_build_index(struct daxfs_branch_ctx *branch);
extern struct daxfs_delta_hdr *daxfs_delta_lookup_inode(
	struct daxfs_branch_ctx *branch, u64 ino);
extern struct daxfs_delta_hdr *daxfs_delta_lookup_dirent(
	struct daxfs_branch_ctx *branch, u64 parent_ino,
	const char *name, int namelen);
extern bool daxfs_delta_is_deleted(struct daxfs_branch_ctx *branch, u64 ino);
extern int daxfs_delta_get_size(struct daxfs_branch_ctx *branch, u64 ino,
				loff_t *size);
extern int daxfs_resolve_inode(struct super_block *sb, u64 ino,
			       umode_t *mode, loff_t *size, bool *deleted);
extern void *daxfs_resolve_file_data(struct super_block *sb, u64 ino,
				     loff_t pos, size_t len, size_t *out_len);
extern void *daxfs_lookup_write_extent(struct daxfs_branch_ctx *branch,
				       u64 ino, loff_t pos, size_t len,
				       size_t *out_len);
extern int daxfs_index_add_write_extent(struct daxfs_branch_ctx *branch,
					u64 ino, u64 offset, u32 len,
					void *data);
extern int daxfs_delta_merge(struct daxfs_branch_ctx *parent,
			     struct daxfs_branch_ctx *child);
extern char *daxfs_delta_get_symlink(struct daxfs_branch_ctx *branch, u64 ino);

/* branch.c */
extern struct daxfs_branch_ctx *daxfs_find_branch_by_name(
	struct daxfs_info *info, const char *name);
extern int daxfs_branch_create(struct daxfs_info *info, const char *name,
			       const char *parent_name,
			       struct daxfs_branch_ctx **out);
extern int daxfs_branch_commit(struct daxfs_info *info,
			       struct daxfs_branch_ctx *branch);
extern int daxfs_branch_abort(struct daxfs_info *info,
			      struct daxfs_branch_ctx *branch);
extern int daxfs_init_main_branch(struct daxfs_info *info);
extern bool daxfs_branch_is_valid(struct daxfs_info *info);
extern bool daxfs_commit_seq_changed(struct daxfs_info *info);

/*
 * ============================================================================
 * Storage Layer (dax_mem.c)
 * ============================================================================
 *
 * The storage layer provides abstraction for DAX memory access:
 * - Memory mapping (memremap, dma-buf)
 * - Region allocation
 * - Direct pointer access helpers
 * - Persistence synchronization
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

/* Region allocation */
extern u64 daxfs_mem_alloc_region(struct daxfs_info *info, size_t size);
extern void daxfs_mem_free_region(struct daxfs_info *info, u64 offset,
				  u64 size);

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

	if (!info->base_super)
		return false;

	base_size = le64_to_cpu(info->base_super->total_size);

	/* Check for overflow */
	if (offset > SIZE_MAX - len)
		return false;
	return offset + len <= base_size;
}

/* Validate base image on mount - returns 0 on success, -errno on error */
extern int daxfs_validate_base_image(struct daxfs_info *info);

#endif /* _FS_DAXFS_H */
