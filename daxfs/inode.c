// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs inode operations
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include "daxfs.h"

static struct kmem_cache *daxfs_inode_cachep;

struct inode *daxfs_alloc_inode(struct super_block *sb)
{
	struct daxfs_inode_info *di;

	di = alloc_inode_sb(sb, daxfs_inode_cachep, GFP_KERNEL);
	if (!di)
		return NULL;

	di->raw = NULL;
	di->data_offset = 0;
	di->delta_size = 0;
	di->from_delta = false;

	return &di->vfs_inode;
}

void daxfs_free_inode(struct inode *inode)
{
	kmem_cache_free(daxfs_inode_cachep, DAXFS_I(inode));
}

static void daxfs_inode_init_once(void *obj)
{
	struct daxfs_inode_info *di = obj;

	inode_init_once(&di->vfs_inode);
}

/*
 * Allocate a new inode number from the branch
 */
u64 daxfs_alloc_ino(struct daxfs_branch_ctx *branch)
{
	u64 ino;

	ino = branch->next_ino++;
	branch->on_dax->next_local_ino = cpu_to_le64(branch->next_ino);

	return ino;
}

/*
 * Get inode
 */
struct inode *daxfs_iget(struct super_block *sb, u64 ino)
{
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_inode_info *di;
	struct inode *inode;
	struct timespec64 zerotime = {0, 0};
	umode_t mode = 0;
	loff_t size = 0;
	uid_t uid = 0;
	gid_t gid = 0;
	bool deleted = false;
	int ret;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode_state_read_once(inode) & I_NEW))
		return inode;

	di = DAXFS_I(inode);

	/* Base image pointer — always set when inode exists there */
	if (info->base_inodes && ino <= info->base_inode_count) {
		di->raw = &info->base_inodes[ino - 1];
		di->data_offset = le64_to_cpu(di->raw->data_offset);
	}

	/* Delta metadata overrides */
	ret = daxfs_resolve_inode(sb, ino, &mode, &size, &uid, &gid, &deleted);
	if (ret == 0 && !deleted) {
		di->from_delta = true;
		di->delta_size = size;
	} else if (di->raw) {
		/* Pure base image inode */
		mode = le32_to_cpu(di->raw->mode);
		size = le64_to_cpu(di->raw->size);
		uid = le32_to_cpu(di->raw->uid);
		gid = le32_to_cpu(di->raw->gid);
		di->from_delta = false;
	} else {
		/* Not found */
		iget_failed(inode);
		return ERR_PTR(-ENOENT);
	}

	inode->i_mode = mode;
	inode->i_uid = make_kuid(&init_user_ns, uid);
	inode->i_gid = make_kgid(&init_user_ns, gid);
	inode->i_size = size;

	/* Set nlink from base image or delta, accounting for unlinks */
	{
		u32 effective_nlink = 1;
		if (daxfs_get_effective_nlink(sb, ino, &effective_nlink) == 0)
			set_nlink(inode, effective_nlink);
		else if (di->raw)
			set_nlink(inode, le32_to_cpu(di->raw->nlink));
		else
			set_nlink(inode, 1);
	}

	inode_set_mtime_to_ts(inode,
		inode_set_atime_to_ts(inode,
			inode_set_ctime_to_ts(inode, zerotime)));

	if (info->static_image) {
		/* Static image mode - use read-only ops */
		switch (mode & S_IFMT) {
		case S_IFREG:
			inode->i_op = &daxfs_file_inode_ops_ro;
			inode->i_fop = &daxfs_file_ops_ro;
			inode->i_mapping->a_ops = &daxfs_aops_ro;
			break;
		case S_IFDIR:
			inode->i_op = &daxfs_dir_inode_ops_ro;
			inode->i_fop = &daxfs_dir_ops_ro;
			break;
		case S_IFLNK:
			inode->i_op = &simple_symlink_inode_operations;
			if (di->raw) {
				u64 symlink_offset = le64_to_cpu(info->super->base_offset) +
						     di->data_offset;
				inode->i_link = daxfs_mem_ptr(info, symlink_offset);
			}
			break;
		default:
			break;
		}
	} else {
		/* Branching mode - use full read-write ops */
		switch (mode & S_IFMT) {
		case S_IFREG:
			inode->i_op = &daxfs_file_inode_ops;
			inode->i_fop = &daxfs_file_ops;
			inode->i_mapping->a_ops = &daxfs_aops;
			break;
		case S_IFDIR:
			inode->i_op = &daxfs_dir_inode_ops;
			inode->i_fop = &daxfs_dir_ops;
			break;
		case S_IFLNK:
			inode->i_op = &simple_symlink_inode_operations;
			if (di->from_delta) {
				/* Try delta first (symlink created in branch) */
				struct daxfs_branch_ctx *b;
				for (b = info->current_branch; b; b = b->parent) {
					char *target = daxfs_delta_get_symlink(b, ino);
					if (target) {
						inode->i_link = target;
						break;
					}
				}
			}
			if (!inode->i_link && di->raw) {
				/* Fall back to base image symlink target */
				u64 symlink_offset = le64_to_cpu(info->super->base_offset) +
						     di->data_offset;
				inode->i_link = daxfs_mem_ptr(info, symlink_offset);
			}
			break;
		default:
			break;
		}
	}

	unlock_new_inode(inode);
	return inode;
}

/*
 * Create a new inode
 */
struct inode *daxfs_new_inode(struct super_block *sb, umode_t mode, u64 ino)
{
	struct inode *inode;
	struct daxfs_inode_info *di;
	struct timespec64 now;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode_state_read_once(inode) & I_NEW)) {
		/* Inode already exists - shouldn't happen for new allocation */
		iput(inode);
		return ERR_PTR(-EEXIST);
	}

	di = DAXFS_I(inode);
	di->raw = NULL;
	di->data_offset = 0;
	di->delta_size = 0;
	di->from_delta = true;

	inode->i_mode = mode;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_size = 0;
	set_nlink(inode, 1);

	now = current_time(inode);
	inode_set_mtime_to_ts(inode,
		inode_set_atime_to_ts(inode,
			inode_set_ctime_to_ts(inode, now)));

	switch (mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &daxfs_file_inode_ops;
		inode->i_fop = &daxfs_file_ops;
		inode->i_mapping->a_ops = &daxfs_aops;
		break;
	case S_IFDIR:
		inode->i_op = &daxfs_dir_inode_ops;
		inode->i_fop = &daxfs_dir_ops;
		inc_nlink(inode);	/* . entry */
		break;
	case S_IFLNK:
		inode->i_op = &simple_symlink_inode_operations;
		break;
	default:
		break;
	}

	/* Don't unlock here - caller must use d_instantiate_new() */
	return inode;
}

int __init daxfs_inode_cache_init(void)
{
	daxfs_inode_cachep = kmem_cache_create("daxfs_inode_cache",
					       sizeof(struct daxfs_inode_info),
					       0,
					       SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
					       daxfs_inode_init_once);
	if (!daxfs_inode_cachep)
		return -ENOMEM;
	return 0;
}

void daxfs_inode_cache_destroy(void)
{
	kmem_cache_destroy(daxfs_inode_cachep);
}
