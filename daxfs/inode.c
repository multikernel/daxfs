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
	xa_init(&di->ovl_pages);

	return &di->vfs_inode;
}

void daxfs_free_inode(struct inode *inode)
{
	xa_destroy(&DAXFS_I(inode)->ovl_pages);
	kmem_cache_free(daxfs_inode_cachep, DAXFS_I(inode));
}

static void daxfs_inode_init_once(void *obj)
{
	struct daxfs_inode_info *di = obj;

	inode_init_once(&di->vfs_inode);
}

/*
 * Get inode - resolves from overlay first, then base image
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
	u32 nlink = 1;

	/* iget_locked takes unsigned long; reject inos that would truncate */
	if (ino > (u64)(unsigned long)-1)
		return ERR_PTR(-EOVERFLOW);

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode_state_read_once(inode) & I_NEW))
		return inode;

	di = DAXFS_I(inode);

	/* Check overlay first */
	if (info->overlay) {
		struct daxfs_ovl_inode_entry *oie;

		oie = daxfs_overlay_get_inode(info, ino);
		if (oie) {
			mode = le32_to_cpu(oie->mode);
			size = le64_to_cpu(oie->size);
			uid = le32_to_cpu(oie->uid);
			gid = le32_to_cpu(oie->gid);
			nlink = le32_to_cpu(oie->nlink);
			goto found;
		}
	}

	/* Base image lookup */
	if (info->base_inodes && ino <= info->base_inode_count) {
		di->raw = &info->base_inodes[ino - 1];
		di->data_offset = le64_to_cpu(di->raw->data_offset);
		mode = le32_to_cpu(di->raw->mode);
		size = le64_to_cpu(di->raw->size);
		uid = le32_to_cpu(di->raw->uid);
		gid = le32_to_cpu(di->raw->gid);
		nlink = le32_to_cpu(di->raw->nlink);
		goto found;
	}

	/* Not found */
	iget_failed(inode);
	return ERR_PTR(-ENOENT);

found:
	inode->i_mode = mode;
	inode->i_uid = make_kuid(&init_user_ns, uid);
	inode->i_gid = make_kgid(&init_user_ns, gid);
	inode->i_size = size;
	set_nlink(inode, nlink);

	inode_set_mtime_to_ts(inode,
		inode_set_atime_to_ts(inode,
			inode_set_ctime_to_ts(inode, zerotime)));

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
		/* Check overlay for symlink target (stored in data page 0) */
		if (info->overlay) {
			void *page = daxfs_overlay_get_page(info, ino, 0);

			if (page) {
				inode->i_link = page;
				goto done;
			}
		}
		/* Fall back to base image */
		if (di->raw && size > 0) {
			u64 symlink_offset = le64_to_cpu(info->super->base_offset) +
					     di->data_offset;
			char *target;

			/*
			 * Validate: symlink target must fit within the
			 * mapped region (size+1 for null terminator).
			 */
			if (!daxfs_valid_offset(info, symlink_offset,
						size + 1)) {
				iget_failed(inode);
				return ERR_PTR(-EIO);
			}
			target = daxfs_mem_ptr(info, symlink_offset);
			if (target[size] != '\0') {
				iget_failed(inode);
				return ERR_PTR(-EIO);
			}
			inode->i_link = target;
		}
		break;
	default:
		break;
	}

done:
	unlock_new_inode(inode);
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
