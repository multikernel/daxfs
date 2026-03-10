// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs directory operations
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include "daxfs.h"

/*
 * Get directory entries from base image (flat dirent array)
 */
static struct daxfs_dirent *daxfs_get_base_dirents(struct daxfs_info *info,
						   u64 dir_ino, u32 *count)
{
	struct daxfs_base_inode *dir_raw;
	u64 base_offset;
	u64 data_offset;
	u64 size;

	if (!info->base_inodes || dir_ino > info->base_inode_count) {
		*count = 0;
		return NULL;
	}

	dir_raw = &info->base_inodes[dir_ino - 1];
	data_offset = le64_to_cpu(dir_raw->data_offset);
	size = le64_to_cpu(dir_raw->size);

	if (size == 0) {
		*count = 0;
		return NULL;
	}

	/* data_offset is relative to base image start */
	base_offset = le64_to_cpu(info->super->base_offset);

	/* Validate dirent array fits in mapped region */
	if (!daxfs_valid_offset(info, base_offset + data_offset, size)) {
		*count = 0;
		return NULL;
	}

	*count = size / DAXFS_DIRENT_SIZE;
	return daxfs_mem_ptr(info, base_offset + data_offset);
}

/*
 * Check if name exists in base image only (no overlay checks)
 */
static bool daxfs_name_exists_base(struct daxfs_info *info, u64 parent_ino,
				   const char *name, int namelen, u64 *ino_out)
{
	struct daxfs_dirent *dirents;
	u32 dirent_count, i;

	dirents = daxfs_get_base_dirents(info, parent_ino, &dirent_count);
	for (i = 0; i < dirent_count; i++) {
		struct daxfs_dirent *de = &dirents[i];
		u16 child_name_len = le16_to_cpu(de->name_len);

		if (namelen == child_name_len &&
		    memcmp(name, de->name, namelen) == 0) {
			if (ino_out)
				*ino_out = le32_to_cpu(de->ino);
			return true;
		}
	}

	return false;
}

/*
 * Unified lookup: overlay first, then base image.
 * If the overlay has a tombstone for this name, it's deleted.
 */
static struct dentry *daxfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct inode *inode = NULL;
	u64 ino;

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	/* Check overlay first */
	if (info->overlay) {
		struct daxfs_ovl_dirent_entry *de;

		de = daxfs_overlay_lookup_dirent(info, dir->i_ino,
						 dentry->d_name.name,
						 dentry->d_name.len);
		if (de) {
			if (le32_to_cpu(de->flags) & DAXFS_OVL_DIRENT_TOMBSTONE)
				return d_splice_alias(NULL, dentry);
			ino = le64_to_cpu(de->child_ino);
			inode = daxfs_iget(dir->i_sb, ino);
			if (IS_ERR(inode))
				return ERR_CAST(inode);
			return d_splice_alias(inode, dentry);
		}
	}

	/*
	 * Check base image. No need to re-check overlay for tombstones here:
	 * if overlay had a tombstone for this name, we would have found it
	 * in the overlay check above and returned NULL already.
	 */
	if (daxfs_name_exists_base(info, dir->i_ino,
				   dentry->d_name.name, dentry->d_name.len,
				   &ino)) {
		inode = daxfs_iget(dir->i_sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}

	return d_splice_alias(inode, dentry);
}

static int daxfs_create(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct daxfs_ovl_inode_entry ie;
	struct inode *inode;
	u64 new_ino;
	int ret;

	if (!info->overlay)
		return -EROFS;

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return -ENAMETOOLONG;

	/* Allocate inode number */
	new_ino = daxfs_overlay_alloc_ino(info);

	/* Create overlay inode entry */
	ie.type = cpu_to_le32(DAXFS_OVL_INODE);
	ie.mode = cpu_to_le32(mode);
	ie.uid = cpu_to_le32(from_kuid(&init_user_ns, current_fsuid()));
	ie.gid = cpu_to_le32(from_kgid(&init_user_ns, current_fsgid()));
	ie.size = cpu_to_le64(0);
	ie.nlink = cpu_to_le32(1);
	ie.flags = 0;

	ret = daxfs_overlay_set_inode(info, new_ino, &ie);
	if (ret)
		return ret;

	/* Create dirent in overlay */
	ret = daxfs_overlay_create_dirent(info, dir->i_ino, new_ino, mode,
					  dentry->d_name.name,
					  dentry->d_name.len);
	if (ret)
		return ret;

	/* Create VFS inode */
	inode = daxfs_iget(dir->i_sb, new_ino);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode_set_mtime_to_ts(dir,
		inode_set_ctime_to_ts(dir, current_time(dir)));

	d_instantiate(dentry, inode);
	return 0;
}

static struct dentry *daxfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
				  struct dentry *dentry, umode_t mode)
{
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct daxfs_ovl_inode_entry ie;
	struct inode *inode;
	u64 new_ino;
	int ret;

	if (!info->overlay)
		return ERR_PTR(-EROFS);

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	new_ino = daxfs_overlay_alloc_ino(info);

	ie.type = cpu_to_le32(DAXFS_OVL_INODE);
	ie.mode = cpu_to_le32(mode | S_IFDIR);
	ie.uid = cpu_to_le32(from_kuid(&init_user_ns, current_fsuid()));
	ie.gid = cpu_to_le32(from_kgid(&init_user_ns, current_fsgid()));
	ie.size = cpu_to_le64(0);
	ie.nlink = cpu_to_le32(2);	/* . and parent link */
	ie.flags = 0;

	ret = daxfs_overlay_set_inode(info, new_ino, &ie);
	if (ret)
		return ERR_PTR(ret);

	ret = daxfs_overlay_create_dirent(info, dir->i_ino, new_ino,
					  mode | S_IFDIR,
					  dentry->d_name.name,
					  dentry->d_name.len);
	if (ret)
		return ERR_PTR(ret);

	inode = daxfs_iget(dir->i_sb, new_ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	inc_nlink(dir);
	inode_set_mtime_to_ts(dir,
		inode_set_ctime_to_ts(dir, current_time(dir)));

	d_instantiate(dentry, inode);
	return NULL;
}

static int daxfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct inode *inode = d_inode(dentry);
	int ret;

	if (!info->overlay)
		return -EROFS;

	ret = daxfs_overlay_delete_dirent(info, dir->i_ino,
					  dentry->d_name.name,
					  dentry->d_name.len);
	if (ret)
		return ret;

	drop_nlink(inode);
	inode_set_ctime_current(inode);
	inode_set_mtime_to_ts(dir,
		inode_set_ctime_to_ts(dir, current_time(dir)));

	return 0;
}

/*
 * Check if a directory is empty (no live children in base image or overlay).
 * Base image entries that have overlay tombstones are considered deleted.
 */
static bool daxfs_dir_is_empty(struct daxfs_info *info, struct inode *dir)
{
	struct daxfs_dirent *dirents;
	u32 dirent_count, i;

	/* Check base image entries (skip tombstoned ones) */
	dirents = daxfs_get_base_dirents(info, dir->i_ino, &dirent_count);
	for (i = 0; i < dirent_count; i++) {
		struct daxfs_dirent *de = &dirents[i];
		u16 name_len = le16_to_cpu(de->name_len);

		if (info->overlay) {
			struct daxfs_ovl_dirent_entry *ode;

			ode = daxfs_overlay_lookup_dirent(info, dir->i_ino,
							  de->name, name_len);
			if (ode && (le32_to_cpu(ode->flags) &
				    DAXFS_OVL_DIRENT_TOMBSTONE))
				continue;
		}
		return false;
	}

	/* Check overlay entries */
	if (daxfs_overlay_dir_has_entries(info, dir->i_ino))
		return false;

	return true;
}

static int daxfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct inode *inode = d_inode(dentry);

	if (!daxfs_dir_is_empty(info, inode))
		return -ENOTEMPTY;

	return daxfs_unlink(dir, dentry);
}

static int daxfs_symlink(struct mnt_idmap *idmap, struct inode *dir,
			 struct dentry *dentry, const char *target)
{
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct daxfs_ovl_inode_entry ie;
	struct inode *inode;
	u64 new_ino;
	size_t target_len = strlen(target);
	int ret;

	if (!info->overlay)
		return -EROFS;

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return -ENAMETOOLONG;

	new_ino = daxfs_overlay_alloc_ino(info);

	ie.type = cpu_to_le32(DAXFS_OVL_INODE);
	ie.mode = cpu_to_le32(S_IFLNK | 0777);
	ie.uid = cpu_to_le32(from_kuid(&init_user_ns, current_fsuid()));
	ie.gid = cpu_to_le32(from_kgid(&init_user_ns, current_fsgid()));
	ie.size = cpu_to_le64(target_len);
	ie.nlink = cpu_to_le32(1);
	ie.flags = 0;

	ret = daxfs_overlay_set_inode(info, new_ino, &ie);
	if (ret)
		return ret;

	/* Store symlink target in first data page */
	{
		u64 pool_off;
		void *page = daxfs_overlay_alloc_page(info, new_ino, 0,
						      &pool_off);

		if (!page)
			return -ENOSPC;
		memcpy(page, target, target_len + 1);
		page = daxfs_overlay_publish_page(info, new_ino, 0,
						  pool_off, page);
		if (!page)
			return -ENOSPC;
	}

	ret = daxfs_overlay_create_dirent(info, dir->i_ino, new_ino,
					  S_IFLNK | 0777,
					  dentry->d_name.name,
					  dentry->d_name.len);
	if (ret)
		return ret;

	inode = daxfs_iget(dir->i_sb, new_ino);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode_set_mtime_to_ts(dir,
		inode_set_ctime_to_ts(dir, current_time(dir)));

	d_instantiate(dentry, inode);
	return 0;
}

/*
 * Rename: create new dirent FIRST, then delete old.
 *
 * Ordering matters for crash safety: if we crash between the two
 * overlay operations, the file is visible in both locations (harmless
 * duplication) rather than invisible in both (data loss).
 */
static int daxfs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
			struct dentry *old_dentry, struct inode *new_dir,
			struct dentry *new_dentry, unsigned int flags)
{
	struct daxfs_info *info = DAXFS_SB(old_dir->i_sb);
	struct inode *inode = d_inode(old_dentry);
	struct inode *target = d_inode(new_dentry);
	int ret;

	if (!info->overlay)
		return -EROFS;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	if (target) {
		if (flags & RENAME_NOREPLACE)
			return -EEXIST;
		ret = daxfs_unlink(new_dir, new_dentry);
		if (ret)
			return ret;
	}

	/* Step 1: Create new dirent (file becomes visible in new location) */
	ret = daxfs_overlay_create_dirent(info, new_dir->i_ino, inode->i_ino,
					  inode->i_mode,
					  new_dentry->d_name.name,
					  new_dentry->d_name.len);
	if (ret)
		return ret;

	/* Step 2: Remove old dirent (file disappears from old location) */
	ret = daxfs_overlay_delete_dirent(info, old_dir->i_ino,
					  old_dentry->d_name.name,
					  old_dentry->d_name.len);
	if (ret)
		return ret;

	inode_set_ctime_current(inode);
	inode_set_mtime_to_ts(old_dir,
		inode_set_ctime_to_ts(old_dir, current_time(old_dir)));
	if (new_dir != old_dir) {
		inode_set_mtime_to_ts(new_dir,
			inode_set_ctime_to_ts(new_dir, current_time(new_dir)));
	}

	return 0;
}

static int daxfs_iterate(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct daxfs_dirent *dirents;
	u32 dirent_count, i;
	loff_t pos = 2;  /* Start after . and .. */

	if (!dir_emit_dots(file, ctx))
		return 0;

	/* Emit entries from base image (check overlay tombstones) */
	dirents = daxfs_get_base_dirents(info, dir->i_ino, &dirent_count);
	for (i = 0; i < dirent_count; i++) {
		struct daxfs_dirent *de = &dirents[i];
		u32 child_ino = le32_to_cpu(de->ino);
		u16 name_len = le16_to_cpu(de->name_len);
		u32 mode = le32_to_cpu(de->mode);
		unsigned char dtype;

		/* Check if deleted in overlay */
		if (info->overlay) {
			struct daxfs_ovl_dirent_entry *ode;

			ode = daxfs_overlay_lookup_dirent(info, dir->i_ino,
							  de->name, name_len);
			if (ode && (le32_to_cpu(ode->flags) &
				    DAXFS_OVL_DIRENT_TOMBSTONE))
				continue;
		}

		if (pos >= ctx->pos) {
			switch (mode & S_IFMT) {
			case S_IFREG: dtype = DT_REG; break;
			case S_IFDIR: dtype = DT_DIR; break;
			case S_IFLNK: dtype = DT_LNK; break;
			default: dtype = DT_UNKNOWN; break;
			}

			if (!dir_emit(ctx, de->name, name_len, child_ino,
				      dtype))
				return 0;
			ctx->pos = pos + 1;
		}
		pos++;
	}

	/* Emit entries from overlay */
	if (info->overlay) {
		int ret;

		ret = daxfs_overlay_iterate_dir(info, dir->i_ino, ctx, &pos);
		if (ret)
			return ret;
	}

	return 0;
}

const struct inode_operations daxfs_dir_inode_ops = {
	.lookup		= daxfs_lookup,
	.create		= daxfs_create,
	.mkdir		= daxfs_mkdir,
	.unlink		= daxfs_unlink,
	.rmdir		= daxfs_rmdir,
	.rename		= daxfs_rename,
	.symlink	= daxfs_symlink,
};

const struct file_operations daxfs_dir_ops = {
	.iterate_shared	= daxfs_iterate,
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
	.unlocked_ioctl	= daxfs_ioctl,
};
