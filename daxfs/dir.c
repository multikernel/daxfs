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
	*count = size / DAXFS_DIRENT_SIZE;
	return daxfs_mem_ptr(info, base_offset + data_offset);
}

/*
 * Check if name exists in directory (checking deltas first, then base)
 */
static bool daxfs_name_exists(struct super_block *sb, u64 parent_ino,
			      const char *name, int namelen, u64 *ino_out)
{
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *b;
	struct daxfs_dirent *dirents;
	u32 dirent_count, i;

	/* Check delta logs from child to parent */
	for (b = info->current_branch; b != NULL; b = b->parent) {
		struct daxfs_delta_hdr *hdr;

		hdr = daxfs_delta_lookup_dirent(b, parent_ino, name, namelen);
		if (hdr) {
			u32 type = le32_to_cpu(hdr->type);

			if (type == DAXFS_DELTA_DELETE)
				return false;	/* Deleted */

			if (type == DAXFS_DELTA_CREATE ||
			    type == DAXFS_DELTA_MKDIR) {
				struct daxfs_delta_create *cr =
					(void *)hdr + sizeof(*hdr);
				if (ino_out)
					*ino_out = le64_to_cpu(cr->new_ino);
				return true;
			}

			if (type == DAXFS_DELTA_SYMLINK) {
				struct daxfs_delta_symlink *sl =
					(void *)hdr + sizeof(*hdr);
				if (ino_out)
					*ino_out = le64_to_cpu(sl->new_ino);
				return true;
			}
		}
	}

	/* Check base image (flat dirent array) */
	dirents = daxfs_get_base_dirents(info, parent_ino, &dirent_count);
	for (i = 0; i < dirent_count; i++) {
		struct daxfs_dirent *de = &dirents[i];
		u32 child_ino = le32_to_cpu(de->ino);
		u16 child_name_len = le16_to_cpu(de->name_len);

		if (namelen == child_name_len &&
		    memcmp(name, de->name, namelen) == 0) {
			/* Check if deleted in delta */
			for (b = info->current_branch; b; b = b->parent) {
				if (daxfs_delta_is_deleted(b, child_ino))
					return false;
			}
			if (ino_out)
				*ino_out = child_ino;
			return true;
		}
	}

	return false;
}

static struct dentry *daxfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct inode *inode = NULL;
	u64 ino;

	if (!daxfs_branch_is_valid(info))
		return ERR_PTR(-ESTALE);

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	if (daxfs_name_exists(sb, dir->i_ino,
			      dentry->d_name.name, dentry->d_name.len,
			      &ino)) {
		inode = daxfs_iget(sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}

	return d_splice_alias(inode, dentry);
}

static int daxfs_create(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	struct inode *inode;
	struct daxfs_delta_create cr;
	char *entry_data;
	size_t entry_size;
	u64 new_ino;
	int ret;

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return -ENAMETOOLONG;

	/* Check if name already exists */
	if (daxfs_name_exists(sb, dir->i_ino,
			      dentry->d_name.name, dentry->d_name.len, NULL))
		return -EEXIST;

	/* Allocate new inode number */
	new_ino = daxfs_alloc_ino(branch);

	/* Update global counter */
	if (new_ino >= le64_to_cpu(info->super->next_inode_id))
		info->super->next_inode_id = cpu_to_le64(new_ino + 1);

	/* Prepare CREATE entry */
	cr.parent_ino = cpu_to_le64(dir->i_ino);
	cr.new_ino = cpu_to_le64(new_ino);
	cr.mode = cpu_to_le32(mode);
	cr.uid = cpu_to_le32(from_kuid(&init_user_ns, current_fsuid()));
	cr.gid = cpu_to_le32(from_kgid(&init_user_ns, current_fsgid()));
	cr.name_len = cpu_to_le16(dentry->d_name.len);
	cr.flags = 0;

	/* Append to delta log */
	entry_size = sizeof(cr) + dentry->d_name.len;
	entry_data = kmalloc(entry_size, GFP_KERNEL);
	if (!entry_data)
		return -ENOMEM;

	memcpy(entry_data, &cr, sizeof(cr));
	memcpy(entry_data + sizeof(cr), dentry->d_name.name, dentry->d_name.len);

	ret = daxfs_delta_append(branch, DAXFS_DELTA_CREATE, new_ino,
				 entry_data, entry_size);
	kfree(entry_data);
	if (ret)
		return ret;

	/* Create VFS inode */
	inode = daxfs_new_inode(sb, mode, new_ino);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	/* Update parent directory timestamps */
	inode_set_mtime_to_ts(dir,
		inode_set_ctime_to_ts(dir, current_time(dir)));

	d_instantiate(dentry, inode);
	return 0;
}

static struct dentry *daxfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
				  struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	struct inode *inode;
	struct daxfs_delta_create cr;
	char *entry_data;
	size_t entry_size;
	u64 new_ino;
	int ret;

	if (!daxfs_branch_is_valid(info))
		return ERR_PTR(-ESTALE);

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	/* Check if name already exists */
	if (daxfs_name_exists(sb, dir->i_ino,
			      dentry->d_name.name, dentry->d_name.len, NULL))
		return ERR_PTR(-EEXIST);

	/* Allocate new inode number */
	new_ino = daxfs_alloc_ino(branch);

	if (new_ino >= le64_to_cpu(info->super->next_inode_id))
		info->super->next_inode_id = cpu_to_le64(new_ino + 1);

	/* Prepare MKDIR entry */
	cr.parent_ino = cpu_to_le64(dir->i_ino);
	cr.new_ino = cpu_to_le64(new_ino);
	cr.mode = cpu_to_le32(mode | S_IFDIR);
	cr.uid = cpu_to_le32(from_kuid(&init_user_ns, current_fsuid()));
	cr.gid = cpu_to_le32(from_kgid(&init_user_ns, current_fsgid()));
	cr.name_len = cpu_to_le16(dentry->d_name.len);
	cr.flags = 0;

	entry_size = sizeof(cr) + dentry->d_name.len;
	entry_data = kmalloc(entry_size, GFP_KERNEL);
	if (!entry_data)
		return ERR_PTR(-ENOMEM);

	memcpy(entry_data, &cr, sizeof(cr));
	memcpy(entry_data + sizeof(cr), dentry->d_name.name, dentry->d_name.len);

	ret = daxfs_delta_append(branch, DAXFS_DELTA_MKDIR, new_ino,
				 entry_data, entry_size);
	kfree(entry_data);
	if (ret)
		return ERR_PTR(ret);

	inode = daxfs_new_inode(sb, mode | S_IFDIR, new_ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	inc_nlink(dir);

	/* Update parent directory timestamps */
	inode_set_mtime_to_ts(dir,
		inode_set_ctime_to_ts(dir, current_time(dir)));

	d_instantiate(dentry, inode);
	return NULL;
}

static int daxfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	struct inode *inode = d_inode(dentry);
	struct daxfs_delta_delete del;
	char *entry_data;
	size_t entry_size;
	int ret;

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	del.parent_ino = cpu_to_le64(dir->i_ino);
	del.name_len = cpu_to_le16(dentry->d_name.len);
	del.flags = 0;
	del.reserved = 0;

	entry_size = sizeof(del) + dentry->d_name.len;
	entry_data = kmalloc(entry_size, GFP_KERNEL);
	if (!entry_data)
		return -ENOMEM;

	memcpy(entry_data, &del, sizeof(del));
	memcpy(entry_data + sizeof(del), dentry->d_name.name, dentry->d_name.len);

	ret = daxfs_delta_append(branch, DAXFS_DELTA_DELETE, inode->i_ino,
				 entry_data, entry_size);
	kfree(entry_data);
	if (ret)
		return ret;

	drop_nlink(inode);
	inode_set_ctime_current(inode);

	/* Update parent directory timestamps */
	inode_set_mtime_to_ts(dir,
		inode_set_ctime_to_ts(dir, current_time(dir)));

	return 0;
}

/*
 * Check if directory is empty (has no entries other than . and ..)
 */
static bool daxfs_dir_is_empty(struct super_block *sb, u64 dir_ino)
{
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *b;
	struct daxfs_dirent *dirents;
	u32 count, i;

	/* Check base image entries */
	dirents = daxfs_get_base_dirents(info, dir_ino, &count);
	for (i = 0; i < count; i++) {
		u32 child_ino = le32_to_cpu(dirents[i].ino);

		/* Check if this entry was deleted in delta */
		for (b = info->current_branch; b; b = b->parent) {
			if (daxfs_delta_is_deleted(b, child_ino))
				goto next_base;
		}
		return false;  /* Found non-deleted entry */
next_base:;
	}

	/* Check delta entries created in this directory */
	for (b = info->current_branch; b; b = b->parent) {
		if (daxfs_delta_has_children(b, dir_ino))
			return false;
	}

	return true;
}

static int daxfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	if (!daxfs_dir_is_empty(dir->i_sb, inode->i_ino))
		return -ENOTEMPTY;

	return daxfs_unlink(dir, dentry);
}

static int daxfs_symlink(struct mnt_idmap *idmap, struct inode *dir,
			 struct dentry *dentry, const char *target)
{
	struct super_block *sb = dir->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	struct inode *inode;
	struct daxfs_delta_symlink sl;
	char *entry_data;
	size_t entry_size;
	size_t target_len;
	u64 new_ino;
	int ret;

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return -ENAMETOOLONG;

	/* Check if name already exists */
	if (daxfs_name_exists(sb, dir->i_ino,
			      dentry->d_name.name, dentry->d_name.len, NULL))
		return -EEXIST;

	target_len = strlen(target);
	if (target_len > PATH_MAX)
		return -ENAMETOOLONG;

	/* Allocate new inode number */
	new_ino = daxfs_alloc_ino(branch);

	/* Update global counter */
	if (new_ino >= le64_to_cpu(info->super->next_inode_id))
		info->super->next_inode_id = cpu_to_le64(new_ino + 1);

	/* Prepare SYMLINK entry */
	sl.parent_ino = cpu_to_le64(dir->i_ino);
	sl.new_ino = cpu_to_le64(new_ino);
	sl.uid = cpu_to_le32(from_kuid(&init_user_ns, current_fsuid()));
	sl.gid = cpu_to_le32(from_kgid(&init_user_ns, current_fsgid()));
	sl.name_len = cpu_to_le16(dentry->d_name.len);
	sl.target_len = cpu_to_le16(target_len);

	/* Entry: struct + name + target + null terminator */
	entry_size = sizeof(sl) + dentry->d_name.len + target_len + 1;
	entry_data = kmalloc(entry_size, GFP_KERNEL);
	if (!entry_data)
		return -ENOMEM;

	memcpy(entry_data, &sl, sizeof(sl));
	memcpy(entry_data + sizeof(sl), dentry->d_name.name, dentry->d_name.len);
	memcpy(entry_data + sizeof(sl) + dentry->d_name.len, target, target_len);
	entry_data[sizeof(sl) + dentry->d_name.len + target_len] = '\0';

	ret = daxfs_delta_append(branch, DAXFS_DELTA_SYMLINK, new_ino,
				 entry_data, entry_size);
	kfree(entry_data);
	if (ret)
		return ret;

	/* Create VFS inode */
	inode = daxfs_new_inode(sb, S_IFLNK | 0777, new_ino);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	/* Set symlink target - point directly to delta log */
	inode->i_link = daxfs_delta_get_symlink(branch, new_ino);
	inode->i_size = target_len;

	/* Update parent directory timestamps */
	inode_set_mtime_to_ts(dir,
		inode_set_ctime_to_ts(dir, current_time(dir)));

	d_instantiate(dentry, inode);
	return 0;
}

static int daxfs_rename(struct mnt_idmap *idmap, struct inode *old_dir,
			struct dentry *old_dentry, struct inode *new_dir,
			struct dentry *new_dentry, unsigned int flags)
{
	struct super_block *sb = old_dir->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	struct inode *inode = d_inode(old_dentry);
	struct inode *target = d_inode(new_dentry);
	struct daxfs_delta_rename rn;
	char *entry_data;
	size_t entry_size;
	int ret;

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	if (new_dentry->d_name.len > DAXFS_NAME_MAX)
		return -ENAMETOOLONG;

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	/* Handle overwrite case */
	if (target) {
		if (flags & RENAME_NOREPLACE)
			return -EEXIST;

		/* Type compatibility checks */
		if (S_ISDIR(inode->i_mode)) {
			if (!S_ISDIR(target->i_mode))
				return -ENOTDIR;
			if (!daxfs_dir_is_empty(sb, target->i_ino))
				return -ENOTEMPTY;
		} else {
			if (S_ISDIR(target->i_mode))
				return -EISDIR;
		}

		/* Remove the target first */
		ret = daxfs_unlink(new_dir, new_dentry);
		if (ret)
			return ret;
	}

	rn.old_parent_ino = cpu_to_le64(old_dir->i_ino);
	rn.new_parent_ino = cpu_to_le64(new_dir->i_ino);
	rn.ino = cpu_to_le64(inode->i_ino);
	rn.old_name_len = cpu_to_le16(old_dentry->d_name.len);
	rn.new_name_len = cpu_to_le16(new_dentry->d_name.len);
	rn.reserved = 0;

	entry_size = sizeof(rn) + old_dentry->d_name.len + new_dentry->d_name.len;
	entry_data = kmalloc(entry_size, GFP_KERNEL);
	if (!entry_data)
		return -ENOMEM;

	memcpy(entry_data, &rn, sizeof(rn));
	memcpy(entry_data + sizeof(rn), old_dentry->d_name.name,
	       old_dentry->d_name.len);
	memcpy(entry_data + sizeof(rn) + old_dentry->d_name.len,
	       new_dentry->d_name.name, new_dentry->d_name.len);

	ret = daxfs_delta_append(branch, DAXFS_DELTA_RENAME, inode->i_ino,
				 entry_data, entry_size);
	kfree(entry_data);
	if (ret)
		return ret;

	/* Update inode ctime */
	inode_set_ctime_current(inode);

	/* Update directory timestamps */
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
	struct super_block *sb = dir->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch;
	loff_t pos = 2;  /* Start after . and .. */

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	if (!dir_emit_dots(file, ctx))
		return 0;

	/* First emit entries from base image (if not deleted) */
	if (info->base_inodes && dir->i_ino <= info->base_inode_count) {
		struct daxfs_dirent *dirents;
		u32 dirent_count, i;

		dirents = daxfs_get_base_dirents(info, dir->i_ino, &dirent_count);
		for (i = 0; i < dirent_count; i++) {
			struct daxfs_dirent *de = &dirents[i];
			u32 child_ino = le32_to_cpu(de->ino);
			u16 name_len = le16_to_cpu(de->name_len);
			u32 mode = le32_to_cpu(de->mode);
			bool deleted = false;
			unsigned char dtype;

			/* Check if deleted in any branch */
			for (branch = info->current_branch; branch; branch = branch->parent) {
				if (daxfs_delta_is_deleted(branch, child_ino)) {
					deleted = true;
					break;
				}
			}

			if (!deleted) {
				if (pos >= ctx->pos) {
					switch (mode & S_IFMT) {
					case S_IFREG: dtype = DT_REG; break;
					case S_IFDIR: dtype = DT_DIR; break;
					case S_IFLNK: dtype = DT_LNK; break;
					default: dtype = DT_UNKNOWN; break;
					}

					if (!dir_emit(ctx, de->name, name_len, child_ino, dtype))
						return 0;
					ctx->pos = pos + 1;
				}
				pos++;
			}
		}
	}

	/* Then emit entries from delta logs */
	for (branch = info->current_branch; branch; branch = branch->parent) {
		u64 offset = 0;

		while (offset < branch->delta_size) {
			struct daxfs_delta_hdr *hdr = branch->delta_log + offset;
			u32 type = le32_to_cpu(hdr->type);
			u32 total_size = le32_to_cpu(hdr->total_size);

			if (total_size == 0)
				break;

			if (type == DAXFS_DELTA_CREATE || type == DAXFS_DELTA_MKDIR) {
				struct daxfs_delta_create *cr = (void *)hdr + sizeof(*hdr);

				if (le64_to_cpu(cr->parent_ino) == dir->i_ino) {
					char *name = (char *)(cr + 1);
					u16 name_len = le16_to_cpu(cr->name_len);
					u64 ino = le64_to_cpu(cr->new_ino);
					u32 mode = le32_to_cpu(cr->mode);
					unsigned char dtype;
					bool deleted = false;

					/* Check if subsequently deleted */
					struct daxfs_branch_ctx *b2;
					for (b2 = info->current_branch; b2 != branch; b2 = b2->parent) {
						if (daxfs_delta_is_deleted(b2, ino)) {
							deleted = true;
							break;
						}
					}

					if (!deleted) {
						if (pos >= ctx->pos) {
							switch (mode & S_IFMT) {
							case S_IFREG: dtype = DT_REG; break;
							case S_IFDIR: dtype = DT_DIR; break;
							case S_IFLNK: dtype = DT_LNK; break;
							default: dtype = DT_UNKNOWN; break;
							}

							if (!dir_emit(ctx, name, name_len, ino, dtype))
								return 0;
							ctx->pos = pos + 1;
						}
						pos++;
					}
				}
			}

			if (type == DAXFS_DELTA_SYMLINK) {
				struct daxfs_delta_symlink *sl = (void *)hdr + sizeof(*hdr);

				if (le64_to_cpu(sl->parent_ino) == dir->i_ino) {
					char *name = (char *)(sl + 1);
					u16 name_len = le16_to_cpu(sl->name_len);
					u64 ino = le64_to_cpu(sl->new_ino);
					bool deleted = false;

					/* Check if subsequently deleted */
					struct daxfs_branch_ctx *b2;
					for (b2 = info->current_branch; b2 != branch; b2 = b2->parent) {
						if (daxfs_delta_is_deleted(b2, ino)) {
							deleted = true;
							break;
						}
					}

					if (!deleted) {
						if (pos >= ctx->pos) {
							if (!dir_emit(ctx, name, name_len, ino, DT_LNK))
								return 0;
							ctx->pos = pos + 1;
						}
						pos++;
					}
				}
			}

			offset += total_size;
		}
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

/*
 * ============================================================================
 * Read-Only Operations (static image mode)
 * ============================================================================
 *
 * These operations provide direct base image access without delta checks.
 * Used when info->static_image is true.
 */

/*
 * Check if name exists in base image only (no delta checks)
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

static struct dentry *daxfs_lookup_ro(struct inode *dir, struct dentry *dentry,
				      unsigned int flags)
{
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct inode *inode = NULL;
	u64 ino;

	if (dentry->d_name.len > DAXFS_NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	if (daxfs_name_exists_base(info, dir->i_ino,
				   dentry->d_name.name, dentry->d_name.len,
				   &ino)) {
		inode = daxfs_iget(dir->i_sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}

	return d_splice_alias(inode, dentry);
}

static int daxfs_iterate_ro(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct daxfs_dirent *dirents;
	u32 dirent_count, i;
	loff_t pos = 2;  /* Start after . and .. */

	if (!dir_emit_dots(file, ctx))
		return 0;

	dirents = daxfs_get_base_dirents(info, dir->i_ino, &dirent_count);
	for (i = 0; i < dirent_count; i++) {
		struct daxfs_dirent *de = &dirents[i];
		u32 child_ino = le32_to_cpu(de->ino);
		u16 name_len = le16_to_cpu(de->name_len);
		u32 mode = le32_to_cpu(de->mode);
		unsigned char dtype;

		if (pos >= ctx->pos) {
			switch (mode & S_IFMT) {
			case S_IFREG: dtype = DT_REG; break;
			case S_IFDIR: dtype = DT_DIR; break;
			case S_IFLNK: dtype = DT_LNK; break;
			default: dtype = DT_UNKNOWN; break;
			}

			if (!dir_emit(ctx, de->name, name_len, child_ino, dtype))
				return 0;
			ctx->pos = pos + 1;
		}
		pos++;
	}

	return 0;
}

const struct inode_operations daxfs_dir_inode_ops_ro = {
	.lookup		= daxfs_lookup_ro,
	/* No create, mkdir, unlink, rmdir, rename - read-only */
};

const struct file_operations daxfs_dir_ops_ro = {
	.iterate_shared	= daxfs_iterate_ro,
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
	.unlocked_ioctl	= daxfs_ioctl,
};
