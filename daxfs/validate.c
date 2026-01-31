// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs image validation
 *
 * Validates base image structure for security when mounting untrusted images.
 * Enabled with the 'validate' mount option.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include "daxfs.h"

/*
 * Validate hard link consistency in the base image.
 * - Count directory references to each inode
 * - Verify nlink matches actual reference count
 * - Verify hard links (nlink > 1) only exist for regular files
 */
static int daxfs_validate_hardlinks(struct daxfs_info *info)
{
	u64 base_offset = le64_to_cpu(info->super->base_offset);
	u32 inode_count = info->base_inode_count;
	u32 *refcount;
	u32 i;
	int ret = 0;

	refcount = kvzalloc(array_size(inode_count, sizeof(u32)), GFP_KERNEL);
	if (!refcount)
		return -ENOMEM;

	/* Pass 1: Count directory references to each inode */
	for (i = 0; i < inode_count; i++) {
		struct daxfs_base_inode *raw = &info->base_inodes[i];
		u32 mode = le32_to_cpu(raw->mode);

		if (S_ISDIR(mode)) {
			u64 file_data_offset = le64_to_cpu(raw->data_offset);
			u64 file_size = le64_to_cpu(raw->size);
			u32 num_entries = file_size / DAXFS_DIRENT_SIZE;
			struct daxfs_dirent *dirents;
			u32 j;

			if (file_size == 0)
				continue;

			dirents = daxfs_mem_ptr(info, base_offset + file_data_offset);

			for (j = 0; j < num_entries; j++) {
				u32 child_ino = le32_to_cpu(dirents[j].ino);
				/* ino is 1-based, refcount is 0-based */
				refcount[child_ino - 1]++;
			}
		}
	}

	/* Pass 2: Verify nlink matches refcount and hard link rules */
	for (i = 0; i < inode_count; i++) {
		struct daxfs_base_inode *raw = &info->base_inodes[i];
		u32 nlink = le32_to_cpu(raw->nlink);
		u32 mode = le32_to_cpu(raw->mode);
		u32 ino = i + 1;

		/* nlink should match directory reference count */
		if (nlink != refcount[i]) {
			pr_err("daxfs: inode %u nlink mismatch: nlink=%u refcount=%u\n",
			       ino, nlink, refcount[i]);
			ret = -EINVAL;
			goto out;
		}

		/* Hard links (nlink > 1) only allowed for regular files */
		if (nlink > 1 && !S_ISREG(mode)) {
			pr_err("daxfs: inode %u has nlink=%u but is not a regular file\n",
			       ino, nlink);
			ret = -EINVAL;
			goto out;
		}

		/* Every inode must have at least one reference */
		if (nlink == 0) {
			pr_err("daxfs: inode %u has no references (nlink=0)\n", ino);
			ret = -EINVAL;
			goto out;
		}
	}

out:
	kvfree(refcount);
	return ret;
}

/*
 * Validate the base image structure for security (flat directory format)
 * Returns 0 on success, -errno on error
 */
int daxfs_validate_base_image(struct daxfs_info *info)
{
	struct daxfs_base_super *base = info->base_super;
	u64 base_offset = le64_to_cpu(info->super->base_offset);
	u64 base_size = le64_to_cpu(info->super->base_size);
	u64 inode_offset, data_offset;
	u32 inode_count, i;
	int ret;

	if (!base)
		return 0;  /* No base image */

	/* Validate base image magic */
	if (le32_to_cpu(base->magic) != DAXFS_BASE_MAGIC) {
		pr_err("daxfs: invalid base image magic 0x%x (expected 0x%x)\n",
		       le32_to_cpu(base->magic), DAXFS_BASE_MAGIC);
		return -EINVAL;
	}

	/* Validate version */
	if (le32_to_cpu(base->version) != DAXFS_VERSION) {
		pr_err("daxfs: unsupported base image version %u\n",
		       le32_to_cpu(base->version));
		return -EINVAL;
	}

	/* Validate base image fits within declared size */
	if (le64_to_cpu(base->total_size) > base_size) {
		pr_err("daxfs: base image total_size exceeds allocated space\n");
		return -EINVAL;
	}

	inode_offset = le64_to_cpu(base->inode_offset);
	data_offset = le64_to_cpu(base->data_offset);
	inode_count = le32_to_cpu(base->inode_count);

	/* Validate inode table bounds */
	if (inode_offset > base_size ||
	    (u64)inode_count * DAXFS_INODE_SIZE > base_size - inode_offset) {
		pr_err("daxfs: inode table exceeds base image bounds\n");
		return -EINVAL;
	}

	/* Validate root inode exists */
	if (le32_to_cpu(base->root_inode) < 1 ||
	    le32_to_cpu(base->root_inode) > inode_count) {
		pr_err("daxfs: invalid root inode number\n");
		return -EINVAL;
	}

	/* Validate each inode's data offset and type-specific constraints */
	for (i = 0; i < inode_count; i++) {
		struct daxfs_base_inode *raw = &info->base_inodes[i];
		u64 file_data_offset = le64_to_cpu(raw->data_offset);
		u64 file_size = le64_to_cpu(raw->size);
		u32 mode = le32_to_cpu(raw->mode);

		/* Validate data offset bounds */
		if (file_size > 0) {
			if (!daxfs_valid_base_offset(info, file_data_offset, file_size)) {
				pr_err("daxfs: inode %u has invalid data offset\n", i + 1);
				return -EINVAL;
			}
		}

		/* For directories, validate dirent array */
		if (S_ISDIR(mode) && file_size > 0) {
			u32 num_entries = file_size / DAXFS_DIRENT_SIZE;
			u32 j;
			struct daxfs_dirent *dirents;

			/* Size must be multiple of DAXFS_DIRENT_SIZE */
			if (file_size % DAXFS_DIRENT_SIZE != 0) {
				pr_err("daxfs: dir inode %u has invalid size\n", i + 1);
				return -EINVAL;
			}

			dirents = daxfs_mem_ptr(info, base_offset + file_data_offset);

			/* Validate each dirent */
			for (j = 0; j < num_entries; j++) {
				struct daxfs_dirent *de = &dirents[j];
				u32 child_ino = le32_to_cpu(de->ino);
				u16 name_len = le16_to_cpu(de->name_len);

				if (child_ino < 1 || child_ino > inode_count) {
					pr_err("daxfs: dir %u entry %u has invalid ino\n",
					       i + 1, j);
					return -EINVAL;
				}

				if (name_len > DAXFS_NAME_MAX) {
					pr_err("daxfs: dir %u entry %u name too long\n",
					       i + 1, j);
					return -EINVAL;
				}
			}
		}

		/* For symlinks, ensure null-termination */
		if (S_ISLNK(mode) && file_size > 0) {
			char *target = daxfs_mem_ptr(info,
				base_offset + file_data_offset);
			size_t check_len = file_size + 1;

			/* Ensure we have space to check for null terminator */
			if (!daxfs_valid_base_offset(info, file_data_offset, check_len)) {
				pr_err("daxfs: inode %u symlink extends past bounds\n", i + 1);
				return -EINVAL;
			}

			/* Check that there's a null at or before position file_size */
			if (strnlen(target, check_len) > file_size) {
				pr_err("daxfs: inode %u symlink not null-terminated\n", i + 1);
				return -EINVAL;
			}
		}
	}

	/* Validate hard link consistency */
	ret = daxfs_validate_hardlinks(info);
	if (ret)
		return ret;

	/* No cycle detection needed - flat directory format has no linked lists */

	return 0;
}

/*
 * Validate overall image structure bounds
 */
int daxfs_validate_super(struct daxfs_info *info)
{
	u64 base_offset = le64_to_cpu(info->super->base_offset);
	u64 base_size = le64_to_cpu(info->super->base_size);
	u64 branch_table_offset = le64_to_cpu(info->super->branch_table_offset);
	u64 branch_table_size = (u64)info->branch_table_entries *
				sizeof(struct daxfs_branch);
	u64 delta_offset = le64_to_cpu(info->super->delta_region_offset);
	u64 delta_size = le64_to_cpu(info->super->delta_region_size);

	/* Validate base image region bounds */
	if (base_offset != 0) {
		if (!daxfs_valid_offset(info, base_offset, base_size)) {
			pr_err("daxfs: base image region exceeds image bounds\n");
			return -EINVAL;
		}
	}

	/* Validate branch table bounds */
	if (branch_table_offset != 0) {
		if (!daxfs_valid_offset(info, branch_table_offset, branch_table_size)) {
			pr_err("daxfs: branch table exceeds image bounds\n");
			return -EINVAL;
		}
	}

	/* Validate delta region bounds */
	if (delta_offset != 0) {
		if (!daxfs_valid_offset(info, delta_offset, delta_size)) {
			pr_err("daxfs: delta region exceeds image bounds\n");
			return -EINVAL;
		}
	}

	return 0;
}
