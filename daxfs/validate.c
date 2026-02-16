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
#include <linux/overflow.h>
#include "daxfs.h"

static inline bool check_add_overflow_u64(u64 a, u64 b, u64 *result)
{
	return check_add_overflow(a, b, result);
}

static inline bool daxfs_valid_file_type(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
		return true;
	default:
		return false;
	}
}

static inline bool regions_overlap(u64 a_start, u64 a_size,
				   u64 b_start, u64 b_size)
{
	if (a_size == 0 || b_size == 0)
		return false;
	return a_start < b_start + b_size && b_start < a_start + a_size;
}

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
			u64 num_entries_u64;
			u32 num_entries;
			struct daxfs_dirent *dirents;
			u64 dirent_offset;
			u32 j;

			if (file_size == 0)
				continue;

			/* Check for overflow in offset calculation */
			if (check_add_overflow_u64(base_offset, file_data_offset,
						   &dirent_offset)) {
				pr_err("daxfs: dir %u offset overflow\n", i + 1);
				ret = -EINVAL;
				goto out;
			}

			/* Validate num_entries fits in u32 */
			num_entries_u64 = file_size / DAXFS_DIRENT_SIZE;
			if (num_entries_u64 > U32_MAX) {
				pr_err("daxfs: dir %u has too many entries\n", i + 1);
				ret = -EINVAL;
				goto out;
			}
			num_entries = (u32)num_entries_u64;

			dirents = daxfs_mem_ptr(info, dirent_offset);

			for (j = 0; j < num_entries; j++) {
				u32 child_ino = le32_to_cpu(dirents[j].ino);

				/* Bounds check - ino is 1-based */
				if (child_ino < 1 || child_ino > inode_count) {
					pr_err("daxfs: dir %u entry %u has invalid ino %u\n",
					       i + 1, j, child_ino);
					ret = -EINVAL;
					goto out;
				}
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
	if (inode_count == 0) {
		pr_err("daxfs: base image has no inodes\n");
		return -EINVAL;
	}

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

	/* Validate root inode is a directory */
	{
		u32 root_idx = le32_to_cpu(base->root_inode) - 1;
		u32 root_mode = le32_to_cpu(info->base_inodes[root_idx].mode);

		if (!S_ISDIR(root_mode)) {
			pr_err("daxfs: root inode is not a directory\n");
			return -EINVAL;
		}
	}

	/* Validate each inode's data offset and type-specific constraints */
	for (i = 0; i < inode_count; i++) {
		struct daxfs_base_inode *raw = &info->base_inodes[i];
		u64 file_data_offset = le64_to_cpu(raw->data_offset);
		u64 file_size = le64_to_cpu(raw->size);
		u32 mode = le32_to_cpu(raw->mode);

		/* Validate file type is supported */
		if (!daxfs_valid_file_type(mode)) {
			pr_err("daxfs: inode %u has unsupported file type 0%o\n",
			       i + 1, (mode & S_IFMT) >> 12);
			return -EINVAL;
		}

		/* Validate data offset bounds */
		if (file_size > 0) {
			if (!daxfs_valid_base_offset(info, file_data_offset, file_size)) {
				pr_err("daxfs: inode %u has invalid data offset\n", i + 1);
				return -EINVAL;
			}
		}

		/* For directories, validate dirent array */
		if (S_ISDIR(mode) && file_size > 0) {
			u64 num_entries_u64;
			u32 num_entries;
			u32 j;
			struct daxfs_dirent *dirents;
			u64 dirent_offset;

			/* Size must be multiple of DAXFS_DIRENT_SIZE */
			if (file_size % DAXFS_DIRENT_SIZE != 0) {
				pr_err("daxfs: dir inode %u has invalid size\n", i + 1);
				return -EINVAL;
			}

			/* Validate num_entries fits in u32 */
			num_entries_u64 = file_size / DAXFS_DIRENT_SIZE;
			if (num_entries_u64 > U32_MAX) {
				pr_err("daxfs: dir inode %u has too many entries\n", i + 1);
				return -EINVAL;
			}
			num_entries = (u32)num_entries_u64;

			/* Check for overflow in offset calculation */
			if (check_add_overflow_u64(base_offset, file_data_offset,
						   &dirent_offset)) {
				pr_err("daxfs: dir inode %u offset overflow\n", i + 1);
				return -EINVAL;
			}

			dirents = daxfs_mem_ptr(info, dirent_offset);

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

				/* Check for duplicate names (O(n^2) but only at validation) */
				if (name_len > 0) {
					u32 k;

					for (k = 0; k < j; k++) {
						struct daxfs_dirent *prev = &dirents[k];
						u16 prev_len = le16_to_cpu(prev->name_len);

						if (prev_len == name_len &&
						    memcmp(de->name, prev->name, name_len) == 0) {
							pr_err("daxfs: dir %u has duplicate name at entries %u and %u\n",
							       i + 1, k, j);
							return -EINVAL;
						}
					}
				}
			}
		}

		/* For symlinks, ensure null-termination */
		if (S_ISLNK(mode) && file_size > 0) {
			u64 symlink_offset;
			char *target;
			size_t check_len = file_size + 1;

			/* Check for overflow in offset calculation */
			if (check_add_overflow_u64(base_offset, file_data_offset,
						   &symlink_offset)) {
				pr_err("daxfs: inode %u symlink offset overflow\n", i + 1);
				return -EINVAL;
			}

			target = daxfs_mem_ptr(info, symlink_offset);

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
	u64 pcache_offset = le64_to_cpu(info->super->pcache_offset);
	u64 pcache_size = le64_to_cpu(info->super->pcache_size);
	u64 super_size = sizeof(struct daxfs_super);

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

	/* Validate page cache region bounds */
	if (pcache_offset != 0) {
		u32 slot_count = le32_to_cpu(info->super->pcache_slot_count);

		if (!daxfs_valid_offset(info, pcache_offset, pcache_size)) {
			pr_err("daxfs: pcache region exceeds image bounds\n");
			return -EINVAL;
		}

		/* Slot count must be a power of 2 */
		if (slot_count == 0 || (slot_count & (slot_count - 1)) != 0) {
			pr_err("daxfs: pcache slot_count %u not power of 2\n",
			       slot_count);
			return -EINVAL;
		}

		/* Validate pcache_size is large enough for header + slots + data */
		{
			u64 meta_size = ALIGN((u64)slot_count * sizeof(struct daxfs_pcache_slot),
					      DAXFS_BLOCK_SIZE);
			u64 data_size = (u64)slot_count * DAXFS_BLOCK_SIZE;
			u64 min_size = DAXFS_BLOCK_SIZE + meta_size + data_size;

			if (pcache_size < min_size) {
				pr_err("daxfs: pcache region too small (%llu < %llu)\n",
				       pcache_size, min_size);
				return -EINVAL;
			}
		}
	}

	/*
	 * Validate regions don't overlap with each other or the superblock.
	 * Superblock is at offset 0.
	 */
	if (base_size > 0 && regions_overlap(0, super_size, base_offset, base_size)) {
		pr_err("daxfs: base image overlaps superblock\n");
		return -EINVAL;
	}

	if (branch_table_size > 0 && regions_overlap(0, super_size,
						     branch_table_offset,
						     branch_table_size)) {
		pr_err("daxfs: branch table overlaps superblock\n");
		return -EINVAL;
	}

	if (delta_size > 0 && regions_overlap(0, super_size,
					      delta_offset, delta_size)) {
		pr_err("daxfs: delta region overlaps superblock\n");
		return -EINVAL;
	}

	if (pcache_size > 0 && regions_overlap(0, super_size,
					       pcache_offset, pcache_size)) {
		pr_err("daxfs: pcache region overlaps superblock\n");
		return -EINVAL;
	}

	if (base_size > 0 && branch_table_size > 0 &&
	    regions_overlap(base_offset, base_size,
			    branch_table_offset, branch_table_size)) {
		pr_err("daxfs: base image overlaps branch table\n");
		return -EINVAL;
	}

	if (base_size > 0 && delta_size > 0 &&
	    regions_overlap(base_offset, base_size, delta_offset, delta_size)) {
		pr_err("daxfs: base image overlaps delta region\n");
		return -EINVAL;
	}

	if (base_size > 0 && pcache_size > 0 &&
	    regions_overlap(base_offset, base_size,
			    pcache_offset, pcache_size)) {
		pr_err("daxfs: base image overlaps pcache region\n");
		return -EINVAL;
	}

	if (branch_table_size > 0 && delta_size > 0 &&
	    regions_overlap(branch_table_offset, branch_table_size,
			    delta_offset, delta_size)) {
		pr_err("daxfs: branch table overlaps delta region\n");
		return -EINVAL;
	}

	if (branch_table_size > 0 && pcache_size > 0 &&
	    regions_overlap(branch_table_offset, branch_table_size,
			    pcache_offset, pcache_size)) {
		pr_err("daxfs: branch table overlaps pcache region\n");
		return -EINVAL;
	}

	if (delta_size > 0 && pcache_size > 0 &&
	    regions_overlap(delta_offset, delta_size,
			    pcache_offset, pcache_size)) {
		pr_err("daxfs: delta region overlaps pcache region\n");
		return -EINVAL;
	}

	return 0;
}
