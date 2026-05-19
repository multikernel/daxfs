// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs image validation
 *
 * Validates base image and overlay structure for security when mounting
 * untrusted images. Enabled with the 'validate' mount option.
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
 * Validate the base image structure for security (flat directory format).
 * Reads layout fields from the main superblock.
 */
int daxfs_validate_base_image(struct daxfs_info *info)
{
	struct daxfs_super *super = info->super;
	u64 base_offset = le64_to_cpu(super->base_offset);
	u64 base_size = le64_to_cpu(super->base_size);
	u64 inode_offset, data_offset;
	u32 inode_count, i;

	if (!base_offset)
		return 0;

	inode_offset = le64_to_cpu(super->inode_offset);
	data_offset = le64_to_cpu(super->data_offset);
	inode_count = le32_to_cpu(super->inode_count);
	if (inode_count == 0) {
		pr_err("daxfs: base image has no inodes\n");
		return -EINVAL;
	}

	if (inode_offset > base_size ||
	    (u64)inode_count * DAXFS_INODE_SIZE > base_size - inode_offset) {
		pr_err("daxfs: inode table exceeds base image bounds\n");
		return -EINVAL;
	}

	if (le32_to_cpu(super->root_inode) < 1 ||
	    le32_to_cpu(super->root_inode) > inode_count) {
		pr_err("daxfs: invalid root inode number\n");
		return -EINVAL;
	}

	{
		u32 root_idx = le32_to_cpu(super->root_inode) - 1;
		u32 root_mode = le32_to_cpu(info->base_inodes[root_idx].mode);

		if (!S_ISDIR(root_mode)) {
			pr_err("daxfs: root inode is not a directory\n");
			return -EINVAL;
		}
	}

	for (i = 0; i < inode_count; i++) {
		struct daxfs_base_inode *raw = &info->base_inodes[i];
		u64 file_data_offset = le64_to_cpu(raw->data_offset);
		u64 file_size = le64_to_cpu(raw->size);
		u32 mode = le32_to_cpu(raw->mode);

		if (!daxfs_valid_file_type(mode)) {
			pr_err("daxfs: inode %u has unsupported file type 0%o\n",
			       i + 1, (mode & S_IFMT) >> 12);
			return -EINVAL;
		}

		if (file_size > 0) {
			/*
			 * Validate data bounds for all file types with
			 * inline data. Regular files in pcache/export mode
			 * fetch data from backing store at runtime, but
			 * their base image data_offset still must be valid
			 * if non-zero (it's used to compute pcache tags in
			 * split mode).
			 */
			if (!daxfs_valid_base_offset(info, file_data_offset, file_size)) {
				pr_err("daxfs: inode %u has invalid data offset\n", i + 1);
				return -EINVAL;
			}
		}

		if (S_ISDIR(mode) && file_size > 0) {
			u64 num_entries_u64;
			u32 num_entries;
			u32 j;
			struct daxfs_dirent *dirents;
			u64 dirent_offset;

			if (file_size % DAXFS_DIRENT_SIZE != 0) {
				pr_err("daxfs: dir inode %u has invalid size\n", i + 1);
				return -EINVAL;
			}

			num_entries_u64 = file_size / DAXFS_DIRENT_SIZE;
			if (num_entries_u64 > U32_MAX) {
				pr_err("daxfs: dir inode %u has too many entries\n", i + 1);
				return -EINVAL;
			}
			num_entries = (u32)num_entries_u64;

			if (check_add_overflow_u64(base_offset, file_data_offset,
						   &dirent_offset)) {
				pr_err("daxfs: dir inode %u offset overflow\n", i + 1);
				return -EINVAL;
			}

			dirents = daxfs_mem_ptr(info, dirent_offset);

			for (j = 0; j < num_entries; j++) {
				struct daxfs_dirent *de = &dirents[j];
				u32 child_ino = le32_to_cpu(de->ino);
				u16 name_len = le16_to_cpu(de->name_len);

				if (child_ino < 1 || child_ino > inode_count) {
					pr_err("daxfs: dir %u entry %u has invalid ino\n",
					       i + 1, j);
					return -EINVAL;
				}

				if (name_len == 0 || name_len > DAXFS_NAME_MAX) {
					pr_err("daxfs: dir %u entry %u has invalid name length\n",
					       i + 1, j);
					return -EINVAL;
				}

				/* Reject path separators and "."/"..". */
				if (memchr(de->name, '/', name_len) ||
				    (name_len == 1 && de->name[0] == '.') ||
				    (name_len == 2 && de->name[0] == '.' &&
				     de->name[1] == '.')) {
					pr_err("daxfs: dir %u entry %u has unsafe name\n",
					       i + 1, j);
					return -EINVAL;
				}
			}
		}
	}

	return 0;
}

/*
 * Validate overall image structure bounds
 */
int daxfs_validate_super(struct daxfs_info *info)
{
	u64 base_offset = le64_to_cpu(info->super->base_offset);
	u64 base_size = le64_to_cpu(info->super->base_size);
	u64 overlay_offset = le64_to_cpu(info->super->overlay_offset);
	u64 overlay_size = le64_to_cpu(info->super->overlay_size);
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

	/* Validate overlay region bounds */
	if (overlay_offset != 0) {
		u32 bucket_count = le32_to_cpu(info->super->overlay_bucket_count);

		if (!daxfs_valid_offset(info, overlay_offset, overlay_size)) {
			pr_err("daxfs: overlay region exceeds image bounds\n");
			return -EINVAL;
		}

		if (bucket_count == 0 ||
		    (bucket_count & (bucket_count - 1)) != 0) {
			pr_err("daxfs: overlay bucket_count %u not power of 2\n",
			       bucket_count);
			return -EINVAL;
		}

		{
			u64 bucket_array_size = ALIGN(
				(u64)bucket_count *
				sizeof(struct daxfs_overlay_bucket),
				info->block_size);
			u64 min_size = info->block_size + bucket_array_size;

			if (overlay_size < min_size) {
				pr_err("daxfs: overlay region too small (%llu < %llu)\n",
				       overlay_size, min_size);
				return -EINVAL;
			}
		}
	}

	/* Validate page cache region bounds */
	if (pcache_offset != 0) {
		u32 slot_count = le32_to_cpu(info->super->pcache_slot_count);

		if (!daxfs_valid_offset(info, pcache_offset, pcache_size)) {
			pr_err("daxfs: pcache region exceeds image bounds\n");
			return -EINVAL;
		}

		if (slot_count == 0 || (slot_count & (slot_count - 1)) != 0) {
			pr_err("daxfs: pcache slot_count %u not power of 2\n",
			       slot_count);
			return -EINVAL;
		}

		if (slot_count < PCACHE_PROBE_LEN) {
			pr_err("daxfs: pcache slot_count %u < probe length %u\n",
			       slot_count, PCACHE_PROBE_LEN);
			return -EINVAL;
		}

		{
			u64 meta_size = ALIGN((u64)slot_count * sizeof(struct daxfs_pcache_slot),
					      info->block_size);
			u64 data_size = (u64)slot_count * info->block_size;
			u64 min_size = info->block_size + meta_size + data_size;

			if (pcache_size < min_size) {
				pr_err("daxfs: pcache region too small (%llu < %llu)\n",
				       pcache_size, min_size);
				return -EINVAL;
			}
		}
	}

	/* Validate regions don't overlap */
	if (base_size > 0 && regions_overlap(0, super_size, base_offset, base_size)) {
		pr_err("daxfs: base image overlaps superblock\n");
		return -EINVAL;
	}

	if (overlay_size > 0 && regions_overlap(0, super_size,
						overlay_offset, overlay_size)) {
		pr_err("daxfs: overlay overlaps superblock\n");
		return -EINVAL;
	}

	if (pcache_size > 0 && regions_overlap(0, super_size,
					       pcache_offset, pcache_size)) {
		pr_err("daxfs: pcache region overlaps superblock\n");
		return -EINVAL;
	}

	if (base_size > 0 && overlay_size > 0 &&
	    regions_overlap(base_offset, base_size,
			    overlay_offset, overlay_size)) {
		pr_err("daxfs: base image overlaps overlay\n");
		return -EINVAL;
	}

	if (base_size > 0 && pcache_size > 0 &&
	    regions_overlap(base_offset, base_size,
			    pcache_offset, pcache_size)) {
		pr_err("daxfs: base image overlaps pcache region\n");
		return -EINVAL;
	}

	if (overlay_size > 0 && pcache_size > 0 &&
	    regions_overlap(overlay_offset, overlay_size,
			    pcache_offset, pcache_size)) {
		pr_err("daxfs: overlay overlaps pcache region\n");
		return -EINVAL;
	}

	return 0;
}
