// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs hash overlay — CAS-based lock-free writes on DAX memory
 *
 * Open-addressing hash table with linear probing. All mutations use
 * cmpxchg on the bucket's state_key field so multiple kernels can
 * write concurrently without locks.
 *
 * Pool entries are bump-allocated from a contiguous region after
 * the bucket array. The allocator is a single atomic fetch-and-add
 * on the pool_alloc field in the on-DAX header.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include "daxfs.h"

/*
 * ============================================================================
 * Hash helpers
 * ============================================================================
 */

/* FNV-1a 64-bit hash for dirent keys */
static u64 fnv1a_hash(u64 parent_ino, const char *name, u16 name_len)
{
	u64 hash = 0xcbf29ce484222325ULL;
	const u8 *p;
	int i;

	/* Mix in parent_ino */
	for (i = 0; i < 8; i++) {
		hash ^= (parent_ino >> (i * 8)) & 0xFF;
		hash *= 0x100000001b3ULL;
	}

	/* Mix in name */
	p = (const u8 *)name;
	for (i = 0; i < name_len; i++) {
		hash ^= p[i];
		hash *= 0x100000001b3ULL;
	}

	/* Return 63-bit key (bit 0 is reserved for state) */
	return hash >> 1;
}

/*
 * ============================================================================
 * Core CAS operations on the bucket array
 * ============================================================================
 */

static u64 bucket_read(struct daxfs_overlay_bucket *b)
{
	return le64_to_cpu(READ_ONCE(b->state_key));
}

static u64 bucket_cmpxchg(struct daxfs_overlay_bucket *b, u64 old_val,
			   u64 new_val)
{
	return cmpxchg((u64 *)&b->state_key, old_val, new_val);
}

/*
 * Lookup a key in the hash table.
 * Returns pointer to pool entry, or NULL if not found.
 */
static void *overlay_lookup(struct daxfs_overlay *ovl, struct daxfs_info *info,
			    u64 key)
{
	u32 idx = (u32)(key & ovl->bucket_mask);
	u32 i;

	for (i = 0; i < ovl->bucket_count; i++) {
		u32 probe = (idx + i) & ovl->bucket_mask;
		struct daxfs_overlay_bucket *b = &ovl->buckets[probe];
		u64 sk = bucket_read(b);

		if (DAXFS_OVL_STATE(sk) == DAXFS_OVL_FREE)
			return NULL;	/* Empty slot — key doesn't exist */

		if (DAXFS_OVL_KEY(sk) == key) {
			u64 pool_off = le64_to_cpu(READ_ONCE(b->value));
			return ovl->pool + pool_off;
		}
	}

	return NULL;	/* Table full, not found */
}

/*
 * Insert a key into the hash table.
 * CAS FREE→USED on the first empty bucket in the probe chain.
 * Returns 0 on success, -ENOSPC if table full, -EEXIST if key exists.
 */
static int overlay_insert(struct daxfs_overlay *ovl, u64 key, u64 pool_offset)
{
	u32 idx = (u32)(key & ovl->bucket_mask);
	u32 i;

	for (i = 0; i < ovl->bucket_count; i++) {
		u32 probe = (idx + i) & ovl->bucket_mask;
		struct daxfs_overlay_bucket *b = &ovl->buckets[probe];
		u64 sk = bucket_read(b);

		if (DAXFS_OVL_STATE(sk) == DAXFS_OVL_FREE) {
			u64 new_sk = DAXFS_OVL_MAKE(DAXFS_OVL_USED, key);
			u64 old;

			old = bucket_cmpxchg(b, sk, new_sk);
			if (old != sk) {
				/* Raced — re-check this slot */
				i--;
				continue;
			}
			/* Won the CAS — write value */
			WRITE_ONCE(b->value, cpu_to_le64(pool_offset));
			smp_wmb();
			return 0;
		}

		if (DAXFS_OVL_KEY(sk) == key) {
			/* Key already exists — update value */
			WRITE_ONCE(b->value, cpu_to_le64(pool_offset));
			smp_wmb();
			return 0;
		}
	}

	return -ENOSPC;
}

/*
 * Bump-allocate space from the pool.
 * Returns pool-relative offset, or (u64)-1 if out of space.
 */
static u64 overlay_pool_alloc(struct daxfs_overlay *ovl, size_t size)
{
	struct daxfs_overlay_header *hdr = ovl->header;
	u64 pool_size = le64_to_cpu(hdr->pool_size);
	u64 old_alloc, new_alloc;

	/* Align to 8 bytes */
	size = ALIGN(size, 8);

	do {
		old_alloc = le64_to_cpu(READ_ONCE(hdr->pool_alloc));
		new_alloc = old_alloc + size;
		if (new_alloc > pool_size)
			return (u64)-1;
	} while (cmpxchg((u64 *)&hdr->pool_alloc,
			 cpu_to_le64(old_alloc),
			 cpu_to_le64(new_alloc)) != cpu_to_le64(old_alloc));

	return old_alloc;
}

/*
 * ============================================================================
 * Public API
 * ============================================================================
 */

int daxfs_overlay_init(struct daxfs_info *info)
{
	struct daxfs_overlay *ovl;
	u64 ovl_offset = le64_to_cpu(info->super->overlay_offset);
	struct daxfs_overlay_header *hdr;

	if (!ovl_offset)
		return 0;

	ovl = kzalloc(sizeof(*ovl), GFP_KERNEL);
	if (!ovl)
		return -ENOMEM;

	hdr = daxfs_mem_ptr(info, ovl_offset);
	if (le32_to_cpu(hdr->magic) != DAXFS_OVERLAY_MAGIC) {
		pr_err("daxfs: invalid overlay magic 0x%x\n",
		       le32_to_cpu(hdr->magic));
		kfree(ovl);
		return -EINVAL;
	}

	ovl->header = hdr;
	ovl->bucket_count = le32_to_cpu(info->super->overlay_bucket_count);
	ovl->bucket_mask = ovl->bucket_count - 1;
	ovl->buckets = daxfs_mem_ptr(info,
		ovl_offset + le64_to_cpu(hdr->bucket_offset));
	ovl->pool = daxfs_mem_ptr(info,
		ovl_offset + le64_to_cpu(hdr->pool_offset));

	info->overlay = ovl;

	pr_info("daxfs: overlay initialized (%u buckets, %llu pool bytes)\n",
		ovl->bucket_count, le64_to_cpu(hdr->pool_size));
	return 0;
}

void daxfs_overlay_exit(struct daxfs_info *info)
{
	if (!info->overlay)
		return;

	kfree(info->overlay);
	info->overlay = NULL;
}

/*
 * Get overlay inode metadata.
 * Returns pointer to on-DAX inode entry, or NULL if not found.
 */
struct daxfs_ovl_inode_entry *daxfs_overlay_get_inode(struct daxfs_info *info,
						      u64 ino)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;

	if (!ovl)
		return NULL;

	key = DAXFS_OVL_KEY_INODE(ino);
	return overlay_lookup(ovl, info, key);
}

/*
 * Set overlay inode metadata (insert or update).
 */
int daxfs_overlay_set_inode(struct daxfs_info *info, u64 ino,
			    const struct daxfs_ovl_inode_entry *ie)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key = DAXFS_OVL_KEY_INODE(ino);
	struct daxfs_ovl_inode_entry *existing;
	u64 pool_off;
	struct daxfs_ovl_inode_entry *dst;

	if (!ovl)
		return -EROFS;

	/* Check if inode already exists in overlay */
	existing = overlay_lookup(ovl, info, key);
	if (existing) {
		*existing = *ie;
		smp_wmb();
		return 0;
	}

	/* Allocate new pool entry */
	pool_off = overlay_pool_alloc(ovl, sizeof(*ie));
	if (pool_off == (u64)-1)
		return -ENOSPC;

	dst = ovl->pool + pool_off;
	*dst = *ie;
	smp_wmb();

	return overlay_insert(ovl, key, pool_off);
}

/*
 * Get a data page from overlay.
 * Returns pointer to 4KB data, or NULL if not found.
 */
void *daxfs_overlay_get_page(struct daxfs_info *info, u64 ino, u64 pgoff)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	struct daxfs_ovl_data_entry *de;

	if (!ovl)
		return NULL;

	key = DAXFS_OVL_KEY_DATA(ino, pgoff);
	de = overlay_lookup(ovl, info, key);
	if (!de)
		return NULL;

	return de->data;
}

/*
 * Allocate a new data page in overlay.
 * Returns pointer to 4KB data area (zeroed), or NULL on failure.
 */
void *daxfs_overlay_alloc_page(struct daxfs_info *info, u64 ino, u64 pgoff)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key = DAXFS_OVL_KEY_DATA(ino, pgoff);
	u64 pool_off;
	struct daxfs_ovl_data_entry *de;
	int ret;

	if (!ovl)
		return NULL;

	pool_off = overlay_pool_alloc(ovl, sizeof(*de));
	if (pool_off == (u64)-1)
		return NULL;

	de = ovl->pool + pool_off;
	de->type = cpu_to_le32(DAXFS_OVL_DATA);
	de->reserved = 0;
	memset(de->data, 0, PAGE_SIZE);

	ret = overlay_insert(ovl, key, pool_off);
	if (ret)
		return NULL;

	return de->data;
}

/*
 * Lookup a directory entry in overlay.
 */
struct daxfs_ovl_dirent_entry *daxfs_overlay_lookup_dirent(
	struct daxfs_info *info, u64 parent_ino,
	const char *name, u16 name_len)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	struct daxfs_ovl_dirent_entry *de;

	if (!ovl)
		return NULL;

	key = fnv1a_hash(parent_ino, name, name_len);
	de = overlay_lookup(ovl, info, key);
	if (!de)
		return NULL;

	/* Verify exact match (hash collision check) */
	if (le64_to_cpu(de->parent_ino) != parent_ino ||
	    le16_to_cpu(de->name_len) != name_len ||
	    memcmp(de->name, name, name_len) != 0)
		return NULL;

	return de;
}

/*
 * Create a directory entry in overlay.
 */
int daxfs_overlay_create_dirent(struct daxfs_info *info,
				u64 parent_ino, u64 child_ino,
				u32 child_mode,
				const char *name, u16 name_len)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	u64 pool_off;
	struct daxfs_ovl_dirent_entry *de;
	int ret;

	if (!ovl)
		return -EROFS;

	key = fnv1a_hash(parent_ino, name, name_len);

	/* Check if dirent already exists (possibly as tombstone) */
	de = overlay_lookup(ovl, info, key);
	if (de && le64_to_cpu(de->parent_ino) == parent_ino &&
	    le16_to_cpu(de->name_len) == name_len &&
	    memcmp(de->name, name, name_len) == 0) {
		/* Reuse existing entry (e.g., un-delete) */
		de->flags = 0;
		de->child_ino = cpu_to_le64(child_ino);
		de->child_mode = cpu_to_le32(child_mode);
		smp_wmb();
		return 0;
	}

	pool_off = overlay_pool_alloc(ovl, sizeof(*de));
	if (pool_off == (u64)-1)
		return -ENOSPC;

	de = ovl->pool + pool_off;
	de->type = cpu_to_le32(DAXFS_OVL_DIRENT);
	de->flags = 0;
	de->parent_ino = cpu_to_le64(parent_ino);
	de->child_ino = cpu_to_le64(child_ino);
	de->child_mode = cpu_to_le32(child_mode);
	de->name_len = cpu_to_le16(name_len);
	memset(de->reserved, 0, sizeof(de->reserved));
	memcpy(de->name, name, name_len);
	de->name[name_len] = '\0';
	smp_wmb();

	ret = overlay_insert(ovl, key, pool_off);
	return ret;
}

/*
 * Delete a directory entry (insert tombstone).
 */
int daxfs_overlay_delete_dirent(struct daxfs_info *info,
				u64 parent_ino,
				const char *name, u16 name_len)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	struct daxfs_ovl_dirent_entry *de;

	if (!ovl)
		return -EROFS;

	key = fnv1a_hash(parent_ino, name, name_len);

	/* Check if dirent exists in overlay */
	de = overlay_lookup(ovl, info, key);
	if (de && le64_to_cpu(de->parent_ino) == parent_ino &&
	    le16_to_cpu(de->name_len) == name_len &&
	    memcmp(de->name, name, name_len) == 0) {
		/* Mark as tombstone */
		de->flags = cpu_to_le32(DAXFS_OVL_DIRENT_TOMBSTONE);
		smp_wmb();
		return 0;
	}

	/*
	 * Entry not in overlay — it's a base image entry.
	 * Create a tombstone in overlay.
	 */
	{
		u64 pool_off;

		pool_off = overlay_pool_alloc(ovl, sizeof(*de));
		if (pool_off == (u64)-1)
			return -ENOSPC;

		de = ovl->pool + pool_off;
		de->type = cpu_to_le32(DAXFS_OVL_DIRENT);
		de->flags = cpu_to_le32(DAXFS_OVL_DIRENT_TOMBSTONE);
		de->parent_ino = cpu_to_le64(parent_ino);
		de->child_ino = 0;
		de->child_mode = 0;
		de->name_len = cpu_to_le16(name_len);
		memset(de->reserved, 0, sizeof(de->reserved));
		memcpy(de->name, name, name_len);
		de->name[name_len] = '\0';
		smp_wmb();

		return overlay_insert(ovl, key, pool_off);
	}
}

/*
 * Allocate a new inode number (atomic).
 */
u64 daxfs_overlay_alloc_ino(struct daxfs_info *info)
{
	struct daxfs_overlay *ovl = info->overlay;
	struct daxfs_overlay_header *hdr;
	u64 old_ino, new_ino;

	if (!ovl)
		return 0;

	hdr = ovl->header;
	do {
		old_ino = le64_to_cpu(READ_ONCE(hdr->next_ino));
		new_ino = old_ino + 1;
	} while (cmpxchg((u64 *)&hdr->next_ino,
			 cpu_to_le64(old_ino),
			 cpu_to_le64(new_ino)) != cpu_to_le64(old_ino));

	return old_ino;
}

/*
 * Iterate overlay directory entries for readdir.
 * Scans all buckets looking for dirent entries with matching parent_ino.
 * This is O(bucket_count) but readdir is inherently slow.
 */
int daxfs_overlay_iterate_dir(struct daxfs_info *info,
			      u64 parent_ino,
			      struct dir_context *ctx,
			      loff_t *pos)
{
	struct daxfs_overlay *ovl = info->overlay;
	u32 i;

	if (!ovl)
		return 0;

	for (i = 0; i < ovl->bucket_count; i++) {
		struct daxfs_overlay_bucket *b = &ovl->buckets[i];
		u64 sk = bucket_read(b);
		u64 pool_off;
		struct daxfs_ovl_dirent_entry *de;
		unsigned char dtype;

		if (DAXFS_OVL_STATE(sk) != DAXFS_OVL_USED)
			continue;

		pool_off = le64_to_cpu(READ_ONCE(b->value));
		de = ovl->pool + pool_off;

		/* Only dirent entries */
		if (le32_to_cpu(de->type) != DAXFS_OVL_DIRENT)
			continue;

		/* Only entries in this directory */
		if (le64_to_cpu(de->parent_ino) != parent_ino)
			continue;

		/* Skip tombstones */
		if (le32_to_cpu(de->flags) & DAXFS_OVL_DIRENT_TOMBSTONE)
			continue;

		if (*pos >= ctx->pos) {
			u32 mode = le32_to_cpu(de->child_mode);
			u64 ino = le64_to_cpu(de->child_ino);
			u16 name_len = le16_to_cpu(de->name_len);

			switch (mode & S_IFMT) {
			case S_IFREG: dtype = DT_REG; break;
			case S_IFDIR: dtype = DT_DIR; break;
			case S_IFLNK: dtype = DT_LNK; break;
			default: dtype = DT_UNKNOWN; break;
			}

			if (!dir_emit(ctx, de->name, name_len, ino, dtype))
				return 0;
			ctx->pos = *pos + 1;
		}
		(*pos)++;
	}

	return 0;
}
