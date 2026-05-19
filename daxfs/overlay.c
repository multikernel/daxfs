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
 * Validate a pool offset is within the pool region.
 * Returns pointer, or NULL if out of bounds.
 */
static void *overlay_pool_ptr(struct daxfs_overlay *ovl, u64 pool_off,
			      size_t entry_size)
{
	u64 pool_size = le64_to_cpu(ovl->header->pool_size);

	if (pool_off >= pool_size || entry_size > pool_size - pool_off)
		return NULL;
	return ovl->pool + pool_off;
}

/*
 * Lookup a key in the hash table.
 * Returns pointer to pool entry, or NULL if not found.
 *
 * The smp_rmb() after matching a key pairs with the smp_wmb() in
 * overlay_insert() that precedes the CAS publishing the key.
 * This ensures we see the value that was written before the key
 * became visible.
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
			u64 pool_off;

			smp_rmb(); /* Pair with smp_wmb() in overlay_insert */
			pool_off = le64_to_cpu(READ_ONCE(b->value));
			return overlay_pool_ptr(ovl, pool_off, 1);
		}
	}

	return NULL;	/* Table full, not found */
}

/*
 * Insert a key into the hash table.
 * CAS FREE→USED on the first empty bucket in the probe chain.
 *
 * If old_value is non-NULL and the key already exists, the previous
 * pool offset is written there so the caller can recycle it.
 *
 * If replace is true and key exists, CAS-update the value field
 * (atomically capturing old value). If replace is false and key
 * exists, leave the value untouched and return -EEXIST.
 *
 * Returns 0 on success, -ENOSPC if table full, -EEXIST if key
 * exists and replace is false.
 */
static int overlay_insert(struct daxfs_overlay *ovl, u64 key, u64 pool_offset,
			  u64 *old_value, bool replace)
{
	u32 idx = (u32)(key & ovl->bucket_mask);
	u32 i;

	if (old_value)
		*old_value = (u64)-1;

	for (i = 0; i < ovl->bucket_count; i++) {
		u32 probe = (idx + i) & ovl->bucket_mask;
		struct daxfs_overlay_bucket *b = &ovl->buckets[probe];
		u64 sk = bucket_read(b);

		if (DAXFS_OVL_STATE(sk) == DAXFS_OVL_FREE) {
			u64 new_sk = DAXFS_OVL_MAKE(DAXFS_OVL_USED, key);
			u64 old;

			/*
			 * Write value BEFORE publishing the key via CAS.
			 * This is safe on a FREE bucket: no reader ever
			 * examines the value of a FREE slot. If our CAS
			 * fails (another CPU claimed this slot), the
			 * spurious value write is harmless — the winner
			 * will overwrite it with their own value before
			 * their CAS, and readers only access value after
			 * seeing USED state with a matching key.
			 *
			 * The smp_wmb() ensures the value store is visible
			 * to all CPUs before the CAS publishes the key.
			 * Paired with smp_rmb() in overlay_lookup().
			 */
			WRITE_ONCE(b->value, cpu_to_le64(pool_offset));
			smp_wmb();

			old = bucket_cmpxchg(b, sk, new_sk);
			if (old != sk) {
				/* Raced — re-check this slot */
				i--;
				continue;
			}
			return 0;
		}

		if (DAXFS_OVL_KEY(sk) == key) {
			u64 cur_val;

			smp_rmb();
			cur_val = le64_to_cpu(READ_ONCE(b->value));

			if (!replace) {
				if (old_value)
					*old_value = cur_val;
				return -EEXIST;
			}

			/* CAS-update value to avoid double-free races */
			while (cmpxchg((u64 *)&b->value,
				       cpu_to_le64(cur_val),
				       cpu_to_le64(pool_offset)) !=
			       cpu_to_le64(cur_val)) {
				cur_val = le64_to_cpu(READ_ONCE(b->value));
			}

			if (old_value)
				*old_value = cur_val;
			smp_wmb();
			return 0;
		}
	}

	return -ENOSPC;
}

/*
 * ============================================================================
 * Pool allocator with free list recycling
 *
 * Each entry type has a per-class free list (CAS-based stack) in the
 * overlay header. Freed entries reuse their first 8 bytes as a
 * next-free pointer. Allocation tries the free list before falling
 * back to the bump allocator.
 * ============================================================================
 */

/*
 * Get the free list head pointer for a given entry type.
 */
static __le64 *overlay_free_head(struct daxfs_overlay *ovl, u32 type)
{
	switch (type) {
	case DAXFS_OVL_INODE:
		return &ovl->header->free_inode;
	case DAXFS_OVL_DATA:
		return &ovl->header->free_data;
	case DAXFS_OVL_DIRENT:
		return &ovl->header->free_dirent;
	default:
		return NULL;
	}
}

/*
 * Tagged free list head: upper 16 bits = generation counter, lower 48
 * bits = pool offset. The generation counter prevents ABA races where
 * a thread reads (offset, next), gets preempted while other threads
 * pop and push the same offset back, then wakes and succeeds a stale
 * CAS. With the generation tag, the CAS fails because the generation
 * changed even though the offset didn't.
 *
 * DAXFS_OVL_FREE_END ((u64)-1) has all bits set, which means
 * offset = 0xFFFFFFFFFFFF and gen = 0xFFFF — a valid "empty" state.
 * No valid pool offset can equal 0xFFFFFFFFFFFF since pool sizes are
 * bounded well below 2^48.
 *
 * Link pointers within freed entries remain plain pool offsets (no tag)
 * since only the head is CAS'd.
 */
#define FREELIST_OFF_MASK	0x0000FFFFFFFFFFFFULL
#define FREELIST_GEN_INC	0x0001000000000000ULL

static inline u64 freelist_offset(u64 tagged)
{
	return tagged & FREELIST_OFF_MASK;
}

static inline bool freelist_is_end(u64 tagged)
{
	return freelist_offset(tagged) ==
	       (DAXFS_OVL_FREE_END & FREELIST_OFF_MASK);
}

static inline u64 freelist_make(u64 offset, u64 old_tagged)
{
	return (offset & FREELIST_OFF_MASK) |
	       ((old_tagged + FREELIST_GEN_INC) & ~FREELIST_OFF_MASK);
}

/*
 * Push a freed entry onto the per-type free list (CAS-based stack push).
 * The first 8 bytes of the entry are overwritten with the next pointer.
 */
static void overlay_pool_free(struct daxfs_overlay *ovl, u64 pool_off, u32 type)
{
	__le64 *head = overlay_free_head(ovl, type);
	__le64 *link = (__le64 *)(ovl->pool + pool_off);
	u64 old_tagged, new_tagged;

	if (!head)
		return;

	do {
		old_tagged = le64_to_cpu(READ_ONCE(*head));
		/* Store raw offset in link (not tagged) */
		if (freelist_is_end(old_tagged))
			WRITE_ONCE(*link, cpu_to_le64(DAXFS_OVL_FREE_END));
		else
			WRITE_ONCE(*link, cpu_to_le64(
				freelist_offset(old_tagged)));
		smp_wmb();
		new_tagged = freelist_make(pool_off, old_tagged);
	} while (cmpxchg((u64 *)head,
			 cpu_to_le64(old_tagged),
			 cpu_to_le64(new_tagged)) !=
		 cpu_to_le64(old_tagged));
}

/*
 * Try to pop an entry from the per-type free list (CAS-based stack pop).
 * Returns pool-relative offset, or (u64)-1 if list is empty.
 */
static u64 overlay_pool_alloc_free(struct daxfs_overlay *ovl, u32 type)
{
	__le64 *head = overlay_free_head(ovl, type);
	u64 old_tagged, new_tagged, off, next_raw;

	if (!head)
		return (u64)-1;

	do {
		old_tagged = le64_to_cpu(READ_ONCE(*head));
		if (freelist_is_end(old_tagged))
			return (u64)-1;

		off = freelist_offset(old_tagged);
		smp_rmb();
		/* Link stores raw offset */
		next_raw = le64_to_cpu(READ_ONCE(
			*((__le64 *)(ovl->pool + off))));
		new_tagged = freelist_make(next_raw, old_tagged);
	} while (cmpxchg((u64 *)head,
			 cpu_to_le64(old_tagged),
			 cpu_to_le64(new_tagged)) !=
		 cpu_to_le64(old_tagged));

	return off;
}

/*
 * Bump-allocate space from the pool.
 * Returns pool-relative offset, or (u64)-1 if out of space.
 *
 * @align: minimum alignment (8 for metadata, PAGE_SIZE for data pages).
 *         Data pages must be page-aligned for DAX mmap PFN mapping.
 */
static u64 overlay_pool_bump(struct daxfs_overlay *ovl, size_t size,
			     size_t align)
{
	struct daxfs_overlay_header *hdr = ovl->header;
	u64 pool_size = le64_to_cpu(hdr->pool_size);
	u64 old_alloc, new_alloc, aligned_off;

	size = ALIGN(size, 8);

	do {
		old_alloc = le64_to_cpu(READ_ONCE(hdr->pool_alloc));
		aligned_off = ALIGN(old_alloc, align);
		new_alloc = aligned_off + size;
		if (new_alloc > pool_size)
			return (u64)-1;
	} while (cmpxchg((u64 *)&hdr->pool_alloc,
			 cpu_to_le64(old_alloc),
			 cpu_to_le64(new_alloc)) != cpu_to_le64(old_alloc));

	return aligned_off;
}

/*
 * Allocate a pool entry: try recycled free list first, then bump.
 * Data pages use PAGE_SIZE alignment for DAX mmap support.
 */
static u64 overlay_pool_alloc(struct daxfs_overlay *ovl, size_t size, u32 type)
{
	u64 off;

	off = overlay_pool_alloc_free(ovl, type);
	if (off != (u64)-1)
		return off;

	return overlay_pool_bump(ovl, size,
				 type == DAXFS_OVL_DATA ? PAGE_SIZE : 8);
}

/*
 * Batch bump-allocate N data pages from the pool.
 * Returns the base pool offset (first page), or (u64)-1 if out of space.
 * Pages are PAGE_SIZE-aligned and contiguous.
 */
static u64 overlay_pool_bump_batch(struct daxfs_overlay *ovl,
				   size_t entry_size, u32 count)
{
	struct daxfs_overlay_header *hdr = ovl->header;
	u64 pool_size = le64_to_cpu(hdr->pool_size);
	size_t total = entry_size * count;
	u64 old_alloc, new_alloc, aligned_off;

	do {
		old_alloc = le64_to_cpu(READ_ONCE(hdr->pool_alloc));
		aligned_off = ALIGN(old_alloc, PAGE_SIZE);
		new_alloc = aligned_off + total;
		if (new_alloc > pool_size)
			return (u64)-1;
	} while (cmpxchg((u64 *)&hdr->pool_alloc,
			 cpu_to_le64(old_alloc),
			 cpu_to_le64(new_alloc)) != cpu_to_le64(old_alloc));

	return aligned_off;
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
	if (le32_to_cpu(hdr->version) != DAXFS_OVERLAY_VERSION) {
		pr_err("daxfs: unsupported overlay version %u (expected %u)\n",
		       le32_to_cpu(hdr->version), DAXFS_OVERLAY_VERSION);
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
 *
 * Always allocates a new pool entry and uses overlay_insert() which
 * atomically handles the "key already exists" case via CAS. This avoids
 * a TOCTOU race where two hosts both see the key as absent, both
 * allocate, and one silently overwrites the other's in-place update.
 *
 * When an existing inode is replaced, the old pool entry is recycled
 * onto the inode free list for reuse.
 */
int daxfs_overlay_set_inode(struct daxfs_info *info, u64 ino,
			    const struct daxfs_ovl_inode_entry *ie)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key = DAXFS_OVL_KEY_INODE(ino);
	u64 pool_off, old_off;
	struct daxfs_ovl_inode_entry *dst;
	int ret;

	if (!ovl)
		return -EROFS;

	pool_off = overlay_pool_alloc(ovl, sizeof(*ie), DAXFS_OVL_INODE);
	if (pool_off == (u64)-1)
		return -ENOSPC;

	dst = ovl->pool + pool_off;
	*dst = *ie;
	smp_wmb();

	ret = overlay_insert(ovl, key, pool_off, &old_off, true);
	if (ret)
		return ret;

	/* Recycle the old entry if we replaced one */
	if (old_off != (u64)-1 && old_off != pool_off)
		overlay_pool_free(ovl, old_off, DAXFS_OVL_INODE);

	return 0;
}

/*
 * Get a data page from overlay.
 * Returns pointer to block_size data, or NULL if not found.
 */
void *daxfs_overlay_get_page(struct daxfs_info *info, u64 ino, u64 pgoff)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;

	if (!ovl)
		return NULL;

	if (pgoff > DAXFS_OVL_MAX_PGOFF)
		return NULL;

	key = DAXFS_OVL_KEY_DATA(ino, pgoff);
	return overlay_lookup(ovl, info, key);
}

/*
 * Allocate a new data page from the pool WITHOUT publishing it
 * to the hash table. The caller must initialise the data and
 * then call daxfs_overlay_publish_page() to make it visible.
 *
 * Data pages are raw block_size allocations (no header), so
 * consecutive bump-allocated pages are contiguous in memory.
 *
 * Returns pointer to block_size data area, or NULL on failure.
 * On success, *pool_off_out receives the pool offset (needed for publish).
 */
void *daxfs_overlay_alloc_page(struct daxfs_info *info, u64 ino, u64 pgoff,
			       u64 *pool_off_out)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 pool_off;

	if (!ovl)
		return NULL;

	if (pgoff > DAXFS_OVL_MAX_PGOFF)
		return NULL;

	pool_off = overlay_pool_alloc(ovl, info->block_size,
				      DAXFS_OVL_DATA);
	if (pool_off == (u64)-1)
		return NULL;

	*pool_off_out = pool_off;
	return ovl->pool + pool_off;
}

/*
 * Publish a previously allocated data page to the hash table.
 *
 * Must be called AFTER the page data is fully initialised so that
 * other hosts never see uninitialised data.
 *
 * If another host already published this (ino, pgoff), recycles our
 * entry and returns the existing page.  Otherwise returns @page.
 * Returns NULL only on hash-table-full.
 */
void *daxfs_overlay_publish_page(struct daxfs_info *info, u64 ino,
				 u64 pgoff, u64 pool_off, void *page)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key = DAXFS_OVL_KEY_DATA(ino, pgoff);
	int ret;

	/* Ensure page data is globally visible before publishing key */
	smp_wmb();

	ret = overlay_insert(ovl, key, pool_off, NULL, false);
	if (ret == -EEXIST) {
		overlay_pool_free(ovl, pool_off, DAXFS_OVL_DATA);
		return overlay_lookup(ovl, info, key);
	}
	if (ret)
		return NULL;

	return page;
}

/*
 * Batch-allocate N data pages from the pool for consecutive pgoffs,
 * WITHOUT publishing to the hash table.
 *
 * Uses a single atomic bump for all N pages. Since data pages are
 * raw PAGE_SIZE allocations (no header), the resulting pages are
 * contiguous in memory, enabling large sequential reads later.
 *
 * pages[i] receives the data pointer; pool_offs[i] the pool offset.
 * Returns the number of successfully reserved entries.
 */
int daxfs_overlay_alloc_pages_batch(struct daxfs_info *info, u64 ino,
				    u64 start_pgoff, u32 count,
				    void **pages, u64 *pool_offs)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 base_pool_off;
	u32 i, ok = 0;

	if (!ovl || count == 0)
		return 0;

	base_pool_off = overlay_pool_bump_batch(ovl, info->block_size,
						count);
	if (base_pool_off == (u64)-1)
		return 0;

	for (i = 0; i < count; i++) {
		u64 pgoff = start_pgoff + i;
		u64 pool_off = base_pool_off + info->block_size * i;

		if (pgoff > DAXFS_OVL_MAX_PGOFF) {
			pages[i] = NULL;
			pool_offs[i] = (u64)-1;
			continue;
		}

		pages[i] = ovl->pool + pool_off;
		pool_offs[i] = pool_off;
		ok++;
	}

	return ok;
}

/*
 * Check if a dirent pool entry matches the given parent_ino + name.
 */
static bool dirent_matches(struct daxfs_ovl_dirent_entry *de,
			   u64 parent_ino, const char *name, u16 name_len)
{
	return le64_to_cpu(de->parent_ino) == parent_ino &&
	       le16_to_cpu(de->name_len) == name_len &&
	       memcmp(de->name, name, name_len) == 0;
}

/*
 * Walk the dirent hash collision chain starting from the head pool entry.
 * Returns the exact-matching entry, or NULL if not found.
 */
static struct daxfs_ovl_dirent_entry *dirent_chain_walk(
	struct daxfs_overlay *ovl, struct daxfs_ovl_dirent_entry *head,
	u64 parent_ino, const char *name, u16 name_len)
{
	struct daxfs_ovl_dirent_entry *de = head;
	int limit = 1024; /* Guard against corrupt chains */

	while (de && limit-- > 0) {
		if (dirent_matches(de, parent_ino, name, name_len))
			return de;

		if (le64_to_cpu(de->next) == DAXFS_OVL_NO_NEXT)
			return NULL;

		smp_rmb(); /* Ensure we see the full next entry */
		de = overlay_pool_ptr(ovl, le64_to_cpu(de->next),
				      sizeof(*de));
	}

	return NULL;
}

/*
 * Append a new dirent entry to the end of a collision chain.
 * Uses CAS on each entry's 'next' field to handle concurrent appends.
 * Returns 0 on success.
 */
static int dirent_chain_append(struct daxfs_overlay *ovl,
			       struct daxfs_ovl_dirent_entry *head,
			       u64 new_pool_off)
{
	struct daxfs_ovl_dirent_entry *de = head;
	int limit = 1024;

	while (limit-- > 0) {
		u64 next = le64_to_cpu(READ_ONCE(de->next));

		if (next == DAXFS_OVL_NO_NEXT) {
			u64 old;

			old = cmpxchg((u64 *)&de->next,
				      cpu_to_le64(DAXFS_OVL_NO_NEXT),
				      cpu_to_le64(new_pool_off));
			if (old == cpu_to_le64(DAXFS_OVL_NO_NEXT)) {
				smp_wmb();
				return 0;
			}
			/* Raced — another host appended; re-read */
			continue;
		}

		smp_rmb();
		de = overlay_pool_ptr(ovl, next, sizeof(*de));
		if (!de)
			return -EIO;
	}

	return -ELOOP;
}

/*
 * Lookup a directory entry in overlay, walking the collision chain.
 */
struct daxfs_ovl_dirent_entry *daxfs_overlay_lookup_dirent(
	struct daxfs_info *info, u64 parent_ino,
	const char *name, u16 name_len)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	struct daxfs_ovl_dirent_entry *head;

	if (!ovl)
		return NULL;

	key = fnv1a_hash(parent_ino, name, name_len);
	head = overlay_lookup(ovl, info, key);
	if (!head)
		return NULL;

	return dirent_chain_walk(ovl, head, parent_ino, name, name_len);
}

/*
 * Initialize a new dirent pool entry.
 */
static void dirent_init(struct daxfs_ovl_dirent_entry *de,
			u64 parent_ino, u64 child_ino, u32 child_mode,
			const char *name, u16 name_len, u32 flags)
{
	de->type = cpu_to_le32(DAXFS_OVL_DIRENT);
	de->flags = cpu_to_le32(flags);
	de->parent_ino = cpu_to_le64(parent_ino);
	de->child_ino = cpu_to_le64(child_ino);
	de->child_mode = cpu_to_le32(child_mode);
	de->name_len = cpu_to_le16(name_len);
	memset(de->reserved, 0, sizeof(de->reserved));
	de->next = cpu_to_le64(DAXFS_OVL_NO_NEXT);
	de->dir_next = cpu_to_le64(DAXFS_OVL_NO_NEXT);
	memcpy(de->name, name, name_len);
	de->name[name_len] = '\0';
	smp_wmb();
}

/*
 * ============================================================================
 * Per-directory dirent list (for O(n) readdir)
 * ============================================================================
 */

/*
 * Get or create the DIRLIST head entry for a directory.
 * Returns pointer to the dirlist entry, or NULL on failure.
 */
static struct daxfs_ovl_dirlist_entry *overlay_get_dirlist(
	struct daxfs_overlay *ovl, struct daxfs_info *info, u64 parent_ino)
{
	u64 key = DAXFS_OVL_KEY_DIRLIST(parent_ino);
	struct daxfs_ovl_dirlist_entry *dl;

	dl = overlay_lookup(ovl, info, key);
	if (dl)
		return dl;

	/* Create a new dirlist head */
	{
		u64 pool_off;
		int ret;

		pool_off = overlay_pool_alloc(ovl,
			sizeof(struct daxfs_ovl_dirlist_entry),
			DAXFS_OVL_DIRLIST);
		if (pool_off == (u64)-1)
			return NULL;

		dl = ovl->pool + pool_off;
		dl->type = cpu_to_le32(DAXFS_OVL_DIRLIST);
		dl->reserved = 0;
		dl->first = cpu_to_le64(DAXFS_OVL_NO_NEXT);
		smp_wmb();

		ret = overlay_insert(ovl, key, pool_off, NULL, false);
		if (ret == -EEXIST) {
			/*
			 * Another host created it concurrently.
			 * Use theirs — our empty entry is harmlessly leaked
			 * (no free list for DIRLIST type).
			 */
			dl = overlay_lookup(ovl, info, key);
		} else if (ret != 0) {
			return NULL;
		}
	}
	return dl;
}

/*
 * CAS-prepend a dirent (at pool_off) to the directory's dirent list.
 */
static void overlay_dirlist_prepend(struct daxfs_overlay *ovl,
				    struct daxfs_info *info,
				    u64 parent_ino, u64 dirent_pool_off)
{
	struct daxfs_ovl_dirlist_entry *dl;
	struct daxfs_ovl_dirent_entry *de;
	u64 old_first;

	dl = overlay_get_dirlist(ovl, info, parent_ino);
	if (!dl)
		return; /* Best-effort; readdir falls back to bucket scan */

	de = ovl->pool + dirent_pool_off;

	do {
		old_first = le64_to_cpu(READ_ONCE(dl->first));
		WRITE_ONCE(de->dir_next, cpu_to_le64(old_first));
		smp_wmb();
	} while (cmpxchg((u64 *)&dl->first,
			 cpu_to_le64(old_first),
			 cpu_to_le64(dirent_pool_off)) !=
		 cpu_to_le64(old_first));
}

/*
 * Create a directory entry in overlay.
 *
 * Handles hash collisions: if the key already exists in the hash table
 * but belongs to a different dirent, the new entry is appended to the
 * collision chain in the pool rather than overwriting the bucket value.
 */
int daxfs_overlay_create_dirent(struct daxfs_info *info,
				u64 parent_ino, u64 child_ino,
				u32 child_mode,
				const char *name, u16 name_len)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	u64 pool_off;
	struct daxfs_ovl_dirent_entry *de, *head;
	int ret;

	if (!ovl)
		return -EROFS;

	key = fnv1a_hash(parent_ino, name, name_len);

	/* Check if key already exists in hash table */
	head = overlay_lookup(ovl, info, key);
	if (head) {
		/* Walk chain for exact match (possibly tombstoned) */
		de = dirent_chain_walk(ovl, head, parent_ino, name, name_len);
		if (de) {
			/* Reuse existing entry (e.g., un-delete) —
			 * already on the dir list, just clear tombstone */
			WRITE_ONCE(de->child_ino, cpu_to_le64(child_ino));
			WRITE_ONCE(de->child_mode, cpu_to_le32(child_mode));
			smp_wmb();
			WRITE_ONCE(de->flags, 0);
			return 0;
		}

		/*
		 * Hash collision: key exists but belongs to a different
		 * dirent. Allocate new entry and append to chain.
		 */
		pool_off = overlay_pool_alloc(ovl, sizeof(*de),
					      DAXFS_OVL_DIRENT);
		if (pool_off == (u64)-1)
			return -ENOSPC;

		de = ovl->pool + pool_off;
		dirent_init(de, parent_ino, child_ino, child_mode,
			    name, name_len, 0);

		ret = dirent_chain_append(ovl, head, pool_off);
		if (ret == 0)
			overlay_dirlist_prepend(ovl, info, parent_ino,
						pool_off);
		return ret;
	}

	/* Key doesn't exist — allocate and insert as new bucket entry */
	pool_off = overlay_pool_alloc(ovl, sizeof(*de), DAXFS_OVL_DIRENT);
	if (pool_off == (u64)-1)
		return -ENOSPC;

	de = ovl->pool + pool_off;
	dirent_init(de, parent_ino, child_ino, child_mode,
		    name, name_len, 0);

	ret = overlay_insert(ovl, key, pool_off, NULL, false);
	if (ret == -ENOSPC)
		return ret;
	if (ret == -EEXIST) {
		/*
		 * Another host inserted the same key concurrently.
		 * Append to their chain instead of overwriting.
		 */
		head = overlay_lookup(ovl, info, key);
		if (head)
			ret = dirent_chain_append(ovl, head, pool_off);
		else
			ret = -EIO; /* Shouldn't happen */
	}

	if (ret == 0)
		overlay_dirlist_prepend(ovl, info, parent_ino, pool_off);

	return ret;
}

/*
 * Delete a directory entry (insert tombstone).
 *
 * Walks the collision chain to find the exact entry. If the entry
 * doesn't exist in overlay (base image entry), creates a tombstone
 * and inserts/appends it.
 */
int daxfs_overlay_delete_dirent(struct daxfs_info *info,
				u64 parent_ino,
				const char *name, u16 name_len)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	struct daxfs_ovl_dirent_entry *de, *head;
	u64 pool_off;
	int ret;

	if (!ovl)
		return -EROFS;

	key = fnv1a_hash(parent_ino, name, name_len);

	/* Check if dirent exists in overlay (walking chain) */
	head = overlay_lookup(ovl, info, key);
	if (head) {
		de = dirent_chain_walk(ovl, head, parent_ino, name, name_len);
		if (de) {
			/* Mark as tombstone */
			WRITE_ONCE(de->flags,
				   cpu_to_le32(DAXFS_OVL_DIRENT_TOMBSTONE));
			smp_wmb();
			return 0;
		}
	}

	/*
	 * Entry not in overlay — it's a base image entry.
	 * Create a tombstone in overlay.
	 */
	pool_off = overlay_pool_alloc(ovl, sizeof(*de), DAXFS_OVL_DIRENT);
	if (pool_off == (u64)-1)
		return -ENOSPC;

	de = ovl->pool + pool_off;
	dirent_init(de, parent_ino, 0, 0, name, name_len,
		    DAXFS_OVL_DIRENT_TOMBSTONE);

	if (head) {
		/* Key exists (hash collision) — append to chain */
		ret = dirent_chain_append(ovl, head, pool_off);
	} else {
		ret = overlay_insert(ovl, key, pool_off, NULL, false);
		if (ret == -ENOSPC)
			return ret;
		if (ret == -EEXIST) {
			/* Concurrent insert — append to their chain */
			head = overlay_lookup(ovl, info, key);
			if (head)
				ret = dirent_chain_append(ovl, head, pool_off);
			else
				ret = -EIO;
		}
	}

	if (ret == 0)
		overlay_dirlist_prepend(ovl, info, parent_ino, pool_off);

	return ret;
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
 * Try to emit a single dirent entry for readdir.
 * Returns false if dir_emit() signals buffer full (caller should stop).
 */
static bool overlay_emit_dirent(struct daxfs_ovl_dirent_entry *de,
				u64 parent_ino, struct dir_context *ctx,
				loff_t *pos)
{
	u32 mode;
	u64 ino;
	u16 name_len;
	unsigned char dtype;

	/* Only entries in this directory */
	if (le64_to_cpu(de->parent_ino) != parent_ino)
		return true;

	/* Skip tombstones */
	if (le32_to_cpu(de->flags) & DAXFS_OVL_DIRENT_TOMBSTONE)
		return true;

	if (*pos >= ctx->pos) {
		mode = le32_to_cpu(de->child_mode);
		ino = le64_to_cpu(de->child_ino);
		name_len = le16_to_cpu(de->name_len);

		switch (mode & S_IFMT) {
		case S_IFREG: dtype = DT_REG; break;
		case S_IFDIR: dtype = DT_DIR; break;
		case S_IFLNK: dtype = DT_LNK; break;
		default: dtype = DT_UNKNOWN; break;
		}

		if (!dir_emit(ctx, de->name, name_len, ino, dtype))
			return false;
		ctx->pos = *pos + 1;
	}
	(*pos)++;
	return true;
}

/*
 * Check if a directory has any non-tombstone overlay entries.
 * Returns true if at least one live entry exists.
 */
bool daxfs_overlay_dir_has_entries(struct daxfs_info *info, u64 parent_ino)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	struct daxfs_ovl_dirlist_entry *dl;
	u64 off;
	int limit = 1 << 20;

	if (!ovl)
		return false;

	key = DAXFS_OVL_KEY_DIRLIST(parent_ino);
	dl = overlay_lookup(ovl, info, key);
	if (!dl)
		return false;

	off = le64_to_cpu(READ_ONCE(dl->first));

	while (off != DAXFS_OVL_NO_NEXT && limit-- > 0) {
		struct daxfs_ovl_dirent_entry *de;

		smp_rmb();
		de = overlay_pool_ptr(ovl, off, sizeof(*de));
		if (!de)
			return false;

		if (le64_to_cpu(de->parent_ino) == parent_ino &&
		    !(le32_to_cpu(de->flags) & DAXFS_OVL_DIRENT_TOMBSTONE))
			return true;

		off = le64_to_cpu(READ_ONCE(de->dir_next));
	}

	return false;
}

/*
 * Iterate overlay directory entries for readdir.
 *
 * Uses the per-directory dirent list (DIRLIST → dir_next chain) for
 * O(entries) iteration instead of scanning all hash buckets.
 */
int daxfs_overlay_iterate_dir(struct daxfs_info *info,
			      u64 parent_ino,
			      struct dir_context *ctx,
			      loff_t *pos)
{
	struct daxfs_overlay *ovl = info->overlay;
	u64 key;
	struct daxfs_ovl_dirlist_entry *dl;
	u64 off;
	int limit = 1 << 20; /* Guard against corrupt chains */

	if (!ovl)
		return 0;

	key = DAXFS_OVL_KEY_DIRLIST(parent_ino);
	dl = overlay_lookup(ovl, info, key);
	if (!dl)
		return 0; /* No overlay entries for this directory */

	off = le64_to_cpu(READ_ONCE(dl->first));

	while (off != DAXFS_OVL_NO_NEXT && limit-- > 0) {
		struct daxfs_ovl_dirent_entry *de;

		smp_rmb();
		de = overlay_pool_ptr(ovl, off, sizeof(*de));
		if (!de)
			return -EIO;

		if (!overlay_emit_dirent(de, parent_ino, ctx, pos))
			return 0;

		off = le64_to_cpu(READ_ONCE(de->dir_next));
	}

	return 0;
}
