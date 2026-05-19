// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs shared page cache
 *
 * Demand-paged cache in DAX memory for backing store mode. Because DAX
 * memory is physically shared across kernel instances, the cache is
 * automatically visible to all kernels with no coherency protocol.
 *
 * Multi-file support: tags encode (ino << 20 | pgoff), so each cache
 * slot is associated with a specific file and page offset. Multiple
 * backing files can be registered, each associated with an inode number.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include "daxfs.h"

static u32 pcache_hash(struct daxfs_pcache *pc, u64 tag)
{
	return (u32)(tag & pc->hash_mask);
}

static u64 slot_cmpxchg(struct daxfs_pcache_slot *slot, u64 old_val, u64 new_val)
{
	return cmpxchg((u64 *)&slot->state_tag, old_val, new_val);
}

static u64 slot_read(struct daxfs_pcache_slot *slot)
{
	return le64_to_cpu(READ_ONCE(slot->state_tag));
}

static void pcache_inc_pending(struct daxfs_pcache_header *hdr)
{
	u32 old_val, new_val;

	do {
		old_val = le32_to_cpu(READ_ONCE(hdr->pending_count));
		new_val = old_val + 1;
	} while (cmpxchg((u32 *)&hdr->pending_count,
			 old_val, new_val) != old_val);
}

static void pcache_dec_pending(struct daxfs_pcache_header *hdr)
{
	u32 old_val, new_val;

	do {
		old_val = le32_to_cpu(READ_ONCE(hdr->pending_count));
		if (old_val == 0)
			break;
		new_val = old_val - 1;
	} while (cmpxchg((u32 *)&hdr->pending_count,
			 old_val, new_val) != old_val);
}

/*
 * Find a backing file for the given inode number.
 * O(1) via direct array lookup.
 */
static struct file *pcache_find_backing(struct daxfs_pcache *pc, u64 ino)
{
	if (ino < pc->backing_array_size && pc->backing_array)
		return pc->backing_array[ino];
	return NULL;
}

static int pcache_fill_slot(struct daxfs_pcache *pc, u32 slot_idx, u64 tag)
{
	u64 ino = PCACHE_TAG_INO(tag);
	u64 pgoff = PCACHE_TAG_PGOFF(tag);
	u32 bsize = pc->block_size;
	loff_t pos = (loff_t)pgoff << pc->block_shift;
	void *dst = pc->data + (u64)slot_idx * bsize;
	struct file *backing;
	ssize_t n;
	u64 old_val, new_val;

	backing = pcache_find_backing(pc, ino);
	if (!backing) {
		/* No backing file — revert slot to FREE so it can be reused */
		old_val = PCACHE_MAKE(PCACHE_STATE_PENDING, tag);
		new_val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
		if (slot_cmpxchg(&pc->slots[slot_idx], old_val, new_val) ==
		    old_val)
			pcache_dec_pending(pc->header);
		return -ENOENT;
	}

	n = kernel_read(backing, dst, bsize, &pos);
	if (n < 0) {
		pr_err_ratelimited("daxfs: pcache read error ino=%llu pgoff=%llu: %zd\n",
				   ino, pgoff, n);
		/* Revert to FREE so the slot can be retried later */
		old_val = PCACHE_MAKE(PCACHE_STATE_PENDING, tag);
		new_val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
		if (slot_cmpxchg(&pc->slots[slot_idx], old_val, new_val) ==
		    old_val)
			pcache_dec_pending(pc->header);
		return (int)n;
	}

	if (n < bsize)
		memset(dst + n, 0, bsize - n);

	smp_wmb();

	/* Transition PENDING → VALID */
	old_val = PCACHE_MAKE(PCACHE_STATE_PENDING, tag);
	new_val = PCACHE_MAKE(PCACHE_STATE_VALID, tag);
	if (slot_cmpxchg(&pc->slots[slot_idx], old_val, new_val) == old_val)
		pcache_dec_pending(pc->header);

	return 0;
}

static void pcache_clock_sweep(struct daxfs_pcache *pc);

static int daxfs_pcache_fill_thread(void *data)
{
	struct daxfs_pcache *pc = data;
	u32 i;

	while (!kthread_should_stop()) {
		u32 pending = le32_to_cpu(READ_ONCE(pc->header->pending_count));

		if (pending == 0) {
			pcache_clock_sweep(pc);
			usleep_range(1000, 2000);
			continue;
		}

		for (i = 0; i < pc->slot_count && !kthread_should_stop(); i++) {
			u64 val = slot_read(&pc->slots[i]);

			if (PCACHE_STATE(val) == PCACHE_STATE_PENDING)
				pcache_fill_slot(pc, i, PCACHE_TAG(val));
		}

		pcache_clock_sweep(pc);
	}

	return 0;
}

static inline void pcache_touch(struct daxfs_pcache_slot *slot)
{
	if (!READ_ONCE(slot->ref_bit))
		WRITE_ONCE(slot->ref_bit, cpu_to_le32(1));
}

/*
 * Pin a VALID slot by CAS-incrementing its refcount.
 * Returns true on success, false if slot state changed (caller retries).
 */
static bool pcache_pin_slot(struct daxfs_pcache_slot *slot, u64 expected_val)
{
	u64 new_val;

	if (PCACHE_REFCNT(expected_val) >= PCACHE_REFCNT_MAX)
		return false;

	new_val = expected_val + PCACHE_REFCNT_INC;
	return slot_cmpxchg(slot, expected_val, new_val) == expected_val;
}

/*
 * Unpin a slot by CAS-decrementing its refcount.
 */
void daxfs_pcache_put_page(struct daxfs_info *info, s32 slot_idx)
{
	struct daxfs_pcache *pc = info->pcache;
	u64 val, new_val;

	if (!pc || slot_idx < 0)
		return;

	do {
		val = slot_read(&pc->slots[slot_idx]);
		if (PCACHE_REFCNT(val) == 0) {
			WARN_ON_ONCE(1);
			return;
		}
		new_val = val - PCACHE_REFCNT_INC;
	} while (slot_cmpxchg(&pc->slots[slot_idx], val, new_val) != val);
}

/*
 * Clock sweep: advance evict_hand by PCACHE_SWEEP_BATCH slots
 * and clear ref_bit on VALID slots in that range.
 */
static void pcache_clock_sweep(struct daxfs_pcache *pc)
{
	u32 old_hand, new_hand, i;

	old_hand = le32_to_cpu(READ_ONCE(pc->header->evict_hand));
	new_hand = (old_hand + PCACHE_SWEEP_BATCH) & pc->hash_mask;

	/* Atomically advance the hand; if another kernel won the race, skip */
	if (cmpxchg((u32 *)&pc->header->evict_hand,
		    old_hand, new_hand) != old_hand)
		return;

	for (i = 0; i < PCACHE_SWEEP_BATCH; i++) {
		u32 idx = (old_hand + i) & pc->hash_mask;
		u64 val = slot_read(&pc->slots[idx]);

		if (PCACHE_STATE(val) == PCACHE_STATE_VALID)
			WRITE_ONCE(pc->slots[idx].ref_bit, cpu_to_le32(0));
	}
}

/*
 * Wait for a PENDING slot to become VALID with matching tag.
 * Pins the slot (increments refcount) before returning.
 * Returns data pointer, ERR_PTR(-EAGAIN) if slot went FREE (caller retries),
 * or ERR_PTR(-EIO) on timeout.
 */
static void *pcache_wait_valid(struct daxfs_pcache *pc, u32 target_idx,
			       u64 desired_tag, s32 *pinned_slot)
{
	int timeout_us = 10000;

	while (timeout_us > 0) {
		u64 val = slot_read(&pc->slots[target_idx]);

		if (PCACHE_STATE(val) == PCACHE_STATE_VALID &&
		    PCACHE_TAG(val) == desired_tag) {
			if (!pcache_pin_slot(&pc->slots[target_idx], val)) {
				cpu_relax();
				timeout_us--;
				continue;
			}
			smp_rmb();
			pcache_touch(&pc->slots[target_idx]);
			if (pinned_slot)
				*pinned_slot = (s32)target_idx;
			return pc->data + (u64)target_idx * pc->block_size;
		}
		if (PCACHE_STATE(val) == PCACHE_STATE_FREE)
			return ERR_PTR(-EAGAIN);
		cpu_relax();
		udelay(1);
		timeout_us--;
	}
	pr_err_ratelimited("daxfs: pcache timeout waiting for slot %u\n",
			   target_idx);
	return ERR_PTR(-EIO);
}

static noinline void *pcache_slow_path(struct daxfs_pcache *pc,
				       u32 slot_idx, u64 desired_tag,
				       u64 val, s32 *pinned_slot);

/*
 * Core cache lookup — multi-file version.
 *
 * Pins the returned slot (increments refcount). Caller MUST call
 * daxfs_pcache_put_page() when done reading the data.
 *
 * @info: filesystem info
 * @ino: inode number of the file
 * @pgoff: page offset within the file's backing data
 * @pinned_slot: output, set to slot index if pinned (-1 if not)
 */
void *daxfs_pcache_get_page(struct daxfs_info *info, u64 ino, u64 pgoff,
			    s32 *pinned_slot)
{
	struct daxfs_pcache *pc = info->pcache;
	u64 desired_tag = PCACHE_TAG_MAKE(ino, pgoff);
	u32 slot_idx;
	u64 val;

	if (pinned_slot)
		*pinned_slot = -1;

	if (unlikely(!pc))
		return ERR_PTR(-ENOENT);

	slot_idx = pcache_hash(pc, desired_tag);

	val = slot_read(&pc->slots[slot_idx]);

	/* Fast path: VALID with matching tag and refcount 0 */
	if (likely(PCACHE_STATE(val) == PCACHE_STATE_VALID &&
		   PCACHE_TAG(val) == desired_tag)) {
		if (pcache_pin_slot(&pc->slots[slot_idx], val)) {
			smp_rmb();
			pcache_touch(&pc->slots[slot_idx]);
			if (pinned_slot)
				*pinned_slot = (s32)slot_idx;
			return pc->data + (u64)slot_idx * pc->block_size;
		}
	}

	return pcache_slow_path(pc, slot_idx, desired_tag, val, pinned_slot);
}

static noinline void *pcache_slow_path(struct daxfs_pcache *pc,
				       u32 slot_idx, u64 desired_tag,
				       u64 val, s32 *pinned_slot)
{
	u64 new_val;
	int retries = 0;
	u32 i;

restart:
	if (retries++ > 100)
		return ERR_PTR(-EIO);

	/*
	 * Phase 1 — Linear probe: scan PCACHE_PROBE_LEN slots from primary
	 * index. On hit return (pinned), track first FREE slot, wait on
	 * matching PENDING.
	 */
	{
		s32 first_free = -1;

		for (i = 0; i < PCACHE_PROBE_LEN; i++) {
			u32 idx = (slot_idx + i) & pc->hash_mask;

			val = slot_read(&pc->slots[idx]);

			switch (PCACHE_STATE(val)) {
			case PCACHE_STATE_VALID:
				if (PCACHE_TAG(val) == desired_tag) {
					if (!pcache_pin_slot(&pc->slots[idx],
							     val))
						goto restart;
					smp_rmb();
					pcache_touch(&pc->slots[idx]);
					if (pinned_slot)
						*pinned_slot = (s32)idx;
					return pc->data + (u64)idx * pc->block_size;
				}
				break;

			case PCACHE_STATE_FREE:
				if (first_free < 0)
					first_free = (s32)idx;
				break;

			case PCACHE_STATE_PENDING:
				if (PCACHE_TAG(val) == desired_tag) {
					void *ret = pcache_wait_valid(pc, idx,
								      desired_tag,
								      pinned_slot);
					if (ret == ERR_PTR(-EAGAIN))
						goto restart;
					return ret;
				}
				break;
			}
		}

		/*
		 * Phase 2 — Claim FREE slot: if one was found during probe,
		 * attempt to claim it.
		 */
		if (first_free >= 0) {
			u32 free_idx = (u32)first_free;

			val = slot_read(&pc->slots[free_idx]);
			if (PCACHE_STATE(val) != PCACHE_STATE_FREE)
				goto restart;

			new_val = PCACHE_MAKE(PCACHE_STATE_PENDING, desired_tag);
			if (slot_cmpxchg(&pc->slots[free_idx], val, new_val) != val)
				goto restart;

			pcache_inc_pending(pc->header);

			if (!list_empty(&pc->backing_files)) {
				pcache_fill_slot(pc, free_idx, desired_tag);
				/* Pin the freshly-filled slot */
				val = slot_read(&pc->slots[free_idx]);
				if (PCACHE_STATE(val) == PCACHE_STATE_VALID &&
				    PCACHE_TAG(val) == desired_tag &&
				    pcache_pin_slot(&pc->slots[free_idx], val)) {
					pcache_touch(&pc->slots[free_idx]);
					if (pinned_slot)
						*pinned_slot = (s32)free_idx;
					return pc->data + (u64)free_idx * pc->block_size;
				}
				goto restart;
			}

			/* Spawn kernel: wait for host to fill */
			{
				void *ret = pcache_wait_valid(pc, free_idx,
							      desired_tag,
							      pinned_slot);
				if (ret == ERR_PTR(-EAGAIN))
					goto restart;
				return ret;
			}
		}
	}

	/*
	 * Phase 3 — Clock-based victim selection: all probe slots occupied.
	 *
	 * Only evict VALID slots with refcount == 0 (no active readers).
	 * Pass 1: find a cold victim (ref_bit=0, refcount=0).
	 */
	for (i = 0; i < PCACHE_PROBE_LEN; i++) {
		u32 idx = (slot_idx + i) & pc->hash_mask;

		val = slot_read(&pc->slots[idx]);
		if (PCACHE_STATE(val) == PCACHE_STATE_VALID &&
		    PCACHE_REFCNT(val) == 0 &&
		    !le32_to_cpu(READ_ONCE(pc->slots[idx].ref_bit))) {
			new_val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
			if (slot_cmpxchg(&pc->slots[idx], val, new_val) == val)
				goto restart;
		}
	}

	/*
	 * All-hot case: all probe slots have ref_bit=1. Clear ref_bits in the
	 * probe window, then briefly yield so other hosts can re-touch their
	 * genuinely hot entries. Re-scan for a cold, unpinned victim.
	 */
	for (i = 0; i < PCACHE_PROBE_LEN; i++) {
		u32 idx = (slot_idx + i) & pc->hash_mask;

		WRITE_ONCE(pc->slots[idx].ref_bit, cpu_to_le32(0));
	}

	cpu_relax();

	/* Re-scan: only evict slots with refcount == 0 */
	for (i = 0; i < PCACHE_PROBE_LEN; i++) {
		u32 idx = (slot_idx + i) & pc->hash_mask;

		val = slot_read(&pc->slots[idx]);
		if (PCACHE_STATE(val) == PCACHE_STATE_VALID &&
		    PCACHE_REFCNT(val) == 0 &&
		    !le32_to_cpu(READ_ONCE(pc->slots[idx].ref_bit))) {
			new_val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
			if (slot_cmpxchg(&pc->slots[idx], val, new_val) == val)
				goto restart;
		}
	}

	/*
	 * Final fallback: extreme contention, all still hot or pinned.
	 * Evict the first VALID slot with refcount == 0.
	 */
	for (i = 0; i < PCACHE_PROBE_LEN; i++) {
		u32 idx = (slot_idx + i) & pc->hash_mask;

		val = slot_read(&pc->slots[idx]);
		if (PCACHE_STATE(val) == PCACHE_STATE_VALID &&
		    PCACHE_REFCNT(val) == 0) {
			new_val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
			if (slot_cmpxchg(&pc->slots[idx], val, new_val) == val)
				goto restart;
		}
	}

	/* All cmpxchg attempts failed — retry from scratch */
	goto restart;
}

bool daxfs_is_pcache_data(struct daxfs_info *info, void *ptr)
{
	struct daxfs_pcache *pc = info->pcache;

	if (!pc || !ptr)
		return false;
	return ptr >= pc->data &&
	       ptr < pc->data + (u64)pc->slot_count * pc->block_size;
}

/*
 * Ensure the backing_array is large enough for the given ino.
 */
static int pcache_grow_backing_array(struct daxfs_pcache *pc, u64 ino)
{
	u32 new_size;
	struct file **new_array;

	if (ino < pc->backing_array_size)
		return 0;

	new_size = (u32)(ino + 1);
	new_array = krealloc(pc->backing_array,
			     new_size * sizeof(struct file *), GFP_KERNEL);
	if (!new_array)
		return -ENOMEM;

	memset(new_array + pc->backing_array_size, 0,
	       (new_size - pc->backing_array_size) * sizeof(struct file *));
	pc->backing_array = new_array;
	pc->backing_array_size = new_size;
	return 0;
}

/*
 * Add a backing file for a specific inode, sharing an already-open file.
 */
static int pcache_add_backing_file(struct daxfs_pcache *pc, u64 ino,
				   struct file *f)
{
	struct daxfs_pcache_backing *b;
	int ret;

	/* Populate O(1) lookup array */
	ret = pcache_grow_backing_array(pc, ino);
	if (ret)
		return ret;
	if (pc->backing_array[ino])
		fput(pc->backing_array[ino]);
	pc->backing_array[ino] = get_file(f);

	/* Keep list for cleanup */
	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (!b)
		return -ENOMEM;

	b->ino = ino;
	b->file = get_file(f);
	list_add(&b->list, &pc->backing_files);
	return 0;
}

/*
 * Recursively walk a directory in the base image and register export files.
 */
static int pcache_register_export_dir(struct daxfs_info *info,
				      struct daxfs_pcache *pc,
				      u32 dir_ino, const char *dir_path)
{
	struct daxfs_base_inode *dir_raw;
	struct daxfs_dirent *dirents;
	u64 base_offset = le64_to_cpu(info->super->base_offset);
	u32 num_entries, i;

	if (dir_ino < 1 || dir_ino > info->base_inode_count)
		return 0;

	dir_raw = &info->base_inodes[dir_ino - 1];
	if (!S_ISDIR(le32_to_cpu(dir_raw->mode)))
		return 0;

	if (le64_to_cpu(dir_raw->size) == 0)
		return 0;

	num_entries = le64_to_cpu(dir_raw->size) / DAXFS_DIRENT_SIZE;
	dirents = daxfs_mem_ptr(info,
				base_offset + le64_to_cpu(dir_raw->data_offset));

	for (i = 0; i < num_entries; i++) {
		struct daxfs_dirent *de = &dirents[i];
		u32 child_ino = le32_to_cpu(de->ino);
		u16 name_len = le16_to_cpu(de->name_len);
		u32 mode = le32_to_cpu(de->mode);
		char *child_path;

		child_path = kasprintf(GFP_KERNEL, "%s/%.*s",
				       dir_path, name_len, de->name);
		if (!child_path)
			return -ENOMEM;

		if (S_ISREG(mode)) {
			struct file *f;

			f = filp_open(child_path, O_RDONLY, 0);
			if (IS_ERR(f)) {
				pr_warn("daxfs: export: cannot open '%s': %ld\n",
					child_path, PTR_ERR(f));
				kfree(child_path);
				continue;
			}
			pcache_add_backing_file(pc, child_ino, f);
			fput(f);
		} else if (S_ISDIR(mode)) {
			int ret;

			ret = pcache_register_export_dir(info, pc,
							 child_ino, child_path);
			if (ret) {
				kfree(child_path);
				return ret;
			}
		}
		/* Symlinks: skip (data stored inline in base image) */

		kfree(child_path);
	}

	return 0;
}

/*
 * Initialize pcache for export mode: walk the base image tree and
 * register each regular file from the export directory.
 */
int daxfs_pcache_init_export(struct daxfs_info *info, const char *export_path)
{
	struct daxfs_pcache *pc = info->pcache;
	u32 root_ino = le32_to_cpu(info->super->root_inode);
	int ret;

	if (!pc)
		return -EINVAL;

	ret = pcache_register_export_dir(info, pc, root_ino, export_path);
	if (ret)
		return ret;

	/* Start fill kthread (not started by daxfs_pcache_init with NULL) */
	pc->fill_thread = kthread_run(daxfs_pcache_fill_thread, pc,
				      "daxfs-pcache");
	if (IS_ERR(pc->fill_thread)) {
		int err = PTR_ERR(pc->fill_thread);

		pr_err("daxfs: failed to start pcache fill thread: %d\n", err);
		pc->fill_thread = NULL;
		return err;
	}

	pr_info("daxfs: pcache initialized with %u slots, export=%s\n",
		pc->slot_count, export_path);

	return 0;
}

/*
 * Add a backing file for a specific inode (opens the path).
 */
int daxfs_pcache_add_backing(struct daxfs_info *info, u64 ino,
			     const char *path)
{
	struct daxfs_pcache *pc = info->pcache;
	struct file *f;
	int ret;

	if (!pc)
		return -EINVAL;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		pr_err("daxfs: failed to open backing file '%s': %ld\n",
		       path, PTR_ERR(f));
		return PTR_ERR(f);
	}

	ret = pcache_add_backing_file(pc, ino, f);
	fput(f);
	return ret;
}

/*
 * Register all regular-file base inodes against a single backing file.
 */
static int pcache_register_base_inodes(struct daxfs_info *info, struct file *f)
{
	struct daxfs_pcache *pc = info->pcache;
	u32 i, count = info->base_inode_count;
	int ret;

	for (i = 0; i < count; i++) {
		struct daxfs_base_inode *raw = &info->base_inodes[i];
		u32 mode = le32_to_cpu(raw->mode);

		if (!S_ISREG(mode))
			continue;

		ret = pcache_add_backing_file(pc, i + 1, f);
		if (ret)
			return ret;
	}
	return 0;
}

int daxfs_pcache_init(struct daxfs_info *info, const char *backing_path)
{
	struct daxfs_pcache *pc;
	u64 pcache_offset = le64_to_cpu(info->super->pcache_offset);
	struct daxfs_pcache_header *hdr;

	if (!pcache_offset)
		return 0;

	pc = kzalloc(sizeof(*pc), GFP_KERNEL);
	if (!pc)
		return -ENOMEM;

	INIT_LIST_HEAD(&pc->backing_files);
	pc->block_size = info->block_size;
	pc->block_shift = ilog2(info->block_size);

	hdr = daxfs_mem_ptr(info, pcache_offset);
	if (le32_to_cpu(hdr->magic) != DAXFS_PCACHE_MAGIC) {
		pr_err("daxfs: invalid pcache magic 0x%x\n",
		       le32_to_cpu(hdr->magic));
		kfree(pc);
		return -EINVAL;
	}

	pc->header = hdr;
	/* Read layout from main superblock */
	pc->slot_count = le32_to_cpu(info->super->pcache_slot_count);
	pc->hash_mask = pc->slot_count - 1;
	pc->slots = daxfs_mem_ptr(info,
		pcache_offset + le64_to_cpu(hdr->slot_meta_offset));
	pc->data = daxfs_mem_ptr(info,
		pcache_offset + le64_to_cpu(hdr->slot_data_offset));

	info->pcache = pc;

	/*
	 * Split mode: register each regular-file base inode against
	 * the single backing file so pcache_find_backing() can look
	 * up the file by real inode number.
	 */
	if (backing_path) {
		struct file *f;
		int ret;

		f = filp_open(backing_path, O_RDONLY, 0);
		if (IS_ERR(f)) {
			int err = PTR_ERR(f);

			pr_err("daxfs: failed to open backing file '%s': %d\n",
			       backing_path, err);
			info->pcache = NULL;
			kfree(pc);
			return err;
		}

		ret = pcache_register_base_inodes(info, f);
		fput(f);
		if (ret) {
			daxfs_pcache_exit(info);
			return ret;
		}

		/* Start fill kthread */
		pc->fill_thread = kthread_run(daxfs_pcache_fill_thread, pc,
					      "daxfs-pcache");
		if (IS_ERR(pc->fill_thread)) {
			int err = PTR_ERR(pc->fill_thread);

			pr_err("daxfs: failed to start pcache fill thread: %d\n",
			       err);
			pc->fill_thread = NULL;
			daxfs_pcache_exit(info);
			return err;
		}

		pr_info("daxfs: pcache initialized with %u slots, backing=%s\n",
			pc->slot_count, backing_path);
	} else {
		pr_info("daxfs: pcache initialized with %u slots (spawn, no backing)\n",
			pc->slot_count);
	}

	return 0;
}

void daxfs_pcache_exit(struct daxfs_info *info)
{
	struct daxfs_pcache *pc = info->pcache;
	struct daxfs_pcache_backing *b, *tmp;

	if (!pc)
		return;

	if (pc->fill_thread) {
		kthread_stop(pc->fill_thread);
		pc->fill_thread = NULL;
	}

	list_for_each_entry_safe(b, tmp, &pc->backing_files, list) {
		if (b->file)
			fput(b->file);
		list_del(&b->list);
		kfree(b);
	}

	/* backing_array holds duplicate refs; drop them */
	if (pc->backing_array) {
		u32 i;

		for (i = 0; i < pc->backing_array_size; i++) {
			if (pc->backing_array[i])
				fput(pc->backing_array[i]);
		}
		kfree(pc->backing_array);
	}

	info->pcache = NULL;
	kfree(pc);
}
