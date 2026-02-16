// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs shared page cache
 *
 * Demand-paged cache in DAX memory for backing store mode. Because DAX
 * memory is physically shared across kernel instances, the cache is
 * automatically visible to all kernels with no coherency protocol.
 *
 * Direct-mapped: each backing file page maps to exactly one cache slot
 * via hash(page_offset) & (slot_count - 1). 3-state machine with all
 * transitions via cmpxchg on DAX memory.
 *
 * Host kernel: has backing file access, fills cache misses inline or
 * via a background kthread that polls for PENDING slots.
 *
 * Spawn kernels: no backing file, mark slots PENDING and busy-poll
 * until the host fills them.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include "daxfs.h"

static u32 pcache_hash(struct daxfs_pcache *pc, u64 backing_offset)
{
	return (u32)((backing_offset >> PAGE_SHIFT) & pc->hash_mask);
}

/*
 * Atomic cmpxchg on the state_tag field.
 * state_tag is __le64 on DAX memory; on little-endian x86-64 this is
 * the same layout as u64, so cmpxchg works directly.
 */
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

static int pcache_fill_slot(struct daxfs_pcache *pc, u32 slot_idx,
			    u64 tag)
{
	u64 backing_offset = tag << PAGE_SHIFT;
	loff_t pos = backing_offset;
	void *dst = pc->data + (u64)slot_idx * PAGE_SIZE;
	ssize_t n;
	u64 old_val, new_val;

	n = kernel_read(pc->backing_file, dst, PAGE_SIZE, &pos);
	if (n < 0) {
		pr_err_ratelimited("daxfs: pcache read error at offset %llu: %zd\n",
				   backing_offset, n);
		memset(dst, 0, PAGE_SIZE);
	} else if (n < PAGE_SIZE) {
		memset(dst + n, 0, PAGE_SIZE - n);
	}

	/* Memory barrier before making data visible */
	smp_wmb();

	/* Transition PENDING → VALID */
	old_val = PCACHE_MAKE(PCACHE_STATE_PENDING, tag);
	new_val = PCACHE_MAKE(PCACHE_STATE_VALID, tag);
	if (slot_cmpxchg(&pc->slots[slot_idx], old_val, new_val) == old_val)
		pcache_dec_pending(pc->header);

	return 0;
}

static int daxfs_pcache_fill_thread(void *data)
{
	struct daxfs_pcache *pc = data;
	u32 i;

	while (!kthread_should_stop()) {
		u32 pending = le32_to_cpu(READ_ONCE(pc->header->pending_count));

		if (pending == 0) {
			usleep_range(1000, 2000);
			continue;
		}

		for (i = 0; i < pc->slot_count && !kthread_should_stop(); i++) {
			u64 val = slot_read(&pc->slots[i]);

			if (PCACHE_STATE(val) == PCACHE_STATE_PENDING)
				pcache_fill_slot(pc, i, PCACHE_TAG(val));
		}
	}

	return 0;
}

static inline void pcache_touch(struct daxfs_pcache_slot *slot)
{
	if (!READ_ONCE(slot->ref_bit))
		WRITE_ONCE(slot->ref_bit, cpu_to_le32(1));
}

/* Slow path for cache miss/eviction/pending — never inlined. */
static noinline void *pcache_slow_path(struct daxfs_pcache *pc,
				       u32 slot_idx, u64 desired_tag,
				       u64 val);

/*
 * Core cache lookup.
 *
 * Hot path (cache hit) is: hash → load state_tag → compare → return.
 * One load from DAX, one compare, one conditional store (ref_bit, only
 * when transitioning from 0→1). smp_rmb() is a compiler barrier on x86.
 */
void *daxfs_pcache_get_page(struct daxfs_info *info, u64 backing_page_offset)
{
	struct daxfs_pcache *pc = info->pcache;
	u32 slot_idx;
	u64 desired_tag, val;

	if (unlikely(!pc))
		return ERR_PTR(-ENOENT);

	slot_idx = pcache_hash(pc, backing_page_offset);
	desired_tag = backing_page_offset >> PAGE_SHIFT;

	val = slot_read(&pc->slots[slot_idx]);

	/* Fast path: VALID with matching tag */
	if (likely(val == PCACHE_MAKE(PCACHE_STATE_VALID, desired_tag))) {
		smp_rmb();
		pcache_touch(&pc->slots[slot_idx]);
		return pc->data + (u64)slot_idx * PAGE_SIZE;
	}

	return pcache_slow_path(pc, slot_idx, desired_tag, val);
}

static noinline void *pcache_slow_path(struct daxfs_pcache *pc,
				       u32 slot_idx, u64 desired_tag,
				       u64 val)
{
	u64 new_val;
	int retries = 0;

retry:
	if (retries++ > 100)
		return ERR_PTR(-EIO);

	switch (PCACHE_STATE(val)) {
	case PCACHE_STATE_VALID:
		/* Tag mismatch (hit case handled in fast path): evict */
		new_val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
		if (slot_cmpxchg(&pc->slots[slot_idx], val, new_val) != val) {
			val = slot_read(&pc->slots[slot_idx]);
			goto retry;
		}
		val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
		goto retry;

	case PCACHE_STATE_FREE:
		/* Claim the slot */
		new_val = PCACHE_MAKE(PCACHE_STATE_PENDING, desired_tag);
		if (slot_cmpxchg(&pc->slots[slot_idx], val, new_val) != val) {
			val = slot_read(&pc->slots[slot_idx]);
			goto retry;
		}

		pcache_inc_pending(pc->header);

		if (pc->backing_file) {
			/* Host kernel: fill inline */
			pcache_fill_slot(pc, slot_idx, desired_tag);
			pcache_touch(&pc->slots[slot_idx]);
			return pc->data + (u64)slot_idx * PAGE_SIZE;
		}

		/* Spawn kernel: busy-poll until host fills */
		goto wait_valid;

	case PCACHE_STATE_PENDING:
		if (PCACHE_TAG(val) == desired_tag)
			goto wait_valid;

		/* PENDING with different tag: wait for state change */
		goto wait_state_change;
	}

	return ERR_PTR(-EIO);

wait_valid:
	{
		int timeout_us = 10000;  /* 10ms */

		while (timeout_us > 0) {
			val = slot_read(&pc->slots[slot_idx]);
			if (PCACHE_STATE(val) == PCACHE_STATE_VALID &&
			    PCACHE_TAG(val) == desired_tag) {
				smp_rmb();
				pcache_touch(&pc->slots[slot_idx]);
				return pc->data + (u64)slot_idx * PAGE_SIZE;
			}
			if (PCACHE_STATE(val) == PCACHE_STATE_FREE)
				goto retry;
			cpu_relax();
			udelay(1);
			timeout_us--;
		}
		pr_err_ratelimited("daxfs: pcache timeout waiting for slot %u\n",
				   slot_idx);
		return ERR_PTR(-EIO);
	}

wait_state_change:
	{
		int timeout_us = 10000;
		u64 orig_val = val;

		while (timeout_us > 0) {
			val = slot_read(&pc->slots[slot_idx]);
			if (val != orig_val)
				goto retry;
			cpu_relax();
			udelay(1);
			timeout_us--;
		}
		/* Timeout: try to evict the stale PENDING slot */
		new_val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
		slot_cmpxchg(&pc->slots[slot_idx], orig_val, new_val);
		val = slot_read(&pc->slots[slot_idx]);
		goto retry;
	}
}

/*
 * Check if a pointer falls within the pcache data region.
 * Used to prevent PFN mapping for cached data (must use anon pages).
 */
bool daxfs_is_pcache_data(struct daxfs_info *info, void *ptr)
{
	struct daxfs_pcache *pc = info->pcache;

	if (!pc || !ptr)
		return false;
	return ptr >= pc->data &&
	       ptr < pc->data + (u64)pc->slot_count * PAGE_SIZE;
}

/*
 * Initialize page cache from on-DAX header.
 *
 * @info: filesystem info (DAX memory already mapped)
 * @backing_path: path to backing file (NULL for spawn kernels)
 */
int daxfs_pcache_init(struct daxfs_info *info, const char *backing_path)
{
	struct daxfs_pcache *pc;
	u64 pcache_offset = le64_to_cpu(info->super->pcache_offset);
	struct daxfs_pcache_header *hdr;

	if (!pcache_offset)
		return 0;  /* No page cache configured */

	pc = kzalloc(sizeof(*pc), GFP_KERNEL);
	if (!pc)
		return -ENOMEM;

	hdr = daxfs_mem_ptr(info, pcache_offset);
	if (le32_to_cpu(hdr->magic) != DAXFS_PCACHE_MAGIC) {
		pr_err("daxfs: invalid pcache magic 0x%x\n",
		       le32_to_cpu(hdr->magic));
		kfree(pc);
		return -EINVAL;
	}

	pc->header = hdr;
	pc->slot_count = le32_to_cpu(hdr->slot_count);
	pc->hash_mask = pc->slot_count - 1;
	pc->slots = daxfs_mem_ptr(info,
		pcache_offset + le64_to_cpu(hdr->slot_meta_offset));
	pc->data = daxfs_mem_ptr(info,
		pcache_offset + le64_to_cpu(hdr->slot_data_offset));

	if (backing_path) {
		pc->backing_file = filp_open(backing_path, O_RDONLY, 0);
		if (IS_ERR(pc->backing_file)) {
			int err = PTR_ERR(pc->backing_file);

			pr_err("daxfs: failed to open backing file '%s': %d\n",
			       backing_path, err);
			pc->backing_file = NULL;
			kfree(pc);
			return err;
		}

		/* Start fill kthread for host kernel */
		pc->fill_thread = kthread_run(daxfs_pcache_fill_thread, pc,
					      "daxfs-pcache");
		if (IS_ERR(pc->fill_thread)) {
			int err = PTR_ERR(pc->fill_thread);

			pr_err("daxfs: failed to start pcache fill thread: %d\n",
			       err);
			pc->fill_thread = NULL;
			filp_close(pc->backing_file, NULL);
			pc->backing_file = NULL;
			kfree(pc);
			return err;
		}

		pr_info("daxfs: pcache initialized with %u slots, backing=%s\n",
			pc->slot_count, backing_path);
	} else {
		pr_info("daxfs: pcache initialized with %u slots (spawn, no backing)\n",
			pc->slot_count);
	}

	info->pcache = pc;
	return 0;
}

/*
 * Tear down page cache.
 */
void daxfs_pcache_exit(struct daxfs_info *info)
{
	struct daxfs_pcache *pc = info->pcache;

	if (!pc)
		return;

	if (pc->fill_thread) {
		kthread_stop(pc->fill_thread);
		pc->fill_thread = NULL;
	}

	if (pc->backing_file) {
		filp_close(pc->backing_file, NULL);
		pc->backing_file = NULL;
	}

	info->pcache = NULL;
	kfree(pc);
}
