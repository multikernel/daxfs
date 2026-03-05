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
 */
static struct file *pcache_find_backing(struct daxfs_pcache *pc, u64 ino)
{
	struct daxfs_pcache_backing *b;

	list_for_each_entry(b, &pc->backing_files, list) {
		if (b->ino == ino)
			return b->file;
	}
	return NULL;
}

static int pcache_fill_slot(struct daxfs_pcache *pc, u32 slot_idx, u64 tag)
{
	u64 ino = PCACHE_TAG_INO(tag);
	u64 pgoff = PCACHE_TAG_PGOFF(tag);
	loff_t pos = (loff_t)pgoff << PAGE_SHIFT;
	void *dst = pc->data + (u64)slot_idx * PAGE_SIZE;
	struct file *backing;
	ssize_t n;
	u64 old_val, new_val;

	backing = pcache_find_backing(pc, ino);
	if (!backing) {
		/* No backing file for this inode — skip */
		return -ENOENT;
	}

	n = kernel_read(backing, dst, PAGE_SIZE, &pos);
	if (n < 0) {
		pr_err_ratelimited("daxfs: pcache read error ino=%llu pgoff=%llu: %zd\n",
				   ino, pgoff, n);
		memset(dst, 0, PAGE_SIZE);
	} else if (n < PAGE_SIZE) {
		memset(dst + n, 0, PAGE_SIZE - n);
	}

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

static noinline void *pcache_slow_path(struct daxfs_pcache *pc,
				       u32 slot_idx, u64 desired_tag,
				       u64 val);

/*
 * Core cache lookup — multi-file version.
 *
 * @info: filesystem info
 * @ino: inode number of the file
 * @pgoff: page offset within the file's backing data
 */
void *daxfs_pcache_get_page(struct daxfs_info *info, u64 ino, u64 pgoff)
{
	struct daxfs_pcache *pc = info->pcache;
	u64 desired_tag = PCACHE_TAG_MAKE(ino, pgoff);
	u32 slot_idx;
	u64 val;

	if (unlikely(!pc))
		return ERR_PTR(-ENOENT);

	slot_idx = pcache_hash(pc, desired_tag);

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
		/* Tag mismatch: evict */
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

		if (!list_empty(&pc->backing_files)) {
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

		goto wait_state_change;
	}

	return ERR_PTR(-EIO);

wait_valid:
	{
		int timeout_us = 10000;

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
		new_val = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
		slot_cmpxchg(&pc->slots[slot_idx], orig_val, new_val);
		val = slot_read(&pc->slots[slot_idx]);
		goto retry;
	}
}

bool daxfs_is_pcache_data(struct daxfs_info *info, void *ptr)
{
	struct daxfs_pcache *pc = info->pcache;

	if (!pc || !ptr)
		return false;
	return ptr >= pc->data &&
	       ptr < pc->data + (u64)pc->slot_count * PAGE_SIZE;
}

/*
 * Add a backing file for a specific inode, sharing an already-open file.
 */
static int pcache_add_backing_file(struct daxfs_pcache *pc, u64 ino,
				   struct file *f)
{
	struct daxfs_pcache_backing *b;

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

	info->pcache = NULL;
	kfree(pc);
}
