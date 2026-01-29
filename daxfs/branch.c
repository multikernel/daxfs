// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs branch management
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/writeback.h>
#include "daxfs.h"

#define INITIAL_DELTA_SIZE	(64 * 1024)	/* 64KB initial delta log */

/*
 * DAX memory spinlock - simple test-and-set for cross-mount coordination
 */
static inline void daxfs_coord_lock(struct daxfs_info *info)
{
	while (cmpxchg(&info->coord->coord_lock, 0, 1) != 0)
		cpu_relax();
}

static inline void daxfs_coord_unlock(struct daxfs_info *info)
{
	smp_store_release(&info->coord->coord_lock, 0);
}

/*
 * Fast check if any commit happened since last check
 */
bool daxfs_commit_seq_changed(struct daxfs_info *info)
{
	u64 cur_seq;

	if (!info->coord)
		return false;

	cur_seq = le64_to_cpu(READ_ONCE(info->coord->commit_sequence));
	return cur_seq != info->cached_commit_seq;
}

/*
 * Full branch validity check
 */
bool daxfs_branch_is_valid(struct daxfs_info *info)
{
	struct daxfs_branch_ctx *branch = info->current_branch;
	u32 state;

	if (!branch)
		return true;  /* Static image mode */

	state = le32_to_cpu(READ_ONCE(branch->on_dax->state));
	return state == DAXFS_BRANCH_ACTIVE;
}

/*
 * Find a branch by name in the active branches list
 */
struct daxfs_branch_ctx *daxfs_find_branch_by_name(struct daxfs_info *info,
						   const char *name)
{
	struct daxfs_branch_ctx *branch;

	list_for_each_entry(branch, &info->active_branches, list) {
		if (strcmp(branch->name, name) == 0)
			return branch;
	}
	return NULL;
}

/*
 * Find a free slot in the branch table
 */
static struct daxfs_branch *find_free_branch_slot(struct daxfs_info *info)
{
	u32 i;

	for (i = 0; i < info->branch_table_entries; i++) {
		if (le32_to_cpu(info->branch_table[i].state) == DAXFS_BRANCH_FREE)
			return &info->branch_table[i];
	}
	return NULL;
}

/*
 * Delta region allocation is now handled by the storage layer.
 * See dax_mem.c: daxfs_mem_alloc_region(), daxfs_mem_free_region()
 */

/*
 * Create a new branch context
 */
static struct daxfs_branch_ctx *alloc_branch_ctx(void)
{
	struct daxfs_branch_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->inode_index = RB_ROOT;
	ctx->dirent_index = RB_ROOT;
	spin_lock_init(&ctx->index_lock);
	atomic_set(&ctx->refcount, 1);

	return ctx;
}

/*
 * Initialize the "main" branch on first mount
 */
int daxfs_init_main_branch(struct daxfs_info *info)
{
	struct daxfs_branch *slot;
	struct daxfs_branch_ctx *ctx;
	u64 delta_offset;
	int ret;

	mutex_lock(&info->branch_lock);

	/* Check if main already exists */
	if (daxfs_find_branch_by_name(info, "main")) {
		mutex_unlock(&info->branch_lock);
		return 0;
	}

	/* Find free slot */
	slot = find_free_branch_slot(info);
	if (!slot) {
		mutex_unlock(&info->branch_lock);
		return -ENOSPC;
	}

	/* Allocate delta log space using storage layer */
	delta_offset = daxfs_mem_alloc_region(info, INITIAL_DELTA_SIZE);
	if (!delta_offset) {
		mutex_unlock(&info->branch_lock);
		return -ENOSPC;
	}

	/* Create runtime context */
	ctx = alloc_branch_ctx();
	if (!ctx) {
		mutex_unlock(&info->branch_lock);
		return -ENOMEM;
	}

	/* Initialize on-DAX branch record */
	slot->branch_id = cpu_to_le64(1);
	slot->parent_id = cpu_to_le64(0);	/* No parent */
	slot->delta_log_offset = cpu_to_le64(delta_offset);
	slot->delta_log_size = cpu_to_le64(0);
	slot->delta_log_capacity = cpu_to_le64(INITIAL_DELTA_SIZE);
	slot->state = cpu_to_le32(DAXFS_BRANCH_ACTIVE);
	slot->refcount = cpu_to_le32(1);
	slot->next_local_ino = cpu_to_le64(DAXFS_ROOT_INO + 1);
	strscpy(slot->name, "main", sizeof(slot->name));

	/* Setup runtime context using storage layer */
	ctx->info = info;
	ctx->branch_id = 1;
	strscpy(ctx->name, "main", sizeof(ctx->name));
	ctx->on_dax = slot;
	ctx->parent = NULL;
	ctx->delta_log = daxfs_mem_ptr(info, delta_offset);
	ctx->delta_size = 0;
	ctx->delta_capacity = INITIAL_DELTA_SIZE;
	ctx->next_ino = DAXFS_ROOT_INO + 1;

	/* Initialize delta index */
	ret = daxfs_delta_init_branch(info, ctx);
	if (ret) {
		kfree(ctx);
		mutex_unlock(&info->branch_lock);
		return ret;
	}

	list_add(&ctx->list, &info->active_branches);

	/* Update superblock */
	info->super->next_branch_id = cpu_to_le64(2);
	info->super->active_branches = cpu_to_le32(1);

	mutex_unlock(&info->branch_lock);

	pr_info("daxfs: initialized main branch\n");
	return 0;
}

/*
 * Create a new named branch
 */
int daxfs_branch_create(struct daxfs_info *info, const char *name,
			const char *parent_name, struct daxfs_branch_ctx **out)
{
	struct daxfs_branch_ctx *parent;
	struct daxfs_branch_ctx *ctx;
	struct daxfs_branch *slot;
	u64 branch_id;
	u64 delta_offset;
	int ret;

	mutex_lock(&info->branch_lock);

	/* Validate name length */
	if (strlen(name) > DAXFS_BRANCH_NAME_MAX) {
		mutex_unlock(&info->branch_lock);
		return -ENAMETOOLONG;
	}

	/* Check name is not "main" */
	if (strcmp(name, "main") == 0) {
		mutex_unlock(&info->branch_lock);
		return -EINVAL;
	}

	/* Check name not already in use */
	if (daxfs_find_branch_by_name(info, name)) {
		mutex_unlock(&info->branch_lock);
		return -EEXIST;
	}

	/* Find parent by name */
	parent = daxfs_find_branch_by_name(info, parent_name);
	if (!parent) {
		mutex_unlock(&info->branch_lock);
		return -ENOENT;
	}

	/* Find free slot in branch table */
	slot = find_free_branch_slot(info);
	if (!slot) {
		mutex_unlock(&info->branch_lock);
		return -ENOSPC;
	}

	/* Allocate branch ID */
	branch_id = le64_to_cpu(info->super->next_branch_id);
	info->super->next_branch_id = cpu_to_le64(branch_id + 1);

	/* Allocate delta log space using storage layer */
	delta_offset = daxfs_mem_alloc_region(info, INITIAL_DELTA_SIZE);
	if (!delta_offset) {
		mutex_unlock(&info->branch_lock);
		return -ENOSPC;
	}

	/* Create runtime context */
	ctx = alloc_branch_ctx();
	if (!ctx) {
		mutex_unlock(&info->branch_lock);
		return -ENOMEM;
	}

	/* Initialize on-DAX branch record */
	slot->branch_id = cpu_to_le64(branch_id);
	slot->parent_id = cpu_to_le64(parent->branch_id);
	slot->delta_log_offset = cpu_to_le64(delta_offset);
	slot->delta_log_size = cpu_to_le64(0);
	slot->delta_log_capacity = cpu_to_le64(INITIAL_DELTA_SIZE);
	slot->state = cpu_to_le32(DAXFS_BRANCH_ACTIVE);
	slot->refcount = cpu_to_le32(1);
	slot->next_local_ino = cpu_to_le64(
		le64_to_cpu(info->super->next_inode_id));
	strscpy(slot->name, name, sizeof(slot->name));

	/* Setup runtime context using storage layer */
	ctx->info = info;
	ctx->branch_id = branch_id;
	strscpy(ctx->name, name, sizeof(ctx->name));
	ctx->on_dax = slot;
	ctx->parent = parent;
	ctx->delta_log = daxfs_mem_ptr(info, delta_offset);
	ctx->delta_size = 0;
	ctx->delta_capacity = INITIAL_DELTA_SIZE;
	ctx->next_ino = le64_to_cpu(info->super->next_inode_id);

	/* Child references parent */
	atomic_inc(&parent->refcount);
	slot->refcount = cpu_to_le32(atomic_read(&parent->refcount));

	/* Initialize delta index */
	ret = daxfs_delta_init_branch(info, ctx);
	if (ret) {
		atomic_dec(&parent->refcount);
		kfree(ctx);
		mutex_unlock(&info->branch_lock);
		return ret;
	}

	list_add(&ctx->list, &info->active_branches);

	/* Update superblock */
	info->super->active_branches = cpu_to_le32(
		le32_to_cpu(info->super->active_branches) + 1);

	mutex_unlock(&info->branch_lock);

	*out = ctx;
	pr_info("daxfs: created branch '%s' (id=%llu, parent='%s')\n",
		name, branch_id, parent_name);
	return 0;
}

/*
 * Commit a branch to its parent
 *
 * This invalidates all sibling branches (branches with the same parent).
 * Sibling mounts will detect this via the fault handler and receive SIGBUS.
 */
int daxfs_branch_commit(struct daxfs_info *info,
			struct daxfs_branch_ctx *branch)
{
	struct daxfs_branch_ctx *parent, *sibling;
	u64 parent_id;
	int ret;
	u32 i;

	/* Acquire global coordination lock */
	if (info->coord)
		daxfs_coord_lock(info);
	mutex_lock(&info->branch_lock);

	/* Can't commit main branch */
	if (strcmp(branch->name, "main") == 0) {
		ret = -EINVAL;
		goto out_unlock;
	}

	parent = branch->parent;
	if (!parent) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Check no active children */
	if (atomic_read(&branch->refcount) > 1) {
		ret = -EBUSY;
		goto out_unlock;
	}

	parent_id = le64_to_cpu(branch->on_dax->parent_id);

	/* Invalidate all sibling branches (same parent, different branch) */
	list_for_each_entry(sibling, &info->active_branches, list) {
		if (sibling == branch)
			continue;
		if (le64_to_cpu(sibling->on_dax->parent_id) != parent_id)
			continue;

		/* Mark sibling as aborted */
		sibling->on_dax->state = cpu_to_le32(DAXFS_BRANCH_ABORTED);
		sibling->on_dax->generation = cpu_to_le32(
			le32_to_cpu(sibling->on_dax->generation) + 1);

		pr_info("daxfs: invalidated sibling branch '%s'\n",
			sibling->name);
	}

	/*
	 * Also invalidate sibling branches that may be mounted by other
	 * processes (not in our active_branches list). Scan the branch table.
	 */
	for (i = 0; i < info->branch_table_entries; i++) {
		struct daxfs_branch *slot = &info->branch_table[i];
		u32 state = le32_to_cpu(slot->state);

		if (state != DAXFS_BRANCH_ACTIVE)
			continue;
		if (le64_to_cpu(slot->branch_id) == branch->branch_id)
			continue;
		if (le64_to_cpu(slot->parent_id) != parent_id)
			continue;

		/* Mark as aborted */
		slot->state = cpu_to_le32(DAXFS_BRANCH_ABORTED);
		slot->generation = cpu_to_le32(
			le32_to_cpu(slot->generation) + 1);
	}

	/* Merge child's deltas into parent's log */
	ret = daxfs_delta_merge(parent, branch);
	if (ret)
		goto out_unlock;

	/* Update commit sequence */
	if (info->coord) {
		info->coord->commit_sequence = cpu_to_le64(
			le64_to_cpu(info->coord->commit_sequence) + 1);
		info->coord->last_committed_id = cpu_to_le64(branch->branch_id);
	}

	/* Mark branch as committed */
	branch->on_dax->state = cpu_to_le32(DAXFS_BRANCH_COMMITTED);
	memset(branch->on_dax->name, 0, sizeof(branch->on_dax->name));
	branch->committed = true;

	/* Decrement parent refcount */
	atomic_dec(&parent->refcount);
	parent->on_dax->refcount = cpu_to_le32(atomic_read(&parent->refcount));

	/* Update superblock */
	info->super->active_branches = cpu_to_le32(
		le32_to_cpu(info->super->active_branches) - 1);

	/* Remove from active list but don't free yet (still mounted) */
	list_del(&branch->list);
	INIT_LIST_HEAD(&branch->list);

	mutex_unlock(&info->branch_lock);
	if (info->coord)
		daxfs_coord_unlock(info);

	pr_info("daxfs: committed branch '%s' to '%s'\n",
		branch->name, parent->name);
	return 0;

out_unlock:
	mutex_unlock(&info->branch_lock);
	if (info->coord)
		daxfs_coord_unlock(info);
	return ret;
}

/*
 * Abort a branch (discard changes)
 *
 * Open files on this branch will receive SIGBUS on subsequent access
 * via the fault handler's branch validity check.
 */
int daxfs_branch_abort(struct daxfs_info *info,
		       struct daxfs_branch_ctx *branch)
{
	struct daxfs_branch_ctx *parent;

	mutex_lock(&info->branch_lock);

	/* Can't abort main branch */
	if (strcmp(branch->name, "main") == 0) {
		mutex_unlock(&info->branch_lock);
		return -EINVAL;
	}

	/* Check no active children */
	if (atomic_read(&branch->refcount) > 1) {
		mutex_unlock(&info->branch_lock);
		return -EBUSY;
	}

	parent = branch->parent;

	/* Mark as aborted, increment generation, and clear name */
	branch->on_dax->state = cpu_to_le32(DAXFS_BRANCH_ABORTED);
	branch->on_dax->generation = cpu_to_le32(
		le32_to_cpu(branch->on_dax->generation) + 1);
	memset(branch->on_dax->name, 0, sizeof(branch->on_dax->name));

	/* Decrement parent refcount */
	if (parent) {
		atomic_dec(&parent->refcount);
		parent->on_dax->refcount = cpu_to_le32(
			atomic_read(&parent->refcount));
	}

	/* Free delta log space using storage layer */
	daxfs_mem_free_region(info,
			      le64_to_cpu(branch->on_dax->delta_log_offset),
			      le64_to_cpu(branch->on_dax->delta_log_capacity));

	/* Update superblock */
	info->super->active_branches = cpu_to_le32(
		le32_to_cpu(info->super->active_branches) - 1);

	/* Remove from active list */
	if (!list_empty(&branch->list))
		list_del(&branch->list);

	mutex_unlock(&info->branch_lock);

	/* Destroy delta index */
	daxfs_delta_destroy_branch(branch);

	pr_info("daxfs: aborted branch '%s'\n", branch->name);

	kfree(branch);
	return 0;
}
