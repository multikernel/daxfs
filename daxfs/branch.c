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
#include <linux/mm.h>
#include "daxfs.h"

#define INITIAL_DELTA_SIZE	(1024 * 1024)	/* 1MB initial delta log */

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
 * Invalidate all DAX mappings for this mount.
 *
 * Called when the current branch becomes invalid (e.g., sibling committed).
 * Unmaps all file pages so next access will fault and get SIGBUS.
 */
void daxfs_invalidate_branch_mappings(struct daxfs_info *info)
{
	struct super_block *sb = info->sb;
	struct inode *inode;

	if (!sb)
		return;

	/*
	 * Iterate over all inodes and unmap their address spaces.
	 * This tears down existing PFN mappings, forcing new faults
	 * which will check branch validity and return SIGBUS.
	 */
	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (!S_ISREG(inode->i_mode))
			continue;

		spin_unlock(&sb->s_inode_list_lock);

		/* Unmap entire file range */
		unmap_mapping_range(inode->i_mapping, 0, 0, 1);

		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
}

/*
 * Find a branch by name in the active branches list (in-memory only)
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
 * Find a branch slot by name in the on-DAX branch table
 */
static struct daxfs_branch *find_branch_slot_by_name(struct daxfs_info *info,
						     const char *name)
{
	u32 i;

	for (i = 0; i < info->branch_table_entries; i++) {
		struct daxfs_branch *slot = &info->branch_table[i];
		u32 state = le32_to_cpu(slot->state);

		if (state == DAXFS_BRANCH_FREE)
			continue;
		if (state == DAXFS_BRANCH_COMMITTED)
			continue;
		if (strncmp(slot->name, name, sizeof(slot->name)) == 0)
			return slot;
	}
	return NULL;
}

/*
 * Find a branch slot by ID in the on-DAX branch table
 */
static struct daxfs_branch *find_branch_slot_by_id(struct daxfs_info *info,
						   u64 id)
{
	u32 i;

	for (i = 0; i < info->branch_table_entries; i++) {
		struct daxfs_branch *slot = &info->branch_table[i];
		u32 state = le32_to_cpu(slot->state);

		if (state == DAXFS_BRANCH_FREE)
			continue;
		if (le64_to_cpu(slot->branch_id) == id)
			return slot;
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
 * Load a branch from on-DAX table into active_branches.
 * Recursively loads parent chain if needed.
 * Caller must hold branch_lock.
 */
static struct daxfs_branch_ctx *load_branch_from_dax(struct daxfs_info *info,
						     struct daxfs_branch *slot)
{
	struct daxfs_branch_ctx *ctx;
	struct daxfs_branch_ctx *parent_ctx = NULL;
	u64 parent_id;
	int ret;

	/* Load parent first if exists */
	parent_id = le64_to_cpu(slot->parent_id);
	if (parent_id != 0) {
		struct daxfs_branch *parent_slot;

		parent_slot = find_branch_slot_by_id(info, parent_id);
		if (!parent_slot) {
			pr_err("daxfs: parent branch id %llu not found\n", parent_id);
			return ERR_PTR(-ENOENT);
		}

		/* Check if parent already loaded */
		parent_ctx = daxfs_find_branch_by_name(info, parent_slot->name);
		if (!parent_ctx) {
			parent_ctx = load_branch_from_dax(info, parent_slot);
			if (IS_ERR(parent_ctx))
				return parent_ctx;
		}
	}

	/* Create runtime context */
	ctx = alloc_branch_ctx();
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	/* Populate from on-DAX data */
	ctx->info = info;
	ctx->branch_id = le64_to_cpu(slot->branch_id);
	strscpy(ctx->name, slot->name, sizeof(ctx->name));
	ctx->on_dax = slot;
	ctx->parent = parent_ctx;
	ctx->delta_log = daxfs_mem_ptr(info, le64_to_cpu(slot->delta_log_offset));
	ctx->delta_size = le64_to_cpu(slot->delta_log_size);
	ctx->delta_capacity = le64_to_cpu(slot->delta_log_capacity);
	ctx->next_ino = le64_to_cpu(slot->next_local_ino);

	/* Initialize delta index */
	ret = daxfs_delta_init_branch(info, ctx);
	if (ret) {
		kfree(ctx);
		return ERR_PTR(ret);
	}

	/* Increment parent refcount */
	if (parent_ctx)
		atomic_inc(&parent_ctx->refcount);

	list_add(&ctx->list, &info->active_branches);

	pr_info("daxfs: loaded branch '%s' from DAX\n", ctx->name);
	return ctx;
}

/*
 * Find or load a branch by name.
 * First checks active_branches, then loads from on-DAX if needed.
 * Caller must hold branch_lock.
 */
static struct daxfs_branch_ctx *find_or_load_branch(struct daxfs_info *info,
						    const char *name)
{
	struct daxfs_branch_ctx *ctx;
	struct daxfs_branch *slot;

	/* Check if already loaded */
	ctx = daxfs_find_branch_by_name(info, name);
	if (ctx)
		return ctx;

	/* Find in on-DAX table */
	slot = find_branch_slot_by_name(info, name);
	if (!slot)
		return NULL;

	/* Load from DAX */
	return load_branch_from_dax(info, slot);
}

/*
 * Initialize or load the "main" branch
 */
int daxfs_init_main_branch(struct daxfs_info *info)
{
	struct daxfs_branch *slot;
	struct daxfs_branch_ctx *ctx;
	u64 delta_offset;
	int ret;

	mutex_lock(&info->branch_lock);

	/* Check if main already loaded in memory */
	if (daxfs_find_branch_by_name(info, "main")) {
		mutex_unlock(&info->branch_lock);
		return 0;
	}

	/* Check if main exists in on-DAX table */
	slot = find_branch_slot_by_name(info, "main");
	if (slot) {
		/* Load existing main from DAX */
		ctx = load_branch_from_dax(info, slot);
		mutex_unlock(&info->branch_lock);
		return IS_ERR(ctx) ? PTR_ERR(ctx) : 0;
	}

	/* Main doesn't exist - create it */
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
 * Load an existing branch by name.
 * Loads from on-DAX table if not already in active_branches.
 * Also loads parent chain.
 */
struct daxfs_branch_ctx *daxfs_load_branch(struct daxfs_info *info,
					   const char *name)
{
	struct daxfs_branch_ctx *ctx;

	mutex_lock(&info->branch_lock);
	ctx = find_or_load_branch(info, name);
	if (ctx && !IS_ERR(ctx))
		atomic_inc(&ctx->refcount);
	mutex_unlock(&info->branch_lock);

	return ctx;
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

	/* Check name not already in use (in-memory or on-DAX) */
	if (daxfs_find_branch_by_name(info, name) ||
	    find_branch_slot_by_name(info, name)) {
		mutex_unlock(&info->branch_lock);
		return -EEXIST;
	}

	/* Find parent by name (load from on-DAX if needed) */
	parent = find_or_load_branch(info, parent_name);
	if (!parent) {
		mutex_unlock(&info->branch_lock);
		return -ENOENT;
	}
	if (IS_ERR(parent)) {
		mutex_unlock(&info->branch_lock);
		return PTR_ERR(parent);
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
 * Invalidate all sibling branches (same parent) in on-DAX table.
 * This affects branches mounted by other processes too.
 */
static void invalidate_siblings(struct daxfs_info *info,
				struct daxfs_branch_ctx *branch)
{
	struct daxfs_branch_ctx *sibling;
	u64 parent_id = le64_to_cpu(branch->on_dax->parent_id);
	u32 i;

	/* Invalidate siblings in our active_branches list */
	list_for_each_entry(sibling, &info->active_branches, list) {
		if (sibling == branch)
			continue;
		if (le64_to_cpu(sibling->on_dax->parent_id) != parent_id)
			continue;

		sibling->on_dax->state = cpu_to_le32(DAXFS_BRANCH_ABORTED);
		sibling->on_dax->generation = cpu_to_le32(
			le32_to_cpu(sibling->on_dax->generation) + 1);

		pr_info("daxfs: invalidated sibling branch '%s'\n",
			sibling->name);
	}

	/* Invalidate siblings in on-DAX table (for other mounts) */
	for (i = 0; i < info->branch_table_entries; i++) {
		struct daxfs_branch *slot = &info->branch_table[i];
		u32 state = le32_to_cpu(slot->state);

		if (state != DAXFS_BRANCH_ACTIVE)
			continue;
		if (le64_to_cpu(slot->branch_id) == branch->branch_id)
			continue;
		if (le64_to_cpu(slot->parent_id) != parent_id)
			continue;

		slot->state = cpu_to_le32(DAXFS_BRANCH_ABORTED);
		slot->generation = cpu_to_le32(
			le32_to_cpu(slot->generation) + 1);
	}
}

/*
 * Commit a branch to main (root)
 *
 * Merges deltas from the committing branch all the way up to main.
 * Invalidates all sibling branches at every level.
 * All intermediate branches are marked as committed.
 */
int daxfs_branch_commit(struct daxfs_info *info,
			struct daxfs_branch_ctx *branch)
{
	struct daxfs_branch_ctx *cur, *parent;
	int ret;
	int committed_count = 0;

	/* Acquire global coordination lock */
	if (info->coord)
		daxfs_coord_lock(info);
	mutex_lock(&info->branch_lock);

	/* Check branch wasn't invalidated by concurrent commit */
	if (le32_to_cpu(READ_ONCE(branch->on_dax->state)) != DAXFS_BRANCH_ACTIVE) {
		ret = -ESTALE;
		goto out_unlock;
	}

	/* Can't commit main branch */
	if (strcmp(branch->name, "main") == 0) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (!branch->parent) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Check no active children on the committing branch */
	if (atomic_read(&branch->refcount) > 1) {
		ret = -EBUSY;
		goto out_unlock;
	}

	/*
	 * Walk up the parent chain to main, merging deltas at each level.
	 * Start from the committing branch, merge into parent, repeat.
	 */
	cur = branch;
	while (cur->parent != NULL) {
		parent = cur->parent;

		/* Invalidate all siblings at this level */
		invalidate_siblings(info, cur);

		/* Merge cur's deltas into parent */
		ret = daxfs_delta_merge(parent, cur);
		if (ret) {
			pr_err("daxfs: failed to merge '%s' into '%s'\n",
			       cur->name, parent->name);
			goto out_unlock;
		}

		/* Mark cur as committed */
		cur->on_dax->state = cpu_to_le32(DAXFS_BRANCH_COMMITTED);
		memset(cur->on_dax->name, 0, sizeof(cur->on_dax->name));
		cur->committed = true;

		/* Decrement parent refcount */
		atomic_dec(&parent->refcount);
		parent->on_dax->refcount = cpu_to_le32(
			atomic_read(&parent->refcount));

		/* Update superblock */
		info->super->active_branches = cpu_to_le32(
			le32_to_cpu(info->super->active_branches) - 1);

		/* Remove from active list */
		if (!list_empty(&cur->list)) {
			list_del(&cur->list);
			INIT_LIST_HEAD(&cur->list);
		}

		committed_count++;
		pr_info("daxfs: merged '%s' into '%s'\n",
			cur->name, parent->name);

		/* Move up to parent for next iteration */
		cur = parent;
	}

	/* Update commit sequence */
	if (info->coord) {
		info->coord->commit_sequence = cpu_to_le64(
			le64_to_cpu(info->coord->commit_sequence) + 1);
		info->coord->last_committed_id = cpu_to_le64(branch->branch_id);
	}

	mutex_unlock(&info->branch_lock);
	if (info->coord)
		daxfs_coord_unlock(info);

	pr_info("daxfs: committed %d branch(es) to main\n", committed_count);
	return 0;

out_unlock:
	mutex_unlock(&info->branch_lock);
	if (info->coord)
		daxfs_coord_unlock(info);
	return ret;
}

/*
 * Abort a single branch level (internal helper)
 * Caller must hold branch_lock.
 */
static void abort_single_branch_locked(struct daxfs_info *info,
				       struct daxfs_branch_ctx *branch)
{
	/* Mark as aborted, increment generation, and clear name */
	branch->on_dax->state = cpu_to_le32(DAXFS_BRANCH_ABORTED);
	branch->on_dax->generation = cpu_to_le32(
		le32_to_cpu(branch->on_dax->generation) + 1);
	memset(branch->on_dax->name, 0, sizeof(branch->on_dax->name));

	/* Free delta log space */
	daxfs_mem_free_region(info,
			      le64_to_cpu(branch->on_dax->delta_log_offset),
			      le64_to_cpu(branch->on_dax->delta_log_capacity));

	/* Update superblock */
	info->super->active_branches = cpu_to_le32(
		le32_to_cpu(info->super->active_branches) - 1);

	/* Remove from active list */
	if (!list_empty(&branch->list))
		list_del(&branch->list);

	pr_info("daxfs: aborted branch '%s'\n", branch->name);
}

/*
 * Abort a single branch (used by unmount)
 * Only aborts the current branch, parent chain remains.
 */
int daxfs_branch_abort_single(struct daxfs_info *info,
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

	/* Decrement parent refcount */
	if (parent) {
		atomic_dec(&parent->refcount);
		parent->on_dax->refcount = cpu_to_le32(
			atomic_read(&parent->refcount));
	}

	abort_single_branch_locked(info, branch);

	mutex_unlock(&info->branch_lock);

	/* Destroy delta index and free memory */
	daxfs_delta_destroy_branch(branch);
	kfree(branch);

	return 0;
}

/*
 * Abort an entire branch chain (discard all changes back to main)
 *
 * Walks up from the current branch to main, aborting each level.
 * This discards the entire speculation chain.
 *
 * Note: Unmount only aborts the current level (one branch).
 * Abort via remount discards the entire chain.
 */
int daxfs_branch_abort(struct daxfs_info *info,
		       struct daxfs_branch_ctx *branch)
{
	struct daxfs_branch_ctx *cur, *parent;
	struct daxfs_branch_ctx *to_free[32];  /* Max depth */
	int free_count = 0;
	int i;

	mutex_lock(&info->branch_lock);

	/* Can't abort main branch */
	if (strcmp(branch->name, "main") == 0) {
		mutex_unlock(&info->branch_lock);
		return -EINVAL;
	}

	/* Check no active children on the starting branch */
	if (atomic_read(&branch->refcount) > 1) {
		mutex_unlock(&info->branch_lock);
		return -EBUSY;
	}

	/*
	 * Walk up the parent chain to main, aborting each branch.
	 */
	cur = branch;
	while (cur != NULL && strcmp(cur->name, "main") != 0) {
		parent = cur->parent;

		/* Decrement parent refcount */
		if (parent) {
			atomic_dec(&parent->refcount);
			parent->on_dax->refcount = cpu_to_le32(
				atomic_read(&parent->refcount));
		}

		/* Abort this branch */
		abort_single_branch_locked(info, cur);

		/* Save for later cleanup (after releasing lock) */
		if (free_count < 32)
			to_free[free_count++] = cur;

		cur = parent;
	}

	mutex_unlock(&info->branch_lock);

	/* Destroy delta indexes and free memory */
	for (i = 0; i < free_count; i++) {
		daxfs_delta_destroy_branch(to_free[i]);
		kfree(to_free[i]);
	}

	pr_info("daxfs: aborted %d branch(es)\n", free_count);
	return 0;
}
