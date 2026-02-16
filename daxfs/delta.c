// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs delta log operations
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rbtree.h>
#include <linux/jhash.h>
#include "daxfs.h"

/*
 * Simple hash for directory entry lookup
 */
static u32 dirent_hash(u64 parent_ino, const char *name, int namelen)
{
	u32 hash = jhash(name, namelen, (u32)parent_ino);
	return hash ^ (parent_ino >> 32);
}

/*
 * Initialize delta log for a branch
 */
int daxfs_delta_init_branch(struct daxfs_info *info,
			    struct daxfs_branch_ctx *branch)
{
	/* Nothing special needed - rb_trees already initialized */
	(void)info;
	(void)branch;
	return 0;
}

/*
 * Free all index entries for a branch
 */
static void free_inode_index(struct daxfs_branch_ctx *branch)
{
	struct rb_node *node;
	struct daxfs_delta_inode_entry *entry;

	while ((node = rb_first(&branch->inode_index)) != NULL) {
		struct daxfs_write_extent *extent, *tmp;

		entry = rb_entry(node, struct daxfs_delta_inode_entry, rb_node);

		/* Free all write extents for this inode */
		list_for_each_entry_safe(extent, tmp, &entry->write_extents, list) {
			list_del(&extent->list);
			kfree(extent);
		}

		rb_erase(node, &branch->inode_index);
		kfree(entry);
	}
}

static void free_dirent_index(struct daxfs_branch_ctx *branch)
{
	struct rb_node *node;
	struct daxfs_delta_dirent_entry *entry;

	while ((node = rb_first(&branch->dirent_index)) != NULL) {
		entry = rb_entry(node, struct daxfs_delta_dirent_entry, rb_node);
		rb_erase(node, &branch->dirent_index);
		kfree(entry->name);
		kfree(entry);
	}
}

/*
 * Destroy delta log state for a branch
 */
void daxfs_delta_destroy_branch(struct daxfs_branch_ctx *branch)
{
	unsigned long flags;

	spin_lock_irqsave(&branch->index_lock, flags);
	free_inode_index(branch);
	free_dirent_index(branch);
	spin_unlock_irqrestore(&branch->index_lock, flags);
}

/*
 * Allocate space in branch's delta log
 */
void *daxfs_delta_alloc(struct daxfs_info *info,
			struct daxfs_branch_ctx *branch, size_t size)
{
	void *ptr;
	u64 new_size;

	spin_lock(&info->alloc_lock);

	new_size = branch->delta_size + size;
	if (new_size > branch->delta_capacity) {
		spin_unlock(&info->alloc_lock);
		pr_err("daxfs: delta log full for branch '%s'\n", branch->name);
		return NULL;
	}

	ptr = branch->delta_log + branch->delta_size;
	branch->delta_size = new_size;
	branch->on_dax->delta_log_size = cpu_to_le64(new_size);

	spin_unlock(&info->alloc_lock);

	return ptr;
}

/*
 * Allocate space in branch's delta log with page-aligned data area.
 * Used for mmap extents where the data must be page-aligned for PFN mapping.
 *
 * @header_size: size of headers before data
 * @data_size: size of data (should be PAGE_SIZE for mmap)
 * @data_out: returns pointer to page-aligned data area
 * @total_out: if non-NULL, returns total allocation size (for delta header)
 *
 * Returns pointer to start of entry (headers), or NULL on failure.
 */
void *daxfs_delta_alloc_mmap(struct daxfs_info *info,
			     struct daxfs_branch_ctx *branch,
			     size_t header_size, size_t data_size,
			     void **data_out, size_t *total_out)
{
	void *ptr;
	void *data_start;
	size_t padding;
	size_t total_size;
	u64 new_size;

	spin_lock(&info->alloc_lock);

	ptr = branch->delta_log + branch->delta_size;
	data_start = ptr + header_size;

	padding = PAGE_ALIGN((unsigned long)data_start) - (unsigned long)data_start;

	total_size = header_size + padding + data_size;
	new_size = branch->delta_size + total_size;

	if (new_size > branch->delta_capacity) {
		spin_unlock(&info->alloc_lock);
		pr_err("daxfs: delta log full for branch '%s'\n", branch->name);
		return NULL;
	}

	branch->delta_size = new_size;
	branch->on_dax->delta_log_size = cpu_to_le64(new_size);

	spin_unlock(&info->alloc_lock);

	*data_out = ptr + header_size + padding;
	if (total_out)
		*total_out = total_size;
	return ptr;
}

/*
 * Get base image nlink for an inode.
 * Returns 0 if inode is not in base image (delta-created).
 */
static u32 get_base_nlink(struct daxfs_info *info, u64 ino)
{
	if (info->base_inodes && ino <= info->base_inode_count)
		return le32_to_cpu(info->base_inodes[ino - 1].nlink);
	return 0;
}

/*
 * Find or create inode index entry (caller must hold index_lock)
 * Returns entry on success, NULL on allocation failure
 */
static struct daxfs_delta_inode_entry *find_or_create_inode_entry(
	struct daxfs_branch_ctx *branch, u64 ino,
	struct rb_node **parent_out, struct rb_node ***link_out)
{
	struct rb_node **link = &branch->inode_index.rb_node;
	struct rb_node *parent = NULL;
	struct daxfs_delta_inode_entry *entry;

	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct daxfs_delta_inode_entry, rb_node);

		if (ino < entry->ino)
			link = &parent->rb_left;
		else if (ino > entry->ino)
			link = &parent->rb_right;
		else
			return entry;
	}

	/* Not found - create new entry */
	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	entry->ino = ino;
	entry->base_nlink = get_base_nlink(branch->info, ino);
	INIT_LIST_HEAD(&entry->write_extents);

	*parent_out = parent;
	*link_out = link;
	return entry;
}

/*
 * Update inode entry and insert into tree if new
 */
static void update_inode_entry(struct daxfs_branch_ctx *branch,
			       struct daxfs_delta_inode_entry *entry,
			       struct rb_node *parent, struct rb_node **link)
{
	entry->deleted = (entry->base_nlink + entry->nlink_delta <= 0);

	if (link) {
		rb_link_node(&entry->rb_node, parent, link);
		rb_insert_color(&entry->rb_node, &branch->inode_index);
	}
}

static void init_entry_from_base(struct daxfs_branch_ctx *branch,
				 struct daxfs_delta_inode_entry *entry,
				 u64 ino, struct rb_node **link)
{
	struct daxfs_info *info = branch->info;

	if (link && entry->mode == 0 && info->base_inodes &&
	    ino <= info->base_inode_count) {
		struct daxfs_base_inode *raw = &info->base_inodes[ino - 1];
		entry->mode = le32_to_cpu(raw->mode);
		entry->uid = le32_to_cpu(raw->uid);
		entry->gid = le32_to_cpu(raw->gid);
	}
}

static int index_inode_create(struct daxfs_branch_ctx *branch, u64 ino,
			      struct daxfs_delta_hdr *hdr, u64 size,
			      u32 mode, u32 uid, u32 gid, char *symlink_target)
{
	struct daxfs_delta_inode_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **link = NULL;
	unsigned long flags;

	spin_lock_irqsave(&branch->index_lock, flags);

	entry = find_or_create_inode_entry(branch, ino, &parent, &link);
	if (!entry) {
		spin_unlock_irqrestore(&branch->index_lock, flags);
		return -ENOMEM;
	}

	entry->hdr = hdr;
	entry->size = size;
	entry->mode = mode;
	entry->uid = uid;
	entry->gid = gid;
	entry->symlink_target = symlink_target;

	update_inode_entry(branch, entry, parent, link);
	spin_unlock_irqrestore(&branch->index_lock, flags);
	return 0;
}

static int index_inode_unlink(struct daxfs_branch_ctx *branch, u64 ino,
			      struct daxfs_delta_hdr *hdr)
{
	struct daxfs_delta_inode_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **link = NULL;
	unsigned long flags;

	spin_lock_irqsave(&branch->index_lock, flags);

	entry = find_or_create_inode_entry(branch, ino, &parent, &link);
	if (!entry) {
		spin_unlock_irqrestore(&branch->index_lock, flags);
		return -ENOMEM;
	}

	entry->hdr = hdr;
	entry->nlink_delta--;
	init_entry_from_base(branch, entry, ino, link);

	update_inode_entry(branch, entry, parent, link);
	spin_unlock_irqrestore(&branch->index_lock, flags);
	return 0;
}

static int index_inode_set_size(struct daxfs_branch_ctx *branch, u64 ino,
				struct daxfs_delta_hdr *hdr, u64 size)
{
	struct daxfs_delta_inode_entry *entry;
	struct rb_node *parent = NULL;
	struct rb_node **link = NULL;
	unsigned long flags;

	spin_lock_irqsave(&branch->index_lock, flags);

	entry = find_or_create_inode_entry(branch, ino, &parent, &link);
	if (!entry) {
		spin_unlock_irqrestore(&branch->index_lock, flags);
		return -ENOMEM;
	}

	entry->hdr = hdr;
	entry->size = size;
	init_entry_from_base(branch, entry, ino, link);

	update_inode_entry(branch, entry, parent, link);
	spin_unlock_irqrestore(&branch->index_lock, flags);
	return 0;
}

static int index_inode_setattr(struct daxfs_branch_ctx *branch, u64 ino,
			       struct daxfs_delta_hdr *hdr,
			       u64 size, u32 mode, u32 uid, u32 gid)
{
	struct daxfs_delta_inode_entry *entry;
	struct daxfs_info *info = branch->info;
	struct rb_node *parent = NULL;
	struct rb_node **link = NULL;
	unsigned long flags;

	spin_lock_irqsave(&branch->index_lock, flags);

	entry = find_or_create_inode_entry(branch, ino, &parent, &link);
	if (!entry) {
		spin_unlock_irqrestore(&branch->index_lock, flags);
		return -ENOMEM;
	}

	init_entry_from_base(branch, entry, ino, link);
	/* Size needs special handling since 0 is a valid size */
	if (link && size == (u64)-1 && info->base_inodes &&
	    ino <= info->base_inode_count) {
		struct daxfs_base_inode *raw = &info->base_inodes[ino - 1];
		entry->size = le64_to_cpu(raw->size);
	}

	entry->hdr = hdr;
	if (size != (u64)-1)
		entry->size = size;
	if (mode != (u32)-1)
		entry->mode = mode;
	if (uid != (u32)-1)
		entry->uid = uid;
	if (gid != (u32)-1)
		entry->gid = gid;

	update_inode_entry(branch, entry, parent, link);
	spin_unlock_irqrestore(&branch->index_lock, flags);
	return 0;
}

/*
 * Find inode entry in index (caller must hold index_lock)
 */
static struct daxfs_delta_inode_entry *find_inode_entry_locked(
	struct daxfs_branch_ctx *branch, u64 ino)
{
	struct rb_node *node = branch->inode_index.rb_node;

	while (node) {
		struct daxfs_delta_inode_entry *entry =
			rb_entry(node, struct daxfs_delta_inode_entry, rb_node);

		if (ino < entry->ino)
			node = node->rb_left;
		else if (ino > entry->ino)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

/*
 * Add a write extent to an inode's extent list
 * Prepends to list so newest writes are first (for fast lookup)
 */
int daxfs_index_add_write_extent(struct daxfs_branch_ctx *branch, u64 ino,
				 u64 offset, u32 len, void *data)
{
	struct daxfs_delta_inode_entry *ie;
	struct daxfs_write_extent *extent;
	unsigned long flags;

	extent = kzalloc(sizeof(*extent), GFP_ATOMIC);
	if (!extent)
		return -ENOMEM;

	extent->offset = offset;
	extent->len = len;
	extent->data = data;

	spin_lock_irqsave(&branch->index_lock, flags);

	ie = find_inode_entry_locked(branch, ino);
	if (!ie) {
		spin_unlock_irqrestore(&branch->index_lock, flags);
		kfree(extent);
		return -ENOENT;
	}

	/* Prepend - newest writes first for fast lookup */
	list_add(&extent->list, &ie->write_extents);

	spin_unlock_irqrestore(&branch->index_lock, flags);
	return 0;
}

/*
 * Insert or update dirent index entry
 */
static int index_add_dirent(struct daxfs_branch_ctx *branch, u64 parent_ino,
			    const char *name, int namelen,
			    struct daxfs_delta_hdr *hdr, bool deleted)
{
	struct rb_node **link = &branch->dirent_index.rb_node;
	struct rb_node *parent = NULL;
	struct daxfs_delta_dirent_entry *entry;
	u32 hash = dirent_hash(parent_ino, name, namelen);
	u64 key;
	unsigned long flags;

	/* Combined key: parent_ino in upper bits, hash in lower */
	key = (parent_ino << 32) | hash;

	spin_lock_irqsave(&branch->index_lock, flags);

	while (*link) {
		u64 entry_key;

		parent = *link;
		entry = rb_entry(parent, struct daxfs_delta_dirent_entry, rb_node);
		entry_key = ((u64)entry->parent_ino << 32) | entry->name_hash;

		if (key < entry_key) {
			link = &parent->rb_left;
		} else if (key > entry_key) {
			link = &parent->rb_right;
		} else {
			/* Same hash - check actual name */
			if (namelen == entry->name_len &&
			    memcmp(name, entry->name, namelen) == 0) {
				/* Update existing entry */
				entry->hdr = hdr;
				entry->deleted = deleted;
				spin_unlock_irqrestore(&branch->index_lock, flags);
				return 0;
			}
			/* Hash collision - use right subtree */
			link = &parent->rb_right;
		}
	}

	/* Create new entry */
	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_irqrestore(&branch->index_lock, flags);
		return -ENOMEM;
	}

	entry->parent_ino = parent_ino;
	entry->name_hash = hash;
	entry->name = kmemdup(name, namelen, GFP_ATOMIC);
	if (!entry->name) {
		kfree(entry);
		spin_unlock_irqrestore(&branch->index_lock, flags);
		return -ENOMEM;
	}
	entry->name_len = namelen;
	entry->hdr = hdr;
	entry->deleted = deleted;

	rb_link_node(&entry->rb_node, parent, link);
	rb_insert_color(&entry->rb_node, &branch->dirent_index);

	spin_unlock_irqrestore(&branch->index_lock, flags);
	return 0;
}

/*
 * Append entry to branch's delta log
 */
int daxfs_delta_append(struct daxfs_branch_ctx *branch, u32 type,
		       u64 ino, void *data, size_t data_len)
{
	struct daxfs_info *info = branch->info;
	struct daxfs_delta_hdr *hdr;
	size_t total_size;
	void *entry;

	total_size = sizeof(*hdr) + data_len;
	entry = daxfs_delta_alloc(info, branch, total_size);
	if (!entry)
		return -ENOSPC;

	hdr = entry;
	hdr->type = cpu_to_le32(type);
	hdr->total_size = cpu_to_le32(total_size);
	hdr->ino = cpu_to_le64(ino);
	hdr->timestamp = cpu_to_le64(ktime_get_real_ns());

	if (data && data_len)
		memcpy(entry + sizeof(*hdr), data, data_len);

	/* Update index based on entry type */
	switch (type) {
	case DAXFS_DELTA_CREATE:
	case DAXFS_DELTA_MKDIR: {
		struct daxfs_delta_create *cr = entry + sizeof(*hdr);
		char *name = (char *)(cr + 1);
		u64 new_ino = le64_to_cpu(cr->new_ino);
		u64 parent_ino = le64_to_cpu(cr->parent_ino);
		u32 mode = le32_to_cpu(cr->mode);
		u32 uid = le32_to_cpu(cr->uid);
		u32 gid = le32_to_cpu(cr->gid);
		u16 name_len = le16_to_cpu(cr->name_len);

		index_inode_create(branch, new_ino, hdr, 0, mode, uid, gid, NULL);
		index_add_dirent(branch, parent_ino, name, name_len, hdr, false);
		break;
	}
	case DAXFS_DELTA_DELETE: {
		struct daxfs_delta_delete *del = entry + sizeof(*hdr);
		char *name = (char *)(del + 1);
		u64 parent_ino = le64_to_cpu(del->parent_ino);
		u16 name_len = le16_to_cpu(del->name_len);

		index_inode_unlink(branch, ino, hdr);
		index_add_dirent(branch, parent_ino, name, name_len, hdr, true);
		break;
	}
	case DAXFS_DELTA_TRUNCATE: {
		struct daxfs_delta_truncate *tr = entry + sizeof(*hdr);
		u64 new_size = le64_to_cpu(tr->new_size);

		index_inode_set_size(branch, ino, hdr, new_size);
		break;
	}
	case DAXFS_DELTA_WRITE: {
		struct daxfs_delta_write *wr = entry + sizeof(*hdr);
		u64 wr_offset = le64_to_cpu(wr->offset);
		u32 wr_len = le32_to_cpu(wr->len);
		u64 end = wr_offset + wr_len;
		void *wr_data = (void *)(wr + 1);

		index_inode_set_size(branch, ino, hdr, end);
		daxfs_index_add_write_extent(branch, ino, wr_offset, wr_len, wr_data);
		break;
	}
	case DAXFS_DELTA_SETATTR: {
		struct daxfs_delta_setattr *sa = entry + sizeof(*hdr);
		u32 valid = le32_to_cpu(sa->valid);
		u64 size = (valid & DAXFS_ATTR_SIZE) ?
			   le64_to_cpu(sa->size) : (u64)-1;
		u32 mode = (valid & DAXFS_ATTR_MODE) ?
			   le32_to_cpu(sa->mode) : (u32)-1;
		u32 uid = (valid & DAXFS_ATTR_UID) ?
			  le32_to_cpu(sa->uid) : (u32)-1;
		u32 gid = (valid & DAXFS_ATTR_GID) ?
			  le32_to_cpu(sa->gid) : (u32)-1;

		index_inode_setattr(branch, ino, hdr, size, mode, uid, gid);
		break;
	}
	case DAXFS_DELTA_SYMLINK: {
		struct daxfs_delta_symlink *sl = entry + sizeof(*hdr);
		char *name = (char *)(sl + 1);
		char *target = name + le16_to_cpu(sl->name_len);
		u64 new_ino = le64_to_cpu(sl->new_ino);
		u64 parent_ino = le64_to_cpu(sl->parent_ino);
		u32 uid = le32_to_cpu(sl->uid);
		u32 gid = le32_to_cpu(sl->gid);
		u16 name_len = le16_to_cpu(sl->name_len);
		u16 target_len = le16_to_cpu(sl->target_len);

		index_inode_create(branch, new_ino, hdr, target_len,
				   S_IFLNK | 0777, uid, gid, target);
		index_add_dirent(branch, parent_ino, name, name_len, hdr, false);
		break;
	}
	case DAXFS_DELTA_RENAME: {
		struct daxfs_delta_rename *rn = entry + sizeof(*hdr);
		char *old_name = (char *)(rn + 1);
		char *new_name = old_name + le16_to_cpu(rn->old_name_len);
		u64 old_parent = le64_to_cpu(rn->old_parent_ino);
		u64 new_parent = le64_to_cpu(rn->new_parent_ino);

		/* Delete from old location */
		index_add_dirent(branch, old_parent, old_name,
				 le16_to_cpu(rn->old_name_len), hdr, true);
		/* Add at new location */
		index_add_dirent(branch, new_parent, new_name,
				 le16_to_cpu(rn->new_name_len), hdr, false);
		break;
	}
	}

	return 0;
}

/*
 * Validate a delta log entry header and return minimum required size
 * Returns 0 if invalid, otherwise the minimum entry size for this type
 */
static size_t daxfs_delta_entry_min_size(u32 type)
{
	switch (type) {
	case DAXFS_DELTA_WRITE:
		return sizeof(struct daxfs_delta_hdr) +
		       sizeof(struct daxfs_delta_write);
	case DAXFS_DELTA_CREATE:
	case DAXFS_DELTA_MKDIR:
		return sizeof(struct daxfs_delta_hdr) +
		       sizeof(struct daxfs_delta_create);
	case DAXFS_DELTA_DELETE:
		return sizeof(struct daxfs_delta_hdr) +
		       sizeof(struct daxfs_delta_delete);
	case DAXFS_DELTA_TRUNCATE:
		return sizeof(struct daxfs_delta_hdr) +
		       sizeof(struct daxfs_delta_truncate);
	case DAXFS_DELTA_RENAME:
		return sizeof(struct daxfs_delta_hdr) +
		       sizeof(struct daxfs_delta_rename);
	case DAXFS_DELTA_SETATTR:
		return sizeof(struct daxfs_delta_hdr) +
		       sizeof(struct daxfs_delta_setattr);
	case DAXFS_DELTA_SYMLINK:
		return sizeof(struct daxfs_delta_hdr) +
		       sizeof(struct daxfs_delta_symlink);
	default:
		return 0;  /* Unknown type */
	}
}

/*
 * Validate a delta log entry
 * Returns 0 on success, -errno on error
 */
static int daxfs_validate_delta_entry(struct daxfs_branch_ctx *branch,
				      u64 offset, struct daxfs_delta_hdr *hdr)
{
	u32 type = le32_to_cpu(hdr->type);
	u32 total_size = le32_to_cpu(hdr->total_size);
	size_t min_size;

	/* Validate total_size is at least header size */
	if (total_size < sizeof(struct daxfs_delta_hdr)) {
		pr_err("daxfs: delta entry at offset %llu has invalid size %u\n",
		       offset, total_size);
		return -EINVAL;
	}

	/* Validate entry doesn't overflow the log */
	if (offset + total_size > branch->delta_capacity) {
		pr_err("daxfs: delta entry at offset %llu exceeds log capacity\n",
		       offset);
		return -EINVAL;
	}

	/* Validate minimum size for this entry type */
	min_size = daxfs_delta_entry_min_size(type);
	if (min_size == 0) {
		pr_err("daxfs: delta entry at offset %llu has unknown type %u\n",
		       offset, type);
		return -EINVAL;
	}

	if (total_size < min_size) {
		pr_err("daxfs: delta entry at offset %llu too small for type %u\n",
		       offset, type);
		return -EINVAL;
	}

	/* Type-specific validation */
	switch (type) {
	case DAXFS_DELTA_WRITE: {
		struct daxfs_delta_write *wr = (void *)hdr + sizeof(*hdr);
		u32 data_len = le32_to_cpu(wr->len);

		if (total_size < min_size + data_len) {
			pr_err("daxfs: WRITE entry at offset %llu truncated\n", offset);
			return -EINVAL;
		}
		break;
	}
	case DAXFS_DELTA_CREATE:
	case DAXFS_DELTA_MKDIR: {
		struct daxfs_delta_create *cr = (void *)hdr + sizeof(*hdr);
		u16 name_len = le16_to_cpu(cr->name_len);

		if (total_size < min_size + name_len) {
			pr_err("daxfs: CREATE/MKDIR entry at offset %llu truncated\n", offset);
			return -EINVAL;
		}
		break;
	}
	case DAXFS_DELTA_DELETE: {
		struct daxfs_delta_delete *del = (void *)hdr + sizeof(*hdr);
		u16 name_len = le16_to_cpu(del->name_len);

		if (total_size < min_size + name_len) {
			pr_err("daxfs: DELETE entry at offset %llu truncated\n", offset);
			return -EINVAL;
		}
		break;
	}
	case DAXFS_DELTA_RENAME: {
		struct daxfs_delta_rename *rn = (void *)hdr + sizeof(*hdr);
		u16 old_name_len = le16_to_cpu(rn->old_name_len);
		u16 new_name_len = le16_to_cpu(rn->new_name_len);

		if (total_size < min_size + old_name_len + new_name_len) {
			pr_err("daxfs: RENAME entry at offset %llu truncated\n", offset);
			return -EINVAL;
		}
		break;
	}
	case DAXFS_DELTA_SYMLINK: {
		struct daxfs_delta_symlink *sl = (void *)hdr + sizeof(*hdr);
		u16 name_len = le16_to_cpu(sl->name_len);
		u16 target_len = le16_to_cpu(sl->target_len);

		if (total_size < min_size + name_len + target_len + 1) {
			pr_err("daxfs: SYMLINK entry at offset %llu truncated\n", offset);
			return -EINVAL;
		}
		break;
	}
	}

	return 0;
}

/*
 * Scan delta log and build in-memory index
 */
int daxfs_delta_build_index(struct daxfs_branch_ctx *branch)
{
	struct daxfs_delta_hdr *hdr;
	u64 offset = 0;
	int ret;

	/* First, build parent's index if needed */
	if (branch->parent && rb_first(&branch->parent->inode_index) == NULL) {
		ret = daxfs_delta_build_index(branch->parent);
		if (ret)
			return ret;
	}

	/* Scan this branch's delta log */
	while (offset < branch->delta_size) {
		u32 type, total_size;

		hdr = branch->delta_log + offset;
		type = le32_to_cpu(hdr->type);
		total_size = le32_to_cpu(hdr->total_size);

		if (total_size == 0)
			break;

		/* Validate entry before processing */
		ret = daxfs_validate_delta_entry(branch, offset, hdr);
		if (ret)
			return ret;

		/* Index this entry based on type */
		switch (type) {
		case DAXFS_DELTA_CREATE:
		case DAXFS_DELTA_MKDIR: {
			struct daxfs_delta_create *cr =
				(void *)hdr + sizeof(*hdr);
			char *name = (char *)(cr + 1);

			index_inode_create(branch, le64_to_cpu(cr->new_ino), hdr,
					   0, le32_to_cpu(cr->mode),
					   le32_to_cpu(cr->uid),
					   le32_to_cpu(cr->gid), NULL);
			index_add_dirent(branch, le64_to_cpu(cr->parent_ino),
					 name, le16_to_cpu(cr->name_len),
					 hdr, false);
			break;
		}
		case DAXFS_DELTA_DELETE: {
			struct daxfs_delta_delete *del =
				(void *)hdr + sizeof(*hdr);
			char *name = (char *)(del + 1);

			index_inode_unlink(branch, le64_to_cpu(hdr->ino), hdr);
			index_add_dirent(branch, le64_to_cpu(del->parent_ino),
					 name, le16_to_cpu(del->name_len),
					 hdr, true);
			break;
		}
		case DAXFS_DELTA_TRUNCATE: {
			struct daxfs_delta_truncate *tr =
				(void *)hdr + sizeof(*hdr);

			index_inode_set_size(branch, le64_to_cpu(hdr->ino), hdr,
					     le64_to_cpu(tr->new_size));
			break;
		}
		case DAXFS_DELTA_WRITE: {
			struct daxfs_delta_write *wr =
				(void *)hdr + sizeof(*hdr);
			u64 wr_offset = le64_to_cpu(wr->offset);
			u32 wr_len = le32_to_cpu(wr->len);
			u64 end = wr_offset + wr_len;
			void *wr_data = (void *)(wr + 1);

			index_inode_set_size(branch, le64_to_cpu(hdr->ino), hdr, end);
			daxfs_index_add_write_extent(branch, le64_to_cpu(hdr->ino),
					       wr_offset, wr_len, wr_data);
			break;
		}
		case DAXFS_DELTA_SETATTR: {
			struct daxfs_delta_setattr *sa =
				(void *)hdr + sizeof(*hdr);
			u32 valid = le32_to_cpu(sa->valid);

			index_inode_setattr(branch, le64_to_cpu(hdr->ino), hdr,
					    (valid & DAXFS_ATTR_SIZE) ?
						le64_to_cpu(sa->size) : (u64)-1,
					    (valid & DAXFS_ATTR_MODE) ?
						le32_to_cpu(sa->mode) : (u32)-1,
					    (valid & DAXFS_ATTR_UID) ?
						le32_to_cpu(sa->uid) : (u32)-1,
					    (valid & DAXFS_ATTR_GID) ?
						le32_to_cpu(sa->gid) : (u32)-1);
			break;
		}
		case DAXFS_DELTA_SYMLINK: {
			struct daxfs_delta_symlink *sl =
				(void *)hdr + sizeof(*hdr);
			char *name = (char *)(sl + 1);
			char *target = name + le16_to_cpu(sl->name_len);
			u16 target_len = le16_to_cpu(sl->target_len);

			index_inode_create(branch, le64_to_cpu(sl->new_ino), hdr,
					   target_len, S_IFLNK | 0777,
					   le32_to_cpu(sl->uid),
					   le32_to_cpu(sl->gid), target);
			index_add_dirent(branch, le64_to_cpu(sl->parent_ino),
					 name, le16_to_cpu(sl->name_len),
					 hdr, false);
			break;
		}
		case DAXFS_DELTA_RENAME: {
			struct daxfs_delta_rename *rn =
				(void *)hdr + sizeof(*hdr);
			char *old_name = (char *)(rn + 1);
			char *new_name = old_name +
					 le16_to_cpu(rn->old_name_len);

			index_add_dirent(branch,
					 le64_to_cpu(rn->old_parent_ino),
					 old_name,
					 le16_to_cpu(rn->old_name_len),
					 hdr, true);
			index_add_dirent(branch,
					 le64_to_cpu(rn->new_parent_ino),
					 new_name,
					 le16_to_cpu(rn->new_name_len),
					 hdr, false);
			break;
		}
		}

		offset += total_size;
	}

	return 0;
}

/*
 * Lookup inode in delta log index
 */
struct daxfs_delta_hdr *daxfs_delta_lookup_inode(struct daxfs_branch_ctx *branch,
						 u64 ino)
{
	struct rb_node *node;
	struct daxfs_delta_inode_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(&branch->index_lock, flags);

	node = branch->inode_index.rb_node;
	while (node) {
		entry = rb_entry(node, struct daxfs_delta_inode_entry, rb_node);

		if (ino < entry->ino)
			node = node->rb_left;
		else if (ino > entry->ino)
			node = node->rb_right;
		else {
			spin_unlock_irqrestore(&branch->index_lock, flags);
			return entry->hdr;
		}
	}

	spin_unlock_irqrestore(&branch->index_lock, flags);
	return NULL;
}

/*
 * Lookup dirent in delta log index
 */
struct daxfs_delta_hdr *daxfs_delta_lookup_dirent(struct daxfs_branch_ctx *branch,
						  u64 parent_ino,
						  const char *name, int namelen)
{
	struct rb_node *node;
	struct daxfs_delta_dirent_entry *entry;
	u32 hash = dirent_hash(parent_ino, name, namelen);
	u64 key = (parent_ino << 32) | hash;
	unsigned long flags;

	spin_lock_irqsave(&branch->index_lock, flags);

	node = branch->dirent_index.rb_node;
	while (node) {
		u64 entry_key;

		entry = rb_entry(node, struct daxfs_delta_dirent_entry, rb_node);
		entry_key = ((u64)entry->parent_ino << 32) | entry->name_hash;

		if (key < entry_key) {
			node = node->rb_left;
		} else if (key > entry_key) {
			node = node->rb_right;
		} else {
			/* Check actual name */
			if (namelen == entry->name_len &&
			    memcmp(name, entry->name, namelen) == 0) {
				spin_unlock_irqrestore(&branch->index_lock, flags);
				return entry->hdr;
			}
			node = node->rb_right;
		}
	}

	spin_unlock_irqrestore(&branch->index_lock, flags);
	return NULL;
}

/*
 * Get nlink_delta for an inode from a single branch (caller must hold index_lock)
 */
static bool get_branch_nlink_delta(struct daxfs_branch_ctx *branch, u64 ino,
				   s32 *delta_out)
{
	struct rb_node *node = branch->inode_index.rb_node;
	struct daxfs_delta_inode_entry *entry;

	while (node) {
		entry = rb_entry(node, struct daxfs_delta_inode_entry, rb_node);

		if (ino < entry->ino)
			node = node->rb_left;
		else if (ino > entry->ino)
			node = node->rb_right;
		else {
			*delta_out = entry->nlink_delta;
			return true;
		}
	}
	return false;
}

/*
 * Accumulate nlink_delta across the entire branch chain
 * Returns true if inode was found in any branch's delta
 */
static bool accumulate_nlink_delta(struct daxfs_branch_ctx *branch, u64 ino,
				   s32 *total_delta)
{
	struct daxfs_branch_ctx *b;
	unsigned long flags;
	s32 delta;
	bool found = false;

	*total_delta = 0;

	for (b = branch; b != NULL; b = b->parent) {
		spin_lock_irqsave(&b->index_lock, flags);
		if (get_branch_nlink_delta(b, ino, &delta)) {
			*total_delta += delta;
			found = true;
		}
		spin_unlock_irqrestore(&b->index_lock, flags);
	}

	return found;
}

/*
 * Compute effective nlink for an inode
 * Returns the effective nlink (base + delta), or 0 if deleted
 */
static u32 compute_effective_nlink(struct daxfs_info *info, u64 ino,
				   s32 total_delta, bool found_in_delta)
{
	u32 base_nlink = get_base_nlink(info, ino);
	s32 effective;

	if (base_nlink > 0) {
		effective = base_nlink + total_delta;
		return (effective > 0) ? effective : 0;
	}

	/* Delta-created inode: base nlink is 1 */
	if (found_in_delta) {
		effective = 1 + total_delta;
		return (effective > 0) ? effective : 0;
	}

	return 0;
}

/*
 * Check if inode is deleted in this branch (accumulates nlink across chain)
 */
bool daxfs_delta_is_deleted(struct daxfs_branch_ctx *branch, u64 ino)
{
	struct daxfs_info *info = branch->info;
	u32 base_nlink = get_base_nlink(info, ino);
	s32 total_delta;
	bool found;

	found = accumulate_nlink_delta(branch, ino, &total_delta);

	/* If never touched in delta and not in base, not deleted (doesn't exist) */
	if (!found && base_nlink == 0)
		return false;

	/* Inode is deleted when effective nlink <= 0 */
	return compute_effective_nlink(info, ino, total_delta, found) == 0;
}

/*
 * Check if directory has any non-deleted children in this branch's delta log
 */
bool daxfs_delta_has_children(struct daxfs_branch_ctx *branch, u64 parent_ino)
{
	u64 offset = 0;

	while (offset < branch->delta_size) {
		struct daxfs_delta_hdr *hdr = branch->delta_log + offset;
		u32 type = le32_to_cpu(hdr->type);
		u32 total_size = le32_to_cpu(hdr->total_size);
		u64 entry_parent, child_ino;

		if (total_size == 0)
			break;

		if (type == DAXFS_DELTA_CREATE || type == DAXFS_DELTA_MKDIR) {
			struct daxfs_delta_create *cr = (void *)hdr + sizeof(*hdr);
			entry_parent = le64_to_cpu(cr->parent_ino);
			child_ino = le64_to_cpu(cr->new_ino);
		} else if (type == DAXFS_DELTA_SYMLINK) {
			struct daxfs_delta_symlink *sl = (void *)hdr + sizeof(*hdr);
			entry_parent = le64_to_cpu(sl->parent_ino);
			child_ino = le64_to_cpu(sl->new_ino);
		} else {
			offset += total_size;
			continue;
		}

		if (entry_parent == parent_ino &&
		    !daxfs_delta_is_deleted(branch, child_ino))
			return true;

		offset += total_size;
	}

	return false;
}

/*
 * Get current size of an inode (from delta or return -1 if not found)
 */
int daxfs_delta_get_size(struct daxfs_branch_ctx *branch, u64 ino, loff_t *size)
{
	struct rb_node *node;
	struct daxfs_delta_inode_entry *entry;
	unsigned long flags;

	spin_lock_irqsave(&branch->index_lock, flags);

	node = branch->inode_index.rb_node;
	while (node) {
		entry = rb_entry(node, struct daxfs_delta_inode_entry, rb_node);

		if (ino < entry->ino)
			node = node->rb_left;
		else if (ino > entry->ino)
			node = node->rb_right;
		else {
			*size = entry->size;
			spin_unlock_irqrestore(&branch->index_lock, flags);
			return 0;
		}
	}

	spin_unlock_irqrestore(&branch->index_lock, flags);
	return -ENOENT;
}

/*
 * Resolve inode through branch chain
 */
int daxfs_resolve_inode(struct super_block *sb, u64 ino,
			umode_t *mode, loff_t *size,
			uid_t *uid, gid_t *gid, bool *deleted)
{
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *b;

	*deleted = false;

	/* Walk branch chain from child to parent */
	for (b = info->current_branch; b != NULL; b = b->parent) {
		if (daxfs_delta_is_deleted(b, ino)) {
			*deleted = true;
			return 0;
		}

		struct daxfs_delta_hdr *hdr = daxfs_delta_lookup_inode(b, ino);
		if (hdr) {
			u32 type = le32_to_cpu(hdr->type);

			if (type == DAXFS_DELTA_DELETE) {
				*deleted = true;
				return 0;
			}

			/* Get mode, size, uid, gid from index */
			struct rb_node *node;
			struct daxfs_delta_inode_entry *entry;

			node = b->inode_index.rb_node;
			while (node) {
				entry = rb_entry(node,
						 struct daxfs_delta_inode_entry,
						 rb_node);
				if (ino < entry->ino)
					node = node->rb_left;
				else if (ino > entry->ino)
					node = node->rb_right;
				else {
					*mode = entry->mode;
					*size = entry->size;
					*uid = entry->uid;
					*gid = entry->gid;
					return 0;
				}
			}
		}
	}

	/* Not found in any delta — let caller fall through to base image */
	return -ENOENT;
}

/*
 * Lookup write extent using the per-inode index
 * Returns pointer to data and length, or NULL if not found
 *
 * Write extents are stored newest-first, so the first match is the latest.
 */
void *daxfs_lookup_write_extent(struct daxfs_branch_ctx *branch, u64 ino,
				loff_t pos, size_t len, size_t *out_len)
{
	struct daxfs_delta_inode_entry *ie;
	struct daxfs_write_extent *extent;
	unsigned long flags;
	void *result = NULL;

	spin_lock_irqsave(&branch->index_lock, flags);

	ie = find_inode_entry_locked(branch, ino);
	if (!ie) {
		spin_unlock_irqrestore(&branch->index_lock, flags);
		return NULL;
	}

	/*
	 * Walk write extents - they're stored newest-first,
	 * so the first match is the latest write at this position.
	 */
	list_for_each_entry(extent, &ie->write_extents, list) {
		if (pos >= extent->offset &&
		    pos < extent->offset + extent->len) {
			/* Found it */
			u64 data_off = pos - extent->offset;
			result = extent->data + data_off;
			*out_len = min(len, (size_t)(extent->len - data_off));
			break;
		}
	}

	spin_unlock_irqrestore(&branch->index_lock, flags);
	return result;
}

/*
 * Resolve file data through branch chain
 * Returns pointer to data and actual length available
 *
 * Uses per-inode write extent index for O(w) lookup where w is
 * the number of writes to this inode, instead of O(n) full log scan.
 */
void *daxfs_resolve_file_data(struct super_block *sb, u64 ino,
			      loff_t pos, size_t len, size_t *out_len)
{
	return daxfs_resolve_file_data_ex(sb, ino, pos, len, out_len, NULL);
}

/*
 * Extended version that also indicates data source.
 * @from_base: if non-NULL, set to true if data came from base image
 */
void *daxfs_resolve_file_data_ex(struct super_block *sb, u64 ino,
				 loff_t pos, size_t len, size_t *out_len,
				 bool *from_base)
{
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *b;

	if (from_base)
		*from_base = false;

	/* Walk branch chain from child to parent looking for write at pos */
	for (b = info->current_branch; b != NULL; b = b->parent) {
		void *data = daxfs_lookup_write_extent(b, ino, pos, len, out_len);
		if (data)
			return data;
	}

	/* Fall back to base image using storage layer */
	if (info->base_inodes && ino <= info->base_inode_count) {
		struct daxfs_base_inode *raw = &info->base_inodes[ino - 1];
		u64 data_offset = le64_to_cpu(raw->data_offset);
		loff_t file_size = le64_to_cpu(raw->size);

		if (pos >= file_size) {
			*out_len = 0;
			return NULL;
		}

		*out_len = min(len, (size_t)(file_size - pos));

		/*
		 * External data mode: regular file data is in the backing
		 * file, accessed through the page cache. Dirs and symlinks
		 * remain in the base image.
		 */
		if (info->pcache && S_ISREG(le32_to_cpu(raw->mode))) {
			u64 page_start = (data_offset + pos) &
					 ~(u64)(PAGE_SIZE - 1);
			void *page;
			u32 intra;

			page = daxfs_pcache_get_page(info, page_start);
			if (IS_ERR(page)) {
				*out_len = 0;
				return NULL;
			}
			intra = (data_offset + pos) & (PAGE_SIZE - 1);
			*out_len = min(*out_len, (size_t)(PAGE_SIZE - intra));
			if (from_base)
				*from_base = true;
			return page + intra;
		}

		/* Direct DAX path (no backing store) */
		{
			u64 abs_offset;

			abs_offset = le64_to_cpu(info->super->base_offset) +
				     data_offset + pos;
			if (from_base)
				*from_base = true;
			return daxfs_mem_ptr((struct daxfs_info *)info,
					    abs_offset);
		}
	}

	*out_len = 0;
	return NULL;
}

/*
 * Get symlink target from delta index
 * Returns pointer to target string (in delta log), or NULL if not found
 */
char *daxfs_delta_get_symlink(struct daxfs_branch_ctx *branch, u64 ino)
{
	struct daxfs_delta_inode_entry *entry;
	unsigned long flags;
	char *target = NULL;

	spin_lock_irqsave(&branch->index_lock, flags);

	entry = find_inode_entry_locked(branch, ino);
	if (entry && entry->symlink_target)
		target = entry->symlink_target;

	spin_unlock_irqrestore(&branch->index_lock, flags);
	return target;
}

/*
 * Merge child's deltas into parent's log
 */
int daxfs_delta_merge(struct daxfs_branch_ctx *parent,
		      struct daxfs_branch_ctx *child)
{
	struct daxfs_info *info = parent->info;
	void *dest;
	u64 child_size = child->delta_size;

	if (child_size == 0)
		return 0;	/* Nothing to merge */

	/* Check if parent has space */
	if (parent->delta_size + child_size > parent->delta_capacity) {
		pr_err("daxfs: parent delta log too small for merge\n");
		return -ENOSPC;
	}

	/* Copy child's delta log to parent */
	dest = daxfs_delta_alloc(info, parent, child_size);
	if (!dest)
		return -ENOSPC;

	memcpy(dest, child->delta_log, child_size);

	/* Rebuild parent's index to include merged entries */
	/* Note: This is simple but not optimal - could merge indices instead */
	free_inode_index(parent);
	free_dirent_index(parent);
	daxfs_delta_build_index(parent);

	return 0;
}

/*
 * Get effective nlink for an inode (base + delta adjustments across chain)
 */
int daxfs_get_effective_nlink(struct super_block *sb, u64 ino, u32 *nlink)
{
	struct daxfs_info *info = DAXFS_SB(sb);
	u32 base_nlink = get_base_nlink(info, ino);
	s32 total_delta;
	bool found;

	found = accumulate_nlink_delta(info->current_branch, ino, &total_delta);

	if (base_nlink > 0 || found) {
		*nlink = compute_effective_nlink(info, ino, total_delta, found);
		return 0;
	}

	return -ENOENT;
}
