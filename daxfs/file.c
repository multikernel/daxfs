// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs file operations
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/writeback.h>
#include "daxfs.h"

static ssize_t daxfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct super_block *sb = inode->i_sb;
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(to);
	size_t total = 0;

	if (pos >= inode->i_size)
		return 0;

	if (pos + count > inode->i_size)
		count = inode->i_size - pos;

	while (count > 0) {
		size_t chunk;
		void *src;

		src = daxfs_resolve_file_data(sb, inode->i_ino, pos, count, &chunk);
		if (!src || chunk == 0)
			break;

		if (copy_to_iter(src, chunk, to) != chunk)
			return total ? total : -EFAULT;

		pos += chunk;
		count -= chunk;
		total += chunk;
	}

	iocb->ki_pos = pos;
	return total;
}

static ssize_t daxfs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct super_block *sb = inode->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	loff_t pos = iocb->ki_pos;
	size_t len = iov_iter_count(from);
	size_t entry_size;
	void *entry;
	struct daxfs_delta_hdr *hdr;
	struct daxfs_delta_write *wr;
	void *data;

	if (len == 0)
		return 0;

	/* Allocate space for delta entry */
	entry_size = sizeof(struct daxfs_delta_hdr) +
		     sizeof(struct daxfs_delta_write) + len;

	entry = daxfs_delta_alloc(info, branch, entry_size);
	if (!entry)
		return -ENOSPC;

	/* Fill header */
	hdr = entry;
	hdr->type = cpu_to_le32(DAXFS_DELTA_WRITE);
	hdr->total_size = cpu_to_le32(entry_size);
	hdr->ino = cpu_to_le64(inode->i_ino);
	hdr->timestamp = cpu_to_le64(ktime_get_real_ns());

	/* Fill write info */
	wr = (void *)(hdr + 1);
	wr->offset = cpu_to_le64(pos);
	wr->len = cpu_to_le32(len);
	wr->flags = 0;

	/* Copy data from user */
	data = (void *)(wr + 1);
	if (copy_from_iter(data, len, from) != len)
		return -EFAULT;

	/* Update inode size if extending */
	if (pos + len > inode->i_size) {
		inode->i_size = pos + len;
		DAXFS_I(inode)->delta_size = inode->i_size;
	}

	/* Manually update index for this write */
	{
		struct rb_node **link = &branch->inode_index.rb_node;
		struct rb_node *parent = NULL;
		struct daxfs_delta_inode_entry *ie;
		unsigned long flags;

		spin_lock_irqsave(&branch->index_lock, flags);

		while (*link) {
			parent = *link;
			ie = rb_entry(parent, struct daxfs_delta_inode_entry,
				      rb_node);

			if (inode->i_ino < ie->ino)
				link = &parent->rb_left;
			else if (inode->i_ino > ie->ino)
				link = &parent->rb_right;
			else {
				/* Update existing */
				ie->hdr = hdr;
				if (pos + len > ie->size)
					ie->size = pos + len;
				spin_unlock_irqrestore(&branch->index_lock, flags);
				goto add_extent;
			}
		}

		ie = kzalloc(sizeof(*ie), GFP_ATOMIC);
		if (ie) {
			ie->ino = inode->i_ino;
			ie->hdr = hdr;
			ie->size = pos + len;
			ie->mode = inode->i_mode;
			ie->deleted = false;
			INIT_LIST_HEAD(&ie->write_extents);
			rb_link_node(&ie->rb_node, parent, link);
			rb_insert_color(&ie->rb_node, &branch->inode_index);
		}
		spin_unlock_irqrestore(&branch->index_lock, flags);
	}

add_extent:
	/* Add write extent for fast data lookup */
	daxfs_index_add_write_extent(branch, inode->i_ino, pos, len, data);

	/*
	 * Invalidate page cache for the written range. This ensures mmap
	 * readers see the new data from the delta log, not stale cached pages.
	 */
	invalidate_inode_pages2_range(inode->i_mapping,
				      pos >> PAGE_SHIFT,
				      (pos + len - 1) >> PAGE_SHIFT);

	iocb->ki_pos = pos + len;
	inode_set_mtime_to_ts(inode, inode_set_ctime_to_ts(inode, current_time(inode)));
	return len;
}

static int daxfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			 struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	int ret;

	ret = setattr_prepare(idmap, dentry, attr);
	if (ret)
		return ret;

	/* Handle truncate */
	if (attr->ia_valid & ATTR_SIZE) {
		struct daxfs_delta_truncate tr;

		tr.new_size = cpu_to_le64(attr->ia_size);

		ret = daxfs_delta_append(branch, DAXFS_DELTA_TRUNCATE,
					 inode->i_ino, &tr, sizeof(tr));
		if (ret)
			return ret;

		i_size_write(inode, attr->ia_size);
		DAXFS_I(inode)->delta_size = attr->ia_size;
	}

	/* Handle mode/uid/gid changes */
	if (attr->ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID)) {
		struct daxfs_delta_setattr sa = {0};

		if (attr->ia_valid & ATTR_MODE) {
			sa.mode = cpu_to_le32(attr->ia_mode);
			sa.valid |= cpu_to_le32(DAXFS_ATTR_MODE);
		}
		if (attr->ia_valid & ATTR_UID) {
			sa.uid = cpu_to_le32(from_kuid(&init_user_ns, attr->ia_uid));
			sa.valid |= cpu_to_le32(DAXFS_ATTR_UID);
		}
		if (attr->ia_valid & ATTR_GID) {
			sa.gid = cpu_to_le32(from_kgid(&init_user_ns, attr->ia_gid));
			sa.valid |= cpu_to_le32(DAXFS_ATTR_GID);
		}

		ret = daxfs_delta_append(branch, DAXFS_DELTA_SETATTR,
					 inode->i_ino, &sa, sizeof(sa));
		if (ret)
			return ret;
	}

	setattr_copy(idmap, inode, attr);
	return 0;
}

static int daxfs_read_folio(struct file *file, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	struct super_block *sb = inode->i_sb;
	loff_t pos = folio_pos(folio);
	size_t len = folio_size(folio);
	size_t filled = 0;

	if (pos >= inode->i_size) {
		folio_zero_range(folio, 0, len);
		goto out;
	}

	while (filled < len && pos + filled < inode->i_size) {
		size_t chunk;
		void *src;

		src = daxfs_resolve_file_data(sb, inode->i_ino,
					      pos + filled, len - filled, &chunk);
		if (!src || chunk == 0) {
			/* Hole or EOF */
			break;
		}

		memcpy_to_folio(folio, filled, src, chunk);
		filled += chunk;
	}

	if (filled < len)
		folio_zero_range(folio, filled, len - filled);

out:
	folio_mark_uptodate(folio);
	folio_unlock(folio);
	return 0;
}

static int daxfs_write_folio(struct folio *folio, struct writeback_control *wbc)
{
	struct inode *inode = folio->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	loff_t pos = folio_pos(folio);
	size_t len = folio_size(folio);
	size_t entry_size;
	void *entry;
	struct daxfs_delta_hdr *hdr;
	struct daxfs_delta_write *wr;
	void *data;

	/* Don't write beyond file size */
	if (pos >= inode->i_size) {
		folio_start_writeback(folio);
		folio_unlock(folio);
		folio_end_writeback(folio);
		return 0;
	}

	if (pos + len > inode->i_size)
		len = inode->i_size - pos;

	/* Allocate space for delta entry */
	entry_size = sizeof(struct daxfs_delta_hdr) +
		     sizeof(struct daxfs_delta_write) + len;

	entry = daxfs_delta_alloc(info, branch, entry_size);
	if (!entry) {
		folio_redirty_for_writepage(wbc, folio);
		folio_unlock(folio);
		return -ENOSPC;
	}

	/* Fill header */
	hdr = entry;
	hdr->type = cpu_to_le32(DAXFS_DELTA_WRITE);
	hdr->total_size = cpu_to_le32(entry_size);
	hdr->ino = cpu_to_le64(inode->i_ino);
	hdr->timestamp = cpu_to_le64(ktime_get_real_ns());

	/* Fill write info */
	wr = (void *)(hdr + 1);
	wr->offset = cpu_to_le64(pos);
	wr->len = cpu_to_le32(len);
	wr->flags = 0;

	/* Copy folio data while still locked */
	data = (void *)(wr + 1);
	memcpy_from_folio(data, folio, 0, len);

	/* Start writeback and unlock - data copy is complete */
	folio_start_writeback(folio);
	folio_unlock(folio);

	/* Update index */
	{
		struct rb_node **link = &branch->inode_index.rb_node;
		struct rb_node *parent = NULL;
		struct daxfs_delta_inode_entry *ie;
		unsigned long flags;

		spin_lock_irqsave(&branch->index_lock, flags);

		while (*link) {
			parent = *link;
			ie = rb_entry(parent, struct daxfs_delta_inode_entry,
				      rb_node);

			if (inode->i_ino < ie->ino)
				link = &parent->rb_left;
			else if (inode->i_ino > ie->ino)
				link = &parent->rb_right;
			else {
				/* Update existing */
				ie->hdr = hdr;
				if (pos + len > ie->size)
					ie->size = pos + len;
				spin_unlock_irqrestore(&branch->index_lock, flags);
				goto add_extent;
			}
		}

		ie = kzalloc(sizeof(*ie), GFP_ATOMIC);
		if (ie) {
			ie->ino = inode->i_ino;
			ie->hdr = hdr;
			ie->size = pos + len;
			ie->mode = inode->i_mode;
			ie->deleted = false;
			INIT_LIST_HEAD(&ie->write_extents);
			rb_link_node(&ie->rb_node, parent, link);
			rb_insert_color(&ie->rb_node, &branch->inode_index);
		}
		spin_unlock_irqrestore(&branch->index_lock, flags);
	}

add_extent:
	/* Add write extent for fast data lookup */
	daxfs_index_add_write_extent(branch, inode->i_ino, pos, len, data);

	folio_end_writeback(folio);
	return 0;
}

static int daxfs_writepages(struct address_space *mapping,
			    struct writeback_control *wbc)
{
	struct folio *folio = NULL;
	int error = 0;

	while ((folio = writeback_iter(mapping, wbc, folio, &error)))
		error = daxfs_write_folio(folio, wbc);

	return error;
}

const struct address_space_operations daxfs_aops = {
	.read_folio	= daxfs_read_folio,
	.writepages	= daxfs_writepages,
	.dirty_folio	= filemap_dirty_folio,
};

static int daxfs_file_open(struct inode *inode, struct file *file)
{
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);

	/* Fail fast if branch already invalid */
	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	if (S_ISREG(inode->i_mode))
		atomic_inc(&info->open_files);
	return 0;
}

static int daxfs_file_release(struct inode *inode, struct file *file)
{
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);

	if (S_ISREG(inode->i_mode))
		atomic_dec(&info->open_files);
	return 0;
}

/*
 * Custom fault handler that checks branch validity before faulting in pages.
 * If the branch has been invalidated (e.g., sibling committed), return SIGBUS.
 */
static vm_fault_t daxfs_fault(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);

	/* Fast path: check commit sequence */
	if (daxfs_commit_seq_changed(info)) {
		/* Slow path: full validation */
		if (!daxfs_branch_is_valid(info))
			return VM_FAULT_SIGBUS;
		info->cached_commit_seq = le64_to_cpu(info->coord->commit_sequence);
	}

	return filemap_fault(vmf);
}

static vm_fault_t daxfs_page_mkwrite(struct vm_fault *vmf)
{
	struct folio *folio = page_folio(vmf->page);
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);

	if (inode->i_sb->s_flags & SB_RDONLY)
		return VM_FAULT_SIGBUS;

	/* Must validate before allowing write */
	if (!daxfs_branch_is_valid(info))
		return VM_FAULT_SIGBUS;

	sb_start_pagefault(inode->i_sb);
	folio_lock(folio);
	folio_mark_dirty(folio);
	folio_wait_stable(folio);
	sb_end_pagefault(inode->i_sb);

	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct daxfs_vm_ops = {
	.fault		= daxfs_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= daxfs_page_mkwrite,
};

static int daxfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);

	if ((vma->vm_flags & VM_WRITE) && (inode->i_sb->s_flags & SB_RDONLY))
		return -EACCES;

	file_accessed(file);
	vma->vm_ops = &daxfs_vm_ops;
	return 0;
}

const struct file_operations daxfs_file_ops = {
	.llseek		= generic_file_llseek,
	.read_iter	= daxfs_read_iter,
	.write_iter	= daxfs_write_iter,
	.splice_read	= filemap_splice_read,
	.open		= daxfs_file_open,
	.release	= daxfs_file_release,
	.mmap		= daxfs_file_mmap,
	.fsync		= generic_file_fsync,
};

const struct inode_operations daxfs_file_inode_ops = {
	.getattr	= simple_getattr,
	.setattr	= daxfs_setattr,
};

/*
 * ============================================================================
 * Read-Only Operations (static image mode)
 * ============================================================================
 *
 * These operations provide direct base image access without delta chain walking.
 * Used when info->static_image is true.
 */

/*
 * Get file data directly from base image (no delta chain)
 */
static void *daxfs_base_file_data(struct daxfs_info *info, u64 ino,
				  loff_t pos, size_t len, size_t *out_len)
{
	struct daxfs_base_inode *raw;
	u64 data_offset, file_size;
	size_t avail;

	if (!info->base_inodes || ino < 1 || ino > info->base_inode_count)
		return NULL;

	raw = &info->base_inodes[ino - 1];
	data_offset = le64_to_cpu(raw->data_offset);
	file_size = le64_to_cpu(raw->size);

	if (pos >= file_size)
		return NULL;

	avail = file_size - pos;
	if (len > avail)
		len = avail;

	if (out_len)
		*out_len = len;

	return daxfs_mem_ptr(info,
			     le64_to_cpu(info->super->base_offset) +
			     data_offset + pos);
}

static ssize_t daxfs_read_iter_ro(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(to);
	size_t chunk;
	void *src;

	if (pos >= inode->i_size)
		return 0;

	if (pos + count > inode->i_size)
		count = inode->i_size - pos;

	src = daxfs_base_file_data(info, inode->i_ino, pos, count, &chunk);
	if (!src || chunk == 0)
		return 0;

	if (copy_to_iter(src, chunk, to) != chunk)
		return -EFAULT;

	iocb->ki_pos = pos + chunk;
	return chunk;
}

static int daxfs_read_folio_ro(struct file *file, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	loff_t pos = folio_pos(folio);
	size_t len = folio_size(folio);
	size_t chunk;
	void *src;

	if (pos >= inode->i_size) {
		folio_zero_range(folio, 0, len);
		goto out;
	}

	src = daxfs_base_file_data(info, inode->i_ino, pos, len, &chunk);
	if (src && chunk > 0)
		memcpy_to_folio(folio, 0, src, chunk);
	else
		chunk = 0;

	if (chunk < len)
		folio_zero_range(folio, chunk, len - chunk);

out:
	folio_mark_uptodate(folio);
	folio_unlock(folio);
	return 0;
}

static const struct vm_operations_struct daxfs_vm_ops_ro = {
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	/* No page_mkwrite - read-only */
};

static int daxfs_file_mmap_ro(struct file *file, struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_WRITE)
		return -EACCES;

	file_accessed(file);
	vma->vm_ops = &daxfs_vm_ops_ro;
	return 0;
}

const struct address_space_operations daxfs_aops_ro = {
	.read_folio	= daxfs_read_folio_ro,
	/* No writepages - read-only */
};

const struct file_operations daxfs_file_ops_ro = {
	.llseek		= generic_file_llseek,
	.read_iter	= daxfs_read_iter_ro,
	.splice_read	= filemap_splice_read,
	.mmap		= daxfs_file_mmap_ro,
	/* No write_iter, no open/release tracking needed */
};

const struct inode_operations daxfs_file_inode_ops_ro = {
	.getattr	= simple_getattr,
	/* No setattr - read-only */
};
