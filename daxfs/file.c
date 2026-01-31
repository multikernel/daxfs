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
#include <linux/dma-buf.h>
#include <linux/iomap.h>
#include <linux/dax.h>
#include <asm/pgtable.h>
#include "daxfs.h"

/*
 * ============================================================================
 * DAX iomap operations
 * ============================================================================
 *
 * These operations translate file offsets to physical DAX memory addresses.
 * For reads, we find existing data in delta log or base image.
 * For writes, we pre-allocate delta entries and map their data areas.
 */

/*
 * Find or allocate a write extent for the given file region.
 * For DAX mmap writes, we pre-allocate the delta entry so we can
 * return a direct mapping to its data area.
 */
static void *daxfs_get_write_extent(struct inode *inode, loff_t pos, size_t len,
				    size_t *out_len)
{
	struct super_block *sb = inode->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_branch_ctx *branch = info->current_branch;
	size_t entry_size;
	void *entry;
	struct daxfs_delta_hdr *hdr;
	struct daxfs_delta_write *wr;
	void *data;
	void *existing_data = NULL;
	size_t existing_len = 0;
	struct rb_node **link;
	struct rb_node *parent;
	struct daxfs_delta_inode_entry *ie;
	struct daxfs_write_extent *extent;
	unsigned long flags;
	bool found_inode = false;

	/* First, check if we already have a write extent covering this position */
	spin_lock_irqsave(&branch->index_lock, flags);

	ie = NULL;
	link = &branch->inode_index.rb_node;
	parent = NULL;
	while (*link) {
		parent = *link;
		ie = rb_entry(parent, struct daxfs_delta_inode_entry, rb_node);
		if (inode->i_ino < ie->ino)
			link = &parent->rb_left;
		else if (inode->i_ino > ie->ino)
			link = &parent->rb_right;
		else {
			found_inode = true;
			break;
		}
	}

	if (found_inode && ie) {
		/* Check for existing extent at this position */
		list_for_each_entry(extent, &ie->write_extents, list) {
			if (pos >= extent->offset &&
			    pos < extent->offset + extent->len) {
				/* Found existing extent */
				u64 data_off = pos - extent->offset;
				data = extent->data + data_off;

				/*
				 * For mmap, data must be page-aligned. If this
				 * extent is page-aligned, return it directly.
				 * Otherwise, we'll need to allocate a new
				 * page-aligned extent and copy the data.
				 */
				if (IS_ALIGNED((unsigned long)data, PAGE_SIZE)) {
					*out_len = min(len, (size_t)(extent->len - data_off));
					spin_unlock_irqrestore(&branch->index_lock, flags);
					return data;
				}

				/*
				 * Existing extent is not page-aligned.
				 * Save the data for COW below.
				 */
				existing_data = data;
				existing_len = min(len, (size_t)(extent->len - data_off));
				break;
			}
		}
	}

	spin_unlock_irqrestore(&branch->index_lock, flags);

	/*
	 * No suitable page-aligned extent exists. Get COW source data
	 * from base image or parent delta if we don't have it already.
	 */
	if (!existing_data)
		existing_data = daxfs_resolve_file_data(sb, inode->i_ino, pos, len,
							&existing_len);

	/*
	 * Allocate new delta entry with page-aligned data area.
	 * This is required for mmap PFN mapping to work correctly.
	 */
	{
		size_t header_size = sizeof(struct daxfs_delta_hdr) +
				     sizeof(struct daxfs_delta_write);
		entry = daxfs_delta_alloc_mmap(info, branch, header_size, len,
					       &data, &entry_size);
	}
	if (!entry)
		return NULL;

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

	/* Data area is page-aligned, returned by daxfs_delta_alloc_mmap */

	/*
	 * Copy existing data (COW) or zero-fill if no existing data.
	 * This preserves base image content when mmap writes only
	 * modify part of a page.
	 */
	if (existing_data && existing_len > 0) {
		memcpy(data, existing_data, min(len, existing_len));
		/* Zero any remaining bytes beyond existing data */
		if (existing_len < len)
			memset(data + existing_len, 0, len - existing_len);
	} else {
		memset(data, 0, len);
	}

	/* Update inode index */
	spin_lock_irqsave(&branch->index_lock, flags);

	if (!found_inode) {
		/* Need to find/create inode entry again */
		link = &branch->inode_index.rb_node;
		parent = NULL;
		while (*link) {
			parent = *link;
			ie = rb_entry(parent, struct daxfs_delta_inode_entry, rb_node);
			if (inode->i_ino < ie->ino)
				link = &parent->rb_left;
			else if (inode->i_ino > ie->ino)
				link = &parent->rb_right;
			else {
				found_inode = true;
				break;
			}
		}
	}

	if (found_inode && ie) {
		ie->hdr = hdr;
		if (pos + len > ie->size)
			ie->size = pos + len;
	} else {
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
	}

	spin_unlock_irqrestore(&branch->index_lock, flags);

	/* Add write extent */
	daxfs_index_add_write_extent(branch, inode->i_ino, pos, len, data);

	/* Update inode size if extending */
	if (pos + len > inode->i_size) {
		inode->i_size = pos + len;
		DAXFS_I(inode)->delta_size = inode->i_size;
	}

	*out_len = len;
	return data;
}

/*
 * iomap_begin for DAX operations
 *
 * Translates file offset to physical memory address:
 * - For reads: finds data in delta log or base image
 * - For writes: pre-allocates delta entry and returns its data area
 */
static int daxfs_iomap_begin(struct inode *inode, loff_t pos, loff_t length,
			     unsigned flags, struct iomap *iomap,
			     struct iomap *srcmap)
{
	struct super_block *sb = inode->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	void *data;
	size_t data_len;
	phys_addr_t phys;
	loff_t file_size = inode->i_size;

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	iomap->bdev = NULL;
	iomap->dax_dev = NULL;

	if (flags & IOMAP_WRITE) {
		/* Write fault - allocate delta entry */
		loff_t alloc_pos, alloc_len;

		/* Align to page boundaries for mmap */
		alloc_pos = pos & ~(loff_t)(PAGE_SIZE - 1);
		alloc_len = PAGE_SIZE;

		/* Extend file size if writing beyond current size */
		if (alloc_pos + alloc_len > file_size)
			file_size = alloc_pos + alloc_len;

		data = daxfs_get_write_extent(inode, alloc_pos, alloc_len, &data_len);
		if (!data)
			return -ENOSPC;

		phys = daxfs_mem_phys(info, daxfs_mem_offset(info, data));
		if (!phys)
			return -EIO;

		iomap->type = IOMAP_MAPPED;
		iomap->flags = IOMAP_F_DIRTY;
		iomap->offset = alloc_pos;
		iomap->length = data_len;
		iomap->addr = phys;
	} else {
		/* Read fault - find existing data */
		if (pos >= file_size) {
			/* Beyond EOF - return hole */
			iomap->type = IOMAP_HOLE;
			iomap->offset = pos;
			iomap->length = length;
			iomap->addr = IOMAP_NULL_ADDR;
			return 0;
		}

		/* Try to find data in delta log or base image */
		data = daxfs_resolve_file_data(sb, inode->i_ino, pos, length, &data_len);
		if (!data || data_len == 0) {
			/* No data - return hole (zeroed) */
			iomap->type = IOMAP_HOLE;
			iomap->offset = pos;
			iomap->length = min((loff_t)length, file_size - pos);
			iomap->addr = IOMAP_NULL_ADDR;
			return 0;
		}

		phys = daxfs_mem_phys(info, daxfs_mem_offset(info, data));
		if (!phys)
			return -EIO;

		iomap->type = IOMAP_MAPPED;
		iomap->flags = 0;
		iomap->offset = pos;
		iomap->length = data_len;
		iomap->addr = phys;
	}

	return 0;
}

static int daxfs_iomap_end(struct inode *inode, loff_t pos, loff_t length,
			   ssize_t written, unsigned flags, struct iomap *iomap)
{
	/* Update mtime on writes */
	if ((flags & IOMAP_WRITE) && written > 0)
		inode_set_mtime_to_ts(inode,
			inode_set_ctime_to_ts(inode, current_time(inode)));
	return 0;
}

static const struct iomap_ops daxfs_iomap_ops = {
	.iomap_begin	= daxfs_iomap_begin,
	.iomap_end	= daxfs_iomap_end,
};

/*
 * For DAX, we don't use the page cache, so address_space_operations
 * are minimal. This is still needed because the VFS expects a_ops.
 */
const struct address_space_operations daxfs_aops = {
	/* Empty - DAX bypasses page cache */
};

/*
 * ============================================================================
 * File read/write operations
 * ============================================================================
 */

static ssize_t daxfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct super_block *sb = inode->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(to);
	size_t total = 0;

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

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

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

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
		inode_set_mtime_to_ts(inode,
			inode_set_ctime_to_ts(inode, current_time(inode)));
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

/*
 * ============================================================================
 * DAX mmap fault handling
 * ============================================================================
 *
 * We implement our own fault handler that directly inserts PFN mappings.
 * This bypasses the need for a dax_device structure.
 */

static void daxfs_copy_page(void *dst, const void *src, size_t len)
{
	if (src && len > 0) {
		memcpy(dst, src, min(len, (size_t)PAGE_SIZE));
		if (len < PAGE_SIZE)
			memset(dst + len, 0, PAGE_SIZE - len);
	} else {
		memset(dst, 0, PAGE_SIZE);
	}
}

static unsigned long daxfs_data_to_pfn(struct daxfs_info *info, void *data)
{
	phys_addr_t phys;

	if (!data)
		return 0;
	phys = daxfs_mem_phys(info, daxfs_mem_offset(info, data));
	return phys ? (phys >> PAGE_SHIFT) : 0;
}

/*
 * DAX fault handler - maps DAX memory directly into userspace.
 * No page cache involved.
 *
 * For mmap to work correctly with PFN mapping, the data must be
 * page-aligned. We achieve this by always allocating page-aligned
 * delta extents for mmap faults, performing COW from base image
 * if needed.
 */
static vm_fault_t daxfs_dax_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	struct super_block *sb = inode->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	loff_t pos = (loff_t)vmf->pgoff << PAGE_SHIFT;
	bool is_write = vmf->flags & FAULT_FLAG_WRITE;
	bool is_shared = vma->vm_flags & VM_SHARED;
	void *data;
	size_t len;
	unsigned long pfn;

	/* Check branch validity */
	if (daxfs_commit_seq_changed(info)) {
		if (!daxfs_branch_is_valid(info)) {
			daxfs_invalidate_branch_mappings(info);
			return VM_FAULT_SIGBUS;
		}
		info->cached_commit_seq = le64_to_cpu(info->coord->commit_sequence);
	}

	if (!is_write && pos >= inode->i_size)
		return VM_FAULT_SIGBUS;

	if (is_write && (sb->s_flags & SB_RDONLY))
		return VM_FAULT_SIGBUS;

	/*
	 * MAP_PRIVATE: always use anonymous pages to ensure COW works.
	 *
	 * The kernel's COW mechanism requires struct pages. DAX PFN mappings
	 * don't have backing pages, so if we inserted a read-only PFN and
	 * the user later writes, do_wp_page() can't do proper COW — it just
	 * makes the PTE writable via pfn_mkwrite, corrupting shared data.
	 *
	 * Solution: copy DAX data to anonymous pages for ALL private accesses.
	 * This sacrifices DAX benefits for private mappings but ensures
	 * correct COW semantics for any read/write access pattern.
	 *
	 * For write faults, the kernel's do_cow_fault() allocates cow_page,
	 * calls our handler, copies from vmf->page to cow_page, then installs
	 * cow_page. We must return a locked page so the kernel can properly
	 * unlock and release it after copying.
	 */
	if (!is_shared) {
		struct page *page;
		void *dst;

		data = daxfs_resolve_file_data(sb, inode->i_ino, pos,
					       PAGE_SIZE, &len);

		page = alloc_page(GFP_HIGHUSER_MOVABLE);
		if (!page)
			return VM_FAULT_OOM;

		dst = kmap_local_page(page);
		daxfs_copy_page(dst, data, len);
		kunmap_local(dst);

		__SetPageUptodate(page);
		lock_page(page);
		vmf->page = page;
		return VM_FAULT_LOCKED;
	}

	/*
	 * MAP_SHARED: writes go to delta log, reads get existing data
	 * or allocate zeroed extent.
	 */
	if (is_write) {
		sb_start_pagefault(sb);
		data = daxfs_get_write_extent(inode, pos, PAGE_SIZE, &len);
		sb_end_pagefault(sb);
	} else {
		data = daxfs_resolve_file_data(sb, inode->i_ino, pos,
					       PAGE_SIZE, &len);
		/*
		 * For PFN mapping, data must be page-aligned. write() stores
		 * data inline (not page-aligned), so we need to copy it to
		 * a page-aligned extent for mmap to work correctly.
		 */
		if (!data || !IS_ALIGNED((unsigned long)data, PAGE_SIZE)) {
			sb_start_pagefault(sb);
			data = daxfs_get_write_extent(inode, pos, PAGE_SIZE, &len);
			sb_end_pagefault(sb);
		}
	}

	pfn = daxfs_data_to_pfn(info, data);
	if (!pfn)
		return VM_FAULT_SIGBUS;

	return vmf_insert_pfn_prot(vma, vmf->address, pfn,
		is_write ? __pgprot(pgprot_val(vma->vm_page_prot) | _PAGE_RW)
			 : vma->vm_page_prot);
}

/*
 * DAX pfn_mkwrite handler - upgrade read-only PFN mapping to writable.
 * Only called for MAP_SHARED (VM_PFNMAP) mappings.
 */
static vm_fault_t daxfs_dax_pfn_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	struct super_block *sb = inode->i_sb;
	struct daxfs_info *info = DAXFS_SB(sb);
	loff_t pos = (loff_t)vmf->pgoff << PAGE_SHIFT;
	void *data;
	size_t len;
	unsigned long pfn;

	/* Should only be called for shared mappings */
	if (!(vma->vm_flags & VM_SHARED))
		return VM_FAULT_SIGBUS;

	if (sb->s_flags & SB_RDONLY)
		return VM_FAULT_SIGBUS;

	if (!daxfs_branch_is_valid(info)) {
		daxfs_invalidate_branch_mappings(info);
		return VM_FAULT_SIGBUS;
	}

	sb_start_pagefault(sb);
	data = daxfs_get_write_extent(inode, pos, PAGE_SIZE, &len);
	sb_end_pagefault(sb);

	pfn = daxfs_data_to_pfn(info, data);
	if (!pfn)
		return VM_FAULT_SIGBUS;

	/* Zap old PTE before inserting writable one */
	zap_vma_ptes(vma, vmf->address, PAGE_SIZE);

	return vmf_insert_pfn_prot(vma, vmf->address, pfn,
			__pgprot(pgprot_val(vma->vm_page_prot) | _PAGE_RW));
}

static const struct vm_operations_struct daxfs_dax_vm_ops = {
	.fault		= daxfs_dax_fault,
	.pfn_mkwrite	= daxfs_dax_pfn_mkwrite,
};

/*
 * ============================================================================
 * File operations
 * ============================================================================
 */

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
 * mmap handler - direct DAX mapping
 */
static int daxfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);

	if ((vma->vm_flags & VM_WRITE) && (inode->i_sb->s_flags & SB_RDONLY))
		return -EACCES;

	file_accessed(file);

	/*
	 * Shared mappings use VM_PFNMAP for direct DAX access.
	 * Private mappings use anonymous pages (no special flags) to
	 * ensure proper COW semantics — see daxfs_dax_fault().
	 */
	if (vma->vm_flags & VM_SHARED)
		vm_flags_set(vma, VM_PFNMAP);

	vma->vm_ops = &daxfs_dax_vm_ops;

	return 0;
}

/*
 * ioctl handler - works for both files and directories.
 * Allows userspace tools to get the dma-buf fd for inspection.
 */
long daxfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct daxfs_info *info = DAXFS_SB(file_inode(file)->i_sb);

	switch (cmd) {
	case DAXFS_IOC_GET_DMABUF: {
		int fd;

		if (!info->dmabuf)
			return -ENOENT;	/* Not a dma-buf mount */

		get_dma_buf(info->dmabuf);
		fd = dma_buf_fd(info->dmabuf, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			dma_buf_put(info->dmabuf);
		return fd;
	}
	}
	return -ENOTTY;
}

static int daxfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file_inode(file);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	struct daxfs_branch_ctx *branch = info->current_branch;

	if (!daxfs_branch_is_valid(info))
		return -ESTALE;

	/*
	 * For DAX, data is written directly to memory. Sync the delta log
	 * region to ensure persistence.
	 */
	if (branch && branch->delta_log && branch->delta_size > 0)
		daxfs_mem_sync(info, branch->delta_log, branch->delta_size);

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
	.fsync		= daxfs_fsync,
	.unlocked_ioctl	= daxfs_ioctl,
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
	.fsync		= noop_fsync,
	.unlocked_ioctl	= daxfs_ioctl,
};

const struct inode_operations daxfs_file_inode_ops_ro = {
	.getattr	= simple_getattr,
	/* No setattr - read-only */
};
