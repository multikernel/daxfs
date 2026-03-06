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
#include <linux/splice.h>
#include <asm/pgtable.h>
#include "daxfs.h"

/*
 * ============================================================================
 * Base image data access
 * ============================================================================
 */

/*
 * Get file data from base image, overlay, or pcache.
 *
 * Resolution order: overlay page → pcache → inline base image data
 *
 * COW granularity is per-page (4KB). After a partial-page write, only
 * the written page has an overlay entry; adjacent pages still resolve
 * through pcache or base image. This is intentional — each page is
 * independently versioned.
 *
 * If data comes from pcache, the slot is pinned (refcount incremented).
 * Caller MUST call daxfs_pcache_put_page(info, *pinned_slot) when done.
 * pinned_slot is set to -1 when data does not come from pcache.
 */
void *daxfs_base_file_data(struct daxfs_info *info, u64 ino,
			   loff_t pos, size_t len, size_t *out_len,
			   s32 *pinned_slot)
{
	struct daxfs_base_inode *raw;
	u64 data_offset, file_size;
	size_t avail;

	if (pinned_slot)
		*pinned_slot = -1;

	/* Check overlay first */
	if (info->overlay) {
		u64 pgoff = pos >> PAGE_SHIFT;
		void *page = daxfs_overlay_get_page(info, ino, pgoff);

		if (page) {
			u32 intra = pos & (PAGE_SIZE - 1);
			if (out_len)
				*out_len = min(len, (size_t)(PAGE_SIZE - intra));
			return page + intra;
		}
	}

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

	/* External data mode: regular file data via pcache */
	if (info->pcache && S_ISREG(le32_to_cpu(raw->mode))) {
		u64 pcache_off = info->export_mode ? pos : (data_offset + pos);
		u64 pgoff = pcache_off >> PAGE_SHIFT;
		void *page;
		u32 intra;

		page = daxfs_pcache_get_page(info, ino, pgoff, pinned_slot);
		if (IS_ERR(page))
			return NULL;
		intra = pcache_off & (PAGE_SIZE - 1);
		if (out_len)
			*out_len = min(len, (size_t)(PAGE_SIZE - intra));
		return page + intra;
	}

	return daxfs_mem_ptr(info,
			     le64_to_cpu(info->super->base_offset) +
			     data_offset + pos);
}

/*
 * ============================================================================
 * Read operations
 * ============================================================================
 */

static ssize_t daxfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
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
		s32 pcslot = -1;

		src = daxfs_base_file_data(info, inode->i_ino, pos, count,
					   &chunk, &pcslot);
		if (!src || chunk == 0) {
			daxfs_pcache_put_page(info, pcslot);
			break;
		}

		if (copy_to_iter(src, chunk, to) != chunk) {
			daxfs_pcache_put_page(info, pcslot);
			return total ? total : -EFAULT;
		}

		daxfs_pcache_put_page(info, pcslot);
		pos += chunk;
		count -= chunk;
		total += chunk;
	}

	iocb->ki_pos = pos;
	return total;
}

/*
 * ============================================================================
 * Write operations (overlay-backed)
 * ============================================================================
 */

static ssize_t daxfs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	loff_t pos = iocb->ki_pos;
	size_t len = iov_iter_count(from);
	size_t total = 0;

	if (!info->overlay)
		return -EROFS;

	if (len == 0)
		return 0;

	while (len > 0) {
		u64 pgoff = pos >> PAGE_SHIFT;
		u32 intra = pos & (PAGE_SIZE - 1);
		size_t chunk = min(len, (size_t)(PAGE_SIZE - intra));
		void *page;

		page = daxfs_overlay_get_page(info, inode->i_ino, pgoff);
		if (!page) {
			/* Allocate new overlay page, COW from base */
			page = daxfs_overlay_alloc_page(info, inode->i_ino,
							pgoff);
			if (!page)
				return total ? total : -ENOSPC;

			/* COW: copy existing data into new page */
			{
				size_t base_len;
				void *base_data;
				s32 pcslot = -1;

				base_data = daxfs_base_file_data(info,
					inode->i_ino,
					(loff_t)pgoff << PAGE_SHIFT,
					PAGE_SIZE, &base_len, &pcslot);
				if (base_data && base_len > 0)
					memcpy(page, base_data,
					       min(base_len, (size_t)PAGE_SIZE));
				daxfs_pcache_put_page(info, pcslot);
			}
		}

		if (copy_from_iter(page + intra, chunk, from) != chunk)
			return total ? total : -EFAULT;

		pos += chunk;
		len -= chunk;
		total += chunk;
	}

	/* Update inode size if extending */
	if (pos > inode->i_size) {
		struct daxfs_ovl_inode_entry *oie;

		inode->i_size = pos;
		oie = daxfs_overlay_get_inode(info, inode->i_ino);
		if (oie) {
			/*
			 * Atomic field update: only touch size, not other
			 * fields. Avoids lost-update race where a concurrent
			 * setattr (mode/uid/gid change) gets overwritten.
			 */
			WRITE_ONCE(oie->size, cpu_to_le64(pos));
			smp_wmb();
		}
	}

	iocb->ki_pos = pos;
	inode_set_mtime_to_ts(inode,
		inode_set_ctime_to_ts(inode, current_time(inode)));
	return total;
}

static int daxfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			 struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	struct daxfs_ovl_inode_entry ie;
	struct daxfs_ovl_inode_entry *existing;
	int ret;

	if (!info->overlay)
		return -EROFS;

	ret = setattr_prepare(idmap, dentry, attr);
	if (ret)
		return ret;

	/*
	 * If overlay inode exists, update individual fields in-place.
	 * Each WRITE_ONCE is atomic for its field width, so concurrent
	 * setattr calls touching different fields won't clobber each other.
	 */
	existing = daxfs_overlay_get_inode(info, inode->i_ino);
	if (existing) {
		if (attr->ia_valid & ATTR_SIZE)
			WRITE_ONCE(existing->size, cpu_to_le64(attr->ia_size));
		if (attr->ia_valid & ATTR_MODE)
			WRITE_ONCE(existing->mode, cpu_to_le32(attr->ia_mode));
		if (attr->ia_valid & ATTR_UID)
			WRITE_ONCE(existing->uid, cpu_to_le32(
				from_kuid(&init_user_ns, attr->ia_uid)));
		if (attr->ia_valid & ATTR_GID)
			WRITE_ONCE(existing->gid, cpu_to_le32(
				from_kgid(&init_user_ns, attr->ia_gid)));
		smp_wmb();
	} else {
		/* No overlay inode yet — create from VFS state + changes */
		ie.type = cpu_to_le32(DAXFS_OVL_INODE);
		ie.mode = cpu_to_le32((attr->ia_valid & ATTR_MODE) ?
			attr->ia_mode : inode->i_mode);
		ie.uid = cpu_to_le32(from_kuid(&init_user_ns,
			(attr->ia_valid & ATTR_UID) ?
			attr->ia_uid : inode->i_uid));
		ie.gid = cpu_to_le32(from_kgid(&init_user_ns,
			(attr->ia_valid & ATTR_GID) ?
			attr->ia_gid : inode->i_gid));
		ie.size = cpu_to_le64((attr->ia_valid & ATTR_SIZE) ?
			attr->ia_size : inode->i_size);
		ie.nlink = cpu_to_le32(inode->i_nlink);
		ie.flags = 0;

		ret = daxfs_overlay_set_inode(info, inode->i_ino, &ie);
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

static vm_fault_t daxfs_dax_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	loff_t pos = (loff_t)vmf->pgoff << PAGE_SHIFT;
	bool is_write = vmf->flags & FAULT_FLAG_WRITE;
	bool is_shared = vma->vm_flags & VM_SHARED;
	void *data;
	size_t len;
	unsigned long pfn;

	if (!is_write && pos >= inode->i_size)
		return VM_FAULT_SIGBUS;

	if (is_write && !info->overlay)
		return VM_FAULT_SIGBUS;

	/*
	 * Write fault (MAP_SHARED with overlay): allocate overlay page
	 */
	if (is_write && is_shared && info->overlay) {
		u64 pgoff = pos >> PAGE_SHIFT;

		sb_start_pagefault(inode->i_sb);
		data = daxfs_overlay_get_page(info, inode->i_ino, pgoff);
		if (!data) {
			data = daxfs_overlay_alloc_page(info, inode->i_ino,
							pgoff);
			if (data) {
				/* COW from base */
				size_t base_len;
				void *base;
				s32 pcslot = -1;

				base = daxfs_base_file_data(info, inode->i_ino,
							    pos, PAGE_SIZE,
							    &base_len, &pcslot);
				daxfs_copy_page(data, base, base_len);
				daxfs_pcache_put_page(info, pcslot);
			}
		}
		sb_end_pagefault(inode->i_sb);

		if (!data)
			return VM_FAULT_SIGBUS;

		pfn = daxfs_data_to_pfn(info, data);
		if (!pfn)
			return VM_FAULT_SIGBUS;

		return vmf_insert_pfn_prot(vma, vmf->address, pfn,
			__pgprot(pgprot_val(vma->vm_page_prot) | _PAGE_RW));
	}

	/* Read path */
	{
		s32 pcslot = -1;

		data = daxfs_base_file_data(info, inode->i_ino, pos,
					    PAGE_SIZE, &len, &pcslot);

		/*
		 * MAP_SHARED with page-aligned data: use direct PFN mapping.
		 * Never use PFN mapping for pcache data (can be evicted).
		 */
		if (is_shared && data &&
		    IS_ALIGNED((unsigned long)data, PAGE_SIZE) &&
		    !daxfs_is_pcache_data(info, data)) {
			daxfs_pcache_put_page(info, pcslot);
			pfn = daxfs_data_to_pfn(info, data);
			if (pfn)
				return vmf_insert_pfn_prot(vma, vmf->address,
							   pfn,
							   vma->vm_page_prot);
		}

		/*
		 * Fall back to anonymous pages for:
		 * - MAP_PRIVATE (COW requires struct pages)
		 * - Non-page-aligned base image data
		 * - pcache data (can be evicted)
		 */
		{
			struct page *page;
			void *dst;

			page = alloc_page(GFP_HIGHUSER_MOVABLE);
			if (!page) {
				daxfs_pcache_put_page(info, pcslot);
				return VM_FAULT_OOM;
			}

			dst = kmap_local_page(page);
			daxfs_copy_page(dst, data, len);
			kunmap_local(dst);

			daxfs_pcache_put_page(info, pcslot);

			__SetPageUptodate(page);
			lock_page(page);
			vmf->page = page;
			return VM_FAULT_LOCKED;
		}
	}
}

static vm_fault_t daxfs_dax_pfn_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	loff_t pos = (loff_t)vmf->pgoff << PAGE_SHIFT;
	u64 pgoff = pos >> PAGE_SHIFT;
	void *data;
	unsigned long pfn;

	if (!(vma->vm_flags & VM_SHARED))
		return VM_FAULT_SIGBUS;

	if (!info->overlay)
		return VM_FAULT_SIGBUS;

	sb_start_pagefault(inode->i_sb);
	data = daxfs_overlay_get_page(info, inode->i_ino, pgoff);
	if (!data) {
		data = daxfs_overlay_alloc_page(info, inode->i_ino, pgoff);
		if (data) {
			size_t base_len;
			void *base;
			s32 pcslot = -1;

			base = daxfs_base_file_data(info, inode->i_ino,
						    pos, PAGE_SIZE,
						    &base_len, &pcslot);
			daxfs_copy_page(data, base, base_len);
			daxfs_pcache_put_page(info, pcslot);
		}
	}
	sb_end_pagefault(inode->i_sb);

	pfn = daxfs_data_to_pfn(info, data);
	if (!pfn)
		return VM_FAULT_SIGBUS;

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

static int daxfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);

	if ((vma->vm_flags & VM_WRITE) && !info->overlay)
		return -EACCES;

	file_accessed(file);

	if (vma->vm_flags & VM_SHARED)
		vm_flags_set(vma, VM_PFNMAP);

	vma->vm_ops = &daxfs_dax_vm_ops;
	return 0;
}

/*
 * ioctl handler - allows userspace tools to get the dma-buf fd.
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

const struct address_space_operations daxfs_aops = {
	/* Empty - DAX bypasses page cache */
};

static int daxfs_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync)
{
	struct daxfs_info *info = DAXFS_SB(file_inode(file)->i_sb);

	if (info->overlay) {
		u64 ovl_offset = le64_to_cpu(info->super->overlay_offset);
		u64 ovl_size = le64_to_cpu(info->super->overlay_size);

		daxfs_mem_sync(info, daxfs_mem_ptr(info, ovl_offset),
			       ovl_size);
	}
	return 0;
}

const struct file_operations daxfs_file_ops = {
	.llseek		= generic_file_llseek,
	.read_iter	= daxfs_read_iter,
	.write_iter	= daxfs_write_iter,
	.splice_read	= copy_splice_read,
	.mmap		= daxfs_file_mmap,
	.fsync		= daxfs_fsync,
	.unlocked_ioctl	= daxfs_ioctl,
};

const struct inode_operations daxfs_file_inode_ops = {
	.getattr	= simple_getattr,
	.setattr	= daxfs_setattr,
};
