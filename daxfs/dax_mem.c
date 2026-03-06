// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs DAX memory storage layer
 *
 * This module provides the storage abstraction for DAXFS, handling
 * memory mapping (memremap/dma-buf) and pointer access.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <linux/io.h>
#include <linux/slab.h>
#include <linux/dma-buf.h>
#include <linux/mm.h>
#include "daxfs.h"

/**
 * daxfs_mem_init_dmabuf - Initialize storage from dma-buf
 * @info: filesystem info structure to initialize
 * @dmabuf_file: file reference to dma-buf
 *
 * Returns 0 on success, negative error code on failure.
 */
int daxfs_mem_init_dmabuf(struct daxfs_info *info, struct file *dmabuf_file)
{
	struct dma_buf *dmabuf;
	int ret;

	dmabuf = dmabuf_file->private_data;
	if (!dmabuf || dmabuf->file != dmabuf_file) {
		pr_err("daxfs: not a dma-buf fd\n");
		return -EINVAL;
	}

	get_dma_buf(dmabuf);
	ret = dma_buf_vmap(dmabuf, &info->dma_map);
	if (ret) {
		dma_buf_put(dmabuf);
		return ret;
	}

	info->dmabuf = dmabuf;
	info->mem = info->dma_map.vaddr;
	info->size = dmabuf->size;

	return 0;
}

/**
 * daxfs_mem_init_phys - Initialize storage from physical address
 * @info: filesystem info structure to initialize
 * @phys_addr: physical address of the DAX region
 * @size: size of the DAX region in bytes
 *
 * Returns 0 on success, negative error code on failure.
 */
int daxfs_mem_init_phys(struct daxfs_info *info, phys_addr_t phys_addr,
			size_t size)
{
	info->phys_addr = phys_addr;
	info->size = size;

	info->mem = memremap(phys_addr, size, MEMREMAP_WB);
	if (!info->mem) {
		pr_err("daxfs: failed to map %pa size %zu\n",
		       &phys_addr, size);
		return -ENOMEM;
	}

	return 0;
}

/**
 * daxfs_mem_exit - Release storage mapping
 * @info: filesystem info structure
 */
void daxfs_mem_exit(struct daxfs_info *info)
{
	if (info->dmabuf) {
		dma_buf_vunmap(info->dmabuf, &info->dma_map);
		dma_buf_put(info->dmabuf);
		info->dmabuf = NULL;
	} else if (info->mem) {
		memunmap(info->mem);
	}
	info->mem = NULL;
}

/**
 * daxfs_mem_ptr - Convert offset to pointer
 * @info: filesystem info structure
 * @offset: byte offset from start of DAX region
 *
 * Returns pointer to the specified offset, or NULL if out of bounds.
 */
void *daxfs_mem_ptr(struct daxfs_info *info, u64 offset)
{
	if (offset >= info->size)
		return NULL;
	return info->mem + offset;
}

/**
 * daxfs_mem_offset - Convert pointer to offset
 * @info: filesystem info structure
 * @ptr: pointer within DAX region
 *
 * Returns byte offset, or -1 if pointer is outside the region.
 */
u64 daxfs_mem_offset(struct daxfs_info *info, void *ptr)
{
	if (ptr < info->mem || ptr >= info->mem + info->size)
		return (u64)-1;
	return ptr - info->mem;
}

/**
 * daxfs_mem_phys - Get physical address for offset
 * @info: filesystem info structure
 * @offset: byte offset from start of DAX region
 *
 * Returns physical address, or 0 on failure.
 */
phys_addr_t daxfs_mem_phys(struct daxfs_info *info, u64 offset)
{
	void *ptr;
	struct page *page;

	if (offset >= info->size)
		return 0;

	/* Fast path for physical address mounts */
	if (info->phys_addr)
		return info->phys_addr + offset;

	/* For dma-buf mounts, derive physical address from virtual */
	ptr = info->mem + offset;

	if (is_vmalloc_addr(ptr)) {
		page = vmalloc_to_page(ptr);
		if (!page)
			return 0;
		return page_to_phys(page) + offset_in_page(ptr);
	}

	/* Direct-mapped memory */
	return virt_to_phys(ptr);
}

/**
 * daxfs_mem_sync - Ensure writes are visible
 * @info: filesystem info structure
 * @ptr: pointer to start of region to sync
 * @size: size of region to sync in bytes
 */
void daxfs_mem_sync(struct daxfs_info *info, void *ptr, size_t size)
{
	(void)info;

	if (!ptr || !size)
		return;

	/*
	 * Ensure all prior stores are globally visible. On platforms
	 * with ADR/eADR, this is sufficient for persistence. On
	 * platforms without hardware persistence guarantees, explicit
	 * cache line flushes (clflush/clwb) would be needed per
	 * cache line — not yet implemented.
	 */
	smp_wmb();
}
