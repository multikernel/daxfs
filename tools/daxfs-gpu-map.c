// SPDX-License-Identifier: GPL-2.0
/*
 * daxfs GPU mapping helper
 *
 * Maps a daxfs DAX region into GPU address space for PCIe AtomicOps.
 *
 * Two mapping paths:
 *   1. dma-buf (preferred): DAXFS_IOC_GET_DMABUF -> cuImportExternalMemory
 *   2. /dev/mem fallback:   phys_addr from ioctl -> mmap + cuMemHostRegister
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cuda.h>

#include "daxfs-gpu-map.h"

/* Compute convenience device pointers from base + ioctl offsets */
static void compute_dev_ptrs(struct daxfs_gpu_map *gpu)
{
	CUdeviceptr b = gpu->base;
	const struct daxfs_gpu_info *gi = &gpu->info;

	if (gi->coord_offset) {
		gpu->coord_lock = b + gi->coord_offset + gi->coord_lock_off;
		gpu->commit_seq = b + gi->coord_offset + gi->commit_seq_off;
	}

	if (gi->pcache_offset) {
		gpu->pcache_slots = b + gi->pcache_slots_offset;
		gpu->pcache_data  = b + gi->pcache_data_offset;
		gpu->pending_count = b + gi->pcache_offset +
				     gi->pending_count_off;
	}
}

/* Primary path: import dma-buf as CUDA external memory */
static int map_dmabuf(struct daxfs_gpu_map *gpu)
{
	int dmabuf_fd;
	CUresult res;
	CUDA_EXTERNAL_MEMORY_HANDLE_DESC ext_desc;
	CUDA_EXTERNAL_MEMORY_BUFFER_DESC buf_desc;

	dmabuf_fd = ioctl(gpu->mount_fd, DAXFS_IOC_GET_DMABUF);
	if (dmabuf_fd < 0)
		return -1;	/* not a dma-buf mount */
	gpu->dmabuf_fd = dmabuf_fd;

	memset(&ext_desc, 0, sizeof(ext_desc));
	ext_desc.type = CU_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD;
	ext_desc.handle.fd = dmabuf_fd;
	ext_desc.size = gpu->info.dax_size;

	res = cuImportExternalMemory(&gpu->ext_mem, &ext_desc);
	if (res != CUDA_SUCCESS) {
		fprintf(stderr, "daxfs-gpu-map: cuImportExternalMemory: %d\n",
			(int)res);
		close(dmabuf_fd);
		gpu->dmabuf_fd = -1;
		return -1;
	}

	/*
	 * cuImportExternalMemory with OPAQUE_FD takes ownership of the fd,
	 * so we must not close it ourselves.
	 */
	gpu->dmabuf_fd = -1;

	memset(&buf_desc, 0, sizeof(buf_desc));
	buf_desc.offset = 0;
	buf_desc.size = gpu->info.dax_size;

	res = cuExternalMemoryGetMappedBuffer(&gpu->base, gpu->ext_mem,
					      &buf_desc);
	if (res != CUDA_SUCCESS) {
		fprintf(stderr,
			"daxfs-gpu-map: cuExternalMemoryGetMappedBuffer: %d\n",
			(int)res);
		cuDestroyExternalMemory(gpu->ext_mem);
		gpu->ext_mem = NULL;
		return -1;
	}

	gpu->size = gpu->info.dax_size;
	return 0;
}

/* Fallback path: /dev/mem mmap + cuMemHostRegister */
static int map_devmem(struct daxfs_gpu_map *gpu)
{
	int fd;
	void *addr;
	CUresult res;

	if (!gpu->info.dax_phys_addr) {
		fprintf(stderr,
			"daxfs-gpu-map: no physical address available\n");
		errno = ENOTSUP;
		return -1;
	}

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("daxfs-gpu-map: open /dev/mem");
		return -1;
	}

	addr = mmap(NULL, gpu->info.dax_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, (off_t)gpu->info.dax_phys_addr);
	close(fd);

	if (addr == MAP_FAILED) {
		perror("daxfs-gpu-map: mmap /dev/mem");
		return -1;
	}
	gpu->host_mmap = addr;

	res = cuMemHostRegister(addr, gpu->info.dax_size,
				CU_MEMHOSTREGISTER_DEVICEMAP);
	if (res != CUDA_SUCCESS) {
		fprintf(stderr,
			"daxfs-gpu-map: cuMemHostRegister: %d\n", (int)res);
		munmap(addr, gpu->info.dax_size);
		gpu->host_mmap = NULL;
		return -1;
	}

	res = cuMemHostGetDevicePointer(&gpu->base, addr, 0);
	if (res != CUDA_SUCCESS) {
		fprintf(stderr,
			"daxfs-gpu-map: cuMemHostGetDevicePointer: %d\n",
			(int)res);
		cuMemHostUnregister(addr);
		munmap(addr, gpu->info.dax_size);
		gpu->host_mmap = NULL;
		return -1;
	}

	gpu->size = gpu->info.dax_size;
	return 0;
}

/* Fallback path 2: mmap dma-buf fd + cuMemHostRegister */
static int map_dmabuf_mmap(struct daxfs_gpu_map *gpu)
{
	int dmabuf_fd;
	void *addr;
	CUresult res;

	dmabuf_fd = ioctl(gpu->mount_fd, DAXFS_IOC_GET_DMABUF);
	if (dmabuf_fd < 0)
		return -1;

	fprintf(stderr, "daxfs-gpu-map: dmabuf_mmap: fd=%d size=%llu\n",
		dmabuf_fd, (unsigned long long)gpu->info.dax_size);

	addr = mmap(NULL, gpu->info.dax_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED, dmabuf_fd, 0);
	if (addr == MAP_FAILED) {
		perror("daxfs-gpu-map: mmap dma-buf fd");
		close(dmabuf_fd);
		return -1;
	}

	fprintf(stderr, "daxfs-gpu-map: dmabuf mmap'd at %p\n", addr);

	gpu->dmabuf_fd = dmabuf_fd;
	gpu->host_mmap = addr;

	res = cuMemHostRegister(addr, gpu->info.dax_size,
				CU_MEMHOSTREGISTER_DEVICEMAP |
				CU_MEMHOSTREGISTER_IOMEMORY);
	if (res != CUDA_SUCCESS) {
		fprintf(stderr,
			"daxfs-gpu-map: cuMemHostRegister(dmabuf, IOMEMORY): "
			"%d, trying without IOMEMORY...\n", (int)res);
		res = cuMemHostRegister(addr, gpu->info.dax_size,
					CU_MEMHOSTREGISTER_DEVICEMAP);
	}
	if (res != CUDA_SUCCESS) {
		fprintf(stderr,
			"daxfs-gpu-map: cuMemHostRegister(dmabuf): %d\n",
			(int)res);
		munmap(addr, gpu->info.dax_size);
		close(dmabuf_fd);
		gpu->host_mmap = NULL;
		gpu->dmabuf_fd = -1;
		return -1;
	}

	res = cuMemHostGetDevicePointer(&gpu->base, addr, 0);
	if (res != CUDA_SUCCESS) {
		fprintf(stderr,
			"daxfs-gpu-map: cuMemHostGetDevicePointer(dmabuf): "
			"%d\n", (int)res);
		cuMemHostUnregister(addr);
		munmap(addr, gpu->info.dax_size);
		close(dmabuf_fd);
		gpu->host_mmap = NULL;
		gpu->dmabuf_fd = -1;
		return -1;
	}

	gpu->size = gpu->info.dax_size;
	return 0;
}

int daxfs_gpu_map(int mount_fd, struct daxfs_gpu_map *gpu)
{
	memset(gpu, 0, sizeof(*gpu));
	gpu->mount_fd = mount_fd;
	gpu->dmabuf_fd = -1;

	/* Step 1: get layout from kernel */
	if (ioctl(mount_fd, DAXFS_IOC_GET_GPU_INFO, &gpu->info) < 0) {
		perror("daxfs-gpu-map: DAXFS_IOC_GET_GPU_INFO");
		return -1;
	}

	if (gpu->info.dax_size == 0) {
		fprintf(stderr, "daxfs-gpu-map: zero-length DAX region\n");
		errno = EINVAL;
		return -1;
	}

	/* Step 2: map into GPU - try dma-buf import, mmap+register, /dev/mem */
	if (map_dmabuf(gpu) < 0 && map_dmabuf_mmap(gpu) < 0 &&
	    map_devmem(gpu) < 0)
		return -1;

	/* Step 3: compute convenience pointers */
	compute_dev_ptrs(gpu);

	return 0;
}

void daxfs_gpu_unmap(struct daxfs_gpu_map *gpu)
{
	if (!gpu)
		return;

	if (gpu->ext_mem) {
		/* dma-buf path */
		if (gpu->base)
			cuMemFree(gpu->base);
		cuDestroyExternalMemory(gpu->ext_mem);
		gpu->ext_mem = NULL;
	} else if (gpu->host_mmap) {
		/* /dev/mem path */
		cuMemHostUnregister(gpu->host_mmap);
		munmap(gpu->host_mmap, gpu->size);
		gpu->host_mmap = NULL;
	}

	if (gpu->dmabuf_fd >= 0) {
		close(gpu->dmabuf_fd);
		gpu->dmabuf_fd = -1;
	}

	gpu->base = 0;
	gpu->size = 0;
}
