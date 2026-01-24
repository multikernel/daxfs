# DAXFS

DAXFS is a simple read-only filesystem that operates directly on shared physical memory
via the DAX (Direct Access) subsystem. It bypasses the traditional block I/O stack entirely,
file reads resolve to direct memory loads with no page cache, no buffer heads, and no copies.

## Origin

DAXFS was originally designed for **multikernel** environments, where multiple kernel
instances share a single physical memory region. The primary use case was booting Docker
images: a daxfs image of a container rootfs placed in shared memory provides all kernels
with a common read-only filesystem without any inter-kernel communication or network I/O.

## Other Use Cases

The same properties - zero-copy reads from memory-mapped regions - make daxfs potentially
useful beyond multikernel:

- **CXL memory pooling** - CXL Type-3 devices expose shared memory across hosts. A daxfs
  image in a CXL shared memory region gives multiple machines the same read-only filesystem
  with no network I/O. CXL memory already integrates with the DAX subsystem (`/dev/dax*`).

- **Persistent memory (PMEM)** - daxfs on Optane/CXL-PM gives a persistent read-only
  filesystem with zero I/O stack overhead. Survives reboots without remounting.

- **Container rootfs sharing** - Multiple containers share one daxfs base image (no page
  cache duplication), with overlayfs on top for writable layers. Every container sees the
  same physical pages.

- **GPU/accelerator data** - A daxfs image in device-accessible memory provides zero-copy
  access to model weights, lookup tables, etc. Mounted via dma-buf fd (see [Mounting](#mounting)).

- **FPGA/SmartNIC** - Shared memory regions between host and device, often already exposed
  as dma-bufs, can host a daxfs image for structured data access (see [Mounting](#mounting)).

## Why Not ...

- **cramfs** - Compressed and read-only, but uses the block I/O layer and page cache.
  Data must be decompressed into page cache pages before access. Cannot directly map
  a shared memory region, so no zero-copy and no physical page sharing across kernels
  or containers.

- **tmpfs/ramfs** - RAM-backed and fast, but read-write and per-instance. File contents
  live in page cache pages, so sharing the same rootfs across N containers or kernels
  means N copies of the same data in physical memory. Populating them also requires
  copying data in first, they cannot map an existing memory region in place.

- **famfs** - Designed for fabric-attached memory and supports DAX, but focused on
  mutable per-file allocation on DAX devices. daxfs is simpler: a self-contained
  read-only image that can be placed in any memory region (physical address, DAX device,
  or dma-buf) with no runtime allocation or device management.

## Building

DAXFS builds as an out-of-tree kernel module:

```bash
make                            # build against the running kernel
make KDIR=/path/to/kernel/build # build against a specific kernel
make clean
```

The target kernel must have `CONFIG_FS_DAX` enabled.

## Mounting

DAXFS needs a contiguous memory region containing a pre-built daxfs image. Two backing
options are supported:

### Physical address

Mount by specifying a raw physical address and size:

```bash
mount -t daxfs -o phys=0x100000000,size=0x10000000 none /mnt
```

The region is mapped into the kernel via `memremap()`. This is the typical path for
multikernel shared memory or known reserved physical ranges.

### dma-buf file descriptor

Mount by passing a dma-buf fd via the new mount API (`fsopen`/`fsconfig`/`fsmount`).
File descriptors cannot be passed as mount option strings, so `FSCONFIG_SET_FD` is required:

```c
/* Allocate a dma-buf (e.g. from a dma-heap) and populate it with a daxfs image */
heap_fd = open("/dev/dma_heap/multikernel", O_RDWR);
alloc.len = image_size;
alloc.fd_flags = O_RDWR | O_CLOEXEC;
ioctl(heap_fd, DMA_HEAP_IOCTL_ALLOC, &alloc);
dmabuf_fd = alloc.fd;
close(heap_fd);

/* Write the daxfs image into the dma-buf */
mem = mmap(NULL, alloc.len, PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf_fd, 0);
img_fd = open("rootfs.daxfs", O_RDONLY);
read(img_fd, mem, image_size);
close(img_fd);
munmap(mem, alloc.len);

/* Mount daxfs, passing the dma-buf fd */
fs_fd = fsopen("daxfs", 0);
fsconfig(fs_fd, FSCONFIG_SET_FD, "dmabuf", NULL, dmabuf_fd);
fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
mnt_fd = fsmount(fs_fd, 0, 0);
move_mount(mnt_fd, "", AT_FDCWD, "/mnt", MOVE_MOUNT_F_EMPTY_PATH);

/* Close — daxfs holds the dma-buf reference internally */
close(mnt_fd);
close(fs_fd);
close(dmabuf_fd);
```

[dma-buf](https://docs.kernel.org/driver-api/dma-buf.html) is the standard Linux API for
cross-subsystem memory sharing. Any device driver (GPU, FPGA, SmartNIC, dma-heap, etc.)
that exports a dma-buf can provide the backing memory for a daxfs mount. Inside the kernel,
daxfs calls `dma_buf_vmap()` to map the buffer into kernel virtual space and reads the
filesystem image directly from device memory — no copies, no intermediate page cache.

This means any subsystem that can export a dma-buf can host a daxfs image:

- A GPU driver exports VRAM containing model weights as a dma-buf → mount it as a
  filesystem for zero-copy access from CPU or other devices.
- An FPGA/SmartNIC exposes a shared memory region as a dma-buf → mount it for structured
  read-only data access between host and device.
- A dma-heap (e.g. a multikernel shared-memory heap) allocates a buffer → populate it with
  a daxfs image and mount it across kernel instances.

daxfs holds a reference to the dma-buf for the lifetime of the mount and releases it
(vunmap + put) on unmount.

## On-Disk Format

The format is defined in `daxfs_format.h`, which can be included by both the kernel module
and user-space tools (e.g., an image builder).

A daxfs image has the following layout:

| Offset | Content |
|--------|---------|
| 0 | Superblock (4KB) |
| `inode_offset` | Inode table (fixed-size 64-byte entries) |
| `strtab_offset` | String table (filenames) |
| `data_offset` | File data area |

Directories use a first-child/next-sibling linked list. Regular files and symlinks
store their content at the offset recorded in their inode.
