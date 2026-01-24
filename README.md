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

- **GPU/accelerator data** - dma-buf is the standard for GPU memory sharing. A daxfs image
  in device-accessible memory provides zero-copy access to model weights, lookup tables, etc.

- **FPGA/SmartNIC** - Shared memory regions between host and device, often already exposed
  as dma-bufs, can host a daxfs image for structured data access.

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
