# DAXFS

**Copy-on-write branching for shared memory filesystems.**

DAXFS is a filesystem that operates directly on shared physical memory via the DAX
(Direct Access) subsystem. It combines a read-only base image with copy-on-write
branches, each branch gets its own delta log for modifications while sharing the
underlying data. File reads resolve to direct memory loads with no page cache, no
buffer heads, and no copies.

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

- **Container rootfs sharing** - Multiple containers share one daxfs base image with
  copy-on-write branches for writable layers. Each container gets its own branch — writes
  go to the branch's delta log while reads fall through to shared physical pages. No page
  cache duplication, no overlayfs overhead.

- **GPU/accelerator data** - A daxfs image in device-accessible memory provides zero-copy
  access to model weights, lookup tables, etc. Mounted via dma-buf fd (see [Mounting](#mounting)).

- **FPGA/SmartNIC** - Shared memory regions between host and device, often already exposed
  as dma-bufs, can host a daxfs image for structured data access (see [Mounting](#mounting)).

## Why Not ...

- **tmpfs/ramfs** - RAM-backed and fast, but read-write and per-instance. File contents
  live in page cache pages, so sharing the same rootfs across N containers or kernels
  means N copies of the same data in physical memory. Populating them also requires
  copying data in first, they cannot map an existing memory region in place.

-- **overlayfs** - A union filesystem that layers a writable upper directory over a
  read-only lower. The main limitation is no nested branching — you cannot branch
  from a branch without stacking overlays, which has depth limits and complexity.
  daxfs branches can have parent branches, enabling arbitrary nesting. overlayfs
  also copies data on first write (copy-up) and uses the page cache for the upper
  layer. daxfs keeps deltas in the same DAX region with no copy-up and zero-copy reads.

- **erofs** - A high-performance read-only filesystem optimized for single-version
  access. Immutability is fundamental to its design: inode locations are computed at
  mkfs time, directory entries are pre-sorted for binary search, and no write path
  exists. Adding branching would require a complete write path, branch chain traversal
  on every lookup, and a "current branch" concept - negating the performance advantages
  that make erofs attractive in the first place.

- **famfs** - Designed for fabric-attached memory and supports DAX, but focused on
  mutable per-file allocation on DAX devices. daxfs is simpler: a self-contained
  image that can be placed in any memory region (physical address, DAX device,
  or dma-buf) with no runtime allocation or device management. Branching provides
  copy-on-write mutability without per-file allocation complexity.

- **cramfs** - Compressed and read-only, but uses the block I/O layer and page cache.
  Data must be decompressed into page cache pages before access. Cannot directly map
  a shared memory region, so no zero-copy and no physical page sharing across kernels
  or containers.

## Branching

DAXFS supports copy-on-write branches for speculative modifications. A read-only base
image provides the initial filesystem state, and each branch maintains its own delta
log for modifications. Branches can be nested (branch from a branch) for multi-level
speculation.

Unlike git, DAXFS branches are mutually exclusive: committing a branch discards all
sibling branches, and aborting discards the current branch and returns to the root.
This models the AI agent use case: an agent can speculatively modify the filesystem,
explore multiple approaches in nested branches, then commit the successful path or
abort failed attempts. There is no merge, no parallel long-lived branches - just
speculative execution with a single winner.

### Why not existing filesystems?

| Filesystem | Log-structured | In-memory index | Hierarchical branches |
|------------|----------------|-----------------|----------------------|
| NILFS2 | Yes | Yes | No (linear snapshots) |
| Btrfs | No (CoW B-tree) | No | Yes |
| F2FS | Yes | Yes | No |
| DAXFS | Yes | Yes | Yes |

**NILFS2** uses continuous checkpointing, every sync creates a new checkpoint, and you
can mount any checkpoint read-only. But checkpoints are linear (a timeline), not a tree.
You cannot branch from a checkpoint, make changes, and commit independently. Converting
a checkpoint to a snapshot protects it from garbage collection, but creating a writable
branch from it would invalidate all subsequent checkpoints. The commit model assumes
a single linear history.

**Btrfs** supports snapshots that can themselves be snapshotted, creating a tree of
subvolumes. However, Btrfs snapshots are full subvolumes sharing data blocks via
reflinks. There's no built-in commit/abort semantic — "committing" is just setting
read-only, "aborting" is deleting the subvolume. More importantly, Btrfs has no
mechanism to discard sibling branches on commit. Each subvolume lives independently,
so you'd need external tooling to enforce the "single winner" model that DAXFS
provides natively.

**EROFS** is architecturally incompatible with branching. Immutability is fundamental:
inode locations are computed directly (`iloc = meta_blkaddr + (nid << islotbits)`),
directory entries are pre-sorted for binary search, and no write path exists. Adding
branching would require indirection on every inode lookup, unsorted delta directories
merged at read time, and a complete write path - negating the performance that makes
EROFS attractive.

### Usage

```bash
# Mount with a writable branch
mount -t daxfs -o phys=0x100000000,size=0x10000000,branch=main,rw none /mnt

# Create and switch to a new branch
daxfs-branch create feature -m /mnt -p main
daxfs-branch switch feature -m /mnt

# List branches
daxfs-branch list -m /mnt

# Commit or abort changes
daxfs-branch commit -m /mnt
daxfs-branch abort -m /mnt
```

### Branch operations

- **create** — Create a new branch from a parent branch
- **switch** — Switch the mount to a different branch
- **list** — List all branches and their states
- **commit** — Make current branch permanent, discard all sibling branches
- **abort** — Discard current branch, switch back to root

### Delta log

Delta entries track writes, creates, deletes, truncates, renames, and attribute changes.
When reading a file, DAXFS checks the branch's delta log first, falling back to parent
branches and ultimately the base image. Each branch maintains an in-memory index
(rb-tree) over its delta log for fast lookups — the log-structured append-only format
keeps writes fast while the index keeps reads fast.

## Source Layout

```
include/daxfs_format.h   - On-disk format (shared by kernel module and user-space)
kernel/                  - Kernel module source
  branch.c               - Branch management
  delta.c                - Delta log operations
  dax_mem.c              - Memory region management
mkdaxfs/                 - User-space image builder
tools/                   - User-space utilities
  daxfs-branch           - Branch management tool
  daxfs-inspect          - Image inspection tool
```

## Building

Build everything (kernel module + mkdaxfs):

```bash
make                            # build against the running kernel
make KDIR=/path/to/kernel/build # build against a specific kernel
make clean
```

Build individually:

```bash
make kernel                     # kernel module only
make mkdaxfs                    # user-space tool only
```

The target kernel must have `CONFIG_FS_DAX` enabled.

## Creating Images

`mkdaxfs` creates a daxfs image from a directory tree:

```bash
# Write to a file
mkdaxfs -d /path/to/rootfs -o image.daxfs

# Allocate from a DMA heap and mount
mkdaxfs -d /path/to/rootfs -H /dev/dma_heap/multikernel -s 256M -m /mnt

# Write to a physical address via /dev/mem
mkdaxfs -d /path/to/rootfs -p 0x100000000 -s 256M
```

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

The format is defined in `include/daxfs_format.h`, shared by both the kernel module
and user-space tools.

A daxfs image has the following layout:

| Offset | Content |
|--------|---------|
| 0 | Superblock (4KB) |
| `branch_table_offset` | Branch table (128-byte entries, up to 256 branches) |
| `base_offset` | Base image (optional embedded read-only snapshot) |
| `delta_region_offset` | Delta region (branch delta logs) |

The **base image** (when present) contains:

| Offset | Content |
|--------|---------|
| 0 | Base superblock (4KB) |
| `inode_offset` | Inode table (fixed-size 64-byte entries) |
| `strtab_offset` | String table (filenames) |
| `data_offset` | File data area |

Each **branch** has a delta log containing variable-size entries for writes, creates,
deletes, truncates, renames, and attribute changes. Reads check the branch's delta log
first, then parent branches, then the base image.

Directories use a first-child/next-sibling linked list. Regular files and symlinks
store their content at the offset recorded in their inode (base) or delta log (branch).
