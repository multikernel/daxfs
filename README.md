# DAXFS

**Disaggregated filesystem for multi-kernel and multi-host shared memory.**

DAXFS operates directly on DAX-capable memory (persistent memory, CXL memory, or DMA
buffers) via direct load/store access. Multiple independent kernels or CXL-connected
hosts sharing memory get a unified storage layer: shared namespace, cooperative page
cache, and zero-copy CPU/GPU access over aggregated distributed storage.

**Not for traditional disks.** DAXFS requires byte-addressable memory with DAX support.
It cannot run on block devices; the entire design assumes direct memory pointer access
and synchronization with `cmpxchg`.

## Features

- **Zero-copy reads** - Direct memory access, no page cache overhead
- **Lock-free writes** - CAS-based hash overlay, no locks across kernels or hosts
- **Shared page cache** - Demand-paged cache in DAX memory, automatically visible to all kernels and hosts
- **Multi-kernel/multi-host namespace** - Each kernel or CXL host exports local storage into a shared filesystem
- **Flexible backing** - Physical address, DAX device, or dma-buf
- **Security by simplicity** - Flat directory format, bounded validation, no pointer chasing

## Use Cases

- **LLM inference serving** - Multiple GPU kernels share model weights through daxfs; one copy in shared memory serves all instances, cold start goes from minutes to seconds
- **Multikernel/multi-host** - Shared rootfs across kernel instances or CXL-connected hosts with cooperative caching
- **CXL memory pooling** - Common filesystem across CXL-connected hosts with lock-free concurrent access
- **GPU/accelerator** - Zero-copy access to data via dma-buf
- **Container rootfs** - Shared base image with writable overlay per container

## Why Not ...

| Filesystem | Limitation for this use case |
|------------|------------------------------|
| **tmpfs/ramfs** | Per-instance, N containers = N copies in memory |
| **overlayfs** | No multi-kernel/multi-host support, copy-up on write, page cache overhead |
| **erofs** | Read-only, fscache is per-kernel so N kernels = N cache copies |
| **famfs** | Single-writer metadata, no shared caching, no CAS coordination (see below) |
| **cramfs** | Block I/O + page cache, no direct memory mapping |

### DAXFS vs FamFS

Both DAXFS and [FamFS](https://github.com/cxl-micron-reskit/famfs) target
CXL shared memory, but they differ fundamentally in architecture:

| | DAXFS | FamFS |
|---|---|---|
| **Coordination model** | Peer-to-peer via `cmpxchg` | Single master, clients replay metadata log |
| **Writes** | Lock-free CAS overlay, any host can write concurrently | Master creates files; clients default read-only, user manages coherency if writable |
| **Shared caching** | Cooperative page cache (pcache) across all hosts, clock-based eviction | None; each node manages its own access |
| **Allocation** | Self-contained image with internal bump allocator | Per-file extent lists allocated by master |
| **File operations** | Create, read, write (COW), delete (tombstone) | Pre-allocate only (no append, truncate, or delete) |
| **Image model** | Self-contained: superblock + base image + overlay + pcache in one region | No images; files are individually mapped extents |
| **CXL multi-host atomics** | Core design primitive: all metadata and cache transitions use `cmpxchg` on shared memory | Not used; relies on single-writer log for metadata consistency |
| **Layered storage** | Base image + overlay (shared base with per-instance COW) | No layering concept |

FamFS is a thin mapping layer that exposes pre-allocated files on shared memory.
DAXFS is a general-purpose shared in-memory filesystem that uses CXL shared memory
atomics for lock-free multi-host coordination: concurrent writes, cooperative
caching, and layered storage without a central coordinator.

## Building

```bash
make              # build kernel module + tools
make clean
```

Requires Linux 5.11+ and `CONFIG_FS_DAX` enabled in the target kernel.

## Usage

```bash
# Create a static read-only image
mkdaxfs -d /path/to/rootfs -o image.daxfs

# Create and mount from DMA heap (read-only)
mkdaxfs -d /path/to/rootfs -H /dev/dma_heap/system -s 256M -m /mnt

# Split mode: metadata+overlay+cache in DAX, file data in backing file (writable)
mkdaxfs -d /path/to/rootfs -H /dev/dma_heap/mk -m /mnt -o /data/rootfs.img

# Empty mode: writable filesystem with no base image
mkdaxfs --empty -H /dev/dma_heap/mk -m /mnt -s 256M

# Custom overlay sizing
mkdaxfs -d /path/to/rootfs -o image.daxfs -O 128M -B 131072

# Create at physical address, then mount separately
mkdaxfs -d /path/to/rootfs -p 0x100000000 -s 256M
mount -t daxfs -o phys=0x100000000,size=0x10000000 none /mnt

# Split mode mount with backing file
mount -t daxfs -o phys=ADDR,size=SIZE,backing=/data/rootfs.img none /mnt
```

### mkdaxfs Options

| Option | Description |
|--------|-------------|
| `-d, --directory DIR` | Source directory |
| `-o, --output FILE` | Output file (backing file in split mode) |
| `-H, --heap PATH` | Allocate from DMA heap |
| `-m, --mountpoint DIR` | Mount after creating (required with `-H`) |
| `-p, --phys ADDR` | Write to physical address via `/dev/mem` |
| `-s, --size SIZE` | Override allocation size |
| `-O, --overlay SIZE` | Overlay pool size (enables writes; default 64M in split/empty) |
| `-B, --buckets N` | Overlay bucket count (power of 2; default 65536) |
| `-C, --pcache-slots N` | Page cache slot count (power of 2; auto in split mode) |
| `-E, --empty` | Empty mode: overlay + pcache only, no base image |
| `-V, --validate` | Validate image on mount |

### Mount Options

`phys=ADDR`, `size=SIZE`, `validate` (check untrusted data),
`backing=PATH` (backing file for split mode).

For dma-buf backing, use the new mount API (`fsopen`/`fsconfig`/`fsmount`) with
`FSCONFIG_SET_FD` to pass the dma-buf fd.

### Inspection

```bash
# Show memory layout and status
daxfs-inspect status -m /mnt/daxfs

# Show overlay hash table details (bucket utilization, entry types, pool usage)
daxfs-inspect overlay -m /mnt/daxfs

# Inspect via physical address
daxfs-inspect status -p 0x100000000 -s 256M
```

## Architecture

### Modes

| Mode | Layout | Description |
|------|--------|-------------|
| **Static** | `[Super][Base Image]` | Read-only, base image embedded in DAX |
| **Split** | `[Super][Base Image][Overlay][PCache]` | Writable, metadata+overlay in DAX, file data in backing file |
| **Empty** | `[Super][Overlay][PCache]` | Writable, no base image, all content via overlay |

### Hash Overlay

The overlay replaces traditional journaling or log-structured writes with a CAS-based
hash table on DAX memory. Multiple kernels or CXL hosts can write concurrently with
no locks.

- **Open addressing** with linear probing, 16-byte buckets
- **Atomic insert** via `cmpxchg` on bucket's `state_key` field (FREE→USED)
- **Bump allocator** for pool entries (atomic fetch-and-add on `pool_alloc`)
- **Entry types**: inode metadata, data pages (4KB COW), directory entries with tombstone deletion

Key encoding (63 bits):
- **Data**: `(ino << 20) | pgoff` (up to 1M pages per file)
- **Inode**: `(ino << 20) | 0xFFFFF` (sentinel pgoff)
- **Dirent**: `FNV-1a(parent_ino, name)` (63-bit hash)

Read path: overlay → base image → pcache (backing store).
Write path: COW from base image into overlay data page.

### Shared Page Cache

Direct-mapped cache in DAX memory for backing store mode. Because DAX memory is
physically shared across kernel instances and CXL hosts, the cache is automatically
visible to all participants with no coherency protocol.

- **3-state machine**: FREE → PENDING → VALID, all transitions via `cmpxchg`
- **Multi-file tags**: `tag = (ino << 20) | pgoff`, multiple backing files share one cache
- **Host fills, spawns wait**: host kernel reads backing file into PENDING slots; spawn kernels busy-poll until VALID
- **Pre-warming**: `mkdaxfs` pre-populates cache slots at image creation time

## On-Disk Format

Defined in `include/daxfs_format.h` (version 7).

| Region | Content |
|--------|---------|
| Superblock | Magic, version, region offsets (4KB) |
| Base image | Read-only snapshot: inode table + data (optional) |
| Overlay | CAS hash table + bump-allocated pool (optional, enables writes) |
| Page cache | Shared cache slots for backing store mode (optional) |

**Base image** (flat format):
- Inode table: fixed 64-byte entries
- Data area: file contents + directory entry arrays
- Directories store `daxfs_dirent` arrays (271 bytes each, 255-char max name)

**Overlay** (hash table):
- Header (4KB): magic, bucket count, pool offsets, atomic counters
- Bucket array: `bucket_count × 16` bytes, open addressing
- Pool: variable-size entries (inodes 32B, data pages 4104B, dirents ~280B)

**Page cache**:
- Header (4KB): magic, slot count, offsets, pending counter
- Slot metadata: `slot_count × 16` bytes (state\_tag + ref\_bit)
- Slot data: `slot_count × 4KB` pages

## Security

DAXFS uses a flat directory format designed for safe handling of untrusted images:

| Property | Benefit |
|----------|---------|
| Flat directories | No linked lists, no cycle attacks |
| Fixed-size dirents | Bounded iteration, trivial validation |
| Inline names | No string table indirection |
| Mount-time validation | Optional `validate` mount option |

## Limitations

- No mknod support (device nodes, FIFOs, sockets not supported)
- Filename max 255 characters (matches VFS NAME_MAX)
- Overlay pool entries are recycled via per-type free lists, but the pool itself is not compacted
- Multi-file pcache tag supports up to ~1M pages per file (4GB with 4KB pages)
- Overlay hash table size is fixed at creation time
