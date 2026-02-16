# DAXFS

**Secure delta-log memory native filesystem with speculative branching.**

DAXFS operates directly on DAX-capable memory (persistent memory, CXL memory, or DMA
buffers) via direct load/store access. It combines a read-only base image with
copy-on-write branches - file reads resolve to direct memory loads with no page cache,
no buffer heads, and no copies.

**Not for traditional disks.** DAXFS requires byte-addressable memory with DAX support.
It cannot run on block devices, the entire design assumes direct memory pointer access
and synchronization with `cmpxchg`.

## Features

- **Zero-copy reads** - Direct memory access, no page cache overhead
- **Security by simplicity** - Flat directory format, bounded validation, no pointer chasing
- **N-level speculative branches** - Nested speculation with commit-to-root/abort semantics
- **Flexible backing** - Physical address, DAX device, or dma-buf
- **Backing store mode** - Split metadata (DAX) from file data (backing file) with shared page cache

## Security

DAXFS v5 uses a flat directory format designed for safe handling of untrusted images:

| Property | Benefit |
|----------|---------|
| Flat directories | No linked lists, no cycle attacks |
| Fixed-size dirents | Bounded iteration, trivial validation |
| Inline names | No string table indirection |
| Mount-time validation | Optional `validate` mount option |

The simple format makes complete validation feasible - no complex tree traversal or
pointer chasing required.

## Use Cases

- **AI agent speculative execution** - Parallel exploration with single-winner commit
- **Multikernel** - Shared rootfs across kernel instances with cross-kernel branch coordination
- **CXL memory pooling** - Common filesystem across CXL-connected hosts
- **GPU/accelerator** - Zero-copy access to data via dma-buf
- **Container rootfs** - Shared base image with per-container branches

## Why Not ...

| Filesystem | Limitation for this use case |
|------------|------------------------------|
| **tmpfs/ramfs** | Per-instance, N containers = N copies in memory |
| **overlayfs** | No nested branching, copy-up on write, page cache overhead |
| **erofs** | Read-only, no branching; fscache is per-kernel so N kernels = N cache copies |
| **famfs** | Per-file allocation complexity, no self-contained images |
| **cramfs** | Block I/O + page cache, no direct memory mapping |

## Building

```bash
make              # build kernel module + tools
make clean
```

Requires `CONFIG_FS_DAX` enabled in the target kernel.

## Usage

```bash
# Create and mount from DMA heap (typical workflow)
mkdaxfs -d /path/to/rootfs -H /dev/dma_heap/system -s 256M -m /mnt -b

# Create at physical address, then mount separately
mkdaxfs -d /path/to/rootfs -p 0x100000000 -s 256M -b
mount -t daxfs -o phys=0x100000000,size=0x10000000 none /mnt

# Create format blob (copy to DAX memory to mount)
mkdaxfs -d /path/to/rootfs -o image.daxfs -b

# Split mode: metadata+cache in DAX, file data in backing file
mkdaxfs -d /path/to/rootfs -H /dev/dma_heap/mk -m /mnt -o /data/rootfs.img -b
mount -t daxfs -o phys=ADDR,size=SIZE,backing=/data/rootfs.img none /mnt
```

Mount options: `phys=ADDR`, `size=SIZE`, `validate` (check untrusted data),
`backing=PATH` (backing file for split mode).

For dma-buf backing, use the new mount API (`fsopen`/`fsconfig`/`fsmount`) with
`FSCONFIG_SET_FD` to pass the dma-buf fd.

## Branching

Branches enable speculative execution with N-level depth and single-winner semantics.

**Main branch is read-only**. To write, create a child branch:

```bash
# Mount main branch (read-only)
mount -t daxfs -o phys=0x100000000,size=256M none /mnt/main

# Create speculation branch (writable)
daxfs-branch create spec1 -m /mnt/spec1 -p main

# Create deeper speculation (N-level)
daxfs-branch create spec1a -m /mnt/spec1a -p spec1

# List all branches
daxfs-branch list

# Commit - merges entire chain to main, invalidates all siblings
daxfs-branch commit -m /mnt/spec1a

# Abort - discards entire chain back to main
daxfs-branch abort -m /mnt/spec1a

# Unmount - discards only current branch (single-level backtrack)
umount /mnt/spec1a
```

**Per-mount branch views**: Each mount is tied to one branch. To work on a
different branch, mount it at a different path.

**N-level speculation**: Branches can be nested arbitrarily deep. Complex tasks
naturally require deeper speculation trees.

**Commit semantics**: Commits the entire branch chain to main and invalidates
ALL sibling branches at every level. Processes with mmap'd files on invalidated
branches receive SIGBUS. File/directory operations return ESTALE.

**Abort semantics**: Discards the entire branch chain back to main. Does NOT
affect sibling branches (they continue unaffected).

**Unmount semantics**: Discards only the current branch. Parent chain remains,
allowing single-level backtracking.

**Multi-kernel coordination**: Multiple kernels can mount sibling branches on
the same DAX region. Coordination uses hardware atomics on shared DAX memory,
no distributed consensus needed.

This model is designed for AI agent speculative execution - multiple agents
explore different paths, one wins (commit), others are discarded.

### Why not subvolumes?

Btrfs-style COW subvolumes are independent trees with no natural merge operation. DAXFS
branches use delta-logs instead:

| Aspect | COW Subvolumes | Delta-log Branches |
|--------|----------------|-------------------|
| Create | Snapshot tree metadata | Allocate log region |
| Commit | Diff trees + apply (expensive) | Append deltas to parent (fast) |
| Abort | Delete snapshot | Discard log region |
| N-level | Independent trees, complex merge | Chain merges naturally to root |

Speculative execution needs fast commit. Delta-logs give O(deltas) merge; COW subvolumes
require O(tree) diffing. The delta-log model is purpose-built for speculative branching
with N-level depth.

### Why not existing filesystems for branching?

| Filesystem | Log-structured | In-memory index | Hierarchical branches |
|------------|----------------|-----------------|----------------------|
| NILFS2 | Yes | Yes | No (linear snapshots) |
| Btrfs | No (CoW B-tree) | No | Yes, but no commit/abort semantics |
| F2FS | Yes | Yes | No |
| DAXFS | Yes | Yes | Yes |

- **NILFS2** - Checkpoints are linear, not a tree. Cannot branch independently.
- **Btrfs** - Snapshots exist but no built-in "discard siblings on commit" semantic.
- **EROFS** - Read-only by design; adding branching would negate its performance.

## On-Disk Format

Defined in `include/daxfs_format.h`. Layout:

| Region | Content |
|--------|---------|
| Superblock | Magic, version, offsets, global coordination (4KB) |
| Branch table | 128-byte entries, up to 256 branches |
| Base image | Read-only snapshot (inode table + data) |
| Page cache | Shared cache slots for backing store mode (optional) |
| Delta region | Branch delta logs |

**Global coordination** (in superblock): commit sequence counter and spinlock for
cross-kernel synchronization. Uses `cmpxchg` on DAX memory - works across kernel
instances without distributed locking protocols.

**Base image** (v5 flat format):
- Inode table: fixed 64-byte entries
- Data area: file contents + directory entry arrays
- Directories store `daxfs_dirent` arrays (271 bytes each, 255-char max name)

**Page cache** (backing store mode): Direct-mapped cache in DAX memory for split-mode
images where metadata stays in DAX and file data lives in an external backing file.
Uses a 3-state machine (FREE/PENDING/VALID) with atomic `cmpxchg` transitions for
lock-free cross-kernel sharing. The host kernel fills cache misses from the backing
file; spawn kernels mark slots PENDING and wait for the host to fill them.

**Delta log** entries: write, create, delete, truncate, mkdir, rename, setattr, symlink.

## Limitations

- Hard links from base image are preserved, but cannot be created in branches
- No mknod support (device nodes, FIFOs, sockets not supported)
- Filename max 255 characters (matches VFS NAME_MAX)
- Branch table max 256 entries
