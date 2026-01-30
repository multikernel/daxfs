# DAXFS

**Secure delta-log filesystem for byte-addressable persistent memory.**

DAXFS operates directly on DAX-capable memory (persistent memory, CXL memory, or DMA
buffers) via direct load/store access. It combines a read-only base image with
copy-on-write branches - file reads resolve to direct memory loads with no page cache,
no buffer heads, and no copies.

**Not for traditional disks.** DAXFS requires byte-addressable memory with DAX support.
It cannot run on block devices (spinning disks, standard SSDs) - the entire design
assumes direct pointer access without block I/O.

## Features

- **Zero-copy reads** - Direct memory access, no page cache overhead
- **Security by simplicity** - Flat directory format, bounded validation, no pointer chasing
- **N-level speculative branches** - Nested speculation with commit-to-root/abort semantics
- **Flexible backing** - Physical address, DAX device, or dma-buf

## Security

DAXFS v4 uses a flat directory format designed for safe handling of untrusted images:

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
- **Multikernel** - Shared rootfs across kernel instances
- **CXL memory pooling** - Common filesystem across CXL-connected hosts
- **GPU/accelerator** - Zero-copy access to data via dma-buf
- **Container rootfs** - Shared base image with per-container branches

## Why Not ...

| Filesystem | Limitation for this use case |
|------------|------------------------------|
| **tmpfs/ramfs** | Per-instance, N containers = N copies in memory |
| **overlayfs** | No nested branching, copy-up on write, page cache overhead |
| **erofs** | Read-only by design, no write path, adding branching negates its benefits |
| **famfs** | Per-file allocation complexity, no self-contained images |
| **cramfs** | Block I/O + page cache, no direct memory mapping |

## Building

```bash
make              # build kernel module + tools
make clean
```

Requires `CONFIG_FS_DAX` enabled in the target kernel.

## Creating Images

```bash
# Create image file
mkdaxfs -d /path/to/rootfs -o image.daxfs

# Create with branching support (read-write)
mkdaxfs -d /path/to/rootfs -o image.daxfs -w

# Allocate from DMA heap and mount
mkdaxfs -d /path/to/rootfs -H /dev/dma_heap/system -s 256M -m /mnt -w
```

## Mounting

```bash
# Physical address
mount -t daxfs -o phys=0x100000000,size=0x10000000 none /mnt

# With validation (for untrusted images)
mount -t daxfs -o phys=0x100000000,size=0x10000000,validate none /mnt

# Read-write with branching
mount -t daxfs -o phys=0x100000000,size=0x10000000,rw none /mnt
```

For dma-buf backing, use the new mount API (`fsopen`/`fsconfig`/`fsmount`) with
`FSCONFIG_SET_FD` to pass the dma-buf fd.

## Branching

Branches enable speculative execution with N-level depth and single-winner semantics:

```bash
# Mount main branch
mount -t daxfs -o phys=0x100000000,size=256M none /mnt/main

# Create speculation branch (new mount)
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
branches receive SIGBUS. File opens return ESTALE.

**Abort semantics**: Discards the entire branch chain back to main. Does NOT
affect sibling branches (they continue unaffected).

**Unmount semantics**: Discards only the current branch. Parent chain remains,
allowing single-level backtracking.

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
| Delta region | Branch delta logs |

**Global coordination** (in superblock): commit sequence counter and lock for
cross-mount synchronization. Enables per-mount branch views with safe invalidation.

**Base image** (v4 flat format):
- Inode table: fixed 64-byte entries
- Data area: file contents + directory entry arrays
- Directories store `daxfs_dirent` arrays (144 bytes each, 128-char max name)

**Delta log** entries: write, create, delete, truncate, mkdir, rename, setattr, symlink.

## Limitations

- No hard links (by design - simplifies delta log)
- Filename max 128 characters
- Branch table max 256 entries
