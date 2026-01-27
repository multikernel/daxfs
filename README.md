# DAXFS

**Secure copy-on-write filesystem for shared memory.**

DAXFS operates directly on shared physical memory via DAX (Direct Access). It combines
a read-only base image with copy-on-write branches - file reads resolve to direct memory
loads with no page cache, no buffer heads, and no copies.

## Features

- **Zero-copy reads** - Direct memory access, no page cache overhead
- **Security by simplicity** - Flat directory format, bounded validation, no pointer chasing
- **Copy-on-write branches** - Speculative modifications with commit/abort semantics
- **Flexible backing** - Physical address, DAX device, or dma-buf

## Security

DAXFS v3 uses a flat directory format designed for safe handling of untrusted images:

| Property | Benefit |
|----------|---------|
| Flat directories | No linked lists, no cycle attacks |
| Fixed-size dirents | Bounded iteration, trivial validation |
| Inline names | No string table indirection |
| Mount-time validation | Optional `validate` mount option |

The simple format makes complete validation feasible - no complex tree traversal or
pointer chasing required.

## Use Cases

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

Branches enable speculative modifications with a single-winner model:

```bash
daxfs-branch create feature -m /mnt -p main  # create and switch
daxfs-branch list -m /mnt                     # list branches
daxfs-branch commit -m /mnt                   # commit (discards siblings)
daxfs-branch abort -m /mnt                    # abort (discards changes)
```

Committing a branch discards all sibling branches. Aborting discards the current
branch. No merge, no parallel long-lived branches - just speculative execution
with a single winner.

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
| Superblock | Magic, version, offsets (4KB) |
| Branch table | 128-byte entries, up to 256 branches |
| Base image | Read-only snapshot (inode table + data) |
| Delta region | Branch delta logs |

**Base image** (v3 flat format):
- Inode table: fixed 64-byte entries
- Data area: file contents + directory entry arrays
- Directories store `daxfs_dirent` arrays (144 bytes each, 128-char max name)

**Delta log** entries: write, create, delete, truncate, mkdir, rename, setattr, symlink.

## Limitations

- No hard links (by design - simplifies delta log)
- Filename max 128 characters
- Branch table max 256 entries
