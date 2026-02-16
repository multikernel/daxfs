/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * daxfs on-disk format definitions
 *
 * Shared between kernel module and user-space tools (e.g., mkfs.daxfs).
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */
#ifndef _DAXFS_FORMAT_H
#define _DAXFS_FORMAT_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* ioctl commands */
#define DAXFS_IOC_GET_DMABUF	_IO('D', 1)	/* Get dma-buf fd for this mount */

#define DAXFS_SUPER_MAGIC	0x64617835	/* "dax5" */
#define DAXFS_VERSION		5
#define DAXFS_BLOCK_SIZE	4096
#define DAXFS_INODE_SIZE	64
#define DAXFS_NAME_MAX		255
#define DAXFS_DIRENT_SIZE	(16 + DAXFS_NAME_MAX)	/* ino + mode + name_len + reserved + name */
#define DAXFS_ROOT_INO		1

#define DAXFS_BRANCH_NAME_MAX	31
#define DAXFS_MAX_BRANCHES	256

/* Branch states */
#define DAXFS_BRANCH_FREE	0
#define DAXFS_BRANCH_ACTIVE	1
#define DAXFS_BRANCH_COMMITTED	2
#define DAXFS_BRANCH_ABORTED	3

/* Delta log entry types */
#define DAXFS_DELTA_WRITE	1	/* File data write */
#define DAXFS_DELTA_CREATE	2	/* Create file */
#define DAXFS_DELTA_DELETE	3	/* Delete (tombstone) */
#define DAXFS_DELTA_TRUNCATE	4	/* Truncate file */
#define DAXFS_DELTA_MKDIR	5	/* Create directory */
#define DAXFS_DELTA_RENAME	6	/* Rename */
#define DAXFS_DELTA_SETATTR	7	/* Inode metadata update */
#define DAXFS_DELTA_SYMLINK	8	/* Create symlink */

/*
 * Superblock - at offset 0, 4KB
 *
 * On-DAX Layout:
 * [ Superblock (4KB) | Branch Table | Base Image (optional) | Delta Region ]
 */
/*
 * Global coordination structure for cross-mount branch synchronization.
 * Located at offset 152 in superblock (start of reserved area).
 */
struct daxfs_global_coord {
	__le64 commit_sequence;		/* Incremented on each commit */
	__le64 last_committed_id;	/* Branch ID that last committed */
	__le32 coord_lock;		/* Simple spinlock (0=free, 1=held) */
	__le32 padding;
	__u8   reserved[40];		/* Total 64 bytes */
};

struct daxfs_super {
	__le32 magic;			/* DAXFS_SUPER_MAGIC (0x64617834) */
	__le32 version;			/* DAXFS_VERSION */
	__le32 flags;
	__le32 block_size;		/* 4096 */
	__le64 total_size;

	/* Base image (optional embedded read-only image) */
	__le64 base_offset;		/* Offset to base image (0 if none) */
	__le64 base_size;

	/* Branch management */
	__le64 branch_table_offset;
	__le32 branch_table_entries;	/* Max branches (DAXFS_MAX_BRANCHES) */
	__le32 active_branches;
	__le64 next_branch_id;
	__le64 next_inode_id;		/* Global inode counter */

	/* Delta region */
	__le64 delta_region_offset;
	__le64 delta_region_size;	/* Total size of delta region */
	__le64 delta_alloc_offset;	/* Next free byte in delta region */

	/* Global coordination - at offset 152 (64 bytes) */
	struct daxfs_global_coord coord;

	/* Page cache for backing store mode */
	__le64 pcache_offset;		/* Offset to page cache region (0 = no cache) */
	__le64 pcache_size;		/* Total size of page cache region */
	__le32 pcache_slot_count;	/* Number of cache slots */
	__le32 pcache_hash_shift;	/* log2(slot_count) for masking */
	__le32 pcache_pending;		/* Atomic: count of PENDING slots */
	__le32 pcache_reserved;

	__u8   reserved[3848];		/* Pad to 4KB (3880 - 32) */
};

/*
 * Branch record - 128 bytes
 */
struct daxfs_branch {
	__le64 branch_id;
	__le64 parent_id;		/* 0 = no parent (main branch) */
	__le64 delta_log_offset;	/* Start of this branch's delta log */
	__le64 delta_log_size;		/* Bytes used */
	__le64 delta_log_capacity;	/* Bytes allocated */
	__le32 state;			/* FREE, ACTIVE, COMMITTED, ABORTED */
	__le32 refcount;		/* Child branches + active mounts */
	__le64 next_local_ino;		/* Branch-local inode counter */
	char   name[32];		/* Branch name (null-terminated) */
	__le32 generation;		/* Incremented on invalidation */
	__u8   reserved[36];		/* Pad to 128 bytes */
};

/*
 * Delta log entry header - variable size entries
 */
struct daxfs_delta_hdr {
	__le32 type;
	__le32 total_size;		/* Size of this entry including header */
	__le64 ino;
	__le64 timestamp;		/* For ordering */
};

/*
 * WRITE entry: header + this + data
 */
struct daxfs_delta_write {
	__le64 offset;			/* File offset */
	__le32 len;			/* Data length */
	__le32 flags;
	/* Data follows immediately */
};

/*
 * CREATE entry: header + this + name
 */
struct daxfs_delta_create {
	__le64 parent_ino;
	__le64 new_ino;
	__le32 mode;
	__le32 uid;
	__le32 gid;
	__le16 name_len;
	__le16 flags;
	/* Name follows immediately */
};

/*
 * DELETE entry (tombstone): header + this + name
 */
struct daxfs_delta_delete {
	__le64 parent_ino;
	__le16 name_len;
	__le16 flags;
	__le32 reserved;
	/* Name follows immediately */
};

/*
 * TRUNCATE entry: header + this
 */
struct daxfs_delta_truncate {
	__le64 new_size;
};

/*
 * RENAME entry: header + this + old_name + new_name
 */
struct daxfs_delta_rename {
	__le64 old_parent_ino;
	__le64 new_parent_ino;
	__le64 ino;
	__le16 old_name_len;
	__le16 new_name_len;
	__le32 reserved;
	/* old_name then new_name follow */
};

/*
 * SETATTR entry: header + this
 */
struct daxfs_delta_setattr {
	__le32 mode;
	__le32 uid;
	__le32 gid;
	__le32 valid;			/* Bitmask of which fields are valid */
	__le64 size;			/* For truncate via setattr */
};

/* Flags for daxfs_delta_setattr.valid */
#define DAXFS_ATTR_MODE		(1 << 0)
#define DAXFS_ATTR_UID		(1 << 1)
#define DAXFS_ATTR_GID		(1 << 2)
#define DAXFS_ATTR_SIZE		(1 << 3)

/*
 * SYMLINK entry: header + this + name + target
 */
struct daxfs_delta_symlink {
	__le64 parent_ino;
	__le64 new_ino;
	__le32 uid;
	__le32 gid;
	__le16 name_len;
	__le16 target_len;
	/* Name follows immediately, then target (null-terminated) */
};

/*
 * ============================================================================
 * Base Image Format (embedded read-only snapshot)
 * ============================================================================
 *
 * The base image is an optional embedded read-only filesystem image
 * that provides the initial state. New changes are stored in deltas.
 *
 * Version 4 uses flat directories: directory contents are stored as an
 * array of daxfs_dirent entries in the data area. No linked lists, no
 * string table - names are stored directly in directory entries.
 */

#define DAXFS_BASE_MAGIC	0x64646135	/* "dda5" - version 5 */

/* Base image flags */
#define DAXFS_BASE_FLAG_EXTERNAL_DATA	(1 << 0)  /* Regular file data in external backing file */

/*
 * Base image superblock - always at base_offset, padded to DAXFS_BLOCK_SIZE
 */
struct daxfs_base_super {
	__le32 magic;		/* DAXFS_BASE_MAGIC */
	__le32 version;		/* 4 */
	__le32 flags;
	__le32 block_size;	/* Always DAXFS_BLOCK_SIZE */
	__le64 total_size;	/* Total base image size in bytes */
	__le64 inode_offset;	/* Offset to inode table (relative to base) */
	__le32 inode_count;	/* Number of inodes */
	__le32 root_inode;	/* Root directory inode number */
	__le64 data_offset;	/* Offset to file data area (relative to base) */
	__u8   reserved[4048];	/* Pad to 4KB */
};

/*
 * Base image inode - fixed size for simple indexing (64 bytes)
 *
 * For directories: data_offset points to array of daxfs_dirent,
 *                  size = number of entries * DAXFS_DIRENT_SIZE
 * For regular files: data_offset points to file data, size = file size
 * For symlinks: data_offset points to target string (null-terminated),
 *               size = target length (excluding null)
 */
struct daxfs_base_inode {
	__le32 ino;		/* Inode number (1-based) */
	__le32 mode;		/* File type and permissions */
	__le32 uid;		/* Owner UID */
	__le32 gid;		/* Owner GID */
	__le64 size;		/* Size in bytes (see above) */
	__le64 data_offset;	/* Offset to data (relative to base) */
	__le32 nlink;		/* Link count */
	__u8   reserved[28];	/* Pad to DAXFS_INODE_SIZE (64 bytes) */
};

/*
 * Directory entry - fixed size for simple validation
 *
 * Directories store an array of these entries at their data_offset.
 * Names are stored inline, no string table needed.
 */
struct daxfs_dirent {
	__le32 ino;			/* Child inode number */
	__le32 mode;			/* Child file type and permissions */
	__le16 name_len;		/* Actual name length */
	__u8   reserved[6];		/* Padding */
	char   name[DAXFS_NAME_MAX];	/* Name (not null-terminated, use name_len) */
};

/*
 * ============================================================================
 * Page Cache (shared across kernel instances via DAX memory)
 * ============================================================================
 *
 * Direct-mapped cache for backing store mode. Each backing file page maps
 * to exactly one cache slot via hash. 3-state machine with all transitions
 * via cmpxchg on DAX memory (no IPIs needed).
 *
 * Region layout:
 *   [pcache_header (4KB)]
 *   [slot_metadata (slot_count * 16B, padded to 4KB)]
 *   [slot_data (slot_count * 4KB)]
 */

#define DAXFS_PCACHE_MAGIC	0x70636163	/* "pcac" */
#define DAXFS_PCACHE_VERSION	1

/* Cache slot states (stored in bits[1:0] of state_tag) */
#define PCACHE_STATE_FREE	0	/* Slot empty, available */
#define PCACHE_STATE_PENDING	1	/* Claimed, needs host to fill */
#define PCACHE_STATE_VALID	2	/* Data ready */

/* Helpers for packed state_tag field */
#define PCACHE_STATE(v)		((v) & 3)
#define PCACHE_TAG(v)		((v) >> 2)
#define PCACHE_MAKE(state, tag)	(((tag) << 2) | (state))

struct daxfs_pcache_header {		/* 4KB, at pcache_offset */
	__le32 magic;			/* DAXFS_PCACHE_MAGIC */
	__le32 version;			/* DAXFS_PCACHE_VERSION */
	__le32 slot_count;
	__le32 hash_shift;
	__le64 slot_meta_offset;	/* From pcache_offset */
	__le64 slot_data_offset;	/* From pcache_offset */
	__le32 evict_hand;		/* Clock sweep position (atomic) */
	__le32 pending_count;		/* Atomic: PENDING slots outstanding */
	__u8   reserved[4096 - 40];
};

struct daxfs_pcache_slot {		/* 16 bytes per slot */
	__le64 state_tag;		/* bits[1:0] = state, bits[63:2] = tag */
					/* Packed so cmpxchg atomically sets both */
	__le32 ref_bit;			/* Clock algorithm: recently accessed */
	__le32 reserved;
};

#endif /* _DAXFS_FORMAT_H */
