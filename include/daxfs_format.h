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
#define DAXFS_VERSION		8
#define DAXFS_MIN_BLOCK_SIZE	4096	/* Minimum (superblock/header padding) */
#define DAXFS_INODE_SIZE	64
#define DAXFS_NAME_MAX		255
#define DAXFS_DIRENT_SIZE	(16 + DAXFS_NAME_MAX)	/* ino + mode + name_len + reserved + name */
#define DAXFS_ROOT_INO		1

/*
 * Superblock - 4KB struct at offset 0, occupies one block (block_size bytes)
 *
 * On-DAX Layout:
 * [ Superblock (block_size) | Base Image (optional) | Overlay (optional) | Page Cache (optional) ]
 *
 * All layout metadata lives here - region headers only carry magic/version
 * for validation, not duplicated layout fields.
 */
struct daxfs_super {
	__le32 magic;			/* DAXFS_SUPER_MAGIC */
	__le32 version;			/* DAXFS_VERSION */
	__le32 block_size;		/* Native page size at mkfs time */
	__le32 reserved0;
	__le64 total_size;

	/* Base image (optional embedded read-only image) */
	__le64 base_offset;		/* Offset to base image (0 if none) */
	__le64 base_size;
	__le64 inode_offset;		/* Offset to inode table (relative to base_offset) */
	__le32 inode_count;		/* Number of inodes */
	__le32 root_inode;		/* Root directory inode number */
	__le64 data_offset;		/* Offset to file data area (relative to base_offset) */

	/* Hash overlay region (optional, enables writes) */
	__le64 overlay_offset;		/* Offset to overlay region (0 if none) */
	__le64 overlay_size;		/* Total size of overlay region */
	__le32 overlay_bucket_count;	/* Number of buckets (power of 2) */
	__le32 overlay_bucket_shift;	/* log2(bucket_count) */

	/* Page cache for backing store mode */
	__le64 pcache_offset;		/* Offset to page cache region (0 = no cache) */
	__le64 pcache_size;		/* Total size of page cache region */
	__le32 pcache_slot_count;	/* Number of cache slots */
	__le32 pcache_hash_shift;	/* log2(slot_count) for masking */

	__u8   reserved[3984];		/* Pad to 4KB */
};

/*
 * ============================================================================
 * Base Image Format (embedded read-only snapshot)
 * ============================================================================
 *
 * The base image is an optional embedded read-only filesystem image
 * that provides the initial state. New changes are stored in the overlay.
 *
 * Layout within base region (no sub-header):
 *   [Inode table] [File/dir/symlink data]
 *
 * Flat directories: directory contents are stored as an array of
 * daxfs_dirent entries in the data area. No linked lists, no string
 * table - names are stored directly in directory entries.
 */

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
 * Hash Overlay (CAS-based, lock-free writes for multi-kernel access)
 * ============================================================================
 *
 * Open-addressing hash table on DAX memory. Each bucket is 16 bytes
 * so cmpxchg16b can atomically update state + key + value.
 *
 * Pool entries are bump-allocated from a contiguous region after
 * the bucket array.
 */

#define DAXFS_OVERLAY_MAGIC	0x6f766c79	/* "ovly" */
#define DAXFS_OVERLAY_VERSION	2

/* Entry types stored in pool */
#define DAXFS_OVL_INODE		1
#define DAXFS_OVL_DATA		2
#define DAXFS_OVL_DIRENT	3
#define DAXFS_OVL_DIRLIST	4	/* Per-directory dirent list head */

/* Dirent flags */
#define DAXFS_OVL_DIRENT_TOMBSTONE	(1 << 0)

/* Sentinel for end of dirent hash collision chain */
#define DAXFS_OVL_NO_NEXT		(((__u64)-1))

/* Sentinel for empty free list / end of free chain */
#define DAXFS_OVL_FREE_END		(((__u64)-1))

/*
 * Bucket: 16 bytes, open addressing with linear probing.
 * state_key: bit[0] = state (FREE=0, USED=1), bits[63:1] = key
 */
struct daxfs_overlay_bucket {
	__le64 state_key;	/* CAS target: bit0=USED, bits[63:1]=key */
	__le64 value;		/* Pool offset of entry */
};

#define DAXFS_OVL_FREE		0
#define DAXFS_OVL_USED		1

#define DAXFS_OVL_STATE(v)	((v) & 1)
#define DAXFS_OVL_KEY(v)	((v) >> 1)
#define DAXFS_OVL_MAKE(state, key)	(((key) << 1) | (state))

/*
 * Key encoding (63 bits):
 *   DATA:    (ino << 20) | (pgoff & 0xFFFFF)   — pgoff must be < 0xFFFFE
 *   INODE:   (ino << 20) | 0xFFFFF             — sentinel
 *   DIRLIST: (ino << 20) | 0xFFFFE             — sentinel
 *   DIRENT:  hash(parent_ino, name)            — 63-bit FNV-1a variant
 */
#define DAXFS_OVL_MAX_PGOFF			0xFFFFDULL	/* Max valid pgoff for DATA keys */
#define DAXFS_OVL_KEY_DATA(ino, pgoff)		((((__u64)(ino)) << 20) | ((pgoff) & 0xFFFFF))
#define DAXFS_OVL_KEY_INODE(ino)		((((__u64)(ino)) << 20) | 0xFFFFF)
#define DAXFS_OVL_KEY_DIRLIST(ino)		((((__u64)(ino)) << 20) | 0xFFFFE)
#define DAXFS_OVL_KEY_INO(key)			((key) >> 20)
#define DAXFS_OVL_KEY_PGOFF(key)		((key) & 0xFFFFF)

/*
 * Overlay header — 4KB, at overlay_offset
 *
 * Bucket count/shift are in the main superblock.
 * This header carries magic/version for validation plus
 * runtime-mutable fields (pool_alloc, next_ino).
 */
struct daxfs_overlay_header {
	__le32 magic;			/* DAXFS_OVERLAY_MAGIC */
	__le32 version;			/* DAXFS_OVERLAY_VERSION */
	__le64 bucket_offset;		/* From overlay start */
	__le64 pool_offset;		/* From overlay start */
	__le64 pool_size;		/* Total pool capacity */
	__le64 pool_alloc;		/* Atomic bump allocator (next free byte) */
	__le64 next_ino;		/* Atomic inode counter */

	/*
	 * Per-size-class free lists for pool entry recycling.
	 * Each is a CAS-based stack head (pool offset, or
	 * DAXFS_OVL_FREE_END if empty). Freed entries reuse
	 * their first 8 bytes as the next-free pointer.
	 */
	__le64 free_inode;		/* Free list: inode entries */
	__le64 free_data;		/* Free list: data page entries */
	__le64 free_dirent;		/* Free list: dirent entries */

	__u8   reserved[4096 - 72];	/* Pad to 4KB */
};

/*
 * Pool entries (variable size, bump-allocated)
 */
struct daxfs_ovl_inode_entry {
	__le32 type;		/* DAXFS_OVL_INODE */
	__le32 mode;
	__le32 uid;
	__le32 gid;
	__le64 size;
	__le32 nlink;
	__le32 flags;
};

/*
 * Data page entries are raw block_size allocations in the pool
 * with no header. This makes consecutively allocated pages
 * contiguous in memory, enabling large sequential reads.
 * The entry type is inferred from the hash key encoding.
 *
 * Free-list recycling reuses the first 8 bytes of the page
 * as the next-free pointer (same as other entry types).
 */

struct daxfs_ovl_dirent_entry {
	__le32 type;		/* DAXFS_OVL_DIRENT */
	__le32 flags;		/* DAXFS_OVL_DIRENT_TOMBSTONE etc. */
	__le64 parent_ino;
	__le64 child_ino;
	__le32 child_mode;
	__le16 name_len;
	__u8   reserved[2];
	__le64 next;		/* Pool offset of next entry in hash chain,
				 * DAXFS_OVL_NO_NEXT = end of chain */
	__le64 dir_next;	/* Next dirent in same directory's list,
				 * DAXFS_OVL_NO_NEXT = end of list */
	char   name[DAXFS_NAME_MAX + 1]; /* Null-terminated */
};

/*
 * Per-directory dirent list head — links all overlay dirents in one
 * directory for O(n) readdir instead of O(bucket_count).
 *
 * Keyed by DAXFS_OVL_KEY_DIRLIST(parent_ino). The 'first' field is
 * the pool offset of the first dirent; new entries are CAS-prepended.
 */
struct daxfs_ovl_dirlist_entry {
	__le32 type;		/* DAXFS_OVL_DIRLIST */
	__le32 reserved;
	__le64 first;		/* Pool offset of first dirent, or
				 * DAXFS_OVL_NO_NEXT = empty */
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
 * Slot count/hash_shift are in the main superblock.
 *
 * Region layout:
 *   [pcache_header (block_size)]
 *   [slot_metadata (slot_count * 16B, padded to block_size)]
 *   [slot_data (slot_count * block_size)]
 */

#define DAXFS_PCACHE_MAGIC	0x70636163	/* "pcac" */
#define DAXFS_PCACHE_VERSION	2

/* Cache slot states (stored in bits[1:0] of state_tag) */
#define PCACHE_STATE_FREE	0	/* Slot empty, available */
#define PCACHE_STATE_PENDING	1	/* Claimed, needs host to fill */
#define PCACHE_STATE_VALID	2	/* Data ready */

/*
 * Packed state_tag layout (64 bits):
 *   bits[1:0]  = state (FREE/PENDING/VALID)
 *   bits[5:2]  = refcount (0-15 concurrent readers)
 *   bits[63:6] = tag
 *
 * Readers CAS-increment refcount to pin a slot during access.
 * Eviction only succeeds when refcount == 0.
 */
#define PCACHE_STATE(v)		((v) & 3)
#define PCACHE_REFCNT(v)	(((v) >> 2) & 0xF)
#define PCACHE_TAG(v)		((v) >> 6)
#define PCACHE_MAKE(state, tag)	(((tag) << 6) | (state))
#define PCACHE_REFCNT_INC	4	/* Add to state_tag to increment refcount */
#define PCACHE_REFCNT_MAX	15

/* Multi-file tag encoding: tag = (ino << 20) | (pgoff & 0xFFFFF) */
#define PCACHE_TAG_MAKE(ino, pgoff)	((((__u64)(ino)) << 20) | ((pgoff) & 0xFFFFF))
#define PCACHE_TAG_INO(tag)		((tag) >> 20)
#define PCACHE_TAG_PGOFF(tag)		((tag) & 0xFFFFF)

#define PCACHE_PROBE_LEN	8
#define PCACHE_SWEEP_BATCH	64

/*
 * Page cache header — 4KB, at pcache_offset
 *
 * Slot count/hash_shift are in the main superblock.
 * This header carries magic/version for validation plus
 * runtime-mutable fields (evict_hand, pending_count).
 */
struct daxfs_pcache_header {		/* 4KB, at pcache_offset */
	__le32 magic;			/* DAXFS_PCACHE_MAGIC */
	__le32 version;			/* DAXFS_PCACHE_VERSION */
	__le64 slot_meta_offset;	/* From pcache_offset */
	__le64 slot_data_offset;	/* From pcache_offset */
	__le32 evict_hand;		/* Clock sweep position (atomic) */
	__le32 pending_count;		/* Atomic: PENDING slots outstanding */
	__u8   reserved[4096 - 32];
};

struct daxfs_pcache_slot {		/* 16 bytes per slot */
	__le64 state_tag;		/* bits[1:0] = state, bits[5:2] = refcount,
					 * bits[63:6] = tag. Packed so cmpxchg
					 * atomically updates all three. */
	__le32 ref_bit;			/* Clock algorithm: recently accessed */
	__le32 reserved;
};

#endif /* _DAXFS_FORMAT_H */
