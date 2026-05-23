/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * daxfs software release version.
 *
 * This is the release version of the daxfs project as a whole (kernel
 * module + user-space tools). It is distinct from the on-disk format
 * versions in daxfs_format.h (DAXFS_VERSION, DAXFS_OVERLAY_VERSION,
 * DAXFS_PCACHE_VERSION), which are bumped only when the binary layout
 * changes. This file is the single source of truth for the release
 * version; the top-level Makefile parses DAXFS_RELEASE_STRING from it.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */
#ifndef _DAXFS_VERSION_H
#define _DAXFS_VERSION_H

#define DAXFS_RELEASE_MAJOR	0
#define DAXFS_RELEASE_MINOR	1
#define DAXFS_RELEASE_PATCH	0
#define DAXFS_RELEASE_STRING	"0.1.0"

#endif /* _DAXFS_VERSION_H */
