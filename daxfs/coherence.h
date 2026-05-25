/* SPDX-License-Identifier: GPL-2.0 */
/*
 * daxfs shared-memory coherence backend.
 *
 * All synchronization on shared DAX memory goes through these helpers so the
 * memory model is selectable per mount. COHERENT is the current, correct
 * behavior for a single hardware cache-coherence domain (multikernel). CXL3
 * is a scaffold for CXL 3.0 HDM-DB shared memory and is NOT yet validated;
 * see docs/COHERENCE.md.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 */
#ifndef _DAXFS_COHERENCE_H
#define _DAXFS_COHERENCE_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <asm/barrier.h>

enum daxfs_mem_model {
	DAXFS_MEM_COHERENT = 0,	/* regular cache-coherent memory (multikernel) */
	DAXFS_MEM_CXL3,		/* CXL 3.0 HDM-DB shared memory (scaffold) */
};

/*
 * 64-bit compare-and-swap on a shared field. Returns the value previously
 * at @ptr. Operates on the raw 64-bit word (callers pass host-order values
 * for fields stored little-endian; this matches the historical behavior and
 * is correct on little-endian hosts).
 */
static inline u64 daxfs_cas64(enum daxfs_mem_model model,
			      void *ptr, u64 old, u64 new)
{
	switch (model) {
	case DAXFS_MEM_CXL3:
		/*
		 * TODO(cxl): validate on hardware. CXL 3.0 HDM-DB maintains
		 * inter-host coherence, so a normal LOCK CMPXCHG is expected to
		 * be globally atomic. If a device needs explicit assist, it goes
		 * here.
		 */
		return cmpxchg((u64 *)ptr, old, new);
	case DAXFS_MEM_COHERENT:
	default:
		return cmpxchg((u64 *)ptr, old, new);
	}
}

/* Ordered read of a little-endian 64-bit shared field (returns host order). */
static inline u64 daxfs_load_once64(enum daxfs_mem_model model,
				    const void *ptr)
{
	switch (model) {
	case DAXFS_MEM_CXL3:
		/* TODO(cxl): a non-HDM-DB device may need an invalidate first. */
		return le64_to_cpu(READ_ONCE(*(const __le64 *)ptr));
	case DAXFS_MEM_COHERENT:
	default:
		return le64_to_cpu(READ_ONCE(*(const __le64 *)ptr));
	}
}

/* Ordered store of a host-order value as a little-endian 64-bit field. */
static inline void daxfs_store_once64(enum daxfs_mem_model model,
				      void *ptr, u64 val)
{
	switch (model) {
	case DAXFS_MEM_CXL3:
		/* TODO(cxl): a non-HDM-DB device may need a flush after. */
		WRITE_ONCE(*(__le64 *)ptr, cpu_to_le64(val));
		break;
	case DAXFS_MEM_COHERENT:
	default:
		WRITE_ONCE(*(__le64 *)ptr, cpu_to_le64(val));
		break;
	}
}

/* Order prior shared stores before a subsequent publishing CAS/store. */
static inline void daxfs_publish_fence(enum daxfs_mem_model model)
{
	switch (model) {
	case DAXFS_MEM_CXL3:
		/* TODO(cxl): non-HDM-DB devices need CLWB + SFENCE here. */
		smp_wmb();
		break;
	case DAXFS_MEM_COHERENT:
	default:
		smp_wmb();
		break;
	}
}

/* Order a shared load after observing a published key/state. */
static inline void daxfs_observe_fence(enum daxfs_mem_model model)
{
	switch (model) {
	case DAXFS_MEM_CXL3:
		/* TODO(cxl): non-HDM-DB devices need an invalidate + LFENCE. */
		smp_rmb();
		break;
	case DAXFS_MEM_COHERENT:
	default:
		smp_rmb();
		break;
	}
}

#endif /* _DAXFS_COHERENCE_H */
