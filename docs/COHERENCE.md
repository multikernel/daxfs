# daxfs coherence model

daxfs coordinates metadata and the shared page cache with lock-free
`cmpxchg` and ordering fences on shared DAX memory. Those primitives are
correct only within a single hardware cache-coherence domain. This document
states that contract explicitly and defines the selectable backends.

## Coherence domain

A *coherence domain* is a set of CPUs whose caches are kept coherent in
hardware and across which a `LOCK`-prefixed atomic read-modify-write is
globally atomic. Examples: the cores and sockets of one server joined by a
coherent interconnect; multiple kernel instances (multikernel) partitioned
across cores of that one server. Two separate servers sharing CXL memory are
*not* one coherence domain unless the hardware explicitly provides inter-host
coherence (see CXL3 below).

## Backends

The active backend is selected per mount (`mem_model=coherent|cxl3`, default
`coherent`) and stored in `daxfs_info.mem_model`. All shared-memory
synchronization is funneled through `daxfs/coherence.h`
(`daxfs_cas64`, `daxfs_load_once64`, `daxfs_store_once64`,
`daxfs_publish_fence`, `daxfs_observe_fence`).

### COHERENT (default, supported)

Regular cache-coherent memory: ordinary DRAM, a DMA-heap / dma-buf
allocation, or `memremap`'d physical memory, shared by multiple kernel
instances within one coherence domain (multikernel).

| Property | Guarantee | Basis |
| --- | --- | --- |
| Atomicity | CAS on a 64-bit shared field is globally atomic across all participants. | x86 `LOCK CMPXCHG` over a coherent fabric. |
| Visibility | A published store is observed by all participants after the paired fence. | Hardware cache coherence; `smp_wmb`/`smp_rmb`. |
| Ordering | Publish-before-link and observe-after-match hold across participants. | `smp_wmb`/`smp_rmb` within the domain. |
| Failure | A crashed participant leaves a structurally valid image; no torn RMW. | Single-domain atomics; no cross-host state to reconcile. |

This is the configuration validated by the test suites (`test_overlay.sh`,
`test_mmap`, fio).

### CXL3 (scaffold, NOT yet validated)

CXL 3.0 shared memory with device-managed coherence (HDM-DB /
back-invalidation). Intended for true multi-host sharing across separate
servers. Today this backend is a scaffold: its primitives are defined
(currently identical to COHERENT, on the assumption that HDM-DB makes a
normal `LOCK CMPXCHG` globally atomic) and every divergence point is marked
`TODO(cxl)` in `daxfs/coherence.h`. It compiles and is selectable
(`mem_model=cxl3`) so the seam can be exercised, but **multi-host operation
is unsupported until the validation gate below passes.**

Selecting `cxl3` over ordinary coherent memory exercises only the plumbing
(selection, dispatch, primitive correctness); it does **not** validate
hardware coherence, because coherent DRAM makes the two backends behave
identically.

## Multi-host validation gate (phase 2)

Before any multi-host correctness is claimed, on real CXL 3.0
hardware-coherent shared memory:

1. **Atomicity:** N hosts concurrently `cmpxchg`-increment one shared counter
   a fixed number of times; assert the final value equals the total with no
   lost updates.
2. **Visibility/ordering:** a writer publishes a payload then a flag via
   `daxfs_publish_fence`; readers on other hosts that observe the flag via
   `daxfs_observe_fence` must always see the complete payload.
3. **Failure:** define and test the behavior of a host crashing mid-update
   (recovery or fail-safe), which is currently undefined for CXL3.

Until these pass on the target platform, daxfs is correct only for the
COHERENT (single-domain / multikernel) configuration.

## Known non-routed sites

A few shared fields are 32-bit and are not routed through the 64-bit
coherence helpers; they are plain `cmpxchg`/`WRITE_ONCE` on `__le32`:

- pcache `pending_count` and `evict_hand` (`pcache.c`).
- dirent `child_mode` and `flags`; pcache slot `ref_bit` (advisory).

These are bracketed by the routed `daxfs_publish_fence` for ordering. A CXL3
backend that needs explicit cache management for sub-64-bit stores must add
32-bit helpers; this is part of phase 2.
