// SPDX-License-Identifier: GPL-2.0
/*
 * DAXFS GPU Coordination Benchmark
 *
 * Measures PCIe AtomicOp latency and throughput for the GPU-side
 * coordination primitives (coord lock, page cache CAS, commit seq read).
 *
 * Uses cudaMallocHost (pinned host memory) to create a GPU-accessible
 * region that mirrors the daxfs DAX layout.  GPU kernels then exercise
 * the same atomicCAS / volatile-read primitives from daxfs_gpu.h,
 * measuring PCIe round-trip latency across the bus.
 *
 * Usage: sudo ./tests/bench_gpu [options]
 */

#include <cuda.h>
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* GPU-side primitives */
#include "../include/daxfs_gpu.h"

/* ── Configuration ────────────────────────────────────────────────── */

#define DEFAULT_ITERS       10000
#define DEFAULT_REPS        5
#define WARMUP_ITERS        200
#define PCACHE_SLOTS        4096

/* ── P2P DMA and Multi-tenant constants ──────────────────────────── */

#define P2P_MAX_SIZE        (1 << 20)   /* 1 MB max transfer */
#define P2P_REGION_SIZE     (4 << 20)   /* 4 MB P2P data region */

#define MT_MAX_TENANTS      32
#define MT_PERM_NONE        0
#define MT_PERM_READ        1
#define MT_PERM_WRITE       2
#define MT_PERM_RW          3

/* ── Simulated DAX layout in pinned host memory ───────────────────── */

struct dax_sim {
    /* Coordination region (mirrors daxfs_global_coord) */
    unsigned int       coord_lock;       /* 0=free, 1=held */
    unsigned int       coord_pad;
    unsigned long long commit_sequence;
    unsigned long long last_committed_id;

    /* Page cache header (mirrors daxfs_pcache_header) */
    unsigned int       pcache_pending;
    unsigned int       pcache_pad[3];

    /* Page cache slot metadata array */
    struct {
        unsigned long long state_tag;    /* bits[1:0]=state, bits[63:2]=tag */
        unsigned int       ref_bit;
        unsigned int       reserved;
    } slots[PCACHE_SLOTS];

    /* Multi-tenant permission table (mirrors CXL shared memory ACL).
     * perm[tenant][slot] = MT_PERM_{NONE,READ,WRITE,RW}.
     * GPU checks this before every read/write to enforce isolation. */
    unsigned char perm[MT_MAX_TENANTS][PCACHE_SLOTS];
};

/* Separate P2P DMA data region (pinned host, simulates CXL memory pages) */
struct p2p_region {
    char data[P2P_REGION_SIZE];
};

/* ── TSV output ───────────────────────────────────────────────────── */

static FILE *tsv_fp;

static void tsv_init(const char *path)
{
    tsv_fp = fopen(path, "w");
    if (!tsv_fp) { perror("fopen"); exit(1); }
    fprintf(tsv_fp, "experiment\tparameter\titeration\toperation\t"
                    "latency_ns\tops_count\tthru_mops\tnotes\n");
}

static void tsv_row(const char *exp, int param, int iter,
                    const char *op, double lat_ns, int ops,
                    double mops, const char *notes)
{
    fprintf(tsv_fp, "%s\t%d\t%d\t%s\t%.1f\t%d\t%.3f\t%s\n",
            exp, param, iter, op, lat_ns, ops, mops, notes ? notes : "");
    fflush(tsv_fp);
}

/* ── GPU timer ────────────────────────────────────────────────────── */

static double event_ms_to_ns(cudaEvent_t a, cudaEvent_t b)
{
    float ms;
    cudaEventElapsedTime(&ms, a, b);
    return (double)ms * 1e6;
}

/* ── Kernel 1: Coord Lock/Unlock Round-Trip (single thread) ──────── */

__global__ void kern_lock_rt(unsigned int *lock, int iters,
                              long long *out_cycles)
{
    long long t0 = clock64();
    for (int i = 0; i < iters; i++) {
        daxfs_gpu_coord_lock(lock);
        daxfs_gpu_coord_unlock(lock);
    }
    *out_cycles = clock64() - t0;
}

/* ── Kernel 2: Commit Sequence Volatile Read ─────────────────────── */

__global__ void kern_seq_read(const unsigned long long *seq, int iters,
                               unsigned long long *sink, long long *out_cycles)
{
    unsigned long long s = 0;
    long long t0 = clock64();
    for (int i = 0; i < iters; i++)
        s += daxfs_gpu_read_commit_seq(seq);
    *out_cycles = clock64() - t0;
    *sink = s;
}

/* ── Kernel 3: Pending Counter Inc/Dec ────────────────────────────── */

__global__ void kern_pending(unsigned int *cnt, int iters,
                              long long *out_cycles)
{
    long long t0 = clock64();
    for (int i = 0; i < iters; i++) {
        daxfs_gpu_pcache_inc_pending(cnt);
        daxfs_gpu_pcache_dec_pending(cnt);
    }
    *out_cycles = clock64() - t0;
}

/* ── Kernel 4: Page Cache Lookup (scaling threads) ────────────────── */

__global__ void kern_lookup(const unsigned long long *slot_base,
                             unsigned int stride, unsigned int st_off,
                             unsigned int slot_count, int iters,
                             unsigned int *out_hits)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int idx = tid % slot_count;
    const unsigned long long *st =
        (const unsigned long long *)((const char *)slot_base +
                                      (unsigned long long)idx * stride + st_off);
    unsigned long long tag = (unsigned long long)(idx + 1);
    unsigned int hits = 0;

    for (int i = 0; i < iters; i++)
        if (daxfs_gpu_pcache_lookup(st, tag))
            hits++;

    atomicAdd(out_hits, hits);
}

/* ── Kernel 5: CAS Throughput on Independent Slots ────────────────── */

__global__ void kern_cas_indep(unsigned long long *slot_base,
                                unsigned int stride, unsigned int st_off,
                                unsigned int slot_count, int iters)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int idx = tid % slot_count;
    unsigned long long *st =
        (unsigned long long *)((char *)slot_base +
                                (unsigned long long)idx * stride + st_off);

    unsigned long long va = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
    unsigned long long vb = PCACHE_MAKE(PCACHE_STATE_PENDING,
                                         (unsigned long long)(tid + 1));

    for (int i = 0; i < iters; i++) {
        unsigned long long old = daxfs_gpu_slot_cmpxchg(st, va, vb);
        if (old == vb)
            daxfs_gpu_slot_cmpxchg(st, vb, va);
    }
}

/* ── Kernel 6: Lock Contention (multiple threads, one lock) ──────── */

__global__ void kern_lock_contend(unsigned int *lock, int iters,
                                   unsigned int *counter)
{
    for (int i = 0; i < iters; i++) {
        daxfs_gpu_coord_lock(lock);
        (*counter)++;
        __threadfence_system();
        daxfs_gpu_coord_unlock(lock);
    }
}

/* ── Kernel 7: Page Cache Claim (FREE→PENDING transition) ─────────── */

__global__ void kern_claim(unsigned long long *slot_base,
                            unsigned int stride, unsigned int st_off,
                            unsigned int slot_count, int iters,
                            unsigned int *pending_count)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int idx = tid % slot_count;
    unsigned long long *st =
        (unsigned long long *)((char *)slot_base +
                                (unsigned long long)idx * stride + st_off);
    unsigned long long tag = (unsigned long long)(idx + 1);

    for (int i = 0; i < iters; i++) {
        if (daxfs_gpu_pcache_claim(st, tag)) {
            daxfs_gpu_pcache_inc_pending(pending_count);
            /* Reset to FREE for next iteration */
            *st = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
            __threadfence_system();
            daxfs_gpu_pcache_dec_pending(pending_count);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * P2P DMA kernels — GPU directly reads/writes CXL/DAX host memory
 * ═══════════════════════════════════════════════════════════════════ */

/* Kernel 8a: P2P DMA Read — GPU reads pages from host CXL memory */
__global__ void kern_p2p_read(const char *host_src, char *dev_dst,
                               unsigned int xfer_size, int iters)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int offset = (tid * xfer_size) % P2P_REGION_SIZE;
    const char *src = host_src + offset;

    for (int i = 0; i < iters; i++) {
        /* Explicit GPU load from host (PCIe read TLPs) */
        for (unsigned int b = 0; b < xfer_size; b += sizeof(unsigned long long)) {
            unsigned long long val =
                *(volatile const unsigned long long *)(src + b);
            /* Store to device mem so compiler doesn't elide the load */
            if (dev_dst)
                *(unsigned long long *)(dev_dst + b) = val;
        }
    }
}

/* Kernel 8b: P2P DMA Write — GPU writes pages to host CXL memory */
__global__ void kern_p2p_write(char *host_dst, unsigned int xfer_size,
                                int iters)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int offset = (tid * xfer_size) % P2P_REGION_SIZE;
    char *dst = host_dst + offset;
    unsigned long long pattern = 0xDA5F5DA5ULL + tid;

    for (int i = 0; i < iters; i++) {
        /* Explicit GPU store to host (PCIe write TLPs) */
        for (unsigned int b = 0; b < xfer_size; b += sizeof(unsigned long long)) {
            *(volatile unsigned long long *)(dst + b) = pattern + b;
        }
        __threadfence_system();
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * Multi-tenant CXL memory permission-checked access kernels
 *
 * Simulates GPU agents from different tenants sharing a CXL memory
 * pool.  Each access performs an explicit permission check against
 * a per-tenant ACL bitmap in the shared DAX region before issuing
 * the actual read/write.  This is the GPU-side enforcement path
 * that mirrors what hardware CXL.mem permission checks would do.
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * Permission check + read: GPU thread loads perm[tenant][slot],
 * verifies MT_PERM_READ is set, then reads the slot data.
 */
__global__ void kern_mt_read(const unsigned long long *slot_base,
                              unsigned int stride, unsigned int st_off,
                              unsigned int slot_count,
                              const unsigned char *perm_base,
                              unsigned int tenant_id, int iters,
                              unsigned int *out_allowed,
                              unsigned int *out_denied)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int idx = tid % slot_count;
    unsigned int allowed = 0, denied = 0;

    /* Permission table row for this tenant */
    const unsigned char *my_perm = perm_base + tenant_id * slot_count;

    const unsigned long long *st =
        (const unsigned long long *)((const char *)slot_base +
                                      (unsigned long long)idx * stride + st_off);

    for (int i = 0; i < iters; i++) {
        /* Step 1: Explicit permission check (volatile read from host ACL) */
        unsigned char p = *(volatile const unsigned char *)(my_perm + idx);

        if (p & MT_PERM_READ) {
            /* Step 2: Allowed — read the slot via PCIe */
            unsigned long long val = *(volatile const unsigned long long *)st;
            (void)val;
            allowed++;
        } else {
            denied++;
        }
        /* Rotate to next slot */
        idx = (idx + 7) % slot_count;
        st = (const unsigned long long *)((const char *)slot_base +
              (unsigned long long)idx * stride + st_off);
    }

    atomicAdd(out_allowed, allowed);
    atomicAdd(out_denied, denied);
}

/*
 * Permission check + write: GPU thread checks MT_PERM_WRITE,
 * then performs CAS on the slot (simulating a page cache mutation).
 */
__global__ void kern_mt_write(unsigned long long *slot_base,
                               unsigned int stride, unsigned int st_off,
                               unsigned int slot_count,
                               const unsigned char *perm_base,
                               unsigned int tenant_id, int iters,
                               unsigned int *out_allowed,
                               unsigned int *out_denied)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int idx = tid % slot_count;
    unsigned int allowed = 0, denied = 0;

    const unsigned char *my_perm = perm_base + tenant_id * slot_count;

    for (int i = 0; i < iters; i++) {
        unsigned long long *st =
            (unsigned long long *)((char *)slot_base +
                                    (unsigned long long)idx * stride + st_off);

        /* Step 1: Explicit permission check */
        unsigned char p = *(volatile const unsigned char *)(my_perm + idx);

        if (p & MT_PERM_WRITE) {
            /* Step 2: Allowed — CAS write to slot (PCIe CAS TLP) */
            unsigned long long old = *st;
            unsigned long long new_val = old + 1;
            daxfs_gpu_slot_cmpxchg(st, old, new_val);
            allowed++;
        } else {
            denied++;
        }
        idx = (idx + 7) % slot_count;
    }

    atomicAdd(out_allowed, allowed);
    atomicAdd(out_denied, denied);
}

/*
 * Baseline: same read without permission check, to measure
 * the overhead of the ACL lookup.
 */
__global__ void kern_mt_read_noacl(const unsigned long long *slot_base,
                                    unsigned int stride, unsigned int st_off,
                                    unsigned int slot_count, int iters,
                                    unsigned int *out_count)
{
    unsigned int tid = blockIdx.x * blockDim.x + threadIdx.x;
    unsigned int idx = tid % slot_count;
    unsigned int count = 0;

    for (int i = 0; i < iters; i++) {
        const unsigned long long *st =
            (const unsigned long long *)((const char *)slot_base +
                                          (unsigned long long)idx * stride + st_off);
        unsigned long long val = *(volatile const unsigned long long *)st;
        (void)val;
        count++;
        idx = (idx + 7) % slot_count;
    }

    atomicAdd(out_count, count);
}

/* ── Error checking ───────────────────────────────────────────────── */

#define CK(call) do {                                                   \
    cudaError_t e = (call);                                             \
    if (e != cudaSuccess) {                                             \
        fprintf(stderr, "CUDA %s:%d: %s\n", __FILE__, __LINE__,        \
                cudaGetErrorString(e));                                  \
        exit(1);                                                        \
    }                                                                   \
} while(0)

/* ── Main ─────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    const char *tsv_path = "./bench_results/gpu.tsv";
    int iters = DEFAULT_ITERS;
    int reps = DEFAULT_REPS;
    int opt;

    while ((opt = getopt(argc, argv, "i:r:o:h")) != -1) {
        switch (opt) {
        case 'i': iters = atoi(optarg); break;
        case 'r': reps = atoi(optarg); break;
        case 'o': tsv_path = optarg; break;
        default:
            fprintf(stderr, "Usage: %s [-i iters] [-r reps] [-o out.tsv]\n",
                    argv[0]);
            return 1;
        }
    }

    /* GPU info */
    cudaDeviceProp prop;
    CK(cudaGetDeviceProperties(&prop, 0));
    int clock_khz;
    CK(cudaDeviceGetAttribute(&clock_khz, cudaDevAttrClockRate, 0));
    double ns_per_cycle = 1e6 / (double)clock_khz;

    printf("DAXFS GPU Coordination Benchmark\n");
    printf("================================\n");
    printf("GPU: %s (SM %d.%d, %d SMs, %.0f MHz)\n",
           prop.name, prop.major, prop.minor,
           prop.multiProcessorCount, prop.clockRate / 1000.0);
    printf("  iters=%d  reps=%d  pcache_slots=%d\n", iters, reps, PCACHE_SLOTS);
    printf("  ns/cycle=%.2f\n\n", ns_per_cycle);

    /* Allocate pinned host memory simulating DAX region */
    struct dax_sim *dax;
    CK(cudaMallocHost(&dax, sizeof(struct dax_sim)));
    memset(dax, 0, sizeof(struct dax_sim));

    /* Initialize pcache slots as VALID with known tags for lookup test */
    for (int i = 0; i < PCACHE_SLOTS; i++)
        dax->slots[i].state_tag = PCACHE_MAKE(PCACHE_STATE_VALID,
                                               (unsigned long long)(i + 1));

    /* Get device pointers for pinned memory */
    unsigned int       *d_lock = &dax->coord_lock;
    unsigned long long *d_seq  = &dax->commit_sequence;
    unsigned int       *d_pend = &dax->pcache_pending;
    unsigned long long *d_slot_base = &dax->slots[0].state_tag;
    unsigned int        slot_stride = sizeof(dax->slots[0]);  /* 16 bytes */
    unsigned int        st_off = 0;  /* state_tag at offset 0 in slot */

    /* Scratch device memory */
    long long *d_cycles;
    unsigned long long *d_sink;
    unsigned int *d_counter, *d_hits;
    CK(cudaMalloc(&d_cycles, sizeof(long long)));
    CK(cudaMalloc(&d_sink, sizeof(unsigned long long)));
    CK(cudaMalloc(&d_counter, sizeof(unsigned int)));
    CK(cudaMalloc(&d_hits, sizeof(unsigned int)));

    cudaEvent_t ev0, ev1;
    CK(cudaEventCreate(&ev0));
    CK(cudaEventCreate(&ev1));

    tsv_init(tsv_path);

    printf("DAX simulation at %p (pinned host memory, GPU-visible via PCIe)\n\n",
           (void *)dax);

    /* ── Exp 1: Coord Lock Round-Trip ─────────────────────────────── */
    printf("Exp 1: Coordination Lock Round-Trip (single thread)\n");
    kern_lock_rt<<<1, 1>>>(d_lock, WARMUP_ITERS, d_cycles);
    CK(cudaDeviceSynchronize());
    dax->coord_lock = 0;

    for (int r = 0; r < reps; r++) {
        long long cyc;
        CK(cudaEventRecord(ev0));
        kern_lock_rt<<<1, 1>>>(d_lock, iters, d_cycles);
        CK(cudaEventRecord(ev1));
        CK(cudaDeviceSynchronize());
        CK(cudaMemcpy(&cyc, d_cycles, sizeof(cyc), cudaMemcpyDeviceToHost));
        double ns_op = (double)cyc * ns_per_cycle / iters;
        double ev_ns = event_ms_to_ns(ev0, ev1);
        printf("  rep %d: %.1f ns/op (cycles), %.1f ns/op (wall)\n",
               r + 1, ns_op, ev_ns / iters);
        tsv_row("gpu_coord_lock", 1, r + 1, "lock_unlock_rt",
                ns_op, iters, iters / (ev_ns / 1e3), "single_thread");
        dax->coord_lock = 0;
    }

    /* ── Exp 2: Commit Seq Volatile Read ──────────────────────────── */
    printf("\nExp 2: Commit Sequence Read (volatile PCIe read)\n");
    kern_seq_read<<<1, 1>>>(d_seq, WARMUP_ITERS, d_sink, d_cycles);
    CK(cudaDeviceSynchronize());

    for (int r = 0; r < reps; r++) {
        long long cyc;
        CK(cudaEventRecord(ev0));
        kern_seq_read<<<1, 1>>>(d_seq, iters, d_sink, d_cycles);
        CK(cudaEventRecord(ev1));
        CK(cudaDeviceSynchronize());
        CK(cudaMemcpy(&cyc, d_cycles, sizeof(cyc), cudaMemcpyDeviceToHost));
        double ns_op = (double)cyc * ns_per_cycle / iters;
        double ev_ns = event_ms_to_ns(ev0, ev1);
        printf("  rep %d: %.1f ns/op\n", r + 1, ns_op);
        tsv_row("gpu_commit_seq", 1, r + 1, "volatile_read",
                ns_op, iters, iters / (ev_ns / 1e3), "single_thread");
    }

    /* ── Exp 3: Pending Counter Inc/Dec ───────────────────────────── */
    printf("\nExp 3: Pending Counter CAS Inc/Dec\n");
    kern_pending<<<1, 1>>>(d_pend, WARMUP_ITERS, d_cycles);
    CK(cudaDeviceSynchronize());
    dax->pcache_pending = 0;

    for (int r = 0; r < reps; r++) {
        long long cyc;
        CK(cudaEventRecord(ev0));
        kern_pending<<<1, 1>>>(d_pend, iters, d_cycles);
        CK(cudaEventRecord(ev1));
        CK(cudaDeviceSynchronize());
        CK(cudaMemcpy(&cyc, d_cycles, sizeof(cyc), cudaMemcpyDeviceToHost));
        double ns_op = (double)cyc * ns_per_cycle / (iters * 2);
        double ev_ns = event_ms_to_ns(ev0, ev1);
        printf("  rep %d: %.1f ns/op (CAS pair)\n", r + 1, ns_op);
        tsv_row("gpu_pending_ctr", 1, r + 1, "cas_inc_dec",
                ns_op, iters * 2, (iters * 2) / (ev_ns / 1e3), "single_thread");
        dax->pcache_pending = 0;
    }

    /* ── Exp 4: Page Cache Lookup Throughput ──────────────────────── */
    printf("\nExp 4: Page Cache Lookup (scaling threads)\n");
    {
        int tcounts[] = {1, 32, 64, 128, 256, 512, 1024};
        for (int c = 0; c < 7; c++) {
            int nt = tcounts[c];
            int blk = (nt + 255) / 256, tpb = nt < 256 ? nt : 256;
            for (int r = 0; r < reps; r++) {
                CK(cudaMemset(d_hits, 0, sizeof(unsigned int)));
                CK(cudaEventRecord(ev0));
                kern_lookup<<<blk, tpb>>>(d_slot_base, slot_stride, st_off,
                                           PCACHE_SLOTS, iters, d_hits);
                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());
                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long ops = (long long)nt * iters;
                double mops = ops / (ev_ns / 1e3);
                printf("  threads=%4d: %8.3f Mops/s\n", nt, mops);
                tsv_row("gpu_pcache_lookup", nt, r + 1, "lookup_throughput",
                        ev_ns / ops, (int)ops, mops, "");
            }
        }
    }

    /* ── Exp 5: Slot CAS Throughput (independent) ─────────────────── */
    printf("\nExp 5: Slot CAS Throughput (independent slots)\n");
    {
        /* Reset slots to FREE for CAS test */
        for (int i = 0; i < PCACHE_SLOTS; i++)
            dax->slots[i].state_tag = PCACHE_MAKE(PCACHE_STATE_FREE, 0);

        int tcounts[] = {1, 32, 64, 128, 256, 512, 1024};
        int cas_iters = iters / 10;
        for (int c = 0; c < 7; c++) {
            int nt = tcounts[c];
            int blk = (nt + 255) / 256, tpb = nt < 256 ? nt : 256;
            for (int r = 0; r < reps; r++) {
                CK(cudaEventRecord(ev0));
                kern_cas_indep<<<blk, tpb>>>(d_slot_base, slot_stride, st_off,
                                              PCACHE_SLOTS, cas_iters);
                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());
                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long ops = (long long)nt * cas_iters;
                double mops = ops / (ev_ns / 1e3);
                printf("  threads=%4d: %8.3f Mops/s\n", nt, mops);
                tsv_row("gpu_slot_cas", nt, r + 1, "cas_throughput",
                        ev_ns / ops, (int)ops, mops, "independent");
            }
        }
    }

    /* ── Exp 6: Lock Contention ───────────────────────────────────── */
    printf("\nExp 6: Lock Contention (scaling threads)\n");
    {
        int tcounts[] = {1, 2, 4, 8, 16, 32};
        int lock_iters = iters / 100;
        for (int c = 0; c < 6; c++) {
            int nt = tcounts[c];
            for (int r = 0; r < reps; r++) {
                dax->coord_lock = 0;
                CK(cudaMemset(d_counter, 0, sizeof(unsigned int)));
                CK(cudaEventRecord(ev0));
                kern_lock_contend<<<1, nt>>>(d_lock, lock_iters, d_counter);
                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());
                unsigned int ctr;
                CK(cudaMemcpy(&ctr, d_counter, sizeof(ctr),
                              cudaMemcpyDeviceToHost));
                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long ops = (long long)nt * lock_iters;
                double ns_acq = ev_ns / ops;
                printf("  threads=%2d: %8.1f ns/acq  counter=%u/%lld\n",
                       nt, ns_acq, ctr, ops);
                char note[64];
                snprintf(note, sizeof(note), "counter=%u", ctr);
                tsv_row("gpu_lock_contention", nt, r + 1, "lock_acquisition",
                        ns_acq, (int)ops, ops / (ev_ns / 1e3), note);
            }
        }
    }

    /* ── Exp 7: Page Cache Claim (FREE→PENDING) ───────────────────── */
    printf("\nExp 7: Page Cache Claim (FREE->PENDING transition)\n");
    {
        int tcounts[] = {1, 32, 64, 128, 256, 512, 1024};
        int claim_iters = iters / 10;
        for (int c = 0; c < 7; c++) {
            int nt = tcounts[c];
            int blk = (nt + 255) / 256, tpb = nt < 256 ? nt : 256;
            /* Reset slots to FREE */
            for (int i = 0; i < PCACHE_SLOTS; i++)
                dax->slots[i].state_tag = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
            dax->pcache_pending = 0;

            for (int r = 0; r < reps; r++) {
                CK(cudaEventRecord(ev0));
                kern_claim<<<blk, tpb>>>(d_slot_base, slot_stride, st_off,
                                          PCACHE_SLOTS, claim_iters, d_pend);
                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());
                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long ops = (long long)nt * claim_iters;
                double mops = ops / (ev_ns / 1e3);
                printf("  threads=%4d: %8.3f Mops/s\n", nt, mops);
                tsv_row("gpu_pcache_claim", nt, r + 1, "claim_throughput",
                        ev_ns / ops, (int)ops, mops, "free_to_pending");
                /* Reset for next rep */
                for (int i = 0; i < PCACHE_SLOTS; i++)
                    dax->slots[i].state_tag = PCACHE_MAKE(PCACHE_STATE_FREE, 0);
                dax->pcache_pending = 0;
            }
        }
    }

    /* ═══════════════════════════════════════════════════════════════
     * Exp 8: P2P DMA — GPU explicit read/write to CXL host memory
     * ═══════════════════════════════════════════════════════════════ */
    printf("\n════════════════════════════════════════════\n");
    printf("Exp 8: P2P DMA Read/Write (GPU ↔ CXL host memory)\n");
    {
        /* Allocate pinned host region simulating CXL memory pages */
        struct p2p_region *p2p;
        CK(cudaMallocHost(&p2p, sizeof(struct p2p_region)));
        memset(p2p->data, 0xAB, P2P_REGION_SIZE);

        /* Device-side scratch buffer for reads */
        char *d_scratch;
        CK(cudaMalloc(&d_scratch, P2P_MAX_SIZE));

        unsigned int sizes[] = {64, 256, 4096, 65536, 1 << 20};
        const char *labels[] = {"64B", "256B", "4KB", "64KB", "1MB"};

        /* 8a: P2P Read (GPU loads from host CXL memory) */
        printf("  ── P2P Read ──\n");
        for (int s = 0; s < 5; s++) {
            unsigned int xsz = sizes[s];
            int nt = (xsz <= 4096) ? 64 : 1;
            int p2p_iters = (xsz <= 4096) ? iters : iters / 100;
            int blk = (nt + 255) / 256, tpb = nt < 256 ? nt : 256;

            for (int r = 0; r < reps; r++) {
                CK(cudaEventRecord(ev0));
                kern_p2p_read<<<blk, tpb>>>(p2p->data, d_scratch,
                                              xsz, p2p_iters);
                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());
                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long total_bytes = (long long)nt * p2p_iters * xsz;
                double bw_gbps = total_bytes / (ev_ns / 1.0); /* B/ns = GB/s */
                double lat_ns = ev_ns / ((long long)nt * p2p_iters);
                printf("    %5s: %8.2f GB/s  %8.1f ns/op\n",
                       labels[s], bw_gbps, lat_ns);
                char note[32];
                snprintf(note, sizeof(note), "size=%s", labels[s]);
                tsv_row("gpu_p2p_read", xsz, r + 1, "read_bw",
                        lat_ns, (int)(total_bytes >> 10), bw_gbps * 1000, note);
            }
        }

        /* 8b: P2P Write (GPU stores to host CXL memory) */
        printf("  ── P2P Write ──\n");
        for (int s = 0; s < 5; s++) {
            unsigned int xsz = sizes[s];
            int nt = (xsz <= 4096) ? 64 : 1;
            int p2p_iters = (xsz <= 4096) ? iters : iters / 100;
            int blk = (nt + 255) / 256, tpb = nt < 256 ? nt : 256;

            for (int r = 0; r < reps; r++) {
                CK(cudaEventRecord(ev0));
                kern_p2p_write<<<blk, tpb>>>(p2p->data, xsz, p2p_iters);
                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());
                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long total_bytes = (long long)nt * p2p_iters * xsz;
                double bw_gbps = total_bytes / (ev_ns / 1.0);
                double lat_ns = ev_ns / ((long long)nt * p2p_iters);
                printf("    %5s: %8.2f GB/s  %8.1f ns/op\n",
                       labels[s], bw_gbps, lat_ns);
                char note[32];
                snprintf(note, sizeof(note), "size=%s", labels[s]);
                tsv_row("gpu_p2p_write", xsz, r + 1, "write_bw",
                        lat_ns, (int)(total_bytes >> 10), bw_gbps * 1000, note);
            }
        }

        cudaFreeHost(p2p);
        cudaFree(d_scratch);
    }

    /* ═══════════════════════════════════════════════════════════════
     * Exp 9: Multi-tenant CXL memory permission-checked access
     *
     * Simulates multiple AI agent tenants sharing CXL memory.
     * GPU explicitly checks per-tenant permission bitmap in shared
     * DAX region before each read/write — the GPU-side enforcement
     * of CXL.mem access control.
     * ═══════════════════════════════════════════════════════════════ */
    printf("\n════════════════════════════════════════════\n");
    printf("Exp 9: Multi-tenant CXL Permission-Checked Access\n");
    {
        /* Re-init slots to VALID for read tests */
        for (int i = 0; i < PCACHE_SLOTS; i++)
            dax->slots[i].state_tag = PCACHE_MAKE(PCACHE_STATE_VALID,
                                                   (unsigned long long)(i + 1));

        unsigned int *d_allowed, *d_denied;
        CK(cudaMalloc(&d_allowed, sizeof(unsigned int)));
        CK(cudaMalloc(&d_denied, sizeof(unsigned int)));

        unsigned char *perm_base = &dax->perm[0][0];

        /* 9a: Permission check overhead — compare with vs without ACL */
        printf("  ── 9a: ACL Check Overhead (256 threads) ──\n");
        {
            int nt = 256, blk = 1, tpb = 256;
            int mt_iters = iters;

            /* Setup: tenant 0 has READ on all slots */
            memset(dax->perm[0], MT_PERM_RW, PCACHE_SLOTS);

            /* With ACL */
            for (int r = 0; r < reps; r++) {
                CK(cudaMemset(d_allowed, 0, sizeof(unsigned int)));
                CK(cudaMemset(d_denied, 0, sizeof(unsigned int)));
                CK(cudaEventRecord(ev0));
                kern_mt_read<<<blk, tpb>>>(d_slot_base, slot_stride, st_off,
                                            PCACHE_SLOTS, perm_base,
                                            0, mt_iters,
                                            d_allowed, d_denied);
                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());
                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long ops = (long long)nt * mt_iters;
                double mops = ops / (ev_ns / 1e3);
                printf("    WITH ACL:  %8.3f Mops/s  (%.1f ns/op)\n",
                       mops, ev_ns / ops);
                tsv_row("gpu_mt_acl_overhead", nt, r + 1, "read_with_acl",
                        ev_ns / ops, (int)ops, mops, "all_allowed");
            }

            /* Without ACL (baseline) */
            CK(cudaMemset(d_hits, 0, sizeof(unsigned int)));
            for (int r = 0; r < reps; r++) {
                CK(cudaMemset(d_hits, 0, sizeof(unsigned int)));
                CK(cudaEventRecord(ev0));
                kern_mt_read_noacl<<<blk, tpb>>>(d_slot_base, slot_stride,
                                                  st_off, PCACHE_SLOTS,
                                                  mt_iters, d_hits);
                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());
                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long ops = (long long)nt * mt_iters;
                double mops = ops / (ev_ns / 1e3);
                printf("    NO ACL:    %8.3f Mops/s  (%.1f ns/op)\n",
                       mops, ev_ns / ops);
                tsv_row("gpu_mt_acl_overhead", nt, r + 1, "read_no_acl",
                        ev_ns / ops, (int)ops, mops, "baseline");
            }
        }

        /* 9b: Multi-tenant read scaling (each warp = different tenant) */
        printf("  ── 9b: Multi-tenant Read (scaling tenants) ──\n");
        {
            int tcounts[] = {1, 2, 4, 8, 16, 32};
            int mt_iters = iters;

            for (int c = 0; c < 6; c++) {
                int n_tenants = tcounts[c];
                int threads_per_tenant = 32; /* one warp per tenant */
                int nt = n_tenants * threads_per_tenant;
                int blk = (nt + 255) / 256, tpb = nt < 256 ? nt : 256;

                /* Setup: all tenants get READ on their own slot range,
                 * NONE on others' slots (isolation) */
                memset(dax->perm, MT_PERM_NONE,
                       MT_MAX_TENANTS * PCACHE_SLOTS);
                int slots_per_tenant = PCACHE_SLOTS / n_tenants;
                for (int t = 0; t < n_tenants; t++) {
                    int start = t * slots_per_tenant;
                    memset(&dax->perm[t][start], MT_PERM_READ,
                           slots_per_tenant);
                }

                for (int r = 0; r < reps; r++) {
                    CK(cudaMemset(d_allowed, 0, sizeof(unsigned int)));
                    CK(cudaMemset(d_denied, 0, sizeof(unsigned int)));
                    CK(cudaEventRecord(ev0));

                    /* Launch one warp per tenant, each with its tenant_id.
                     * Use a per-tenant kernel launch to keep it simple. */
                    for (int t = 0; t < n_tenants; t++) {
                        kern_mt_read<<<1, threads_per_tenant>>>(
                            d_slot_base, slot_stride, st_off,
                            PCACHE_SLOTS, perm_base,
                            t, mt_iters, d_allowed, d_denied);
                    }

                    CK(cudaEventRecord(ev1));
                    CK(cudaDeviceSynchronize());

                    unsigned int h_allowed, h_denied;
                    CK(cudaMemcpy(&h_allowed, d_allowed, sizeof(unsigned int),
                                  cudaMemcpyDeviceToHost));
                    CK(cudaMemcpy(&h_denied, d_denied, sizeof(unsigned int),
                                  cudaMemcpyDeviceToHost));

                    double ev_ns = event_ms_to_ns(ev0, ev1);
                    long long ops = (long long)nt * mt_iters;
                    double mops = ops / (ev_ns / 1e3);

                    printf("    tenants=%2d: %8.3f Mops/s  allowed=%u "
                           "denied=%u\n",
                           n_tenants, mops, h_allowed, h_denied);

                    char note[64];
                    snprintf(note, sizeof(note),
                             "allowed=%u,denied=%u", h_allowed, h_denied);
                    tsv_row("gpu_mt_read", n_tenants, r + 1,
                            "mt_read_throughput",
                            ev_ns / ops, (int)ops, mops, note);
                }
            }
        }

        /* 9c: Multi-tenant write with permission check */
        printf("  ── 9c: Multi-tenant Write (scaling tenants) ──\n");
        {
            int tcounts[] = {1, 2, 4, 8, 16, 32};
            int mt_iters = iters / 10; /* CAS writes are slower */

            for (int c = 0; c < 6; c++) {
                int n_tenants = tcounts[c];
                int threads_per_tenant = 32;
                int nt = n_tenants * threads_per_tenant;

                /* Setup: each tenant gets WRITE on its slot range */
                memset(dax->perm, MT_PERM_NONE,
                       MT_MAX_TENANTS * PCACHE_SLOTS);
                int slots_per_tenant = PCACHE_SLOTS / n_tenants;
                for (int t = 0; t < n_tenants; t++) {
                    int start = t * slots_per_tenant;
                    memset(&dax->perm[t][start], MT_PERM_RW,
                           slots_per_tenant);
                }

                /* Reset slots */
                for (int i = 0; i < PCACHE_SLOTS; i++)
                    dax->slots[i].state_tag = PCACHE_MAKE(
                        PCACHE_STATE_VALID, (unsigned long long)(i + 1));

                for (int r = 0; r < reps; r++) {
                    CK(cudaMemset(d_allowed, 0, sizeof(unsigned int)));
                    CK(cudaMemset(d_denied, 0, sizeof(unsigned int)));
                    CK(cudaEventRecord(ev0));

                    for (int t = 0; t < n_tenants; t++) {
                        kern_mt_write<<<1, threads_per_tenant>>>(
                            d_slot_base, slot_stride, st_off,
                            PCACHE_SLOTS, perm_base,
                            t, mt_iters, d_allowed, d_denied);
                    }

                    CK(cudaEventRecord(ev1));
                    CK(cudaDeviceSynchronize());

                    unsigned int h_allowed, h_denied;
                    CK(cudaMemcpy(&h_allowed, d_allowed, sizeof(unsigned int),
                                  cudaMemcpyDeviceToHost));
                    CK(cudaMemcpy(&h_denied, d_denied, sizeof(unsigned int),
                                  cudaMemcpyDeviceToHost));

                    double ev_ns = event_ms_to_ns(ev0, ev1);
                    long long ops = (long long)nt * mt_iters;
                    double mops = ops / (ev_ns / 1e3);

                    printf("    tenants=%2d: %8.3f Mops/s  allowed=%u "
                           "denied=%u\n",
                           n_tenants, mops, h_allowed, h_denied);

                    char note[64];
                    snprintf(note, sizeof(note),
                             "allowed=%u,denied=%u", h_allowed, h_denied);
                    tsv_row("gpu_mt_write", n_tenants, r + 1,
                            "mt_write_throughput",
                            ev_ns / ops, (int)ops, mops, note);
                }
            }
        }

        /* 9d: Cross-tenant isolation test — tenant tries to access
         * another tenant's slots (should all be denied) */
        printf("  ── 9d: Cross-tenant Isolation (denied access) ──\n");
        {
            int n_tenants = 4;
            int threads_per_tenant = 32;
            int mt_iters = iters;

            /* Setup: 4 tenants, each owns 1/4 of slots */
            memset(dax->perm, MT_PERM_NONE,
                   MT_MAX_TENANTS * PCACHE_SLOTS);
            int slots_per_tenant = PCACHE_SLOTS / n_tenants;
            for (int t = 0; t < n_tenants; t++) {
                int start = t * slots_per_tenant;
                memset(&dax->perm[t][start], MT_PERM_RW,
                       slots_per_tenant);
            }

            for (int r = 0; r < reps; r++) {
                CK(cudaMemset(d_allowed, 0, sizeof(unsigned int)));
                CK(cudaMemset(d_denied, 0, sizeof(unsigned int)));
                CK(cudaEventRecord(ev0));

                /* Tenant 0 tries to read ALL slots (including tenant 1-3's).
                 * Perm check uses global slot index, so tenant 0 can only
                 * access its own 1/4 — the rest should be denied. */
                kern_mt_read<<<1, threads_per_tenant>>>(
                    d_slot_base,
                    slot_stride, st_off, PCACHE_SLOTS,
                    perm_base, 0 /* tenant 0 */, mt_iters,
                    d_allowed, d_denied);

                CK(cudaEventRecord(ev1));
                CK(cudaDeviceSynchronize());

                unsigned int h_allowed, h_denied;
                CK(cudaMemcpy(&h_allowed, d_allowed, sizeof(unsigned int),
                              cudaMemcpyDeviceToHost));
                CK(cudaMemcpy(&h_denied, d_denied, sizeof(unsigned int),
                              cudaMemcpyDeviceToHost));

                double ev_ns = event_ms_to_ns(ev0, ev1);
                long long ops = (long long)threads_per_tenant * mt_iters;
                double mops = ops / (ev_ns / 1e3);

                printf("    cross-tenant: %8.3f Mops/s  allowed=%u "
                       "denied=%u (%s)\n",
                       mops, h_allowed, h_denied,
                       h_allowed == 0 ? "ISOLATED" : "VIOLATION!");

                char note[80];
                snprintf(note, sizeof(note),
                         "allowed=%u,denied=%u,%s",
                         h_allowed, h_denied,
                         h_allowed == 0 ? "isolated" : "violation");
                tsv_row("gpu_mt_isolation", n_tenants, r + 1,
                        "cross_tenant_read",
                        ev_ns / ops, (int)ops, mops, note);
            }
        }

        cudaFree(d_allowed);
        cudaFree(d_denied);
    }

    /* ── Cleanup ──────────────────────────────────────────────────── */
    fclose(tsv_fp);
    cudaEventDestroy(ev0);
    cudaEventDestroy(ev1);
    cudaFree(d_cycles);
    cudaFree(d_sink);
    cudaFree(d_counter);
    cudaFree(d_hits);
    cudaFreeHost(dax);

    printf("\nResults written to %s\n", tsv_path);
    return 0;
}
