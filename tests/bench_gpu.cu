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

    /* ── Cleanup ──────────────────────────────────────────────────── */
    fclose(tsv_fp);
    cudaEventDestroy(ev0);
    cudaEventDestroy(ev1);
    cudaFree(d_cycles);
    cudaFree(d_sink);
    cudaFree(d_counter);
    cudaFree(d_hits);
    cudaFreeHost(dax);

    /* Unmount if we set up daxfs */
    printf("\nResults written to %s\n", tsv_path);
    return 0;
}
