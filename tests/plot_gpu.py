#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
DAXFS GPU Coordination Benchmark Plotter

Reads gpu.tsv and produces multi-panel figures showing PCIe AtomicOp
latency/throughput, P2P DMA bandwidth, and multi-tenant CXL permission
check overhead.
"""

import sys
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

def load_data(path):
    df = pd.read_csv(path, sep='\t')
    return df

def mean_by_param(df, experiment, operation, value_col='latency_ns'):
    sub = df[(df['experiment'] == experiment) & (df['operation'] == operation)]
    return sub.groupby('parameter')[value_col].agg(['mean', 'std']).reset_index()

def mean_by_param_mops(df, experiment, operation):
    sub = df[(df['experiment'] == experiment) & (df['operation'] == operation)]
    return sub.groupby('parameter')['thru_mops'].agg(['mean', 'std']).reset_index()

# ── Original 6 panels ────────────────────────────────────────────────

def plot_latency_bars(ax, df):
    primitives = [
        ('gpu_commit_seq', 'volatile_read', 'PCIe Read\n(commit_seq)', '#2196F3'),
        ('gpu_pending_ctr', 'cas_inc_dec', 'CAS Inc/Dec\n(pending_ctr)', '#FF9800'),
        ('gpu_coord_lock', 'lock_unlock_rt', 'Lock+Unlock\n(coord_lock)', '#F44336'),
    ]
    names, means, stds, colors = [], [], [], []
    for exp, op, name, color in primitives:
        sub = df[(df['experiment'] == exp) & (df['operation'] == op)]
        if len(sub) == 0: continue
        names.append(name); means.append(sub['latency_ns'].mean())
        stds.append(sub['latency_ns'].std()); colors.append(color)
    bars = ax.bar(names, means, yerr=stds, color=colors, capsize=5,
                  edgecolor='black', linewidth=0.5)
    ax.set_ylabel('Latency (ns)')
    ax.set_title('PCIe Atomic Primitive Latency\n(single GPU thread)')
    ax.grid(True, alpha=0.3, axis='y')
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 30,
                f'{m:.0f} ns', ha='center', va='bottom', fontsize=9, fontweight='bold')

def plot_lookup_throughput(ax, df):
    d = mean_by_param_mops(df, 'gpu_pcache_lookup', 'lookup_throughput')
    if len(d) == 0: return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#2196F3', marker='o', capsize=3, linewidth=2, markersize=7)
    base = d['mean'].iloc[0]
    ax.plot(d['parameter'], d['parameter'] * base, '--', color='gray',
            alpha=0.5, label='Ideal linear')
    ax.set_xlabel('GPU Threads'); ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('Page Cache Lookup Throughput')
    ax.set_xscale('log', base=2); ax.set_yscale('log', base=10)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9); ax.grid(True, alpha=0.3)

def plot_cas_throughput(ax, df):
    d = mean_by_param_mops(df, 'gpu_slot_cas', 'cas_throughput')
    if len(d) == 0: return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#E91E63', marker='D', capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('GPU Threads'); ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('Slot CAS Throughput\n(independent slots, PCIe atomics)')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(True, alpha=0.3)
    if len(d) >= 4:
        plateau = d['mean'].iloc[-3:].mean()
        ax.axhline(y=plateau, color='gray', linestyle=':', alpha=0.5)
        ax.text(d['parameter'].iloc[-1], plateau * 1.1,
                f'PCIe limit: {plateau:.1f} Mops/s',
                ha='right', fontsize=8, color='gray')

def plot_lock_contention(ax, df):
    d = mean_by_param(df, 'gpu_lock_contention', 'lock_acquisition')
    if len(d) == 0: return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#F44336', marker='s', capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('Contending GPU Threads')
    ax.set_ylabel('Time per Acquisition (ns)')
    ax.set_title('Coordination Lock Contention')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(True, alpha=0.3)

def plot_claim_throughput(ax, df):
    d = mean_by_param_mops(df, 'gpu_pcache_claim', 'claim_throughput')
    if len(d) == 0: return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#4CAF50', marker='^', capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('GPU Threads'); ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('Page Cache Claim\n(FREE->PENDING + pending counter)')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(True, alpha=0.3)

def plot_lookup_latency(ax, df):
    d = mean_by_param(df, 'gpu_pcache_lookup', 'lookup_throughput')
    if len(d) == 0: return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#2196F3', marker='o', capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('GPU Threads'); ax.set_ylabel('Per-Op Latency (ns)')
    ax.set_title('Page Cache Lookup Latency')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(True, alpha=0.3)

# ── New panels: P2P DMA & Multi-tenant ────────────────────────────────

def plot_p2p_bandwidth(ax, df):
    """P2P DMA read/write bandwidth vs transfer size"""
    sizes = [64, 256, 4096, 65536, 1 << 20]
    labels = ['64B', '256B', '4KB', '64KB', '1MB']

    for exp, label, color, marker in [
        ('gpu_p2p_read', 'GPU Read from CXL', '#2196F3', 'o'),
        ('gpu_p2p_write', 'GPU Write to CXL', '#FF5722', 's'),
    ]:
        sub = df[df['experiment'] == exp]
        if len(sub) == 0: continue
        # thru_mops is actually GB/s * 1000 in this context
        means, stds_v = [], []
        for sz in sizes:
            s = sub[sub['parameter'] == sz]
            if len(s) == 0: continue
            # Compute GB/s from latency and size
            lat = s['latency_ns'].mean()
            bw = sz / lat  # bytes/ns = GB/s
            means.append(bw)
            stds_v.append(0)
        if means:
            ax.plot(range(len(means)), means, marker=marker, color=color,
                    linewidth=2, markersize=7, label=label)

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_xlabel('Transfer Size')
    ax.set_ylabel('Bandwidth (GB/s)')
    ax.set_title('P2P DMA Bandwidth\n(GPU <-> CXL Host Memory)')
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def plot_p2p_latency(ax, df):
    """P2P DMA read/write latency vs transfer size"""
    sizes = [64, 256, 4096, 65536, 1 << 20]
    labels = ['64B', '256B', '4KB', '64KB', '1MB']

    for exp, label, color, marker in [
        ('gpu_p2p_read', 'GPU Read', '#2196F3', 'o'),
        ('gpu_p2p_write', 'GPU Write', '#FF5722', 's'),
    ]:
        sub = df[df['experiment'] == exp]
        if len(sub) == 0: continue
        means = []
        for sz in sizes:
            s = sub[sub['parameter'] == sz]
            if len(s) == 0: continue
            means.append(s['latency_ns'].mean() / 1e3)  # us
        if means:
            ax.plot(range(len(means)), means, marker=marker, color=color,
                    linewidth=2, markersize=7, label=label)

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_xlabel('Transfer Size')
    ax.set_ylabel('Latency (us)')
    ax.set_yscale('log')
    ax.set_title('P2P DMA Latency\n(GPU <-> CXL Host Memory)')
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def plot_mt_acl_overhead(ax, df):
    """Multi-tenant: ACL check overhead vs no-check baseline"""
    sub_acl = df[(df['experiment'] == 'gpu_mt_acl_overhead') &
                 (df['operation'] == 'read_with_acl')]
    sub_noacl = df[(df['experiment'] == 'gpu_mt_acl_overhead') &
                   (df['operation'] == 'read_no_acl')]

    names = ['With ACL\n(perm check + read)', 'Without ACL\n(read only)']
    means = [sub_acl['thru_mops'].mean() if len(sub_acl) else 0,
             sub_noacl['thru_mops'].mean() if len(sub_noacl) else 0]
    stds = [sub_acl['thru_mops'].std() if len(sub_acl) else 0,
            sub_noacl['thru_mops'].std() if len(sub_noacl) else 0]
    colors = ['#4CAF50', '#9E9E9E']

    bars = ax.bar(names, means, yerr=stds, color=colors, capsize=5,
                  edgecolor='black', linewidth=0.5)
    ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('CXL ACL Permission Check Overhead\n(256 threads, all-allowed)')
    ax.grid(True, alpha=0.3, axis='y')
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                f'{m:.1f}', ha='center', va='bottom', fontsize=10, fontweight='bold')

def plot_mt_read_tenants(ax, df):
    """Multi-tenant read throughput vs tenant count"""
    d = mean_by_param_mops(df, 'gpu_mt_read', 'mt_read_throughput')
    if len(d) == 0: return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#2196F3', marker='o', capsize=3, linewidth=2, markersize=7,
                label='Read (perm-checked)')
    ax.set_xlabel('Number of Tenants')
    ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('Multi-tenant Read Throughput\n(each tenant: 32 GPU threads)')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9); ax.grid(True, alpha=0.3)

def plot_mt_write_tenants(ax, df):
    """Multi-tenant write throughput vs tenant count"""
    d = mean_by_param_mops(df, 'gpu_mt_write', 'mt_write_throughput')
    if len(d) == 0: return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#FF5722', marker='s', capsize=3, linewidth=2, markersize=7,
                label='Write (perm-checked CAS)')
    ax.set_xlabel('Number of Tenants')
    ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('Multi-tenant Write Throughput\n(each tenant: 32 GPU threads)')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9); ax.grid(True, alpha=0.3)

def plot_mt_isolation(ax, df):
    """Cross-tenant isolation: allowed vs denied pie/bar"""
    sub = df[(df['experiment'] == 'gpu_mt_isolation')]
    if len(sub) == 0: return

    # Parse allowed/denied from notes
    allowed_total, denied_total = 0, 0
    for _, row in sub.iterrows():
        notes = str(row.get('notes', ''))
        for part in notes.split(','):
            if part.startswith('allowed='):
                allowed_total += int(part.split('=')[1])
            elif part.startswith('denied='):
                denied_total += int(part.split('=')[1])

    if allowed_total + denied_total == 0: return
    total = allowed_total + denied_total
    pct_allowed = 100.0 * allowed_total / total
    pct_denied = 100.0 * denied_total / total

    colors = ['#F44336', '#4CAF50']
    wedges, texts, autotexts = ax.pie(
        [allowed_total, denied_total],
        labels=[f'Own Slots\n(allowed)', f'Other Tenants\n(denied)'],
        colors=colors, autopct='%1.1f%%', startangle=90,
        textprops={'fontsize': 10})
    ax.set_title(f'Cross-Tenant Isolation (4 tenants)\n'
                 f'Tenant 0 accessing all {total//len(sub)} slots/rep')

def main():
    tsv = sys.argv[1] if len(sys.argv) > 1 else './bench_results/gpu.tsv'
    out = sys.argv[2] if len(sys.argv) > 2 else './bench_results/daxfs_gpu_bench.png'

    df = load_data(tsv)
    print(f"Loaded {len(df)} rows from {tsv}")
    print(f"Experiments: {df['experiment'].unique()}")

    # ── Figure 1: Core PCIe atomics (6 panels) ──
    fig1, axes1 = plt.subplots(2, 3, figsize=(18, 11))
    fig1.suptitle('DAXFS GPU PCIe AtomicOp Coordination Benchmark\n'
                  '(RTX 5090, pinned host memory, PCIe 5.0)',
                  fontsize=15, fontweight='bold')
    plot_latency_bars(axes1[0, 0], df)
    plot_lookup_throughput(axes1[0, 1], df)
    plot_cas_throughput(axes1[0, 2], df)
    plot_lock_contention(axes1[1, 0], df)
    plot_claim_throughput(axes1[1, 1], df)
    plot_lookup_latency(axes1[1, 2], df)
    plt.tight_layout(rect=[0, 0, 1, 0.93])
    fig1.savefig(out, dpi=150, bbox_inches='tight')
    print(f"Saved: {out}")
    plt.close(fig1)

    # ── Figure 2: P2P DMA + Multi-tenant (6 panels) ──
    out2 = out.replace('.png', '_p2p_mt.png')
    fig2, axes2 = plt.subplots(2, 3, figsize=(18, 11))
    fig2.suptitle('DAXFS GPU P2P DMA & Multi-tenant CXL Memory Benchmark\n'
                  '(RTX 5090, PCIe 5.0, shared CXL memory simulation)',
                  fontsize=15, fontweight='bold')
    plot_p2p_bandwidth(axes2[0, 0], df)
    plot_p2p_latency(axes2[0, 1], df)
    plot_mt_acl_overhead(axes2[0, 2], df)
    plot_mt_read_tenants(axes2[1, 0], df)
    plot_mt_write_tenants(axes2[1, 1], df)
    plot_mt_isolation(axes2[1, 2], df)
    plt.tight_layout(rect=[0, 0, 1, 0.93])
    fig2.savefig(out2, dpi=150, bbox_inches='tight')
    print(f"Saved: {out2}")
    plt.close(fig2)

    # ── Individual plots ──
    all_plots = [
        ('latency_bars', plot_latency_bars),
        ('lookup_throughput', plot_lookup_throughput),
        ('cas_throughput', plot_cas_throughput),
        ('lock_contention', plot_lock_contention),
        ('claim_throughput', plot_claim_throughput),
        ('lookup_latency', plot_lookup_latency),
        ('p2p_bandwidth', plot_p2p_bandwidth),
        ('p2p_latency', plot_p2p_latency),
        ('mt_acl_overhead', plot_mt_acl_overhead),
        ('mt_read_tenants', plot_mt_read_tenants),
        ('mt_write_tenants', plot_mt_write_tenants),
        ('mt_isolation', plot_mt_isolation),
    ]
    for name, fn in all_plots:
        f, a = plt.subplots(figsize=(7, 5))
        fn(a, df)
        f.tight_layout()
        p = out.replace('.png', f'_{name}.png')
        f.savefig(p, dpi=150, bbox_inches='tight')
        plt.close(f)
        print(f"  -> {p}")

if __name__ == '__main__':
    main()
