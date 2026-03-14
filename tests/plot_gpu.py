#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
DAXFS GPU Coordination Benchmark Plotter

Reads gpu.tsv and produces a multi-panel figure showing PCIe AtomicOp
latency and throughput for GPU-side coordination primitives.
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

def plot_latency_bars(ax, df):
    """Panel 1: Single-thread latency of each primitive"""
    primitives = [
        ('gpu_commit_seq', 'volatile_read', 'PCIe Read\n(commit_seq)', '#2196F3'),
        ('gpu_pending_ctr', 'cas_inc_dec', 'CAS Inc/Dec\n(pending_ctr)', '#FF9800'),
        ('gpu_coord_lock', 'lock_unlock_rt', 'Lock+Unlock\n(coord_lock)', '#F44336'),
    ]
    names, means, stds, colors = [], [], [], []
    for exp, op, name, color in primitives:
        sub = df[(df['experiment'] == exp) & (df['operation'] == op)]
        if len(sub) == 0:
            continue
        names.append(name)
        means.append(sub['latency_ns'].mean())
        stds.append(sub['latency_ns'].std())
        colors.append(color)

    bars = ax.bar(names, means, yerr=stds, color=colors, capsize=5, edgecolor='black', linewidth=0.5)
    ax.set_ylabel('Latency (ns)')
    ax.set_title('PCIe Atomic Primitive Latency\n(single GPU thread)')
    ax.grid(True, alpha=0.3, axis='y')
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 30,
                f'{m:.0f} ns', ha='center', va='bottom', fontsize=9, fontweight='bold')

def plot_lookup_throughput(ax, df):
    """Panel 2: Page cache lookup throughput vs thread count"""
    d = mean_by_param_mops(df, 'gpu_pcache_lookup', 'lookup_throughput')
    if len(d) == 0:
        ax.text(0.5, 0.5, 'No data', transform=ax.transAxes, ha='center')
        return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#2196F3', marker='o', capsize=3, linewidth=2, markersize=7)
    # Add ideal scaling line
    base = d['mean'].iloc[0]
    ideal = d['parameter'] * base
    ax.plot(d['parameter'], ideal, '--', color='gray', alpha=0.5, label='Ideal linear')
    ax.set_xlabel('GPU Threads')
    ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('Page Cache Lookup Throughput')
    ax.set_xscale('log', base=2)
    ax.set_yscale('log', base=10)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def plot_cas_throughput(ax, df):
    """Panel 3: CAS throughput vs thread count"""
    d = mean_by_param_mops(df, 'gpu_slot_cas', 'cas_throughput')
    if len(d) == 0:
        ax.text(0.5, 0.5, 'No data', transform=ax.transAxes, ha='center')
        return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#E91E63', marker='D', capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('GPU Threads')
    ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('Slot CAS Throughput\n(independent slots, PCIe atomics)')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(True, alpha=0.3)
    # Annotate plateau
    if len(d) >= 4:
        plateau = d['mean'].iloc[-3:].mean()
        ax.axhline(y=plateau, color='gray', linestyle=':', alpha=0.5)
        ax.text(d['parameter'].iloc[-1], plateau * 1.1,
                f'PCIe BW limit: {plateau:.1f} Mops/s',
                ha='right', fontsize=8, color='gray')

def plot_lock_contention(ax, df):
    """Panel 4: Lock acquisition time vs thread count"""
    d = mean_by_param(df, 'gpu_lock_contention', 'lock_acquisition')
    if len(d) == 0:
        ax.text(0.5, 0.5, 'No data', transform=ax.transAxes, ha='center')
        return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#F44336', marker='s', capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('Contending GPU Threads')
    ax.set_ylabel('Time per Acquisition (ns)')
    ax.set_title('Coordination Lock Contention')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(True, alpha=0.3)

def plot_claim_throughput(ax, df):
    """Panel 5: Page cache claim throughput vs thread count"""
    d = mean_by_param_mops(df, 'gpu_pcache_claim', 'claim_throughput')
    if len(d) == 0:
        ax.text(0.5, 0.5, 'No data', transform=ax.transAxes, ha='center')
        return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#4CAF50', marker='^', capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('GPU Threads')
    ax.set_ylabel('Throughput (Mops/s)')
    ax.set_title('Page Cache Claim\n(FREE→PENDING + pending counter)')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(True, alpha=0.3)

def plot_lookup_latency(ax, df):
    """Panel 6: Per-op lookup latency vs thread count"""
    d = mean_by_param(df, 'gpu_pcache_lookup', 'lookup_throughput')
    if len(d) == 0:
        ax.text(0.5, 0.5, 'No data', transform=ax.transAxes, ha='center')
        return
    ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                color='#2196F3', marker='o', capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('GPU Threads')
    ax.set_ylabel('Per-Op Latency (ns)')
    ax.set_title('Page Cache Lookup Latency')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.grid(True, alpha=0.3)

def main():
    tsv = sys.argv[1] if len(sys.argv) > 1 else './bench_results/gpu.tsv'
    out = sys.argv[2] if len(sys.argv) > 2 else './bench_results/daxfs_gpu_bench.png'

    df = load_data(tsv)
    print(f"Loaded {len(df)} rows from {tsv}")
    print(f"Experiments: {df['experiment'].unique()}")

    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    fig.suptitle('DAXFS GPU PCIe AtomicOp Coordination Benchmark\n'
                 '(RTX 5090, pinned host memory, PCIe 5.0)',
                 fontsize=15, fontweight='bold')

    plot_latency_bars(axes[0, 0], df)
    plot_lookup_throughput(axes[0, 1], df)
    plot_cas_throughput(axes[0, 2], df)
    plot_lock_contention(axes[1, 0], df)
    plot_claim_throughput(axes[1, 1], df)
    plot_lookup_latency(axes[1, 2], df)

    plt.tight_layout(rect=[0, 0, 1, 0.93])
    fig.savefig(out, dpi=150, bbox_inches='tight')
    print(f"Saved: {out}")

    # Individual plots
    for name, fn in [
        ('latency_bars', plot_latency_bars),
        ('lookup_throughput', plot_lookup_throughput),
        ('cas_throughput', plot_cas_throughput),
        ('lock_contention', plot_lock_contention),
        ('claim_throughput', plot_claim_throughput),
        ('lookup_latency', plot_lookup_latency),
    ]:
        f2, a2 = plt.subplots(figsize=(7, 5))
        fn(a2, df)
        f2.tight_layout()
        p = out.replace('.png', f'_{name}.png')
        f2.savefig(p, dpi=150, bbox_inches='tight')
        plt.close(f2)
        print(f"  -> {p}")

    plt.close(fig)

if __name__ == '__main__':
    main()
