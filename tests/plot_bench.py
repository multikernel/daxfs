#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
DAXFS Benchmark Plotter

Reads agents.tsv and produces a multi-panel figure comparing DAXFS
against tmpfs and overlayfs baselines.
"""

import sys
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

def load_data(tsv_path):
    df = pd.read_csv(tsv_path, sep='\t')
    df['latency_ms'] = df['latency_us'] / 1000.0
    return df

def mean_latency(df, experiment, operation):
    sub = df[(df['experiment'] == experiment) & (df['operation'] == operation)]
    return sub.groupby('parameter')['latency_ms'].agg(['mean', 'std']).reset_index()

def plot_agent_scalability(ax, df):
    """Panel 1: Branch creation time (total) vs N agents — DAXFS vs tmpfs vs overlayfs"""
    for exp, label, color, marker in [
        ('scale_agents', 'DAXFS', '#2196F3', 'o'),
        ('baseline_tmpfs', 'tmpfs (cp -a)', '#FF5722', 's'),
        ('baseline_overlayfs', 'OverlayFS', '#4CAF50', '^'),
    ]:
        d = mean_latency(df, exp, 'branch_create_total')
        if len(d) == 0:
            continue
        ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                     label=label, color=color, marker=marker,
                     capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('Number of Agents (N)')
    ax.set_ylabel('Total Branch Creation (ms)')
    ax.set_title('Branch Creation Cost vs Agent Count')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def plot_parallel_workload(ax, df):
    """Panel 2: Parallel workload time vs N agents"""
    for exp, label, color, marker in [
        ('scale_agents', 'DAXFS', '#2196F3', 'o'),
        ('baseline_tmpfs', 'tmpfs', '#FF5722', 's'),
        ('baseline_overlayfs', 'OverlayFS', '#4CAF50', '^'),
    ]:
        d = mean_latency(df, exp, 'parallel_workload')
        if len(d) == 0:
            continue
        ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                     label=label, color=color, marker=marker,
                     capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('Number of Agents (N)')
    ax.set_ylabel('Parallel Workload Time (ms)')
    ax.set_title('Parallel Agent Workload Scalability')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def plot_commit_time(ax, df):
    """Panel 3: Commit time vs N agents"""
    for exp, label, color, marker in [
        ('scale_agents', 'DAXFS', '#2196F3', 'o'),
        ('baseline_tmpfs', 'tmpfs (cp -a)', '#FF5722', 's'),
        ('baseline_overlayfs', 'OverlayFS (cp upper)', '#4CAF50', '^'),
    ]:
        d = mean_latency(df, exp, 'commit')
        if len(d) == 0:
            continue
        ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                     label=label, color=color, marker=marker,
                     capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('Number of Agents (N)')
    ax.set_ylabel('Commit Time (ms)')
    ax.set_title('Commit / Merge Cost')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def plot_branch_create_avg(ax, df):
    """Panel 4: Per-branch creation cost (avg) vs N — shows O(1) vs O(tree_size)"""
    for exp, label, color, marker in [
        ('scale_agents', 'DAXFS (O(1) CoW)', '#2196F3', 'o'),
        ('baseline_tmpfs', 'tmpfs (O(n) copy)', '#FF5722', 's'),
        ('baseline_overlayfs', 'OverlayFS (mount)', '#4CAF50', '^'),
    ]:
        d = mean_latency(df, exp, 'branch_create_avg')
        if len(d) == 0:
            continue
        ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                     label=label, color=color, marker=marker,
                     capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('Number of Agents (N)')
    ax.set_ylabel('Per-Branch Creation (ms)')
    ax.set_title('Per-Branch Creation Cost (Average)')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def plot_nesting_depth(ax, df):
    """Panel 5: Chain creation + commit time vs nesting depth"""
    for op, label, color, marker in [
        ('chain_create', 'Chain Create', '#2196F3', 'o'),
        ('commit', 'Commit (walks chain)', '#E91E63', 'D'),
        ('workload', 'Workload at Deepest', '#9E9E9E', 'x'),
    ]:
        d = mean_latency(df, 'scale_depth', op)
        if len(d) == 0:
            continue
        ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                     label=label, color=color, marker=marker,
                     capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('Nesting Depth (D)')
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Speculation Nesting Depth')
    ax.set_xscale('log', base=2)
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def plot_commit_cost(ax, df):
    """Panel 6: Commit cost vs number of write operations"""
    for op, label, color, marker in [
        ('commit', 'Commit Time', '#E91E63', 'D'),
        ('workload', 'Workload Time', '#9E9E9E', 'x'),
    ]:
        d = mean_latency(df, 'commit_cost', op)
        if len(d) == 0:
            continue
        ax.errorbar(d['parameter'], d['mean'], yerr=d['std'],
                     label=label, color=color, marker=marker,
                     capsize=3, linewidth=2, markersize=7)
    ax.set_xlabel('Number of Write Operations')
    ax.set_ylabel('Latency (ms)')
    ax.set_title('Commit Cost vs Delta Size')
    ax.set_xscale('log')
    ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)

def main():
    tsv_path = sys.argv[1] if len(sys.argv) > 1 else './bench_results/agents.tsv'
    out_path = sys.argv[2] if len(sys.argv) > 2 else './bench_results/daxfs_bench.png'

    df = load_data(tsv_path)
    print(f"Loaded {len(df)} rows from {tsv_path}")
    print(f"Experiments: {df['experiment'].unique()}")

    fig, axes = plt.subplots(2, 3, figsize=(18, 11))
    fig.suptitle('DAXFS AI Agent Speculative Branching Benchmark', fontsize=16, fontweight='bold')

    plot_agent_scalability(axes[0, 0], df)
    plot_branch_create_avg(axes[0, 1], df)
    plot_parallel_workload(axes[0, 2], df)
    plot_commit_time(axes[1, 0], df)
    plot_nesting_depth(axes[1, 1], df)
    plot_commit_cost(axes[1, 2], df)

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(out_path, dpi=150, bbox_inches='tight')
    print(f"Saved figure to {out_path}")

    # Also save individual plots for paper use
    for name, plot_fn in [
        ('branch_creation', plot_agent_scalability),
        ('branch_avg', plot_branch_create_avg),
        ('parallel_workload', plot_parallel_workload),
        ('commit_time', plot_commit_time),
        ('nesting_depth', plot_nesting_depth),
        ('commit_cost', plot_commit_cost),
    ]:
        fig2, ax2 = plt.subplots(figsize=(7, 5))
        plot_fn(ax2, df)
        fig2.tight_layout()
        p = out_path.replace('.png', f'_{name}.png')
        fig2.savefig(p, dpi=150, bbox_inches='tight')
        plt.close(fig2)
        print(f"  -> {p}")

    plt.close(fig)

if __name__ == '__main__':
    main()
