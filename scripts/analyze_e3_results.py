#!/usr/bin/env python
# scripts/analyze_e3_results.py
"""
分析 E3 黑洞攻击实验结果（种子 42、43、44），与基线对比。
基线数据来自 results/simulation_summary.json。
"""

import json
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

# 配置
BASELINE_FILE = "results/simulation_summary.json"
SEED_FILES = {
    42: "results/raw/attack_e3_Black hole_seed42.json",
    43: "results/raw/attack_e3_Black hole_seed43.json",
    44: "results/raw/attack_e3_Black hole_seed44.json",
}
OUTPUT_PLOT = "results/e3_attack_analysis.png"

def load_baseline():
    with open(BASELINE_FILE, 'r') as f:
        data = json.load(f)
    return {
        'delivery': data.get('delivery_ratio', 1.0),
        'hops': data.get('avg_hops', 8.0),
        'latency': data.get('avg_latency_ms', 133.9),
        'success_hops': data.get('avg_success_hops', 8.0),
        'success_latency': data.get('avg_success_latency_ms', 133.9),
    }

def load_seed_results():
    data = {}
    for seed, path in SEED_FILES.items():
        with open(path, 'r') as f:
            data[seed] = json.load(f)
    return data

def analyze(data):
    seeds = sorted(data.keys())
    deliveries = []
    hops = []
    attacked_counts = []
    dropped_counts = []
    for seed in seeds:
        d = data[seed]['data_stats']
        deliveries.append(d['delivery_ratio'])
        hops.append(d['avg_hops'])
        attacked_counts.append(d['attacked_count'])
        dropped_counts.append(d['dropped_by_attacker'])
    
    stats = {
        'mean_delivery': np.mean(deliveries),
        'std_delivery': np.std(deliveries, ddof=1),
        'mean_hops': np.mean(hops),
        'std_hops': np.std(hops, ddof=1),
        'mean_attacked': np.mean(attacked_counts),
        'std_attacked': np.std(attacked_counts, ddof=1),
        'mean_dropped': np.mean(dropped_counts),
        'std_dropped': np.std(dropped_counts, ddof=1),
        'seeds': seeds,
        'deliveries': deliveries,
        'hops': hops,
        'attacked': attacked_counts,
        'dropped': dropped_counts,
    }
    return stats

def print_table(stats, baseline):
    print("="*70)
    print("E3 Blackhole Attack Results vs Baseline")
    print("="*70)
    print(f"{'Seed':<8} {'Delivery':<12} {'Avg Hops':<12} {'Attacked':<12} {'Dropped':<12}")
    print("-"*70)
    for i, seed in enumerate(stats['seeds']):
        print(f"{seed:<8} {stats['deliveries'][i]:.3f}       {stats['hops'][i]:.2f}        {stats['attacked'][i]:.0f}         {stats['dropped'][i]:.0f}")
    print("-"*70)
    print(f"Attack Mean ± Std: Delivery = {stats['mean_delivery']:.3f} ± {stats['std_delivery']:.3f}, "
          f"Hops = {stats['mean_hops']:.2f} ± {stats['std_hops']:.2f}")
    print(f"Attacked flows: {stats['mean_attacked']:.1f} ± {stats['std_attacked']:.1f}, "
          f"Dropped: {stats['mean_dropped']:.1f} ± {stats['std_dropped']:.1f}")
    print("="*70)
    print("\nBaseline (no attack):")
    print(f"  Delivery = {baseline['delivery']:.3f}, Hops = {baseline['hops']:.2f}")
    print(f"  Latency  = {baseline['latency']:.2f} ms")
    print("\nAttack Impact:")
    print(f"  Delivery drop: {(1 - stats['mean_delivery'])*100:.1f}% (from {baseline['delivery']:.3f} to {stats['mean_delivery']:.3f})")
    print(f"  Hops change:   {stats['mean_hops'] - baseline['hops']:+.2f} (from {baseline['hops']:.2f} to {stats['mean_hops']:.2f})")
    print("="*70)

def plot_comparison(stats, baseline):
    seeds = stats['seeds']
    deliveries = stats['deliveries']
    attacked = stats['attacked']
    dropped = stats['dropped']

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    
    # 左图：交付率对比
    ax = axes[0]
    bars = ax.bar([str(s) for s in seeds], deliveries, color='skyblue', label='Attack')
    ax.axhline(y=baseline['delivery'], color='r', linestyle='--', label=f'Baseline ({baseline["delivery"]:.2f})')
    ax.set_ylim(0, 1.1)
    ax.set_ylabel('Delivery Ratio')
    ax.set_title('Delivery Ratio per Seed')
    ax.legend()
    for bar, val in zip(bars, deliveries):
        ax.text(bar.get_x() + bar.get_width()/2, val + 0.02, f'{val:.2f}', ha='center')
    
    # 右图：攻击吸引/丢弃流数
    ax = axes[1]
    x = np.arange(len(seeds))
    width = 0.35
    bars1 = ax.bar(x - width/2, attacked, width, label='Attracted', color='orange')
    bars2 = ax.bar(x + width/2, dropped, width, label='Dropped', color='red')
    ax.set_xticks(x)
    ax.set_xticklabels([str(s) for s in seeds])
    ax.set_ylabel('Number of Flows')
    ax.set_title('Flows Attracted and Dropped by Attackers')
    ax.legend()
    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.5, f'{h:.0f}', ha='center')
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.5, f'{h:.0f}', ha='center')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_PLOT, dpi=150)
    plt.show()
    print(f"Plot saved to {OUTPUT_PLOT}")

def main():
    baseline = load_baseline()
    data = load_seed_results()
    stats = analyze(data)
    print_table(stats, baseline)
    plot_comparison(stats, baseline)

if __name__ == '__main__':
    main()