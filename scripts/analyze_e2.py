#!/usr/bin/env python
"""
E2 Jamming Attack Analysis (Seeds 42,43,44 only)
Reads paired results (no-attack and attack) for seeds 42,43,44.
Generates summary tables, paired statistics, and plots.
"""
import json
import glob
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Use seaborn-like style if available, otherwise fallback
try:
    plt.style.use('seaborn-v0_8-whitegrid')
except:
    plt.style.use('default')


def load_metrics(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return {
        'seed': data['seed'],
        'is_attack': data['config']['attack']['count'] > 0,
        'delivery_ratio': data['delivery_ratio'],
        'total_loops': data['total_loops'],
        'attracted_count': data['attacked_count'],
        'avg_success_hops': data['avg_success_hops'],
        'num_success': data['num_success'],
        'num_trials': data['num_trials'],
    }


def main():
    raw_dir = Path("results/raw")
    fig_dir = Path("results/figures")
    fig_dir.mkdir(parents=True, exist_ok=True)

    # Find all relevant JSON files
    files = glob.glob(str(raw_dir / "e2_jamming_seed4*.json"))  # seeds 42,43,44
    if not files:
        print("No files for seeds 42,43,44 found.")
        return

    # Load data
    rows = []
    for f in files:
        try:
            rows.append(load_metrics(f))
        except Exception as e:
            print(f"Error loading {f}: {e}")

    if not rows:
        return

    df = pd.DataFrame(rows)

    # Keep only seeds 42,43,44 (if any others appear, filter)
    df = df[df['seed'].isin([42, 43, 44])]

    # Separate no-attack and attack
    no_attack = df[df['is_attack'] == False].set_index('seed').sort_index()
    attack = df[df['is_attack'] == True].set_index('seed').sort_index()

    # Merge for paired analysis
    paired = no_attack.join(attack, lsuffix='_no', rsuffix='_att')
    paired['delivery_ratio_drop'] = (paired['delivery_ratio_no'] - paired['delivery_ratio_att']) / paired['delivery_ratio_no'] * 100
    paired['loop_increase'] = paired['total_loops_att'] - paired['total_loops_no']
    paired['attracted_mean'] = paired['attracted_count_att']  # no-attack is 0

    # Summary statistics
    summary_no = no_attack.describe().loc[['mean', 'std']].round(4)
    summary_att = attack.describe().loc[['mean', 'std']].round(4)

    # Print tables
    print("\n=== E2 Jamming Attack Analysis (Seeds 42-44) ===\n")
    print("| Metric | No-Attack Mean | No-Attack Std | Attack Mean | Attack Std |")
    print("|--------|---------------|---------------|-------------|------------|")
    for metric in ['delivery_ratio', 'total_loops', 'attracted_count', 'avg_success_hops']:
        m_no = summary_no.loc['mean', metric]
        s_no = summary_no.loc['std', metric]
        m_att = summary_att.loc['mean', metric]
        s_att = summary_att.loc['std', metric]
        print(f"| {metric} | {m_no:.4f} | {s_no:.4f} | {m_att:.4f} | {s_att:.4f} |")

    # Paired results
    print("\n=== Paired Comparison (Attack vs No-Attack) ===\n")
    print("| Seed | No-Attack DR | Attack DR | DR Drop (%) | Loop Increase |")
    print("|------|--------------|-----------|-------------|---------------|")
    for seed in paired.index:
        row = paired.loc[seed]
        print(f"| {seed} | {row['delivery_ratio_no']:.4f} | {row['delivery_ratio_att']:.4f} | {row['delivery_ratio_drop']:.2f} | {row['loop_increase']:.0f} |")

    # Overall average drop
    avg_drop = paired['delivery_ratio_drop'].mean()
    avg_loop_inc = paired['loop_increase'].mean()
    print(f"\nAverage delivery ratio drop: {avg_drop:.2f}%")
    print(f"Average loop increase: {avg_loop_inc:.0f} loops")

    # Plotting
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))

    # 1. Delivery ratio boxplot
    ax = axes[0, 0]
    ax.boxplot([no_attack['delivery_ratio'], attack['delivery_ratio']])
    ax.set_xticklabels(['No Attack', 'Attack'])
    ax.set_title('Delivery Ratio')
    ax.set_ylabel('Delivery Ratio')
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    # 2. Total loops boxplot
    ax = axes[0, 1]
    ax.boxplot([no_attack['total_loops'], attack['total_loops']])
    ax.set_xticklabels(['No Attack', 'Attack'])
    ax.set_title('Total Loops')
    ax.set_ylabel('Number of Loops')
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    # 3. Attracted flows per experiment (attack only)
    ax = axes[1, 0]
    ax.hist(attack['attracted_count'], bins=4, edgecolor='black')
    ax.set_title('Attracted Flows per Experiment')
    ax.set_xlabel('Attracted Count')
    ax.set_ylabel('Frequency')
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    # 4. Per-attacker attracted flows (aggregate from all attack files)
    attacker_counts = []
    for f in files:
        if 'seed42_2' in f or 'seed43_2' in f or 'seed44_2' in f:  # attack files
            with open(f, 'r') as fp:
                data = json.load(fp)
                stats = data.get('attacker_stats', [])
                for att in stats:
                    if att['attracted_count'] > 0:
                        attacker_counts.append(att['attracted_count'])
    ax = axes[1, 1]
    if attacker_counts:
        ax.hist(attacker_counts, bins=8, edgecolor='black')
        ax.set_title('Attracted Flows per Attacker')
        ax.set_xlabel('Attracted Count per Attacker')
        ax.set_ylabel('Frequency')
        ax.grid(axis='y', linestyle='--', alpha=0.7)
    else:
        ax.text(0.5, 0.5, 'No attacker stats', ha='center', va='center')

    plt.tight_layout()
    plt.savefig(fig_dir / 'e2_analysis_42_44.png', dpi=300)
    print(f"\nPlot saved to {fig_dir / 'e2_analysis_42_44.png'}")

    # Save CSVs
    no_attack.to_csv(fig_dir / 'no_attack_42_44.csv')
    attack.to_csv(fig_dir / 'attack_42_44.csv')
    paired.to_csv(fig_dir / 'paired_42_44.csv')
    print("CSV files saved.")


if __name__ == "__main__":
    main()