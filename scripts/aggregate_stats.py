#!/usr/bin/env python
# scripts/aggregate_stats.py
"""
统计聚合器：把逐 seed raw JSON 聚合为带 CI/检验的汇总，并执行"匹配基线"比较。

两种模式：

1) 单实验聚合（mean±std + bootstrap 95% CI）：
   python scripts/aggregate_stats.py --arm e1_baseline="results/raw/e1_baseline_seed*.json" \
       --output results/aggregated/stats_e1_baseline.json

2) 攻击臂 vs 匹配基线臂（按匹配键分组 → 组内按 seed 配对检验）：
   python scripts/aggregate_stats.py \
       --attack e1_small_attack="results/raw/e1_small_attack_seed*.json" \
       --baseline e1_small_noattack="results/raw/e1_small_noattack_seed*.json" \
       --output results/aggregated/stats_e1_small_comparison.json

匹配键 = (shell, node_limit, num_eval_epochs, num_flows)。攻击臂只与同匹配键
基线臂比较；无任何共享匹配键时报错退出（可用 --attack-meta/--baseline-meta
为缺 config 快照的旧记录补齐字段，语法：key=value,key=value，
支持 shell/node_limit/num_flows/num_eval_epochs/trials_per_flow_epoch，
'null' → None）。

输出 JSON 中每组/每指标含检验类型（同 seed → Wilcoxon signed-rank；
seed 不重叠 → Mann-Whitney U 退回）、p 值、显著性、rank-biserial 效应量，
以及 trials 基数三元组与小样本告警。
"""
import sys
import json
import argparse
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from starlink_sim.analytics.stats import (
    TrialsCardinalityError,
    aggregate_experiment,
    compare_attack_vs_baseline,
)


def parse_arm(spec: str):
    """解析 label=glob 形式的臂定义。"""
    if '=' not in spec:
        raise argparse.ArgumentTypeError(f"臂定义须为 label=glob 形式，收到: {spec!r}")
    label, pattern = spec.split('=', 1)
    return label.strip(), pattern.strip()


def parse_meta(spec: str) -> dict:
    """解析 key=value,key=value 形式的匹配键覆盖（'null' → None）。"""
    out = {}
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        if '=' not in part:
            raise argparse.ArgumentTypeError(f"meta 覆盖须为 key=value，收到: {part!r}")
        k, v = part.split('=', 1)
        k, v = k.strip(), v.strip()
        if v.lower() == 'null':
            out[k] = None
        elif k in ('node_limit', 'num_flows', 'num_eval_epochs', 'trials_per_flow_epoch', 'total_trials'):
            out[k] = int(v)
        else:
            out[k] = v
    return out


def print_arm_summary(label: str, agg: dict):
    print(f"\n=== 臂 [{label}] 聚合（{agg['n_seeds']} seeds: {agg['seeds']}） ===")
    card = agg['cardinality']
    if card.get('match_key'):
        print(f"匹配键: {json.dumps(card['match_key'], ensure_ascii=False)}")
    detail = card.get('detail') or {}
    if detail.get('total_trials') is not None:
        print(f"trials 基数: {detail.get('num_flows')} flows × {detail.get('num_eval_epochs')} epochs "
              f"× {detail.get('trials_per_flow_epoch', 1)} = {detail['total_trials']} / seed")
    hdr = f"{'metric':<24}{'mean':>10}{'std':>10}{'ci95_low':>10}{'ci95_high':>10}"
    print(hdr)
    print('-' * len(hdr))
    for name, m in agg['metrics'].items():
        lo = f"{m['ci95_low']:.4f}" if m.get('ci95_low') is not None else '-'
        hi = f"{m['ci95_high']:.4f}" if m.get('ci95_high') is not None else '-'
        print(f"{name:<24}{m['mean']:>10.4f}{m['std']:>10.4f}{lo:>10}{hi:>10}")
    for w in agg['warnings']:
        print(f"  [warn] {w}")


def print_comparison(cmp: dict):
    print(f"\n=== 匹配基线比较（{cmp['n_comparable_groups']}/{cmp['n_groups']} 组可比） ===")
    for g in cmp['groups']:
        print(f"\n匹配键: {json.dumps(g['match_key'], ensure_ascii=False)}")
        if not g.get('comparable'):
            for w in g.get('warnings', []):
                print(f"  [skip] {w}")
            continue
        print(f"  配对 seeds: {g.get('paired_seeds')}")
        for metric, r in g.get('comparisons', {}).items():
            sig = '显著' if r['significant'] else '不显著'
            es = r.get('effect_size', {}).get('rank_biserial')
            es_s = f"{es:+.3f}" if es is not None else '-'
            print(f"  {metric:<24} {r['test']:<12} stat={r.get('statistic', r.get('U')):<10.3f} "
                  f"p={r['p_value']:.4f} → {sig}  rank-biserial={es_s}  "
                  f"median_diff={r['median_diff']:+.4f}")
            for w in r.get('warnings', []):
                print(f"      [warn] {w}")


def main(argv=None):
    parser = argparse.ArgumentParser(description='统计聚合器（bootstrap CI + 匹配基线配对检验）')
    parser.add_argument('--arm', action='append', type=parse_arm, default=[],
                        metavar='LABEL=GLOB', help='单实验聚合臂（可多次）')
    parser.add_argument('--attack', type=parse_arm, default=None,
                        metavar='LABEL=GLOB', help='攻击臂')
    parser.add_argument('--baseline', type=parse_arm, default=None,
                        metavar='LABEL=GLOB', help='匹配基线臂（no-attack）')
    parser.add_argument('--attack-meta', type=parse_meta, default=None,
                        help="攻击臂匹配键覆盖，如 'shell=53°,node_limit=null,num_flows=100'")
    parser.add_argument('--baseline-meta', type=parse_meta, default=None,
                        help='基线臂匹配键覆盖（语法同上）')
    parser.add_argument('--alpha', type=float, default=0.05)
    parser.add_argument('--n-boot', type=int, default=2000)
    parser.add_argument('--non-strict', action='store_true',
                        help='匹配键不一致时不抛错，仅在输出中标记不可比')
    parser.add_argument('--output', default=None, help='汇总 JSON 输出路径')
    args = parser.parse_args(argv)

    if not args.arm and not (args.attack and args.baseline):
        parser.error('至少提供 --arm，或同时提供 --attack 与 --baseline')

    report = {
        'generated_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'alpha': args.alpha,
        'n_boot': args.n_boot,
        'arms': {},
        'comparison': None,
    }
    exit_code = 0

    for label, pattern in args.arm:
        agg = aggregate_experiment(pattern, n_boot=args.n_boot, alpha=args.alpha, rng=0)
        print_arm_summary(label, agg)
        report['arms'][label] = agg

    if args.attack and args.baseline:
        atk_label, atk_pattern = args.attack
        base_label, base_pattern = args.baseline
        # 单臂聚合展示
        for label, pattern, overrides in ((atk_label, atk_pattern, args.attack_meta),
                                          (base_label, base_pattern, args.baseline_meta)):
            if label not in report['arms']:
                agg = aggregate_experiment(pattern, n_boot=args.n_boot, alpha=args.alpha,
                                           match_key_overrides=overrides, rng=0)
                print_arm_summary(label, agg)
                report['arms'][label] = agg
        try:
            cmp = compare_attack_vs_baseline(
                atk_pattern, base_pattern, alpha=args.alpha,
                attack_overrides=args.attack_meta,
                baseline_overrides=args.baseline_meta,
                strict=not args.non_strict)
            print_comparison(cmp)
            report['comparison'] = {'attack': atk_label, 'baseline': base_label, **cmp}
        except TrialsCardinalityError as exc:
            print(f"\n[拒绝比较] {exc}", file=sys.stderr)
            report['comparison'] = {'attack': atk_label, 'baseline': base_label,
                                    'error': str(exc)}
            exit_code = 2

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n统计汇总已写入 {out_path}")
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
