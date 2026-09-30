# -*- coding: utf-8 -*-
"""
scripts/aggregate_step3.py
step3 / Phase 1 攻击矩阵（B 档）统一聚合 + 全配对比较 + 图表产出。

为什么需要它（而不是只用 run_experiment_sweep.py 自带聚合）
--------------------------------------------------------
sweep 的 ``comparison`` 字段**只支持一对** (attack, baseline)，且 CLI ``--attack/--baseline``
会触发**重跑**。step3 有 9 个 sweep、61 个臂，需要「每个攻击臂 vs 其配对基线」的**全部**
比较（E4 六档、E5 五策略、E5 九强度、E7 七臂、四壳 × 两规模、六档规模阶梯）。
本脚本直接从已落盘的 raw JSON 复算，**不重跑任何仿真**，因此可以在 sweep 跑完后
反复调整比较口径与图表。

产出
----
1. ``results/aggregated/step3/agg_{sweep}__{arm}.json``     逐臂聚合（bootstrap 95% CI）
2. ``results/aggregated/step3/cmp_{sweep}__{a}_vs_{b}.json`` 逐对比较（Wilcoxon/MWU + strict 匹配键）
3. ``results/aggregated/step3/step3_arms.csv``               全部臂 × 指标扁平表
4. ``results/aggregated/step3/step3_comparisons.csv``        全部配对 × 指标扁平表
5. ``results/aggregated/step3/step3_summary.json``           机读摘要（含完整性/失败清单）
6. ``results/figures/step3_*.png`` + 同名 ``.csv``            图表（PNG 与数据同源）

统计口径（全部走 starlink_sim/analytics/stats.py，不自实现）
--------------------------------------------------------
- bootstrap 95% CI，``n_boot=4000``（≥ 用户硬要求 2000）
- 同 seed 成对数 ≥2 → Wilcoxon signed-rank；否则退回 Mann-Whitney U
- ``compare_attack_vs_baseline(..., strict=True)``：匹配键
  ``(shell, node_limit, num_eval_epochs, num_flows)`` 不一致即抛
  ``TrialsCardinalityError`` —— 本脚本**捕获并如实记录为失败对**，绝不放宽 strict。

用法::

    python scripts/aggregate_step3.py                      # 全量聚合 + 图表
    python scripts/aggregate_step3.py --no-figures         # 仅 JSON/CSV
    python scripts/aggregate_step3.py --only e4_sybil e6_wormhole
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
for _p in (str(PROJECT_ROOT), str(PROJECT_ROOT / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from starlink_sim.analytics.stats import (  # noqa: E402
    aggregate_experiment,
    compare_attack_vs_baseline,
    TrialsCardinalityError,
)
from run_experiment_sweep import SWEEP_METRICS  # noqa: E402  与 sweep 完全同一指标宇宙

RAW_ROOT = PROJECT_ROOT / "results" / "step3_raw"
OUT_DIR = PROJECT_ROOT / "results" / "aggregated" / "step3"
FIG_DIR = PROJECT_ROOT / "results" / "figures"
SPEC_DIR = PROJECT_ROOT / "configs" / "experiments" / "step3"

N_BOOT = 4000
ALPHA = 0.05

# ==================== 配对比较计划（sweep -> [(attack_label, baseline_label), ...]）====================
# 每对都必须是**同 sweep 内**的臂（同 shell/node_limit/num_eval_epochs/num_flows），
# 否则 strict=True 会拒绝 —— 这是刻意的硬约束，不做任何放宽。
_SHELL_TAGS = ("53", "70", "975", "43")
_E5A_SMALL_NL = (48, 96, 256, 512, 1024)

COMPARISON_PLAN: Dict[str, List[Tuple[str, str]]] = {
    "e4_sybil": [(f"ids{n}", "base") for n in (1, 2, 4, 8, 16, 32)],
    "e5_placement": [(lbl, "base") for lbl in ("degree", "rnd", "btw", "kcore", "led")],
    "e5_intensity": [(lbl, "base") for lbl in
                     ("c1", "c3", "c6", "c12", "c24", "p00", "p20", "p50", "p100")],
    "e6_wormhole": [(lbl, "base_det") for lbl in ("t1", "t3", "extreme")],
    "e7_combo": [(lbl, "base") for lbl in
                 ("bh3", "jm3", "sy8", "bh3_jm3", "bh3_sy8", "jm3_sy8", "bh3_jm3_sy8")],
    "shell256": [(f"bh3_{t}", f"base_{t}") for t in _SHELL_TAGS],
    "shell1024": [(f"bh3_{t}", f"base_{t}") for t in _SHELL_TAGS],
    "e5a_scale_small": [(f"bh3_n{nl}", f"base_n{nl}") for nl in _E5A_SMALL_NL],
    # 顶档：原计划 4284 全量在本机内存不可行（实测 2 epochs 就 ≥20.7GB 且未完成，
    # 根因 = 500B·N² 活路由表 + 100B·N²·epochs 历史快照），已如实降级为 2048。
    "e5a_scale_top": [("bh3_n2048", "base_n2048")],
}

# 报告/图表重点关注指标（其余指标仍全部落 CSV，不丢弃）
FOCUS_METRICS: Tuple[str, ...] = (
    "delivery_ratio", "avg_hops", "avg_latency_ms", "total_loops",
    "attacked_count", "dropped_by_attacker",
    "sybil_attraction_ratio", "sybil_attracted_trials",
    "wormhole_attracted_ratio", "wormhole_detection_rate",
    "wormhole_false_positive_rate", "wormhole_path_stretch",
    "wormhole_geo_stretch", "wormhole_latency_flagged_ratio",
)

_RAW_RE = re.compile(r"^(?P<label>.+)__(?P<exp>.+)_seed(?P<seed>-?\d+)\.json$")


# ==================== 发现与完整性 ====================

def discover(raw_root: Path) -> Dict[str, Dict[str, List[Path]]]:
    """扫描 raw 目录：{sweep_key: {arm_label: [raw json paths]}}（按 seed 排序）。"""
    out: Dict[str, Dict[str, List[Path]]] = {}
    if not raw_root.exists():
        return out
    for sweep_dir in sorted(p for p in raw_root.iterdir() if p.is_dir()):
        arms: Dict[str, List[Path]] = {}
        for f in sorted(sweep_dir.glob("*.json")):
            m = _RAW_RE.match(f.name)
            if not m:
                continue
            arms.setdefault(m.group("label"), []).append(f)
        for lbl in arms:
            arms[lbl].sort(key=lambda p: int(_RAW_RE.match(p.name).group("seed")))
        if arms:
            out[sweep_dir.name] = arms
    return out


def expected_from_spec(sweep_key: str) -> Optional[Dict[str, Any]]:
    """从 sweep YAML 读出「应有的」臂与 seeds，用于完整性核对（诚实报告缺口）。"""
    path = SPEC_DIR / f"sweep_{sweep_key}.yaml"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    sw = raw.get("sweep", raw)
    return {
        "labels": [a["label"] for a in sw.get("arms", [])],
        "seeds": [int(s) for s in sw.get("seeds", [])],
        "workers": int(sw.get("workers", 2)),
        "n_boot": int(sw.get("n_boot", 2000)),
    }


def completeness(found: Dict[str, Dict[str, List[Path]]]) -> List[Dict[str, Any]]:
    """逐 sweep 逐臂核对「实得 seed 数 vs 应有 seed 数」，列出所有缺口。"""
    rows: List[Dict[str, Any]] = []
    for key in sorted(set(found) | set(COMPARISON_PLAN)):
        spec = expected_from_spec(key)
        arms = found.get(key, {})
        want_seeds = (spec or {}).get("seeds") or []
        want_labels = (spec or {}).get("labels") or sorted(arms)
        for lbl in want_labels:
            files = arms.get(lbl, [])
            got = sorted(int(_RAW_RE.match(p.name).group("seed")) for p in files)
            missing = [s for s in want_seeds if s not in got]
            rows.append({
                "sweep": key, "arm": lbl, "n_expected": len(want_seeds),
                "n_found": len(files), "seeds_found": got, "seeds_missing": missing,
                "complete": (not missing) and len(files) == len(want_seeds),
            })
    return rows


# ==================== 聚合与比较 ====================

def _flat_metric(agg: dict, name: str) -> Dict[str, Any]:
    m = (agg.get("metrics") or {}).get(name)
    if not m:
        return {}
    return {"mean": m.get("mean"), "std": m.get("std"),
            "ci95_low": m.get("ci95_low"), "ci95_high": m.get("ci95_high"),
            "n": m.get("n"), "per_seed": m.get("per_seed")}


def _cmp_row(sweep: str, atk: str, base: str, group: dict,
             metric: str, r: dict, extra: Optional[dict] = None) -> Dict[str, Any]:
    es = (r.get("effect_size") or {}).get("rank_biserial")
    row = {
        "sweep": sweep, "attack": atk, "baseline": base,
        "shell": (group.get("match_key") or {}).get("shell"),
        "node_limit": (group.get("match_key") or {}).get("node_limit"),
        "num_eval_epochs": (group.get("match_key") or {}).get("num_eval_epochs"),
        "num_flows": (group.get("match_key") or {}).get("num_flows"),
        "metric": metric,
        "test": r.get("test"),
        "statistic": r.get("statistic", r.get("U")),
        "p_value": r.get("p_value"),
        "significant": r.get("significant"),
        "rank_biserial": es,
        "median_diff": r.get("median_diff"),
        "median_attack": r.get("median_attack"),
        "median_baseline": r.get("median_baseline"),
        "n_pairs": r.get("n_pairs"),
        "warnings": "; ".join(r.get("warnings") or []),
    }
    if extra:
        row.update(extra)
    return row


# ---- 带符号配对效应量（绕开 stats.py 在 scipy>=1.7 下的符号缺陷）----

def _seed_series(agg: dict, metric: str) -> Dict[int, float]:
    """从逐臂聚合结果抽出 {seed: 指标值}（与 stats.py 配对检验用的同一序列）。"""
    out: Dict[int, float] = {}
    for ps in (agg.get("per_seed") or []):
        v = (ps.get("metrics") or {}).get(metric)
        if v is not None:
            out[int(ps["seed"])] = float(v)
    return out


def _signed_rank_biserial(a: Dict[int, float], b: Dict[int, float]) -> Dict[str, Any]:
    """配对 rank-biserial，**带符号**（T+ 口径），符号约定 >0 = 攻击臂更大。

    为什么不直接用 stats.py 的 ``effect_size.rank_biserial``
    --------------------------------------------------------
    scipy>=1.7 下 ``wilcoxon(diff, alternative='two-sided').statistic`` 返回的是
    **min(T+, T−)** 而不是 T+；stats.paired_by_seed 却按 T+ 口径代入
    ``r = (2V − T)/T``，于是只要全部配对差值同号（攻击实验的常态），
    就恒得 ``r = −1``：**符号失效 + 幅度饱和**，与 ``median_diff`` 方向矛盾。
    实测证据（scipy 1.15.3）::

        wilcoxon([1, 2]).statistic  == 0.0   # 全正差值，T+ 应为 3.0
        wilcoxon([-1, -2]).statistic == 0.0  # 与上者不可区分

    本函数直接从配对差值重算 T+（含并列平均秩）。**仅补正效应量**：
    检验类型与 p 值仍取 stats.py 的结果（那部分经验证正确：n=5 全同号
    得 p=0.0625 = 2/2⁵）。上游 bug 已在报告中列出，建议 Task #9+ 修 stats.py。
    """
    shared = sorted(set(a) & set(b))
    nz = [a[s] - b[s] for s in shared if a[s] - b[s] != 0.0]
    n_eff = len(nz)
    if n_eff == 0:
        return {"rank_biserial_signed": 0.0, "t_plus": 0.0, "n_eff": 0,
                "rb_note": "所有配对差值为 0，效应量无定义"}
    order = sorted(range(n_eff), key=lambda i: abs(nz[i]))
    ranks = [0.0] * n_eff
    i = 0
    while i < n_eff:
        j = i
        while j + 1 < n_eff and abs(nz[order[j + 1]]) == abs(nz[order[i]]):
            j += 1
        avg = (i + j) / 2.0 + 1.0          # 并列取平均秩
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    t_plus = float(sum(rk for rk, d in zip(ranks, nz) if d > 0))
    t_tot = n_eff * (n_eff + 1) / 2.0
    return {"rank_biserial_signed": (2.0 * t_plus - t_tot) / t_tot,
            "t_plus": t_plus, "n_eff": n_eff, "rb_note": ""}


def run(raw_root: Path, out_dir: Path, only: Optional[Sequence[str]] = None,
        n_boot: int = N_BOOT, alpha: float = ALPHA) -> Dict[str, Any]:
    found = discover(raw_root)
    out_dir.mkdir(parents=True, exist_ok=True)

    aggs: Dict[str, Dict[str, dict]] = {}
    cmp_rows: List[Dict[str, Any]] = []
    arm_rows: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    cmp_json: Dict[str, Any] = {}

    sweeps = sorted(found)
    if only:
        sweeps = [s for s in sweeps if s in set(only)]

    for sweep in sweeps:
        arms = found[sweep]
        aggs[sweep] = {}
        for lbl, files in arms.items():
            try:
                agg = aggregate_experiment([str(p) for p in files],
                                           metrics=SWEEP_METRICS,
                                           n_boot=n_boot, alpha=alpha, rng=0)
            except Exception as exc:                      # noqa: BLE001 如实记录
                failures.append({"sweep": sweep, "arm": lbl, "stage": "aggregate",
                                 "error": f"{type(exc).__name__}: {exc}"})
                continue
            aggs[sweep][lbl] = agg
            with open(out_dir / f"agg_{sweep}__{lbl}.json", "w", encoding="utf-8") as f:
                json.dump(agg, f, indent=2, ensure_ascii=False)
            mk = (agg.get("cardinality") or {}).get("match_key") or {}
            for name, m in (agg.get("metrics") or {}).items():
                arm_rows.append({
                    "sweep": sweep, "arm": lbl, "metric": name,
                    "shell": mk.get("shell"), "node_limit": mk.get("node_limit"),
                    "num_eval_epochs": mk.get("num_eval_epochs"),
                    "num_flows": mk.get("num_flows"),
                    "n_seeds": agg.get("n_seeds"), "n": m.get("n"),
                    "mean": m.get("mean"), "std": m.get("std"),
                    "ci95_low": m.get("ci95_low"), "ci95_high": m.get("ci95_high"),
                    "warnings": "; ".join(agg.get("warnings") or []),
                })

        for atk, base in COMPARISON_PLAN.get(sweep, []):
            a_files = arms.get(atk)
            b_files = arms.get(base)
            if not a_files or not b_files:
                failures.append({
                    "sweep": sweep, "arm": f"{atk} vs {base}", "stage": "compare",
                    "error": f"缺少 raw 文件（attack={len(a_files or [])}, "
                             f"baseline={len(b_files or [])}）"})
                continue
            try:
                cmp_res = compare_attack_vs_baseline(
                    [str(p) for p in a_files], [str(p) for p in b_files],
                    metrics=SWEEP_METRICS, alpha=alpha, strict=True)
            except TrialsCardinalityError as exc:
                # **不放宽 strict**：如实记录为失败对，配置须修正后重跑
                failures.append({"sweep": sweep, "arm": f"{atk} vs {base}",
                                 "stage": "compare",
                                 "error": f"TrialsCardinalityError: {exc}"})
                continue
            except Exception as exc:                      # noqa: BLE001
                failures.append({"sweep": sweep, "arm": f"{atk} vs {base}",
                                 "stage": "compare",
                                 "error": f"{type(exc).__name__}: {exc}"})
                continue
            cmp_json[f"{sweep}__{atk}_vs_{base}"] = cmp_res
            with open(out_dir / f"cmp_{sweep}__{atk}_vs_{base}.json", "w",
                      encoding="utf-8") as f:
                json.dump(cmp_res, f, indent=2, ensure_ascii=False)
            for g in cmp_res.get("groups", []):
                if not g.get("comparable"):
                    failures.append({"sweep": sweep, "arm": f"{atk} vs {base}",
                                     "stage": "group",
                                     "error": "; ".join(g.get("warnings") or [])})
                    continue
                for metric, r in (g.get("comparisons") or {}).items():
                    extra = None
                    if r.get("test") == "wilcoxon":
                        aa = aggs[sweep].get(atk)
                        bb = aggs[sweep].get(base)
                        if aa and bb:
                            extra = _signed_rank_biserial(
                                _seed_series(aa, metric), _seed_series(bb, metric))
                    cmp_rows.append(_cmp_row(sweep, atk, base, g, metric, r, extra))

    # ---------- 扁平 CSV ----------
    _write_csv(out_dir / "step3_arms.csv", arm_rows,
               ["sweep", "arm", "metric", "shell", "node_limit", "num_eval_epochs",
                "num_flows", "n_seeds", "n", "mean", "std", "ci95_low", "ci95_high",
                "warnings"])
    _write_csv(out_dir / "step3_comparisons.csv", cmp_rows,
               ["sweep", "attack", "baseline", "shell", "node_limit", "num_eval_epochs",
                "num_flows", "metric", "test", "statistic", "p_value", "significant",
                "rank_biserial", "rank_biserial_signed", "t_plus", "n_eff", "rb_note",
                "median_diff", "median_attack", "median_baseline",
                "n_pairs", "warnings"])

    comp_rows = completeness(found)
    summary = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "raw_root": str(raw_root), "out_dir": str(out_dir),
        "n_boot": n_boot, "alpha": alpha,
        "metrics_universe": list(SWEEP_METRICS),
        "policy": "bootstrap 95% CI；同 seed≥2 用 Wilcoxon，否则 Mann-Whitney U；"
                  "compare_attack_vs_baseline(strict=True) —— 匹配键不一致即判为不可比，不做任何放宽",
        "known_upstream_bug": {
            "where": "starlink_sim/analytics/stats.py paired_by_seed() 的 rank-biserial",
            "what": "scipy>=1.7 下 wilcoxon(alternative='two-sided').statistic 返回 "
                    "min(T+,T-) 而非 T+，但代码按 T+ 口径代入 r=(2V-T)/T",
            "impact": "配对效应量 rank_biserial 符号失效：全部差值同号时恒得 -1，"
                      "与 median_diff 方向矛盾（不影响 p 值与显著性判定）",
            "evidence": "scipy 1.15.3: wilcoxon([1,2]).statistic == 0.0（T+ 应为 3.0）；"
                        "wilcoxon([-1,-2]).statistic == 0.0（与全正不可区分）",
            "workaround": "本脚本附加计算 rank_biserial_signed（直接从配对差值重算 T+，"
                          "含并列平均秩）；**报告与图表一律用 rank_biserial_signed**",
            "recommend": "Task #9+ 修 stats.py（改用 alternative='greater' 取 T+ 或自算），"
                         "并补回归测试钉住符号约定；修后需重算历史 T7 聚合结果的效应量",
        },
        "sweeps": {s: {"arms": sorted(aggs.get(s, {})),
                       "n_arms": len(aggs.get(s, {})),
                       "n_seeds": {l: a.get("n_seeds") for l, a in (aggs.get(s) or {}).items()},
                       "match_keys": {l: (a.get("cardinality") or {}).get("match_key")
                                      for l, a in (aggs.get(s) or {}).items()}}
                   for s in sorted(aggs)},
        "n_comparisons": len({(r["sweep"], r["attack"], r["baseline"]) for r in cmp_rows}),
        "n_comparison_rows": len(cmp_rows),
        "completeness": comp_rows,
        "failures": failures,
    }
    with open(out_dir / "step3_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    _write_csv(out_dir / "step3_completeness.csv", comp_rows,
               ["sweep", "arm", "n_expected", "n_found", "complete",
                "seeds_found", "seeds_missing"])
    _write_csv(out_dir / "step3_failures.csv", failures,
               ["sweep", "arm", "stage", "error"])

    print(f"[aggregate_step3] sweeps={len(aggs)} arms={sum(len(v) for v in aggs.values())} "
          f"comparison_rows={len(cmp_rows)} failures={len(failures)}")
    print(f"[aggregate_step3] 输出 → {out_dir}")
    return {"summary": summary, "aggs": aggs, "cmp_rows": cmp_rows,
            "arm_rows": arm_rows, "failures": failures}


def _write_csv(path: Path, rows: List[Dict[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fields), extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _csv_val(r.get(k)) for k in fields})


def _csv_val(v: Any) -> Any:
    if isinstance(v, (list, tuple, set)):
        return "|".join(str(x) for x in v)
    if isinstance(v, bool):
        return int(v)
    return v


# ==================== 图表 ====================

def _lookup(arm_rows: List[Dict[str, Any]], sweep: str, arm: str,
            metric: str) -> Optional[Dict[str, Any]]:
    for r in arm_rows:
        if r["sweep"] == sweep and r["arm"] == arm and r["metric"] == metric:
            return r
    return None


def _cmp_lookup(cmp_rows: List[Dict[str, Any]], sweep: str, atk: str, base: str,
                metric: str) -> Optional[Dict[str, Any]]:
    for r in cmp_rows:
        if (r["sweep"] == sweep and r["attack"] == atk and r["baseline"] == base
                and r["metric"] == metric):
            return r
    return None


def _rb(r: Optional[Dict[str, Any]]) -> Optional[float]:
    """图表/报告用效应量：**优先带符号的** rank_biserial_signed。

    stats.py 在 scipy>=1.7 下返回的 ``rank_biserial`` 符号失效（详见
    ``_signed_rank_biserial`` 文档），故不得用于方向判读。非 Wilcoxon 路径
    （Mann-Whitney）本身符号正确，且无 signed 字段 → 回退到原值。
    """
    if not r:
        return None
    v = r.get("rank_biserial_signed")
    return float(v) if v is not None else (r.get("rank_biserial"))


def make_figures(arm_rows: List[Dict[str, Any]], cmp_rows: List[Dict[str, Any]],
                 fig_dir: Path) -> List[str]:
    """产出 step3 全部图表（PNG + 同源 CSV）。返回已写出的 PNG 路径列表。"""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    fig_dir.mkdir(parents=True, exist_ok=True)
    made: List[str] = []

    def _savefig(fig, name: str) -> None:
        p = fig_dir / f"{name}.png"
        fig.tight_layout()
        fig.savefig(p, dpi=150)
        plt.close(fig)
        made.append(str(p))

    # ---------- Fig 1: E4 Sybil 身份数梯度 ----------
    ids = [1, 2, 4, 8, 16, 32]
    rows1: List[Dict[str, Any]] = []
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for ax, metric, ylab in (
            (axes[0], "sybil_attraction_ratio", "Sybil attraction ratio"),
            (axes[1], "delivery_ratio", "Delivery ratio")):
        means, los, his = [], [], []
        for n in ids:
            r = _lookup(arm_rows, "e4_sybil", f"ids{n}", metric)
            b = _lookup(arm_rows, "e4_sybil", "base", metric) if metric == "delivery_ratio" else None
            if r is None:
                means.append(np.nan); los.append(0); his.append(0)
                continue
            means.append(r["mean"])
            los.append((r["mean"] - r["ci95_low"]) if r["ci95_low"] is not None else 0)
            his.append((r["ci95_high"] - r["mean"]) if r["ci95_high"] is not None else 0)
            rows1.append({"num_identities": n, "metric": metric, "mean": r["mean"],
                          "ci95_low": r["ci95_low"], "ci95_high": r["ci95_high"],
                          "n_seeds": r["n_seeds"],
                          "baseline_mean": (b or {}).get("mean")})
        xs = np.arange(len(ids))
        ax.errorbar(xs, means, yerr=[los, his], marker="o", capsize=3, label="attack")
        if metric == "delivery_ratio":
            b = _lookup(arm_rows, "e4_sybil", "base", metric)
            if b is not None:
                ax.axhline(b["mean"], ls="--", c="gray", label="no-attack baseline")
                ax.legend(fontsize=8)
        ax.set_xticks(xs); ax.set_xticklabels([str(n) for n in ids])
        ax.set_xlabel("num_identities"); ax.set_ylabel(ylab)
        ax.set_title(f"E4 Sybil gradient - {metric} (nl=1024, 53deg, 10 seeds)")
        ax.grid(alpha=.3)
    _savefig(fig, "step3_fig1_e4_sybil_gradient")
    _write_csv(fig_dir / "step3_fig1_e4_sybil_gradient.csv", rows1,
               ["num_identities", "metric", "mean", "ci95_low", "ci95_high",
                "n_seeds", "baseline_mean"])

    # ---------- Fig 2: E5 放置策略排序 ----------
    strat = [("degree", "degree"), ("rnd", "random"), ("btw", "betweenness"),
             ("kcore", "k_core"), ("led", "last_epoch_degree")]
    rows2: List[Dict[str, Any]] = []
    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    labels, rb, md, sig = [], [], [], []
    for lbl, name in strat:
        r = _cmp_lookup(cmp_rows, "e5_placement", lbl, "base", "delivery_ratio")
        a = _lookup(arm_rows, "e5_placement", lbl, "delivery_ratio")
        if r is None or a is None:
            continue
        labels.append(name); rb.append(_rb(r) or 0.0)
        md.append(r["median_diff"] or 0.0); sig.append(bool(r["significant"]))
        rows2.append({"placement": name, "arm": lbl,
                      "delivery_mean": a["mean"], "delivery_ci95_low": a["ci95_low"],
                      "delivery_ci95_high": a["ci95_high"],
                      "median_diff": r["median_diff"], "p_value": r["p_value"],
                      "rank_biserial": _rb(r),
                      "rank_biserial_upstream": r["rank_biserial"],
                      "test": r["test"],
                      "significant": r["significant"], "n_pairs": r["n_pairs"]})
    order = sorted(range(len(labels)), key=lambda i: md[i])
    labels = [labels[i] for i in order]; md = [md[i] for i in order]
    rb = [rb[i] for i in order]; sig = [sig[i] for i in order]
    ax.barh(labels, md, color=["#c0392b" if s else "#7f8c8d" for s in sig])
    for i, (v, r_) in enumerate(zip(md, rb)):
        ax.text(v, i, f"  d={v:+.3f}  r_rb={r_:+.2f}", va="center", fontsize=8)
    ax.axvline(0, c="k", lw=.8)
    ax.set_xlabel("median diff of delivery_ratio (attack - baseline)")
    ax.set_title("E5 attacker placement ranking (blackhole x3, drop_prob=0.8, nl=1024)")
    ax.grid(alpha=.3, axis="x")
    _savefig(fig, "step3_fig2_e5_placement_ranking")
    _write_csv(fig_dir / "step3_fig2_e5_placement_ranking.csv", rows2,
               ["placement", "arm", "delivery_mean", "delivery_ci95_low",
                "delivery_ci95_high", "median_diff", "p_value", "rank_biserial",
                "rank_biserial_upstream", "test", "significant", "n_pairs"])

    # ---------- Fig 3: E5 强度梯度（数量 × 丢包率）----------
    rows3: List[Dict[str, Any]] = []
    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.2))
    for ax, series, xlab, title in (
            (axes[0], [(f"c{n}", n) for n in (1, 3, 6, 12, 24)],
             "num attackers (drop_prob=0.8)", "E5 intensity - attacker count"),
            (axes[1], [(f"p{p:02d}", p / 100.0) for p in (0, 20, 50, 100)],
             "drop_prob (3 attackers)", "E5 intensity - drop probability")):
        xs, means, los, his = [], [], [], []
        for lbl, xv in series:
            r = _lookup(arm_rows, "e5_intensity", lbl, "delivery_ratio")
            if r is None:
                continue
            xs.append(xv); means.append(r["mean"])
            los.append((r["mean"] - r["ci95_low"]) if r["ci95_low"] is not None else 0)
            his.append((r["ci95_high"] - r["mean"]) if r["ci95_high"] is not None else 0)
            c = _cmp_lookup(cmp_rows, "e5_intensity", lbl, "base", "delivery_ratio")
            rows3.append({"gradient": xlab, "arm": lbl, "x": xv,
                          "delivery_mean": r["mean"], "ci95_low": r["ci95_low"],
                          "ci95_high": r["ci95_high"],
                          "median_diff": (c or {}).get("median_diff"),
                          "p_value": (c or {}).get("p_value"),
                          "rank_biserial": _rb(c)})
        b = _lookup(arm_rows, "e5_intensity", "base", "delivery_ratio")
        ax.errorbar(xs, means, yerr=[los, his], marker="o", capsize=3, label="attack")
        if b is not None:
            ax.axhline(b["mean"], ls="--", c="gray", label="baseline")
        ax.set_xlabel(xlab); ax.set_ylabel("delivery_ratio")
        ax.set_title(title + " (nl=1024, 10 seeds)"); ax.legend(fontsize=8); ax.grid(alpha=.3)
    _savefig(fig, "step3_fig3_e5_intensity")
    _write_csv(fig_dir / "step3_fig3_e5_intensity.csv", rows3,
               ["gradient", "arm", "x", "delivery_mean", "ci95_low", "ci95_high",
                "median_diff", "p_value", "rank_biserial"])

    # ---------- Fig 4: E6 Wormhole（攻击效果 + 检测器不可分离）----------
    e6_arms = [("base_det", "baseline(det on)"), ("t1", "1 tunnel/peer_only"),
               ("t3", "3 tunnels/peer_only"), ("extreme", "3 tunnels/peer_side")]
    e6_metrics = ["wormhole_attracted_ratio", "wormhole_detection_rate",
                  "wormhole_false_positive_rate", "wormhole_path_stretch",
                  "delivery_ratio"]
    rows4: List[Dict[str, Any]] = []
    present = [m for m in e6_metrics
               if any(_lookup(arm_rows, "e6_wormhole", a, m) for a, _ in e6_arms)]
    fig, axes = plt.subplots(1, len(present), figsize=(3.3 * len(present), 4.0))
    if len(present) == 1:
        axes = [axes]
    for ax, metric in zip(axes, present):
        vals, los, his, names = [], [], [], []
        for a, disp in e6_arms:
            r = _lookup(arm_rows, "e6_wormhole", a, metric)
            if r is None:
                continue
            names.append(disp); vals.append(r["mean"])
            los.append((r["mean"] - r["ci95_low"]) if r["ci95_low"] is not None else 0)
            his.append((r["ci95_high"] - r["mean"]) if r["ci95_high"] is not None else 0)
            rows4.append({"arm": a, "arm_display": disp, "metric": metric,
                          "mean": r["mean"], "ci95_low": r["ci95_low"],
                          "ci95_high": r["ci95_high"], "n_seeds": r["n_seeds"]})
        ax.bar(range(len(vals)), vals, yerr=[los, his], capsize=3,
               color=["#7f8c8d", "#2980b9", "#8e44ad", "#c0392b"][:len(vals)])
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels(names, rotation=25, ha="right", fontsize=7)
        ax.set_title(metric, fontsize=9); ax.grid(alpha=.3, axis="y")
    fig.suptitle("E6 Wormhole (nl=1024): attack effect is the primary signal; "
                 "distance detector INCONCLUSIVE on shipped data", fontsize=9)
    _savefig(fig, "step3_fig4_e6_wormhole")
    _write_csv(fig_dir / "step3_fig4_e6_wormhole.csv", rows4,
               ["arm", "arm_display", "metric", "mean", "ci95_low", "ci95_high", "n_seeds"])

    # ---------- Fig 5: E7 组合攻击超加性 ----------
    singles = {"bh3": "blackhole x3", "jm3": "jamming x3", "sy8": "sybil x8ids"}
    combos = [("bh3_jm3", ["bh3", "jm3"]), ("bh3_sy8", ["bh3", "sy8"]),
              ("jm3_sy8", ["jm3", "sy8"]), ("bh3_jm3_sy8", ["bh3", "jm3", "sy8"])]
    rows5: List[Dict[str, Any]] = []

    def _delta(arm: str, metric: str) -> Optional[float]:
        a = _lookup(arm_rows, "e7_combo", arm, metric)
        b = _lookup(arm_rows, "e7_combo", "base", metric)
        if a is None or b is None or a["mean"] is None or b["mean"] is None:
            return None
        return float(a["mean"]) - float(b["mean"])

    for metric in ("delivery_ratio", "avg_hops", "total_loops"):
        for arm, disp in list(singles.items()):
            d = _delta(arm, metric)
            rows5.append({"kind": "single", "arm": arm, "display": disp, "metric": metric,
                          "delta_observed": d, "delta_additive_prediction": d,
                          "synergy": 0.0 if d is not None else None})
        for arm, parts in combos:
            d = _delta(arm, metric)
            parts_d = [_delta(p, metric) for p in parts]
            pred = (sum(x for x in parts_d if x is not None)
                    if all(x is not None for x in parts_d) else None)
            syn = (d - pred) if (d is not None and pred is not None) else None
            rows5.append({"kind": "combo", "arm": arm, "display": "+".join(parts),
                          "metric": metric, "delta_observed": d,
                          "delta_additive_prediction": pred, "synergy": syn})
    dr = [r for r in rows5 if r["metric"] == "delivery_ratio"]
    fig, ax = plt.subplots(figsize=(9.5, 4.4))
    xs = range(len(dr))
    obs = [r["delta_observed"] if r["delta_observed"] is not None else np.nan for r in dr]
    pred = [r["delta_additive_prediction"] if r["delta_additive_prediction"] is not None
            else np.nan for r in dr]
    ax.bar([x - 0.2 for x in xs], obs, width=0.4, label="observed delta", color="#c0392b")
    ax.bar([x + 0.2 for x in xs], pred, width=0.4, label="additive prediction",
           color="#95a5a6")
    ax.set_xticks(list(xs))
    ax.set_xticklabels([r["display"] for r in dr], rotation=25, ha="right", fontsize=7)
    ax.axhline(0, c="k", lw=.8)
    ax.set_ylabel("delta mean delivery_ratio (arm - baseline)")
    ax.set_title("E7 combined attacks: super-additivity check (nl=1024, 10 seeds)")
    ax.legend(fontsize=8); ax.grid(alpha=.3, axis="y")
    _savefig(fig, "step3_fig5_e7_combo_synergy")
    _write_csv(fig_dir / "step3_fig5_e7_combo_synergy.csv", rows5,
               ["kind", "arm", "display", "metric", "delta_observed",
                "delta_additive_prediction", "synergy"])

    # ---------- Fig 6: 跨壳对比（nl=256 与 nl=1024）----------
    rows6: List[Dict[str, Any]] = []
    for sweep, nl in (("shell256", 256), ("shell1024", 1024)):
        for t, shell in (("53", "53deg"), ("70", "70deg"),
                         ("975", "97.5deg"), ("43", "43deg")):
            for metric in ("delivery_ratio", "avg_hops", "total_loops"):
                c = _cmp_lookup(cmp_rows, sweep, f"bh3_{t}", f"base_{t}", metric)
                a = _lookup(arm_rows, sweep, f"bh3_{t}", metric)
                b = _lookup(arm_rows, sweep, f"base_{t}", metric)
                if c is None:
                    continue
                rows6.append({"node_limit": nl, "shell": shell, "metric": metric,
                              "attack_mean": (a or {}).get("mean"),
                              "baseline_mean": (b or {}).get("mean"),
                              "median_diff": c["median_diff"], "p_value": c["p_value"],
                              "rank_biserial": _rb(c),
                              "significant": c["significant"], "test": c["test"],
                              "n_pairs": c["n_pairs"]})
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.0))
    for ax, metric in zip(axes, ("delivery_ratio", "avg_hops", "total_loops")):
        sub = [r for r in rows6 if r["metric"] == metric]
        shells = sorted({r["shell"] for r in sub})
        width = 0.38
        for i, nl in enumerate((256, 1024)):
            vals = [next((r["median_diff"] for r in sub
                          if r["shell"] == s and r["node_limit"] == nl), np.nan)
                    for s in shells]
            ax.bar(np.arange(len(shells)) + (i - 0.5) * width, vals, width,
                   label=f"nl={nl}")
        ax.set_xticks(range(len(shells))); ax.set_xticklabels(shells, fontsize=8)
        ax.axhline(0, c="k", lw=.8)
        ax.set_ylabel(f"median diff {metric}")
        ax.set_title(f"cross-shell: {metric}", fontsize=9)
        ax.legend(fontsize=8); ax.grid(alpha=.3, axis="y")
    fig.suptitle("Cross-shell attack effect (blackhole x3, degree, drop_prob=0.8); "
                 "70deg/97.5deg @nl=1024 are DEGRADED tiers", fontsize=9)
    _savefig(fig, "step3_fig6_shell_compare")
    _write_csv(fig_dir / "step3_fig6_shell_compare.csv", rows6,
               ["node_limit", "shell", "metric", "attack_mean", "baseline_mean",
                "median_diff", "p_value", "rank_biserial", "significant", "test",
                "n_pairs"])

    # ---------- Fig 7: E5-a 规模律 ----------
    rows7: List[Dict[str, Any]] = []
    for nl in _E5A_SMALL_NL:
        c = _cmp_lookup(cmp_rows, "e5a_scale_small", f"bh3_n{nl}", f"base_n{nl}",
                        "delivery_ratio")
        a = _lookup(arm_rows, "e5a_scale_small", f"bh3_n{nl}", "delivery_ratio")
        b = _lookup(arm_rows, "e5a_scale_small", f"base_n{nl}", "delivery_ratio")
        if c is None:
            continue
        rows7.append({"node_limit": nl, "attack_mean": (a or {}).get("mean"),
                      "baseline_mean": (b or {}).get("mean"),
                      "median_diff": c["median_diff"], "p_value": c["p_value"],
                      "rank_biserial": _rb(c),
                      "significant": c["significant"], "n_pairs": c["n_pairs"]})
    c = _cmp_lookup(cmp_rows, "e5a_scale_top", "bh3_n2048", "base_n2048", "delivery_ratio")
    if c is not None:
        rows7.append({"node_limit": 2048,
                      "attack_mean": (_lookup(arm_rows, "e5a_scale_top", "bh3_n2048",
                                              "delivery_ratio") or {}).get("mean"),
                      "baseline_mean": (_lookup(arm_rows, "e5a_scale_top", "base_n2048",
                                                "delivery_ratio") or {}).get("mean"),
                      "median_diff": c["median_diff"], "p_value": c["p_value"],
                      "rank_biserial": _rb(c),
                      "significant": c["significant"], "n_pairs": c["n_pairs"]})
    rows7.sort(key=lambda r: r["node_limit"])
    if rows7:
        fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
        xs = [r["node_limit"] for r in rows7]
        axes[0].plot(xs, [r["median_diff"] for r in rows7], marker="o")
        axes[0].set_xscale("log", base=2)
        axes[0].set_xticks(xs); axes[0].set_xticklabels([str(x) for x in xs], fontsize=8)
        axes[0].axhline(0, c="k", lw=.8)
        axes[0].set_xlabel("node_limit (log2)"); axes[0].set_ylabel("median diff delivery_ratio")
        axes[0].set_title("E5-a scale law: effect on delivery_ratio (top tier 2048; "
                          "4284 infeasible in RAM)", fontsize=8)
        axes[0].grid(alpha=.3)
        axes[1].plot(xs, [(r["rank_biserial"] if r["rank_biserial"] is not None
                           else np.nan) for r in rows7], marker="s", color="#8e44ad")
        axes[1].set_xscale("log", base=2)
        axes[1].set_xticks(xs); axes[1].set_xticklabels([str(x) for x in xs], fontsize=8)
        axes[1].axhline(0, c="k", lw=.8)
        axes[1].set_xlabel("node_limit (log2)")
        axes[1].set_ylabel("signed rank-biserial r (>0 = attack larger)")
        axes[1].set_title("E5-a scale law: effect size"); axes[1].grid(alpha=.3)
        _savefig(fig, "step3_fig7_e5a_scale_law")
    _write_csv(fig_dir / "step3_fig7_e5a_scale_law.csv", rows7,
               ["node_limit", "attack_mean", "baseline_mean", "median_diff",
                "p_value", "rank_biserial", "significant", "n_pairs"])

    return made


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="step3 攻击矩阵统一聚合 + 图表")
    ap.add_argument("--raw-root", default=str(RAW_ROOT))
    ap.add_argument("--out-dir", default=str(OUT_DIR))
    ap.add_argument("--figures-dir", default=str(FIG_DIR))
    ap.add_argument("--n-boot", type=int, default=N_BOOT)
    ap.add_argument("--alpha", type=float, default=ALPHA)
    ap.add_argument("--only", nargs="*", default=None, help="仅聚合指定 sweep")
    ap.add_argument("--no-figures", action="store_true")
    args = ap.parse_args(argv)

    res = run(Path(args.raw_root), Path(args.out_dir), only=args.only,
              n_boot=args.n_boot, alpha=args.alpha)
    if not args.no_figures:
        made = make_figures(res["arm_rows"], res["cmp_rows"], Path(args.figures_dir))
        print(f"[aggregate_step3] 图表 {len(made)} 张 → {args.figures_dir}")
        for m in made:
            print(f"    {m}")
    fails = res["failures"]
    if fails:
        print(f"[aggregate_step3] !! 失败/跳过 {len(fails)} 项（详见 step3_failures.csv）")
        for f in fails[:20]:
            print(f"    - {f['sweep']} / {f['arm']} [{f['stage']}]: {f['error'][:160]}")
    gaps = [r for r in res["summary"]["completeness"] if not r["complete"]]
    if gaps:
        print(f"[aggregate_step3] !! 臂不完整 {len(gaps)} 个：")
        for g in gaps[:20]:
            print(f"    - {g['sweep']}/{g['arm']}: {g['n_found']}/{g['n_expected']} "
                  f"seeds, missing={g['seeds_missing']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
