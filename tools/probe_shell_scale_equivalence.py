# -*- coding: utf-8 -*-
"""
tools/probe_shell_scale_equivalence.py
Task #12 (E5-a) **只读**探测器：跨壳 × 规模阶梯的连通性等价性实测。

为什么需要它
------------
``sweep_shell256`` / ``sweep_shell1024`` 的头注里引用的四壳连通比数字来自生成器落盘前的
一次性探测，没有留档、不可复核；而跨壳对比的**全部合法性**都建立在「同一 node_limit 下
四壳规模等价且逐 epoch 全连通」这一前提上。本脚本用 shipped 的
``starlink_sim.topology.subset`` **生产路径**（不重写任何逻辑）重新实测并落盘 JSON 证据，
使 ``docs/STEP3_SHELL_SCALE_RUNBOOK.md`` 与两个 shell sweep 的头注可以引用可复核的数字。

一个必须同时度量的口径细节
--------------------------
``run_e3_blackhole_experiment.run_experiment`` 在 ``duration=60 / epoch_interval=30`` 下
``last_epoch_idx = 60//30 - 1 = 1``，控制面 ``run_ticks(300)`` 与数据面
``eval_edges = edges_by_epoch[0:2]`` **只触达 pkl 的前 2 个 epoch**（121 个中的 2 个）。
但 ``select_connected_subset`` 的持久性判据用的是**全部 121 epoch**。因此本脚本对每个
(壳, nl) 同时给出两套连通比：

- ``all``：全 121 epoch 的 min/mean —— 子集选择器的**设计保证**口径（更严格）；
- ``evalwin``：仅 epoch[0:2] 的 min/mean —— e3 runner **实际评估窗口**口径（真正影响 DR）。

二者不一致时（例如 97.5° nl=1024）必须如实标注「全 epoch 碎裂但评估窗口尚可」或反之，
不得只用其中一套下结论。

内存纪律（硬约束：本进程峰值 ≤ 4GB，且加载前 FreeRAM ≥ 8GB）
------------------------------------------------------------
一次只在内存里保留**一个壳**的 ``edges_per_epoch``：先整体反序列化 pkl，逐壳取出边集后
立即 ``del`` 该壳（连带释放体积更大的 ``positions_per_epoch``）并 ``gc.collect()``，处理完
再取下一个。绝不构造任何路由表 / 不跑仿真 —— 本脚本是纯拓扑分析。

用法::

    python tools/probe_shell_scale_equivalence.py                 # 全四壳 × 全阶梯
    python tools/probe_shell_scale_equivalence.py --shells 53°    # 只测一个壳
    python tools/probe_shell_scale_equivalence.py --out path.json
"""
from __future__ import annotations

import argparse
import gc
import json
import pickle
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from starlink_sim.topology.subset import (   # noqa: E402  生产路径，不重写
    all_nodes,
    edge_persistence,
    evaluate_subset_connectivity,
    persistent_core,
    select_connected_subset,
)

PKL = PROJECT_ROOT / "data" / "topology" / "topology_results.pkl"
SUMMARY = PROJECT_ROOT / "data" / "topology" / "topology_summary.json"
DEFAULT_OUT = PROJECT_ROOT / "results" / "step3_logs" / "shell_scale_equivalence.json"

# 与 configs/experiments/step3/*.yaml 完全一致的壳顺序（SHELLS）与子集方法
SHELLS: Sequence[str] = ("53°", "70°", "97.5°", "43°")
SUBSET_METHOD = "cumulative_degree"

# e3 runner 在 duration=60 / epoch_interval=30 下真正触达的 epoch 窗口 [0, 1]
EVAL_EPOCHS = 2

# 规模阶梯：E5-a 六档（48..2048，无 4284）∪ 跨壳三档（256/512/1024）
LADDER: Sequence[int] = (48, 96, 256, 512, 1024, 2048)

FREE_RAM_FLOOR_GB = 8.0     # 加载 pkl 前的最低空闲物理内存
SELF_PEAK_CEIL_GB = 4.0     # 本进程峰值 RSS 上限（门禁关闭期间的自我约束）

# PowerShell 传参时非 ASCII 的 "°" 容易被代码页吃掉，故 --shells 同时接受 ASCII 简写
SHELL_ALIAS = {"53": "53°", "70": "70°", "975": "97.5°", "97.5": "97.5°", "43": "43°"}


def _norm_shell(s: str) -> str:
    s = s.strip()
    return SHELL_ALIAS.get(s, s)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def free_ram_gb() -> float:
    """当前空闲物理内存（GB）。Windows 用 CIM，其他平台退回 psutil。"""
    try:
        import psutil
        return psutil.virtual_memory().available / 1024 ** 3
    except Exception:
        return float("nan")


def peak_rss_gb() -> float:
    """本进程内存占用（GB）。Windows 下 ``peak_wset`` 是**真峰值**工作集，
    而 ``rss`` 在 ``del`` + ``gc.collect()`` 后会回落，故取两者最大值，
    避免把「已经释放」误报成「从未占用」而违反 ≤4GB 自我约束。"""
    try:
        import psutil
        mi = psutil.Process().memory_info()
        return max(mi.rss, getattr(mi, "peak_wset", 0) or 0) / 1024 ** 3
    except Exception:
        return float("nan")


def _ratios(edges_per_epoch: List[Any], subset: Sequence[int],
            window: Optional[slice] = None) -> Dict[str, Any]:
    """子集在给定 epoch 窗口内的最大连通分量占比统计。"""
    eps = edges_per_epoch if window is None else edges_per_epoch[window]
    ev = evaluate_subset_connectivity(eps, subset)
    return {
        "num_epochs": ev["num_epochs"],
        "min_ratio": round(ev["min_ratio"], 6),
        "mean_ratio": round(ev["mean_ratio"], 6),
        "fully_connected": bool(ev["min_ratio"] >= 1.0 - 1e-12),
    }


def _induced_density(edges_per_epoch: List[Any], subset: Sequence[int],
                     window: Optional[slice] = None) -> Dict[str, Any]:
    """诱导子图在给定 epoch 窗口内的边数 / 平均度（规模律的机理变量）。

    平均度是解释「为何效应量随规模变化」的关键协变量：同一攻击配置
    （blackhole×3, degree 布点）在不同 nl 下剔除的**拓扑份额**不同，
    而平均度决定了黑洞节点能截断多少条替代路径。
    """
    eps = edges_per_epoch if window is None else edges_per_epoch[window]
    sset = set(subset)
    n = max(1, len(sset))
    counts = [sum(1 for u, v in e if u in sset and v in sset) for e in eps]
    mean_edges = (sum(counts) / len(counts)) if counts else 0.0
    return {
        "num_epochs": len(counts),
        "min_edges": min(counts) if counts else 0,
        "mean_edges": round(mean_edges, 2),
        "mean_avg_degree": round(2.0 * mean_edges / n, 4),
    }


def probe_nesting(subsets: Dict[int, List[int]]) -> Dict[str, Any]:
    """阶梯**嵌套性**度量：相邻/全部档位之间的包含率与 Jaccard。

    为什么必须测：``select_connected_subset`` 在 ``target_size`` 超过严格持久核 GCC 时
    会沿 ``_FRAC_LADDER`` **放宽阈值**并在新的（更大的）核内重新从最高累计度种子
    连通生长 —— 因此 nl=2048 的子集**不必包含** nl=1024 的子集。若不嵌套，
    「规模律」就不是「同一拓扑逐渐变大」而是「换了一批节点」，跨档比较只能
    当作独立观测点而不能当作单调曲线读。
    """
    nls = sorted(subsets)
    sets = {nl: set(subsets[nl]) for nl in nls}
    pairs: List[Dict[str, Any]] = []
    for i, a in enumerate(nls):
        for b in nls[i + 1:]:
            inter = len(sets[a] & sets[b])
            union = len(sets[a] | sets[b])
            pairs.append({
                "smaller_nl": a, "larger_nl": b,
                "intersect": inter,
                "containment_of_smaller": round(inter / max(1, len(sets[a])), 6),
                "jaccard": round(inter / max(1, union), 6),
                "nested": inter == len(sets[a]),
            })
    chain: List[Dict[str, Any]] = []
    for i in range(len(nls) - 1):
        a, b = nls[i], nls[i + 1]
        chain.append(next(p for p in pairs
                          if p["smaller_nl"] == a and p["larger_nl"] == b))
    return {
        "pairs": pairs,
        "adjacent_chain_all_nested": all(p["nested"] for p in chain) if chain else None,
        "all_pairs_nested": all(p["nested"] for p in pairs) if pairs else None,
    }


def probe_shell(shell: str, shell_data: Dict[str, Any], ladder: Sequence[int],
                summary: Dict[str, Any], method: str = SUBSET_METHOD) -> Dict[str, Any]:
    """实测单壳的持久核与规模阶梯连通性（**不修改**传入数据）。"""
    t0 = time.time()
    edges_per_epoch = shell_data["edges_per_epoch"]
    n_epochs = len(edges_per_epoch)
    nodes = all_nodes(edges_per_epoch)
    persist = edge_persistence(edges_per_epoch)

    # 最严格阈值（frac=1.0，边存在于**全部** epoch）的稳定核 —— 这是
    # 「nl <= GCC(strict) ⇒ 逐 epoch 连通比恒为 1.000」的判据来源。
    core_strict, core_adj_strict, frac_strict = persistent_core(edges_per_epoch, None)

    rec: Dict[str, Any] = {
        "shell": shell,
        "num_satellites_summary": (summary.get(shell) or {}).get("num_satellites"),
        "num_nodes_in_edges": len(nodes),
        "num_epochs": n_epochs,
        "num_unique_edges_all_time": len(persist),
        "avg_degree_summary": (summary.get(shell) or {}).get("avg_degree"),
        "edge_overlap_300s_summary": (summary.get(shell) or {}).get("edge_overlap_300s"),
        "strict_persistent_core": {
            "frac": frac_strict,
            "gcc_size": len(core_strict),
            "num_persistent_edges": sum(1 for nbs in core_adj_strict.values() for _ in nbs) // 2,
            "core_coverage_of_shell": round(len(core_strict) / max(1, len(nodes)), 6),
        },
        "eval_window_epochs": EVAL_EPOCHS,
        "subset_method": method,
        "ladder": [],
    }

    del persist
    gc.collect()

    subsets: Dict[int, List[int]] = {}

    for nl in ladder:
        t1 = time.time()
        subset = select_connected_subset(edges_per_epoch, nl, method=method)
        # 生产路径实际用到的持久核（target_size=nl 会沿 _FRAC_LADDER 放宽）
        core_nl, _adj_nl, frac_nl = persistent_core(edges_per_epoch, nl)
        inside = len(set(subset) & core_strict)
        row = {
            "node_limit": nl,
            "subset_size": len(subset),
            "subset_size_equals_node_limit": len(subset) == nl,
            "degenerate_full_shell": len(subset) >= len(nodes),
            "core_frac_used": frac_nl,
            "core_gcc_at_that_frac": len(core_nl),
            "inside_strict_core": inside,
            "inside_strict_core_ratio": round(inside / max(1, len(subset)), 6),
            "conn_all_epochs": _ratios(edges_per_epoch, subset),
            "conn_eval_window": _ratios(edges_per_epoch, subset, slice(0, EVAL_EPOCHS)),
            "density_all_epochs": _induced_density(edges_per_epoch, subset),
            "density_eval_window": _induced_density(edges_per_epoch, subset,
                                                     slice(0, EVAL_EPOCHS)),
            "probe_seconds": round(time.time() - t1, 2),
        }
        rec["ladder"].append(row)
        subsets[nl] = subset            # 仅存 int 列表（极小），用于嵌套性度量
        del core_nl, _adj_nl
        gc.collect()

    rec["nesting"] = probe_nesting(subsets)
    del subsets
    gc.collect()

    rec["probe_seconds_total"] = round(time.time() - t0, 2)
    rec["peak_rss_gb_after_shell"] = round(peak_rss_gb(), 3)
    return rec


def max_common_fully_connected_nl(shells: List[Dict[str, Any]],
                                  ladder: Sequence[int],
                                  key: str) -> Dict[str, Any]:
    """在给定连通口径（``conn_all_epochs`` / ``conn_eval_window``）下，
    找出**所有壳**都满足 ``subset_size == nl`` 且 min_ratio == 1.000 的最大 nl。"""
    ok: List[int] = []
    for nl in ladder:
        good = True
        for s in shells:
            row = next((r for r in s["ladder"] if r["node_limit"] == nl), None)
            if row is None or not row["subset_size_equals_node_limit"]:
                good = False       # 该壳总节点不足 nl → 退化为全量，规模不等价
                break
            if not row[key]["fully_connected"]:
                good = False
                break
        if good:
            ok.append(nl)
    return {
        "criterion": key,
        "fully_connected_nls": ok,
        "max_common_nl": max(ok) if ok else None,
        "max_common_power_of_two": max((n for n in ok if n & (n - 1) == 0), default=None),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="跨壳 × 规模阶梯连通性等价性只读探测")
    ap.add_argument("--shells", nargs="*", default=None, help="仅探测指定壳（默认四壳全测）")
    ap.add_argument("--ladder", nargs="*", type=int, default=None, help="规模档位（默认 48..2048）")
    ap.add_argument("--pkl", default=str(PKL))
    ap.add_argument("--method", default=SUBSET_METHOD, choices=("cumulative_degree", "stable_core"),
                    help="子集选择方法（默认与全部 sweep 一致的 cumulative_degree；"
                         "stable_core 仅用于对照实验，不得写回生产配置）")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--skip-ram-guard", action="store_true", help="跳过 FreeRAM 前置检查")
    args = ap.parse_args(argv)

    ladder = tuple(args.ladder) if args.ladder else LADDER
    want = [_norm_shell(s) for s in args.shells] if args.shells else list(SHELLS)

    fr = free_ram_gb()
    print(f"[probe] FreeRAM={fr:.2f} GB（下限 {FREE_RAM_FLOOR_GB} GB），"
          f"本进程 RSS={peak_rss_gb():.3f} GB（上限 {SELF_PEAK_CEIL_GB} GB）")
    if not args.skip_ram_guard and not (fr >= FREE_RAM_FLOOR_GB):
        print(f"[probe] !! FreeRAM 不足 {FREE_RAM_FLOOR_GB} GB，拒绝加载 pkl（避免与并行 sweep 抢内存）")
        return 3

    summary: Dict[str, Any] = {}
    if SUMMARY.exists():
        summary = json.loads(SUMMARY.read_text(encoding="utf-8"))

    t_load = time.time()
    with open(args.pkl, "rb") as f:
        topo = pickle.load(f)
    available = list(topo.keys())
    print(f"[probe] pkl 反序列化完成 {time.time() - t_load:.1f}s，"
          f"含壳 {available}，RSS={peak_rss_gb():.3f} GB")

    missing = [s for s in want if s not in topo]
    if missing:
        print(f"[probe] !! pkl 中缺失壳：{missing}（可用：{available}）")

    out: Dict[str, Any] = {
        "generated_utc": _utc(),
        "tool": "tools/probe_shell_scale_equivalence.py",
        "pkl": str(args.pkl),
        "pkl_bytes": Path(args.pkl).stat().st_size,
        "subset_method": args.method,
        "shells_in_pkl": available,
        "shells_probed": [s for s in want if s in topo],
        "shells_missing": missing,
        "ladder": list(ladder),
        "eval_window_epochs": EVAL_EPOCHS,
        "free_ram_gb_before_load": round(fr, 2),
        "peak_rss_gb": round(peak_rss_gb(), 3),
        "shells": [],
    }

    # 内存纪律：一次只保留一个壳的边集，取完立即从 dict 里删除该壳（连带释放 positions）
    for shell in want:
        if shell not in topo:
            continue
        shell_data = topo.pop(shell)          # pop：取出并从缓存 dict 移除
        gc.collect()
        print(f"[probe] === {shell} === RSS={peak_rss_gb():.3f} GB, FreeRAM={free_ram_gb():.2f} GB")
        rec = probe_shell(shell, shell_data, ladder, summary, method=args.method)
        out["shells"].append(rec)
        sc = rec["strict_persistent_core"]
        print(f"[probe]   nodes_in_edges={rec['num_nodes_in_edges']} "
              f"(summary {rec['num_satellites_summary']}), epochs={rec['num_epochs']}, "
              f"strict core GCC={sc['gcc_size']} @frac={sc['frac']}")
        for row in rec["ladder"]:
            ca, cw = row["conn_all_epochs"], row["conn_eval_window"]
            dw = row["density_eval_window"]
            flag = "OK " if (row["subset_size_equals_node_limit"] and ca["fully_connected"]) else "DEG"
            print(f"[probe]   [{flag}] nl={row['node_limit']:<5} size={row['subset_size']:<5} "
                  f"core_frac={row['core_frac_used']:<5} inside_core={row['inside_strict_core_ratio']:.3f} "
                  f"| all121 min={ca['min_ratio']:.3f} mean={ca['mean_ratio']:.3f} "
                  f"| evalwin[0:2] min={cw['min_ratio']:.3f} mean={cw['mean_ratio']:.3f} "
                  f"| evalwin avgdeg={dw['mean_avg_degree']:.3f}")
        nest = rec["nesting"]
        if nest.get("pairs"):
            print(f"[probe]   嵌套性: 相邻链全嵌套={nest['adjacent_chain_all_nested']}, "
                  f"全对嵌套={nest['all_pairs_nested']}")
            for p in nest["pairs"]:
                if not p["nested"]:
                    print(f"[probe]     !! nl={p['smaller_nl']} ⊄ nl={p['larger_nl']}: "
                          f"交集 {p['intersect']}, 包含率 {p['containment_of_smaller']:.3f}, "
                          f"Jaccard {p['jaccard']:.3f}")
        del shell_data, rec
        gc.collect()

    del topo
    gc.collect()

    out["max_common_nl_all_epochs"] = max_common_fully_connected_nl(
        out["shells"], ladder, "conn_all_epochs")
    out["max_common_nl_eval_window"] = max_common_fully_connected_nl(
        out["shells"], ladder, "conn_eval_window")
    out["peak_rss_gb"] = round(peak_rss_gb(), 3)
    out["finished_utc"] = _utc()

    print("\n[probe] === 跨壳公共规模结论 ===")
    for k in ("max_common_nl_all_epochs", "max_common_nl_eval_window"):
        v = out[k]
        print(f"[probe] {k}: max_common_nl={v['max_common_nl']} "
              f"(2 的幂最大 {v['max_common_power_of_two']}), 满足档位={v['fully_connected_nls']}")
    print(f"[probe] 本进程峰值 RSS={out['peak_rss_gb']:.3f} GB "
          f"（上限 {SELF_PEAK_CEIL_GB} GB）→ {'合规' if out['peak_rss_gb'] <= SELF_PEAK_CEIL_GB else '超限'}")

    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[probe] 证据已落盘：{outp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
