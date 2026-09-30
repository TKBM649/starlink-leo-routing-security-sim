# -*- coding: utf-8 -*-
"""
scripts/run_step3_matrix.py
step3 / Phase 1 攻击矩阵（B 档）**总驱动器**：按序跑全部 sweep 并留档计时/退出码。

为什么需要它（而不是手敲 9 条命令）
----------------------------------
1. **顺序与隔离**：内存（不是 CPU）是硬约束 —— nl=1024 单 worker ~1.62GB（剔壳后）、
   四壳 sweep ~2.2GB/worker、nl=2048 顶档 ~4GB/worker。多个 sweep 同时跑会叠加
   Pool 常驻内存，故必须**串行**跑 sweep、并行只发生在 sweep 内部。
2. **可断点续跑**：逐 sweep 检查「应有的 raw JSON 是否已齐全」，齐全则跳过。
   单 sweep 内部 ``run_experiment_sweep`` 已改为**逐任务即时落盘**，因此中断只丢
   正在跑的那批任务，重跑该 sweep 即可（已完成的臂会被重写，结果确定性不变）。
3. **留档**：每 sweep 独立日志 + 汇总 JSON（起止时刻/墙钟/退出码/任务数），
   供报告核对「实测 vs 预估」，也让失败臂不会被静默丢弃。

用法::

    python scripts/run_step3_matrix.py                    # 全部 9 个 sweep
    python scripts/run_step3_matrix.py --only e4_sybil e6_wormhole
    python scripts/run_step3_matrix.py --skip-existing     # 跳过 raw 已齐全的 sweep
    python scripts/run_step3_matrix.py --list              # 只列出计划，不执行
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
SPEC_DIR = PROJECT_ROOT / "configs" / "experiments" / "step3"
RAW_ROOT = PROJECT_ROOT / "results" / "step3_raw"
LOG_DIR = PROJECT_ROOT / "results" / "step3_logs"
SWEEP_RUNNER = PROJECT_ROOT / "scripts" / "run_experiment_sweep.py"

# 执行顺序：先跑「信息密度最高 / 最快暴露配置问题」的，再跑重档与跨壳档。
# 顶档 nl=2048 放最后（单任务 ~4GB、workers=2，最慢且最吃内存）。
ORDER: List[str] = [
    "e6_wormhole",       # 4 臂 × 10 seeds = 40 任务（上轮已验证过口径）
    "e4_sybil",          # 7 × 10 = 70
    "e5_placement",      # 6 × 10 = 60
    "e5_intensity",      # 10 × 10 = 100
    "e7_combo",          # 8 × 10 = 80
    "e5a_scale_small",   # 10 × 10 = 100（48..1024，多数档远快于 58s）
    "shell256",          # 8 × 10 = 80（四壳，nl=256 快）
    "shell1024",         # 8 × 10 = 80（四壳，nl=1024；70°/97.5° 为降级档）
    "e5a_scale_top",     # 2 × 10 = 20（nl=2048，workers=2）
]

_LABEL_RE = re.compile(r"^\s*-\s*label:\s*(.+?)\s*$")


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_plan(only: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """读全部 sweep YAML，返回执行计划（含应有 raw 文件清单，用于续跑判定）。"""
    plan: List[Dict[str, Any]] = []
    for key in ORDER:
        if only and key not in set(only):
            continue
        path = SPEC_DIR / f"sweep_{key}.yaml"
        if not path.exists():
            print(f"[matrix] !! 缺少 sweep 配置：{path}")
            continue
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        sw = raw.get("sweep", raw)
        arms = [a["label"] for a in sw.get("arms", [])]
        seeds = [int(s) for s in sw.get("seeds", [])]
        plan.append({
            "key": key, "path": str(path), "arms": arms, "seeds": seeds,
            "n_tasks": len(arms) * len(seeds),
            "workers": int(sw.get("workers", 2)),
            "raw_dir": sw.get("raw_dir") or str(RAW_ROOT / key),
        })
    return plan


def expected_raw_files(item: Dict[str, Any]) -> List[Path]:
    """该 sweep **齐全**时应存在的 raw JSON 路径。

    文件名由 run_experiment_sweep._emit_raw 决定：``{label}__{exp_name}_seed{seed}.json``，
    其中 exp_name 取自臂配置的 experiment.name。这里用 glob 前缀匹配以避免重复解析
    臂 YAML（label 与 seed 是稳定部分，exp_name 不参与判定）。
    """
    raw_dir = Path(item["raw_dir"])
    if not raw_dir.is_absolute():
        raw_dir = PROJECT_ROOT / raw_dir
    out: List[Path] = []
    for lbl in item["arms"]:
        for sd in item["seeds"]:
            hits = sorted(raw_dir.glob(f"{lbl}__*_seed{sd}.json"))
            if hits:
                out.append(hits[0])
    return out


def is_complete(item: Dict[str, Any]) -> bool:
    return len(expected_raw_files(item)) >= item["n_tasks"]


def run_one(item: Dict[str, Any], log_dir: Path) -> Dict[str, Any]:
    """跑单个 sweep（子进程，实时把 stdout 落日志）。返回计时/退出码记录。"""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{item['key']}.log"
    cmd = [sys.executable, str(SWEEP_RUNNER), "--sweep-config", item["path"]]
    rec = {"key": item["key"], "cmd": " ".join(cmd), "n_tasks": item["n_tasks"],
           "workers": item["workers"], "start_utc": _utc()}
    t0 = time.time()
    with open(log_path, "w", encoding="utf-8") as lf:
        lf.write(f"# {_utc()} START {' '.join(cmd)}\n")
        lf.flush()
        proc = subprocess.Popen(cmd, cwd=str(PROJECT_ROOT), stdout=lf,
                                stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace")
        rc = proc.wait()
    wall = time.time() - t0
    rec.update({"end_utc": _utc(), "wall_s": round(wall, 1), "exit_code": rc,
                "log": str(log_path),
                "n_raw_found": len(expected_raw_files(item))})
    with open(log_path, "a", encoding="utf-8") as lf:
        lf.write(f"\n# {_utc()} END exit={rc} wall={wall:.1f}s\n")
    return rec


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="step3 攻击矩阵总驱动器")
    ap.add_argument("--only", nargs="*", default=None, help="仅跑指定 sweep key")
    ap.add_argument("--skip-existing", action="store_true",
                    help="raw 已齐全的 sweep 直接跳过（断点续跑）")
    ap.add_argument("--list", action="store_true", help="只列出计划，不执行")
    ap.add_argument("--log-dir", default=str(LOG_DIR))
    args = ap.parse_args(argv)

    plan = load_plan(args.only)
    if not plan:
        print("[matrix] 无 sweep 可跑")
        return 1

    total_tasks = sum(p["n_tasks"] for p in plan)
    print(f"[matrix] 计划 {len(plan)} 个 sweep / {total_tasks} 任务（串行 sweep、sweep 内并行）")
    for p in plan:
        done = is_complete(p)
        print(f"    {p['key']:<18} arms={len(p['arms']):<3} seeds={len(p['seeds']):<3} "
              f"tasks={p['n_tasks']:<4} workers={p['workers']:<3} complete={done}")
    if args.list:
        return 0

    todo = [p for p in plan if not (args.skip_existing and is_complete(p))]
    skipped = [p["key"] for p in plan if p not in todo]
    if skipped:
        print(f"[matrix] --skip-existing 跳过已齐全：{skipped}")

    log_dir = Path(args.log_dir)
    records: List[Dict[str, Any]] = []
    t_all = time.time()
    for i, item in enumerate(todo, 1):
        print(f"[matrix] ({i}/{len(todo)}) START {item['key']} "
              f"tasks={item['n_tasks']} workers={item['workers']} @{_utc()}")
        rec = run_one(item, log_dir)
        records.append(rec)
        print(f"[matrix] ({i}/{len(todo)}) END   {item['key']} exit={rec['exit_code']} "
              f"wall={rec['wall_s']}s raw_found={rec['n_raw_found']}/{item['n_tasks']}")
        # 逐 sweep 落盘汇总，中途被打断也保留已完成记录
        _write_summary(log_dir, records, skipped, time.time() - t_all, finished=False)

    _write_summary(log_dir, records, skipped, time.time() - t_all, finished=True)
    ok = [r for r in records if r["exit_code"] == 0]
    bad = [r for r in records if r["exit_code"] != 0]
    print(f"[matrix] 全部完成：成功 {len(ok)}/{len(records)}，失败 {len(bad)}，"
          f"总墙钟 {time.time() - t_all:.1f}s")
    for r in bad:
        print(f"    !! {r['key']} exit={r['exit_code']} log={r['log']}")
    return 0 if not bad else 2


def _write_summary(log_dir: Path, records: List[Dict[str, Any]],
                   skipped: List[str], wall_all: float, finished: bool) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / "_matrix_summary.json", "w", encoding="utf-8") as f:
        json.dump({"updated_utc": _utc(), "finished": finished,
                   "wall_all_s": round(wall_all, 1),
                   "skipped_complete": skipped, "runs": records},
                  f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    sys.exit(main())
