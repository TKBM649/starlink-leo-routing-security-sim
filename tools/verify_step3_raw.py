#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""step3 raw 完整性校验器（只读，不写任何文件）。

用途
----
sweep 跑完（或中断）后，逐文件核验 ``results/step3_raw/<sweep>/*.json`` 是否达到
「可聚合」标准，并交叉核对 sweep YAML 声明的 (label × seed) 任务矩阵是否有缺口。

判据（四条，全部满足才算 VALID）
--------------------------------
1. JSON 可解析（utf-8）；
2. ``schema_version == 2``（顶层与 ``metadata`` 内任一为 2 即可，两处都缺则不合格）；
3. ``data_stats.num_trials > 0``（0 表示该 seed 一条流都没成功送达，通常是配置错误）；
4. 匹配键四字段 ``{shell, node_limit, num_eval_epochs, num_flows}`` 在 ``metadata`` 中齐全。

另外对「统一口径」做一致性告警（不判失败，只提示）：
``num_eval_epochs==2``、``num_flows==20``、``total_trials==40``、``runner`` 以 ``e3`` 开头、
``duration==60``、``epoch_interval==30``、``subset_method=='cumulative_degree'``、
``seed ∈ [42, 51]``。

退出码
------
0 = 全部 sweep 齐全且全部文件 VALID；1 = 有缺口或有 INVALID 文件；2 = 用法/路径错误。

示例
----
    python tools/verify_step3_raw.py                       # 校验全部 9 个 sweep
    python tools/verify_step3_raw.py --only shell256 shell1024
    python tools/verify_step3_raw.py --only e7_combo -v    # 逐文件明细
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # 允许直接 `python tools/verify_step3_raw.py`
    PROJECT_ROOT = Path(__file__).resolve().parents[1]
except IndexError:  # pragma: no cover
    PROJECT_ROOT = Path.cwd()

SPEC_DIR = PROJECT_ROOT / "configs" / "experiments" / "step3"
RAW_ROOT = PROJECT_ROOT / "results" / "step3_raw"

# 与 scripts/run_step3_matrix.py 的 ORDER 保持一致（便于对照）
SWEEP_ORDER: Tuple[str, ...] = (
    "e6_wormhole", "e4_sybil", "e5_placement", "e5_intensity", "e7_combo",
    "e5a_scale_small", "shell256", "shell1024", "e5a_scale_top",
)

MATCH_KEYS: Tuple[str, ...] = ("shell", "node_limit", "num_eval_epochs", "num_flows")

# 统一口径期望值（B 档，见 scripts/gen_step3_configs.py）
CANON: Dict[str, Any] = {
    "num_eval_epochs": 2,
    "num_flows": 20,
    "total_trials": 40,
    "duration": 60,
    "epoch_interval": 30,
    "subset_method": "cumulative_degree",
}
CANON_SEEDS = set(range(42, 52))

_LABEL_RE = re.compile(r"^\s*-\s*label:\s*(.+?)\s*$")


# --------------------------------------------------------------------------- #
# sweep YAML 解析（轻量正则，避免为拿 label 而引入 yaml 依赖差异）
# --------------------------------------------------------------------------- #
def load_sweep_spec(key: str) -> Optional[Dict[str, Any]]:
    """读 sweep YAML，返回 {labels, seeds, raw_dir, n_tasks}。缺失返回 None。"""
    path = SPEC_DIR / f"sweep_{key}.yaml"
    if not path.exists():
        return None
    try:
        import yaml  # 优先用 yaml，语义最准
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        sw = raw.get("sweep", raw)
        labels = [str(a["label"]) for a in (sw.get("arms") or [])]
        seeds = [int(s) for s in (sw.get("seeds") or [])]
        raw_dir = sw.get("raw_dir") or str(RAW_ROOT / key)
    except Exception:  # yaml 不可用或格式异常 → 退回正则
        text = path.read_text(encoding="utf-8", errors="replace")
        labels = [m.group(1).strip().strip("'\"") for m in _LABEL_RE.finditer(text)]
        seeds = [int(x) for x in re.findall(r"^\s*-\s*(\d{2})\s*$", text, re.M)]
        raw_dir = str(RAW_ROOT / key)
    rd = Path(raw_dir)
    if not rd.is_absolute():
        rd = PROJECT_ROOT / rd
    return {"key": key, "labels": labels, "seeds": seeds, "raw_dir": rd,
            "n_tasks": len(labels) * len(seeds)}


# --------------------------------------------------------------------------- #
# 单文件校验
# --------------------------------------------------------------------------- #
def check_file(path: Path) -> Dict[str, Any]:
    """返回 {status: VALID|INVALID, reasons: [...], warns: [...], meta: {...}}"""
    reasons: List[str] = []
    warns: List[str] = []
    out: Dict[str, Any] = {"path": path, "status": "INVALID", "reasons": reasons,
                           "warns": warns, "meta": {}}
    # 1. 可解析
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception as exc:
        reasons.append(f"JSON 解析失败：{type(exc).__name__}: {exc}")
        return out
    if not isinstance(d, dict):
        reasons.append("顶层不是 JSON object")
        return out

    # 2. schema_version == 2
    sv_top = d.get("schema_version")
    meta = d.get("metadata") or {}
    sv_meta = meta.get("schema_version")
    if sv_top != 2 and sv_meta != 2:
        reasons.append(f"schema_version != 2（top={sv_top!r}, metadata={sv_meta!r}）")

    # 3. data_stats.num_trials > 0
    ds = d.get("data_stats") or {}
    nt = ds.get("num_trials")
    if not isinstance(nt, int) or nt <= 0:
        reasons.append(f"data_stats.num_trials 非法：{nt!r}")

    # 4. 匹配键四字段齐全
    missing = [k for k in MATCH_KEYS if meta.get(k) is None]
    if missing:
        reasons.append(f"metadata 缺匹配键字段：{missing}")

    out["meta"] = {k: meta.get(k) for k in MATCH_KEYS}
    out["meta"]["seed"] = d.get("seed", meta.get("seed"))
    out["meta"]["runner"] = meta.get("runner")
    out["meta"]["num_trials"] = nt
    out["meta"]["delivery_ratio"] = ds.get("delivery_ratio")

    # --- 统一口径一致性告警（不判失败）---
    for k, want in CANON.items():
        if k == "duration":
            got = ((d.get("config") or {}).get("experiment") or {}).get("duration")
        elif k == "epoch_interval":
            got = ((d.get("config") or {}).get("topology") or {}).get("epoch_interval")
        elif k == "subset_method":
            got = ((d.get("config") or {}).get("topology") or {}).get("subset_method")
        else:
            got = meta.get(k)
        if got is not None and got != want:
            warns.append(f"{k}={got!r} 与统一口径 {want!r} 不一致")
    runner = meta.get("runner") or ""
    if not str(runner).startswith("e3"):
        warns.append(f"runner={runner!r} 非 e3 系")
    sd = out["meta"]["seed"]
    if sd is not None and int(sd) not in CANON_SEEDS:
        warns.append(f"seed={sd} 不在 42..51")

    out["status"] = "VALID" if not reasons else "INVALID"
    return out


# --------------------------------------------------------------------------- #
# sweep 级校验
# --------------------------------------------------------------------------- #
def verify_sweep(key: str, verbose: bool = False) -> Dict[str, Any]:
    spec = load_sweep_spec(key)
    rec: Dict[str, Any] = {"key": key, "spec_ok": spec is not None}
    if spec is None:
        rec.update({"error": f"缺少 sweep 配置 {SPEC_DIR / f'sweep_{key}.yaml'}"})
        return rec

    raw_dir: Path = spec["raw_dir"]
    rec.update({"n_tasks": spec["n_tasks"], "labels": len(spec["labels"]),
                "seeds": len(spec["seeds"]), "raw_dir": str(raw_dir)})
    if not raw_dir.exists():
        rec.update({"n_json_on_disk": 0, "n_matrix_found": 0,
                    "missing": [(lbl, sd) for lbl in spec["labels"] for sd in spec["seeds"]],
                    "n_missing": spec["n_tasks"], "invalid": [], "n_invalid": 0,
                    "n_warn_files": 0, "warns": [], "complete": False,
                    "error": f"raw 目录不存在：{raw_dir}"})
        return rec

    # 期望矩阵：{label: {seed: path}}，用 run_step3_matrix 同款 glob 前缀匹配
    found: Dict[Tuple[str, int], Path] = {}
    for lbl in spec["labels"]:
        for sd in spec["seeds"]:
            hits = sorted(raw_dir.glob(f"{lbl}__*_seed{sd}.json"))
            if hits:
                found[(lbl, sd)] = hits[0]

    all_json = sorted(raw_dir.glob("*.json"))
    results = [check_file(p) for p in all_json]
    invalid = [r for r in results if r["status"] == "INVALID"]
    warn_files = [r for r in results if r["warns"]]

    missing = [(lbl, sd) for lbl in spec["labels"] for sd in spec["seeds"]
               if (lbl, sd) not in found]

    rec.update({
        "n_json_on_disk": len(all_json),
        "n_matrix_found": len(found),
        "missing": missing,
        "n_missing": len(missing),
        "invalid": [{"path": str(r["path"]), "reasons": r["reasons"]} for r in invalid],
        "n_invalid": len(invalid),
        "n_warn_files": len(warn_files),
        "warns": sorted({w for r in warn_files for w in r["warns"]}),
        "complete": len(found) >= spec["n_tasks"] and not invalid,
    })
    if verbose:
        rec["detail"] = [{
            "file": r["path"].name, "status": r["status"],
            "match_key": r["meta"], "num_trials": r["meta"].get("num_trials"),
            "delivery_ratio": r["meta"].get("delivery_ratio"),
            "reasons": r["reasons"], "warns": r["warns"],
        } for r in results]
    return rec


# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="step3 raw 完整性校验（只读）：JSON 可解析 + schema_version==2 "
                    "+ num_trials>0 + 匹配键四字段齐全 + (label×seed) 矩阵无缺口")
    ap.add_argument("--only", nargs="*", default=None, help="仅校验指定 sweep key")
    ap.add_argument("-v", "--verbose", action="store_true", help="打印逐文件明细")
    ap.add_argument("--json", default=None, help="把完整结果另存为 JSON（默认不写）")
    args = ap.parse_args(argv)

    keys = args.only if args.only else list(SWEEP_ORDER)
    unknown = [k for k in keys if k not in SWEEP_ORDER]
    if unknown:
        print(f"[warn] 非标准 sweep key（仍会尝试校验）：{unknown}", file=sys.stderr)

    recs = [verify_sweep(k, verbose=args.verbose) for k in keys]

    hdr = f"{'sweep':<18}{'tasks':>6}{'found':>7}{'miss':>6}{'inval':>7}{'warn':>6}  complete"
    print("=" * len(hdr))
    print(hdr)
    print("-" * len(hdr))
    for r in recs:
        if not r.get("spec_ok"):
            print(f"{r['key']:<18}{'-':>6}{'-':>7}{'-':>6}{'-':>7}{'-':>6}  SPEC_MISSING")
            continue
        print(f"{r['key']:<18}{r['n_tasks']:>6}{r['n_matrix_found']:>7}"
              f"{r['n_missing']:>6}{r['n_invalid']:>7}{r['n_warn_files']:>6}  "
              f"{'YES' if r['complete'] else 'NO'}")
    print("=" * len(hdr))

    tot_tasks = sum(r.get("n_tasks", 0) for r in recs if r.get("spec_ok"))
    tot_found = sum(r.get("n_matrix_found", 0) for r in recs if r.get("spec_ok"))
    tot_missing = sum(r.get("n_missing", 0) for r in recs if r.get("spec_ok"))
    tot_invalid = sum(r.get("n_invalid", 0) for r in recs if r.get("spec_ok"))
    print(f"合计：{tot_found}/{tot_tasks} 任务矩阵齐全，缺失 {tot_missing}，INVALID {tot_invalid}")

    # 明细：缺口 / 非法 / 告警
    for r in recs:
        if not r.get("spec_ok"):
            continue
        if r.get("error"):
            print(f"\n[{r['key']}] ERROR: {r['error']}")
        if r["missing"]:
            show = r["missing"][:20]
            more = f" …(+{len(r['missing']) - 20})" if len(r["missing"]) > 20 else ""
            print(f"\n[{r['key']}] 缺失 {r['n_missing']} 项（label, seed）：{show}{more}")
        if r["invalid"]:
            print(f"\n[{r['key']}] INVALID {r['n_invalid']} 个文件：")
            for it in r["invalid"][:20]:
                print(f"  - {Path(it['path']).name}: {'; '.join(it['reasons'])}")
            if r["n_invalid"] > 20:
                print(f"  …(+{r['n_invalid'] - 20})")
        if r["warns"]:
            print(f"\n[{r['key']}] 口径告警（去重，不判失败）：")
            for w in r["warns"]:
                print(f"  ! {w}")
        if args.verbose and r.get("detail"):
            print(f"\n[{r['key']}] 逐文件明细：")
            for d in r["detail"]:
                mk = d["match_key"]
                print(f"  {d['status']:<8}{d['file']:<62}"
                      f"shell={mk.get('shell')} nl={mk.get('node_limit')} "
                      f"nee={mk.get('num_eval_epochs')} nf={mk.get('num_flows')} "
                      f"seed={mk.get('seed')} nt={d['num_trials']} DR={d['delivery_ratio']}")

    if args.json:
        outp = Path(args.json)
        if not outp.is_absolute():
            outp = PROJECT_ROOT / outp
        outp.parent.mkdir(parents=True, exist_ok=True)
        with open(outp, "w", encoding="utf-8") as f:
            json.dump(recs, f, ensure_ascii=False, indent=1, default=str)
        print(f"\n[written] {outp}")

    ok = all(r.get("spec_ok") and r.get("complete") for r in recs)
    print(f"\n结论：{'ALL GREEN' if ok else 'NOT COMPLETE / HAS INVALID'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
