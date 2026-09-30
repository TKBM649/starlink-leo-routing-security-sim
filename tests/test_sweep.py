# tests/test_sweep.py
"""
并行 sweep 框架（``scripts/run_experiment_sweep.py``）集成测试。

用**极小合成拓扑**（6 节点环 × 3 epoch）+ 一对同 runner（e3）、同匹配键的臂
（baseline 无攻击 / attack 黑洞 drop_prob=1.0），验证：

1. 配置解析 / 校验（parse_arm、load_sweep_config、_validate_spec）；
2. dry-run：仅校验任务矩阵与攻击窗口，不加载 pkl、不跑仿真；
3. 串行（workers=1）与**并行（workers=2，spawn）** 两条路径都能跑通
   ``2 workers × 3 seeds``，产出逐 seed raw JSON + 逐臂聚合（mean±std + bootstrap
   95% CI）+ 配对比较（Wilcoxon/MWU p 值）；
4. 攻击窗口守卫在 sweep 层生效。

全部秒级、不碰真实 102.8MB 拓扑。并行用例须在 ``python -m pytest`` 下运行
（spawn 子进程通过 ``.__main__`` 守卫避免递归重跑 pytest）。
"""
import json
import pickle
from pathlib import Path

import pytest
import yaml

import run_experiment_sweep as sw
from run_experiment_sweep import (
    Arm,
    SweepSpec,
    parse_arm,
    load_sweep_config,
    build_spec,
    run_sweep,
)


SHELL = "TEST"
SEEDS = [42, 43, 44]


# ==================== 合成拓扑与配置夹具 ====================

def _make_tiny_pkl(path: Path):
    """6 节点环 × 3 epoch（无位置缓存 → latency=0，但交付/路由正常）。"""
    ring = {(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 0)}
    edges = [set(ring) for _ in range(3)]
    topo = {SHELL: {"edges_per_epoch": edges, "positions_per_epoch": None}}
    with open(path, "wb") as f:
        pickle.dump(topo, f)


def _arm_config(pkl: Path, name: str, attackers, out: Path) -> dict:
    return {
        "experiment": {"name": name, "duration": 60},
        "topology": {
            "shell": SHELL, "epoch_interval": 30, "node_limit": None,
            "cache_path": str(pkl), "positions_cache": None,
        },
        "routing": {"t_adv": 2.0, "tick": 1.0, "max_hops": 20},
        "traffic": {"num_flows": 5},
        "attack": {"attackers": attackers},
        "output": {
            "raw_dir": str(out / "raw"), "agg_dir": str(out / "agg"),
            "figures_dir": str(out / "fig"),
        },
    }


@pytest.fixture
def sweep_env(tmp_path):
    """搭建极小 sweep 环境：tiny pkl + baseline/attack 两个配置 + sweep 规格 YAML。"""
    pkl = tmp_path / "tiny.pkl"
    _make_tiny_pkl(pkl)

    base_cfg = tmp_path / "base.yaml"
    atk_cfg = tmp_path / "attack.yaml"
    with open(base_cfg, "w", encoding="utf-8") as f:
        yaml.safe_dump(_arm_config(pkl, "sweep_test_baseline", [], tmp_path), f)
    blackhole = [{"type": "blackhole", "count": 1, "placement": "degree",
                  "active_since": 0.0, "active_until": float("inf"),
                  "params": {"drop_prob": 1.0, "metric_fake": 0}}]
    with open(atk_cfg, "w", encoding="utf-8") as f:
        yaml.safe_dump(_arm_config(pkl, "sweep_test_attack", blackhole, tmp_path), f)

    spec_yaml = tmp_path / "sweep.yaml"
    spec_dict = {
        "sweep": {
            "name": "sweep_test", "runner": "e3", "seeds": SEEDS, "workers": 2,
            "raw_dir": str(tmp_path / "raw"), "agg_dir": str(tmp_path / "agg"),
            "subset_method": "cumulative_degree", "alpha": 0.05, "n_boot": 2000,
            "arms": [{"label": "baseline", "config": str(base_cfg)},
                     {"label": "attack", "config": str(atk_cfg)}],
            "comparison": {"attack": "attack", "baseline": "baseline"},
        }
    }
    with open(spec_yaml, "w", encoding="utf-8") as f:
        yaml.safe_dump(spec_dict, f)

    return {"tmp": tmp_path, "pkl": pkl, "base_cfg": base_cfg,
            "atk_cfg": atk_cfg, "spec_yaml": spec_yaml}


# ==================== 配置解析 / 校验 ====================

def test_parse_arm():
    a = parse_arm("attack=configs/x.yaml")
    assert a.label == "attack" and a.config_path == "configs/x.yaml"
    with pytest.raises(Exception):
        parse_arm("no_equals_sign")


def test_load_sweep_config(sweep_env):
    spec = load_sweep_config(sweep_env["spec_yaml"])
    assert spec.name == "sweep_test"
    assert spec.runner == "e3"
    assert spec.seeds == SEEDS
    assert spec.workers == 2
    assert {a.label for a in spec.arms} == {"baseline", "attack"}
    assert spec.comparison == ("attack", "baseline")


def test_validate_spec_rejects_bad_runner(sweep_env):
    spec = load_sweep_config(sweep_env["spec_yaml"])
    spec.runner = "e9"
    with pytest.raises(ValueError):
        sw._validate_spec(spec)


def test_validate_spec_rejects_empty_arms():
    spec = SweepSpec(arms=[], seeds=[1])
    with pytest.raises(ValueError):
        sw._validate_spec(spec)


def test_validate_spec_rejects_duplicate_labels(sweep_env):
    spec = load_sweep_config(sweep_env["spec_yaml"])
    spec.arms = [Arm("x", "a.yaml"), Arm("x", "b.yaml")]
    with pytest.raises(ValueError):
        sw._validate_spec(spec)


def test_validate_spec_rejects_unknown_comparison_label(sweep_env):
    spec = load_sweep_config(sweep_env["spec_yaml"])
    spec.comparison = ("ghost", "baseline")
    with pytest.raises(ValueError):
        sw._validate_spec(spec)


def test_build_spec_cli_overrides(sweep_env):
    import argparse
    ns = argparse.Namespace(
        sweep_config=str(sweep_env["spec_yaml"]), runner=None, arm=[],
        seeds=[1, 2], workers=1, raw_dir=None, agg_dir=None, subset_method=None,
        attack=None, baseline=None, strict_window=False, non_strict=False,
        alpha=None, n_boot=None,
    )
    spec = build_spec(ns)
    assert spec.seeds == [1, 2]   # CLI 覆盖 YAML
    assert spec.workers == 1


# ==================== dry-run ====================

def test_dry_run_validates_without_loading_pkl(sweep_env):
    spec = load_sweep_config(sweep_env["spec_yaml"])
    report, code = run_sweep(spec, dry_run=True)
    assert code == 0
    assert report["dry_run"] is True
    # 任务矩阵 = 2 臂 × 3 seeds = 6
    assert report["n_tasks"] == 6
    assert {a["label"] for a in report["arms"]} == {"baseline", "attack"}
    # dry-run 不应真正跑仿真 → raw 目录里没有逐 seed 结果
    raw_files = list((sweep_env["tmp"] / "raw").glob("*.json")) if (sweep_env["tmp"] / "raw").exists() else []
    assert raw_files == []


def test_dry_run_flags_deactivated_attack_window(sweep_env):
    # 构造一个评估期完全失活的攻击臂（active 窗口远晚于评估时刻）
    bad_cfg = sweep_env["tmp"] / "bad.yaml"
    blackhole = [{"type": "blackhole", "count": 1, "placement": "degree",
                  "active_since": 1000.0, "active_until": 2000.0,
                  "params": {"drop_prob": 1.0, "metric_fake": 0}}]
    with open(bad_cfg, "w", encoding="utf-8") as f:
        yaml.safe_dump(_arm_config(sweep_env["pkl"], "bad_window", blackhole,
                                   sweep_env["tmp"]), f)
    spec = SweepSpec(name="bad", runner="e3", seeds=[42], workers=1,
                     raw_dir=str(sweep_env["tmp"] / "raw2"),
                     agg_dir=str(sweep_env["tmp"] / "agg2"),
                     arms=[Arm("bad", str(bad_cfg))])
    report, code = run_sweep(spec, dry_run=True)
    assert code == 0
    warns = report["arms"][0]["window_warnings"]
    assert len(warns) == 1 and "完全失活" in warns[0]


# ==================== 串行聚合（workers=1，无 spawn） ====================

def _assert_sweep_outputs(report, code, tmp):
    assert code == 0
    assert report["n_completed"] == 6
    # 两臂均聚合，n_seeds=3，delivery_ratio 有 bootstrap CI（n_seeds>=2）
    for label in ("baseline", "attack"):
        arm = report["arms"][label]
        assert arm["n_seeds"] == 3
        dr = arm["metrics"]["delivery_ratio"]
        assert dr["ci95_low"] is not None and dr["ci95_high"] is not None
        assert dr["n"] == 3
    # 配对比较产出 p 值
    cmp = report["comparison"]
    assert cmp["n_comparable_groups"] >= 1
    grp = next(g for g in cmp["groups"] if g.get("comparable"))
    dr_cmp = grp["comparisons"]["delivery_ratio"]
    assert dr_cmp["test"] in ("wilcoxon", "mannwhitneyu")
    assert "p_value" in dr_cmp and 0.0 <= dr_cmp["p_value"] <= 1.0
    # 逐 seed raw 文件：2 臂 × 3 seeds = 6
    raw_files = list((tmp / "raw").glob("*.json"))
    assert len(raw_files) == 6
    # 每个 raw 都是合法 JSON 且带真实基数元数据
    for rf in raw_files:
        rec = json.loads(rf.read_text(encoding="utf-8"))
        assert rec["metadata"]["num_eval_epochs"] == 2
        assert rec["metadata"]["num_flows"] == 5
        assert rec["data_stats"]["num_trials"] == 10  # 5 flows × 2 epochs
    # 聚合/对比文件落盘
    assert (tmp / "agg" / "agg_baseline.json").exists()
    assert (tmp / "agg" / "comparison_attack_vs_baseline.json").exists()
    assert (tmp / "agg" / "sweep_report.json").exists()


def test_serial_sweep_aggregation(sweep_env):
    spec = load_sweep_config(sweep_env["spec_yaml"])
    spec.workers = 1  # 串行路径：父进程加载一次缓存，无 spawn 开销
    report, code = run_sweep(spec, dry_run=False)
    _assert_sweep_outputs(report, code, sweep_env["tmp"])
    # 黑洞 drop_prob=1.0 应压低交付率（验证攻击确实生效、管线检测到差异）
    base_dr = report["arms"]["baseline"]["metrics"]["delivery_ratio"]["mean"]
    atk_dr = report["arms"]["attack"]["metrics"]["delivery_ratio"]["mean"]
    assert atk_dr < base_dr


# ==================== 并行聚合（workers=2，spawn Pool） ====================

def test_parallel_sweep_2workers_3seeds(sweep_env):
    spec = load_sweep_config(sweep_env["spec_yaml"])
    assert spec.workers == 2
    report, code = run_sweep(spec, dry_run=False)
    _assert_sweep_outputs(report, code, sweep_env["tmp"])


# ==================== JSON 安全序列化 ====================

def test_json_safe_handles_inf_nan_and_numpy():
    import numpy as np
    obj = {"a": float("inf"), "b": float("nan"), "c": np.float64(1.5),
           "d": np.int64(7), "e": [float("-inf"), np.bool_(True)], "f": "x"}
    safe = sw._json_safe(obj)
    assert safe["a"] is None and safe["b"] is None
    assert safe["c"] == 1.5 and safe["d"] == 7
    assert safe["e"][0] is None and safe["e"][1] is True
    assert safe["f"] == "x"
    # 结果必须可被严格 JSON 序列化（无 inf/nan）
    json.dumps(safe)
