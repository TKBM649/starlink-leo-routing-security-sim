#!/usr/bin/env python
# scripts/run_experiment_sweep.py
"""
并行实验 sweep 框架（1.6 X1）。

把每个 (config, seed) 作为独立任务并行执行，收集逐 seed raw JSON，再调用
``starlink_sim.analytics`` 的 :func:`aggregate_experiment` /
:func:`compare_attack_vs_baseline` 产出 mean±std + bootstrap 95% CI +
Wilcoxon/MWU 配对检验。

设计要点
========
- **Windows spawn**：102.8MB 的 ``topology_results.pkl`` 在 ``Pool(initializer=...)``
  里**每进程加载一次**（缓存在 worker 全局 ``_TOPO_CACHE``），绝不每任务重复加载；
  入口用 ``if __name__ == '__main__':`` 保护，避免 spawn 递归。
- **同 runner 配对**：一个 sweep 只有一个 ``runner``（'e2' 用 Simulator 逐 epoch 评估；
  'e3' 用 ControlPlane+DataPlane 末窗口评估），攻击臂与基线臂必须同 runner —— 二者
  epoch 约定不同，跨 runner 比较无意义。trials 基数以 raw JSON 的 ``num_trials`` 为真值。
- **任务独立无共享态**：每个 (config,seed) 仅依赖 worker 全局只读拓扑缓存，互不干扰。
- **攻击窗口守卫**：dry-run 与实际运行均校验 active_since/active_until 与评估时刻重叠。

用法
====
1) sweep YAML 配置::

    python scripts/run_experiment_sweep.py --sweep-config configs/experiments/sweep_e3_demo.yaml

2) 纯命令行（一对攻击臂 + 匹配基线臂）::

    python scripts/run_experiment_sweep.py --runner e3 \
        --arm attack=configs/experiments/e3_blackhole_t7.yaml \
        --arm baseline=configs/experiments/e3_noattack_t7.yaml \
        --attack attack --baseline baseline \
        --seeds 42 43 44 45 46 --workers 4

3) dry-run（仅校验配置/任务矩阵/攻击窗口，不加载 pkl、不跑仿真）::

    python scripts/run_experiment_sweep.py --sweep-config <cfg> --dry-run
"""
from __future__ import annotations

import sys
import json
import pickle
import argparse
import multiprocessing as mp
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
for _p in (str(PROJECT_ROOT), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import yaml  # noqa: E402

from starlink_sim.io.config import load_experiment_config, get_attacker_configs  # noqa: E402
from starlink_sim.net.placement import evaluation_times, check_attack_windows  # noqa: E402
from starlink_sim.topology.subset import select_connected_subset, all_nodes  # noqa: E402
from starlink_sim.analytics.stats import (  # noqa: E402
    aggregate_experiment,
    compare_attack_vs_baseline,
    TrialsCardinalityError,
    DEFAULT_METRICS,
)
from starlink_sim.net.sybil import SYBIL_METRIC_KEYS  # noqa: E402
from starlink_sim.net.wormhole import WORMHOLE_METRIC_KEYS  # noqa: E402

VALID_RUNNERS = ('e2', 'e3')

# 聚合指标 = 既有默认指标 + E4 Sybil 特有指标 + E6 Wormhole 特有指标（纯附加：
# 某臂缺失该指标时 aggregate_experiment / compare_attack_vs_baseline 自动跳过，
# 不影响既有臂与匹配键）。虫洞的 WORMHOLE_TUNNEL_KEYS 在基线臂上**故意缺席**
# （无 ground truth 时检测率/stretch 无定义），故不会用 0.0 污染统计。
SWEEP_METRICS: Tuple[str, ...] = (tuple(DEFAULT_METRICS) + tuple(SYBIL_METRIC_KEYS)
                                  + tuple(WORMHOLE_METRIC_KEYS))

# worker 全局只读拓扑缓存：cache_path(str) -> pickle 反序列化的 dict。
# 由 _init_worker 在每进程启动时填充一次（spawn 下每子进程独立持有一份）。
_TOPO_CACHE: Dict[str, Any] = {}

# 本进程溯源元数据缓存：topology_cache_path(str) -> provenance dict。
# SHA256(102.8MB pkl) 计算一次约 0.3-0.5s，若每任务重算，400 任务的 sweep 会白烧
# 数分钟，故按缓存路径做进程级记忆化（worker 进程内只算一次）。
_PROV_CACHE: Dict[str, Any] = {}
_TLE_CANDIDATES: Tuple[str, ...] = ('data/tle/starlink.tle',)


def _provenance(topo_cache_path: str) -> Dict[str, Any]:
    """返回溯源元数据（TLE SHA256 / 拓扑缓存 SHA256 / git commit / python 版本）。

    纯附加能力：这些键原先只有 ``scripts/run_simulation.py`` 的 canonical E1 路径
    会写，sweep 路径的 raw JSON 缺失 → 无法满足「raw JSON metadata 含 TLE SHA256 /
    基数 / git commit」的可复现性要求。此处复用 run_simulation 的同名工具函数，
    避免逻辑重复。``timestamp_utc`` 由调用方逐任务填写（不缓存）。
    """
    cached = _PROV_CACHE.get(topo_cache_path)
    if cached is not None:
        return dict(cached)
    from run_simulation import _sha256_file, _git_commit
    tle_path: Optional[Path] = None
    for cand in _TLE_CANDIDATES:
        p = PROJECT_ROOT / cand
        if p.exists():
            tle_path = p
            break
    prov: Dict[str, Any] = {
        'git_commit': _git_commit(),
        'python_version': sys.version.split()[0],
        'tle_path': str(tle_path) if tle_path else None,
        'tle_sha256': _sha256_file(tle_path),
        'topology_cache_sha256': _sha256_file(Path(topo_cache_path)),
        'topology_cache': str(topo_cache_path),
    }
    _PROV_CACHE[topo_cache_path] = prov
    return dict(prov)


# ==================== 配置数据结构 ====================

@dataclass
class Arm:
    label: str
    config_path: str


@dataclass
class SweepSpec:
    name: str = 'sweep'
    runner: str = 'e3'
    seeds: List[int] = field(default_factory=lambda: [42])
    workers: int = 2
    raw_dir: str = 'results/sweep_raw/'
    agg_dir: str = 'results/sweep_agg/'
    subset_method: str = 'cumulative_degree'
    strict_window: bool = False
    non_strict: bool = False
    alpha: float = 0.05
    n_boot: int = 2000
    arms: List[Arm] = field(default_factory=list)
    comparison: Optional[Tuple[str, str]] = None  # (attack_label, baseline_label)


def parse_arm(spec: str) -> Arm:
    """解析 ``label=config_path`` 形式的臂定义。"""
    if '=' not in spec:
        raise argparse.ArgumentTypeError(f"臂定义须为 label=config 形式，收到: {spec!r}")
    label, path = spec.split('=', 1)
    return Arm(label.strip(), path.strip())


def load_sweep_config(path: str | Path) -> SweepSpec:
    """从 sweep YAML 加载 :class:`SweepSpec`。"""
    with open(path, 'r', encoding='utf-8') as f:
        raw = yaml.safe_load(f) or {}
    sw = raw.get('sweep', raw)
    arms = [Arm(a['label'], a['config']) for a in sw.get('arms', [])]
    comp = sw.get('comparison')
    comparison = (comp['attack'], comp['baseline']) if comp else None
    return SweepSpec(
        name=sw.get('name', 'sweep'),
        runner=str(sw.get('runner', 'e3')),
        seeds=[int(s) for s in sw.get('seeds', [42])],
        workers=int(sw.get('workers', 2)),
        raw_dir=sw.get('raw_dir', 'results/sweep_raw/'),
        agg_dir=sw.get('agg_dir', 'results/sweep_agg/'),
        subset_method=sw.get('subset_method', 'cumulative_degree'),
        strict_window=bool(sw.get('strict_window', False)),
        non_strict=bool(sw.get('non_strict', False)),
        alpha=float(sw.get('alpha', 0.05)),
        n_boot=int(sw.get('n_boot', 2000)),
        arms=arms,
        comparison=comparison,
    )


def build_spec(args: argparse.Namespace) -> SweepSpec:
    """从 CLI 参数（可叠加 sweep YAML）构造 :class:`SweepSpec`，CLI 覆盖优先。"""
    if args.sweep_config:
        spec = load_sweep_config(args.sweep_config)
    else:
        spec = SweepSpec()
        spec.arms = list(args.arm)
    if args.runner is not None:
        spec.runner = args.runner
    if args.arm:
        # 命令行臂定义覆盖/补充 YAML 中的臂
        existing = {a.label for a in spec.arms}
        for a in args.arm:
            if a.label not in existing:
                spec.arms.append(a)
    if args.seeds is not None:
        spec.seeds = list(args.seeds)
    if args.workers is not None:
        spec.workers = args.workers
    if args.raw_dir is not None:
        spec.raw_dir = args.raw_dir
    if args.agg_dir is not None:
        spec.agg_dir = args.agg_dir
    if args.subset_method is not None:
        spec.subset_method = args.subset_method
    if args.attack and args.baseline:
        spec.comparison = (args.attack, args.baseline)
    if args.strict_window:
        spec.strict_window = True
    if args.non_strict:
        spec.non_strict = True
    if args.alpha is not None:
        spec.alpha = args.alpha
    if args.n_boot is not None:
        spec.n_boot = args.n_boot
    _validate_spec(spec)
    return spec


def _validate_spec(spec: SweepSpec) -> None:
    if spec.runner not in VALID_RUNNERS:
        raise ValueError(f"runner 必须是 {VALID_RUNNERS} 之一，收到 {spec.runner!r}")
    if not spec.arms:
        raise ValueError("至少需要一个臂（--arm label=config 或 sweep YAML 的 arms）")
    if not spec.seeds:
        raise ValueError("seeds 不能为空")
    labels = [a.label for a in spec.arms]
    if len(set(labels)) != len(labels):
        raise ValueError(f"臂 label 重复: {labels}")
    if spec.comparison:
        for lab in spec.comparison:
            if lab not in labels:
                raise ValueError(f"comparison 引用了不存在的臂 label: {lab!r}（可用: {labels}）")


# ==================== worker：拓扑缓存与单任务执行 ====================

def _init_worker(cache_paths: Sequence[str],
                 keep_shells: Optional[Sequence[str]] = None) -> None:
    """Pool initializer：每进程加载一次拓扑缓存（102.8MB pkl），缓存到全局。

    ``keep_shells`` 非空时**仅保留**本 sweep 实际引用的壳层，其余壳从缓存 dict 中
    剔除。纯内存优化，不改变任何被引用壳的数据与下游行为：实测 4 壳全量 pkl
    反序列化后占 ~1.13GB RSS/worker（单壳 53° 约 ~0.53GB），nl=1024 单任务峰值
    RSS 达 ~2.22GB；在 31.7GB 机器上剔除无关壳可把安全并行度从 ~8 提到 ~12。
    """
    for cp in cache_paths:
        cp = str(cp)
        if cp not in _TOPO_CACHE:
            with open(cp, 'rb') as f:
                data = pickle.load(f)
            if keep_shells and isinstance(data, dict):
                keep = set(keep_shells)
                for shell in list(data.keys()):
                    if shell not in keep:
                        del data[shell]
            _TOPO_CACHE[cp] = data


def _prepare_topology(config: dict, subset_method: str = 'cumulative_degree'):
    """
    从 worker 全局缓存（必要时回退直接加载）取出 shell 拓扑，按 node_limit 做
    跨 epoch 连通子集裁剪。**不修改缓存原始数据**（裁剪生成新列表/新集合）。

    返回 (edges_per_epoch, positions_per_epoch, node_ids)。
    """
    topo = config['topology']
    cache_path = str(topo['cache_path'])
    shell = topo['shell']
    node_limit = topo.get('node_limit')

    topo_data = _TOPO_CACHE.get(cache_path)
    if topo_data is None:  # 串行/未预加载回退
        with open(cache_path, 'rb') as f:
            topo_data = pickle.load(f)
        _TOPO_CACHE[cache_path] = topo_data
    if shell not in topo_data:
        raise ValueError(f"Shell '{shell}' 不在缓存中，可用: {list(topo_data.keys())}")

    shell_data = topo_data[shell]
    edges_per_epoch = shell_data['edges_per_epoch']
    positions_per_epoch = shell_data.get('positions_per_epoch', None)

    if node_limit is not None:
        node_subset = set(select_connected_subset(edges_per_epoch, node_limit,
                                                  method=subset_method))
        edges_per_epoch = [{(u, v) for u, v in edges if u in node_subset and v in node_subset}
                           for edges in edges_per_epoch]
        if positions_per_epoch and positions_per_epoch[0] is not None:
            positions_per_epoch = [{n: pos[n] for n in node_subset if n in pos}
                                   for pos in positions_per_epoch]
        node_ids = sorted(node_subset)
    else:
        node_ids = sorted(all_nodes(edges_per_epoch))

    if positions_per_epoch is None:
        positions_per_epoch = [None] * len(edges_per_epoch)
    return edges_per_epoch, positions_per_epoch, node_ids


def _run_task(task: Tuple[str, str, int, str, str, bool]):
    """
    执行单个 (arm, seed) 任务，返回 (arm_label, seed, record_dict)。

    在 worker 进程中运行；拓扑来自 ``_init_worker`` 预加载的全局缓存。
    每个任务相互独立、无共享可变状态。
    """
    arm_label, config_path, seed, runner, subset_method, strict_window = task
    config = load_experiment_config(config_path)
    edges_per_epoch, positions_per_epoch, node_ids = _prepare_topology(config, subset_method)

    # 攻击窗口守卫（精确版：用实际评估窗口）——strict 时评估期完全失活直接报错
    _guard_windows(config, edges_per_epoch, runner, strict_window)

    if runner == 'e3':
        import run_e3_blackhole_experiment as e3
        record = e3.run_experiment(seed, config, edges_per_epoch, positions_per_epoch, node_ids)
    elif runner == 'e2':
        import run_e2_jamming_experiment as e2
        flow_pairs = e2.generate_flows(node_ids, config['traffic']['num_flows'], seed)
        record = e2.run_experiment_with_topology(config, seed, edges_per_epoch,
                                                 positions_per_epoch, flow_pairs)
    else:  # pragma: no cover - _validate_spec 已拦截
        raise ValueError(f"Unknown runner: {runner!r}")

    # ---- provenance 注入（纯附加：setdefault 语义，绝不覆盖 runner 已写字段）----
    meta = record.setdefault('metadata', {})
    prov = _provenance(str(config['topology']['cache_path']))
    prov['timestamp_utc'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    for k, v in prov.items():
        meta.setdefault(k, v)
    return arm_label, seed, record


def _guard_windows(config: dict, edges_per_epoch, runner: str, strict: bool) -> None:
    """按 runner 的评估约定计算评估时刻并校验攻击窗口重叠。"""
    att_configs = get_attacker_configs(config)
    if not att_configs:
        return
    topo = config['topology']
    exp = config['experiment']
    interval = float(topo.get('epoch_interval', 30.0))
    duration = float(exp.get('duration', 60.0))
    n_avail = len(edges_per_epoch)
    if runner == 'e3':
        last_idx = max(0, min(int(duration / interval) - 1, n_avail - 1))
        num_eval = max(1, min(last_idx + 1, n_avail))
        start_idx = max(0, last_idx - num_eval + 1)
        base_time = start_idx * interval
    else:  # e2 / Simulator: base_time=0, 评估 epoch [0, num_eval)
        num_eval = min(n_avail, max(1, int(duration // interval)))
        base_time = 0.0
    eval_times = evaluation_times(base_time, num_eval, interval)
    for w in check_attack_windows(att_configs, eval_times, strict=strict):
        # strict=True 时 check_attack_windows 已抛错；此处仅打印非致命告警
        print(f"[attack-window-guard] {w}")


# ==================== JSON 安全序列化 ====================

def _json_safe(obj):
    """递归把非有限浮点（inf/nan）→ None、numpy 标量 → python，确保严格 JSON 可序列化。"""
    import numpy as np
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (bool, np.bool_)):
        return bool(obj)
    if isinstance(obj, (int, np.integer)):
        return int(obj)
    if isinstance(obj, (float, np.floating)):
        f = float(obj)
        return f if np.isfinite(f) else None
    return obj


# ==================== dry-run ====================

def _dry_run(spec: SweepSpec, tasks: List[tuple]) -> Dict[str, Any]:
    """仅校验配置 / 任务矩阵 / 攻击窗口，不加载 pkl、不跑仿真。"""
    print("=" * 60)
    print(f"[DRY-RUN] sweep={spec.name} runner={spec.runner} workers={spec.workers}")
    print(f"[DRY-RUN] seeds={spec.seeds} subset_method={spec.subset_method}")
    print(f"[DRY-RUN] raw_dir={spec.raw_dir} agg_dir={spec.agg_dir}")
    print(f"[DRY-RUN] 任务矩阵: {len(tasks)} 任务 = {len(spec.arms)} 臂 × {len(spec.seeds)} seeds")
    arm_summaries = []
    for arm in spec.arms:
        cfg = load_experiment_config(arm.config_path)
        exp = cfg['experiment']
        topo = cfg['topology']
        interval = float(topo.get('epoch_interval', 30.0))
        duration = float(exp.get('duration', 60.0))
        num_eval = max(1, int(duration // interval))
        eval_times = evaluation_times(0.0, num_eval, interval)
        att = get_attacker_configs(cfg)
        warns = check_attack_windows(att, eval_times, strict=False)
        n_att = sum(int(a.get('count', 1) or 0) for a in att)
        # E4 Sybil 臂：预计注入的虚假身份总数（count × params.num_identities）
        sybil_cfgs = [a for a in att
                      if str(a.get('type', '')).lower() in ('sybil', 'sybilattacker')]
        sybil_ids = 0
        for a in sybil_cfgs:
            p = a.get('params') or {}
            sybil_ids += int(a.get('count', 1) or 0) * int(p.get('num_identities', 1) or 0)
        # E6 Wormhole 臂：预计注入的隧道数（每个 wormhole 攻击者 1 条，两端均为真实
        # 节点 → 节点空间**不**扩展），以及检测门控（基线臂靠 detection.wormhole.enabled
        # 开启检测以度量误报率）。
        wh_cfgs = [a for a in att
                   if str(a.get('type', '')).lower() in ('wormhole', 'wormholeattacker')]
        wh_tunnels = sum(int(a.get('count', 1) or 0) for a in wh_cfgs)
        wh_det = (cfg.get('detection') or {}).get('wormhole') or {}
        wh_det_on = bool(wh_tunnels) or bool(wh_det.get('enabled', False))
        print(f"  臂 [{arm.label}] {arm.config_path}")
        print(f"    name={exp.get('name')} shell={topo.get('shell')} "
              f"node_limit={topo.get('node_limit')} duration={duration} "
              f"~num_eval_epochs={num_eval} attackers={n_att}")
        if sybil_cfgs:
            att_desc = ', '.join(f"{a.get('params', {}).get('num_identities', 1)}×"
                                 f"{a.get('params', {}).get('attachment', 'betweenness')}"
                                 for a in sybil_cfgs)
            print(f"    [sybil] 预计注入虚假身份 {sybil_ids} 个（节点空间将扩展）: {att_desc}")
        if wh_cfgs or wh_det_on:
            wh_desc = ', '.join(
                f"A=placement:{a.get('placement', 'degree')}"
                f"/B={(a.get('params') or {}).get('endpoint_strategy', 'farthest')}"
                f"/scope={(a.get('params') or {}).get('poison_scope', 'peer_only')}"
                for a in wh_cfgs) or '(无虫洞攻击者)'
            print(f"    [wormhole] 预计注入隧道 {wh_tunnels} 条（节点空间不变）; "
                  f"检测启用={wh_det_on} "
                  f"max_isl_km={wh_det.get('max_isl_km', 2000.0)} "
                  f"distance_factor={wh_det.get('distance_factor', 1.5)} "
                  f"adaptive_factor={wh_det.get('adaptive_factor', 3.0)} "
                  f"latency_factor={wh_det.get('latency_factor', 1.0)}: {wh_desc}")
        for w in warns:
            print(f"    [window-guard] {w}")
        arm_summaries.append({'label': arm.label, 'config': arm.config_path,
                              'name': exp.get('name'), 'num_eval_epochs_approx': num_eval,
                              'sybil_num_identities': sybil_ids,
                              'wormhole_num_tunnels': wh_tunnels,
                              'wormhole_detection_enabled': wh_det_on,
                              'window_warnings': warns})
    if spec.comparison:
        print(f"  对比: attack={spec.comparison[0]!r} vs baseline={spec.comparison[1]!r}（同 runner={spec.runner}）")
    print("=" * 60)
    return {'dry_run': True, 'spec': _spec_to_dict(spec), 'arms': arm_summaries,
            'n_tasks': len(tasks)}


def _spec_to_dict(spec: SweepSpec) -> Dict[str, Any]:
    return {
        'name': spec.name, 'runner': spec.runner, 'seeds': spec.seeds,
        'workers': spec.workers, 'raw_dir': spec.raw_dir, 'agg_dir': spec.agg_dir,
        'subset_method': spec.subset_method, 'strict_window': spec.strict_window,
        'non_strict': spec.non_strict, 'alpha': spec.alpha, 'n_boot': spec.n_boot,
        'arms': [{'label': a.label, 'config': a.config_path} for a in spec.arms],
        'comparison': list(spec.comparison) if spec.comparison else None,
    }


# ==================== 主 sweep 执行 ====================

def run_sweep(spec: SweepSpec, dry_run: bool = False) -> Tuple[Dict[str, Any], int]:
    """执行 sweep，返回 (report_dict, exit_code)。exit_code=2 表示基数/匹配键不一致被拒。"""
    tasks: List[tuple] = []
    for arm in spec.arms:
        for seed in spec.seeds:
            tasks.append((arm.label, arm.config_path, int(seed), spec.runner,
                          spec.subset_method, spec.strict_window))

    if dry_run:
        return _dry_run(spec, tasks), 0

    # 收集所有臂引用的拓扑缓存路径 + 壳层（供 worker initializer 一次性加载；
    # 壳层集合用于剔除无关壳以省内存，见 _init_worker）
    _arm_cfgs = [load_experiment_config(a.config_path) for a in spec.arms]
    cache_paths = sorted({str(c['topology']['cache_path']) for c in _arm_cfgs})
    keep_shells = sorted({str(c['topology']['shell']) for c in _arm_cfgs})

    raw_dir = Path(spec.raw_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)
    agg_dir = Path(spec.agg_dir)
    agg_dir.mkdir(parents=True, exist_ok=True)

    workers = max(1, min(int(spec.workers), len(tasks)))
    print(f"[sweep] 启动 {workers} worker（spawn），共 {len(tasks)} 任务；"
          f"拓扑缓存: {cache_paths} 壳层: {keep_shells}")

    results: List[Tuple[str, int, dict]] = []
    arm_files: Dict[str, List[Path]] = {a.label: [] for a in spec.arms}

    def _emit_raw(label: str, seed: int, record: dict) -> Path:
        """逐任务**即时**落盘 raw JSON（断点友好：进程中断也不丢已完成任务）。"""
        exp_name = (record.get('experiment')
                    or (record.get('config', {}).get('experiment', {}) or {}).get('name')
                    or label)
        fpath = raw_dir / f"{label}__{exp_name}_seed{seed}.json"
        with open(fpath, 'w', encoding='utf-8') as f:
            json.dump(_json_safe(record), f, indent=2, ensure_ascii=False)
        arm_files.setdefault(label, []).append(fpath)
        return fpath

    if workers <= 1:
        # 串行：在父进程加载一次缓存后逐任务执行（便于调试，无 Pool 开销）
        _init_worker(cache_paths, keep_shells)
        for t in tasks:
            res = _run_task(t)
            results.append(res)
            _emit_raw(res[0], res[1], res[2])
            print(f"  [done] arm={t[0]} seed={t[2]} ({len(results)}/{len(tasks)})")
    else:
        ctx = mp.get_context('spawn')
        with ctx.Pool(processes=workers, initializer=_init_worker,
                      initargs=(cache_paths, keep_shells)) as pool:
            for res in pool.imap_unordered(_run_task, tasks):
                results.append(res)
                _emit_raw(res[0], res[1], res[2])
                print(f"  [done] arm={res[0]} seed={res[1]} ({len(results)}/{len(tasks)})")

    # 逐臂聚合 + 配对比较
    report: Dict[str, Any] = {
        'generated_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'sweep': _spec_to_dict(spec),
        'n_tasks': len(tasks),
        'n_completed': len(results),
        'arms': {},
        'comparison': None,
    }
    exit_code = 0
    for label, files in arm_files.items():
        if not files:
            continue
        agg = aggregate_experiment([str(p) for p in files], metrics=SWEEP_METRICS,
                                   n_boot=spec.n_boot, alpha=spec.alpha, rng=0)
        report['arms'][label] = agg
        with open(agg_dir / f"agg_{label}.json", 'w', encoding='utf-8') as f:
            json.dump(agg, f, indent=2, ensure_ascii=False)
        _print_arm(label, agg)

    if spec.comparison:
        atk_label, base_label = spec.comparison
        try:
            cmp = compare_attack_vs_baseline(
                [str(p) for p in arm_files.get(atk_label, [])],
                [str(p) for p in arm_files.get(base_label, [])],
                metrics=SWEEP_METRICS,
                alpha=spec.alpha, strict=not spec.non_strict)
            report['comparison'] = {'attack': atk_label, 'baseline': base_label, **cmp}
            with open(agg_dir / f"comparison_{atk_label}_vs_{base_label}.json", 'w',
                      encoding='utf-8') as f:
                json.dump(cmp, f, indent=2, ensure_ascii=False)
            _print_comparison(cmp)
        except TrialsCardinalityError as exc:
            print(f"\n[拒绝比较] {exc}", file=sys.stderr)
            report['comparison'] = {'attack': atk_label, 'baseline': base_label,
                                    'error': str(exc)}
            exit_code = 2

    with open(agg_dir / "sweep_report.json", 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[sweep] 完成：raw → {raw_dir}，聚合/对比 → {agg_dir}")
    return report, exit_code


def _print_arm(label: str, agg: dict) -> None:
    print(f"\n=== 臂 [{label}] 聚合（{agg['n_seeds']} seeds: {agg['seeds']}） ===")
    mk = (agg.get('cardinality') or {}).get('match_key')
    if mk:
        print(f"匹配键: {json.dumps(mk, ensure_ascii=False)}")
    for name, m in agg['metrics'].items():
        lo = f"{m['ci95_low']:.4f}" if m.get('ci95_low') is not None else '-'
        hi = f"{m['ci95_high']:.4f}" if m.get('ci95_high') is not None else '-'
        print(f"  {name:<24} mean={m['mean']:.4f} std={m['std']:.4f} CI95=[{lo}, {hi}]")
    for w in agg.get('warnings', []):
        print(f"  [warn] {w}")


def _print_comparison(cmp: dict) -> None:
    print(f"\n=== 匹配基线比较（{cmp['n_comparable_groups']}/{cmp['n_groups']} 组可比） ===")
    for g in cmp['groups']:
        if not g.get('comparable'):
            for w in g.get('warnings', []):
                print(f"  [skip] {w}")
            continue
        print(f"  匹配键: {json.dumps(g['match_key'], ensure_ascii=False)} 配对 seeds: {g.get('paired_seeds')}")
        for metric, r in g.get('comparisons', {}).items():
            es = r.get('effect_size', {}).get('rank_biserial')
            es_s = f"{es:+.3f}" if es is not None else '-'
            stat = r.get('statistic', r.get('U'))
            print(f"    {metric:<22} {r['test']:<12} stat={stat:<9.3f} p={r['p_value']:.4f} "
                  f"{'显著' if r['significant'] else '不显著'} r_rb={es_s} medΔ={r['median_diff']:+.4f}")


# ==================== CLI ====================

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='并行实验 sweep（多 seed × 多臂 + 统计聚合/配对检验）')
    parser.add_argument('--sweep-config', default=None, help='sweep YAML 配置路径')
    parser.add_argument('--runner', choices=list(VALID_RUNNERS), default=None,
                        help="执行器：'e2'(Simulator 逐 epoch) 或 'e3'(ControlPlane+DataPlane 末窗口)")
    parser.add_argument('--arm', action='append', type=parse_arm, default=[],
                        metavar='LABEL=CONFIG', help='臂定义（可多次）')
    parser.add_argument('--seeds', nargs='+', type=int, default=None, help='随机种子列表（支持 >=10）')
    parser.add_argument('--workers', type=int, default=None, help='并行进程数（spawn Pool）')
    parser.add_argument('--raw-dir', default=None, help='逐 seed raw JSON 输出目录')
    parser.add_argument('--agg-dir', default=None, help='聚合/对比输出目录')
    parser.add_argument('--subset-method', default=None,
                        help="跨 epoch 连通子集方法：cumulative_degree|stable_core")
    parser.add_argument('--attack', default=None, help='对比攻击臂 label')
    parser.add_argument('--baseline', default=None, help='对比基线臂 label')
    parser.add_argument('--strict-window', action='store_true',
                        help='攻击窗口与评估时刻无重叠时报错（默认仅告警）')
    parser.add_argument('--non-strict', action='store_true',
                        help='匹配键不一致时不抛错，仅标记不可比')
    parser.add_argument('--alpha', type=float, default=None)
    parser.add_argument('--n-boot', type=int, default=None)
    parser.add_argument('--dry-run', action='store_true',
                        help='仅校验配置/任务矩阵/攻击窗口，不加载 pkl、不跑仿真')
    args = parser.parse_args(argv)

    spec = build_spec(args)
    _, exit_code = run_sweep(spec, dry_run=args.dry_run)
    return exit_code


if __name__ == '__main__':
    mp.freeze_support()
    sys.exit(main())
