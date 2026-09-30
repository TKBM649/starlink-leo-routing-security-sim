# scripts/run_simulation.py
"""
E1 基线仿真（无攻击）—— 统一 schema v2，支持多 seed 重标定。

用法（仓库根目录运行）：
    python scripts/run_simulation.py --seeds 42 43 44
    python scripts/run_simulation.py --config configs/experiments/e1_baseline.yaml \
        --seeds 42 43 44 45 46 47 48 49 50 51

产出：
1. 逐 seed raw JSON：{output.raw_dir}/{experiment.name}_seed{seed}.json，
   内嵌完整 config 快照 + 运行元数据（seed、shell、节点数、评估 epoch 数、
   flows 数、trials 基数三元组、t0、TLE/拓扑缓存 SHA256、代码版本、时间戳）；
2. 聚合摘要（多 seed mean±std + bootstrap 95% CI）：
   {output.agg_dir}/simulation_summary.json（canonical E1 基线路径，
   顶层保留 delivery_ratio/avg_hops/avg_latency_ms 等旧键 = 跨 seed 均值，
   与 analyze_e3_results.py 的读取方式向后兼容）。

命令行覆盖项（便于小样验证）：--node-limit / --duration / --num-flows /
--raw-dir / --agg-dir；--node-limit 传 -1 表示全量节点（null）。

断点续跑：--skip-existing 会跳过「已存在且完整」的逐 seed raw JSON
（完整 = 可解析 + schema_version==2 + data_stats.num_trials>0 + 匹配键齐全），
因此长时作业被打断后重跑同一命令即可续跑，不会重算已完成的 seed。

子集方法：--subset-method 默认 ``bfs``（历史行为，逐位不变）；传
``cumulative_degree`` / ``stable_core`` 时改走 starlink_sim.topology.subset，
以便与 run_experiment_sweep 的攻击矩阵**用同一批节点**（否则两者的
node_limit=1024 会选到不同子集，基线与攻击臂不可比）。
"""
import sys
import json
import random
import hashlib
import argparse
import pickle
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from starlink_sim.io.config import load_experiment_config
from starlink_sim.net.simulator import Simulator
from starlink_sim.analytics.stats import aggregate_experiment

DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "experiments" / "e1_baseline.yaml"
# 仿真起始时刻（与 build_topology 的 t0 一致）
T0 = (2026, 8, 22, 10, 13, 50)


# ==================== 元数据工具 ====================

def _sha256_file(path: Optional[Path], chunk_size: int = 1 << 20) -> Optional[str]:
    """流式计算文件 SHA256（大文件如 102.8MB 拓扑缓存亦可）；文件不存在返回 None。"""
    if path is None or not Path(path).exists():
        return None
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _git_commit() -> Optional[str]:
    try:
        out = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=str(PROJECT_ROOT),
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def build_run_metadata(seed: int, config: dict, num_nodes: int,
                       num_eval_epochs: int, num_flows: int,
                       total_trials: int, tle_path: Optional[Path] = None,
                       topo_cache_path: Optional[Path] = None) -> dict:
    """构造运行元数据（含 trials 基数三元组语义，供统计框架校验可比性）。"""
    topo = config.get('topology', {})
    return {
        'schema_version': 2,
        'seed': seed,
        'timestamp_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'git_commit': _git_commit(),
        'python_version': sys.version.split()[0],
        'shell': topo.get('shell'),
        'node_limit': topo.get('node_limit'),
        'num_nodes': int(num_nodes),
        'num_eval_epochs': int(num_eval_epochs),
        'num_flows': int(num_flows),
        'trials_per_flow_epoch': 1,
        'total_trials': int(total_trials),
        'cardinality_semantics': 'total_trials = num_flows × num_eval_epochs × trials_per_flow_epoch',
        # 子集选取方法：'bfs'（历史默认）或 'cumulative_degree'/'stable_core'
        # （与 run_experiment_sweep 同口径）。缺失时按 'bfs' 解读以兼容旧 raw。
        'subset_method': topo.get('subset_method', 'bfs'),
        't0': {'year': T0[0], 'month': T0[1], 'day': T0[2],
               'hour': T0[3], 'minute': T0[4], 'second': T0[5]},
        'tle_sha256': _sha256_file(tle_path),
        'topology_cache_sha256': _sha256_file(topo_cache_path),
        'topology_cache': str(topo_cache_path) if topo_cache_path else None,
    }


# ==================== 拓扑加载 ====================

def load_topology(topo_cache: str, shell: str,
                  node_limit: Optional[int],
                  subset_method: str = 'bfs') -> Tuple[List[Set[Tuple[int, int]]],
                                                       Optional[list], List[int], Counter]:
    """从 pkl 缓存加载拓扑（含 positions_per_epoch，T4 修复产物），可选子集裁剪。

    ``subset_method='bfs'``（默认）：保持历史行为逐位不变 —— 按第一个 epoch 的
    邻接表从任意起点 BFS 取前 node_limit 个节点（不保证跨 epoch 连通）。
    ``'cumulative_degree'`` / ``'stable_core'``：改走 subset.select_connected_subset，
    与攻击矩阵（run_experiment_sweep 的 spec.subset_method）选出**同一批节点**。
    """
    cache = Path(topo_cache)
    if not cache.exists():
        raise FileNotFoundError(f"拓扑缓存未找到: {cache}，请先运行 scripts/build_topology.py")
    with open(cache, 'rb') as f:
        topo_data = pickle.load(f)
    if shell not in topo_data:
        raise ValueError(f"Shell '{shell}' 不在缓存中，可用: {list(topo_data.keys())}")
    shell_data = topo_data[shell]
    edges_by_epoch = shell_data['edges_per_epoch']
    positions_per_epoch = shell_data.get('positions_per_epoch', None)

    if node_limit is not None:
        if subset_method in ('cumulative_degree', 'stable_core'):
            from starlink_sim.topology.subset import select_connected_subset
            node_set = set(select_connected_subset(
                edges_by_epoch, node_limit, method=subset_method))
            if not node_set:
                raise RuntimeError(f"select_connected_subset(method={subset_method}) "
                                   f"返回空子集，无法继续")
            print(f"[{subset_method}] 跨 epoch 连通子集节点数: {len(node_set)} "
                  f"(target={node_limit})")
        else:
            first_edges = edges_by_epoch[0]
            adj: Dict[int, Set[int]] = {}
            for u, v in first_edges:
                adj.setdefault(u, set()).add(v)
                adj.setdefault(v, set()).add(u)
            if not adj:
                raise RuntimeError("第一个 epoch 无边，无法提取连通子图")
            start_node = next(iter(adj))
            queue = [start_node]
            visited = {start_node}
            while queue and len(visited) < node_limit:
                node = queue.pop(0)
                for nb in adj.get(node, []):
                    if nb not in visited:
                        visited.add(nb)
                        queue.append(nb)
                        if len(visited) >= node_limit:
                            break
            node_set = visited
            print(f"BFS 提取节点数: {len(node_set)} (图中总节点数: {len(adj)})")
        edges_by_epoch = [{(u, v) for u, v in edges if u in node_set and v in node_set}
                          for edges in edges_by_epoch]
        if positions_per_epoch and positions_per_epoch[0] is not None:
            positions_per_epoch = [{n: pos[n] for n in node_set if n in pos}
                                   for pos in positions_per_epoch]
    else:
        node_set = set()
        for edges in edges_by_epoch:
            for u, v in edges:
                node_set.add(u)
                node_set.add(v)
        print(f"使用全量节点: {len(node_set)}")

    all_node_ids = sorted(node_set)
    degree_counter = Counter()
    for edges in edges_by_epoch:
        for u, v in edges:
            degree_counter[u] += 1
            degree_counter[v] += 1
    return edges_by_epoch, positions_per_epoch, all_node_ids, degree_counter


def generate_flows(node_ids: List[int], num_flows: int, seed: int) -> List[Tuple[int, int]]:
    """按 seed 生成随机流对（替换旧版 :126 硬编码 random.seed(42)）。"""
    rng = random.Random(seed)
    flows = []
    for _ in range(num_flows):
        src = rng.choice(node_ids)
        dst = rng.choice(node_ids)
        while dst == src:
            dst = rng.choice(node_ids)
        flows.append((src, dst))
    return flows


# ==================== 单 seed 运行 ====================

def run_one_seed(seed: int, config: dict, edges_by_epoch, positions_per_epoch,
                 all_node_ids: List[int],
                 tle_path: Optional[Path] = None,
                 topo_cache_path: Optional[Path] = None) -> dict:
    """运行单个 seed 的 E1 基线仿真，返回逐 seed raw JSON 记录（dict）。"""
    random.seed(seed)
    np.random.seed(seed)

    routing_config = config['routing']
    topo_config = config['topology']
    traffic_config = config['traffic']
    exp_config = config['experiment']

    num_flows = traffic_config['num_flows']
    flows = generate_flows(all_node_ids, num_flows, seed)
    num_nodes = max(all_node_ids) + 1 if all_node_ids else 0

    sim = Simulator(
        edge_sets=edges_by_epoch,
        positions_per_epoch=positions_per_epoch,
        num_nodes=num_nodes,
        tick_interval=routing_config['tick'],
        attackers=[],  # E1 基线：无攻击
        flow_pairs=flows,
        epoch_duration=topo_config['epoch_interval'],
        base_time=0.0,
        adv_interval=routing_config['t_adv'],
        max_hops=routing_config['max_hops'],
    )
    duration = exp_config['duration']
    print(f"[seed {seed}] 运行 E1 基线仿真 {duration}s（{num_nodes} 节点路由域, {num_flows} flows）...")
    results = sim.run(duration=duration)

    # 实际评估的 epoch 数（与 Simulator.run 内部一致），用于 trials 基数记录
    num_eval_epochs = min(len(edges_by_epoch), max(1, int(duration // topo_config['epoch_interval'])))
    loop_paths = results.pop('loop_paths', [])
    data_stats = {k: v for k, v in results.items()
                  if k not in ('total_loops', 'attacker_stats')}

    metadata = build_run_metadata(
        seed=seed, config=config, num_nodes=num_nodes,
        num_eval_epochs=num_eval_epochs, num_flows=num_flows,
        total_trials=int(data_stats.get('num_trials', 0)),
        tle_path=tle_path, topo_cache_path=topo_cache_path)

    return {
        'schema_version': 2,
        'experiment': exp_config['name'],
        'seed': seed,
        'metadata': metadata,
        'config_snapshot': config,
        'control_stats': {
            'total_loops': int(results.get('total_loops', 0)),
            'loop_paths_count': len(loop_paths),
        },
        'data_stats': data_stats,
        'flows': flows,
    }


# ==================== 多 seed 聚合摘要 ====================

def build_aggregate_summary(raw_files: List[Path], num_nodes: int) -> dict:
    """跨 seed 聚合（mean±std + bootstrap 95% CI），并保留旧版顶层键向后兼容。"""
    agg = aggregate_experiment(raw_files, n_boot=2000, rng=0)
    metrics = agg['metrics']

    def _mean(name, default=None):
        return metrics[name]['mean'] if name in metrics else default

    summary = {
        'num_nodes': num_nodes,
        'num_seeds': agg['n_seeds'],
        'seeds': agg['seeds'],
        'per_seed': agg['per_seed'],
        'cardinality': agg['cardinality'],
        'metrics': metrics,
        'warnings': agg['warnings'],
        # ---- 向后兼容旧键（analyze_e3_results.py / 文档引用）：跨 seed 均值 ----
        'num_epochs': agg['cardinality']['match_key']['num_eval_epochs'] if agg['cardinality']['match_key'] else None,
        'loop_events_count': _mean('total_loops', 0),
        'delivery_ratio': _mean('delivery_ratio'),
        'avg_hops': _mean('avg_hops'),
        'avg_latency_ms': _mean('avg_latency_ms'),
        'avg_success_hops': _mean('avg_success_hops'),
        'avg_success_latency_ms': _mean('avg_success_latency_ms'),
        'num_success': _mean('num_success'),
        'num_trials': _mean('num_trials'),
    }
    return summary


# ==================== 断点续跑：raw 完整性判定 ====================

def raw_is_complete(path: Path) -> bool:
    """已落盘的逐 seed raw JSON 是否「完整可用」（断点续跑的判据）。

    完整的定义（缺一不可）：文件可解析为 JSON、``schema_version == 2``、
    ``data_stats.num_trials > 0``、匹配键四字段（shell / node_limit /
    num_eval_epochs / num_flows）均存在。写一半就被打断的文件（进程被 kill
    时 json.dump 只写了前半个）会在此被识别为不完整 → 重跑该 seed。
    """
    if not path.exists():
        return False
    try:
        with open(path, 'r', encoding='utf-8') as f:
            rec = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False
    if rec.get('schema_version') != 2:
        return False
    ds = rec.get('data_stats') or {}
    if not (ds.get('num_trials') or 0) > 0:
        return False
    md = rec.get('metadata') or {}
    return all(k in md for k in ('shell', 'node_limit', 'num_eval_epochs', 'num_flows'))


# ==================== 主入口 ====================

def main(argv: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(description='E1 基线仿真（统一 schema，多 seed 重标定）')
    parser.add_argument('--config', default=str(DEFAULT_CONFIG),
                        help=f'实验配置 YAML（默认 {DEFAULT_CONFIG}）')
    parser.add_argument('--seeds', nargs='+', type=int, default=None,
                        help='随机种子列表，如 --seeds 42 43 44（默认取 config seed 或 42）')
    parser.add_argument('--node-limit', type=int, default=None,
                        help='覆盖 topology.node_limit（-1 = 全量 null）')
    parser.add_argument('--duration', type=float, default=None,
                        help='覆盖 experiment.duration（秒）')
    parser.add_argument('--num-flows', type=int, default=None,
                        help='覆盖 traffic.num_flows')
    parser.add_argument('--raw-dir', default=None, help='覆盖 output.raw_dir')
    parser.add_argument('--agg-dir', default=None, help='覆盖 output.agg_dir')
    parser.add_argument('--no-aggregate', action='store_true',
                        help='不写聚合摘要 simulation_summary.json（小样验证时避免覆盖 canonical E1 基线）')
    parser.add_argument('--subset-method', default='bfs',
                        choices=['bfs', 'cumulative_degree', 'stable_core'],
                        help='node_limit 子集选取法；bfs=历史行为（默认），'
                             'cumulative_degree/stable_core=与攻击矩阵同口径')
    parser.add_argument('--skip-existing', action='store_true',
                        help='跳过已存在且完整的逐 seed raw JSON（断点续跑）')
    args = parser.parse_args(argv)

    config = load_experiment_config(args.config)
    # 命令行覆盖（仅改内存副本，config 快照记录覆盖后的生效值）
    if args.node_limit is not None:
        config['topology']['node_limit'] = None if args.node_limit < 0 else args.node_limit
    if args.duration is not None:
        config['experiment']['duration'] = args.duration
    if args.num_flows is not None:
        config['traffic']['num_flows'] = args.num_flows
    if args.raw_dir is not None:
        config['output']['raw_dir'] = args.raw_dir
    if args.agg_dir is not None:
        config['output']['agg_dir'] = args.agg_dir
    # 子集方法写入 config 副本 → 同时进入 config_snapshot 与 metadata（可追溯）
    config['topology']['subset_method'] = args.subset_method

    seeds = args.seeds
    if not seeds:
        cfg_seed = config['experiment'].get('seed')
        seeds = [int(cfg_seed)] if cfg_seed is not None else [42]

    topo_config = config['topology']
    topo_cache_path = Path(topo_config['cache_path'])
    tle_path = Path('data/tle/starlink.tle')

    edges_by_epoch, positions_per_epoch, all_node_ids, _ = load_topology(
        topo_cache=topo_config['cache_path'],
        shell=topo_config['shell'],
        node_limit=topo_config.get('node_limit'),
        subset_method=args.subset_method)
    num_nodes = max(all_node_ids) + 1 if all_node_ids else 0
    print(f"Shell {topo_config['shell']}: {len(edges_by_epoch)} epochs 可用, "
          f"路由域节点上限 {num_nodes}")

    raw_dir = Path(config['output']['raw_dir'])
    raw_dir.mkdir(parents=True, exist_ok=True)
    exp_name = config['experiment']['name']

    raw_files: List[Path] = []
    skipped: List[int] = []
    for seed in seeds:
        out_file = raw_dir / f"{exp_name}_seed{seed}.json"
        if args.skip_existing and raw_is_complete(out_file):
            skipped.append(seed)
            raw_files.append(out_file)
            print(f"[seed {seed}] 跳过（raw 已存在且完整）→ {out_file}")
            continue
        record = run_one_seed(seed, config, edges_by_epoch, positions_per_epoch,
                              all_node_ids, tle_path=tle_path,
                              topo_cache_path=topo_cache_path)
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(record, f, indent=2, ensure_ascii=False)
        raw_files.append(out_file)
        ds = record['data_stats']
        print(f"[seed {seed}] DR={ds['delivery_ratio']:.4f} hops={ds['avg_hops']:.2f} "
              f"latency={ds['avg_latency_ms']:.2f}ms trials={ds['num_trials']} "
              f"loops={record['control_stats']['total_loops']} → {out_file}")
    if skipped:
        print(f"[resume] 共跳过 {len(skipped)} 个已完成 seed：{skipped}")

    if not args.no_aggregate:
        summary = build_aggregate_summary(raw_files, num_nodes)
        agg_dir = Path(config['output']['agg_dir'])
        agg_dir.mkdir(parents=True, exist_ok=True)
        agg_file = agg_dir / 'simulation_summary.json'
        with open(agg_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        print(f"\n聚合摘要（{len(seeds)} seeds）→ {agg_file}")
        for w in summary.get('warnings', []):
            print(f"  [warn] {w}")
        if summary.get('delivery_ratio') is not None:
            m = summary['metrics']
            dr = m['delivery_ratio']
            ci = (f" [{dr['ci95_low']:.4f}, {dr['ci95_high']:.4f}]"
                  if dr.get('ci95_low') is not None else "")
            print(f"  delivery_ratio = {dr['mean']:.4f} ± {dr['std']:.4f}{ci}")

    print("Simulation completed.")


if __name__ == "__main__":
    main()
