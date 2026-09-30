#!/usr/bin/env python
# scripts/run_e3_blackhole_experiment.py
"""
运行攻击实验（E3 黑洞）—— 统一 schema v2。
支持多攻击者类型、多 seed、配置驱动输出文件名。
"""

import os
import sys
import argparse
import pickle
import random
import logging
import json
import numpy as np
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from starlink_sim.net.simulator import ControlPlane, DataPlane
from starlink_sim.net.attack import (
    BlackholeAttacker,
    JammingAttacker,
    SybilAttacker,
    WormholeAttacker,
)
from starlink_sim.net.placement import (
    ATTACKER_CLASSES,
    instantiate_attackers,
    check_attack_windows,
    evaluation_times,
)
from starlink_sim.topology.subset import select_connected_subset
from starlink_sim.net.sybil import (
    expand_topology_for_sybils,
    compute_sybil_attraction,
)
from starlink_sim.net.wormhole import (
    expand_topology_for_wormholes,
    run_wormhole_detection,
)
from starlink_sim.io.config import load_experiment_config, get_attacker_configs

logger = logging.getLogger(__name__)


def _json_safe(obj):
    """递归把非有限浮点（inf/nan）→ None、numpy 标量 → python，确保严格 JSON 可序列化。
    仅用于输出落盘；active_until=.inf 归一为 None（语义等价：常驻）。"""
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


def load_topology_and_positions(topo_cache, pos_cache, shell, node_limit=None,
                                subset_method='cumulative_degree'):
    """加载拓扑缓存，可选跨 epoch 连通子集裁剪（替代旧 epoch-0 BFS）。"""
    with open(topo_cache, 'rb') as f:
        topo_data = pickle.load(f)
    shell_data = topo_data[shell]
    edges_by_epoch = shell_data['edges_per_epoch']

    # 位置缓存直接从 topology_results.pkl 读取
    positions_per_epoch = shell_data.get('positions_per_epoch', None)
    if pos_cache and os.path.exists(pos_cache):
        with open(pos_cache, 'rb') as f:
            pos_data = pickle.load(f)
        if isinstance(pos_data, dict) and shell in pos_data:
            positions_per_epoch = pos_data[shell]
        else:
            positions_per_epoch = pos_data
        print(f"Loaded positions from external cache {pos_cache}")

    # 跨 epoch 连通子集裁剪（node_limit=None 时全量）——替代旧 epoch-0 BFS。
    # 旧 BFS 仅在 epoch-0 上取前 node_limit 个节点，后续 epoch 可能碎裂（T7 实测
    # BFS-512 在部分 epoch 最大连通分量占比跌至 ~42%）；select_connected_subset 选出
    # 跨 epoch 累计度数高、逐 epoch 连通性更优的节点集。
    if node_limit is not None:
        node_set = set(select_connected_subset(edges_by_epoch, node_limit,
                                               method=subset_method))
        if node_set:
            print(f"跨epoch连通子集提取节点数: {len(node_set)} "
                  f"(目标: {node_limit}, 方法: {subset_method})")
            edges_by_epoch = [
                {(u, v) for u, v in edges if u in node_set and v in node_set}
                for edges in edges_by_epoch
            ]
            if positions_per_epoch and positions_per_epoch[0] is not None:
                positions_per_epoch = [
                    {n: pos[n] for n in node_set if n in pos}
                    for pos in positions_per_epoch
                ]
    else:
        node_set = set()
        for edges in edges_by_epoch:
            for u, v in edges:
                node_set.add(u)
                node_set.add(v)

    all_node_ids = sorted(node_set) if node_set else sorted(set(
        n for edges in edges_by_epoch for u, v in edges for n in (u, v)
    ))
    print(f"Loaded {len(all_node_ids)} nodes from {shell} shell")

    # 计算每个节点的度数（用于选择攻击者）
    degree_counter = Counter()
    for edges in edges_by_epoch:
        for u, v in edges:
            degree_counter[u] += 1
            degree_counter[v] += 1

    if positions_per_epoch is None:
        print(f"Warning: topology cache {topo_cache} has no positions_per_epoch "
              f"for shell {shell}. Latency will be 0.")
    elif positions_per_epoch and positions_per_epoch[0] is not None:
        print(f"Loaded positions for {len(positions_per_epoch)} epochs "
              f"({len(positions_per_epoch[0])} nodes at epoch 0)")

    return edges_by_epoch, positions_per_epoch, all_node_ids, degree_counter


# instantiate_attackers / create_attacker / ATTACKER_CLASSES 已迁移至
# starlink_sim.net.placement（统一放置模块，支持 degree/random/betweenness/k_core/
# last_epoch_degree 多策略），此处通过顶部 import 复用，消除与 run_e2 的重复实现。


def generate_flows(node_ids, num_flows, seed):
    rng = random.Random(seed)
    flows = []
    for _ in range(num_flows):
        src = rng.choice(node_ids)
        dst = rng.choice(node_ids)
        while dst == src:
            dst = rng.choice(node_ids)
        flows.append((src, dst))
    return flows


def run_experiment(seed, config, edges_by_epoch, positions_per_epoch, all_node_ids,
                   degree_counter=None):
    """运行单 seed E3 实验。

    修复（B1 epoch 语义）：旧版计算了 ``num_eval_epochs`` 却未传给 ``evaluate_flows``，
    且 ``DataPlane`` 只收到 ``[last_edges]`` 单个边集 → 数据面实际仅评估 1 个 epoch，
    与变量名/配置注释不符（trials 基数被低估）。现改为：评估窗口结束于
    ``last_epoch_idx``、长度 ``num_eval_epochs`` 的连续 epoch，并把该窗口的边集与
    ``num_epochs`` 一并传给 ``DataPlane.evaluate_flows``，使 trials 基数真实
    （``num_flows × num_eval_epochs``）、与 T6 统计框架兼容。
    """
    random.seed(seed)
    np.random.seed(seed)

    routing_config = config.get('routing', {})
    topo_config = config.get('topology', {})
    traffic_config = config.get('traffic', {})
    exp_config = config.get('experiment', {})

    tick_interval = routing_config.get('tick', 0.2)
    epoch_duration = topo_config.get('epoch_interval', 30.0)
    duration = exp_config.get('duration', 60)
    adv_interval = routing_config.get('t_adv', 2.0)
    max_hops = routing_config.get('max_hops', 100)
    num_ticks = int(duration / tick_interval)

    # 计算最后一个 epoch 索引和起始时间
    last_epoch_idx = int(duration / epoch_duration) - 1
    if last_epoch_idx < 0:
        last_epoch_idx = 0
    if last_epoch_idx >= len(edges_by_epoch):
        last_epoch_idx = len(edges_by_epoch) - 1
    last_epoch_start_time = last_epoch_idx * epoch_duration
    print(f"Using last epoch index {last_epoch_idx}, start time = {last_epoch_start_time:.1f}s")

    # 创建攻击者（统一放置模块；默认 'degree' 策略与既有行为逐位一致）
    att_configs = get_attacker_configs(config)
    attackers = instantiate_attackers(att_configs, edges_by_epoch, seed,
                                      available_nodes=all_node_ids)

    # ---- E6 Wormhole 隧道注入（不扩展节点 ID 空间，必须在 ControlPlane 构建之前）----
    # 虫洞连接两个**既有真实节点** A、B：只把隧道边 (A,B) 写入每个 epoch 的
    # edge_sets，num_nodes 不变。放在 Sybil 注入**之前**，使虫洞端点只在真实节点中选取，
    # Sybil 随后在虫洞增强后的边集上附着。无 Wormhole 攻击者时原样返回（既有行为不变）。
    edges_by_epoch, all_node_ids, wormhole_injections = expand_topology_for_wormholes(
        attackers, edges_by_epoch, all_node_ids, positions_per_epoch, seed=seed)
    wormhole_tunnels = sorted({t for inj in wormhole_injections for t in inj.tunnels})
    wormhole_tunnel_km = {t: km for inj in wormhole_injections
                          for t, km in inj.tunnel_km.items()}
    if wormhole_tunnels:
        km_txt = ', '.join(f"{t}: {wormhole_tunnel_km.get(t, float('nan')):.0f} km"
                           for t in wormhole_tunnels)
        print(f"[wormhole] 注入 {len(wormhole_tunnels)} 条隧道边: {wormhole_tunnels} "
              f"({km_txt})；节点空间保持 {len(all_node_ids)}")

    # ---- E4 Sybil 身份注入（节点 ID 空间扩展，必须在 ControlPlane 构建之前）----
    # 虚假身份是新节点：扩大 num_nodes 并把身份->附着点的新边写入每个 epoch 的 edge_sets，
    # 同时把身份 ID 绑定回 SybilAttacker。无 Sybil 攻击者时原样返回（既有行为不变）。
    # 数据流端点仅用**真实节点**（real_node_ids），虚假身份只作为牵引基础设施。
    real_node_ids = list(all_node_ids)
    edges_by_epoch, all_node_ids, sybil_injections = expand_topology_for_sybils(
        attackers, edges_by_epoch, all_node_ids, seed=seed)
    sybil_node_ids = sorted({sid for inj in sybil_injections for sid in inj.sybil_node_ids})
    if sybil_node_ids:
        print(f"[sybil] 注入 {len(sybil_node_ids)} 个虚假身份: {sybil_node_ids} "
              f"(节点空间 {len(real_node_ids)} → {len(all_node_ids)})")

    # ---- E6 虫洞检测门控：存在虫洞攻击臂，或配置显式要求跑检测（匹配基线臂用它
    # 测**误报率**）。默认关闭 → 所有既有配置/记录不含任何 wormhole 键（纯附加）。
    det_cfg = config.get('detection', {}).get('wormhole') or {}
    has_wormhole_attacker = any(isinstance(a, WormholeAttacker) for a in attackers)
    wormhole_detection_enabled = bool(wormhole_tunnels) or has_wormhole_attacker \
        or bool(det_cfg.get('enabled', False))

    # 初始化控制面（wire adv_interval）
    num_total = max(all_node_ids) + 1 if all_node_ids else 0
    control = ControlPlane(num_nodes=num_total, tick_interval=tick_interval,
                           attackers=attackers, adv_interval=adv_interval)
    print(f"Running control plane with {len(attackers)} attackers for {num_ticks} ticks...")
    control.run_ticks(num_ticks, edges_by_epoch, epoch_duration)

    routing_tables = control.get_routing_tables()
    print(f"Final routing tables contain {len(routing_tables)} nodes")

    # 检查攻击者是否在最后一个边集中
    last_edges = edges_by_epoch[last_epoch_idx]
    for att in attackers:
        in_edges = any(att.node_id == u or att.node_id == v for u, v in last_edges)
        print(f"Attacker {att.node_id} present in last epoch edges: {in_edges}")

    # 生成数据流（端点仅用真实节点；Sybil 虚假身份不作为流的源/宿）
    num_flows = traffic_config.get('num_flows', 100)
    flows = generate_flows(real_node_ids, num_flows, seed)

    # ---- 数据面评估（B1 修复：评估窗口 = 结束于 last_epoch_idx 的 num_eval_epochs 个连续 epoch）----
    # 与 e2/Simulator 的 duration//epoch_interval 约定对齐：last_epoch_idx = duration/epoch_interval - 1，
    # 评估窗口 [start_epoch_idx, last_epoch_idx]，base_time = start_epoch_idx * epoch_duration，
    # 使每个评估 epoch 的攻击者活跃判定时刻与真实仿真时间一致。
    num_eval_epochs = max(1, min(last_epoch_idx + 1, len(edges_by_epoch)))
    start_epoch_idx = max(0, last_epoch_idx - num_eval_epochs + 1)
    eval_edges = edges_by_epoch[start_epoch_idx:last_epoch_idx + 1]
    num_eval_epochs = len(eval_edges)  # 实际可用 epoch 数（防越界）
    base_time = start_epoch_idx * epoch_duration
    if positions_per_epoch is not None:
        positions_slice = positions_per_epoch[start_epoch_idx:last_epoch_idx + 1]
    else:
        positions_slice = None
    print(f"数据面评估窗口: epoch [{start_epoch_idx}..{last_epoch_idx}] 共 {num_eval_epochs} 个, "
          f"base_time={base_time:.1f}s")

    # ---- 攻击窗口守卫（B3）：校验攻击者在评估时刻至少有一个 epoch 活跃 ----
    eval_times = evaluation_times(base_time, num_eval_epochs, epoch_duration)
    for w in check_attack_windows(att_configs, eval_times, strict=False):
        print(f"[attack-window-guard] {w}")

    data_plane = DataPlane(routing_tables, eval_edges, attackers=attackers,
                           max_hops=max_hops)
    data_stats = data_plane.evaluate_flows(
        flows,
        positions_per_epoch=positions_slice,
        epoch_duration=epoch_duration,
        base_time=base_time,
        num_epochs=num_eval_epochs,
    )

    # ---- E4 Sybil 指标：吸引的流量占比（转发链经过虚假身份的 flow-epoch 比例）----
    # 容忍环路追踪（sybil.trace_forwarding_nodes）：虚假身份伪造低 metric 常致 R→I→R 环，
    # 普通 compute_path 遇环返回 None 会丢失"流量曾被牵引"这一事实，故用专用追踪器度量。
    sybil_stats = None
    if sybil_node_ids:
        sybil_attraction = compute_sybil_attraction(
            flows, sybil_node_ids, [routing_tables] * num_eval_epochs,
            eval_edges, num_eval_epochs, max_hops)
        data_stats['sybil_attraction_ratio'] = sybil_attraction['sybil_attraction_ratio']
        data_stats['sybil_attracted_trials'] = sybil_attraction['sybil_attracted_trials']
        data_stats['sybil_num_identities'] = len(sybil_node_ids)
        sybil_stats = {
            'num_identities': len(sybil_node_ids),
            'sybil_node_ids': sorted(sybil_node_ids),
            'attraction_ratio': sybil_attraction['sybil_attraction_ratio'],
            'attracted_trials': sybil_attraction['sybil_attracted_trials'],
            'total_trials': sybil_attraction['sybil_total_trials'],
            'injections': [
                {
                    'controller_node': inj.controller_node,
                    'attachment': inj.attachment,
                    'num_identities': inj.num_identities,
                    'sybil_node_ids': inj.sybil_node_ids,
                    'attachment_map': {str(k): v for k, v in inj.attachment_map.items()},
                    'targets': inj.targets,
                } for inj in sybil_injections
            ],
        }

    # ---- E6 Wormhole 指标：物理接地检测 + 牵引占比 + path/geo stretch ----
    # 与 Sybil 同口径：用容忍环路的专用追踪器度量"流量是否用了隧道这一跳"；
    # 另叠加两条相互独立的检测信号（距离不一致 / 时延-跳数不一致）。
    # 基线臂（无隧道但启用检测）只发射 WORMHOLE_BASELINE_KEYS，用于测误报率。
    wormhole_stats = None
    if wormhole_detection_enabled:
        wh = run_wormhole_detection(
            wormhole_tunnels, flows, [routing_tables] * num_eval_epochs,
            eval_edges, num_eval_epochs,
            positions_per_epoch=positions_slice,
            max_hops=max_hops,
            max_isl_km=float(det_cfg.get('max_isl_km', 2000.0)),
            distance_factor=float(det_cfg.get('distance_factor', 1.5)),
            adaptive_factor=det_cfg.get('adaptive_factor', 3.0),
            latency_factor=float(det_cfg.get('latency_factor', 1.0)),
            tunnel_km=wormhole_tunnel_km, injections=wormhole_injections)
        data_stats.update(wh['data_stats'])
        wormhole_stats = wh['stats']
        print(f"[wormhole] detection: tunnels={wormhole_stats['num_tunnels']} "
              f"detected={wormhole_stats['detected_tunnels']} "
              f"rate={wormhole_stats['detection_rate']} "
              f"fp_rate={wormhole_stats['false_positive_rate']:.4f} "
              f"attracted={wormhole_stats['attracted_ratio']:.4f} "
              f"path_stretch={wormhole_stats['path_stretch']:.3f} "
              f"geo_stretch={wormhole_stats['geo_stretch']:.3f} "
              f"available={wormhole_stats['detector_available']}")

    attacker_stats = []
    for att in attackers:
        attacker_stats.append({
            'node_id': att.node_id,
            'attracted_count': att.attracted_count,
            'dropped_count': att.dropped_count,
        })

    control_stats = {
        'total_loops': control.total_loops,
        'loop_paths_count': len(control.loop_paths),
    }

    # ---- 基数元数据（与 T6 统计框架兼容：extract_match_key 优先读 metadata）----
    total_trials = int(data_stats.get('num_trials', num_flows * num_eval_epochs))
    metadata = {
        'schema_version': 2,
        'seed': seed,
        'shell': topo_config.get('shell'),
        'node_limit': topo_config.get('node_limit'),
        'num_nodes': len(all_node_ids),
        'num_eval_epochs': int(num_eval_epochs),
        'num_flows': int(num_flows),
        'trials_per_flow_epoch': 1,
        'total_trials': total_trials,
        'base_time': float(base_time),
        'start_epoch_idx': int(start_epoch_idx),
        'last_epoch_idx': int(last_epoch_idx),
        'runner': 'e3_blackhole',
        'cardinality_semantics': 'total_trials = num_flows × num_eval_epochs × trials_per_flow_epoch',
    }
    if sybil_node_ids:
        # Sybil 臂：节点空间已扩展（num_nodes 含虚假身份）；匹配键 (shell/node_limit/
        # num_eval_epochs/num_flows) 不受影响，故仍与同配置基线臂可比。
        metadata['sybil_injected'] = True
        metadata['sybil_num_identities'] = len(sybil_node_ids)
        metadata['num_real_nodes'] = len(real_node_ids)
    if wormhole_detection_enabled:
        # Wormhole 臂/启用检测的基线臂：隧道两端均为真实节点，num_nodes **不变**，
        # 匹配键同样不受影响（不含任何 wormhole 键）。
        metadata['wormhole_detection_enabled'] = True
        metadata['wormhole_num_tunnels'] = len(wormhole_tunnels)
        metadata['wormhole_detector_available'] = bool(
            wormhole_stats and wormhole_stats['detector_available'])
        if wormhole_tunnels:
            metadata['wormhole_injected'] = True
            metadata['wormhole_tunnels'] = [list(t) for t in wormhole_tunnels]
            metadata['wormhole_mean_tunnel_km'] = float(
                wormhole_stats['mean_tunnel_km']) if wormhole_stats else None
            metadata['num_real_nodes'] = len(real_node_ids)

    result = {
        'schema_version': 2,
        'experiment': exp_config.get('name', 'e3_blackhole'),
        'seed': seed,
        'metadata': metadata,
        'config': config,
        'control_stats': control_stats,
        'data_stats': data_stats,
        'attacker_stats': attacker_stats,
    }
    if sybil_stats is not None:
        result['sybil_stats'] = sybil_stats
    if wormhole_stats is not None:
        result['wormhole_stats'] = wormhole_stats
    return result


def aggregate_results(results):
    delivery_ratios = [r['data_stats']['delivery_ratio'] for r in results]
    avg_hops = [r['data_stats']['avg_hops'] for r in results]
    avg_latency = [r['data_stats']['avg_latency_ms'] for r in results]
    attacked_counts = [r['data_stats']['attacked_count'] for r in results]
    dropped_counts = [r['data_stats']['dropped_by_attacker'] for r in results]
    total_loops = [r['control_stats']['total_loops'] for r in results]

    return {
        'mean_delivery_ratio': float(np.mean(delivery_ratios)),
        'std_delivery_ratio': float(np.std(delivery_ratios)),
        'mean_avg_hops': float(np.mean(avg_hops)),
        'mean_avg_latency_ms': float(np.mean(avg_latency)),
        'mean_attacked_count': float(np.mean(attacked_counts)),
        'mean_dropped_by_attacker': float(np.mean(dropped_counts)),
        'mean_total_loops': float(np.mean(total_loops)),
        'num_seeds': len(results)
    }


def main():
    parser = argparse.ArgumentParser(description='Run attack experiments (unified schema)')
    parser.add_argument('--config', required=True, help='Path to experiment YAML')
    parser.add_argument('--seeds', nargs='+', type=int, default=[42], help='List of random seeds')
    parser.add_argument('--output', default=None, help='Output directory (overrides config)')
    args = parser.parse_args()

    config = load_experiment_config(args.config)
    exp_name = config['experiment']['name']
    topo_config = config['topology']

    edges_by_epoch, positions_per_epoch, all_node_ids, degree_counter = load_topology_and_positions(
        topo_cache=topo_config['cache_path'],
        pos_cache=topo_config.get('positions_cache'),
        shell=topo_config['shell'],
        node_limit=topo_config.get('node_limit'),
        subset_method=topo_config.get('subset_method', 'cumulative_degree'),
    )

    # 输出目录：命令行 > config > 默认
    out_dir = Path(args.output) if args.output else Path(config['output']['raw_dir'])
    out_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    for seed in args.seeds:
        logger.info(f"Running seed {seed}")
        result = run_experiment(seed, config, edges_by_epoch, positions_per_epoch, all_node_ids, degree_counter)
        # 输出文件名依据 config 的 experiment name（避免不同攻击类型互相覆盖）
        seed_file = out_dir / f"{exp_name}_seed{seed}.json"
        with open(seed_file, 'w', encoding='utf-8') as f:
            json.dump(_json_safe(result), f, indent=2, ensure_ascii=False)
        all_results.append(result)

    aggregated = aggregate_results(all_results)
    agg_file = out_dir / f"aggregated_{exp_name}.json"
    with open(agg_file, 'w', encoding='utf-8') as f:
        json.dump(_json_safe(aggregated), f, indent=2)

    logger.info(f"All done. Results saved to {out_dir}")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
