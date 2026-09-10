#!/usr/bin/env python
# scripts/run_attack_experiment.py
"""
运行攻击实验（E3 黑洞），修复攻击时间问题。
"""

import os
import sys
import argparse
import yaml
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
from starlink_sim.net.attack import BlackholeAttacker, JammingAttacker, SybilAttacker

logger = logging.getLogger(__name__)

ATTACKER_CLASSES = {
    'blackhole': BlackholeAttacker,
    'jamming': JammingAttacker,
    'sybil': SybilAttacker,
}

def load_topology_and_positions(topo_cache, pos_cache, shell):
    with open(topo_cache, 'rb') as f:
        topo_data = pickle.load(f)
    shell_data = topo_data[shell]
    edges_by_epoch = shell_data['edges_per_epoch']
    num_epochs = shell_data['num_epochs']

    node_set = set()
    for edges in edges_by_epoch:
        for u, v in edges:
            node_set.add(u)
            node_set.add(v)
    all_node_ids = sorted(list(node_set))
    print(f"Loaded {len(all_node_ids)} nodes from {shell} shell")

    # 计算每个节点的度数（用于选择攻击者）
    degree_counter = Counter()
    for edges in edges_by_epoch:
        for u, v in edges:
            degree_counter[u] += 1
            degree_counter[v] += 1

    positions_per_epoch = None
    if os.path.exists(pos_cache):
        with open(pos_cache, 'rb') as f:
            pos_data = pickle.load(f)
        if isinstance(pos_data, dict) and shell in pos_data:
            positions_per_epoch = pos_data[shell]
        else:
            positions_per_epoch = pos_data
    else:
        print(f"Warning: positions cache {pos_cache} not found. Latency will be omitted.")
    return edges_by_epoch, positions_per_epoch, all_node_ids, degree_counter

def instantiate_attackers(att_configs, available_nodes, degree_counter, seed):
    attackers = []
    rng = random.Random(seed)
    for cfg in att_configs:
        att_type = cfg['type']
        if 'params' in cfg:
            params = cfg['params'].copy()
        else:
            params = {}
        for key in ['drop_prob', 'metric_fake', 'active_since', 'active_until', 'count']:
            if key in cfg and key not in params:
                params[key] = cfg[key]
        if cfg.get('node_id') is not None:
            selected = [cfg['node_id']]
        else:
            count = params.get('count', 1)
            # 选择度数最高的前 count 个节点
            sorted_nodes = sorted(degree_counter.items(), key=lambda x: x[1], reverse=True)
            top_nodes = [nid for nid, _ in sorted_nodes[:count]]
            # 如果可用节点不足，则从可用节点中随机选
            if len(top_nodes) < count:
                top_nodes = rng.sample(available_nodes, min(count, len(available_nodes)))
            selected = top_nodes
        for nid in selected:
            att_class = ATTACKER_CLASSES.get(att_type)
            if not att_class:
                raise ValueError(f"Unknown attacker type: {att_type}")
            att_params = {k: v for k, v in params.items() if k != 'count'}
            attacker = att_class(node_id=nid, **att_params)
            attackers.append(attacker)
    return attackers

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

def run_experiment(seed, config, edges_by_epoch, positions_per_epoch, all_node_ids, degree_counter):
    random.seed(seed)
    np.random.seed(seed)

    tick_interval = config.get('control_tick', 0.2)
    epoch_duration = config.get('topology_epoch', 30.0)
    duration = config.get('duration', 60)
    num_ticks = int(duration / tick_interval)

    # 计算最后一个 epoch 索引和起始时间
    last_epoch_idx = int(duration / epoch_duration) - 1
    if last_epoch_idx < 0:
        last_epoch_idx = 0
    if last_epoch_idx >= len(edges_by_epoch):
        last_epoch_idx = len(edges_by_epoch) - 1
    last_epoch_start_time = last_epoch_idx * epoch_duration
    print(f"Using last epoch index {last_epoch_idx}, start time = {last_epoch_start_time:.1f}s")

    # 创建攻击者（选择度数最高的节点）
    att_configs = config.get('attackers', [])
    attackers = instantiate_attackers(att_configs, all_node_ids, degree_counter, seed)

    # 初始化控制面
    num_total = max(all_node_ids) + 1 if all_node_ids else 0
    control = ControlPlane(num_nodes=num_total, tick_interval=tick_interval, attackers=attackers)
    print(f"Running control plane with {len(attackers)} attackers for {num_ticks} ticks...")
    control.run_ticks(num_ticks, edges_by_epoch, epoch_duration)

    routing_tables = control.get_routing_tables()
    print(f"Final routing tables contain {len(routing_tables)} nodes")

    # 检查攻击者是否在最后一个边集中
    last_edges = edges_by_epoch[last_epoch_idx]
    for att in attackers:
        in_edges = any(att.node_id == u or att.node_id == v for u, v in last_edges)
        print(f"Attacker {att.node_id} present in last epoch edges: {in_edges}")

    # 生成数据流
    num_flows = config.get('num_flows', 100)
    flows = generate_flows(all_node_ids, num_flows, seed)

    # 数据面评估，传入正确的 base_time
    data_plane = DataPlane(routing_tables, [last_edges], attackers=attackers)
    data_stats = data_plane.evaluate_flows(
        flows, 
        positions_per_epoch=None, 
        epoch_duration=epoch_duration,
        base_time=last_epoch_start_time
    )

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

    result = {
        'seed': seed,
        'control_stats': control_stats,
        'data_stats': data_stats,
        'attacker_stats': attacker_stats,
    }
    return result

def aggregate_results(results):
    delivery_ratios = [r['data_stats']['delivery_ratio'] for r in results]
    avg_hops = [r['data_stats']['avg_hops'] for r in results]
    avg_latency = [r['data_stats']['avg_latency_ms'] for r in results]
    attacked_counts = [r['data_stats']['attacked_count'] for r in results]
    dropped_counts = [r['data_stats']['dropped_by_attacker'] for r in results]
    total_loops = [r['control_stats']['total_loops'] for r in results]

    return {
        'mean_delivery_ratio': np.mean(delivery_ratios),
        'std_delivery_ratio': np.std(delivery_ratios),
        'mean_avg_hops': np.mean(avg_hops),
        'mean_avg_latency_ms': np.mean(avg_latency),
        'mean_attacked_count': np.mean(attacked_counts),
        'mean_dropped_by_attacker': np.mean(dropped_counts),
        'mean_total_loops': np.mean(total_loops),
        'num_seeds': len(results)
    }

def main():
    parser = argparse.ArgumentParser(description='Run attack experiments')
    parser.add_argument('--config', required=True, help='Path to experiment YAML')
    parser.add_argument('--seeds', nargs='+', type=int, default=[42], help='List of random seeds')
    parser.add_argument('--output', default='results/raw', help='Output directory')
    args = parser.parse_args()

    with open(args.config, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    topo_cache = config.get('topology_cache', 'data/topology/topology_results.pkl')
    pos_cache = config.get('positions_cache', 'data/snapshots/positions_per_epoch.pkl')
    shell = config.get('shell', '53°')
    edges_by_epoch, positions_per_epoch, all_node_ids, degree_counter = load_topology_and_positions(topo_cache, pos_cache, shell)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    for seed in args.seeds:
        logger.info(f"Running seed {seed}")
        result = run_experiment(seed, config, edges_by_epoch, positions_per_epoch, all_node_ids, degree_counter)
        seed_file = out_dir / f"attack_e3_blackhole_seed{seed}.json"
        with open(seed_file, 'w') as f:
            json.dump(result, f, indent=2)
        all_results.append(result)

    aggregated = aggregate_results(all_results)
    agg_file = out_dir / "aggregated_attack_e3.json"
    with open(agg_file, 'w') as f:
        json.dump(aggregated, f, indent=2)

    logger.info(f"All done. Results saved to {out_dir}")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()