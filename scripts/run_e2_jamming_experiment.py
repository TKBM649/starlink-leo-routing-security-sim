#!/usr/bin/env python
"""
攻击实验运行脚本
支持配置 YAML、多种攻击类型、多随机种子。
"""
import sys
import os
# 添加项目根目录到 sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import json
import random
import numpy as np
import yaml
import pickle
from pathlib import Path
from typing import List, Tuple, Set, Dict, Optional, Any

from starlink_sim.net.attack import Attacker, BlackholeAttacker, JammingAttacker, SybilAttacker
from starlink_sim.net.simulator import Simulator, ControlPlane, DataPlane


# ==================== 拓扑构建（从缓存加载） ====================
def build_topology_from_tle(
    tle_file: str,
    shell: str = "53°",
    epoch_interval: float = 30.0,
    use_lattice: bool = True,
    isl_distance_limit: float = 800.0,
    gimbal_limit: float = 60.0,
    num_flows: int = 100,
    flow_duration: float = 10.0,
    start_offset: float = 5.0,
    seed: int = 42
) -> Tuple[List[Set[Tuple[int, int]]], List[Dict[int, np.ndarray]], List[Tuple[int, int]]]:
    # 加载缓存
    cache_path = Path("data/topology/topology_results.pkl")
    if not cache_path.exists():
        raise FileNotFoundError("拓扑缓存未找到，请先运行 scripts/build_topology.py 生成。")
    with open(cache_path, 'rb') as f:
        topology_results = pickle.load(f)

    if shell not in topology_results:
        available = list(topology_results.keys())
        raise ValueError(f"Shell '{shell}' 不在缓存中，可用壳层：{available}")
    result = topology_results[shell]

    edges_per_epoch = result['edges_per_epoch']
    positions_per_epoch = result.get('positions_per_epoch', None)
    if positions_per_epoch is None:
        positions_per_epoch = [None] * len(edges_per_epoch)

    # ---- 提取连通子图：BFS 取前 N 个节点 ----
    NODE_LIMIT = 96   # 开发调试用
    first_edges = edges_per_epoch[0]
    # 构建邻接表
    adj = {}
    for u, v in first_edges:
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)
    
    if not adj:
        raise RuntimeError("第一个 epoch 无边，无法提取连通子图")
    
    # 从任意节点开始 BFS
    start_node = next(iter(adj))
    queue = [start_node]
    visited = set([start_node])
    while queue and len(visited) < NODE_LIMIT:
        node = queue.pop(0)
        for nb in adj.get(node, []):
            if nb not in visited:
                visited.add(nb)
                queue.append(nb)
                if len(visited) >= NODE_LIMIT:
                    break
    node_set = visited
    print(f"BFS 提取节点数: {len(node_set)} (图中总节点数: {len(adj)})")

    # 过滤边集：只保留两端都在 node_set 中的边
    filtered_edges = []
    for edges in edges_per_epoch:
        new_edges = {(u, v) for u, v in edges if u in node_set and v in node_set}
        filtered_edges.append(new_edges)
    edges_per_epoch = filtered_edges

    # 过滤位置
    if positions_per_epoch and positions_per_epoch[0] is not None:
        filtered_positions = []
        for pos_dict in positions_per_epoch:
            new_pos = {node: pos_dict[node] for node in node_set if node in pos_dict}
            filtered_positions.append(new_pos)
        positions_per_epoch = filtered_positions
    else:
        positions_per_epoch = [None] * len(edges_per_epoch)

    # 生成流对
    node_list = list(node_set)
    random.seed(seed)
    flow_pairs = []
    for _ in range(num_flows):
        src = random.choice(node_list)
        dst = random.choice(node_list)
        while dst == src:
            dst = random.choice(node_list)
        flow_pairs.append((src, dst))

    return edges_per_epoch, positions_per_epoch, flow_pairs

# ==================== 攻击者工厂 ====================
def create_attacker(node_id: int, attack_config: dict) -> Attacker:
    """根据配置创建攻击者实例"""
    atype = attack_config.get('type')
    params = attack_config.get('params', {})
    common = {
        'active_since': attack_config.get('active_since', 0.0),
        'active_until': attack_config.get('active_until', float('inf'))
    }
    full_params = {**common, **params}

    if atype == "BlackholeAttacker":
        return BlackholeAttacker(node_id, **full_params)
    elif atype == "JammingAttacker":
        return JammingAttacker(node_id, **full_params)
    elif atype == "SybilAttacker":
        return SybilAttacker(node_id, **full_params)
    else:
        raise ValueError(f"Unsupported attacker type: {atype}")


def select_attackers(edge_sets: List[Set[Tuple[int, int]]],
                     attack_config: dict,
                     rng: random.Random) -> List[int]:
    """
    根据配置选择攻击者节点 ID。
    目前支持 'degree' 策略：选择历史度数最高的节点。
    """
    count = attack_config.get('count', 1)
    placement = attack_config.get('placement', 'degree')

    if placement == 'degree':
        # 统计所有 epoch 中每个节点的度数和（或平均）
        degree_count = {}
        for edges in edge_sets:
            for u, v in edges:
                degree_count[u] = degree_count.get(u, 0) + 1
                degree_count[v] = degree_count.get(v, 0) + 1
        # 按度数降序排序
        sorted_nodes = sorted(degree_count.items(), key=lambda x: x[1], reverse=True)
        # 取前 count 个，但确保不重复
        chosen = [node for node, _ in sorted_nodes[:count]]
        # 若不足，从剩余节点中随机补充
        if len(chosen) < count:
            remaining = [n for n in degree_count.keys() if n not in chosen]
            if remaining:
                chosen.extend(rng.sample(remaining, count - len(chosen)))
        return chosen
    else:
        # 其他策略留作扩展
        raise ValueError(f"Unsupported placement: {placement}")


# ==================== 主实验函数 ====================
def run_experiment(config_path: str, seed: int):
    """运行单次实验"""
    # 显式指定 UTF-8 编码
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    # 设置随机种子
    random.seed(seed)
    np.random.seed(seed)
    rng = random.Random(seed)

    # 提取配置
    exp_config = config['experiment']
    topo_config = config['topology']
    routing_config = config['routing']
    traffic_config = config['traffic']
    attack_config = config['attack']
    output_config = config['output']

    # 1. 构建拓扑（从缓存加载）
    print("构建拓扑...")
    edge_sets, positions_per_epoch, flow_pairs = build_topology_from_tle(
        tle_file=topo_config['tle_file'],
        shell=topo_config['shell'],
        epoch_interval=topo_config['epoch_interval'],
        use_lattice=topo_config.get('use_lattice', True),
        isl_distance_limit=topo_config.get('isl_distance_limit', 800.0),
        gimbal_limit=topo_config.get('gimbal_limit', 60.0),
        num_flows=traffic_config['num_flows'],
        flow_duration=traffic_config['flow_duration'],
        start_offset=traffic_config.get('start_offset', 5.0),
        seed=seed
    )

    # 2. 选择攻击者
    print("选择攻击者节点...")
    attacker_nodes = select_attackers(edge_sets, attack_config, rng)
    print(f"攻击者节点: {attacker_nodes}")

    # 3. 创建攻击者实例
    attackers = []
    for node_id in attacker_nodes:
        attacker = create_attacker(node_id, attack_config)
        attackers.append(attacker)

    # 4. 确定节点总数（从边集中提取）
    all_nodes = set()
    for edges in edge_sets:
        for u, v in edges:
            all_nodes.add(u)
            all_nodes.add(v)
    num_nodes = max(all_nodes) + 1 if all_nodes else 0

    # 5. 实例化 Simulator
    sim = Simulator(
        edge_sets=edge_sets,
        positions_per_epoch=positions_per_epoch,
        num_nodes=num_nodes,
        tick_interval=routing_config['tick'],
        attackers=attackers,
        flow_pairs=flow_pairs,
        epoch_duration=topo_config['epoch_interval'],
        base_time=0.0
    )

    # 6. 运行仿真
    print(f"运行仿真 {exp_config['duration']} 秒...")
    results = sim.run(duration=exp_config['duration'])

    # 7. 附加配置和种子信息
    results['seed'] = seed
    results['config'] = config

    # 8. 保存结果（UTF-8 编码）
    raw_dir = Path(output_config['raw_dir'])
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_file = raw_dir / f"{exp_config['name']}_seed{seed}.json"
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"结果已保存至 {out_file}")
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return results


# ==================== 命令行入口 ====================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="运行攻击实验")
    parser.add_argument('--config', required=True, help='实验配置文件路径（YAML）')
    parser.add_argument('--seeds', nargs='+', type=int, default=[42],
                        help='随机种子列表，如 --seeds 42 43 44')
    args = parser.parse_args()

    for seed in args.seeds:
        run_experiment(args.config, seed)