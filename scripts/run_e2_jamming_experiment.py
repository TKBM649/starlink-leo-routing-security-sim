#!/usr/bin/env python
"""
E2 攻击实验运行脚本（统一 schema v2）
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
import pickle
from pathlib import Path
from typing import List, Tuple, Set, Dict, Optional, Any

from starlink_sim.net.attack import (
    Attacker,
    BlackholeAttacker,
    JammingAttacker,
    SybilAttacker,
    WormholeAttacker,
)
from starlink_sim.net.simulator import Simulator, ControlPlane, DataPlane
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


# 攻击者类型映射 / create_attacker / select_attackers / instantiate_attackers 已统一迁移至
# starlink_sim.net.placement（多策略放置模块），此处通过顶部 import 复用，消除与 run_e3 的重复。


def _json_safe(obj):
    """递归把非有限浮点（inf/nan）→ None、numpy 标量 → python，确保严格 JSON 可序列化。"""
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


def generate_flows(node_list: List[int], num_flows: int, seed: int) -> List[Tuple[int, int]]:
    """按 seed 生成随机流对（与既有 build_topology_from_cache 内联逻辑一致）。"""
    random.seed(seed)
    flow_pairs: List[Tuple[int, int]] = []
    for _ in range(num_flows):
        src = random.choice(node_list)
        dst = random.choice(node_list)
        while dst == src:
            dst = random.choice(node_list)
        flow_pairs.append((src, dst))
    return flow_pairs


# ==================== 拓扑构建（从缓存加载） ====================
def build_topology_from_cache(
    cache_path: str,
    shell: str = "53°",
    node_limit: Optional[int] = 96,
    num_flows: int = 100,
    seed: int = 42,
    subset_method: str = "cumulative_degree",
) -> Tuple[List[Set[Tuple[int, int]]], List[Optional[Dict[int, np.ndarray]]], List[Tuple[int, int]]]:
    """从 pkl 缓存加载拓扑，可选 BFS 裁剪节点子集。"""
    cache = Path(cache_path)
    if not cache.exists():
        raise FileNotFoundError(f"拓扑缓存未找到: {cache}，请先运行 scripts/build_topology.py 生成。")
    with open(cache, 'rb') as f:
        topology_results = pickle.load(f)

    if shell not in topology_results:
        available = list(topology_results.keys())
        raise ValueError(f"Shell '{shell}' 不在缓存中，可用壳层：{available}")
    result = topology_results[shell]

    edges_per_epoch = result['edges_per_epoch']
    positions_per_epoch = result.get('positions_per_epoch', None)
    if positions_per_epoch is None:
        positions_per_epoch = [None] * len(edges_per_epoch)

    # ---- 跨 epoch 连通子集裁剪（node_limit=None 时使用全量）——替代旧 epoch-0 BFS ----
    # 旧 BFS 仅在 epoch-0 上取前 node_limit 个节点，后续 epoch 可能碎裂（T7 实测
    # BFS-512 在部分 epoch 最大连通分量占比跌至 ~42%）；select_connected_subset 选出
    # 跨 epoch 累计度数高、逐 epoch 连通性更优的节点集。
    if node_limit is not None:
        node_set = set(select_connected_subset(edges_per_epoch, node_limit,
                                               method=subset_method))
        if not node_set:
            raise RuntimeError("无法从拓扑提取连通子集（边集为空？）")
        print(f"跨epoch连通子集提取节点数: {len(node_set)} (目标: {node_limit}, 方法: {subset_method})")

        # 过滤边集
        edges_per_epoch = [
            {(u, v) for u, v in edges if u in node_set and v in node_set}
            for edges in edges_per_epoch
        ]

        # 过滤位置
        if positions_per_epoch and positions_per_epoch[0] is not None:
            positions_per_epoch = [
                {node: pos_dict[node] for node in node_set if node in pos_dict}
                for pos_dict in positions_per_epoch
            ]
        else:
            positions_per_epoch = [None] * len(edges_per_epoch)

        node_list = sorted(node_set)
    else:
        # 全量节点
        node_set = set()
        for edges in edges_per_epoch:
            for u, v in edges:
                node_set.add(u)
                node_set.add(v)
        node_list = sorted(node_set)
        print(f"使用全量节点: {len(node_list)}")

    # 生成流对
    flow_pairs = generate_flows(node_list, num_flows, seed)

    return edges_per_epoch, positions_per_epoch, flow_pairs


# ==================== 主实验函数 ====================
def run_experiment_with_topology(config: dict, seed: int, edge_sets, positions_per_epoch,
                                 flow_pairs):
    """运行单次实验（拓扑已预加载）。

    抽出此函数供 ``scripts/run_experiment_sweep.py`` 复用：sweep 在 ``Pool(initializer=...)``
    里一次性加载 102.8MB 拓扑缓存，逐 (config,seed) 任务只做仿真，避免重复加载。
    返回逐 seed raw 记录（dict），**不落盘**（落盘由调用方负责）。
    """
    random.seed(seed)
    np.random.seed(seed)

    exp_config = config['experiment']
    topo_config = config['topology']
    routing_config = config['routing']
    traffic_config = config['traffic']
    attacker_configs = get_attacker_configs(config)

    # 1. 节点全集（从边集提取）
    all_nodes = set()
    for edges in edge_sets:
        for u, v in edges:
            all_nodes.add(u)
            all_nodes.add(v)
    node_ids = sorted(all_nodes)
    num_nodes = max(all_nodes) + 1 if all_nodes else 0

    # 2. 选择并创建攻击者（统一放置模块；默认 'degree' 与既有行为逐位一致）
    attackers = instantiate_attackers(attacker_configs, edge_sets, seed,
                                      available_nodes=node_ids)
    print(f"攻击者数量: {len(attackers)}, 节点: {[a.node_id for a in attackers]}")

    # 2a. E6 Wormhole 隧道注入（**不**扩展节点 ID 空间，必须在 Simulator 构建之前）。
    # 虫洞两端 A、B 均为既有真实节点，只把隧道边写入每个 epoch 的 edge_sets；
    # num_nodes 不变，流端点（flow_pairs）也不变。放在 Sybil 注入之前，使虫洞端点
    # 只在真实节点中选取。无 Wormhole 攻击者时原样返回（既有行为不变）。
    edge_sets, node_ids, wormhole_injections = expand_topology_for_wormholes(
        attackers, edge_sets, node_ids, positions_per_epoch, seed=seed)
    wormhole_tunnels = sorted({t for inj in wormhole_injections for t in inj.tunnels})
    wormhole_tunnel_km = {t: km for inj in wormhole_injections
                          for t, km in inj.tunnel_km.items()}
    if wormhole_tunnels:
        print(f"[wormhole] 注入 {len(wormhole_tunnels)} 条隧道边: {wormhole_tunnels} "
              f"(num_nodes 保持 {num_nodes})")

    # 2b. E4 Sybil 身份注入（节点 ID 空间扩展，必须在 Simulator/ControlPlane 构建之前）。
    # 虚假身份作为新节点接入 edge_sets，num_nodes 随之扩大；无 Sybil 时原样返回。
    # 流端点（flow_pairs）已由 build_topology_from_cache 从真实节点生成，不受影响。
    real_node_ids = list(node_ids)
    edge_sets, node_ids, sybil_injections = expand_topology_for_sybils(
        attackers, edge_sets, node_ids, seed=seed)
    sybil_node_ids = sorted({sid for inj in sybil_injections for sid in inj.sybil_node_ids})
    if sybil_node_ids:
        num_nodes = max(node_ids) + 1 if node_ids else num_nodes
        print(f"[sybil] 注入 {len(sybil_node_ids)} 个虚假身份: {sybil_node_ids} "
              f"(num_nodes → {num_nodes})")

    # 2c. E6 虫洞检测门控：存在虫洞攻击臂，或配置显式要求跑检测（匹配基线臂用它
    # 测**误报率**）。默认关闭 → 既有配置/记录不含任何 wormhole 键（纯附加）。
    det_cfg = config.get('detection', {}).get('wormhole') or {}
    wormhole_detection_enabled = bool(wormhole_tunnels) \
        or any(isinstance(a, WormholeAttacker) for a in attackers) \
        or bool(det_cfg.get('enabled', False))

    # 3. 攻击窗口守卫（B3）：e2/Simulator base_time=0，评估 epoch [0, num_epochs)
    epoch_interval = topo_config['epoch_interval']
    duration = exp_config['duration']
    num_eval_epochs = min(len(edge_sets), max(1, int(duration // epoch_interval)))
    eval_times = evaluation_times(0.0, num_eval_epochs, epoch_interval)
    for w in check_attack_windows(attacker_configs, eval_times, strict=False):
        print(f"[attack-window-guard] {w}")

    # 4. 实例化 Simulator（wire t_adv 和 max_hops）
    sim = Simulator(
        edge_sets=edge_sets,
        positions_per_epoch=positions_per_epoch,
        num_nodes=num_nodes,
        tick_interval=routing_config['tick'],
        attackers=attackers,
        flow_pairs=flow_pairs,
        epoch_duration=epoch_interval,
        base_time=0.0,
        adv_interval=routing_config['t_adv'],
        max_hops=routing_config['max_hops'],
    )

    # 5. 运行仿真
    print(f"运行仿真 {duration} 秒...")
    results = sim.run(duration=duration)

    # 5b. E4 Sybil 指标：吸引的流量占比（转发链经过虚假身份的 flow-epoch 比例）。
    # 用控制面逐 epoch 路由表快照 + 容忍环路追踪（与 e3 口径一致）。
    # e2 为平铺 schema：extract_metrics 顶层仅提取 DEFAULT_METRICS，故新指标统一放入
    # 一个 ``data_stats`` 块（与顶层既有键无重叠，不影响 num_trials / 匹配键推导），
    # 使 T6 统计框架能自动聚合。该块**仅在 Sybil/Wormhole 启用时**才存在，
    # 以保证既有（无新攻击）记录的 schema 逐位不变。
    extra_data_stats: Dict[str, Any] = {}
    if sybil_node_ids:
        history = sim.control_plane.routing_table_history if sim.control_plane else {}
        tables_per_epoch = [history.get(i, sim.routing_tables) for i in range(num_eval_epochs)]
        sybil_attraction = compute_sybil_attraction(
            flow_pairs, sybil_node_ids, tables_per_epoch, edge_sets,
            num_eval_epochs, routing_config['max_hops'])
        results['sybil_attraction_ratio'] = sybil_attraction['sybil_attraction_ratio']
        results['sybil_attracted_trials'] = sybil_attraction['sybil_attracted_trials']
        results['sybil_num_identities'] = len(sybil_node_ids)
        extra_data_stats.update({
            'sybil_attraction_ratio': sybil_attraction['sybil_attraction_ratio'],
            'sybil_attracted_trials': sybil_attraction['sybil_attracted_trials'],
            'sybil_num_identities': len(sybil_node_ids),
        })
        results['sybil_stats'] = {
            'num_identities': len(sybil_node_ids),
            'sybil_node_ids': sybil_node_ids,
            'attraction_ratio': sybil_attraction['sybil_attraction_ratio'],
            'attracted_trials': sybil_attraction['sybil_attracted_trials'],
            'total_trials': sybil_attraction['sybil_total_trials'],
            'injections': [
                {'controller_node': inj.controller_node, 'attachment': inj.attachment,
                 'num_identities': inj.num_identities, 'sybil_node_ids': inj.sybil_node_ids,
                 'attachment_map': {str(k): v for k, v in inj.attachment_map.items()},
                 'targets': inj.targets} for inj in sybil_injections
            ],
        }

    # 5c. E6 Wormhole 指标：物理接地检测 + 牵引占比 + path/geo stretch（与 e3 共用
    # ``run_wormhole_detection``，口径完全一致）。e2/Simulator 的评估窗口为
    # epoch [0, num_eval_epochs)、base_time=0，故位置/边集切片取前 num_eval_epochs 个。
    if wormhole_detection_enabled:
        history = sim.control_plane.routing_table_history if sim.control_plane else {}
        tables_per_epoch = [history.get(i, sim.routing_tables) for i in range(num_eval_epochs)]
        pos_slice = None
        if positions_per_epoch is not None:
            pos_slice = list(positions_per_epoch)[:num_eval_epochs]
        wh = run_wormhole_detection(
            wormhole_tunnels, flow_pairs, tables_per_epoch,
            list(edge_sets)[:num_eval_epochs], num_eval_epochs,
            positions_per_epoch=pos_slice,
            max_hops=routing_config['max_hops'],
            max_isl_km=float(det_cfg.get('max_isl_km', 2000.0)),
            distance_factor=float(det_cfg.get('distance_factor', 1.5)),
            adaptive_factor=det_cfg.get('adaptive_factor', 3.0),
            latency_factor=float(det_cfg.get('latency_factor', 1.0)),
            tunnel_km=wormhole_tunnel_km, injections=wormhole_injections)
        extra_data_stats.update(wh['data_stats'])
        results['wormhole_stats'] = wh['stats']
        print(f"[wormhole] detection: tunnels={wh['stats']['num_tunnels']} "
              f"detected={wh['stats']['detected_tunnels']} "
              f"rate={wh['stats']['detection_rate']} "
              f"fp_rate={wh['stats']['false_positive_rate']:.4f} "
              f"attracted={wh['stats']['attracted_ratio']:.4f} "
              f"available={wh['stats']['detector_available']}")
    if extra_data_stats:
        results['data_stats'] = extra_data_stats

    # 6. 附加配置、种子与基数元数据（与 T6 统计框架兼容）
    results['seed'] = seed
    results['config'] = config
    results['metadata'] = {
        'schema_version': 2,
        'seed': seed,
        'shell': topo_config.get('shell'),
        'node_limit': topo_config.get('node_limit'),
        'num_nodes': int(num_nodes),
        'num_eval_epochs': int(num_eval_epochs),
        'num_flows': int(traffic_config['num_flows']),
        'trials_per_flow_epoch': 1,
        'total_trials': int(results.get('num_trials', 0)),
        'runner': 'e2_simulator',
        'cardinality_semantics': 'total_trials = num_flows × num_eval_epochs × trials_per_flow_epoch',
    }
    if sybil_node_ids:
        results['metadata']['sybil_injected'] = True
        results['metadata']['sybil_num_identities'] = len(sybil_node_ids)
        results['metadata']['num_real_nodes'] = len(real_node_ids)
    if wormhole_detection_enabled:
        # 隧道两端均为真实节点 → num_nodes 不变，匹配键不受影响（不含任何 wormhole 键）。
        results['metadata']['wormhole_detection_enabled'] = True
        results['metadata']['wormhole_num_tunnels'] = len(wormhole_tunnels)
        if wormhole_tunnels:
            results['metadata']['wormhole_injected'] = True
            results['metadata']['wormhole_tunnels'] = [list(t) for t in wormhole_tunnels]
            results['metadata']['num_real_nodes'] = len(real_node_ids)
    return results


def run_experiment(config_path: str, seed: int):
    """运行单次实验（CLI 入口：加载配置+拓扑后委托 run_experiment_with_topology）。"""
    config = load_experiment_config(config_path)
    topo_config = config['topology']
    traffic_config = config['traffic']
    output_config = config['output']
    exp_config = config['experiment']

    # 构建拓扑（从缓存加载 + 跨 epoch 连通子集裁剪）
    print("构建拓扑...")
    edge_sets, positions_per_epoch, flow_pairs = build_topology_from_cache(
        cache_path=topo_config['cache_path'],
        shell=topo_config['shell'],
        node_limit=topo_config.get('node_limit'),
        num_flows=traffic_config['num_flows'],
        seed=seed,
        subset_method=topo_config.get('subset_method', 'cumulative_degree'),
    )

    results = run_experiment_with_topology(config, seed, edge_sets,
                                           positions_per_epoch, flow_pairs)

    # 保存结果（UTF-8，严格 JSON：inf→None）
    raw_dir = Path(output_config['raw_dir'])
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_file = raw_dir / f"{exp_config['name']}_seed{seed}.json"
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(_json_safe(results), f, indent=2, ensure_ascii=False)

    print(f"结果已保存至 {out_file}")
    return results


# ==================== 命令行入口 ====================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="运行 E2 攻击实验（统一 schema）")
    parser.add_argument('--config', required=True, help='实验配置文件路径（YAML）')
    parser.add_argument('--seeds', nargs='+', type=int, default=[42],
                        help='随机种子列表，如 --seeds 42 43 44')
    args = parser.parse_args()

    for seed in args.seeds:
        run_experiment(args.config, seed)
