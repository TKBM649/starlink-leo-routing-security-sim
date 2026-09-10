# scripts/run_simulation.py
import sys
from pathlib import Path
import pickle
import random
import numpy as np
import json
from typing import List, Dict, Optional, Tuple

sys.path.append(str(Path(__file__).parent.parent))

from starlink_sim.net.simulator import ControlPlane, DataPlane
from starlink_sim.topology.isl import propagate_satellite

def compute_positions_for_epoch(records: List[dict], jd: float, fr: float) -> Dict[int, np.ndarray]:
    """计算给定 epoch 的所有卫星位置"""
    positions = {}
    for idx, rec in enumerate(records):
        pos = propagate_satellite(rec['line1'], rec['line2'], jd, fr)
        if pos is not None:
            positions[idx] = pos[0]  # 位置矢量
    return positions

def main():
    # 加载拓扑数据
    topo_path = Path("data/topology/topology_results.pkl")
    if not topo_path.exists():
        print("Topology results not found. Please run build_topology.py first.")
        sys.exit(1)
    with open(topo_path, 'rb') as f:
        topo_data = pickle.load(f)

    # 选择壳层（53° 作为主实验）
    shell_name = '53°'
    if shell_name not in topo_data:
        print(f"Shell {shell_name} not found in topology results.")
        sys.exit(1)
    shell_data = topo_data[shell_name]
    edges_per_epoch = shell_data['edges_per_epoch']  # list of sets
    num_epochs = len(edges_per_epoch)
    print(f"Shell {shell_name}: {num_epochs} epochs.")

    # 加载卫星记录（用于位置计算）
    lattice_path = Path("data/lattice/lattice_result.pkl")
    if not lattice_path.exists():
        print("Lattice result not found. Please run build_lattice.py first.")
        sys.exit(1)
    with open(lattice_path, 'rb') as f:
        lattice_data = pickle.load(f)
    records = lattice_data[shell_name]['records']
    num_nodes = len(records)
    print(f"Total nodes: {num_nodes}")

    # 预计算每个 epoch 的位置（全量）
    from sgp4.api import jday
    t0_jd, t0_fr = jday(2026, 8, 22, 10, 13, 50)
    positions_per_epoch = []
    for epoch_idx in range(num_epochs):
        dt = epoch_idx * 30.0  # 每个 epoch 30秒
        dt_day = dt / 86400.0
        jd = t0_jd
        fr = t0_fr + dt_day
        if fr >= 1.0:
            jd += int(fr)
            fr -= int(fr)
        pos_dict = compute_positions_for_epoch(records, jd, fr)
        positions_per_epoch.append(pos_dict)
        if (epoch_idx + 1) % 20 == 0:
            print(f"  Computed positions for epoch {epoch_idx+1}/{num_epochs}")

    # 构建控制面
    control = ControlPlane(num_nodes, tick_interval=0.2)

    # 运行控制面，每个 tick 使用对应 epoch 的边集
    print("Running control plane...")
    num_ticks = 1000   # 400 秒
    for tick in range(num_ticks):
        epoch_idx = int(tick * control.tick_interval / 30.0)
        if epoch_idx >= num_epochs:
            epoch_idx = num_epochs - 1
        edges = edges_per_epoch[0]
        control.step(tick * control.tick_interval, edges)
        if (tick + 1) % 100 == 0:
            print(f"  Control plane tick {tick+1}/{num_ticks} done.")

    # 检查路由表状态
    total_entries = 0
    routers_with_entries = 0
    for node_id, router in control.routers.items():
        size = len(router.get_routing_table())
        if size > 0:
            routers_with_entries += 1
            total_entries += size
    print(f"Total routing entries across all nodes: {total_entries}")
    print(f"Routers with non-empty tables: {routers_with_entries}/{num_nodes}")

    if total_entries == 0:
        print("Routing tables empty. Exiting.")
        sys.exit(1)
    
    # 调试打印
    sample_nodes = [0, 100, 1000, 2000, 3000]
    for nid in sample_nodes:
        if nid < num_nodes:
            size = len(control.routers[nid].get_routing_table())
            print(f"Node {nid} has {size} routes")

    # 保存路由表
    routing_tables = control.get_routing_tables()
    with open("results/routing_tables.pkl", 'wb') as f:
        pickle.dump(routing_tables, f)

    # 环路统计
    loop_paths = control.loop_paths
    print(f"Loop events detected: {len(loop_paths)}")
    if len(loop_paths) > 0:
        print("First few loop paths:")
        for path in loop_paths[:3]:
            print(f"  {path}")

    # --- 数据面评估 ---
    fixed_edges = [edges_per_epoch[0]] * num_epochs
    data = DataPlane(routing_tables, fixed_edges)

    # 生成 100 条随机流（源-目的对）
    random.seed(42)
    flows = []
    for _ in range(100):
        src = random.randint(0, num_nodes - 1)
        dst = random.randint(0, num_nodes - 1)
        while src == dst:
            dst = random.randint(0, num_nodes - 1)
        flows.append((src, dst))

    # 评估
    result = data.evaluate_flows(flows, positions_per_epoch)
    print("\nData plane results over 100 random flows:")
    print(f"  Delivery ratio: {result['delivery_ratio']:.3f}")
    print(f"  Avg hops (all): {result['avg_hops']:.1f}")
    print(f"  Avg latency (all) ms: {result['avg_latency_ms']:.1f}")
    print(f"  Avg hops (successful): {result['avg_success_hops']:.1f}")
    print(f"  Avg latency (successful) ms: {result['avg_success_latency_ms']:.1f}")
    print(f"  Successful trials: {result['num_success']}/{result['num_trials']}")

    # 保存摘要
    summary = {
        'num_nodes': num_nodes,
        'num_epochs': num_epochs,
        'num_ticks': num_ticks,
        'total_routing_entries': total_entries,
        'routers_with_entries': routers_with_entries,
        'loop_events_count': len(loop_paths),
        'flows': flows,
        'delivery_ratio': result['delivery_ratio'],
        'avg_hops': result['avg_hops'],
        'avg_latency_ms': result['avg_latency_ms'],
        'avg_success_hops': result['avg_success_hops'],
        'avg_success_latency_ms': result['avg_success_latency_ms'],
        'num_success': result['num_success'],
        'num_trials': result['num_trials']
    }
    with open("results/simulation_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)

    print("Simulation completed. Results saved to results/")

if __name__ == "__main__":
    main()