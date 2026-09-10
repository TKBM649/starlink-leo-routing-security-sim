# scripts/build_topology.py
import sys
from pathlib import Path
import pickle
import json
import numpy as np
from sgp4.api import jday
sys.path.append(str(Path(__file__).parent.parent))
from starlink_sim.topology.isl import build_topology_for_shell, compute_edge_overlap

def main():
    # 加载格点拟合结果
    lattice_path = Path("data/lattice/lattice_result.pkl")
    with open(lattice_path, 'rb') as f:
        lattice_results = pickle.load(f)

    # 定义时间范围（从 t0 开始，持续 3600 秒，步长 30 秒）
    t0_jd, t0_fr = jday(2026, 8, 22, 10, 13, 50)
    duration = 3600  # 秒
    step = 30        # 秒
    num_steps = duration // step + 1
    times = []
    for k in range(num_steps):
        dt_sec = k * step
        # 将秒数转换为天的分数
        dt_day = dt_sec / 86400.0
        jd = t0_jd
        fr = t0_fr + dt_day
        # 如果 fr >= 1，进位
        if fr >= 1.0:
            jd += int(fr)
            fr -= int(fr)
        times.append((jd, fr))

    # 对每个壳层独立建拓扑
    topology_results = {}
    stats_summary = {}

    for shell_name, data in lattice_results.items():
        records = data['records']
        if not records:
            continue
        print(f"Building topology for shell {shell_name} with {len(records)} satellites...")
        result = build_topology_for_shell(records, times, max_dist_km=99999.0)
        topology_results[shell_name] = result

        # 统计度数分布
        edges_per_epoch = result['edges_per_epoch']
        # 取第一个时间步的度数分布（代表性）
        edges = edges_per_epoch[0]
        degree_count = {}
        for edge in edges:
            i, j = edge
            degree_count[i] = degree_count.get(i, 0) + 1
            degree_count[j] = degree_count.get(j, 0) + 1
        # 统计度数的频数
        deg_hist = {}
        for deg in degree_count.values():
            deg_hist[deg] = deg_hist.get(deg, 0) + 1
        # 节点度数0的数目（孤立节点）
        isolated = len(records) - len(degree_count)
        if isolated > 0:
            deg_hist[0] = isolated

        # 边重合率：间隔300s（10个步长）
        overlap_ratios = []
        for t_idx in range(0, num_steps - 10, 10):
            overlap = compute_edge_overlap(edges_per_epoch[t_idx], edges_per_epoch[t_idx+10])
            overlap_ratios.append(overlap)
        avg_overlap = np.mean(overlap_ratios) if overlap_ratios else 1.0

        stats_summary[shell_name] = {
            'num_satellites': len(records),
            'degree_distribution': deg_hist,
            'avg_degree': sum(deg * cnt for deg, cnt in deg_hist.items()) / len(records),
            'edge_overlap_300s': avg_overlap,
            'num_edges_first_epoch': len(edges),
            'total_edges_all_time': len(result['event_stream'])
        }
        print(f"  avg degree={stats_summary[shell_name]['avg_degree']:.2f}, overlap={avg_overlap:.3f}")

    # 保存结果
    output_dir = Path("data/topology")
    output_dir.mkdir(parents=True, exist_ok=True)

    # 保存所有边和事件流（压缩）
    with open(output_dir / "topology_results.pkl", 'wb') as f:
        pickle.dump(topology_results, f)

    # 保存统计摘要
    with open(output_dir / "topology_summary.json", 'w') as f:
        json.dump(stats_summary, f, indent=2)

    # 保存边事件流为文本（可选，用于调试）
    for shell_name, result in topology_results.items():
        event_file = output_dir / f"events_{shell_name}.txt"
        with open(event_file, 'w') as f:
            f.write(f"# Edge events for shell {shell_name}\n")
            f.write("# start_epoch, end_epoch, satellite_i, satellite_j\n")
            for start, end, edge in result['event_stream']:
                f.write(f"{start} {end} {edge[0]} {edge[1]}\n")

    print("Topology building completed. Results saved to data/topology/")

if __name__ == "__main__":
    main()