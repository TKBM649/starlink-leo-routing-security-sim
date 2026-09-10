# starlink_sim/net/simulator.py
import pickle
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
import numpy as np
from starlink_sim.net.routing_dv import DVRouter, DVMessage
import math

SPEED_OF_LIGHT = 299792.458  # km/s

class ControlPlane:
    def __init__(self, num_nodes: int, tick_interval: float = 0.2):
        self.num_nodes = num_nodes
        self.tick_interval = tick_interval
        self.routers: Dict[int, DVRouter] = {i: DVRouter(i, tick_interval) for i in range(num_nodes)}
        self.inboxes: Dict[int, List[DVMessage]] = {i: [] for i in range(num_nodes)}
        self.neighbors: Dict[int, Set[int]] = {i: set() for i in range(num_nodes)}
        self.time = 0.0
        self.total_loops = 0
        self.loop_paths = []

    def update_neighbors(self, edges: Set[Tuple[int, int]]):
        """根据当前 epoch 的边集更新邻居关系"""
        new_neighbors = {i: set() for i in range(self.num_nodes)}
        for u, v in edges:
            if u < self.num_nodes and v < self.num_nodes:
                new_neighbors[u].add(v)
                new_neighbors[v].add(u)
        self.neighbors = new_neighbors
        for node_id, neigh in self.neighbors.items():
            self.routers[node_id].set_neighbors(neigh)

    def step(self, current_time: float, edges: Set[Tuple[int, int]]) -> int:
        """执行一个 tick，同时传入当前边集以更新邻居"""
        self.update_neighbors(edges)
        received_msgs = {i: self.inboxes[i] for i in range(self.num_nodes)}
        self.inboxes = {i: [] for i in range(self.num_nodes)}
        outgoing_msgs = []
        for node_id, router in self.routers.items():
            msgs = router.process_tick(current_time, received_msgs[node_id])
            outgoing_msgs.extend(msgs)
        for msg in outgoing_msgs:
            if msg.dst == -1:
                for neighbor in self.neighbors[msg.src]:
                    if neighbor != msg.src:
                        self.inboxes[neighbor].append(msg)
            else:
                if msg.dst in self.inboxes:
                    self.inboxes[msg.dst].append(msg)
        loop_count = 0
        for router in self.routers.values():
            if router.loops_detected:
                loop_count += len(router.loops_detected)
                self.loop_paths.extend(router.loops_detected)
                router.loops_detected.clear()
        self.total_loops += loop_count
        self.time = current_time
        return loop_count

    def run(self, num_ticks: int, edge_sets: List[Set[Tuple[int, int]]]):
        """运行控制面，每个 tick 使用对应的边集（按索引取）"""
        for tick in range(num_ticks):
            epoch_idx = tick // 5  # 假设每 5 个 tick 对应一个 epoch（tick=0.2s，epoch=30s => 150 ticks）
            # 但我们的 epoch 步长是 30s，tick 是 0.2s，所以 150 ticks 一个 epoch
            # 为了简化，我们直接取边集索引：tick 与 epoch 的映射由外部传入
            # 这里使用一种简单映射：假定 edge_sets 长度等于总 ticks，或者我们重新设计。
            # 更好的方式：在 run 中传入 epoch_edges 列表，每个 tick 根据当前时间计算对应的 epoch 索引。
            pass

    # 我们将在 run_simulation 中直接控制边集更新，而不是在 run 内部。
    def run_ticks(self, num_ticks: int, edge_sets: List[Set[Tuple[int, int]]]):
        """运行指定数量的 tick，每个 tick 从 edge_sets 中取对应 epoch 的边集"""
        for tick in range(num_ticks):
            # 计算当前 tick 对应的 epoch 索引：tick_interval = 0.2s，epoch 步长 30s
            epoch_idx = int(tick * self.tick_interval / 30.0)  # 30s per epoch
            if epoch_idx >= len(edge_sets):
                epoch_idx = len(edge_sets) - 1
            current_edges = edge_sets[epoch_idx]
            self.step(tick * self.tick_interval, current_edges)
            if (tick + 1) % 100 == 0:
                print(f"  Control plane tick {tick+1}/{num_ticks} done.")

    def get_routing_tables(self) -> Dict[int, Dict]:
        return {node: router.get_routing_table() for node, router in self.routers.items()}


class DataPlane:
    def __init__(self, routing_tables: Dict[int, Dict], edge_sets: List[Set[Tuple[int, int]]]):
        self.routing_tables = routing_tables
        self.edge_sets = edge_sets
        self.num_nodes = len(routing_tables)

    def compute_path(self, src: int, dst: int, epoch_idx: int, positions: Dict[int, np.ndarray]) -> Tuple[Optional[List[int]], float]:
        """
        返回 (路径列表, 总时延ms)。若路径不存在，返回 (None, 0)。
        时延 = 每跳传播时延之和（距离/c）。
        需要 positions: 节点在该 epoch 的位置字典。
        """
        if src == dst:
            return [src], 0.0
        current = src
        path = [current]
        visited = set([current])
        max_hops = 100
        edges = self.edge_sets[epoch_idx] if epoch_idx < len(self.edge_sets) else set()
        total_delay = 0.0

        for _ in range(max_hops):
            router = self.routing_tables.get(current)
            if router is None:
                return None, 0.0
            entry = router.get(dst)
            if entry is None:
                return None, 0.0
            next_hop = entry.next_hop
            # 检查链路存在
            if (current, next_hop) not in edges and (next_hop, current) not in edges:
                return None, 0.0
            if next_hop in visited:
                return path + [next_hop], 0.0  # 环路，失败
            # 计算距离
            if current in positions and next_hop in positions:
                dist = np.linalg.norm(positions[current] - positions[next_hop])
                total_delay += dist / SPEED_OF_LIGHT * 1000.0  # ms
            path.append(next_hop)
            visited.add(next_hop)
            if next_hop == dst:
                return path, total_delay
            current = next_hop
        return None, 0.0

    def evaluate_flows(self, flows: List[Tuple[int, int]], positions_per_epoch: List[Dict[int, np.ndarray]]) -> Dict:
        """
        flows: list of (src, dst)
        positions_per_epoch: 每个 epoch 的位置字典
        返回: 交付率、成功平均跳数、成功平均时延、总平均跳数（含失败）
        """
        num_epochs = len(self.edge_sets)
        deliveries = []
        hop_counts = []
        latencies = []
        successful_hop_counts = []
        successful_latencies = []

        for src, dst in flows:
            for epoch_idx in range(num_epochs):
                positions = positions_per_epoch[epoch_idx]
                path, delay = self.compute_path(src, dst, epoch_idx, positions)
                if path is not None:
                    deliveries.append(1)
                    hop_counts.append(len(path)-1)
                    latencies.append(delay)
                    successful_hop_counts.append(len(path)-1)
                    successful_latencies.append(delay)
                else:
                    deliveries.append(0)
                    hop_counts.append(0)   # 失败计0跳
                    latencies.append(0)
        total_trials = len(deliveries)
        delivery_ratio = sum(deliveries) / total_trials if total_trials > 0 else 0.0
        avg_hops = np.mean(hop_counts) if hop_counts else 0.0
        avg_latency = np.mean(latencies) if latencies else 0.0
        avg_success_hops = np.mean(successful_hop_counts) if successful_hop_counts else 0.0
        avg_success_latency = np.mean(successful_latencies) if successful_latencies else 0.0

        return {
            'delivery_ratio': delivery_ratio,
            'avg_hops': avg_hops,
            'avg_latency_ms': avg_latency,
            'avg_success_hops': avg_success_hops,
            'avg_success_latency_ms': avg_success_latency,
            'num_success': len(successful_hop_counts),
            'num_trials': total_trials
        }