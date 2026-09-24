# starlink_sim/net/simulator.py
import pickle
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
import numpy as np
import math

from starlink_sim.net.routing_dv import DVRouter, DVMessage
from starlink_sim.net.attack import Attacker

SPEED_OF_LIGHT = 299792.458  # km/s


class ControlPlane:
    def __init__(self, num_nodes: int, tick_interval: float = 0.2, attackers: Optional[List[Attacker]] = None):
        self.num_nodes = num_nodes
        self.tick_interval = tick_interval
        self.routers: Dict[int, DVRouter] = {i: DVRouter(i, tick_interval) for i in range(num_nodes)}
        self.inboxes: Dict[int, List[DVMessage]] = {i: [] for i in range(num_nodes)}
        self.neighbors: Dict[int, Set[int]] = {i: set() for i in range(num_nodes)}
        self.time = 0.0
        self.total_loops = 0
        self.loop_paths = []
        self.routing_table_history: Dict[int, Dict[int, Dict]] = {}
        self.attackers = attackers if attackers is not None else []

    def update_neighbors(self, edges: Set[Tuple[int, int]]):
        new_neighbors = {i: set() for i in range(self.num_nodes)}
        for u, v in edges:
            if u < self.num_nodes and v < self.num_nodes:
                new_neighbors[u].add(v)
                new_neighbors[v].add(u)
        self.neighbors = new_neighbors
        for node_id, neigh in self.neighbors.items():
            self.routers[node_id].set_neighbors(neigh)

    def step(self, current_time: float, edges: Set[Tuple[int, int]]) -> int:
        self.update_neighbors(edges)
        received_msgs = {i: self.inboxes[i] for i in range(self.num_nodes)}
        self.inboxes = {i: [] for i in range(self.num_nodes)}
        outgoing_msgs = []

        for node_id, router in self.routers.items():
            msgs = router.process_tick(current_time, received_msgs[node_id])
            if msgs is None:
                msgs = []
            elif not isinstance(msgs, list):
                if hasattr(msgs, 'dst'):
                    msgs = [msgs]
                else:
                    msgs = []

            for att in self.attackers:
                if att.node_id == node_id and att.is_active(current_time):
                    modified_msgs = []
                    for msg in msgs:
                        if hasattr(msg, 'dst'):
                            modified = att.modify_advertisement(msg, router, None, current_time)
                            if modified is not None:
                                modified_msgs.append(modified)
                    msgs = modified_msgs
                    break

            outgoing_msgs.extend(msgs)

        for msg in outgoing_msgs:
            if not hasattr(msg, 'dst'):
                continue
            if msg.dst == -1:
                for neighbor in self.neighbors[msg.src]:
                    if neighbor != msg.src:
                        self.inboxes[neighbor].append(msg)
            else:
                if msg.dst in self.inboxes:
                    self.inboxes[msg.dst].append(msg)

        loop_count = 0
        for router in self.routers.values():
            if hasattr(router, 'loops_detected') and router.loops_detected:
                loop_count += len(router.loops_detected)
                self.loop_paths.extend(router.loops_detected)
                router.loops_detected.clear()
        self.total_loops += loop_count
        self.time = current_time
        return loop_count

    def run_ticks(self, num_ticks: int, edge_sets: List[Set[Tuple[int, int]]], epoch_duration: float = 30.0):
        self.routing_table_history = {}
        for tick in range(num_ticks):
            current_time = tick * self.tick_interval
            epoch_idx = int(current_time / epoch_duration)
            if epoch_idx >= len(edge_sets):
                epoch_idx = len(edge_sets) - 1
            current_edges = edge_sets[epoch_idx]
            self.step(current_time, current_edges)
            next_epoch = int((current_time + self.tick_interval) / epoch_duration)
            if tick == num_ticks - 1 or next_epoch != epoch_idx:
                # epoch 结束快照：该 epoch 数据面实际可用的路由表状态
                self.routing_table_history[epoch_idx] = self.get_routing_tables()
            if (tick + 1) % 100 == 0:
                print(f"  Control plane tick {tick+1}/{num_ticks} done.")

    def get_routing_tables(self) -> Dict[int, Dict]:
        return {node: router.get_routing_table() for node, router in self.routers.items()}

    def get_attackers_stats(self) -> List[Dict]:
        return [{'node_id': a.node_id, 'attracted_count': a.attracted_count, 'dropped_count': a.dropped_count}
                for a in self.attackers]


class DataPlane:
    def __init__(self, routing_tables: Dict[int, Dict], edge_sets: List[Set[Tuple[int, int]]],
                 attackers: Optional[List[Attacker]] = None,
                 routing_tables_per_epoch: Optional[List[Dict[int, Dict]]] = None):
        self.routing_tables = routing_tables
        self.edge_sets = edge_sets
        self.num_nodes = len(routing_tables)
        self.attackers = attackers if attackers is not None else []
        self.routing_tables_per_epoch = routing_tables_per_epoch
        self.loop_paths: List[List[int]] = []

    def compute_path(self, src: int, dst: int, epoch_idx: int, positions: Optional[Dict[int, np.ndarray]] = None) -> Tuple[Optional[List[int]], float]:
        if src == dst:
            return [src], 0.0
        current = src
        path = [current]
        visited = set([current])
        max_hops = 100
        edges = self.edge_sets[epoch_idx] if epoch_idx < len(self.edge_sets) else set()
        tables = self.routing_tables
        if self.routing_tables_per_epoch is not None and epoch_idx < len(self.routing_tables_per_epoch):
            tables = self.routing_tables_per_epoch[epoch_idx]
        total_delay = 0.0
        for _ in range(max_hops):
            router_entry = tables.get(current)
            if router_entry is None:
                return None, 0.0
            entry = router_entry.get(dst)
            if entry is None:
                return None, 0.0
            next_hop = entry.next_hop
            if (current, next_hop) not in edges and (next_hop, current) not in edges:
                return None, 0.0
            if next_hop in visited:
                # 转发环路：记为不可达并记录环路路径
                self.loop_paths.append(path + [next_hop])
                return None, 0.0
            if positions is not None:
                if current in positions and next_hop in positions:
                    dist = np.linalg.norm(positions[current] - positions[next_hop])
                    total_delay += dist / SPEED_OF_LIGHT * 1000.0
            path.append(next_hop)
            visited.add(next_hop)
            if next_hop == dst:
                return path, total_delay
            current = next_hop
        return None, 0.0

    def evaluate_flows(self, flows: List[Tuple[int, int]],
                       positions_per_epoch: Optional[List[Dict[int, np.ndarray]]] = None,
                       epoch_duration: float = 30.0,
                       base_time: float = 0.0,
                       num_epochs: Optional[int] = None) -> Dict:
        """评估数据流，仅统计 num_epochs 个 epoch（默认为逐 epoch 路由表数量），支持攻击者统计"""
        self.loop_paths = []
        if num_epochs is None:
            if self.routing_tables_per_epoch is not None:
                num_epochs = len(self.routing_tables_per_epoch)
            else:
                num_epochs = len(self.edge_sets)
        num_epochs = min(num_epochs, len(self.edge_sets))
        deliveries = []
        hop_counts = []
        latencies = []
        successful_hop_counts = []
        successful_latencies = []
        dropped_by_attacker = 0

        # 重置攻击者统计
        for att in self.attackers:
            att.attracted_count = 0
            att.dropped_count = 0

        for src, dst in flows:
            for epoch_idx in range(num_epochs):
                positions = positions_per_epoch[epoch_idx] if (
                    positions_per_epoch is not None and epoch_idx < len(positions_per_epoch)) else None
                path, delay = self.compute_path(src, dst, epoch_idx, positions)
                if path is not None:
                    attacked = False
                    dropped = False
                    epoch_time = base_time + epoch_idx * epoch_duration
                    for node in path:
                        for att in self.attackers:
                            if att.node_id == node and att.is_active(epoch_time):
                                attacked = True
                                att.attracted_count += 1
                                if att.should_drop_data((src, dst), epoch_time):
                                    dropped = True
                                    dropped_by_attacker += 1
                                    att.dropped_count += 1
                                break
                        if dropped:
                            break
                    if dropped:
                        deliveries.append(0)
                        hop_counts.append(0)
                        latencies.append(0)
                    else:
                        deliveries.append(1)
                        hop_counts.append(len(path)-1)
                        latencies.append(delay)
                        successful_hop_counts.append(len(path)-1)
                        successful_latencies.append(delay)
                else:
                    deliveries.append(0)
                    hop_counts.append(0)
                    latencies.append(0)

        attacked_count = sum(att.attracted_count for att in self.attackers)

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
            'num_trials': total_trials,
            'attacked_count': attacked_count,
            'dropped_by_attacker': dropped_by_attacker,
        }


class Simulator:
    """
    仿真器主类，协调控制面和数据面。
    """
    def __init__(self,
                 edge_sets: List[Set[Tuple[int, int]]],
                 positions_per_epoch: Optional[List[Dict[int, np.ndarray]]] = None,
                 num_nodes: int = 0,
                 tick_interval: float = 0.2,
                 attackers: Optional[List[Attacker]] = None,
                 flow_pairs: Optional[List[Tuple[int, int]]] = None,
                 epoch_duration: float = 30.0,
                 base_time: float = 0.0):
        self.edge_sets = edge_sets
        self.positions_per_epoch = positions_per_epoch
        self.tick_interval = tick_interval
        self.attackers = attackers if attackers is not None else []
        self.flow_pairs = flow_pairs if flow_pairs is not None else []
        self.epoch_duration = epoch_duration
        self.base_time = base_time

        if num_nodes == 0 and edge_sets:
            nodes = set()
            for edges in edge_sets:
                for u, v in edges:
                    nodes.add(u)
                    nodes.add(v)
            # 使用最大节点 ID + 1 确保所有节点都有路由器
            self.num_nodes = max(nodes) + 1 if nodes else 0
        else:
            self.num_nodes = num_nodes

        self.control_plane = None
        self.data_plane = None
        self.routing_tables = None

    def run(self, duration: float) -> Dict:
        num_ticks = int(duration / self.tick_interval) + 1

        self.control_plane = ControlPlane(
            num_nodes=self.num_nodes,
            tick_interval=self.tick_interval,
            attackers=self.attackers
        )
        self.control_plane.run_ticks(num_ticks, self.edge_sets, self.epoch_duration)

        # 数据面仅评估控制面实际仿真到的 epoch，并使用逐 epoch 结束时的路由表快照
        num_epochs = min(len(self.edge_sets),
                         max(1, int(duration // self.epoch_duration)))
        history = self.control_plane.routing_table_history
        fallback_tables = self.control_plane.get_routing_tables()
        tables_per_epoch = [history.get(i, fallback_tables) for i in range(num_epochs)]

        self.routing_tables = tables_per_epoch[-1] if tables_per_epoch else fallback_tables
        self.data_plane = DataPlane(
            routing_tables=self.routing_tables,
            edge_sets=self.edge_sets,
            attackers=self.attackers,
            routing_tables_per_epoch=tables_per_epoch
        )

        results = self.data_plane.evaluate_flows(
            flows=self.flow_pairs,
            positions_per_epoch=self.positions_per_epoch,
            epoch_duration=self.epoch_duration,
            base_time=self.base_time,
            num_epochs=num_epochs
        )

        # 防御：确保 results 是字典
        if results is None:
            results = {}

        results['total_loops'] = self.control_plane.total_loops + len(self.data_plane.loop_paths)
        results['loop_paths'] = self.data_plane.loop_paths
        results['attacker_stats'] = self.control_plane.get_attackers_stats()

        return results