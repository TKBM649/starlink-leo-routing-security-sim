# starlink_sim/net/simulator.py
import pickle
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
import numpy as np
from starlink_sim.net.routing_dv import DVRouter, DVMessage
import math

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
            for att in self.attackers:
                if att.node_id == node_id and att.is_active(current_time):
                    modified_msgs = []
                    for msg in msgs:
                        modified_msg = att.modify_advertisement(msg, router, None, current_time)
                        modified_msgs.append(modified_msg)
                    msgs = modified_msgs
                    break
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

    def run_ticks(self, num_ticks: int, edge_sets: List[Set[Tuple[int, int]]], epoch_duration: float = 30.0):
        for tick in range(num_ticks):
            current_time = tick * self.tick_interval
            epoch_idx = int(current_time / epoch_duration)
            if epoch_idx >= len(edge_sets):
                epoch_idx = len(edge_sets) - 1
            current_edges = edge_sets[epoch_idx]
            self.step(current_time, current_edges)
            if (tick + 1) % 100 == 0:
                print(f"  Control plane tick {tick+1}/{num_ticks} done.")

    def get_routing_tables(self) -> Dict[int, Dict]:
        return {node: router.get_routing_table() for node, router in self.routers.items()}

    def get_attackers_stats(self) -> List[Dict]:
        return [{'node_id': a.node_id, 'attracted_count': a.attracted_count, 'dropped_count': a.dropped_count}
                for a in self.attackers]


class DataPlane:
    def __init__(self, routing_tables: Dict[int, Dict], edge_sets: List[Set[Tuple[int, int]]],
                 attackers: Optional[List[Attacker]] = None):
        self.routing_tables = routing_tables
        self.edge_sets = edge_sets
        self.num_nodes = len(routing_tables)
        self.attackers = attackers if attackers is not None else []

    def compute_path(self, src: int, dst: int, epoch_idx: int, positions: Optional[Dict[int, np.ndarray]] = None) -> Tuple[Optional[List[int]], float]:
        if src == dst:
            return [src], 0.0
        current = src
        path = [current]
        visited = set([current])
        max_hops = 100
        edges = self.edge_sets[epoch_idx] if epoch_idx < len(self.edge_sets) else set()
        total_delay = 0.0
        for _ in range(max_hops):
            router_entry = self.routing_tables.get(current)
            if router_entry is None:
                return None, 0.0
            entry = router_entry.get(dst)
            if entry is None:
                return None, 0.0
            next_hop = entry.next_hop
            if (current, next_hop) not in edges and (next_hop, current) not in edges:
                return None, 0.0
            if next_hop in visited:
                return path + [next_hop], 0.0
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
                       base_time: float = 0.0) -> Dict:
        """
        base_time: 该 epoch 的起始绝对时间，用于攻击者活跃判断。
        """
        num_epochs = len(self.edge_sets)
        deliveries = []
        hop_counts = []
        latencies = []
        successful_hop_counts = []
        successful_latencies = []

        attacked_count = 0
        dropped_by_attacker = 0

        for src, dst in flows:
            for epoch_idx in range(num_epochs):
                positions = positions_per_epoch[epoch_idx] if positions_per_epoch is not None else None
                path, delay = self.compute_path(src, dst, epoch_idx, positions)
                if path is not None:
                    attacked = False
                    dropped = False
                    epoch_time = base_time + epoch_idx * epoch_duration  # 真实绝对时间
                    for node in path:
                        for att in self.attackers:
                            if att.node_id == node and att.is_active(epoch_time):
                                attacked = True
                                if att.should_drop_data((src, dst), epoch_time):
                                    dropped = True
                                    dropped_by_attacker += 1
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

        for att in self.attackers:
            attacked_count += att.attracted_count

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