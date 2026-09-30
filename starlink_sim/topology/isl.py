# starlink_sim/topology/isl.py
import numpy as np
from sgp4.api import Satrec
from typing import List, Dict, Tuple, Set
from collections import defaultdict
import math

R_EARTH = 6371.0
SPEED_OF_LIGHT = 299792.458  # km/s

# Satrec 解析缓存：TLE 两行 -> Satrec 对象。
# Satrec 初始化后 sgp4(jd, fr) 调用是无状态的，复用对象与每次 twoline2rv
# 结果完全一致，仅避免全量重生成（4284 星 × 121 epoch）时的重复解析开销。
_SATREC_CACHE: Dict[Tuple[str, str], Satrec] = {}

def _get_satrec(line1: str, line2: str) -> Satrec:
    key = (line1, line2)
    sat = _SATREC_CACHE.get(key)
    if sat is None:
        sat = Satrec.twoline2rv(line1, line2)
        _SATREC_CACHE[key] = sat
    return sat

def propagate_satellite(line1: str, line2: str, jd: float, fr: float):
    """返回 (位置矢量, 速度矢量) 或 None。位置单位 km（TEME 坐标系）。"""
    sat = _get_satrec(line1, line2)
    error, r, v = sat.sgp4(jd, fr)
    if error != 0:
        return None
    return np.array(r), np.array(v)

def compute_phase(rec: dict, jd: float, fr: float) -> float:
    """计算卫星在指定时刻的沿轨相位（度）"""
    sat = _get_satrec(rec['line1'], rec['line2'])
    ma0 = sat.mo * 180 / math.pi
    n = sat.no * 2 * math.pi / 86400.0
    epoch_jd = sat.jdsatepoch
    epoch_fr = sat.jdsatepochF
    dt_sec = (jd + fr - epoch_jd - epoch_fr) * 86400.0
    ma = (ma0 + n * dt_sec * 180 / math.pi) % 360
    ap = sat.argpo * 180 / math.pi
    return (ma + ap) % 360

def build_edges_for_epoch(records: List[dict], jd: float, fr: float,
                          max_dist_km: float = 2000.0,
                          out_positions: Dict[int, np.ndarray] = None) -> Set[Tuple[int, int]]:
    """构建单个 epoch 的边集。若传入 out_positions（dict），则同时回填各节点
    在该 epoch 的位置矢量 {node_id: np.ndarray(x, y, z)}（TEME，单位 km），
    避免为计算位置而重复 SGP4 传播。"""
    N = len(records)
    if N == 0:
        return set()

    pos_dict = {}
    phase_dict = {}
    for i, rec in enumerate(records):
        pos = propagate_satellite(rec['line1'], rec['line2'], jd, fr)
        if pos is None:
            continue
        pos_dict[i] = pos[0]
        phase_dict[i] = compute_phase(rec, jd, fr)

    if out_positions is not None:
        out_positions.update(pos_dict)

    if len(pos_dict) < 2:
        return set()

    edges = set()
    planes = defaultdict(list)
    for i, rec in enumerate(records):
        if not rec.get('off_lattice', False) and 'plane_id' in rec:
            p = rec['plane_id']
            planes[p].append(i)

    # 1. 同面链路：实际最近邻（前后各1），相位差<180°
    for p, idx_list in planes.items():
        if len(idx_list) < 2:
            continue
        idx_sorted = sorted(idx_list, key=lambda i: phase_dict.get(i, 0))
        m = len(idx_sorted)
        for k, i in enumerate(idx_sorted):
            candidates = []
            for offset in [-2, -1, 1, 2]:
                j = idx_sorted[(k + offset) % m]
                if j == i:
                    continue
                diff = abs(phase_dict[i] - phase_dict[j])
                if diff > 180:
                    diff = 360 - diff
                candidates.append((diff, j))
            candidates.sort(key=lambda x: x[0])
            added = set()
            for diff, j in candidates[:2]:
                if j in added:
                    continue
                if i in pos_dict and j in pos_dict:
                    dist = np.linalg.norm(pos_dict[i] - pos_dict[j])
                    if dist <= max_dist_km:
                        edges.add(tuple(sorted((i, j))))
                        added.add(j)

    # 2. 异面链路：相邻面最接近相位
    all_planes = sorted(planes.keys())
    for p in all_planes:
        for neighbor_p in (p-1, p+1):
            if neighbor_p not in planes:
                continue
            for i in planes[p]:
                if i not in phase_dict:
                    continue
                best_j = None
                best_diff = 360.0
                for j in planes[neighbor_p]:
                    if j not in phase_dict:
                        continue
                    diff = (phase_dict[j] - phase_dict[i]) % 360
                    if diff > 180:
                        diff = 360 - diff
                    if diff < best_diff:
                        best_diff = diff
                        best_j = j
                if best_j is not None:
                    if i in pos_dict and best_j in pos_dict:
                        dist = np.linalg.norm(pos_dict[i] - pos_dict[best_j])
                        if dist <= max_dist_km:
                            edges.add(tuple(sorted((i, best_j))))

    # 3. 面外卫星：几何回退（kNN，距离门限 max_dist_km）
    off_indices = [i for i, rec in enumerate(records) if rec.get('off_lattice', False) and i in pos_dict]
    if off_indices:
        for i in off_indices:
            pos_i = pos_dict[i]
            dist_list = []
            for j, pos_j in pos_dict.items():
                if j == i:
                    continue
                d = np.linalg.norm(pos_i - pos_j)
                dist_list.append((d, j))
            dist_list.sort(key=lambda x: x[0])
            count = 0
            for d, j in dist_list:
                if d <= max_dist_km and count < 4:
                    edges.add(tuple(sorted((i, j))))
                    count += 1
                if count >= 4:
                    break

    return edges

def build_topology_for_shell(records: List[dict], times: List[Tuple[float, float]],
                             max_dist_km: float = 2000.0,
                             progress_every: int = 0) -> Dict:
    """构建壳层全时段拓扑。

    返回 dict 包含：
      - edges_per_epoch: List[Set[(i, j)]]
      - positions_per_epoch: List[Dict[node_id, np.ndarray(x, y, z)]]，
        与 edges_per_epoch 同长度、同 node_id 键（均为 records 的枚举下标），
        坐标系为 SGP4 TEME、单位 km，使 norm(pos差)/c*1000 直接得到 ms 时延，
        与 DataPlane.compute_path 的时延计算一致。
      - event_stream, num_epochs
    """
    edges_per_epoch = []
    positions_per_epoch = []
    num_epochs = len(times)
    for e_idx, (jd, fr) in enumerate(times):
        positions: Dict[int, np.ndarray] = {}
        edges = build_edges_for_epoch(records, jd, fr, max_dist_km,
                                      out_positions=positions)
        edges_per_epoch.append(edges)
        positions_per_epoch.append(positions)
        if progress_every > 0 and ((e_idx + 1) % progress_every == 0 or e_idx == num_epochs - 1):
            print(f"    epoch {e_idx + 1}/{num_epochs}: "
                  f"{len(edges)} edges, {len(positions)} positions", flush=True)

    event_stream = []
    all_edges = set()
    for edges in edges_per_epoch:
        all_edges.update(edges)

    for edge in all_edges:
        start_idx = None
        for t_idx, edges in enumerate(edges_per_epoch):
            if edge in edges:
                if start_idx is None:
                    start_idx = t_idx
            else:
                if start_idx is not None:
                    event_stream.append((start_idx, t_idx-1, edge))
                    start_idx = None
        if start_idx is not None:
            event_stream.append((start_idx, len(times)-1, edge))

    return {
        'edges_per_epoch': edges_per_epoch,
        'positions_per_epoch': positions_per_epoch,
        'event_stream': event_stream,
        'num_epochs': len(times)
    }

def compute_edge_overlap(edges1: Set, edges2: Set) -> float:
    if not edges1 and not edges2:
        return 1.0
    inter = len(edges1 & edges2)
    union = len(edges1 | edges2)
    return inter / union if union > 0 else 0.0