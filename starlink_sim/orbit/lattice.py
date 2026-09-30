# starlink_sim/orbit/lattice.py
import numpy as np
from sgp4.api import Satrec
from typing import List, Dict, Tuple
import math

def compute_raan_at_epoch(line1: str, line2: str, target_jd: float, target_fr: float) -> float:
    """
    使用 SGP4 传播到目标时刻，从位置/速度计算 RAAN（度，0-360）
    """
    sat = Satrec.twoline2rv(line1, line2)
    error, r, v = sat.sgp4(target_jd, target_fr)
    if error != 0:
        raise RuntimeError(f"SGP4 propagation error: {error}")
    # 角动量 h = r × v
    hx = r[1]*v[2] - r[2]*v[1]
    hy = r[2]*v[0] - r[0]*v[2]
    hz = r[0]*v[1] - r[1]*v[0]
    # RAAN = atan2(hx, -hy)
    raan_rad = math.atan2(hx, -hy)
    if raan_rad < 0:
        raan_rad += 2 * math.pi
    return raan_rad * 180 / math.pi

def fit_planes_for_shell(records: List[Dict], shell_name: str, t0_jd: float, t0_fr: float) -> Tuple[int, float, List[Dict]]:
    """
    对给定壳层的记录进行格点拟合。
    返回 (P, phi, updated_records) 其中 updated_records 添加了 'plane_id' 和 'off_lattice' 字段。
    """
    # 提取 RAAN 在 t0 时刻的值
    raans = []
    for rec in records:
        raan = compute_raan_at_epoch(rec['line1'], rec['line2'], t0_jd, t0_fr)
        rec['raan_t0'] = raan
        raans.append(raan)
    N = len(records)
    if N == 0:
        return None, None, records

    # 扫描 P 从 10 到 180
    best_P = None
    best_phi = None
    best_excess = -1
    step_phi = 0.1  # 度，搜索精度

    for P in range(10, 181):
        # 对每个 P，搜索 phi 在 [0, 360/P) 内，步长 0.1°
        for phi in np.arange(0, 360/P, step_phi):
            centers = np.array([phi + k * (360/P) for k in range(P)])
            in_grid = 0
            for r in raans:
                diff = (r - centers + 180) % 360 - 180
                min_dist = np.min(np.abs(diff))
                if min_dist <= 0.6:
                    in_grid += 1
            random_share = min(1.0, 2 * 0.6 * P / 360)
            excess = in_grid / N - random_share
            if excess > best_excess:
                best_excess = excess
                best_P = P
                best_phi = phi

    # 使用最佳 P 和 phi 分配面号
    centers = np.array([best_phi + k * (360/best_P) for k in range(best_P)])
    off_lattice_count = 0
    for rec, r in zip(records, raans):
        diff = (r - centers + 180) % 360 - 180
        min_dist = np.min(np.abs(diff))
        if min_dist <= 0.6:
            plane_id = np.argmin(np.abs(diff))
            rec['plane_id'] = int(plane_id)
            rec['off_lattice'] = False
        else:
            rec['plane_id'] = -1
            rec['off_lattice'] = True
            off_lattice_count += 1

    print(f"Shell {shell_name}: P={best_P}, phi={best_phi:.2f}°, excess={best_excess:.3f}, "
          f"off_lattice={off_lattice_count}/{N} ({100*off_lattice_count/N:.1f}%)")
    return best_P, best_phi, records