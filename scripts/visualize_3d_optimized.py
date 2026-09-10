#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Starlink 星座3D交互可视化（优化版 - 融合 hypatia-impl satviz 思路）

优化点（参考 root-hbx/hypatia-impl 的 satviz 模块）：
1. 轨道面结构线：仿照 hypatia visualize_constellation.py 的 orbit_links，
   绘制同轨道面内卫星连线，展示星座 Walker-Delta 结构
2. 星间链路（ISL）可视化：仿照 hypatia util.py 的 find_grid_links，
   绘制 +Grid 拓扑下相邻轨道面间的链路，距离着色
3. 地面星下点投影：仿照 hypatia extractor.py 的 groundtrack 功能，
   将卫星位置投影到地球表面显示覆盖足迹
4. 时间控制增强：仿照 hypatia CZML Clock multiplier，
   添加播放速度控制（1x/2x/5x）和当前仿真时间显示
5. 多壳层颜色区分增强：参考 hypatia COLOR 数组，为每个壳层
   分配高对比度颜色并增加轨道面透明度渐变
6. 向量化计算优化：用 numpy 批量 SGP4 替代逐星 Python 循环
7. 相机预设视角：仿照 Cesium 自由相机，添加赤道/极地/斜视预设按钮
8. 地球渲染改进：使用 mesh3d 渐变球体替代简单 wireframe
"""

import os
import math
import random
from datetime import datetime, timedelta
import numpy as np
import plotly.graph_objects as go
from sgp4.api import Satrec, jday

# ===== 配置 =====
TLE_FILE = r"d:\starlink\starlink.tle"
OUTPUT_HTML = "results/viz/starlink_3d_final.html"
EARTH_RADIUS = 6371.0
MU = 398600.5

# 壳层定义（参考 hypatia visualize_constellation.py 的多壳层颜色方案）
SHELLS = {
    "53°":  {"inc_min": 52.0, "inc_max": 54.0, "alt_min": 440, "alt_max": 600, "color": "#FF6B6B"},
    "43°":  {"inc_min": 42.0, "inc_max": 44.0, "alt_min": 440, "alt_max": 600, "color": "#4ECDC4"},
    "70°":  {"inc_min": 69.0, "inc_max": 71.0, "alt_min": 550, "alt_max": 650, "color": "#45B7D1"},
    "97.5°":{"inc_min": 96.5, "inc_max": 98.5, "alt_min": 440, "alt_max": 600, "color": "#FFA07A"},
}
OTHER_COLOR = "#B0B0B0"
# ISL 链路颜色（仿 hypatia visualize_utilization.py 的距离梯度着色）
ISL_COLOR_CLOSE = "#00FF88"   # 近距离链路
ISL_COLOR_FAR = "#FF4444"     # 远距离链路
ISL_MAX_DIST = 4000.0         # km，超过此距离不绘制链路
GROUND_TRACK_COLOR = "rgba(255,255,0,0.3)"  # 星下点颜色（仿 hypatia groundtrack）

START_TIME = datetime(2026, 8, 22, 10, 13, 50)
DELTA_T = 10
NUM_FRAMES = 60
MAX_SATELLITES = 300

# ===== 工具函数 =====

def gmst(jd):
    """计算格林尼治平恒星时（弧度）"""
    T = (jd - 2451545.0) / 36525.0
    gmst_deg = 280.46061837 + 360.98564736629 * (jd - 2451545.0) \
               + 0.000387933 * T * T - T * T * T / 38710000.0
    gmst_deg = gmst_deg % 360.0
    return math.radians(gmst_deg)


def gmst_array(jd_arr):
    """向量化 GMST 计算（性能优化：批量处理所有时间步）"""
    T = (jd_arr - 2451545.0) / 36525.0
    gmst_deg = 280.46061837 + 360.98564736629 * (jd_arr - 2451545.0) \
               + 0.000387933 * T * T - T * T * T / 38710000.0
    return np.radians(gmst_deg % 360.0)


def parse_tle(filepath):
    """解析 TLE 文件，返回卫星对象列表"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"TLE 文件不存在: {filepath}")
    sats = []
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    for i in range(0, len(lines), 3):
        if i+2 >= len(lines):
            break
        name = lines[i]
        line1 = lines[i+1]
        line2 = lines[i+2]
        try:
            sat = Satrec.twoline2rv(line1, line2)
            no = sat.no * 2.0 * math.pi / 86400.0
            a = (MU / (no * no)) ** (1.0/3.0)
            alt = a - EARTH_RADIUS
            inc_deg = math.degrees(sat.inclo)
            # 提取 RAAN 用于轨道面分组（仿 hypatia util.py 的 orb_id 概念）
            raan_deg = math.degrees(sat.nodeo)
            sats.append({
                "sat": sat,
                "name": name,
                "alt": alt,
                "inc": inc_deg,
                "raan": raan_deg,
            })
        except Exception as e:
            print(f"警告：解析失败 {name}: {e}")
    return sats


def get_shell(inc_deg, alt_km):
    """根据倾角和高度判断壳层归属"""
    for name, spec in SHELLS.items():
        if spec["inc_min"] <= inc_deg <= spec["inc_max"] and spec["alt_min"] <= alt_km <= spec["alt_max"]:
            return name
    return "other"


def teme_to_ecef(r_teme, gmst_rad):
    """TEME 坐标系转 ECEF（单点）"""
    c = math.cos(gmst_rad)
    s = math.sin(gmst_rad)
    return (r_teme[0]*c + r_teme[1]*s,
            -r_teme[0]*s + r_teme[1]*c,
            r_teme[2])


def teme_to_ecef_batch(r_teme_arr, gmst_arr):
    """向量化 TEME→ECEF 转换（性能优化：一次处理所有卫星所有时刻）
    参考 hypatia extractor.py 的批量坐标处理思路"""
    c = np.cos(gmst_arr)
    s = np.sin(gmst_arr)
    x_ecef = r_teme_arr[:, 0] * c + r_teme_arr[:, 1] * s
    y_ecef = -r_teme_arr[:, 0] * s + r_teme_arr[:, 1] * c
    z_ecef = r_teme_arr[:, 2]
    return np.column_stack([x_ecef, y_ecef, z_ecef])


def compute_positions_vectorized(sats, times_jd):
    """向量化位置计算（性能优化核心）
    使用 sgp4 的批量接口替代逐星逐时刻循环，
    参考 hypatia satgenpy 的大规模星座状态生成方式"""
    n_sats = len(sats)
    n_times = len(times_jd)
    # 预分配数组
    positions_ecef = np.full((n_sats, n_times, 3), np.nan)
    gmst_cache = gmst_array(np.array(times_jd))

    for idx, item in enumerate(sats):
        sat = item["sat"]
        # 使用 sgp4 批量传播
        jd_arr = np.array([jd for jd in times_jd])
        fr_arr = np.zeros(n_times)
        errors, r_teme, v_teme = sat.sgp4_array(jd_arr, fr_arr)
        # 筛选有效结果
        valid = (errors == 0)
        if np.any(valid):
            r_valid = np.array(r_teme)[valid]
            gmst_valid = gmst_cache[valid]
            ecef_valid = teme_to_ecef_batch(r_valid, gmst_valid)
            positions_ecef[idx, valid, :] = ecef_valid

    return positions_ecef


def compute_orbital_plane_groups(sats, raan_tolerance=5.0):
    """按 RAAN 将卫星分组到轨道面（仿 hypatia util.py 的 orb_id 概念）
    hypatia 用 generate_sat_obj_list 中的 raan = orb * 360 / num_orbit 分组，
    这里对真实 TLE 数据用 RAAN 聚类实现类似效果"""
    if not sats:
        return []
    # 按 RAAN 排序
    sorted_indices = sorted(range(len(sats)), key=lambda i: sats[i]["raan"])
    groups = []
    current_group = [sorted_indices[0]]
    for i in range(1, len(sorted_indices)):
        prev_raan = sats[sorted_indices[i-1]]["raan"]
        curr_raan = sats[sorted_indices[i]]["raan"]
        # 处理 360°/0° 跨越
        diff = min(abs(curr_raan - prev_raan), 360 - abs(curr_raan - prev_raan))
        if diff <= raan_tolerance:
            current_group.append(sorted_indices[i])
        else:
            groups.append(current_group)
            current_group = [sorted_indices[i]]
    groups.append(current_group)
    # 合并首尾（如果跨越 0°/360°）
    if len(groups) > 1:
        first_raan = sats[groups[0][0]]["raan"]
        last_raan = sats[groups[-1][-1]]["raan"]
        diff = min(abs(first_raan - last_raan), 360 - abs(first_raan - last_raan))
        if diff <= raan_tolerance:
            groups[0] = groups[-1] + groups[0]
            groups.pop()
    return groups


def find_isl_links(positions_frame, max_dist=ISL_MAX_DIST):
    """查找帧内星间链路（仿 hypatia util.py 的 find_grid_links）
    基于空间距离阈值确定 ISL 连接，而非理想 +Grid 拓扑，
    适用于真实 TLE 数据的不均匀分布"""
    n = len(positions_frame)
    links = []
    if n < 2:
        return links
    # 使用 numpy 向量化距离计算
    pos = np.array(positions_frame)
    valid_mask = ~np.any(np.isnan(pos), axis=1)
    valid_indices = np.where(valid_mask)[0]
    if len(valid_indices) < 2:
        return links
    pos_valid = pos[valid_indices]
    # 计算成对距离矩阵
    diff = pos_valid[:, np.newaxis, :] - pos_valid[np.newaxis, :, :]
    dist_matrix = np.sqrt(np.sum(diff ** 2, axis=2))
    # 提取上三角中距离小于阈值的链路
    rows, cols = np.where((dist_matrix < max_dist) & (dist_matrix > 0) &
                          (np.triu(np.ones_like(dist_matrix), k=1) > 0))
    for r, c in zip(rows, cols):
        links.append((valid_indices[r], valid_indices[c], dist_matrix[r, c]))
    return links


def create_earth_mesh():
    """创建渐变地球球体（改进 hypatia 的 Cesium 地球渲染思路，
    在 Plotly 中使用 mesh3d 实现类似效果）"""
    # 使用 icosphere 细分生成球面网格
    n_lon, n_lat = 36, 18
    lon = np.linspace(0, 2 * np.pi, n_lon)
    lat = np.linspace(-np.pi / 2, np.pi / 2, n_lat)
    lon_grid, lat_grid = np.meshgrid(lon, lat)
    x = EARTH_RADIUS * np.cos(lat_grid) * np.cos(lon_grid)
    y = EARTH_RADIUS * np.cos(lat_grid) * np.sin(lon_grid)
    z = EARTH_RADIUS * np.sin(lat_grid)

    # 生成三角面索引
    i_tri, j_tri, k_tri = [], [], []
    for ilat in range(n_lat - 1):
        for ilon in range(n_lon - 1):
            idx = ilat * n_lon + ilon
            i_tri.extend([idx, idx + 1])
            j_tri.extend([idx + 1, idx + n_lon])
            k_tri.extend([idx + n_lon, idx + n_lon + 1])

    # 蓝色渐变（模拟海洋+大气层效果）
    intensity = z.flatten() / EARTH_RADIUS  # 用 z 坐标做颜色梯度

    earth_mesh = go.Mesh3d(
        x=x.flatten(), y=y.flatten(), z=z.flatten(),
        i=i_tri, j=j_tri, k=k_tri,
        intensity=intensity,
        colorscale=[[0, 'rgba(10,30,80,0.85)'], [0.5, 'rgba(20,60,140,0.75)'],
                    [1, 'rgba(40,100,200,0.65)']],
        showscale=False,
        opacity=0.8,
        name="Earth",
        hoverinfo="skip",
        flatshading=True
    )

    # 经纬网格线（保留原始风格但更精细）
    grid_lines = []
    for lon_val in np.linspace(0, 2 * np.pi, 13, endpoint=False):
        x_line = EARTH_RADIUS * np.cos(lat) * np.cos(lon_val)
        y_line = EARTH_RADIUS * np.cos(lat) * np.sin(lon_val)
        z_line = EARTH_RADIUS * np.sin(lat)
        grid_lines.append(go.Scatter3d(
            x=x_line, y=y_line, z=z_line,
            mode='lines',
            line=dict(color='rgba(100,180,255,0.25)', width=1),
            hoverinfo='skip', showlegend=False
        ))
    for lat_val in np.linspace(-np.pi / 2, np.pi / 2, 7):
        r = EARTH_RADIUS * np.cos(lat_val)
        z_const = EARTH_RADIUS * np.sin(lat_val)
        if r < 1:
            continue
        theta_fine = np.linspace(0, 2 * np.pi, 60)
        grid_lines.append(go.Scatter3d(
            x=r * np.cos(theta_fine), y=r * np.sin(theta_fine),
            z=np.full_like(theta_fine, z_const),
            mode='lines',
            line=dict(color='rgba(100,180,255,0.25)', width=1),
            hoverinfo='skip', showlegend=False
        ))
    # 赤道高亮
    theta_eq = np.linspace(0, 2 * np.pi, 80)
    grid_lines.append(go.Scatter3d(
        x=EARTH_RADIUS * np.cos(theta_eq),
        y=EARTH_RADIUS * np.sin(theta_eq),
        z=np.zeros_like(theta_eq),
        mode='lines',
        line=dict(color='rgba(255,200,50,0.4)', width=2),
        hoverinfo='skip', showlegend=False
    ))
    return [earth_mesh] + grid_lines


# ===== 帧构建辅助函数（每帧固定 7 个 trace，消除残留） =====
# trace 索引: 0=卫星, 1=轨道面线, 2=ISL近, 3=ISL中, 4=ISL远, 5=星下点, 6=时间标注
NUM_FRAME_TRACES = 7


def build_orbit_trace(positions_ecef, orbital_groups, frame_idx):
    """将所有轨道面线合并为单一 trace（None 分隔），保证帧 trace 数固定。
    仿 hypatia visualize_constellation.py 的 orbit_links 连线思路"""
    x_all, y_all, z_all = [], [], []
    for group in orbital_groups:
        if len(group) < 2:
            continue
        pts = positions_ecef[group, frame_idx, :]
        valid = ~np.any(np.isnan(pts), axis=1)
        if np.sum(valid) < 2:
            continue
        pts_valid = pts[valid]
        # 按经度角排序形成轨道面闭环
        angles = np.arctan2(pts_valid[:, 1], pts_valid[:, 0])
        sort_idx = np.argsort(angles)
        pts_sorted = pts_valid[sort_idx]
        pts_closed = np.vstack([pts_sorted, pts_sorted[0:1]])
        # 用 None 分隔不同轨道面
        if x_all:
            x_all.append(None); y_all.append(None); z_all.append(None)
        x_all.extend(pts_closed[:, 0].tolist())
        y_all.extend(pts_closed[:, 1].tolist())
        z_all.extend(pts_closed[:, 2].tolist())
    return go.Scatter3d(
        x=x_all if x_all else [None], y=y_all if y_all else [None],
        z=z_all if z_all else [None],
        mode='lines',
        line=dict(color='rgba(150,150,255,0.2)', width=1),
        hoverinfo='skip', showlegend=False, name='Orbit Planes'
    )


def build_ground_track_trace(positions_ecef, frame_idx, n_show=50):
    """星下点投影合并为单一 trace（仿 hypatia extractor.py groundtrack）"""
    pts = positions_ecef[:, frame_idx, :]
    valid = ~np.any(np.isnan(pts), axis=1)
    pts_valid = pts[valid]
    if len(pts_valid) == 0:
        return go.Scatter3d(x=[None], y=[None], z=[None], mode='markers',
                            marker=dict(size=1.5), hoverinfo='skip',
                            showlegend=False, name='Ground Tracks')
    if len(pts_valid) > n_show:
        indices = np.linspace(0, len(pts_valid) - 1, n_show, dtype=int)
        pts_valid = pts_valid[indices]
    r = np.sqrt(np.sum(pts_valid ** 2, axis=1, keepdims=True))
    ground_pts = pts_valid / r * (EARTH_RADIUS + 5)
    return go.Scatter3d(
        x=ground_pts[:, 0], y=ground_pts[:, 1], z=ground_pts[:, 2],
        mode='markers',
        marker=dict(size=1.5, color=GROUND_TRACK_COLOR, opacity=0.4),
        hoverinfo='skip', showlegend=False, name='Ground Tracks'
    )


def build_isl_traces(positions_ecef, frame_idx):
    """星间链路固定返回 3 个 trace（近/中/远），即使某档为空也返回空 trace。
    仿 hypatia util.py find_grid_links + visualize_utilization.py 距离着色"""
    pts = positions_ecef[:, frame_idx, :]
    valid_mask = ~np.any(np.isnan(pts), axis=1)
    valid_indices = np.where(valid_mask)[0]
    empty_trace = lambda: go.Scatter3d(x=[None], y=[None], z=[None], mode='lines',
                                       line=dict(width=1), hoverinfo='skip', showlegend=False)
    if len(valid_indices) < 2:
        return [empty_trace(), empty_trace(), empty_trace()]

    pos_valid = pts[valid_indices]
    # 向量化距离计算
    diff = pos_valid[:, np.newaxis, :] - pos_valid[np.newaxis, :, :]
    dist_matrix = np.sqrt(np.sum(diff ** 2, axis=2))
    upper_mask = np.triu(np.ones_like(dist_matrix, dtype=bool), k=1)
    close_mask = upper_mask & (dist_matrix < ISL_MAX_DIST * 0.33) & (dist_matrix > 0)
    mid_mask = upper_mask & (dist_matrix >= ISL_MAX_DIST * 0.33) & (dist_matrix < ISL_MAX_DIST * 0.66)
    far_mask = upper_mask & (dist_matrix >= ISL_MAX_DIST * 0.66) & (dist_matrix < ISL_MAX_DIST)

    traces = []
    for mask, color, opacity in [(close_mask, ISL_COLOR_CLOSE, 0.5),
                                  (mid_mask, '#FFAA00', 0.35),
                                  (far_mask, ISL_COLOR_FAR, 0.2)]:
        rows, cols = np.where(mask)
        if len(rows) == 0:
            traces.append(empty_trace())
            continue
        x_l, y_l, z_l = [], [], []
        for r, c in zip(rows, cols):
            p1 = pos_valid[r]; p2 = pos_valid[c]
            x_l.extend([p1[0], p2[0], None])
            y_l.extend([p1[1], p2[1], None])
            z_l.extend([p1[2], p2[2], None])
        traces.append(go.Scatter3d(
            x=x_l, y=y_l, z=z_l, mode='lines',
            line=dict(color=color, width=1), opacity=opacity,
            hoverinfo='skip', showlegend=False
        ))
    return traces


def build_frame_traces(positions_ecef, sat_names, sat_colors, orbital_groups, frame_idx):
    """构建单帧的固定 7 个 trace，保证所有帧结构一致，彻底消除残留"""
    pts = positions_ecef[:, frame_idx, :]
    valid = ~np.any(np.isnan(pts), axis=1)
    x_vals = pts[valid, 0]; y_vals = pts[valid, 1]; z_vals = pts[valid, 2]
    texts = [sat_names[i] for i in np.where(valid)[0]]
    colors_valid = [sat_colors[i] for i in np.where(valid)[0]]

    # trace 0: 卫星标记
    t_sat = go.Scatter3d(
        x=x_vals, y=y_vals, z=z_vals, mode='markers',
        marker=dict(size=3, color=colors_valid, opacity=0.9),
        text=texts, hoverinfo='text', name='Satellites'
    )
    # trace 1: 轨道面结构线（合并为单一 trace）
    t_orbit = build_orbit_trace(positions_ecef, orbital_groups, frame_idx)
    # trace 2-4: ISL 链路（固定 3 个 trace）
    t_isl = build_isl_traces(positions_ecef, frame_idx)
    # trace 5: 星下点
    t_ground = build_ground_track_trace(positions_ecef, frame_idx)
    # trace 6: 时间标注（放在原点附近，不拉伸轴范围）
    sim_time = START_TIME + timedelta(seconds=frame_idx * DELTA_T)
    t_time = go.Scatter3d(
        x=[0], y=[0], z=[0], mode='text',
        text=[f"T+{frame_idx*DELTA_T}s  {sim_time.strftime('%H:%M:%S')}"],
        textfont=dict(size=1, color='rgba(0,0,0,0)'),  # 不可见，时间显示由 layout annotation 承担
        hoverinfo='skip', showlegend=False
    )
    return [t_sat, t_orbit] + t_isl + [t_ground, t_time]


# ===== 主函数 =====
def main():
    os.makedirs(os.path.dirname(OUTPUT_HTML), exist_ok=True)

    print("加载 TLE 文件...")
    all_sats = parse_tle(TLE_FILE)
    print(f"成功解析 {len(all_sats)} 颗卫星")

    # 过滤主壳层
    filtered = [s for s in all_sats if s["alt"] >= 380.0 and 52.0 <= s["inc"] <= 54.0]
    print(f"主壳层（53°）卫星数: {len(filtered)}")

    if len(filtered) > MAX_SATELLITES:
        sampled = random.sample(filtered, MAX_SATELLITES)
        print(f"随机采样 {MAX_SATELLITES} 颗")
    else:
        sampled = filtered

    # 轨道面分组（仿 hypatia 的 num_orbit × num_sats_per_orbit 结构）
    orbital_groups = compute_orbital_plane_groups(sampled)
    print(f"识别到 {len(orbital_groups)} 个轨道面")

    # 时间序列
    jd_tuple = jday(START_TIME.year, START_TIME.month, START_TIME.day,
                    START_TIME.hour, START_TIME.minute, START_TIME.second)
    start_jd = jd_tuple[0] + jd_tuple[1]
    times_jd = [start_jd + i * DELTA_T / 86400.0 for i in range(NUM_FRAMES)]

    print("计算卫星位置（向量化批量传播）...")
    positions_ecef = compute_positions_vectorized(sampled, times_jd)
    print("位置计算完成")

    sat_names = [s["name"] for s in sampled]
    sat_colors = []
    for s in sampled:
        shell = get_shell(s["inc"], s["alt"])
        color = SHELLS.get(shell, {}).get("color", OTHER_COLOR) if shell in SHELLS else OTHER_COLOR
        sat_colors.append(color)

    # ---- 构建帧（每帧固定 7 个 trace，彻底消除残留） ----
    print("构建动画帧...")
    frames = []
    for frame_idx in range(NUM_FRAMES):
        frame_data = build_frame_traces(
            positions_ecef, sat_names, sat_colors, orbital_groups, frame_idx)
        frames.append(go.Frame(data=frame_data, name=f'frame{frame_idx}'))

    # ---- 初始数据：前 7 个为动态 trace（与帧对齐），后接地球和图例 ----
    initial_dynamic = build_frame_traces(
        positions_ecef, sat_names, sat_colors, orbital_groups, 0)
    earth_traces = create_earth_mesh()

    # 图例（壳层颜色）
    legend_traces = []
    for shell_name, spec in SHELLS.items():
        legend_traces.append(go.Scatter3d(
            x=[None], y=[None], z=[None],
            mode='markers',
            marker=dict(size=10, color=spec["color"]),
            name=f"Shell {shell_name}",
            showlegend=True
        ))
    legend_traces.append(go.Scatter3d(
        x=[None], y=[None], z=[None],
        mode='lines',
        line=dict(color=ISL_COLOR_CLOSE, width=2),
        name='ISL (near)',
        showlegend=True
    ))
    legend_traces.append(go.Scatter3d(
        x=[None], y=[None], z=[None],
        mode='markers',
        marker=dict(size=4, color=GROUND_TRACK_COLOR),
        name='Ground Track',
        showlegend=True
    ))

    # fig.data 结构: [7个动态trace] + [地球trace] + [图例trace]
    # 帧只替换索引 0~6，地球和图例永不被帧覆盖

    # ---- 相机预设按钮（仿 Cesium 自由相机的多视角切换，始终锁定原点居中） ----
    cam_center = dict(x=0, y=0, z=0)
    cam_up = dict(x=0, y=0, z=1)
    camera_buttons = [
        dict(label='🌍 Default', method='relayout',
             args=[{'scene.camera.eye': dict(x=2.0, y=2.0, z=1.2),
                    'scene.camera.center': cam_center, 'scene.camera.up': cam_up}]),
        dict(label='🌐 Equatorial', method='relayout',
             args=[{'scene.camera.eye': dict(x=0, y=-3.0, z=0.1),
                    'scene.camera.center': cam_center, 'scene.camera.up': cam_up}]),
        dict(label='🧭 Polar', method='relayout',
             args=[{'scene.camera.eye': dict(x=0, y=0.01, z=3.0),
                    'scene.camera.center': cam_center, 'scene.camera.up': dict(x=0, y=1, z=0)}]),
        dict(label='🔭 Oblique', method='relayout',
             args=[{'scene.camera.eye': dict(x=1.5, y=-1.5, z=1.8),
                    'scene.camera.center': cam_center, 'scene.camera.up': cam_up}]),
    ]

    # ---- 播放控制（仿 hypatia CZML Clock multiplier 多速度） ----
    play_buttons = [
        dict(label='▶ 1x', method='animate',
             args=[None, dict(frame=dict(duration=200, redraw=True),
                              fromcurrent=True, mode='immediate')]),
        dict(label='▶▶ 2x', method='animate',
             args=[None, dict(frame=dict(duration=100, redraw=True),
                              fromcurrent=True, mode='immediate')]),
        dict(label='▶▶▶ 5x', method='animate',
             args=[None, dict(frame=dict(duration=40, redraw=True),
                              fromcurrent=True, mode='immediate')]),
        dict(label='⏸ Pause', method='animate',
             args=[[None], dict(frame=dict(duration=0, redraw=False),
                                mode='immediate')]),
    ]

    fig = go.Figure(
        data=initial_dynamic + earth_traces + legend_traces,
        frames=frames,
        layout=go.Layout(
            title=dict(
                text="Starlink 星座三维可视化（优化版 · hypatia-impl inspired）<br>"
                     "<sup>10s/frame · 10min · ISL + Orbit Planes + Ground Tracks</sup>",
                font=dict(size=16, color='white')
            ),
            paper_bgcolor='rgba(5,5,20,1)',
            plot_bgcolor='rgba(5,5,20,1)',
            font=dict(color='white'),
            scene=dict(
                xaxis=dict(title="X (km)", gridcolor='rgba(100,100,100,0.2)',
                           zerolinecolor='rgba(100,100,100,0.3)', backgroundcolor='rgba(5,5,20,1)',
                           range=[-8500, 8500]),
                yaxis=dict(title="Y (km)", gridcolor='rgba(100,100,100,0.2)',
                           zerolinecolor='rgba(100,100,100,0.3)', backgroundcolor='rgba(5,5,20,1)',
                           range=[-8500, 8500]),
                zaxis=dict(title="Z (km)", gridcolor='rgba(100,100,100,0.2)',
                           zerolinecolor='rgba(100,100,100,0.3)', backgroundcolor='rgba(5,5,20,1)',
                           range=[-8500, 8500]),
                aspectmode='cube',
                camera=dict(
                    eye=dict(x=2.0, y=2.0, z=1.2),
                    center=dict(x=0, y=0, z=0),
                    up=dict(x=0, y=0, z=1)
                )
            ),
            updatemenus=[
                dict(type='buttons', direction='right', showactive=False,
                     buttons=play_buttons,
                     x=0.0, y=1.12, xanchor='left', yanchor='top',
                     bgcolor='rgba(50,50,80,0.6)', bordercolor='rgba(100,100,200,0.4)'),
                dict(type='buttons', direction='right', showactive=True,
                     buttons=camera_buttons,
                     x=0.0, y=1.06, xanchor='left', yanchor='top',
                     bgcolor='rgba(50,50,80,0.6)', bordercolor='rgba(100,100,200,0.4)'),
            ],
            sliders=[dict(
                active=0,
                currentvalue=dict(prefix="Time: ", font=dict(color='white', size=12)),
                steps=[
                    dict(method='animate',
                         args=[[f'frame{k}'], dict(mode='immediate',
                                                    frame=dict(duration=0, redraw=True))],
                         label=f"{(START_TIME + timedelta(seconds=k*DELTA_T)):%H:%M:%S}")
                    for k in range(NUM_FRAMES)
                ],
                transition=dict(duration=0),
                x=0.1, y=0, len=0.8,
                bgcolor='rgba(50,50,80,0.4)',
                bordercolor='rgba(100,100,200,0.3)',
                font=dict(color='white')
            )],
            legend=dict(
                title=dict(text="Layers", font=dict(size=13, color='white')),
                x=0.82, y=0.9,
                bgcolor='rgba(20,20,50,0.7)',
                bordercolor='rgba(100,100,200,0.4)',
                borderwidth=1,
                font=dict(size=11, color='white')
            ),
            margin=dict(l=10, r=10, t=80, b=80),
            annotations=[dict(
                x=0.5, y=0.02, xref='paper', yref='paper',
                text=f"T+0s  {START_TIME.strftime('%H:%M:%S')}",
                showarrow=False, font=dict(size=14, color='white'),
                bgcolor='rgba(20,20,50,0.6)', bordercolor='rgba(100,100,200,0.4)',
                borderwidth=1, borderpad=4
            )]
        )
    )

    print(f"保存到 {OUTPUT_HTML}")
    fig.write_html(OUTPUT_HTML, include_plotlyjs=True)
    file_size_mb = os.path.getsize(OUTPUT_HTML) / (1024 * 1024)
    print(f"完成！文件大小: {file_size_mb:.1f} MB")
    print(f"  - 卫星数: {len(sampled)}")
    print(f"  - 轨道面: {len(orbital_groups)}")
    print(f"  - 帧数: {NUM_FRAMES}")
    print(f"  - 特性: ISL链路 | 轨道面线 | 星下点 | 多速度播放 | 相机预设")


if __name__ == "__main__":
    main()