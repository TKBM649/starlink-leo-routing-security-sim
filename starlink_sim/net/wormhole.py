# starlink_sim/net/wormhole.py
"""
E6 Wormhole（虫洞）攻击的**隧道边注入**、**端点选取**与**物理接地检测器**。

虫洞语义
========
两个**物理上相距很远**的真实节点 A、B 通过私有隧道串通，对彼此邻域伪造可达性，
使网络误以为它们**相邻**：一条"短 metric 跳"实为超长物理距离。后果是流量被牵引、
路由环路、地理路由（geo-routing）被破坏。

与 Sybil 的关键差异：虫洞**不新增节点身份**——A、B 都是既有真实节点，因此
**不需要扩展节点 ID 空间**（``num_nodes`` 不变），只需把隧道边注入每个 epoch 的
edge_sets。注入范式与 :mod:`starlink_sim.net.sybil` 完全同构（新建 set、只读纪律、
必须在 ``ControlPlane`` 构建**之前**完成——``ControlPlane.update_neighbors`` 只认
已存在于 edge_sets 的边）。

物理接地检测（本项的科研亮点）与其**适用前提**
============================================
:func:`starlink_sim.topology.isl.build_edges_for_epoch` 对合法 ISL 施加**硬距离上限**
``max_dist_km``（**代码默认 2000 km**；同面/异面/kNN 三条建链分支都只在
``norm(pos_i - pos_j) <= max_dist_km`` 时加边）。**在据此上限生成的拓扑上**，任何合法边
物理距离 ``<= max_isl_km``，而虫洞隧道连接相距数千公里的真实节点、其“单跳”距离远超该
上限，于是“测量实际转发跳的物理距离、凡显著超过合法 ISL 分布者判为虫洞”就是一个
**零误报**（sound）判据（卫星星历 positions 公开可得）。

**前提与 shipped 数据的实测结论（务必阅读）**
------------------------------------------
上述零误报性**以“合法 ISL 受 ``max_isl_km`` 约束”为前提**。实测本仓库 shipped 的
``data/topology/topology_results.pkl`` 四个壳（53°/70°/97.5°/43°）的合法边距离**并未**受
2000 km 约束：中位 ~2700–4200 km、p90 ~1.0–1.3×10^4 km、最大 ~1.37×10^4 km（≈ 该轨道
高度的对踵距离 2R，R≈6850 km）——即该 pkl 是用**远大于默认的 ``max_dist_km``** 生成的。后果：

- **绝对判据**（``max_isl_km * distance_factor`` = 3000 km）在 shipped 数据上会**大量误报**
  （53° 壳 46.5% 合法边 > 3000 km），故实际由**自适应判据** ``median_hop_km * adaptive_factor``
  主导。但因虫洞两端皆真实节点，隧道长度上界同为对踵距离 ~2R，落在合法边分布**之内**
  （隧道 ~1.36–1.37×10^4 km ≈ 合法最大边），**没有任何阈值能把隧道与最长的合法边分开**——
  检测器在 shipped 数据上**不可分离**，其表现随子集 ``median_hop_km``（决定自适应阈值落点）而变，
  呈现「检出率 vs 误报率」的**此消彼长**（实测 53° 壳单臂单 seed）：

  ============  ============  ==========  ==========  ==========  ==========
  node_limit    median_isl    threshold   tunnel_km   det_rate    fp_rate
  96            6638          19916       13682       0.0         0.000
  512           4158          12475       13682       1.0         0.114
  1024          3234          9702        13568       1.0         0.201
  ============  ============  ==========  ==========  ==========  ==========

  小 subset（median 高）阈值被抬到最长合法边之上 → ``fp=0`` 但 ``detection_rate=0``（**漏报**）；
  大 subset（median 低）阈值落到隧道之下 → 检出隧道但同时误报更长的合法边（``fp>0``，**非 sound**）。
  这是 shipped 数据 ISL 未受距离上限约束的**直接后果，非检测器 bug**。
- **时延判据**（:func:`detect_wormhole_by_latency`）同理接近饱和：shipped 合法路径平均每跳
  时延（~23 ms）本就远超 ``2000 km / c ≈ 6.67 ms``，基线臂即 ``flagged_ratio≈0.95``，判别力弱。

因此：检测器的**真阳能力**在“合法 ISL 受距离上限约束”的拓扑上成立，并由
``tests/test_wormhole.py`` 的合成受限拓扑单元测试验证（隧道 ~5600 km、合法边 800 km →
detection_rate=1.0、基线 fp=0.0）；在 shipped 全量拓扑上，E6 的**主信号**是不依赖距离前提的
攻击效果度量（``attracted_ratio`` / ``path_stretch`` / 送达率对比——实测 t1/t3/extreme 牵引
0.25/0.55/0.80、送达 1.0/1.0/0.2，随隧道数与强度单调）。要在 shipped 数据上让距离检测器出
真阳，需一个按 ``max_dist_km``（如 2000）重新生成的拓扑缓存——本项遵循“不重生成 data”约束，
故不改数据。

检测器提供两条相互独立的信号（在受限拓扑上均 sound）：

1. **距离不一致**（:func:`detect_wormhole_edges`）：逐边物理距离 vs 阈值
   ``max(max_isl_km * distance_factor, median_hop_km * adaptive_factor)``。前者是建链硬上限的
   绝对判据，后者是“邻域中位跳距若干倍”的自适应判据（对未知建链门限稳健；在“合法 ISL 受
   上限约束”的拓扑上它兜底保持零误报，但在 shipped 数据上二者不可分离——见上方实测表）。
   再与路由表交叉，区分“存在嫌疑边”与“嫌疑边**确被用于转发**”
   （后者才对应真实危害）。
2. **时延-跳数不一致**（:func:`detect_wormhole_by_latency`）：仅用端到端可观测量（成功流的
   时延与跳数），**不需要边集/邻居信息**，是更弱假设下的独立检测面。

只读拓扑纪律
============
本模块**只读**基础拓扑：所有边集扩充都生成新的 set，绝不原地修改传入的
``edges_per_epoch``（sweep worker 进程内 ``_TOPO_CACHE`` 跨任务共享，原地修改会
污染其他臂的实验结果）。
"""
from __future__ import annotations

import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import numpy as np

from starlink_sim.net.placement import cumulative_degree, all_nodes

__all__ = [
    'SPEED_OF_LIGHT_KM_S',
    'DEFAULT_MAX_ISL_KM',
    'DEFAULT_DISTANCE_FACTOR',
    'DEFAULT_ADAPTIVE_FACTOR',
    'DEFAULT_LATENCY_FACTOR',
    'MAX_ISL_ONEWAY_MS',
    'WORMHOLE_ENDPOINT_STRATEGIES',
    'WORMHOLE_METRIC_KEYS',
    'WormholeInjection',
    'WormholeDetection',
    'canonical_edge',
    'edge_distances',
    'select_wormhole_peer',
    'inject_wormhole_tunnels',
    'expand_topology_for_wormholes',
    'forwarding_hops',
    'detect_wormhole_edges',
    'detect_wormhole_by_latency',
    'summarize_wormhole_detection',
    'run_wormhole_detection',
    'trace_forwarding_hops',
    'compute_wormhole_metrics',
]

Edge = Tuple[int, int]
EdgesPerEpoch = Sequence[Iterable[Edge]]
Positions = Optional[Dict[int, np.ndarray]]
PositionsPerEpoch = Optional[Sequence[Positions]]

SPEED_OF_LIGHT_KM_S = 299792.458

# isl.build_edges_for_epoch 的合法 ISL 硬距离上限（km）——检测器绝对判据的基线。
# 注意：这是**建链函数的代码默认**；实测 shipped 的 topology_results.pkl 是用**更大的
# max_dist_km** 生成的（合法边最大 ~1.37e4 km ≈ 对踵），故绝对判据在其上会误报、
# 由自适应判据兜底保持零误报（详见模块 docstring 的“适用前提”一节）。
DEFAULT_MAX_ISL_KM = 2000.0
# 绝对阈值倍数：threshold >= max_isl_km * distance_factor = 3000 km
DEFAULT_DISTANCE_FACTOR = 1.5
# 自适应阈值倍数：threshold >= median_hop_km * adaptive_factor（对未知建链门限稳健）
DEFAULT_ADAPTIVE_FACTOR = 3.0
# 时延判据倍数：平均每跳时延 > (max_isl_km / c) * latency_factor → 物理不可能。
# 取 1.0 即合法单跳的**物理上界**本身：在“合法 ISL <= max_isl_km”的拓扑上，合法路径的
# 平均每跳时延 <= 最大单跳时延 <= max_isl_km / c，故零误报（sound）；但 shipped 数据合法边
# 远超 2000 km，该判据在其上接近饱和（基线臂 flagged_ratio≈0.95，见模块 docstring），判别力
# 弱。调小可提升灵敏度但会引入误报，调大则漏报。
DEFAULT_LATENCY_FACTOR = 1.0
# 合法 ISL 单跳单向时延上界（ms）≈ 6.672
MAX_ISL_ONEWAY_MS = DEFAULT_MAX_ISL_KM / SPEED_OF_LIGHT_KM_S * 1000.0

# 对端选取策略（A 由 placement 模块决定，此处只选 B）
WORMHOLE_ENDPOINT_STRATEGIES: Tuple[str, ...] = (
    'farthest', 'betweenness', 'degree', 'random',
)

# Wormhole 特有指标键（放入 data_stats 后即被 analytics.stats.extract_metrics 自动
# 提取，并由 sweep 追加到聚合 metrics 列表；某臂缺失时聚合自动跳过，不破坏匹配键）。
#
# 发射规则（与 Sybil 键同模式，保证纯附加）：
# - ``WORMHOLE_BASELINE_KEYS``：只要启用了虫洞检测（存在 WormholeAttacker 或配置
#   ``detection.wormhole``）就**恒发射**。在**无虫洞基线臂**上它们同样有意义：
#   ``attracted_ratio`` 应为 0、``false_positive_rate`` 应为 0（检测器的误报度量）、
#   ``latency_flagged_ratio`` 应为 0（时延判据的 soundness 验证）——这正是与攻击臂
#   配对比较所需的对照量。
# - ``WORMHOLE_TUNNEL_KEYS``：**仅在注入了隧道时发射**。基线臂无 ground truth，
#   检测率/被检隧道数/隧道长度无定义，path/geo stretch 也没有"去隧道参考最短路"
#   可比；发射 0.0 只会污染统计，故让它们在基线臂缺席 → 聚合自动跳过。
WORMHOLE_BASELINE_KEYS: Tuple[str, ...] = (
    'wormhole_num_tunnels',
    'wormhole_attracted_ratio',
    'wormhole_attracted_trials',
    'wormhole_false_positive_rate',
    'wormhole_suspicious_hops',
    'wormhole_edges_examined',
    'wormhole_latency_flagged_ratio',
)
WORMHOLE_TUNNEL_KEYS: Tuple[str, ...] = (
    'wormhole_detection_rate',
    'wormhole_detected_tunnels',
    'wormhole_path_stretch',
    'wormhole_geo_stretch',
    'wormhole_mean_tunnel_km',
)
WORMHOLE_METRIC_KEYS: Tuple[str, ...] = WORMHOLE_BASELINE_KEYS + WORMHOLE_TUNNEL_KEYS


# ==================== 基础工具 ====================

def canonical_edge(u: int, v: int) -> Edge:
    """规范化无向边为 ``(min, max)``——与 ``isl.build_edges_for_epoch`` 的存储约定一致。"""
    return (u, v) if u <= v else (v, u)


def edge_distances(positions: Positions, edges: Iterable[Edge]) -> Dict[Edge, float]:
    """逐边物理距离（km）。两端点均有 positions 的边才可测；不可测的边被跳过。"""
    if not positions:
        return {}
    pairs: List[Edge] = []
    pa: List[Any] = []
    pb: List[Any] = []
    for (u, v) in edges:
        pu = positions.get(u)
        pv = positions.get(v)
        if pu is None or pv is None:
            continue
        pairs.append(canonical_edge(u, v))
        pa.append(pu)
        pb.append(pv)
    if not pairs:
        return {}
    A = np.asarray(pa, dtype=float)
    B = np.asarray(pb, dtype=float)
    d = np.linalg.norm(A - B, axis=1)
    return {p: float(x) for p, x in zip(pairs, d)}


def aggregate_adjacency(edges_per_epoch: EdgesPerEpoch) -> Dict[int, Set[int]]:
    """聚合图邻接表（所有 epoch 边的并集）。"""
    adj: Dict[int, Set[int]] = defaultdict(set)
    for edges in edges_per_epoch:
        for u, v in edges:
            adj[u].add(v)
            adj[v].add(u)
    return dict(adj)


def _bfs_hops(adj: Dict[int, Set[int]], src: int) -> Dict[int, int]:
    """单源 BFS 跳数（不可达节点不出现在结果中）。"""
    dist = {src: 0}
    q = deque([src])
    while q:
        u = q.popleft()
        du = dist[u]
        for v in adj.get(u, ()):  # 聚合图邻接
            if v not in dist:
                dist[v] = du + 1
                q.append(v)
    return dist


def _bfs_parents(adj: Dict[int, Set[int]], src: int) -> Dict[int, int]:
    """单源 BFS 父指针表（用于重建最短路路径）。"""
    parent: Dict[int, int] = {src: src}
    q = deque([src])
    while q:
        u = q.popleft()
        for v in sorted(adj.get(u, ())):  # sorted → 确定性 tie-break
            if v not in parent:
                parent[v] = u
                q.append(v)
    return parent


def _path_from_parents(parent: Dict[int, int], src: int, dst: int) -> Optional[List[int]]:
    """由父指针表重建 src→dst 路径；不可达返回 None。"""
    if dst not in parent:
        return None
    path = [dst]
    cur = dst
    while cur != src:
        cur = parent[cur]
        path.append(cur)
        if len(path) > len(parent) + 1:  # 防御：异常父指针
            return None
    path.reverse()
    return path


def first_positions(positions_per_epoch: PositionsPerEpoch) -> Positions:
    """取第一份非空 positions（端点选取只需一个几何快照）。"""
    if not positions_per_epoch:
        return None
    for pos in positions_per_epoch:
        if pos:
            return pos
    return None


# ==================== ① 对端选取 ====================

def select_wormhole_peer(edges_per_epoch: EdgesPerEpoch,
                         node_a: int,
                         strategy: str = 'farthest',
                         positions: Positions = None,
                         rng: Optional[random.Random] = None,
                         pool_size: int = 48,
                         available_nodes: Optional[Iterable[int]] = None,
                         exclude_nodes: Optional[Iterable[int]] = None) -> Optional[int]:
    """
    为虫洞端点 ``node_a`` 选取对端 ``node_b``（默认取**物理上最远**的高价值节点）。

    参数
    ----
    edges_per_epoch : 逐 epoch 边集（**只读**）。
    node_a          : 已确定的虫洞一端（由 ``placement`` 模块的攻击者布点决定）。
    strategy        : 对端策略，见 :data:`WORMHOLE_ENDPOINT_STRATEGIES`：

                      - ``'farthest'``（默认）：候选池中**物理距离最远**者（需 positions；
                        缺失时回退 ``'betweenness'``）。最大化"时延-跳数不一致"，
                        使隧道最容易被物理接地检测器发现，也最能破坏地理路由。
                      - ``'betweenness'``：聚合图上**跳数最远**者（tie-break 按介数），
                        无需 positions。
                      - ``'degree'``：累计度数最高者（最大化路由影响面，但物理距离不保证远）。
                      - ``'random'``：均匀随机（用 ``rng`` 保证可复现）。
    positions       : 几何快照 ``{node_id: np.ndarray(x,y,z)}``（km，TEME）。
    pool_size       : 高价值候选池大小（按累计度取 top-K，再在其中按策略择优）。
                      限制池大小既符合"攻击者瞄准枢纽"的现实假设，也把 O(N^2) 降为 O(K)。
    available_nodes : 候选节点全集；默认从边集推导。
    exclude_nodes   : 需排除的节点（如其他虫洞已占用的端点，避免端点复用）。

    返回
    ----
    对端 node_id；无合法候选时返回 ``None``。**已在任一 epoch 与 ``node_a`` 相邻的节点
    不会被选为对端**——它们本就相邻，隧道既无新增可达性也无物理异常，攻击与检测都无意义。
    """
    if rng is None:
        rng = random.Random(0)
    present = all_nodes(edges_per_epoch)
    if not present:
        return None
    pool_base = present if available_nodes is None else (set(available_nodes) & present)

    adj = aggregate_adjacency(edges_per_epoch)
    excluded: Set[int] = {int(node_a)} | set(exclude_nodes or ())
    excluded |= set(adj.get(node_a, ()))          # 排除既有邻居
    cand = sorted(n for n in pool_base if n not in excluded)
    if not cand:
        return None

    # 高价值候选池：累计度 top-K（确定性 tie-break：度降序 → id 升序）
    deg = cumulative_degree(edges_per_epoch)
    pool = sorted(cand, key=lambda n: (-deg.get(n, 0), n))
    pool = pool[:max(1, int(pool_size))] if pool_size else pool

    strat = strategy if strategy in WORMHOLE_ENDPOINT_STRATEGIES else 'farthest'

    if strat == 'random':
        return int(rng.choice(pool))

    if strat == 'degree':
        return int(pool[0])

    if strat == 'farthest':
        if positions:
            pa = positions.get(node_a)
            if pa is not None:
                d = edge_distances(positions, [(node_a, n) for n in pool])
                scored = [(d.get(canonical_edge(node_a, n)), n) for n in pool]
                scored = [(x, n) for x, n in scored if x is not None]
                if scored:
                    # 距离降序 → id 升序（确定性）
                    scored.sort(key=lambda t: (-t[0], t[1]))
                    return int(scored[0][1])
        strat = 'betweenness'   # 无 positions / 无可测距离 → 回退

    # 'betweenness'：聚合图上跳数最远者，tie-break 按介数中心性
    hops = _bfs_hops(adj, int(node_a))
    reachable = [n for n in pool if n in hops]
    if not reachable:
        return int(pool[0])
    try:
        import networkx as nx
        G = nx.Graph()
        G.add_nodes_from(sorted(present))
        for edges in edges_per_epoch:
            G.add_edges_from(edges)
        bc = nx.betweenness_centrality(G, k=min(64, G.number_of_nodes()))
    except Exception:  # networkx 不可用时仅按跳数
        bc = {}
    reachable.sort(key=lambda n: (-hops[n], -float(bc.get(n, 0.0)), n))
    return int(reachable[0])


# ==================== ② 隧道边注入 ====================

@dataclass
class WormholeInjection:
    """一次虫洞隧道注入的结果（edge_sets 扩充；**节点 ID 空间不变**）。"""
    edges_per_epoch: List[Set[Edge]]                  # 扩充后的逐 epoch 边集（新对象）
    tunnels: List[Edge]                               # 规范化隧道端点对 [(min,max), ...]
    node_ids: List[int]                               # 节点全集（与注入前一致）
    num_nodes: int                                    # = max(node_ids)+1（与注入前一致）
    tunnel_km: Dict[Edge, float] = field(default_factory=dict)   # 隧道物理距离（跨 epoch 均值）
    strategy: str = 'farthest'
    controllers: List[int] = field(default_factory=list)         # 各隧道的 A 端（攻击者 node_id）


def inject_wormhole_tunnels(edges_per_epoch: EdgesPerEpoch,
                            tunnels: Iterable[Tuple[int, int]],
                            positions_per_epoch: PositionsPerEpoch = None,
                            available_nodes: Optional[Iterable[int]] = None,
                            strategy: str = 'farthest',
                            controllers: Optional[Iterable[int]] = None
                            ) -> WormholeInjection:
    """
    把虫洞隧道边 ``(A, B)`` 注入**每一个 epoch** 的 edge_sets（隧道常驻）。

    与 :func:`starlink_sim.net.sybil.inject_sybil_identities` 同构，但**不分配新节点
    ID、不扩展 ``num_nodes``**——虫洞连接的是两个既有真实节点。返回的
    ``edges_per_epoch`` 是全新的 set 列表，传入对象绝不被修改。

    参数
    ----
    edges_per_epoch   : 基础拓扑逐 epoch 边集（**只读**）。
    tunnels           : 隧道端点对可迭代对象 ``[(A, B), ...]``；内部规范化为 ``(min, max)``。
    positions_per_epoch : 逐 epoch positions（用于记录隧道物理距离，供审计与检测器阈值参照）。
    available_nodes   : 节点全集；默认从边集推导。
    strategy          : 仅记录（端点选取见 :func:`select_wormhole_peer`）。
    controllers       : 仅记录（各隧道的 A 端）。

    返回
    ----
    :class:`WormholeInjection`。``tunnels`` 为空或边集为空时返回空注入（原拓扑的新拷贝）。
    """
    real_nodes = sorted(all_nodes(edges_per_epoch)) if available_nodes is None \
        else sorted(set(available_nodes))
    base_edges: List[Set[Edge]] = [set(ep) for ep in edges_per_epoch]

    canon = sorted({canonical_edge(int(u), int(v)) for u, v in (tunnels or []) if u != v})
    num_nodes = (max(real_nodes) + 1) if real_nodes else 0
    if not canon or not base_edges:
        return WormholeInjection(edges_per_epoch=base_edges, tunnels=[],
                                 node_ids=real_nodes, num_nodes=num_nodes,
                                 tunnel_km={}, strategy=strategy,
                                 controllers=list(controllers or []))

    # 隧道常驻：新边写入每一个 epoch（新 set，不改原缓存）
    new_edges: List[Set[Edge]] = []
    for ep in base_edges:
        s = set(ep)
        s.update(canon)
        new_edges.append(s)

    # 隧道物理距离：跨 epoch 均值（两端点均可测的 epoch 才计入）
    tunnel_km: Dict[Edge, float] = {}
    if positions_per_epoch:
        acc: Dict[Edge, List[float]] = {t: [] for t in canon}
        for pos in positions_per_epoch:
            if not pos:
                continue
            d = edge_distances(pos, canon)
            for t, km in d.items():
                acc[t].append(km)
        tunnel_km = {t: float(np.mean(v)) for t, v in acc.items() if v}

    node_ids = sorted(set(real_nodes) | {n for t in canon for n in t})
    return WormholeInjection(edges_per_epoch=new_edges, tunnels=canon,
                             node_ids=node_ids,
                             num_nodes=(max(node_ids) + 1) if node_ids else 0,
                             tunnel_km=tunnel_km, strategy=strategy,
                             controllers=list(controllers or []))


def expand_topology_for_wormholes(attackers: Sequence[Any],
                                  edges_per_epoch: EdgesPerEpoch,
                                  all_node_ids: Iterable[int],
                                  positions_per_epoch: PositionsPerEpoch = None,
                                  seed: int = 0,
                                  rng: Optional[random.Random] = None
                                  ) -> Tuple[List[Set[Edge]], List[int], List[WormholeInjection]]:
    """
    runner/sweep 的**统一入口**：为攻击者列表中的所有 WormholeAttacker 注入隧道边。

    在 ``ControlPlane`` / ``Simulator`` 构建**之前**调用。对每个虫洞攻击者：
    以其 ``node_id`` 为 A 端，按 ``endpoint_strategy`` 选对端 B（或用配置显式指定的
    ``second_endpoint``），把隧道边写入每个 epoch，并调用 ``att.bind_endpoints(A, B)``
    把双端点绑定回攻击者（供其 :meth:`~starlink_sim.net.attack.Attacker.controls` /
    ``modify_advertisement`` 使用）。多个虫洞攻击者的端点互不复用（``exclude_nodes``）。

    **节点 ID 空间不变**（``node_ids`` 原样返回）——虫洞不新增身份。无虫洞攻击者时
    返回 ``edges_per_epoch`` / ``all_node_ids`` 的浅拷贝（既有行为完全不变）。

    返回 ``(expanded_edges_per_epoch, node_ids, injections)``。
    """
    from starlink_sim.net.attack import WormholeAttacker   # 延迟导入避免潜在环

    node_ids = list(all_node_ids)
    wh_attackers = [a for a in attackers if isinstance(a, WormholeAttacker)]
    if not wh_attackers:
        return [set(ep) for ep in edges_per_epoch], node_ids, []

    if rng is None:
        rng = random.Random(seed)
    cur_edges: List[Set[Edge]] = [set(ep) for ep in edges_per_epoch]
    pos0 = first_positions(positions_per_epoch)
    used: Set[int] = set()
    injections: List[WormholeInjection] = []

    for att in wh_attackers:
        a = int(att.node_id)
        b = getattr(att, 'second_endpoint', None)
        if b is None:
            b = select_wormhole_peer(
                cur_edges, a,
                strategy=getattr(att, 'endpoint_strategy', 'farthest'),
                positions=pos0, rng=rng,
                pool_size=getattr(att, 'pool_size', 48),
                available_nodes=node_ids, exclude_nodes=used)
        if b is None:
            continue                      # 无合法对端（拓扑过小/全为邻居）→ 不注入
        b = int(b)
        att.bind_endpoints(a, b)
        used |= {a, b}
        inj = inject_wormhole_tunnels(cur_edges, [(a, b)],
                                      positions_per_epoch=positions_per_epoch,
                                      available_nodes=node_ids,
                                      strategy=getattr(att, 'endpoint_strategy', 'farthest'),
                                      controllers=[a])
        cur_edges = inj.edges_per_epoch
        node_ids = inj.node_ids
        injections.append(inj)
    return cur_edges, node_ids, injections


# ==================== ③ 物理接地检测器 ====================

@dataclass
class WormholeDetection:
    """单 epoch 的虫洞检测结果（距离不一致判据）。"""
    suspicious_edges: List[Edge] = field(default_factory=list)        # 物理距离超阈值的边
    used_suspicious_edges: List[Edge] = field(default_factory=list)   # 其中确被用于转发的
    edge_km: Dict[Edge, float] = field(default_factory=dict)
    threshold_km: float = 0.0
    num_edges_examined: int = 0
    num_unmeasured: int = 0            # 缺 positions 而无法测量的边数
    median_isl_km: Optional[float] = None
    max_isl_km: Optional[float] = None
    max_isl_km_assumed: float = DEFAULT_MAX_ISL_KM
    distance_factor: float = DEFAULT_DISTANCE_FACTOR
    adaptive_factor: Optional[float] = DEFAULT_ADAPTIVE_FACTOR
    available: bool = False            # positions 缺失 → 检测器不可用


def forwarding_hops(routing_tables: Optional[Dict[int, Dict]]) -> Set[Edge]:
    """路由表中**实际会被用于转发**的跳集合（``(u, entry.next_hop)`` 规范化）。"""
    hops: Set[Edge] = set()
    for u, rt in (routing_tables or {}).items():
        for _dest, entry in (rt or {}).items():
            nh = getattr(entry, 'next_hop', None)
            if nh is None or nh == u:
                continue
            hops.add(canonical_edge(u, nh))
    return hops


def detect_wormhole_edges(positions: Positions,
                          edges: Iterable[Edge],
                          routing_tables: Optional[Dict[int, Dict]] = None,
                          max_isl_km: float = DEFAULT_MAX_ISL_KM,
                          distance_factor: float = DEFAULT_DISTANCE_FACTOR,
                          adaptive_factor: Optional[float] = DEFAULT_ADAPTIVE_FACTOR
                          ) -> WormholeDetection:
    """
    **距离不一致检测器**：标记物理距离显著超过合法 ISL 分布的边（虫洞嫌疑）。

    阈值取两条判据的较大者，以同时保证"真实拓扑零误报"与"对未知建链门限稳健"::

        threshold_km = max(max_isl_km * distance_factor,
                           median_hop_km * adaptive_factor)   # adaptive_factor=None 时只用前者

    - ``max_isl_km``（默认 2000）是 :func:`isl.build_edges_for_epoch` 的硬上限，
      ``distance_factor``（默认 1.5）留出测量/数值余量 → 真实拓扑上**不可能**误报。
    - ``median_hop_km * adaptive_factor`` 是"邻域中位跳距的若干倍"的自适应判据，
      在 positions 存在但建链门限未知的拓扑上仍能工作。

    若传入 ``routing_tables``，额外区分出 ``used_suspicious_edges``——**确被用于转发**
    的嫌疑跳（只有被使用的隧道才造成真实危害，也才是数据面可观测的信号）。

    ``positions`` 缺失时返回 ``available=False`` 的空检测（不抛异常，便于无几何缓存的
    合成拓扑测试优雅降级）。
    """
    edges = list(edges)
    km = edge_distances(positions, edges)
    det = WormholeDetection(edge_km=km, num_edges_examined=len(edges),
                            num_unmeasured=len(edges) - len(km),
                            max_isl_km_assumed=float(max_isl_km),
                            distance_factor=float(distance_factor),
                            adaptive_factor=adaptive_factor,
                            available=bool(km))
    if not km:
        return det

    vals = np.asarray(list(km.values()), dtype=float)
    median_km = float(np.median(vals))
    det.median_isl_km = median_km
    det.max_isl_km = float(np.max(vals))

    threshold = float(max_isl_km) * float(distance_factor)
    if adaptive_factor:
        threshold = max(threshold, median_km * float(adaptive_factor))
    det.threshold_km = threshold

    det.suspicious_edges = sorted(e for e, d in km.items() if d > threshold)
    if routing_tables is not None and det.suspicious_edges:
        used = forwarding_hops(routing_tables)
        det.used_suspicious_edges = sorted(set(det.suspicious_edges) & used)
    return det


def detect_wormhole_by_latency(deliveries: Iterable[Tuple[float, int]],
                               latency_factor: float = DEFAULT_LATENCY_FACTOR,
                               max_isl_km: float = DEFAULT_MAX_ISL_KM
                               ) -> Dict[str, Any]:
    """
    **时延-跳数不一致检测器**（仅用端到端可观测量，不需要边集/邻居信息）。

    参数 ``deliveries`` 为 ``(latency_ms, hop_count)`` 序列（仅成功送达的流）。合法
    ISL 单跳单向时延上界为 ``max_isl_km / c``（2000 km → ≈6.67 ms），故若某流的
    **平均每跳时延** ``latency_ms / hop_count`` 超过 ``上界 × latency_factor``，
    则该流路径必含一条物理上不可能的"单跳"→ 判为虫洞嫌疑。

    ``latency_factor`` 默认 1.0，即阈值恰为合法单跳的物理上界——因为平均值
    ``<=`` 最大值，合法流永不会超过它，故**零误报**（与 :func:`detect_wormhole_edges`
    的绝对判据同一逻辑）。注意平均值会被短跳稀释，因此本判据的灵敏度低于
    距离判据（需隧道足够长或路径足够短才能触发），它的价值在于**假设更弱**：
    不需边集/邻居信息，仅需端到端可观测的时延与跳数。

    返回 dict：``flagged``（被标记流数）、``total``、``ratio``、
    ``threshold_ms_per_hop``、``max_observed_ms_per_hop``、``mean_observed_ms_per_hop``。
    """
    deliveries = [(float(lat), int(hops)) for lat, hops in (deliveries or [])
                  if hops and hops > 0]
    thr = (float(max_isl_km) / SPEED_OF_LIGHT_KM_S * 1000.0) * float(latency_factor)
    per_hop = [lat / hops for lat, hops in deliveries]
    flagged = sum(1 for x in per_hop if x > thr)
    total = len(deliveries)
    return {
        'flagged': int(flagged),
        'total': int(total),
        'ratio': float(flagged / total) if total else 0.0,
        'threshold_ms_per_hop': float(thr),
        'max_observed_ms_per_hop': float(max(per_hop)) if per_hop else 0.0,
        'mean_observed_ms_per_hop': float(np.mean(per_hop)) if per_hop else 0.0,
    }


def summarize_wormhole_detection(injected_tunnels: Iterable[Tuple[int, int]],
                                 detections: Sequence[WormholeDetection]) -> Dict[str, float]:
    """
    汇总跨 epoch 检测结果，产出**检测率（真阳/注入隧道数）**与**误报率**。

    - ``wormhole_detection_rate``  = |注入隧道 ∩ 被标记| / |注入隧道|（召回/真阳率）；
      **仅在注入了隧道时给出**（基线臂无隧道可检，该键缺席 → 聚合自动跳过，
      避免用 0.0 或 1.0 的空洞取值污染统计）。
    - ``wormhole_false_positive_rate`` = |被标记但非注入隧道| / |被检查的可测边|。
      在**无虫洞基线**上这就是纯误报率；在“合法 ISL 受 ``max_isl_km`` 约束”的拓扑上
      由自适应阈值兜底为 0，但在 shipped 数据（ISL 未受距离约束）上会随子集 median 而 >0
      （见模块 docstring 的实测表）。
    - ``wormhole_suspicious_hops`` = 跨 epoch **确被用于转发**的嫌疑跳数（真实危害面）。

    返回的键均落在 :data:`WORMHOLE_METRIC_KEYS` 内（除 ``detector_available``，
    它只进 ``wormhole_stats`` 供审计）。
    """
    inj = {canonical_edge(int(u), int(v)) for u, v in (injected_tunnels or []) if u != v}
    flagged: Set[Edge] = set()
    used: Set[Edge] = set()
    examined: Set[Edge] = set()
    available = False
    thresholds: List[float] = []
    for d in (detections or []):
        if getattr(d, 'available', False):
            available = True
            thresholds.append(float(d.threshold_km))
        flagged |= set(d.suspicious_edges)
        used |= set(d.used_suspicious_edges)
        examined |= set(d.edge_km.keys())

    tp = len(inj & flagged)
    fp = len(flagged - inj)
    out: Dict[str, float] = {
        'wormhole_num_tunnels': float(len(inj)),
        'wormhole_detected_tunnels': float(tp),
        'wormhole_suspicious_hops': float(len(used)),
        'wormhole_edges_examined': float(len(examined)),
        'wormhole_false_positive_rate': float(fp / len(examined)) if examined else 0.0,
        'detector_available': 1.0 if available else 0.0,
        'threshold_km': float(np.mean(thresholds)) if thresholds else 0.0,
    }
    if inj:
        out['wormhole_detection_rate'] = float(tp / len(inj))
    return out


# ==================== ④ 牵引与 path stretch 度量（容忍环路） ====================

def trace_forwarding_hops(routing_tables: Dict[int, Dict],
                          edges: Iterable[Edge],
                          src: int, dst: int,
                          max_hops: int = 100
                          ) -> Tuple[List[Edge], List[int], bool]:
    """
    沿路由表 next_hop 从 ``src`` 向 ``dst`` 追踪，返回 (规范化跳序列, 有序节点路径, 是否抵达)。

    与 :func:`starlink_sim.net.sybil.trace_forwarding_nodes` 同语义（容忍环路：遇环即停
    但保留已途经的跳/节点），额外返回两样东西：

    - **跳序列**（规范化 ``(min,max)``，可直接与隧道边集合比对）——虫洞的判据是
      "哪条边被用了"，仅凭节点集无法区分"分别经过 A 与 B"和"经隧道 A→B"；
    - **有序节点路径** ``path``（``path[0] == src``，且
      ``canonical_edge(path[i], path[i+1]) == hops[i]``）——用于计算物理距离/时延。
      规范化边是**无序**的，不能用来重建有向路径，故必须单独返回。

    成环时 ``path`` 含闭环的最后一跳（与 ``DataPlane.loop_paths`` 的记录方式一致），
    途经节点集即 ``set(path)``。
    """
    edge_set = set(edges)
    hops: List[Edge] = []
    path: List[int] = [src]
    if src == dst:
        return hops, path, True
    current = src
    seen: Set[int] = {src}
    for _ in range(max_hops):
        rt = routing_tables.get(current)
        if rt is None:
            return hops, path, False
        entry = rt.get(dst)
        if entry is None:
            return hops, path, False
        next_hop = getattr(entry, 'next_hop', None)
        if next_hop is None:
            return hops, path, False
        if (current, next_hop) not in edge_set and (next_hop, current) not in edge_set:
            return hops, path, False
        hops.append(canonical_edge(current, next_hop))
        path.append(next_hop)
        if next_hop == dst:
            return hops, path, True
        if next_hop in seen:
            return hops, path, False      # 成环：停止，但已记录途经跳
        seen.add(next_hop)
        current = next_hop
    return hops, path, False


def _path_geo_km(path: Sequence[int], positions: Positions) -> Optional[float]:
    """路径累计物理距离（km）；任一跳不可测则返回 None。"""
    if not positions or len(path) < 2:
        return None
    total = 0.0
    for u, v in zip(path, path[1:]):
        pu, pv = positions.get(u), positions.get(v)
        if pu is None or pv is None:
            return None
        total += float(np.linalg.norm(np.asarray(pu, dtype=float) - np.asarray(pv, dtype=float)))
    return total


def compute_wormhole_metrics(flows: Sequence[Tuple[int, int]],
                             tunnels: Iterable[Tuple[int, int]],
                             tables_per_epoch: Sequence[Dict[int, Dict]],
                             edges_per_epoch: EdgesPerEpoch,
                             num_epochs: int,
                             positions_per_epoch: PositionsPerEpoch = None,
                             max_hops: int = 100,
                             latency_factor: float = DEFAULT_LATENCY_FACTOR,
                             max_isl_km: float = DEFAULT_MAX_ISL_KM,
                             max_cache_trees: int = 512) -> Dict[str, float]:
    """
    虫洞度量：**被牵引流量占比** + **path stretch** + **时延-跳数不一致**（单次遍历产出）。

    - ``wormhole_attracted_ratio``：转发链**使用了任一隧道边**的 flow-epoch 占比
      （E6 主指标，与 Sybil 的"经过虚假身份"口径对齐，但精确到边——因为隧道两端
      都是真实节点，只有"用了隧道这一跳"才说明流量真被虫洞牵引）。
    - ``wormhole_path_stretch``：实际转发跳数 / **无隧道**参考最短路跳数。虫洞让远端
      看起来相邻 → 该值通常 **< 1**（跳数被"缩短"，正是攻击得逞的表现）。
    - ``wormhole_geo_stretch``：实际路径物理距离 / 参考路径物理距离。通常 **> 1**
      ——跳数变少但物理距离变长，这就是"地理路由被破坏"的定量证据。
    - ``wormhole_latency_flagged_ratio``：被 :func:`detect_wormhole_by_latency` 判为
      时延-跳数不一致的**成功流**占比（弱假设下的独立检测面）。

    参考最短路在 ``edges − tunnels`` 上用 BFS 求得（父指针表按 (epoch, src) 缓存，
    上限 ``max_cache_trees`` 以防全量拓扑下内存膨胀）。
    """
    tunnel_set = {canonical_edge(int(u), int(v)) for u, v in (tunnels or []) if u != v}
    num_epochs = max(0, int(num_epochs))
    out: Dict[str, float] = {
        'wormhole_attracted_ratio': 0.0,
        'wormhole_attracted_trials': 0.0,
        'wormhole_total_trials': 0.0,
        'wormhole_path_stretch': 0.0,
        'wormhole_geo_stretch': 0.0,
        'wormhole_latency_flagged_ratio': 0.0,
        'wormhole_latency_flagged_trials': 0.0,
    }
    if num_epochs <= 0 or not flows:
        return out

    last_tables = tables_per_epoch[-1] if tables_per_epoch else {}
    total = 0
    attracted = 0
    stretches: List[float] = []
    geo_stretches: List[float] = []
    deliveries: List[Tuple[float, int]] = []
    ref_cache: Dict[Tuple[int, int], Dict[int, int]] = {}

    for epoch_idx in range(num_epochs):
        tables = tables_per_epoch[epoch_idx] if epoch_idx < len(tables_per_epoch) else last_tables
        edges = set(edges_per_epoch[epoch_idx]) if epoch_idx < len(edges_per_epoch) else set()
        pos = None
        if positions_per_epoch and epoch_idx < len(positions_per_epoch):
            pos = positions_per_epoch[epoch_idx]
        ref_adj: Optional[Dict[int, Set[int]]] = None
        if tunnel_set:
            ref_edges = {e for e in edges if canonical_edge(*e) not in tunnel_set}
            ref_adj = aggregate_adjacency([ref_edges])

        for (src, dst) in flows:
            total += 1
            hops, actual_path, reached = trace_forwarding_hops(tables, edges, src, dst, max_hops)
            if tunnel_set and any(h in tunnel_set for h in hops):
                attracted += 1
            if not reached or not hops:
                continue
            # 实际路径（含隧道）的物理长度与端到端时延
            if pos:
                geo = _path_geo_km(actual_path, pos)
                if geo is not None:
                    deliveries.append((geo / SPEED_OF_LIGHT_KM_S * 1000.0, len(hops)))
            # 参考最短路（去掉隧道边）
            if ref_adj is not None and src != dst:
                key = (epoch_idx, int(src))
                parents = ref_cache.get(key)
                if parents is None:
                    if len(ref_cache) < max_cache_trees:
                        parents = _bfs_parents(ref_adj, int(src))
                        ref_cache[key] = parents
                    else:                       # 缓存上限：退化为不计算 stretch
                        parents = {}
                if parents:
                    ref_path = _path_from_parents(parents, int(src), int(dst))
                    if ref_path and len(ref_path) >= 2:
                        ref_hops = len(ref_path) - 1
                        stretches.append(len(hops) / float(ref_hops))
                        if pos:
                            ref_geo = _path_geo_km(ref_path, pos)
                            act_geo = _path_geo_km(actual_path, pos)
                            if ref_geo and act_geo and ref_geo > 0:
                                geo_stretches.append(act_geo / ref_geo)

    lat = detect_wormhole_by_latency(deliveries, latency_factor=latency_factor,
                                     max_isl_km=max_isl_km)
    out['wormhole_attracted_ratio'] = float(attracted / total) if total else 0.0
    out['wormhole_attracted_trials'] = float(attracted)
    out['wormhole_total_trials'] = float(total)
    out['wormhole_path_stretch'] = float(np.mean(stretches)) if stretches else 0.0
    out['wormhole_geo_stretch'] = float(np.mean(geo_stretches)) if geo_stretches else 0.0
    out['wormhole_latency_flagged_ratio'] = float(lat['ratio'])
    out['wormhole_latency_flagged_trials'] = float(lat['flagged'])
    return out


# ==================== ⑤ runner 统一检测入口 ====================

def run_wormhole_detection(tunnels: Iterable[Tuple[int, int]],
                           flows: Sequence[Tuple[int, int]],
                           tables_per_epoch: Sequence[Dict[int, Dict]],
                           edges_per_epoch: EdgesPerEpoch,
                           num_epochs: int,
                           positions_per_epoch: PositionsPerEpoch = None,
                           max_hops: int = 100,
                           max_isl_km: float = DEFAULT_MAX_ISL_KM,
                           distance_factor: float = DEFAULT_DISTANCE_FACTOR,
                           adaptive_factor: Optional[float] = DEFAULT_ADAPTIVE_FACTOR,
                           latency_factor: float = DEFAULT_LATENCY_FACTOR,
                           tunnel_km: Optional[Dict[Edge, float]] = None,
                           injections: Optional[Sequence[WormholeInjection]] = None
                           ) -> Dict[str, Any]:
    """
    runner（e3 / e2）的**统一检测入口**：逐 epoch 距离检测 + 牵引/stretch 度量 + 发射规则。

    把 :func:`detect_wormhole_edges` / :func:`summarize_wormhole_detection` /
    :func:`compute_wormhole_metrics` 三步封成一次调用，使两个 runner 的接线代码
    保持一致（e3 嵌套 schema 与 e2 平铺 schema 共用同一产出）。

    返回 ``{'data_stats': {...}, 'stats': {...}}``：

    - ``data_stats``：仅含 :data:`WORMHOLE_METRIC_KEYS` 的子集，可直接
      ``runner_data_stats.update(...)``。按发射规则，:data:`WORMHOLE_TUNNEL_KEYS`
      仅在 ``tunnels`` 非空时出现（基线臂缺席 → 聚合自动跳过）。
    - ``stats``：审计块（写入 ``result['wormhole_stats']``），额外含
      ``detector_available`` / ``threshold_km`` / 逐 epoch 嫌疑边明细 / 注入摘要。
      **不含** ``edge_km`` 全量映射（全量拓扑下达数万条，会使 raw JSON 膨胀）。

    ``positions_per_epoch`` 缺失时检测器优雅降级（``detector_available=False``、
    各计数为 0），不抛异常；牵引与 path_stretch 仍可从路由表算出。
    """
    tunnel_set = sorted({canonical_edge(int(u), int(v))
                         for u, v in (tunnels or []) if u != v})
    num_epochs = max(0, int(num_epochs))

    detections: List[WormholeDetection] = []
    for i in range(num_epochs):
        pos = None
        if positions_per_epoch is not None and i < len(positions_per_epoch):
            pos = positions_per_epoch[i]
        edges = edges_per_epoch[i] if i < len(edges_per_epoch) else ()
        tables = None
        if tables_per_epoch and i < len(tables_per_epoch):
            tables = tables_per_epoch[i]
        detections.append(detect_wormhole_edges(
            pos, edges, tables, max_isl_km=max_isl_km,
            distance_factor=distance_factor, adaptive_factor=adaptive_factor))

    summary = summarize_wormhole_detection(tunnel_set, detections)
    metrics = compute_wormhole_metrics(
        flows, tunnel_set, tables_per_epoch, edges_per_epoch, num_epochs,
        positions_per_epoch=positions_per_epoch, max_hops=max_hops,
        latency_factor=latency_factor, max_isl_km=max_isl_km)

    km_vals = [float(v) for v in (tunnel_km or {}).values()]
    pool: Dict[str, Any] = {}
    pool.update(summary)
    pool.update(metrics)
    pool['wormhole_mean_tunnel_km'] = float(np.mean(km_vals)) if km_vals else 0.0

    keys = WORMHOLE_METRIC_KEYS if tunnel_set else WORMHOLE_BASELINE_KEYS
    data_stats: Dict[str, float] = {k: float(pool.get(k, 0.0)) for k in keys}

    stats: Dict[str, Any] = {
        'num_tunnels': len(tunnel_set),
        'tunnels': [list(t) for t in tunnel_set],
        'tunnel_km': {f'{u}-{v}': float(km) for (u, v), km in (tunnel_km or {}).items()},
        'mean_tunnel_km': float(np.mean(km_vals)) if km_vals else 0.0,
        'detector_available': bool(summary.get('detector_available')),
        'threshold_km': float(summary.get('threshold_km', 0.0)),
        'max_isl_km_assumed': float(max_isl_km),
        'distance_factor': float(distance_factor),
        'adaptive_factor': adaptive_factor,
        'latency_factor': float(latency_factor),
        'latency_threshold_ms_per_hop': float(max_isl_km) / SPEED_OF_LIGHT_KM_S
                                        * 1000.0 * float(latency_factor),
        'detected_tunnels': int(summary.get('wormhole_detected_tunnels', 0.0)),
        'detection_rate': summary.get('wormhole_detection_rate'),
        'false_positive_rate': float(summary.get('wormhole_false_positive_rate', 0.0)),
        'suspicious_hops': int(summary.get('wormhole_suspicious_hops', 0.0)),
        'edges_examined': int(summary.get('wormhole_edges_examined', 0.0)),
        'attracted_ratio': float(metrics.get('wormhole_attracted_ratio', 0.0)),
        'attracted_trials': int(metrics.get('wormhole_attracted_trials', 0.0)),
        'total_trials': int(metrics.get('wormhole_total_trials', 0.0)),
        'path_stretch': float(metrics.get('wormhole_path_stretch', 0.0)),
        'geo_stretch': float(metrics.get('wormhole_geo_stretch', 0.0)),
        'latency_flagged_trials': int(metrics.get('wormhole_latency_flagged_trials', 0.0)),
        'num_epochs_examined': len(detections),
        'per_epoch': [
            {
                'epoch': i,
                'available': bool(d.available),
                'threshold_km': float(d.threshold_km),
                'median_isl_km': d.median_isl_km,
                'max_isl_km': d.max_isl_km,
                'num_edges_examined': int(d.num_edges_examined),
                'num_unmeasured': int(d.num_unmeasured),
                'suspicious_edges': [list(e) for e in d.suspicious_edges],
                'used_suspicious_edges': [list(e) for e in d.used_suspicious_edges],
            } for i, d in enumerate(detections)
        ],
        'injections': [
            {
                'controllers': list(inj.controllers),
                'tunnels': [list(t) for t in inj.tunnels],
                'strategy': inj.strategy,
                'tunnel_km': {f'{u}-{v}': float(km)
                              for (u, v), km in inj.tunnel_km.items()},
            } for inj in (injections or [])
        ],
    }
    return {'data_stats': data_stats, 'stats': stats}
