# starlink_sim/topology/subset.py
"""
跨 epoch 连通子集选择。

问题背景
========
``run_e2`` / ``run_e3`` / ``run_simulation`` 既有的节点裁剪只在 **epoch-0** 上做一次
BFS 取前 ``node_limit`` 个节点。LEO 卫星高速运动，epoch-0 连通的节点在后续 epoch
可能因链路切换而脱离子图，导致动态实验在部分 epoch 上诱导子图碎裂。T7 实测：
BFS-512 子集在某些 epoch 的最大连通分量占比跌至 ~42%，交付率被结构性拉低
（非路由/老化 bug，而是子集选择缺陷）。

一个**更隐蔽的陷阱**：单纯"按跨 epoch 累计度数取 top-K"在真实 LEO 壳上同样糟糕——
高度数节点分散在不同轨道面，彼此并不相邻。实测 53° 壳（121 epoch / 4284 节点）：

========================  ========  ========
方法（node_limit=96）    min ratio  mean
========================  ========  ========
epoch-0 BFS               0.625     0.642
累计度 top-K（朴素）       0.042     0.042   ← 几乎全碎裂
**持久核连通生长（本模块）** **1.000**  **1.000**
========================  ========  ========

方法
====
关键观察：LEO 星座的**同轨道面内 ISL 是持久的**——实测 53° 壳有 10830 条边出现在
全部 121 个 epoch，这些"持久边"构成的图有一个 **1064 节点的巨大连通分量（稳定核）**。
在持久边子图里连通地生长出的节点子集，其诱导子图在**每一个 epoch 都连通**
（因为这些边在每个 epoch 都存在）→ 逐 epoch 最大连通分量占比恒为 1.0。

据此，:func:`select_connected_subset` 先用 :func:`persistent_core` 求出跨 epoch 稳定核
（从"边存在于全部 epoch"的最严格阈值开始，若核不够大则逐级放宽持久性），再在核内做
**连通贪心生长**（每个新节点都邻接已选集合，保证诱导持久子图连通），按打分排序：

- ``'cumulative_degree'``（默认）：按跨 epoch 累计度数打分，偏好高流量枢纽区域。
- ``'stable_core'``：按持久度数（核内边数）打分，偏好最稠密的稳定核心。

两者都保证逐 epoch 连通（当 ``target_size <= 稳定核 GCC`` 时占比恒为 1.0）。

建议
====
动态实验子集规模应 **<= 稳定核 GCC**（53° 壳约 1064），推荐 **>= 1024 或直接用全量**
（``node_limit=None``）；``target_size`` 超过稳定核时会自动放宽持久性阈值并用核外高度数
节点补齐，此时逐 epoch 连通占比可能 < 1.0（尽力而为）。
"""
from __future__ import annotations

import heapq
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = [
    'SUBSET_METHODS',
    'Edge',
    'cumulative_degree',
    'all_nodes',
    'edge_persistence',
    'persistent_core',
    'epoch0_bfs',
    'max_connected_component_ratio',
    'evaluate_subset_connectivity',
    'filter_edges_to_subset',
    'select_connected_subset',
]

# 支持的子集选择方法
SUBSET_METHODS: Tuple[str, ...] = ('cumulative_degree', 'stable_core')

Edge = Tuple[int, int]
EdgesPerEpoch = Sequence[Iterable[Edge]]

# 持久性阈值阶梯：从"边存在于全部 epoch"（最严格）逐级放宽到聚合图（0.0）
_FRAC_LADDER: Tuple[float, ...] = (1.0, 0.95, 0.9, 0.85, 0.8, 0.7, 0.6, 0.5, 0.35, 0.2, 0.0)


# ==================== 基础工具 ====================

def cumulative_degree(edges_per_epoch: EdgesPerEpoch) -> Dict[int, int]:
    """跨 epoch 累计度数（节点在所有 epoch 边集中出现的端点次数之和）。"""
    deg: Dict[int, int] = {}
    for edges in edges_per_epoch:
        for u, v in edges:
            deg[u] = deg.get(u, 0) + 1
            deg[v] = deg.get(v, 0) + 1
    return deg


def all_nodes(edges_per_epoch: EdgesPerEpoch) -> Set[int]:
    """所有 epoch 边集中出现过的节点全集。"""
    nodes: Set[int] = set()
    for edges in edges_per_epoch:
        for u, v in edges:
            nodes.add(u)
            nodes.add(v)
    return nodes


def _canon(u: int, v: int) -> Edge:
    """无向边规范化（端点升序），使 (u,v) 与 (v,u) 视为同一条边。"""
    return (u, v) if u <= v else (v, u)


def edge_persistence(edges_per_epoch: EdgesPerEpoch) -> Dict[Edge, int]:
    """每条无向边出现在多少个 epoch（同一 epoch 内重复边只计一次）。"""
    cnt: Dict[Edge, int] = {}
    for edges in edges_per_epoch:
        seen: Set[Edge] = set()
        for u, v in edges:
            e = _canon(u, v)
            if e in seen:
                continue
            seen.add(e)
            cnt[e] = cnt.get(e, 0) + 1
    return cnt


def _adj_from_edges(edges: Iterable[Edge]) -> Dict[int, Set[int]]:
    adj: Dict[int, Set[int]] = {}
    for u, v in edges:
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)
    return adj


def _largest_component(adj: Dict[int, Set[int]]) -> Set[int]:
    """邻接表的最大连通分量节点集。"""
    seen: Set[int] = set()
    best: Set[int] = set()
    for start in adj:
        if start in seen:
            continue
        stack = [start]
        seen.add(start)
        comp: Set[int] = set()
        while stack:
            n = stack.pop()
            comp.add(n)
            for nb in adj.get(n, ()):
                if nb not in seen:
                    seen.add(nb)
                    stack.append(nb)
        if len(comp) > len(best):
            best = comp
    return best


# ==================== 跨 epoch 稳定核 ====================

def persistent_core(edges_per_epoch: EdgesPerEpoch,
                    target_size: Optional[int] = None
                    ) -> Tuple[Set[int], Dict[int, Set[int]], Optional[float]]:
    """
    求跨 epoch 稳定核：用"出现在足够多 epoch"的**持久边**构图，取其最大连通分量。

    从最严格阈值（边存在于全部 epoch，``frac=1.0``）开始；若该持久图的最大连通分量
    ``< target_size``，沿 :data:`_FRAC_LADDER` 逐级放宽，返回**首个**满足
    ``|GCC| >= target_size`` 的 ``(core_nodes, core_adj, frac)``。若放宽到聚合图仍不足，
    返回遇到的最大 GCC。``core_adj`` 仅含相应持久边，故核内任意连通子图在这些边存在的
    所有 epoch 上都保持连通。

    ``target_size=None`` 时直接返回最严格阈值（``frac=1.0``）的稳定核。
    """
    n_ep = len(edges_per_epoch)
    if n_ep == 0:
        return set(), {}, None
    persist = edge_persistence(edges_per_epoch)
    best_nodes: Set[int] = set()
    best_adj: Dict[int, Set[int]] = {}
    best_frac: Optional[float] = None
    for frac in _FRAC_LADDER:
        thr = frac * n_ep
        pedges = [e for e, c in persist.items() if c >= thr]
        adj = _adj_from_edges(pedges)
        gcc = _largest_component(adj)
        if len(gcc) > len(best_nodes):
            best_nodes, best_adj, best_frac = gcc, adj, frac
        if target_size is None:
            return gcc, adj, frac
        if len(gcc) >= target_size:
            return gcc, adj, frac
    return best_nodes, best_adj, best_frac


def _connected_greedy(core_nodes: Set[int], core_adj: Dict[int, Set[int]],
                      target_size: int, score: Dict[int, float]) -> List[int]:
    """
    在 ``core_adj``（持久边）内做**连通贪心生长**到 ``target_size`` 个节点。

    从打分最高的种子出发，用最大堆每次取出"邻接已选集合、打分最高"的节点加入。
    每个新节点都至少与已选集合有一条持久边相连 → 选中的节点诱导的持久子图连通 →
    在这些持久边存在的所有 epoch 上逐 epoch 连通。``score`` 越大越优先，tie-break 取小 id。
    """
    if target_size >= len(core_nodes):
        return sorted(core_nodes)
    seed = min(core_nodes, key=lambda n: (-score.get(n, 0), n))
    selected: Set[int] = {seed}
    pushed: Set[int] = {seed}
    heap: List[Tuple[float, int]] = []
    for nb in core_adj.get(seed, ()):
        if nb in core_nodes and nb not in pushed:
            heapq.heappush(heap, (-score.get(nb, 0), nb))
            pushed.add(nb)
    while len(selected) < target_size and heap:
        _, node = heapq.heappop(heap)
        if node in selected:
            continue
        selected.add(node)
        for nb in core_adj.get(node, ()):
            if nb in core_nodes and nb not in pushed:
                heapq.heappush(heap, (-score.get(nb, 0), nb))
                pushed.add(nb)
    # 持久核不足以达到 target_size（核已放宽到聚合图 GCC 仍不够）→ 按打分补齐剩余核节点
    if len(selected) < target_size:
        for n in sorted(core_nodes - selected, key=lambda n: (-score.get(n, 0), n)):
            selected.add(n)
            if len(selected) >= target_size:
                break
    return sorted(selected)


# ==================== 参照实现（既有缺陷方法，仅供测试对比） ====================

def epoch0_bfs(edges_per_epoch: EdgesPerEpoch, target_size: int) -> List[int]:
    """
    参照实现：仅在 epoch-0 上做 BFS 取前 ``target_size`` 个节点（既有缺陷方法）。

    保留于此仅供测试对比（证明 :func:`select_connected_subset` 的逐 epoch 连通性更优），
    生产路径不应再使用。返回 sorted 节点列表。
    """
    if not edges_per_epoch:
        return []
    first_edges = list(edges_per_epoch[0])
    adj = _adj_from_edges(first_edges)
    if not adj:
        return []
    start_node = sorted(adj)[0]
    queue = [start_node]
    visited = {start_node}
    while queue and len(visited) < target_size:
        node = queue.pop(0)
        for nb in sorted(adj.get(node, ())):
            if nb not in visited:
                visited.add(nb)
                queue.append(nb)
                if len(visited) >= target_size:
                    break
    return sorted(visited)


# ==================== 连通性度量 ====================

def max_connected_component_ratio(edges: Iterable[Edge], node_subset: Iterable[int]) -> float:
    """
    给定单 epoch 边集与节点子集，返回"落在诱导子图最大连通分量内的子集节点占比"。

    诱导子图：仅保留两端都在 ``node_subset`` 内的边。**分母为 ``|node_subset|``**
    （全部被选节点），因此在某 epoch 变为孤立/脱离的子集节点会拉低该比例 ——
    这正是 T7 中 "BFS-512 子集在部分 epoch 最大连通分量占比跌至 ~42%" 的度量口径。
    子集为空返回 0.0。
    """
    subset = set(node_subset)
    if not subset:
        return 0.0
    adj = _adj_from_edges((u, v) for u, v in edges if u in subset and v in subset)
    if not adj:
        return 0.0
    max_cc = len(_largest_component(adj))
    return max_cc / len(subset)


def evaluate_subset_connectivity(edges_per_epoch: EdgesPerEpoch,
                                 node_subset: Iterable[int]) -> Dict[str, Any]:
    """
    评估一个节点子集的逐 epoch 连通质量。

    返回 dict：``per_epoch_ratio``（逐 epoch 最大连通分量占比列表）、``mean_ratio``、
    ``min_ratio``、``num_epochs``。用于对比不同子集选择方法。
    """
    subset = set(node_subset)
    ratios = [max_connected_component_ratio(edges, subset) for edges in edges_per_epoch]
    return {
        'per_epoch_ratio': ratios,
        'mean_ratio': (sum(ratios) / len(ratios)) if ratios else 0.0,
        'min_ratio': min(ratios) if ratios else 0.0,
        'num_epochs': len(ratios),
    }


def filter_edges_to_subset(edges_per_epoch: EdgesPerEpoch,
                           node_subset: Iterable[int]) -> List[Set[Edge]]:
    """把逐 epoch 边集裁剪到 ``node_subset`` 内（仅保留两端都在子集的边）。"""
    subset = set(node_subset)
    return [{(u, v) for u, v in edges if u in subset and v in subset}
            for edges in edges_per_epoch]


# ==================== 子集选择（公开入口） ====================

def select_connected_subset(edges_per_epoch: EdgesPerEpoch,
                             target_size: Optional[int],
                             method: str = 'cumulative_degree',
                             rng: Optional[Any] = None) -> List[int]:
    """
    选出在所有 epoch 上保持良好连通的节点子集。

    参数
    ----
    edges_per_epoch : 逐 epoch 边集（``List[Set[(int,int)]]``）。
    target_size     : 目标子集规模；``None`` 返回全部节点，``<=0`` 返回空列表，
                      ``>= 全量`` 返回全部节点。
    method          : ``'cumulative_degree'``（默认，按累计度在稳定核内连通生长）或
                      ``'stable_core'``（按持久度在最稠密稳定核内连通生长）。
    rng             : 预留（当前两种方法均确定性，无需随机源）。

    返回
    ----
    sorted 节点 id 列表（长度 ``<= target_size``）。当 ``target_size <= 稳定核 GCC`` 时，
    返回子集的诱导子图在每个 epoch 都连通（逐 epoch 最大连通分量占比 = 1.0）。
    """
    nodes = sorted(all_nodes(edges_per_epoch))
    if target_size is None:
        return nodes
    if target_size <= 0 or not nodes:
        return []
    if target_size >= len(nodes):
        return nodes
    if method not in SUBSET_METHODS:
        raise ValueError(f"Unsupported subset method: {method!r}; expected one of {SUBSET_METHODS}")

    deg = cumulative_degree(edges_per_epoch)
    core_nodes, core_adj, _frac = persistent_core(edges_per_epoch, target_size)

    if not core_nodes:
        # 退化（无任何边）→ 退回累计度 top-K，至少给出确定性结果
        ordered = sorted(nodes, key=lambda n: (-deg.get(n, 0), n))
        return sorted(ordered[:target_size])

    if method == 'cumulative_degree':
        score: Dict[int, float] = deg                                    # 偏好高流量枢纽
    else:  # 'stable_core'
        score = {n: len(core_adj.get(n, ())) for n in core_nodes}        # 偏好最稠密稳定核

    chosen = _connected_greedy(core_nodes, core_adj, target_size, score)

    # 稳定核（已尽力放宽到聚合图 GCC）仍不足 target_size → 用核外高累计度节点补齐
    if len(chosen) < target_size:
        chosen_set = set(chosen)
        for n in sorted(nodes, key=lambda n: (-deg.get(n, 0), n)):
            if n not in chosen_set:
                chosen.append(n)
                chosen_set.add(n)
            if len(chosen) >= target_size:
                break
        chosen = sorted(chosen)
    return chosen
