# starlink_sim/net/placement.py
"""
统一攻击者放置模块（去重 + 多策略）。

背景
====
``scripts/run_e2_jamming_experiment.py`` 与 ``scripts/run_e3_blackhole_experiment.py``
各自维护了一份几乎相同的 ``select_attackers`` / ``instantiate_attackers`` /
``create_attacker`` 逻辑（均只支持 'degree' 放置）。本模块把它们抽成单一实现，
并扩展多种放置策略，为 E5-c「放置敏感性」实验铺路；两个 runner 均改为调用本模块，
**默认策略仍为 'degree'，且与既有行为逐位一致**（稳定排序保留累计度数的插入顺序）。

放置策略（``strategy``）
----------------------
- ``'degree'``（默认）：跨 epoch 累计度数 top-K。与两个 runner 既有 ``sorted(deg.items(),
  key=lambda x: x[1], reverse=True)`` 逐位一致（稳定排序 → 等度节点按首次出现顺序）。
- ``'random'``：在拓扑内出现的节点中均匀随机抽取（用 ``rng`` 保证可复现）。
- ``'betweenness'``：聚合图（所有 epoch 边的并集）介数中心性 top-K（networkx）。
- ``'k_core'``：聚合图核数（core number）top-K，tie-break 依次按累计度数、节点 id（networkx）。
- ``'last_epoch_degree'``：仅用最后一个 epoch 的度数 top-K。

攻击窗口守卫
----------
:func:`check_attack_windows` 校验每个攻击者的 ``[active_since, active_until]`` 是否与
数据面评估时刻（``base_time + i*epoch_duration``）有重叠；若攻击在评估期完全失活
（静默无效），告警或（``strict=True``）报错。配对实验默认应使用常驻窗口
（``active_until=.inf``）以适配单/末 epoch 评估。
"""
from __future__ import annotations

import random
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from starlink_sim.net.attack import (
    Attacker,
    BlackholeAttacker,
    JammingAttacker,
    SybilAttacker,
    WormholeAttacker,
)

__all__ = [
    'ATTACKER_CLASSES',
    'PLACEMENT_STRATEGIES',
    'cumulative_degree',
    'all_nodes',
    'evaluation_times',
    'select_attackers',
    'create_attacker',
    'instantiate_attackers',
    'attack_window_overlaps',
    'check_attack_windows',
]

# 攻击者类型映射（兼容大小写/别名，与两个 runner 既有字典一致）
ATTACKER_CLASSES: Dict[str, type] = {
    'blackhole': BlackholeAttacker,
    'BlackholeAttacker': BlackholeAttacker,
    'jamming': JammingAttacker,
    'JammingAttacker': JammingAttacker,
    'sybil': SybilAttacker,
    'SybilAttacker': SybilAttacker,
    'wormhole': WormholeAttacker,
    'WormholeAttacker': WormholeAttacker,
}

# 支持的放置策略
PLACEMENT_STRATEGIES: Tuple[str, ...] = (
    'degree', 'random', 'betweenness', 'k_core', 'last_epoch_degree',
)

Edge = Tuple[int, int]
EdgesPerEpoch = Sequence[Iterable[Edge]]


# ==================== 基础图工具 ====================

def cumulative_degree(edges_per_epoch: EdgesPerEpoch) -> Dict[int, int]:
    """
    跨 epoch 累计度数。

    插入顺序与既有 runner 完全一致（逐 epoch、逐边 ``u`` 后 ``v``），
    因此 ``sorted(deg.items(), key=value, reverse=True)`` 的等度 tie-break
    顺序与旧代码逐位相同 —— 保证 'degree' 默认行为不变。
    """
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


def _aggregate_graph(edges_per_epoch: EdgesPerEpoch):
    """构造聚合无向图（所有 epoch 边的并集），用于 betweenness / k_core。"""
    import networkx as nx
    G = nx.Graph()
    G.add_nodes_from(sorted(all_nodes(edges_per_epoch)))
    for edges in edges_per_epoch:
        G.add_edges_from(edges)
    return G


def _fill_shortfall(chosen: List[int], count: int, pool: Sequence[int],
                    rng: random.Random) -> List[int]:
    """候选不足 count 时，从 pool 中随机补齐（去重）。"""
    if len(chosen) >= count:
        return chosen[:count]
    chosen_set = set(chosen)
    remaining = [n for n in pool if n not in chosen_set]
    if remaining:
        extra = rng.sample(remaining, min(count - len(chosen), len(remaining)))
        chosen = list(chosen) + extra
    return chosen


# ==================== 放置策略 ====================

def select_attackers(edges_per_epoch: EdgesPerEpoch,
                     count: int,
                     strategy: str = 'degree',
                     rng: Optional[random.Random] = None,
                     available_nodes: Optional[Iterable[int]] = None) -> List[int]:
    """
    选择 ``count`` 个攻击者节点，返回 node_id 列表（长度 ``<= count``）。

    参数
    ----
    edges_per_epoch : 逐 epoch 边集（``List[Set[(int,int)]]``）。
    count           : 目标攻击者数量（``<= 0`` 返回空列表）。
    strategy        : 放置策略，取值见 :data:`PLACEMENT_STRATEGIES`。
    rng             : ``random.Random`` 实例，用于 'random' 策略与候选不足时补齐。
    available_nodes : 候选节点全集；默认从 ``edges_per_epoch`` 推导（拓扑内出现的节点）。

    返回
    ----
    选中的 node_id 列表。所有策略均只返回**确实存在于拓扑中**的节点。
    """
    if count is None or count <= 0:
        return []
    if rng is None:
        rng = random.Random(0)
    if strategy not in PLACEMENT_STRATEGIES:
        raise ValueError(
            f"Unsupported placement strategy: {strategy!r}; "
            f"expected one of {PLACEMENT_STRATEGIES}")

    present = sorted(all_nodes(edges_per_epoch))
    if available_nodes is None:
        pool = present
    else:
        avail = list(available_nodes)
        present_set = set(present)
        # 仅保留拓扑内出现的节点，确保攻击者落在图上
        pool = [n for n in avail if n in present_set] or present

    if not pool:
        return []

    if strategy == 'degree':
        deg = cumulative_degree(edges_per_epoch)
        # 与既有 runner 逐位一致：累计度降序 + 稳定排序（等度按插入顺序）
        ordered = sorted(deg.items(), key=lambda x: x[1], reverse=True)
        chosen = [n for n, _ in ordered[:count]]
        return _fill_shortfall(chosen, count, pool, rng)

    if strategy == 'last_epoch_degree':
        last = list(edges_per_epoch)[-1] if len(edges_per_epoch) else []
        deg: Dict[int, int] = {}
        for u, v in last:
            deg[u] = deg.get(u, 0) + 1
            deg[v] = deg.get(v, 0) + 1
        # 确定性 tie-break：度数降序 → 节点 id 升序
        ordered = sorted(deg.items(), key=lambda x: (-x[1], x[0]))
        chosen = [n for n, _ in ordered[:count]]
        return _fill_shortfall(chosen, count, pool, rng)

    if strategy == 'random':
        return list(rng.sample(pool, min(count, len(pool))))

    if strategy == 'betweenness':
        import networkx as nx
        G = _aggregate_graph(edges_per_epoch)
        bc = nx.betweenness_centrality(G)
        pool_set = set(pool)
        cand = {n: bc.get(n, 0.0) for n in pool_set}
        # 确定性 tie-break：介数降序 → 节点 id 升序
        ordered = sorted(cand.items(), key=lambda x: (-x[1], x[0]))
        chosen = [n for n, _ in ordered[:count]]
        return _fill_shortfall(chosen, count, pool, rng)

    if strategy == 'k_core':
        import networkx as nx
        G = _aggregate_graph(edges_per_epoch)
        core = nx.core_number(G)
        deg = cumulative_degree(edges_per_epoch)
        pool_set = set(pool)
        # 确定性排序：核数降序 → 累计度降序 → 节点 id 升序
        ordered = sorted(pool_set, key=lambda n: (-core.get(n, 0), -deg.get(n, 0), n))
        chosen = ordered[:count]
        return _fill_shortfall(chosen, count, pool, rng)

    # 理论上不可达（strategy 已校验）
    raise ValueError(f"Unsupported placement strategy: {strategy!r}")  # pragma: no cover


# ==================== 攻击者实例化 ====================

def create_attacker(node_id: int, att_config: Dict[str, Any]) -> Attacker:
    """
    根据统一 schema 的单条攻击者配置创建实例。

    ``att_config`` 形如 ``{type, count, placement, active_since, active_until, params}``；
    ``active_until == inf`` 归一为 ``None``（常驻），与两个 runner 既有行为一致。
    """
    atype = att_config.get('type', 'BlackholeAttacker')
    att_class = ATTACKER_CLASSES.get(atype)
    if att_class is None:
        raise ValueError(f"Unsupported attacker type: {atype!r}; "
                         f"expected one of {sorted(set(ATTACKER_CLASSES))}")

    params = dict(att_config.get('params', {}))
    params['active_since'] = att_config.get('active_since', 0.0)
    active_until = att_config.get('active_until', None)
    if active_until == float('inf'):
        active_until = None
    params['active_until'] = active_until

    return att_class(node_id=node_id, **params)


def instantiate_attackers(att_configs: Sequence[Dict[str, Any]],
                          edges_per_epoch: EdgesPerEpoch,
                          seed: int = 0,
                          available_nodes: Optional[Iterable[int]] = None) -> List[Attacker]:
    """
    根据统一 schema 的攻击者配置列表 + 逐 epoch 边集，选择节点并创建攻击者实例。

    替代 ``run_e2.select_attackers``+``create_attacker`` 与
    ``run_e3.instantiate_attackers`` 的重复逻辑。逐条配置：

    - ``count <= 0`` → 跳过；
    - 显式 ``node_id`` → 直接使用该节点（与 e3 既有行为一致）；
    - 否则按 ``placement``（默认 'degree'）调用 :func:`select_attackers` 选点。

    所有配置共享同一个 ``random.Random(seed)``，保证多组攻击者布点整体可复现。
    """
    rng = random.Random(seed)
    attackers: List[Attacker] = []
    for cfg in att_configs:
        count = cfg.get('count', 1)
        if count is None or count <= 0:
            continue
        if cfg.get('node_id') is not None:
            chosen = [cfg['node_id']]
        else:
            strategy = cfg.get('placement', 'degree')
            chosen = select_attackers(edges_per_epoch, count, strategy=strategy,
                                      rng=rng, available_nodes=available_nodes)
        for nid in chosen:
            attackers.append(create_attacker(nid, cfg))
    return attackers


# ==================== 攻击窗口守卫 ====================

def evaluation_times(base_time: float, num_eval_epochs: int,
                     epoch_duration: float) -> List[float]:
    """数据面逐 epoch 评估时刻：``base_time + i*epoch_duration``，``i ∈ [0, num_eval_epochs)``。"""
    n = max(0, int(num_eval_epochs))
    return [float(base_time) + i * float(epoch_duration) for i in range(n)]


def attack_window_overlaps(active_since: Optional[float],
                           active_until: Optional[float],
                           eval_times: Iterable[float]) -> bool:
    """
    攻击窗口 ``[active_since, active_until]`` 是否与任一评估时刻重叠。

    ``active_since=None`` 视为 0.0；``active_until=None`` 视为 ``+inf``（常驻）。
    与 :meth:`Attacker.is_active` 的判定保持一致（闭区间）。
    """
    a_from = 0.0 if active_since is None else float(active_since)
    a_to = float('inf') if active_until is None else float(active_until)
    for t in eval_times:
        if a_from <= float(t) <= a_to:
            return True
    return False


def check_attack_windows(att_configs: Sequence[Dict[str, Any]],
                         eval_times: Iterable[float],
                         strict: bool = False) -> List[str]:
    """
    校验每个攻击者配置的 active 窗口与数据面评估时刻是否重叠。

    参数
    ----
    att_configs : 统一 schema 攻击者配置列表。
    eval_times  : 数据面评估各 epoch 的时刻（见 :func:`evaluation_times`）。
    strict      : ``True`` 且存在评估期完全失活的攻击者时抛 ``ValueError``；
                  ``False``（默认）仅收集告警字符串返回。

    返回
    ----
    告警字符串列表（每条对应一个评估期完全失活的攻击者）。空列表表示全部攻击者
    在评估期至少有一个 epoch 处于活跃状态。
    """
    eval_times = list(eval_times)
    warns: List[str] = []
    if not eval_times:
        return warns
    for i, cfg in enumerate(att_configs):
        if (cfg.get('count', 1) or 0) <= 0:
            continue
        active_since = cfg.get('active_since', 0.0)
        active_until = cfg.get('active_until', None)
        if active_until == float('inf'):
            active_until = None
        if not attack_window_overlaps(active_since, active_until, eval_times):
            au = 'inf' if active_until is None else active_until
            msg = (f"攻击者[{i}] type={cfg.get('type')} count={cfg.get('count', 1)} "
                   f"窗口 [active_since={active_since}, active_until={au}] 与数据面评估时刻 "
                   f"{eval_times} 无重叠 → 评估期完全失活，攻击静默无效"
                   f"（建议常驻窗口 active_until=.inf 以适配单/末 epoch 评估）")
            warns.append(msg)
            if strict:
                raise ValueError(msg)
    return warns
