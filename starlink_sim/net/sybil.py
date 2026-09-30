# starlink_sim/net/sybil.py
"""
E4 Sybil（虚假身份）攻击的**节点 ID 空间扩展**与**吸引率度量**工具。

问题背景（E4 的真正难点不在 attack.py，而在这里）
==============================================
``ControlPlane.__init__`` 用 ``range(num_nodes)`` 建 router，且 ``num_nodes =
max(all_node_ids)+1``（见 run_e3）。``ControlPlane.update_neighbors`` 还会**丢弃**
任一端点 ``>= num_nodes`` 的边。因此 Sybil 虚假身份（新节点）必须在 **ControlPlane
构建之前**：① 分配新的节点 ID（扩大 ID 空间）；② 作为新边接入其附着的真实节点
（扩充每个 epoch 的 edge_sets）；③ 把新 ``num_nodes`` 传给 ControlPlane。否则虚假
身份既没有 router，也没有链路，攻击完全无效。

机制
====
:func:`inject_sybil_identities` 给定基础拓扑（``edges_per_epoch``）与身份数
``num_identities`` + **附着策略** ``attachment``（默认 ``'betweenness'``，用 networkx
选高介数真实节点；亦支持 ``'degree'`` / ``'random'``），为每个虚假身份分配一个新节点
ID（从 ``max(真实节点)+1`` 起连续编号），并把它接到一个高价值真实节点上（新边写入
**每一个 epoch**，因为虚假身份是常驻的）。返回扩展后的 edge_sets、新节点全集、新
``num_nodes`` 与附着映射。

:func:`expand_topology_for_sybils` 是供 runner/sweep 调用的**清晰入口**：扫描已实例化
的攻击者列表，对其中每个 :class:`~starlink_sim.net.attack.SybilAttacker` 按其
``num_identities`` / ``attachment`` 注入身份、把身份 ID 绑定回该攻击者（供其
``controls()`` / ``modify_advertisement`` 使用），并累积扩展拓扑。多个 Sybil 攻击者
各自获得一批不重叠的身份 ID。

度量
====
:func:`compute_sybil_attraction` 产出 Sybil 特有指标——**Sybil 吸引的流量占比**
（转发链经过任一虚假身份的 flow-epoch 比例）。与 ``DataPlane.compute_path`` 不同，
:func:`trace_forwarding_nodes` 是**容忍环路**的：虚假身份伪造低 metric 常把真实节点
的路由指向自己，而身份本身只能经其附着点回转，从而形成 ``R→I→R`` 转发环；普通
``compute_path`` 遇环即返回 ``None``（丢失"流量曾被牵引到身份"这一事实）。本追踪器
沿 next_hop 前进、记录**所有**途经节点（含成环节点），直到抵达目的 / 成环 / 断链 /
超过 ``max_hops``，因此能稳健度量 Sybil 的路由牵引效果。

注意：本模块**只读**基础拓扑——所有边集扩充都生成新的 set，绝不原地修改传入的
``edges_per_epoch``（sweep worker 进程内拓扑缓存是跨任务共享的，原地修改会污染缓存）。
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from starlink_sim.net.placement import select_attackers, all_nodes

__all__ = [
    'SYBIL_ATTACHMENT_STRATEGIES',
    'SYBIL_METRIC_KEYS',
    'SybilInjection',
    'inject_sybil_identities',
    'expand_topology_for_sybils',
    'trace_forwarding_nodes',
    'compute_sybil_attraction',
]

# 支持的附着策略（复用 placement.select_attackers 的策略名）
SYBIL_ATTACHMENT_STRATEGIES: Tuple[str, ...] = ('betweenness', 'degree', 'random')

# Sybil 特有指标键（放入 data_stats 后即被 analytics.stats.extract_metrics 自动提取，
# 并可由 sweep 追加到聚合 metrics 列表；缺失时聚合自动跳过，不破坏既有匹配键）
SYBIL_METRIC_KEYS: Tuple[str, ...] = (
    'sybil_attraction_ratio', 'sybil_attracted_trials', 'sybil_num_identities',
)

Edge = Tuple[int, int]
EdgesPerEpoch = Sequence[Iterable[Edge]]


@dataclass
class SybilInjection:
    """一次 Sybil 身份注入的结果（节点 ID 空间扩展 + edge_sets 扩充）。"""
    edges_per_epoch: List[Set[Edge]]            # 扩充后的逐 epoch 边集（新对象，未改原缓存）
    sybil_node_ids: List[int]                   # 新分配的虚假身份节点 ID
    attachment_map: Dict[int, int]              # 虚假身份 ID -> 附着的真实节点 ID
    node_ids: List[int]                         # 扩展后的节点全集（真实 + 虚假），sorted
    num_nodes: int                              # 扩展后的 num_nodes（= max(node_ids)+1）
    controller_node: Optional[int] = None       # 被劫持的物理节点（SybilAttacker.node_id）
    num_identities: int = 0
    attachment: str = 'betweenness'
    targets: List[int] = field(default_factory=list)  # 实际选中的附着目标真实节点


def _select_targets(edges_per_epoch: EdgesPerEpoch, num_targets: int,
                    attachment: str, rng: random.Random,
                    exclude: Optional[Set[int]] = None) -> List[int]:
    """按附着策略选出 ``num_targets`` 个高价值真实节点作为身份附着目标。"""
    strategy = attachment if attachment in SYBIL_ATTACHMENT_STRATEGIES else 'betweenness'
    chosen = select_attackers(edges_per_epoch, num_targets, strategy=strategy, rng=rng)
    if exclude:
        chosen = [n for n in chosen if n not in exclude]
    if not chosen:  # 兜底：用累计度数最高的若干真实节点
        present = sorted(all_nodes(edges_per_epoch))
        chosen = present[:num_targets]
    return chosen


def inject_sybil_identities(edges_per_epoch: EdgesPerEpoch,
                            num_identities: int,
                            attachment: str = 'betweenness',
                            controller_node: Optional[int] = None,
                            base_node_id: Optional[int] = None,
                            rng: Optional[random.Random] = None,
                            available_nodes: Optional[Iterable[int]] = None
                            ) -> SybilInjection:
    """
    把 ``num_identities`` 个 Sybil 虚假身份作为新节点注入拓扑。

    参数
    ----
    edges_per_epoch : 基础拓扑逐 epoch 边集（**只读**，不被修改）。
    num_identities  : 虚假身份数量（``<= 0`` 时返回原拓扑的空注入）。
    attachment      : 附着策略，见 :data:`SYBIL_ATTACHMENT_STRATEGIES`（默认 'betweenness'）。
    controller_node : 被劫持物理节点 ID（仅记录，供审计/指标归属）。
    base_node_id    : 新身份 ID 起点；默认 ``max(真实节点)+1``。
    rng             : 随机源（'random' 策略与候选不足补齐用），保证可复现。
    available_nodes : 真实节点全集；默认从 ``edges_per_epoch`` 推导。

    返回
    ----
    :class:`SybilInjection`：扩充后的 edge_sets（每个 epoch 都加入身份->附着点的新边）、
    身份 ID 列表、附着映射、扩展后节点全集与新 ``num_nodes``。
    """
    real_nodes = sorted(all_nodes(edges_per_epoch)) if available_nodes is None \
        else sorted(set(available_nodes))
    # 规范化原边集为新的 set 列表（绝不原地修改传入对象/缓存）
    base_edges: List[Set[Edge]] = [set(ep) for ep in edges_per_epoch]

    if num_identities is None or num_identities <= 0 or not real_nodes:
        return SybilInjection(edges_per_epoch=base_edges, sybil_node_ids=[],
                              attachment_map={}, node_ids=real_nodes,
                              num_nodes=(max(real_nodes) + 1) if real_nodes else 0,
                              controller_node=controller_node, num_identities=0,
                              attachment=attachment, targets=[])

    if rng is None:
        rng = random.Random(0)
    if base_node_id is None:
        base_node_id = max(real_nodes) + 1

    # 每个身份优先附着到不同的高价值真实节点（最大化路由影响面）；不足则轮回复用
    num_targets = max(1, min(int(num_identities), len(real_nodes)))
    targets = _select_targets(base_edges, num_targets, attachment, rng)

    sybil_ids = [int(base_node_id) + i for i in range(int(num_identities))]
    attachment_map: Dict[int, int] = {}
    for i, sid in enumerate(sybil_ids):
        attachment_map[sid] = targets[i % len(targets)]

    # 虚假身份常驻：新边写入每一个 epoch
    new_edges: List[Set[Edge]] = []
    for ep in base_edges:
        s = set(ep)
        for sid, tgt in attachment_map.items():
            s.add((sid, tgt))
        new_edges.append(s)

    node_ids = sorted(set(real_nodes) | set(sybil_ids))
    num_nodes = max(node_ids) + 1 if node_ids else 0
    return SybilInjection(edges_per_epoch=new_edges, sybil_node_ids=sybil_ids,
                          attachment_map=attachment_map, node_ids=node_ids,
                          num_nodes=num_nodes, controller_node=controller_node,
                          num_identities=int(num_identities), attachment=attachment,
                          targets=list(targets))


def expand_topology_for_sybils(attackers: Sequence[Any],
                               edges_per_epoch: EdgesPerEpoch,
                               all_node_ids: Iterable[int],
                               seed: int = 0,
                               rng: Optional[random.Random] = None
                               ) -> Tuple[List[Set[Edge]], List[int], List[SybilInjection]]:
    """
    runner/sweep 的**统一入口**：为攻击者列表中的所有 SybilAttacker 注入虚假身份。

    在 ControlPlane/Simulator 构建**之前**调用。对每个 Sybil 攻击者：按其
    ``num_identities`` / ``attachment`` 注入身份、把身份 ID 与附着映射**绑定回该攻击者**
    （``att.bind_identities(...)``，供其 ``controls()`` / ``modify_advertisement`` 使用），
    并累积扩展拓扑。多个 Sybil 攻击者的身份 ID 互不重叠（后一批从前一批的 ``num_nodes``
    起继续编号）。无 Sybil 攻击者时原样返回（``edges_per_epoch`` / ``all_node_ids`` 的浅拷贝）。

    返回 ``(expanded_edges_per_epoch, expanded_node_ids, injections)``。
    """
    # 延迟导入避免 attack <-> sybil 潜在环（attack 不依赖 sybil，此处仅为稳妥）
    from starlink_sim.net.attack import SybilAttacker

    node_ids = list(all_node_ids)
    sybil_attackers = [a for a in attackers if isinstance(a, SybilAttacker)]
    if not sybil_attackers:
        return [set(ep) for ep in edges_per_epoch], node_ids, []

    if rng is None:
        rng = random.Random(seed)
    cur_edges: List[Set[Edge]] = [set(ep) for ep in edges_per_epoch]
    base = (max(node_ids) + 1) if node_ids else 0
    injections: List[SybilInjection] = []
    for att in sybil_attackers:
        inj = inject_sybil_identities(
            cur_edges, getattr(att, 'num_identities', 1),
            attachment=getattr(att, 'attachment', 'betweenness'),
            controller_node=getattr(att, 'node_id', None),
            base_node_id=base, rng=rng, available_nodes=node_ids)
        att.bind_identities(inj.sybil_node_ids, inj.attachment_map)
        cur_edges = inj.edges_per_epoch
        node_ids = inj.node_ids
        base = inj.num_nodes  # 下一批身份从本批之后继续编号
        injections.append(inj)
    return cur_edges, node_ids, injections


# ==================== 吸引率度量（容忍环路的转发链追踪） ====================

def trace_forwarding_nodes(routing_tables: Dict[int, Dict],
                           edges: Iterable[Edge],
                           src: int, dst: int,
                           max_hops: int = 100) -> Tuple[Set[int], bool]:
    """
    沿路由表 next_hop 从 ``src`` 向 ``dst`` 追踪转发链，返回 (途经节点集合, 是否抵达)。

    与 ``DataPlane.compute_path`` 的 next_hop/边存在性判定一致，但**容忍环路**：遇环
    （next_hop 已访问过）即停止并返回已途经的全部节点（含成环节点），而非丢弃路径。
    断链（无路由条目 / 下一跳无边）或超过 ``max_hops`` 同样停止。用于稳健度量"流量是否
    曾被牵引经过某节点"，即使该牵引最终导致环路/不可达。
    """
    edge_set = set(edges)
    nodes: Set[int] = {src}
    if src == dst:
        return nodes, True
    current = src
    seen: Set[int] = {src}
    for _ in range(max_hops):
        rt = routing_tables.get(current)
        if rt is None:
            return nodes, False
        entry = rt.get(dst)
        if entry is None:
            return nodes, False
        next_hop = getattr(entry, 'next_hop', None)
        if next_hop is None:
            return nodes, False
        if (current, next_hop) not in edge_set and (next_hop, current) not in edge_set:
            return nodes, False
        nodes.add(next_hop)
        if next_hop == dst:
            return nodes, True
        if next_hop in seen:
            return nodes, False  # 成环：停止，但已记录途经节点
        seen.add(next_hop)
        current = next_hop
    return nodes, False


def compute_sybil_attraction(flows: Sequence[Tuple[int, int]],
                             sybil_node_ids: Iterable[int],
                             tables_per_epoch: Sequence[Dict[int, Dict]],
                             edges_per_epoch: EdgesPerEpoch,
                             num_epochs: int,
                             max_hops: int = 100) -> Dict[str, float]:
    """
    计算 **Sybil 吸引的流量占比**：转发链经过任一虚假身份的 flow-epoch 比例。

    参数
    ----
    flows            : (src, dst) 流对列表。
    sybil_node_ids   : 虚假身份节点 ID 集合。
    tables_per_epoch : 逐 epoch 路由表（``List[Dict[node, Dict[dest, RouteEntry]]]``）；
                       长度不足时对越界 epoch 复用最后一份。
    edges_per_epoch  : 逐 epoch 边集（含已注入的 Sybil 边）。
    num_epochs       : 评估的 epoch 数（与 data_stats 的 num_trials 基数一致）。
    max_hops         : 追踪跳数上限。

    返回 dict：``sybil_attraction_ratio``（0..1）、``sybil_attracted_trials``、
    ``sybil_total_trials``（= len(flows) × num_epochs）。无身份时占比为 0.0。
    """
    sybil_set = set(sybil_node_ids)
    num_epochs = max(0, int(num_epochs))
    total = 0
    attracted = 0
    if sybil_set and num_epochs > 0 and flows:
        last_tables = tables_per_epoch[-1] if tables_per_epoch else {}
        for epoch_idx in range(num_epochs):
            tables = tables_per_epoch[epoch_idx] if epoch_idx < len(tables_per_epoch) else last_tables
            edges = edges_per_epoch[epoch_idx] if epoch_idx < len(edges_per_epoch) else set()
            for (src, dst) in flows:
                total += 1
                nodes, _ = trace_forwarding_nodes(tables, edges, src, dst, max_hops)
                if nodes & sybil_set:
                    attracted += 1
    ratio = (attracted / total) if total > 0 else 0.0
    return {
        'sybil_attraction_ratio': float(ratio),
        'sybil_attracted_trials': int(attracted),
        'sybil_total_trials': int(total),
    }
