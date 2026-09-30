# tests/test_wormhole.py
"""
E6 Wormhole（虫洞）攻击单元测试。

覆盖任务规格要求的五类断言：

① **隧道边注入**正确扩充 edge_sets（新边存在于每个 epoch、只读不改入参、A/B 端点
   符合预期、**节点 ID 空间不变**——这是虫洞与 Sybil 的关键差异）；
② ``WormholeAttacker`` 经 :meth:`controls` **同时控制 A、B**，且伪造的低 metric 通告
   被真实邻居在 ``DVRouter._process_update`` 中采纳（端到端小 ControlPlane）；
③ 小合成拓扑上虫洞**牵引到可测量流量**（``attracted_ratio > 0``），并制造可检测的
   距离/时延不一致（``path_stretch < 1`` 而 ``geo_stretch > 1``）；
④ **物理接地检测器**在有虫洞时报真阳（``detection_rate == 1``）、在无虫洞基线上
   不误报（``false_positive_rate == 0``，由 isl 的 2000 km 硬上限保证）；
⑤ 注册与工厂分派 ``type=wormhole``。

外加：Attacker ABC 签名未变的回归护栏、双端点 controls 不影响 blackhole/jamming/sybil
语义、runner（e3 嵌套 schema / e2 平铺 schema）接线产出与 metadata、指标键发射规则
（基线臂只发 BASELINE 键）、sweep/T6 聚合兼容、与 Sybil 注入的先后次序。

全部纯合成小图（<= 12 节点、<= 60 tick），秒级完成，不碰真实 102.8MB 拓扑缓存。
"""
import copy
import inspect
import json
import random
from types import SimpleNamespace

import numpy as np
import pytest

from starlink_sim.analytics.stats import DEFAULT_METRICS
from starlink_sim.net.attack import (
    Attacker,
    BlackholeAttacker,
    JammingAttacker,
    SybilAttacker,
    WormholeAttacker,
)
from starlink_sim.net.placement import (
    ATTACKER_CLASSES,
    create_attacker,
    instantiate_attackers,
)
from starlink_sim.net.routing_dv import DVMessage
from starlink_sim.net.simulator import ControlPlane, DataPlane
from starlink_sim.net.sybil import SYBIL_METRIC_KEYS, expand_topology_for_sybils
from starlink_sim.net.wormhole import (
    DEFAULT_ADAPTIVE_FACTOR,
    DEFAULT_DISTANCE_FACTOR,
    DEFAULT_LATENCY_FACTOR,
    DEFAULT_MAX_ISL_KM,
    MAX_ISL_ONEWAY_MS,
    SPEED_OF_LIGHT_KM_S,
    WORMHOLE_BASELINE_KEYS,
    WORMHOLE_ENDPOINT_STRATEGIES,
    WORMHOLE_METRIC_KEYS,
    WORMHOLE_TUNNEL_KEYS,
    canonical_edge,
    compute_wormhole_metrics,
    detect_wormhole_by_latency,
    detect_wormhole_edges,
    edge_distances,
    expand_topology_for_wormholes,
    first_positions,
    forwarding_hops,
    inject_wormhole_tunnels,
    run_wormhole_detection,
    select_wormhole_peer,
    summarize_wormhole_detection,
    trace_forwarding_hops,
)


# ==================== 合成小拓扑工具 ====================

#: 合法 ISL 单跳间距（km）——远低于 isl.build_edges_for_epoch 的 2000 km 硬上限，
#: 因此真实边永不会被物理接地检测器标记（零误报由构造保证）。
SPACING_KM = 800.0


def _line(n=10, spacing=SPACING_KM, epochs=1):
    """n 节点链 0-1-...-(n-1) × epochs 个 epoch（每个 epoch 边集相同）。"""
    edges = {(i, i + 1) for i in range(n - 1)}
    return [set(edges) for _ in range(epochs)]


def _line_positions(n=10, spacing=SPACING_KM, epochs=1):
    """链状拓扑的几何快照：节点沿 x 轴等距排布（TEME km 的合法替身）。"""
    pos = {i: np.array([i * spacing, 0.0, 0.0]) for i in range(n)}
    return [{k: v.copy() for k, v in pos.items()} for _ in range(epochs)]


def _entry(next_hop, metric=1, seq=1):
    """轻量路由条目替身（追踪器/检测器只读 next_hop）。"""
    return SimpleNamespace(dest=None, next_hop=next_hop, metric=metric, seq=seq,
                           age=0.0, path=[])


def _adv(src, entries, visited=None):
    """构造一条 DV 通告报文。"""
    return DVMessage(type='update', src=src, dst=-1, seq=1,
                     visited=list(visited or []), entries=list(entries))


def _run_control_plane(edges, num_nodes, attackers, ticks=60, tick=1.0, adv=2.0):
    """在给定（可能已注入隧道的）拓扑上跑一个单 epoch 控制面，返回 ControlPlane。"""
    cp = ControlPlane(num_nodes=num_nodes, tick_interval=tick,
                      attackers=attackers, adv_interval=adv)
    # epoch_duration 远大于总时长 → 全程 epoch 0（单快照）
    cp.run_ticks(ticks, edges, epoch_duration=float(ticks * tick * 10))
    return cp


def _cfg(attackers, name='e6_wormhole_tiny', duration=60, num_flows=5, detection=None):
    """runner 用的最小实验配置（与 tests/test_sybil.py 的 _e3_config 同构）。"""
    c = {
        'experiment': {'name': name, 'duration': duration},
        'topology': {'shell': 'TEST', 'epoch_interval': 30, 'node_limit': None,
                     'cache_path': 'unused.pkl', 'positions_cache': None},
        'routing': {'t_adv': 2.0, 'tick': 1.0, 'max_hops': 20},
        'traffic': {'num_flows': num_flows},
        'attack': {'attackers': attackers},
        'output': {'raw_dir': 'unused', 'agg_dir': 'unused', 'figures_dir': 'unused'},
    }
    if detection is not None:
        c['detection'] = detection
    return c


def _wh_att_cfg(node_id=1, second_endpoint=8, poison_scope='peer_only', **params):
    """统一 schema 的虫洞攻击者配置（显式 node_id → A 端确定，测试可复现）。"""
    p = {'endpoint_strategy': 'farthest', 'metric_fake': 0, 'drop_prob': 0.0,
         'poison_scope': poison_scope}
    if second_endpoint is not None:
        p['second_endpoint'] = second_endpoint
    p.update(params)
    cfg = {'type': 'wormhole', 'count': 1, 'active_since': 0.0,
           'active_until': float('inf'), 'params': p}
    if node_id is not None:
        cfg['node_id'] = node_id
    return cfg


# ==================== ⓪ 常量与指标键契约 ====================

def test_metric_keys_partition_and_no_collision():
    """指标键分区正确，且与既有指标键（默认/Sybil）零冲突 → 纯附加。"""
    assert set(WORMHOLE_BASELINE_KEYS) | set(WORMHOLE_TUNNEL_KEYS) == set(WORMHOLE_METRIC_KEYS)
    assert len(set(WORMHOLE_METRIC_KEYS)) == len(WORMHOLE_METRIC_KEYS)
    assert not (set(WORMHOLE_METRIC_KEYS) & set(SYBIL_METRIC_KEYS))
    assert not (set(WORMHOLE_METRIC_KEYS) & set(DEFAULT_METRICS))
    assert all(k.startswith('wormhole_') for k in WORMHOLE_METRIC_KEYS)


def test_physical_constants_are_consistent_and_sound():
    """时延判据默认阈值 = 合法单跳物理上界（latency_factor=1.0 → sound，零误报）。"""
    assert MAX_ISL_ONEWAY_MS == pytest.approx(DEFAULT_MAX_ISL_KM / SPEED_OF_LIGHT_KM_S * 1000.0)
    assert 6.0 < MAX_ISL_ONEWAY_MS < 7.0          # 2000 km / c ≈ 6.672 ms
    assert DEFAULT_LATENCY_FACTOR == 1.0
    assert DEFAULT_MAX_ISL_KM == 2000.0           # 与 isl.build_edges_for_epoch 一致
    assert DEFAULT_DISTANCE_FACTOR == 1.5 and DEFAULT_ADAPTIVE_FACTOR == 3.0


def test_canonical_edge_and_edge_distances():
    assert canonical_edge(5, 2) == (2, 5)
    assert canonical_edge(2, 5) == (2, 5)
    assert canonical_edge(3, 3) == (3, 3)
    pos = {0: np.array([0.0, 0.0, 0.0]), 1: np.array([300.0, 400.0, 0.0])}
    # 键规范化为 (min,max)；缺 positions 的边被跳过（不可测）
    assert edge_distances(pos, [(1, 0), (0, 2)]) == {(0, 1): pytest.approx(500.0)}
    assert edge_distances(None, [(0, 1)]) == {}
    assert edge_distances(pos, []) == {}


def test_first_positions_skips_empty_snapshots():
    p = {0: np.array([1.0, 2.0, 3.0])}
    assert first_positions(None) is None
    assert first_positions([]) is None
    assert first_positions([None, {}, p]) is p


# ==================== ① 隧道边注入 ====================

def test_inject_writes_tunnel_into_every_epoch_without_touching_input():
    edges = _line(6, epochs=3)
    before = copy.deepcopy(edges)
    pos = _line_positions(6, epochs=3)
    inj = inject_wormhole_tunnels(edges, [(4, 1)], positions_per_epoch=pos,
                                 strategy='farthest', controllers=[1])
    assert inj.tunnels == [(1, 4)]                 # 规范化为 (min,max)
    assert len(inj.edges_per_epoch) == 3
    for orig, new in zip(edges, inj.edges_per_epoch):
        assert (1, 4) in new                       # 隧道常驻每个 epoch
        assert orig.issubset(new)                  # 原有边一条不少
        assert len(new) == len(orig) + 1
    # **只读纪律**：绝不原地修改传入拓扑（sweep worker 的 _TOPO_CACHE 跨任务共享）
    assert edges == before
    # **节点 ID 空间不变**（与 Sybil 的关键差异：虫洞不新增身份）
    assert inj.node_ids == [0, 1, 2, 3, 4, 5]
    assert inj.num_nodes == 6
    assert inj.tunnel_km[(1, 4)] == pytest.approx(3 * SPACING_KM)
    assert inj.strategy == 'farthest' and inj.controllers == [1]


def test_inject_returns_brand_new_edge_set_objects():
    edges = _line(5, epochs=2)
    inj = inject_wormhole_tunnels(edges, [(0, 4)])
    for i in range(2):
        assert inj.edges_per_epoch[i] is not edges[i]


def test_inject_dedups_reversed_duplicates_and_drops_self_loops():
    edges = _line(6, epochs=1)
    inj = inject_wormhole_tunnels(edges, [(5, 2), (2, 5), (3, 3)])
    assert inj.tunnels == [(2, 5)]                 # 去重 + 丢弃自环
    assert len(inj.edges_per_epoch[0]) == len(edges[0]) + 1


def test_inject_multiple_tunnels_sorted_and_all_present():
    edges = _line(10, epochs=1)
    inj = inject_wormhole_tunnels(edges, [(8, 1), (3, 6)])
    assert inj.tunnels == [(1, 8), (3, 6)]         # 排序后确定
    assert {(1, 8), (3, 6)}.issubset(inj.edges_per_epoch[0])
    assert len(inj.edges_per_epoch[0]) == len(edges[0]) + 2


def test_inject_empty_tunnels_is_noop():
    edges = _line(5, epochs=2)
    before = copy.deepcopy(edges)
    for t in ([], None, [(2, 2)]):
        inj = inject_wormhole_tunnels(edges, t)
        assert inj.tunnels == [] and inj.tunnel_km == {}
        assert inj.edges_per_epoch == before
        assert inj.node_ids == [0, 1, 2, 3, 4] and inj.num_nodes == 5
    assert edges == before


def test_inject_empty_topology_returns_empty_injection():
    inj = inject_wormhole_tunnels([], [(0, 3)])
    assert inj.tunnels == [] and inj.edges_per_epoch == []
    assert inj.node_ids == [] and inj.num_nodes == 0


def test_inject_available_nodes_override():
    edges = _line(6, epochs=1)
    inj = inject_wormhole_tunnels(edges, [(0, 5)], available_nodes=[0, 1, 2, 3, 4, 5, 9])
    assert inj.node_ids == [0, 1, 2, 3, 4, 5, 9] and inj.num_nodes == 10


def test_inject_records_tunnel_km_only_when_measurable():
    edges = _line(6, epochs=2)
    # 第二个 epoch 缺 positions → 只用第一个 epoch 的距离
    pos = [_line_positions(6, epochs=1)[0], None]
    inj = inject_wormhole_tunnels(edges, [(1, 5)], positions_per_epoch=pos)
    assert inj.tunnel_km[(1, 5)] == pytest.approx(4 * SPACING_KM)
    assert inject_wormhole_tunnels(edges, [(1, 5)]).tunnel_km == {}


# ==================== ① b 端点选取 ====================

def test_select_peer_farthest_picks_most_distant_node():
    n = 8
    edges = _line(n, epochs=1)
    pos = first_positions(_line_positions(n, epochs=1))
    assert select_wormhole_peer(edges, 0, 'farthest', pos) == n - 1
    assert select_wormhole_peer(edges, 3, 'farthest', pos) == n - 1   # |3-7|=4 > |3-0|=3
    # 既有邻居被排除：7 是 6 的邻居 → 退回 0
    assert select_wormhole_peer(edges, 6, 'farthest', pos) == 0


def test_select_peer_farthest_falls_back_to_betweenness_without_positions():
    n = 8
    edges = _line(n, epochs=1)
    assert select_wormhole_peer(edges, 0, 'farthest', None) == n - 1
    assert select_wormhole_peer(edges, 0, 'betweenness', None) == n - 1


def test_select_peer_degree_picks_highest_cumulative_degree():
    edges = _line(8, epochs=1)
    # 排除自身 0 与邻居 1 后，累计度最高（链内部节点度 2）且 id 最小者 = 2
    assert select_wormhole_peer(edges, 0, 'degree', None) == 2


def test_select_peer_random_is_reproducible_and_valid():
    n = 8
    edges = _line(n, epochs=1)
    a = select_wormhole_peer(edges, 0, 'random', None, rng=random.Random(5))
    b = select_wormhole_peer(edges, 0, 'random', None, rng=random.Random(5))
    assert a == b and a in set(range(2, n))       # 排除自身与邻居 1


@pytest.mark.parametrize("strategy", list(WORMHOLE_ENDPOINT_STRATEGIES))
def test_select_peer_all_strategies_return_valid_non_neighbor(strategy):
    n = 10
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    b = select_wormhole_peer(edges, 4, strategy, first_positions(pos),
                             rng=random.Random(0), pool_size=6)
    assert b is not None and b != 4 and b not in (3, 5)


def test_select_peer_unknown_strategy_falls_back_to_farthest():
    n = 8
    edges = _line(n, epochs=1)
    pos = first_positions(_line_positions(n, epochs=1))
    assert select_wormhole_peer(edges, 0, 'nonsense', pos) == n - 1


def test_select_peer_respects_exclude_and_available_nodes():
    n = 10
    edges = _line(n, epochs=1)
    pos = first_positions(_line_positions(n, epochs=1))
    assert select_wormhole_peer(edges, 0, 'farthest', pos, exclude_nodes=[9]) == 8
    assert select_wormhole_peer(edges, 0, 'farthest', pos, available_nodes=[2, 3]) == 3
    # 候选全被排除 → None（调用方据此跳过注入，而非硬造一条无意义隧道）
    assert select_wormhole_peer(edges, 0, 'farthest', pos, available_nodes=[0, 1]) is None


def test_select_peer_degenerate_topologies_return_none():
    assert select_wormhole_peer([set()], 0, 'farthest', None) is None
    # 2 节点：唯一候选就是自己的邻居 → 无合法对端
    assert select_wormhole_peer([{(0, 1)}], 0, 'farthest', None) is None


def test_select_peer_pool_size_limits_candidates():
    n = 12
    edges = _line(n, epochs=1)
    pos = first_positions(_line_positions(n, epochs=1))
    # 累计度排序：内部节点(度2) 1..10 优先于端点(度1) 0/11；排除 0 与邻居 1 后
    # 池 = [2,3,...,10][:4] = [2,3,4,5] → 最远者 5（而非全图的 11）
    assert select_wormhole_peer(edges, 0, 'farthest', pos, pool_size=4) == 5
    assert select_wormhole_peer(edges, 0, 'farthest', pos, pool_size=0) == n - 1


# ==================== ① c expand_topology_for_wormholes（统一入口） ====================

def test_expand_without_wormhole_attacker_is_pure_copy():
    edges = _line(6, epochs=2)
    before = copy.deepcopy(edges)
    atts = [BlackholeAttacker(node_id=2), JammingAttacker(node_id=3),
            SybilAttacker(node_id=1, num_identities=2)]
    exp, node_ids, injs = expand_topology_for_wormholes(atts, edges, list(range(6)), seed=0)
    assert injs == [] and node_ids == [0, 1, 2, 3, 4, 5]
    assert exp == before                                    # 既有行为完全不变
    assert all(exp[i] is not edges[i] for i in range(2))    # 但返回新对象（不共享缓存）
    assert edges == before


def test_expand_binds_endpoints_and_prevents_endpoint_reuse():
    n = 12
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    a1 = WormholeAttacker(node_id=1)
    a2 = WormholeAttacker(node_id=4)
    exp, node_ids, injs = expand_topology_for_wormholes([a1, a2], edges, list(range(n)),
                                                       pos, seed=7)
    assert len(injs) == 2
    assert a1.second_endpoint == n - 1 and a2.second_endpoint == n - 2
    ends = {a1.node_id, a1.second_endpoint, a2.node_id, a2.second_endpoint}
    assert len(ends) == 4                                   # 端点互不复用
    assert node_ids == list(range(n))                       # 节点空间不变
    assert len(exp[0]) == len(edges[0]) + 2
    for inj in injs:
        for t in inj.tunnels:
            assert t in exp[0]
    assert edges == _line(n, epochs=1)                      # 入参未被修改


def test_expand_honors_explicit_second_endpoint():
    edges = _line(8, epochs=1)
    att = WormholeAttacker(node_id=2, second_endpoint=6)
    exp, node_ids, injs = expand_topology_for_wormholes([att], edges, list(range(8)), seed=0)
    assert injs[0].tunnels == [(2, 6)] and injs[0].controllers == [2]
    assert att.endpoints == (2, 6) and att.tunnel == (2, 6)
    assert (2, 6) in exp[0] and node_ids == list(range(8))


def test_expand_skips_attacker_without_legal_peer():
    edges = [{(0, 1)}]                       # 2 节点：1 是 0 的唯一邻居 → 无合法对端
    att = WormholeAttacker(node_id=0)
    exp, node_ids, injs = expand_topology_for_wormholes([att], edges, [0, 1], seed=0)
    assert injs == [] and att.second_endpoint is None
    assert exp == edges and node_ids == [0, 1]


def test_expand_does_not_mutate_input_topology():
    edges = _line(8, epochs=2)
    before = copy.deepcopy(edges)
    att = WormholeAttacker(node_id=1, second_endpoint=6)
    expand_topology_for_wormholes([att], edges, list(range(8)),
                                  _line_positions(8, epochs=2), seed=0)
    assert edges == before


def test_expand_runs_before_sybil_and_preserves_node_id_ordering():
    """注入次序：虫洞先于 Sybil → 虫洞端点只在真实节点中选，Sybil 在其后扩展 ID 空间。"""
    n = 10
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    wh = WormholeAttacker(node_id=1, second_endpoint=8)
    exp, node_ids, wh_injs = expand_topology_for_wormholes([wh], edges, list(range(n)),
                                                          pos, seed=0)
    assert node_ids == list(range(n)) and wh_injs[0].tunnels == [(1, 8)]
    sy = SybilAttacker(node_id=2, num_identities=2, attachment='degree')
    exp2, node_ids2, sy_injs = expand_topology_for_sybils([sy], exp, node_ids, seed=0)
    assert node_ids2 == list(range(n + 2))                  # Sybil 才扩展节点空间
    assert (1, 8) in exp2[0]                                # 隧道边保留
    assert len(sy_injs[0].sybil_node_ids) == 2
    assert max(sy_injs[0].sybil_node_ids) >= n              # 新 ID 不与真实节点冲突


# ==================== ② WormholeAttacker：双端点控制与通告伪造 ====================

def test_attacker_abc_signature_unchanged():
    """回归护栏：双端点控制**未**改动 Attacker ABC 的构造签名（simulator 亦无需改动）。"""
    assert list(inspect.signature(Attacker.__init__).parameters) == \
        ['self', 'node_id', 'active_since', 'active_until', 'kwargs']
    assert list(inspect.signature(Attacker.controls).parameters) == ['self', 'node_id']


def test_controls_covers_both_endpoints_only_after_binding():
    att = WormholeAttacker(node_id=3)
    assert att.controls(3) and not att.controls(4)          # 未绑定 → 退化为仅控制 A
    assert att.endpoints is None and att.tunnel is None
    att.bind_endpoints(3, 9)
    assert att.controls(3) and att.controls(9)
    assert not att.controls(0) and not att.controls(4) and not att.controls(8)
    assert att.endpoints == (3, 9) and att.tunnel == (3, 9)
    att.bind_endpoints(9, 3)                                # 顺序无关
    assert att.tunnel == (3, 9) and att.controls(3) and att.controls(9)


def test_other_attackers_controls_semantics_unchanged():
    """双端点 controls 不外溢：blackhole/jamming/sybil 语义逐位不变。"""
    for cls in (BlackholeAttacker, JammingAttacker):
        a = cls(node_id=5)
        assert a.controls(5) and not a.controls(6)
    s = SybilAttacker(node_id=1, num_identities=2)
    assert s.controls(1) and not s.controls(2)
    s.bind_identities([6, 7], {6: 1, 7: 2})
    assert s.controls(6) and s.controls(7) and not s.controls(8)


def test_constructor_defaults_and_kwarg_passthrough():
    att = WormholeAttacker(node_id=1)
    assert att.second_endpoint is None and att.endpoint_strategy == 'farthest'
    assert att.pool_size == 48 and att.metric_fake == 0
    assert att.drop_prob == 0.0                              # 默认只牵引不丢包
    assert att.seq_lead == 8 and att.poison_scope == 'peer_only'
    assert att.active_since == 0.0 and att.active_until is None
    a2 = WormholeAttacker(node_id=2, second_endpoint='9', endpoint_strategy='degree',
                          pool_size='7', metric_fake=1, drop_prob=0.5, seq_lead=-3,
                          poison_scope='peer_side', active_since=5.0, active_until=9.0,
                          ignored_extra=1)
    assert a2.second_endpoint == 9 and a2.endpoint_strategy == 'degree'
    assert a2.pool_size == 7 and a2.metric_fake == 1 and a2.drop_prob == 0.5
    assert a2.seq_lead == 0                                  # 负值被夹到 0
    assert a2.poison_scope == 'peer_side'
    assert (a2.active_since, a2.active_until) == (5.0, 9.0)


def test_invalid_poison_scope_falls_back_to_default():
    assert WormholeAttacker.DEFAULT_POISON_SCOPE == 'peer_only'
    assert set(WormholeAttacker.POISON_SCOPES) == {'peer_only', 'peer_side'}
    assert WormholeAttacker(node_id=0, poison_scope='nope').poison_scope == 'peer_only'
    assert WormholeAttacker(node_id=0, poison_scope=None).poison_scope == 'peer_only'


def test_modify_advertisement_fakes_peer_metric_and_preserves_its_seq():
    att = WormholeAttacker(node_id=1, second_endpoint=8, metric_fake=0,
                           poison_scope='peer_only')
    msg = _adv(1, [(1, 0, 5), (8, 7, 12), (0, 1, 9), (2, 1, 11)])
    out = att.modify_advertisement(msg, SimpleNamespace(routing_table={}), None, 0.0)
    by_dest = {d: (m, s) for d, m, s in out.entries}
    assert by_dest[1] == (0, 5)          # 到自身条目保留（不污染本地距离）
    # 对端：metric 降为 0，seq **保留自然值**——抬 seq 会让谎言被邻居反射回 A 并压过
    # 其直连路由 → A↔邻居 转发环、所有以 B 为终点的流失败（见 test_no_seq_reflection_loop）
    assert by_dest[8] == (0, 12)
    assert by_dest[0] == (1, 9) and by_dest[2] == (1, 11)   # peer_only：其余不动
    assert (out.src, out.dst, out.type, out.seq) == (1, -1, 'update', 1)
    assert out is not msg


def test_modify_advertisement_runs_symmetrically_for_both_endpoints():
    """一个攻击者同时改写 A 与 B 两端发出的通告（controls 双端点的直接后果）。"""
    att = WormholeAttacker(node_id=1, second_endpoint=8)
    node = SimpleNamespace(routing_table={})
    out_a = att.modify_advertisement(_adv(1, [(1, 0, 3)]), node, None, 0.0)
    out_b = att.modify_advertisement(_adv(8, [(8, 0, 4)]), node, None, 0.0)
    assert {d: m for d, m, s in out_a.entries}[8] == 0      # A 补入"对端 1 跳可达"
    assert {d: m for d, m, s in out_b.entries}[1] == 0      # B 同理（对称）
    # 补入条目的 seq 由 _bump_seq 单调基线给出，且**不**叠加 seq_lead
    seq_a = {d: s for d, m, s in out_a.entries}[8]
    assert seq_a == att._seq_floor[8]


def test_modify_advertisement_ignores_third_party_and_unbound_attacker():
    att = WormholeAttacker(node_id=1, second_endpoint=8)
    msg = _adv(5, [(5, 0, 1), (8, 3, 2)])
    assert att.modify_advertisement(msg, None, None, 0.0) is msg   # 只改自己两端
    unbound = WormholeAttacker(node_id=1)
    msg2 = _adv(1, [(1, 0, 1), (8, 3, 2)])
    assert unbound.modify_advertisement(msg2, None, None, 0.0) is msg2  # 无隧道可言


def test_modify_advertisement_respects_active_window():
    att = WormholeAttacker(node_id=1, second_endpoint=8, active_since=10.0)
    msg = _adv(1, [(1, 0, 1), (8, 7, 2)])
    assert att.modify_advertisement(msg, None, None, 5.0) is msg
    assert att.modify_advertisement(msg, None, None, 15.0) is not msg


def test_peer_side_scope_poisons_whole_far_side_with_seq_lead():
    att = WormholeAttacker(node_id=1, second_endpoint=8, poison_scope='peer_side',
                           seq_lead=4)
    rt = {9: SimpleNamespace(next_hop=8), 0: SimpleNamespace(next_hop=0)}
    msg = _adv(1, [(1, 0, 5), (8, 7, 12), (9, 8, 20), (0, 1, 7)])
    out = att.modify_advertisement(msg, SimpleNamespace(routing_table=rt), None, 0.0)
    by_dest = {d: (m, s) for d, m, s in out.entries}
    assert by_dest[8] == (0, 12)                 # 对端本身仍保留自然 seq
    assert by_dest[9][0] == 0                    # 对端一侧（next_hop==8）被伪造
    assert by_dest[9][1] > 20                    # 且领先 seq（否则被更新鲜通告翻回）
    assert by_dest[0] == (1, 7)                  # 非对端一侧不动
    # peer_only 下同一条目不被篡改
    att2 = WormholeAttacker(node_id=1, second_endpoint=8, poison_scope='peer_only')
    out2 = att2.modify_advertisement(_adv(1, [(9, 8, 20)]),
                                     SimpleNamespace(routing_table=rt), None, 0.0)
    assert {d: (m, s) for d, m, s in out2.entries}[9] == (8, 20)


def test_should_drop_data_defaults_to_no_drop():
    att = WormholeAttacker(node_id=1, second_endpoint=8)
    assert att.drop_prob == 0.0
    assert not any(att.should_drop_data((0, 9), 0.0) for _ in range(50))
    assert all(WormholeAttacker(node_id=1, second_endpoint=8, drop_prob=1.0)
               .should_drop_data((0, 9), 0.0) for _ in range(5))
    inactive = WormholeAttacker(node_id=1, second_endpoint=8, drop_prob=1.0,
                                active_since=100.0)
    assert not inactive.should_drop_data((0, 9), 0.0)


def test_wormhole_fake_advertisement_adopted_by_real_neighbors():
    """端到端：伪造的"对端 1 跳可达"被真实邻居在 _process_update 中采纳。"""
    n = 10
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    att = WormholeAttacker(node_id=1, second_endpoint=8)
    exp, node_ids, injs = expand_topology_for_wormholes([att], edges, list(range(n)),
                                                       pos, seed=0)
    assert injs[0].tunnels == [(1, 8)]
    cp = _run_control_plane(exp, num_nodes=n, attackers=[att], ticks=60)
    tables = cp.get_routing_tables()

    # 注入边生效：两端互为邻居
    assert 8 in cp.neighbors[1] and 1 in cp.neighbors[8]
    # 邻居被牵引：节点 2 到 8 原为 6 跳（next_hop 3），现被伪造为 1 跳经隧道
    assert tables[2][8].next_hop == 1 and tables[2][8].metric == 1
    # 对称方向：节点 7 到 1 被牵引经 8
    assert tables[7][1].next_hop == 8 and tables[7][1].metric == 1

    # 关键回归护栏：端点自身到对端仍为**直连**（metric 1、next_hop 即对端）。
    # 若对 dest==peer 抬 seq，被抬高的 seq 会经邻居反射回端点并压过其直连路由，
    # 造成 A↔邻居 转发环 → 所有以 B 为终点的流全部失败。
    assert tables[1][8].next_hop == 8 and tables[1][8].metric == 1
    assert tables[8][1].next_hop == 1 and tables[8][1].metric == 1

    # 无环路：数据面全部可达，且被牵引的流确实使用了隧道这一跳
    dp = DataPlane(tables, exp, attackers=[att], max_hops=30)
    for src, dst in [(0, 9), (2, 7), (1, 8), (5, 6), (9, 0)]:
        path, _ = dp.compute_path(src, dst, 0)
        assert path is not None and path[0] == src and path[-1] == dst
    hops, path, reached = trace_forwarding_hops(tables, exp[0], 2, 7, max_hops=30)
    assert reached and path == [2, 1, 8, 7] and (1, 8) in hops


def test_wormhole_without_injected_edge_cannot_take_effect():
    """反证注入必要性：``_process_update`` 只采纳邻居通告 → 无隧道边则谎言无效。"""
    n = 10
    edges = _line(n, epochs=1)
    att = WormholeAttacker(node_id=1, second_endpoint=8)   # 未注入隧道边
    cp = _run_control_plane(edges, num_nodes=n, attackers=[att], ticks=60)
    tables = cp.get_routing_tables()
    assert 8 not in cp.neighbors[1]
    # 节点 2 到 8 仍走真实最短路（6 跳、next_hop 3），未被牵引
    assert tables[2][8].next_hop == 3 and tables[2][8].metric == 6


def test_no_seq_reflection_loop_when_peer_seq_preserved():
    """专项回归：对端条目保留自然 seq → 端点的直连路由不被邻居反射的谎言替换。"""
    n = 10
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    att = WormholeAttacker(node_id=1, second_endpoint=8)
    exp, _, _ = expand_topology_for_wormholes([att], edges, list(range(n)), pos, seed=0)
    cp = _run_control_plane(exp, num_nodes=n, attackers=[att], ticks=60)
    tables = cp.get_routing_tables()
    # 端点到对端必须是直连（next_hop == 对端本身），而非绕经自己的邻居
    assert tables[1][8].next_hop == 8
    assert tables[8][1].next_hop == 1
    # 端点的邻居学到的"经隧道到对端"路由不得把端点自身的直连条目顶掉
    assert tables[0][8].next_hop == 1 and tables[9][1].next_hop == 8
    # 全部流可达（反射环会让以 B 为终点的流全灭）
    dp = DataPlane(tables, exp, attackers=[att], max_hops=30)
    for dst in range(n):
        for src in range(n):
            if src == dst:
                continue
            path, _ = dp.compute_path(src, dst, 0)
            assert path is not None, f"{src}->{dst} 不可达（疑似反射环）"


# ==================== ③ 牵引与 stretch 度量 ====================

def test_attraction_and_stretch_signature_on_line_topology():
    """虫洞签名：跳数变少（path_stretch < 1）而物理距离/时延暴涨（geo_stretch > 1）。"""
    n = 10
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    att = WormholeAttacker(node_id=1, second_endpoint=8)
    exp, _, injs = expand_topology_for_wormholes([att], edges, list(range(n)), pos, seed=0)
    cp = _run_control_plane(exp, num_nodes=n, attackers=[att], ticks=60)
    tables = cp.get_routing_tables()
    flows = [(1, 8), (2, 7), (0, 9), (3, 6), (4, 5)]
    m = compute_wormhole_metrics(flows, injs[0].tunnels, [tables], exp, 1,
                                 positions_per_epoch=pos, max_hops=30)
    assert m['wormhole_total_trials'] == 5.0
    assert m['wormhole_attracted_ratio'] > 0.0            # 牵引可测量（E6 主指标）
    assert m['wormhole_attracted_trials'] == pytest.approx(3.0)   # 前 3 条流经隧道
    assert 0.0 < m['wormhole_attracted_ratio'] <= 1.0
    assert m['wormhole_path_stretch'] < 1.0               # 攻击得逞：跳数被"缩短"
    assert m['wormhole_geo_stretch'] > 1.0                # 代价：物理距离变长
    assert m['wormhole_latency_flagged_ratio'] > 0.0      # 时延判据亦捕获


def test_metrics_are_zero_without_tunnels():
    n = 10
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    cp = _run_control_plane(edges, num_nodes=n, attackers=[], ticks=60)
    tables = cp.get_routing_tables()
    flows = [(1, 8), (2, 7), (0, 9)]
    m = compute_wormhole_metrics(flows, [], [tables], edges, 1,
                                 positions_per_epoch=pos, max_hops=30)
    assert m['wormhole_attracted_ratio'] == 0.0 and m['wormhole_attracted_trials'] == 0.0
    assert m['wormhole_total_trials'] == 3.0
    # 无隧道 → 无"去隧道参考最短路"可比 → stretch 保持 0（而非 1.0）
    assert m['wormhole_path_stretch'] == 0.0 and m['wormhole_geo_stretch'] == 0.0
    assert m['wormhole_latency_flagged_ratio'] == 0.0     # 合法拓扑零误报


def test_metrics_empty_inputs_are_safe():
    edges = _line(4, epochs=1)
    out = compute_wormhole_metrics([], [(0, 3)], [{}], edges, 1)
    assert out['wormhole_total_trials'] == 0.0 and out['wormhole_attracted_ratio'] == 0.0
    out2 = compute_wormhole_metrics([(0, 3)], [(0, 3)], [{}], edges, 0)
    assert out2['wormhole_total_trials'] == 0.0


def test_metrics_without_positions_still_measures_attraction():
    n = 8
    edges = _line(n, epochs=1)
    att = WormholeAttacker(node_id=1, second_endpoint=6)
    exp, _, injs = expand_topology_for_wormholes([att], edges, list(range(n)), None, seed=0)
    cp = _run_control_plane(exp, num_nodes=n, attackers=[att], ticks=60)
    tables = cp.get_routing_tables()
    # 流 (0,7)：无隧道 7 跳，经隧道 0->1->6->7 仅 3 跳
    m = compute_wormhole_metrics([(0, 7)], injs[0].tunnels, [tables], exp, 1,
                                 positions_per_epoch=None, max_hops=30)
    assert m['wormhole_attracted_ratio'] == 1.0           # 无几何也能度量牵引
    assert m['wormhole_geo_stretch'] == 0.0               # 但物理距离不可测
    assert m['wormhole_latency_flagged_ratio'] == 0.0
    assert m['wormhole_path_stretch'] == pytest.approx(3.0 / 7.0)   # 跳数参考不依赖 positions


def test_trace_forwarding_hops_returns_ordered_path_and_hops():
    edges = _line(5)[0]
    tables = {0: {4: _entry(1)}, 1: {4: _entry(2)}, 2: {4: _entry(3)}, 3: {4: _entry(4)}}
    hops, path, reached = trace_forwarding_hops(tables, edges, 0, 4)
    assert reached and path == [0, 1, 2, 3, 4]
    assert hops == [(0, 1), (1, 2), (2, 3), (3, 4)]
    assert all(canonical_edge(path[i], path[i + 1]) == hops[i] for i in range(len(hops)))
    assert trace_forwarding_hops(tables, edges, 2, 2) == ([], [2], True)


def test_trace_forwarding_hops_tolerates_loops():
    edges = _line(4)[0] | {(0, 3)}
    tables = {0: {3: _entry(1)}, 1: {3: _entry(0)}, 3: {0: _entry(0)}}
    hops, path, reached = trace_forwarding_hops(tables, edges, 1, 3)
    assert reached is False
    assert path == [1, 0, 1]                    # 成环即停，但保留已途经跳/节点
    assert hops == [(0, 1), (0, 1)]
    assert set(path) == {0, 1}                  # "流量曾被牵引"这一事实不丢失


def test_trace_forwarding_hops_stops_on_missing_route_or_non_edge():
    edges = _line(4)[0]
    # next_hop 不是邻居 → 立即失败
    hops, path, reached = trace_forwarding_hops({0: {3: _entry(2)}}, edges, 0, 3)
    assert (hops, path, reached) == ([], [0], False)
    # 中转节点无路由表 / 无该目的地条目
    assert trace_forwarding_hops({0: {3: _entry(1)}}, edges, 0, 3)[2] is False
    assert trace_forwarding_hops({0: {3: _entry(1)}, 1: {}}, edges, 0, 3)[2] is False
    assert trace_forwarding_hops({0: {3: _entry(1)},
                                  1: {3: _entry(None)}}, edges, 0, 3)[2] is False


# ==================== ④ 物理接地检测器 ====================

def test_detector_true_positive_on_injected_tunnel():
    n = 10
    base = _line(n, epochs=1)[0]
    pos = _line_positions(n, epochs=1)[0]
    edges = base | {(1, 8)}                     # 隧道 5600 km >> 2000 km 硬上限
    d = detect_wormhole_edges(pos, edges, None)
    assert d.available is True
    assert d.num_edges_examined == len(edges) and d.num_unmeasured == 0
    assert d.median_isl_km == pytest.approx(SPACING_KM)
    assert d.max_isl_km == pytest.approx(7 * SPACING_KM)
    # 阈值 = max(2000*1.5, 800*3) = 3000 km
    assert d.threshold_km == pytest.approx(DEFAULT_MAX_ISL_KM * DEFAULT_DISTANCE_FACTOR)
    assert d.suspicious_edges == [(1, 8)]
    s = summarize_wormhole_detection([(1, 8)], [d])
    assert s['wormhole_detection_rate'] == 1.0          # 真阳率
    assert s['wormhole_detected_tunnels'] == 1.0
    assert s['wormhole_num_tunnels'] == 1.0
    assert s['wormhole_false_positive_rate'] == 0.0     # 合法边一条不误报
    assert s['wormhole_edges_examined'] == float(len(edges))
    assert s['detector_available'] == 1.0


def test_detector_no_false_positive_on_clean_topology():
    n = 10
    edges = _line(n, epochs=1)[0]
    pos = _line_positions(n, epochs=1)[0]
    d = detect_wormhole_edges(pos, edges, None)
    assert d.available and d.suspicious_edges == [] and d.used_suspicious_edges == []
    s = summarize_wormhole_detection([], [d])
    assert s['wormhole_false_positive_rate'] == 0.0
    assert s['wormhole_num_tunnels'] == 0.0 and s['wormhole_suspicious_hops'] == 0.0
    # 无 ground truth → 检测率键**缺席**（不用 0.0/1.0 的空洞取值污染统计）
    assert 'wormhole_detection_rate' not in s


def test_detector_threshold_is_max_of_absolute_and_adaptive():
    n = 6
    edges = {(i, i + 1) for i in range(n - 1)}
    # 稀疏拓扑：合法跳距 1900 km（接近 2000 km 硬上限）→ 自适应判据主导
    pos = {i: np.array([i * 1900.0, 0.0, 0.0]) for i in range(n)}
    d = detect_wormhole_edges(pos, edges, None)
    assert d.median_isl_km == pytest.approx(1900.0)
    assert d.threshold_km == pytest.approx(1900.0 * DEFAULT_ADAPTIVE_FACTOR)   # 5700 > 3000
    assert d.suspicious_edges == []                     # 合法边全部 < 阈值 → 零误报
    # 关闭自适应判据 → 退回绝对判据 2000*1.5 = 3000 km
    d2 = detect_wormhole_edges(pos, edges, None, adaptive_factor=None)
    assert d2.threshold_km == pytest.approx(3000.0)
    assert d2.suspicious_edges == []
    # 绝对判据可调：门限降到 500 km 后合法边即被判为嫌疑（阈值语义的显式契约）
    d3 = detect_wormhole_edges(pos, edges, None, max_isl_km=500.0, adaptive_factor=None)
    assert d3.threshold_km == pytest.approx(750.0)
    assert len(d3.suspicious_edges) == len(edges)


def test_detector_distinguishes_used_from_unused_suspicious_hops():
    n = 10
    edges = _line(n, epochs=1)[0] | {(1, 8)}
    pos = _line_positions(n, epochs=1)[0]
    used_tables = {1: {8: _entry(8)}, 8: {1: _entry(1)}, 2: {8: _entry(1)}}
    d = detect_wormhole_edges(pos, edges, used_tables)
    assert d.suspicious_edges == [(1, 8)]
    assert d.used_suspicious_edges == [(1, 8)]          # 确被用于转发 → 真实危害
    unused = detect_wormhole_edges(pos, edges, {0: {5: _entry(1)}})
    assert unused.suspicious_edges == [(1, 8)]
    assert unused.used_suspicious_edges == []           # 存在嫌疑边但未被使用
    # 不传路由表 → 不区分（空列表）
    assert detect_wormhole_edges(pos, edges, None).used_suspicious_edges == []
    s = summarize_wormhole_detection([(1, 8)], [d, unused])
    assert s['wormhole_suspicious_hops'] == 1.0         # 跨 epoch 取并集


def test_detector_without_positions_degrades_gracefully():
    edges = _line(6, epochs=1)[0]
    d = detect_wormhole_edges(None, edges, None)
    assert d.available is False
    assert d.suspicious_edges == [] and d.edge_km == {}
    assert d.num_edges_examined == len(edges) and d.num_unmeasured == len(edges)
    assert d.threshold_km == 0.0
    s = summarize_wormhole_detection([(0, 5)], [d])
    assert s['detector_available'] == 0.0
    assert s['wormhole_detection_rate'] == 0.0
    assert s['wormhole_edges_examined'] == 0.0
    assert s['wormhole_false_positive_rate'] == 0.0     # 分母为 0 → 不报误报


def test_detector_partial_positions_counts_unmeasured():
    pos = {0: np.array([0.0, 0.0, 0.0]), 1: np.array([800.0, 0.0, 0.0])}
    edges = {(0, 1), (1, 2), (2, 3)}
    d = detect_wormhole_edges(pos, edges, None)
    assert d.available is True
    assert d.num_edges_examined == 3 and d.num_unmeasured == 2
    assert set(d.edge_km) == {(0, 1)}


def test_detector_multiple_epochs_union_and_mean_threshold():
    n = 8
    pos = _line_positions(n, epochs=1)[0]
    e0 = _line(n, epochs=1)[0] | {(0, 7)}
    e1 = _line(n, epochs=1)[0]                       # 第二个 epoch 隧道消失
    ds = [detect_wormhole_edges(pos, e0, None), detect_wormhole_edges(pos, e1, None)]
    s = summarize_wormhole_detection([(0, 7)], ds)
    assert s['wormhole_detection_rate'] == 1.0         # 任一 epoch 命中即算检出
    assert s['wormhole_false_positive_rate'] == 0.0
    assert s['threshold_km'] == pytest.approx(3000.0)


def test_latency_detector_flags_physically_impossible_hops():
    thr = MAX_ISL_ONEWAY_MS
    legal = [(thr * 0.99 * 3, 3)]                      # 合法：略低于单跳上界
    r = detect_wormhole_by_latency(legal)
    assert r['flagged'] == 0 and r['total'] == 1 and r['ratio'] == 0.0
    assert r['threshold_ms_per_hop'] == pytest.approx(thr)
    assert r['max_observed_ms_per_hop'] == pytest.approx(thr * 0.99)
    assert r['mean_observed_ms_per_hop'] == pytest.approx(thr * 0.99)
    # 虫洞：一条 7200 km 的"单跳" → 24 ms/跳 >> 6.67 ms 上界
    wh = [(7200.0 / SPEED_OF_LIGHT_KM_S * 1000.0, 1)]
    r2 = detect_wormhole_by_latency(wh)
    assert r2['flagged'] == 1 and r2['total'] == 1 and r2['ratio'] == 1.0
    r3 = detect_wormhole_by_latency(legal + wh)
    assert (r3['flagged'], r3['total'], r3['ratio']) == (1, 2, pytest.approx(0.5))


def test_latency_detector_ignores_degenerate_deliveries():
    assert detect_wormhole_by_latency([])['total'] == 0
    assert detect_wormhole_by_latency([(5.0, 0), (3.0, -1)])['total'] == 0
    r = detect_wormhole_by_latency(None)
    assert r['flagged'] == 0 and r['ratio'] == 0.0 and r['max_observed_ms_per_hop'] == 0.0


def test_latency_detector_factor_tunes_sensitivity():
    """latency_factor<1 会牺牲 soundness（合法流被误报）——阈值的显式契约。"""
    deliveries = [(2.669 * 3, 3)]                      # 合法 800 km/跳
    assert detect_wormhole_by_latency(deliveries)['flagged'] == 0
    assert detect_wormhole_by_latency(deliveries, latency_factor=0.25)['flagged'] == 1
    assert detect_wormhole_by_latency(deliveries, max_isl_km=500.0)['flagged'] == 1


def test_forwarding_hops_canonical_and_skips_self_next_hop():
    tables = {0: {3: _entry(1)}, 1: {0: _entry(0), 5: _entry(5)}, 2: {7: _entry(2)}}
    hops = forwarding_hops(tables)
    assert (0, 1) in hops and (1, 5) in hops
    assert (2, 2) not in hops                          # next_hop == 自身 → 不转发
    assert forwarding_hops(None) == set() and forwarding_hops({}) == set()
    assert forwarding_hops({0: None}) == set()


# ==================== ④ b run_wormhole_detection（runner 统一入口） ====================

def test_run_wormhole_detection_emits_all_keys_with_tunnels():
    n = 10
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    att = WormholeAttacker(node_id=1, second_endpoint=8)
    exp, _, injs = expand_topology_for_wormholes([att], edges, list(range(n)), pos, seed=0)
    cp = _run_control_plane(exp, num_nodes=n, attackers=[att], ticks=60)
    tables = cp.get_routing_tables()
    flows = [(1, 8), (2, 7), (0, 9)]
    wh = run_wormhole_detection(injs[0].tunnels, flows, [tables], exp, 1,
                                positions_per_epoch=pos, max_hops=30,
                                tunnel_km=injs[0].tunnel_km, injections=injs)
    assert set(wh['data_stats']) == set(WORMHOLE_METRIC_KEYS)      # 12 键齐全
    ds = wh['data_stats']
    assert all(isinstance(v, float) for v in ds.values())
    assert ds['wormhole_num_tunnels'] == 1.0
    assert ds['wormhole_detection_rate'] == 1.0
    assert ds['wormhole_detected_tunnels'] == 1.0
    assert ds['wormhole_false_positive_rate'] == 0.0
    assert ds['wormhole_suspicious_hops'] == 1.0
    assert ds['wormhole_attracted_ratio'] == pytest.approx(1.0)
    assert ds['wormhole_path_stretch'] < 1.0 < ds['wormhole_geo_stretch']
    assert ds['wormhole_mean_tunnel_km'] == pytest.approx(7 * SPACING_KM)

    st = wh['stats']
    assert st['detector_available'] is True and st['num_tunnels'] == 1
    assert st['tunnels'] == [[1, 8]] and st['tunnel_km'] == {'1-8': pytest.approx(5600.0)}
    assert st['threshold_km'] == pytest.approx(3000.0)
    assert st['max_isl_km_assumed'] == 2000.0 and st['distance_factor'] == 1.5
    assert st['adaptive_factor'] == 3.0 and st['latency_factor'] == 1.0
    assert st['latency_threshold_ms_per_hop'] == pytest.approx(MAX_ISL_ONEWAY_MS)
    assert st['detection_rate'] == 1.0 and st['false_positive_rate'] == 0.0
    assert st['total_trials'] == 3 and st['num_epochs_examined'] == 1
    assert len(st['per_epoch']) == 1
    assert st['per_epoch'][0]['suspicious_edges'] == [[1, 8]]
    assert st['per_epoch'][0]['used_suspicious_edges'] == [[1, 8]]
    assert st['per_epoch'][0]['available'] is True
    assert st['injections'][0]['controllers'] == [1]
    assert st['injections'][0]['tunnels'] == [[1, 8]]
    # 审计块**不含**全量边距映射（全量拓扑下达数万条，会使 raw JSON 膨胀）
    assert 'edge_km' not in st
    json.dumps(wh)                                     # 严格 JSON 可序列化


def test_run_wormhole_detection_baseline_emits_only_baseline_keys():
    n = 10
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    cp = _run_control_plane(edges, num_nodes=n, attackers=[], ticks=60)
    flows = [(1, 8), (2, 7), (0, 9)]
    wh = run_wormhole_detection([], flows, [cp.get_routing_tables()], edges, 1,
                                positions_per_epoch=pos, max_hops=30)
    assert set(wh['data_stats']) == set(WORMHOLE_BASELINE_KEYS)    # 7 键，无 TUNNEL 键
    ds = wh['data_stats']
    assert ds['wormhole_num_tunnels'] == 0.0
    assert ds['wormhole_false_positive_rate'] == 0.0               # 误报度量
    assert ds['wormhole_suspicious_hops'] == 0.0
    assert ds['wormhole_attracted_ratio'] == 0.0
    assert ds['wormhole_latency_flagged_ratio'] == 0.0             # 时延判据 soundness
    assert ds['wormhole_edges_examined'] == float(len(edges[0]))
    assert wh['stats']['detection_rate'] is None
    assert wh['stats']['num_tunnels'] == 0 and wh['stats']['injections'] == []
    json.dumps(wh)


def test_run_wormhole_detection_without_positions_degrades():
    n = 8
    edges = _line(n, epochs=2)
    att = WormholeAttacker(node_id=1, second_endpoint=6)
    exp, _, injs = expand_topology_for_wormholes([att], edges, list(range(n)), None, seed=0)
    cp = _run_control_plane(exp, num_nodes=n, attackers=[att], ticks=60)
    wh = run_wormhole_detection(injs[0].tunnels, [(2, 5)], [cp.get_routing_tables()] * 2,
                                exp, 2, positions_per_epoch=None, max_hops=30)
    assert set(wh['data_stats']) == set(WORMHOLE_METRIC_KEYS)
    assert wh['stats']['detector_available'] is False
    assert wh['data_stats']['wormhole_detection_rate'] == 0.0      # 无几何 → 无法检出
    assert wh['data_stats']['wormhole_attracted_ratio'] == 1.0     # 牵引仍可度量
    assert wh['data_stats']['wormhole_mean_tunnel_km'] == 0.0
    json.dumps(wh)


def test_run_wormhole_detection_honors_config_overrides():
    n = 8
    edges = _line(n, epochs=1)
    pos = _line_positions(n, epochs=1)
    cp = _run_control_plane(edges, num_nodes=n, attackers=[], ticks=60)
    wh = run_wormhole_detection([], [(0, 7)], [cp.get_routing_tables()], edges, 1,
                                positions_per_epoch=pos, max_hops=30,
                                max_isl_km=500.0, distance_factor=1.2,
                                adaptive_factor=None, latency_factor=0.5)
    st = wh['stats']
    assert st['max_isl_km_assumed'] == 500.0 and st['distance_factor'] == 1.2
    assert st['adaptive_factor'] is None
    assert st['threshold_km'] == pytest.approx(600.0)              # 500*1.2
    assert st['latency_factor'] == 0.5
    assert st['latency_threshold_ms_per_hop'] == pytest.approx(
        500.0 / SPEED_OF_LIGHT_KM_S * 1000.0 * 0.5)
    # 门限被压到合法跳距(800 km)以下 → 真实边全部被判嫌疑（误配阈值的可观测后果）
    assert st['edges_examined'] == len(edges[0])
    assert wh['data_stats']['wormhole_false_positive_rate'] == pytest.approx(1.0)
    assert wh['data_stats']['wormhole_latency_flagged_ratio'] == pytest.approx(1.0)


def test_run_wormhole_detection_zero_epochs_is_safe():
    wh = run_wormhole_detection([], [], [], [], 0)
    assert set(wh['data_stats']) == set(WORMHOLE_BASELINE_KEYS)
    assert wh['stats']['num_epochs_examined'] == 0
    assert all(v == 0.0 for v in wh['data_stats'].values())


# ==================== ⑤ 注册与工厂分派 ====================

def test_wormhole_registered_in_attacker_classes():
    assert ATTACKER_CLASSES['wormhole'] is WormholeAttacker
    assert ATTACKER_CLASSES['WormholeAttacker'] is WormholeAttacker
    # 既有类型未被扰动
    assert ATTACKER_CLASSES['blackhole'] is BlackholeAttacker
    assert ATTACKER_CLASSES['jamming'] is JammingAttacker
    assert ATTACKER_CLASSES['sybil'] is SybilAttacker


def test_create_attacker_dispatches_wormhole_with_params():
    cfg = {'type': 'wormhole', 'count': 1, 'active_since': 3.0,
           'active_until': float('inf'),
           'params': {'second_endpoint': 9, 'endpoint_strategy': 'betweenness',
                      'pool_size': 12, 'metric_fake': 1, 'drop_prob': 0.25,
                      'seq_lead': 3, 'poison_scope': 'peer_side'}}
    att = create_attacker(4, cfg)
    assert isinstance(att, WormholeAttacker)
    assert att.node_id == 4 and att.second_endpoint == 9
    assert att.endpoint_strategy == 'betweenness' and att.pool_size == 12
    assert att.metric_fake == 1 and att.drop_prob == 0.25 and att.seq_lead == 3
    assert att.poison_scope == 'peer_side'
    assert att.active_since == 3.0 and att.active_until is None      # inf → None
    assert att.controls(4) and att.controls(9)
    # 别名同样可用
    assert isinstance(create_attacker(0, {'type': 'WormholeAttacker', 'params': {}}),
                      WormholeAttacker)


def test_instantiate_attackers_places_wormhole_a_endpoint():
    n = 10
    edges = _line(n, epochs=1)
    cfg = {'type': 'wormhole', 'count': 1, 'placement': 'degree',
           'active_until': float('inf'), 'params': {'endpoint_strategy': 'farthest'}}
    atts = instantiate_attackers([cfg], edges, seed=0, available_nodes=list(range(n)))
    assert len(atts) == 1 and isinstance(atts[0], WormholeAttacker)
    assert atts[0].node_id in set(range(n))
    assert atts[0].second_endpoint is None          # B 端由注入阶段绑定
    # 显式 node_id 覆盖 placement
    atts2 = instantiate_attackers([dict(cfg, node_id=7)], edges, seed=0,
                                  available_nodes=list(range(n)))
    assert atts2[0].node_id == 7
    # count <= 0 → 跳过
    assert instantiate_attackers([dict(cfg, count=0)], edges, seed=0) == []


def test_unknown_attacker_type_still_raises():
    with pytest.raises(ValueError):
        create_attacker(0, {'type': 'wormhole_typo'})


# ==================== ⑥ runner 接线（e3 嵌套 schema） ====================

def test_e3_runner_wormhole_wiring_metrics_and_metadata():
    import run_e3_blackhole_experiment as e3

    n = 10
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    cfg = _cfg([_wh_att_cfg(node_id=1, second_endpoint=8)], num_flows=5)
    rec = e3.run_experiment(42, cfg, copy.deepcopy(edges), pos, list(range(n)))

    md = rec['metadata']
    assert md['wormhole_injected'] is True
    assert md['wormhole_detection_enabled'] is True
    assert md['wormhole_num_tunnels'] == 1
    assert md['wormhole_tunnels'] == [[1, 8]]
    assert md['wormhole_detector_available'] is True
    assert md['wormhole_mean_tunnel_km'] == pytest.approx(7 * SPACING_KM)
    assert md['num_nodes'] == n and md['num_real_nodes'] == n     # 节点空间**不变**
    # 匹配键不受注入影响 → 仍与同配置基线臂可比
    assert (md['shell'], md['node_limit'], md['num_eval_epochs'], md['num_flows']) == \
           ('TEST', None, 2, 5)

    ds = rec['data_stats']
    for key in WORMHOLE_METRIC_KEYS:
        assert key in ds, key
    assert ds['wormhole_detection_rate'] == 1.0
    assert ds['wormhole_false_positive_rate'] == 0.0
    assert ds['wormhole_attracted_ratio'] > 0.0
    assert ds['wormhole_attracted_trials'] <= ds['num_trials']
    assert ds['num_trials'] == 5 * 2
    # 跳数被"缩短"（攻击得逞）；共线合成布局下隧道两端点的直线距离恰等于原链路
    # 长度，故 geo_stretch 仅在"折返流"（两端均落在隧道区间内）上才严格 > 1；
    # 该签名由 test_attraction_and_stretch_signature_on_line_topology 确定性断言。
    assert ds['wormhole_path_stretch'] < 1.0
    assert ds['wormhole_geo_stretch'] >= 1.0

    wh = rec['wormhole_stats']
    assert wh['num_tunnels'] == 1 and wh['detector_available'] is True
    assert wh['tunnels'] == [[1, 8]]
    assert wh['per_epoch'][0]['suspicious_edges'] == [[1, 8]]
    json.dumps(rec)


def test_e3_runner_baseline_has_no_wormhole_keys_by_default():
    """默认关闭 → 既有配置/记录不含任何 wormhole 键（纯附加，零回归面）。"""
    import run_e3_blackhole_experiment as e3

    rec = e3.run_experiment(42, _cfg([], num_flows=4), copy.deepcopy(_line(8, epochs=2)),
                            None, list(range(8)))
    assert 'wormhole_stats' not in rec
    assert not [k for k in rec['data_stats'] if k.startswith('wormhole_')]
    assert not [k for k in rec['metadata'] if k.startswith('wormhole_')]


def test_e3_runner_detection_enabled_baseline_measures_false_positives():
    """启用检测的匹配基线臂：只发 BASELINE 键，且真实拓扑上误报率为 0。"""
    import run_e3_blackhole_experiment as e3

    n = 10
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    cfg = _cfg([], num_flows=4, detection={'wormhole': {'enabled': True}})
    rec = e3.run_experiment(43, cfg, copy.deepcopy(edges), pos, list(range(n)))
    md = rec['metadata']
    assert md['wormhole_detection_enabled'] is True
    assert md['wormhole_num_tunnels'] == 0
    assert md['wormhole_detector_available'] is True
    assert 'wormhole_injected' not in md                 # 未注入 → 不设该键
    assert 'wormhole_tunnels' not in md
    ds = rec['data_stats']
    assert {k for k in ds if k.startswith('wormhole_')} == set(WORMHOLE_BASELINE_KEYS)
    assert ds['wormhole_false_positive_rate'] == 0.0
    assert ds['wormhole_suspicious_hops'] == 0.0
    assert ds['wormhole_attracted_ratio'] == 0.0
    assert ds['wormhole_latency_flagged_ratio'] == 0.0
    assert rec['wormhole_stats']['detection_rate'] is None


def test_e3_runner_detection_params_come_from_config():
    import run_e3_blackhole_experiment as e3

    n = 8
    cfg = _cfg([], num_flows=3, detection={'wormhole': {
        'enabled': True, 'max_isl_km': 500.0, 'distance_factor': 1.2,
        'adaptive_factor': None, 'latency_factor': 0.5}})
    rec = e3.run_experiment(7, cfg, copy.deepcopy(_line(n, epochs=2)),
                            _line_positions(n, epochs=2), list(range(n)))
    st = rec['wormhole_stats']
    assert st['max_isl_km_assumed'] == 500.0 and st['distance_factor'] == 1.2
    assert st['adaptive_factor'] is None
    assert st['threshold_km'] == pytest.approx(600.0)
    assert st['latency_threshold_ms_per_hop'] == pytest.approx(
        500.0 / SPEED_OF_LIGHT_KM_S * 1000.0 * 0.5)
    # 阈值被压到合法跳距(800 km)以下 → 全部真实边误报（配置生效的可观测证据）
    assert st['false_positive_rate'] == pytest.approx(1.0)
    assert rec['data_stats']['wormhole_latency_flagged_ratio'] == pytest.approx(1.0)


def test_e3_runner_wormhole_endpoint_chosen_by_strategy():
    """不显式给 second_endpoint 时，B 端由 farthest 策略选出（此处链的另一端）。"""
    import run_e3_blackhole_experiment as e3

    n = 10
    cfg = _cfg([_wh_att_cfg(node_id=1, second_endpoint=None)], num_flows=4)
    rec = e3.run_experiment(11, cfg, copy.deepcopy(_line(n, epochs=2)),
                            _line_positions(n, epochs=2), list(range(n)))
    assert rec['metadata']['wormhole_tunnels'] == [[1, n - 1]]
    assert rec['metadata']['num_nodes'] == n
    assert rec['data_stats']['wormhole_detection_rate'] == 1.0


def test_e3_runner_wormhole_coexists_with_blackhole_and_sybil():
    """虫洞与既有攻击者可同臂共存；注入次序为 wormhole → sybil。"""
    import run_e3_blackhole_experiment as e3

    n = 10
    cfg = _cfg([_wh_att_cfg(node_id=1, second_endpoint=8),
                {'type': 'blackhole', 'count': 1, 'node_id': 4, 'drop_prob': 0.0,
                 'active_until': float('inf'), 'params': {}},
                {'type': 'sybil', 'count': 1, 'node_id': 2,
                 'active_until': float('inf'),
                 'params': {'num_identities': 1, 'attachment': 'degree'}}],
               num_flows=4)
    rec = e3.run_experiment(5, cfg, copy.deepcopy(_line(n, epochs=2)),
                            _line_positions(n, epochs=2), list(range(n)))
    md = rec['metadata']
    assert md['wormhole_tunnels'] == [[1, 8]]
    assert md['sybil_injected'] is True and md['sybil_num_identities'] == 1
    assert md['num_nodes'] == n + 1                       # 仅 Sybil 扩展节点空间
    assert md['num_real_nodes'] == n
    assert {k for k in rec['data_stats'] if k.startswith('wormhole_')} == \
        set(WORMHOLE_METRIC_KEYS)
    assert {k for k in rec['data_stats'] if k.startswith('sybil_')} == \
        set(SYBIL_METRIC_KEYS)
    assert (md['shell'], md['node_limit'], md['num_eval_epochs'], md['num_flows']) == \
           ('TEST', None, 2, 4)


def test_e3_runner_peer_side_scope_is_destructive():
    """强度对照臂：peer_side 谎言过强 → 自伤成环，送达率不高于 peer_only。"""
    import run_e3_blackhole_experiment as e3

    n = 10
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    mild = e3.run_experiment(3, _cfg([_wh_att_cfg(1, 8, 'peer_only')], num_flows=6),
                             copy.deepcopy(edges), pos, list(range(n)))
    harsh = e3.run_experiment(3, _cfg([_wh_att_cfg(1, 8, 'peer_side')], num_flows=6),
                              copy.deepcopy(edges), pos, list(range(n)))
    for rec in (mild, harsh):
        assert {k for k in rec['data_stats'] if k.startswith('wormhole_')} == \
            set(WORMHOLE_METRIC_KEYS)
        assert rec['data_stats']['wormhole_detection_rate'] == 1.0
    assert harsh['data_stats']['delivery_ratio'] <= mild['data_stats']['delivery_ratio']
    assert harsh['data_stats']['wormhole_path_stretch'] >= 0.0
    assert mild['wormhole_stats']['num_tunnels'] == 1


# ==================== ⑥ b runner 接线（e2 平铺 schema） ====================

def test_e2_runner_wormhole_wiring_flat_schema():
    import run_e2_jamming_experiment as e2

    n = 10
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    cfg = _cfg([_wh_att_cfg(node_id=1, second_endpoint=8)],
               name='e6_wormhole_e2_tiny', num_flows=5)
    flow_pairs = e2.generate_flows(list(range(n)), 5, 42)
    assert all(s < n and d < n for s, d in flow_pairs)
    res = e2.run_experiment_with_topology(cfg, 42, copy.deepcopy(edges), pos, flow_pairs)

    md = res['metadata']
    assert md['wormhole_injected'] is True
    assert md['wormhole_detection_enabled'] is True
    assert md['wormhole_num_tunnels'] == 1
    assert md['wormhole_tunnels'] == [[1, 8]]
    assert md['num_nodes'] == n and md['num_real_nodes'] == n      # 节点空间不变
    assert (md['shell'], md['node_limit'], md['num_eval_epochs'], md['num_flows']) == \
           ('TEST', None, 2, 5)
    # 平铺 schema 下额外提供 data_stats 块供 T6 聚合提取
    assert {k for k in res['data_stats'] if k.startswith('wormhole_')} == \
        set(WORMHOLE_METRIC_KEYS)
    assert res['data_stats']['wormhole_detection_rate'] == 1.0
    assert res['data_stats']['wormhole_false_positive_rate'] == 0.0
    assert res['wormhole_stats']['detector_available'] is True
    assert res['num_trials'] == 5 * 2
    json.dumps(res)


def test_e2_runner_baseline_data_stats_untouched_by_wormhole_wiring():
    """既有断言护栏：无 Sybil/Wormhole 时 e2 不产出 data_stats 块。"""
    import run_e2_jamming_experiment as e2

    edges = _line(8, epochs=2)
    cfg = _cfg([], name='e6_base_e2_tiny', num_flows=4)
    flow_pairs = e2.generate_flows(list(range(8)), 4, 42)
    res = e2.run_experiment_with_topology(cfg, 42, copy.deepcopy(edges),
                                          [None, None], flow_pairs)
    assert 'data_stats' not in res
    assert 'wormhole_stats' not in res
    assert not [k for k in res['metadata'] if k.startswith('wormhole_')]


def test_e2_runner_sybil_only_arm_keeps_data_stats_sybil_keys():
    """回归护栏：Sybil 臂的 data_stats 键集仍恰为 SYBIL_METRIC_KEYS（未被虫洞污染）。"""
    import run_e2_jamming_experiment as e2

    edges = _line(8, epochs=2)
    cfg = _cfg([{'type': 'sybil', 'count': 1, 'node_id': 1,
                 'active_until': float('inf'),
                 'params': {'num_identities': 2, 'attachment': 'degree'}}],
               name='e4_sybil_e2_guard', num_flows=4)
    flow_pairs = e2.generate_flows(list(range(8)), 4, 42)
    res = e2.run_experiment_with_topology(cfg, 42, copy.deepcopy(edges),
                                          [None, None], flow_pairs)
    assert set(res['data_stats']) == set(SYBIL_METRIC_KEYS)
    assert not [k for k in res['data_stats'] if k.startswith('wormhole_')]


def test_e2_runner_detection_enabled_baseline_measures_false_positives():
    import run_e2_jamming_experiment as e2

    n = 10
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    cfg = _cfg([], name='e6_base_det_e2', num_flows=4,
               detection={'wormhole': {'enabled': True}})
    flow_pairs = e2.generate_flows(list(range(n)), 4, 42)
    res = e2.run_experiment_with_topology(cfg, 42, copy.deepcopy(edges), pos, flow_pairs)
    assert {k for k in res['data_stats'] if k.startswith('wormhole_')} == \
        set(WORMHOLE_BASELINE_KEYS)
    assert res['data_stats']['wormhole_false_positive_rate'] == 0.0
    assert res['data_stats']['wormhole_suspicious_hops'] == 0.0
    assert res['metadata']['wormhole_num_tunnels'] == 0
    assert 'wormhole_injected' not in res['metadata']


def test_e2_runner_sybil_and_wormhole_share_data_stats_block():
    import run_e2_jamming_experiment as e2

    n = 10
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    cfg = _cfg([_wh_att_cfg(node_id=1, second_endpoint=8),
                {'type': 'sybil', 'count': 1, 'node_id': 3,
                 'active_until': float('inf'),
                 'params': {'num_identities': 1, 'attachment': 'degree'}}],
               name='e6_mix_e2', num_flows=4)
    flow_pairs = e2.generate_flows(list(range(n)), 4, 42)
    res = e2.run_experiment_with_topology(cfg, 42, copy.deepcopy(edges), pos, flow_pairs)
    assert set(res['data_stats']) == set(SYBIL_METRIC_KEYS) | set(WORMHOLE_METRIC_KEYS)
    assert res['metadata']['num_nodes'] == n + 1
    assert res['metadata']['wormhole_tunnels'] == [[1, 8]]


# ==================== ⑦ sweep / T6 统计框架兼容 ====================

def test_sweep_metrics_include_wormhole_keys_without_duplicates():
    import run_experiment_sweep as sw

    assert set(DEFAULT_METRICS).issubset(set(sw.SWEEP_METRICS))
    assert set(SYBIL_METRIC_KEYS).issubset(set(sw.SWEEP_METRICS))
    assert set(WORMHOLE_METRIC_KEYS).issubset(set(sw.SWEEP_METRICS))
    assert len(set(sw.SWEEP_METRICS)) == len(sw.SWEEP_METRICS)


def test_extract_metrics_and_aggregate_include_wormhole_keys(tmp_path):
    import run_e3_blackhole_experiment as e3
    from starlink_sim.analytics import stats as st
    import run_experiment_sweep as sw

    n = 8
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    cfg = _cfg([_wh_att_cfg(node_id=1, second_endpoint=6)], num_flows=4)
    files = []
    for seed in (42, 43):
        rec = e3.run_experiment(seed, cfg, copy.deepcopy(edges), pos, list(range(n)))
        m = st.extract_metrics(rec)
        for key in WORMHOLE_METRIC_KEYS:
            assert key in m
        p = tmp_path / f"e6_wormhole_seed{seed}.json"
        p.write_text(json.dumps(rec), encoding='utf-8')
        files.append(p)

    agg = st.aggregate_experiment([str(p) for p in files], metrics=sw.SWEEP_METRICS,
                                  n_boot=2000, alpha=0.05, rng=0)
    for key in WORMHOLE_METRIC_KEYS:
        assert key in agg['metrics'] and 'mean' in agg['metrics'][key]
    assert agg['metrics']['wormhole_num_tunnels']['mean'] == pytest.approx(1.0)
    assert agg['metrics']['wormhole_detection_rate']['mean'] == pytest.approx(1.0)
    assert agg['metrics']['wormhole_false_positive_rate']['mean'] == pytest.approx(0.0)
    # 匹配键不含 num_nodes、不含任何 wormhole 键 → 注入不破坏与基线臂的可比性
    assert agg['cardinality']['match_key'] == {'shell': 'TEST', 'node_limit': None,
                                               'num_eval_epochs': 2, 'num_flows': 4}


def test_aggregate_skips_tunnel_keys_absent_on_baseline_arm(tmp_path):
    """基线臂缺席 TUNNEL 键 → 聚合自动跳过，不会用 0.0 污染统计。"""
    import run_e3_blackhole_experiment as e3
    from starlink_sim.analytics import stats as st
    import run_experiment_sweep as sw

    n = 8
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    cfg = _cfg([], num_flows=4, detection={'wormhole': {'enabled': True}})
    files = []
    for seed in (42, 43):
        rec = e3.run_experiment(seed, cfg, copy.deepcopy(edges), pos, list(range(n)))
        p = tmp_path / f"e6_base_seed{seed}.json"
        p.write_text(json.dumps(rec), encoding='utf-8')
        files.append(p)
    agg = st.aggregate_experiment([str(p) for p in files], metrics=sw.SWEEP_METRICS,
                                  n_boot=2000, alpha=0.05, rng=0)
    for key in WORMHOLE_BASELINE_KEYS:
        assert key in agg['metrics']
    for key in WORMHOLE_TUNNEL_KEYS:
        assert key not in agg['metrics']


def test_compare_wormhole_arm_vs_baseline_still_comparable(tmp_path):
    """虫洞臂与"启用检测的匹配基线臂"匹配键一致 → 可配对比较。"""
    import run_e3_blackhole_experiment as e3
    from starlink_sim.analytics import stats as st
    import run_experiment_sweep as sw

    n = 8
    edges = _line(n, epochs=2)
    pos = _line_positions(n, epochs=2)
    det = {'wormhole': {'enabled': True}}
    atk_files, base_files = [], []
    for seed in (42, 43):
        atk = e3.run_experiment(seed, _cfg([_wh_att_cfg(node_id=1, second_endpoint=6)],
                                           num_flows=4, detection=det),
                                copy.deepcopy(edges), pos, list(range(n)))
        base = e3.run_experiment(seed, _cfg([], num_flows=4, detection=det),
                                 copy.deepcopy(edges), pos, list(range(n)))
        pa = tmp_path / f"wh_atk_seed{seed}.json"
        pb = tmp_path / f"wh_base_seed{seed}.json"
        pa.write_text(json.dumps(atk), encoding='utf-8')
        pb.write_text(json.dumps(base), encoding='utf-8')
        atk_files.append(pa)
        base_files.append(pb)

    cmp = st.compare_attack_vs_baseline([str(p) for p in atk_files],
                                        [str(p) for p in base_files],
                                        metrics=sw.SWEEP_METRICS,
                                        alpha=0.05, strict=True)
    assert cmp['n_comparable_groups'] >= 1
    grp = next(g for g in cmp['groups'] if g.get('comparable'))
    assert 'delivery_ratio' in grp['comparisons']
    # peer_only 是健全捷径：送达率不高于基线（通常持平），破坏性体现在时延/距离
    assert grp['comparisons']['delivery_ratio']['median_diff'] <= 0.0
    # 两臂都发射的 BASELINE 键可配对比较（误报率两臂皆为 0）
    assert 'wormhole_false_positive_rate' in grp['comparisons']
