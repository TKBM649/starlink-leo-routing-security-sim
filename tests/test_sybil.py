# tests/test_sybil.py
"""
E4 Sybil（虚假身份）攻击单元测试。

覆盖任务规格要求的四类断言：
① **身份注入**正确扩展节点 ID 空间与 edge_sets（新 num_nodes、新边存在于每个 epoch、
   附着到预期真实节点、绝不原地修改传入拓扑）；
② **伪造通告被真实采纳**：虚假身份发布的低 metric 通告经 ``_bump_seq`` 被其附着邻居
   在 ``DVRouter._process_update`` 中真实采纳（端到端小拓扑 ControlPlane）；
③ **吸引率可度量**：小合成拓扑上 ``compute_sybil_attraction`` 给出 > 0 的流量占比，
   且容忍环路的 ``trace_forwarding_nodes`` 不丢"流量曾被牵引"这一事实；
④ **注册与工厂分派**：``ATTACKER_CLASSES['sybil']`` / ``create_attacker`` /
   ``instantiate_attackers`` 可用，构造签名兼容 ``params`` kwargs。

外加：``controls()`` 基类与旧 ``att.node_id == X`` 判定逐位等价（blackhole/jamming
回归护栏）、runner（e3/e2）接线产出 Sybil 指标与 metadata、sweep 聚合指标含 Sybil 键。

全部纯合成小图（<= 7 节点、<= 40 tick），秒级完成，不碰真实 102.8MB 拓扑缓存。
"""
import copy
import json
import random
from types import SimpleNamespace

import pytest

from starlink_sim.net.attack import (
    Attacker,
    BlackholeAttacker,
    JammingAttacker,
    SybilAttacker,
)
from starlink_sim.net.placement import (
    ATTACKER_CLASSES,
    create_attacker,
    instantiate_attackers,
    select_attackers,
)
from starlink_sim.net.routing_dv import DVMessage
from starlink_sim.net.simulator import ControlPlane, DataPlane
from starlink_sim.net.sybil import (
    SYBIL_ATTACHMENT_STRATEGIES,
    SYBIL_METRIC_KEYS,
    SybilInjection,
    compute_sybil_attraction,
    expand_topology_for_sybils,
    inject_sybil_identities,
    trace_forwarding_nodes,
)


# ==================== 合成小拓扑工具 ====================

def _path(n=4):
    """单 epoch 路径图 0-1-...-(n-1)。"""
    return [{(i, i + 1) for i in range(n - 1)}]


def _ring(n=4, epochs=1):
    """n 节点环 × epochs 个 epoch（每个 epoch 边集相同）。"""
    ring = {(i, (i + 1) % n) for i in range(n)}
    return [set(ring) for _ in range(epochs)]


def _entry(next_hop, metric=1, seq=1):
    """轻量路由条目替身（trace_forwarding_nodes 只读 next_hop）。"""
    return SimpleNamespace(dest=None, next_hop=next_hop, metric=metric, seq=seq,
                           age=0.0, path=[])


def _run_control_plane(edges, num_nodes, attackers, ticks=40, tick=1.0, adv=2.0):
    """在给定（可能已扩展的）拓扑上跑一个单 epoch 控制面，返回 ControlPlane。"""
    cp = ControlPlane(num_nodes=num_nodes, tick_interval=tick,
                      attackers=attackers, adv_interval=adv)
    # epoch_duration 远大于总时长 → 全程 epoch 0（单快照）
    cp.run_ticks(ticks, edges, epoch_duration=float(ticks * tick * 10))
    return cp


# ==================== ① 身份注入：节点 ID 空间与 edge_sets 扩展 ====================

def test_inject_expands_node_space_edges_and_num_nodes():
    edges = _path(4)                      # 真实节点 0..3
    before = copy.deepcopy(edges)
    inj = inject_sybil_identities(edges, num_identities=2, attachment='degree',
                                 controller_node=0, rng=random.Random(0))
    # 新身份 ID 从 max(真实)+1 起连续编号
    assert inj.sybil_node_ids == [4, 5]
    assert inj.node_ids == [0, 1, 2, 3, 4, 5]
    assert inj.num_nodes == 6             # = max(node_ids)+1
    assert inj.num_identities == 2
    assert inj.controller_node == 0
    # 附着映射：每个身份接到一个**真实**节点
    assert set(inj.attachment_map) == {4, 5}
    assert all(t in {0, 1, 2, 3} for t in inj.attachment_map.values())
    assert set(inj.targets).issubset({0, 1, 2, 3})
    # 新边确实写入 edge_sets
    for ep in inj.edges_per_epoch:
        for sid, tgt in inj.attachment_map.items():
            assert (sid, tgt) in ep
        # 原有边一条不少
        assert before[0].issubset(ep)
    # **绝不原地修改**传入拓扑（sweep worker 缓存跨任务共享）
    assert edges == before


def test_inject_writes_identity_edges_into_every_epoch():
    edges = _ring(5, epochs=3)
    inj = inject_sybil_identities(edges, num_identities=1, attachment='degree',
                                 rng=random.Random(1))
    sid = inj.sybil_node_ids[0]
    tgt = inj.attachment_map[sid]
    assert len(inj.edges_per_epoch) == 3
    for ep in inj.edges_per_epoch:          # 虚假身份常驻 → 每个 epoch 都有边
        assert (sid, tgt) in ep
    for orig, new in zip(edges, inj.edges_per_epoch):
        assert orig.issubset(new)
        assert len(new) == len(orig) + 1


def test_inject_zero_or_negative_identities_is_noop():
    edges = _ring(4, epochs=2)
    before = copy.deepcopy(edges)
    for n in (0, -3, None):
        inj = inject_sybil_identities(edges, num_identities=n, rng=random.Random(0))
        assert inj.sybil_node_ids == []
        assert inj.attachment_map == {}
        assert inj.num_identities == 0
        assert inj.node_ids == [0, 1, 2, 3]
        assert inj.num_nodes == 4
        assert inj.edges_per_epoch == before
    assert edges == before


def test_inject_empty_topology_returns_empty_injection():
    inj = inject_sybil_identities([set()], num_identities=3, rng=random.Random(0))
    assert inj.sybil_node_ids == [] and inj.num_nodes == 0 and inj.node_ids == []


def test_inject_more_identities_than_real_nodes_round_robin():
    edges = _path(3)                        # 真实节点 0,1,2
    inj = inject_sybil_identities(edges, num_identities=5, attachment='degree',
                                 rng=random.Random(0))
    assert inj.sybil_node_ids == [3, 4, 5, 6, 7]
    assert inj.num_nodes == 8
    # 目标数 = min(num_identities, 真实节点数) = 3，身份轮回复用附着点
    assert len(inj.targets) == 3
    assert len(set(inj.attachment_map.values())) == 3
    counts = {}
    for tgt in inj.attachment_map.values():
        counts[tgt] = counts.get(tgt, 0) + 1
    assert sum(counts.values()) == 5
    assert max(counts.values()) - min(counts.values()) <= 1   # 轮转均衡


def test_inject_base_node_id_override_avoids_collision():
    edges = _path(4)
    inj = inject_sybil_identities(edges, num_identities=2, base_node_id=100,
                                 rng=random.Random(0))
    assert inj.sybil_node_ids == [100, 101]
    assert inj.num_nodes == 102
    assert inj.node_ids == [0, 1, 2, 3, 100, 101]


@pytest.mark.parametrize("strategy", list(SYBIL_ATTACHMENT_STRATEGIES))
def test_inject_attachment_strategies_all_valid(strategy):
    edges = _path(6)
    inj = inject_sybil_identities(edges, num_identities=2, attachment=strategy,
                                 rng=random.Random(3))
    assert len(inj.sybil_node_ids) == 2
    assert set(inj.targets).issubset(set(range(6)))
    # 身份边存在且附着点为真实节点
    for sid, tgt in inj.attachment_map.items():
        assert (sid, tgt) in inj.edges_per_epoch[0]
        assert tgt < 6


def test_inject_betweenness_attaches_to_high_centrality_node():
    edges = _path(5)                        # 0-1-2-3-4，中心 2 介数最高
    inj = inject_sybil_identities(edges, num_identities=1, attachment='betweenness',
                                 rng=random.Random(0))
    assert inj.targets == [2]
    assert inj.targets == select_attackers(edges, 1, strategy='betweenness',
                                          rng=random.Random(0))
    assert inj.attachment_map[inj.sybil_node_ids[0]] == 2


def test_inject_invalid_attachment_falls_back_to_betweenness():
    edges = _path(5)
    inj = inject_sybil_identities(edges, num_identities=1, attachment='not_a_strategy',
                                 rng=random.Random(0))
    assert inj.targets == [2]               # 回退 betweenness → 中心节点


def test_inject_deterministic_given_same_seed():
    edges = _ring(6, epochs=2)
    a = inject_sybil_identities(edges, 3, attachment='random', rng=random.Random(7))
    b = inject_sybil_identities(edges, 3, attachment='random', rng=random.Random(7))
    assert a.attachment_map == b.attachment_map
    assert a.sybil_node_ids == b.sybil_node_ids
    assert a.edges_per_epoch == b.edges_per_epoch


def test_inject_returns_dataclass_with_documented_fields():
    inj = inject_sybil_identities(_path(3), 1, rng=random.Random(0))
    assert isinstance(inj, SybilInjection)
    for f in ('edges_per_epoch', 'sybil_node_ids', 'attachment_map', 'node_ids',
              'num_nodes', 'controller_node', 'num_identities', 'attachment', 'targets'):
        assert hasattr(inj, f)


# ==================== expand_topology_for_sybils（runner/sweep 入口） ====================

def test_expand_binds_identities_back_to_attacker():
    edges = _ring(5, epochs=2)
    att = SybilAttacker(node_id=1, num_identities=2, attachment='degree')
    exp_edges, node_ids, injs = expand_topology_for_sybils([att], edges, [0, 1, 2, 3, 4],
                                                          seed=0)
    assert len(injs) == 1
    assert att.sybil_node_ids == set(injs[0].sybil_node_ids) == {5, 6}
    assert att.attachment_map == injs[0].attachment_map
    # controls() 覆盖被劫持物理节点 + 全部虚假身份
    assert att.controls(1) and att.controls(5) and att.controls(6)
    assert not att.controls(0) and not att.controls(7)
    assert node_ids == [0, 1, 2, 3, 4, 5, 6]
    assert max(node_ids) + 1 == 7
    for ep in exp_edges:
        for sid, tgt in att.attachment_map.items():
            assert (sid, tgt) in ep


def test_expand_multiple_sybil_attackers_get_disjoint_ids():
    edges = _ring(6, epochs=1)
    a1 = SybilAttacker(node_id=0, num_identities=2, attachment='degree')
    a2 = SybilAttacker(node_id=3, num_identities=3, attachment='random')
    exp_edges, node_ids, injs = expand_topology_for_sybils([a1, a2], edges,
                                                          list(range(6)), seed=5)
    assert len(injs) == 2
    assert a1.sybil_node_ids == {6, 7}
    assert a2.sybil_node_ids == {8, 9, 10}
    assert not (a1.sybil_node_ids & a2.sybil_node_ids)     # ID 不重叠
    assert node_ids == list(range(11))
    assert max(node_ids) + 1 == 11
    # 两个攻击者的身份边都在最终 edge_sets 里
    for sid, tgt in {**a1.attachment_map, **a2.attachment_map}.items():
        assert (sid, tgt) in exp_edges[0]


def test_expand_without_sybil_returns_equal_copy_and_no_injections():
    edges = _ring(4, epochs=2)
    bh = BlackholeAttacker(node_id=1, drop_prob=1.0)
    jam = JammingAttacker(node_id=2, jamming_ratio=0.5)
    exp_edges, node_ids, injs = expand_topology_for_sybils([bh, jam], edges,
                                                          [0, 1, 2, 3], seed=0)
    assert injs == []
    assert node_ids == [0, 1, 2, 3]
    assert exp_edges == [set(ep) for ep in edges]
    # 是新对象（不改缓存），且既有攻击者未被绑定任何身份
    assert all(exp_edges[i] is not edges[i] for i in range(len(edges)))
    assert not hasattr(bh, 'sybil_node_ids')


def test_expand_does_not_mutate_input_edges():
    edges = _ring(4, epochs=2)
    before = copy.deepcopy(edges)
    att = SybilAttacker(node_id=0, num_identities=2)
    expand_topology_for_sybils([att], edges, [0, 1, 2, 3], seed=0)
    assert edges == before


def test_expand_uses_attacker_num_identities_and_attachment():
    edges = _path(5)
    att = SybilAttacker(node_id=0, num_identities=1, attachment='betweenness')
    _, _, injs = expand_topology_for_sybils([att], edges, [0, 1, 2, 3, 4], seed=0)
    assert injs[0].num_identities == 1
    assert injs[0].attachment == 'betweenness'
    assert injs[0].targets == [2]           # 路径中心（最高介数）
    assert injs[0].controller_node == 0


# ==================== SybilAttacker 语义 ====================

def test_attacker_controls_base_class_is_node_id_equality():
    """回归护栏：基类 controls 与旧 ``att.node_id == X`` 逐位等价。"""
    for att in (BlackholeAttacker(node_id=3, drop_prob=1.0),
                JammingAttacker(node_id=3, jamming_ratio=0.5)):
        for n in range(-1, 9):
            assert att.controls(n) == (n == 3)


def test_sybil_controls_covers_controller_and_identities():
    att = SybilAttacker(node_id=2, num_identities=2)
    assert att.controls(2)                  # 未绑定身份前仍控制物理节点
    assert not att.controls(9)
    att.bind_identities([7, 8], {7: 2, 8: 5})
    assert att.controls(2) and att.controls(7) and att.controls(8)
    assert not att.controls(0) and not att.controls(9)
    assert att.sybil_node_ids == {7, 8}
    assert att.attachment_map == {7: 2, 8: 5}


def _adv(src, entries, visited=None):
    return DVMessage(type='update', src=src, dst=-1, seq=1,
                     visited=list(visited or []), entries=list(entries))


def test_sybil_poisons_identity_advertisement_with_fake_low_metric():
    att = SybilAttacker(node_id=0, num_identities=1, metric_fake=0)
    att.bind_identities([4], {4: 1})
    msg = _adv(4, [(4, 0, 1), (1, 1, 1), (2, 2, 1), (3, 3, 1)])
    out = att.modify_advertisement(msg, None, None, 0.0)
    by_dest = {d: (m, s) for d, m, s in out.entries}
    assert by_dest[4] == (0, 1)             # 到自身条目保留（不污染本地距离）
    for d in (1, 2, 3):
        assert by_dest[d][0] == 0           # 伪造低 metric
        assert by_dest[d][1] > 1            # _bump_seq：seq 严格增大 → 接收端采纳
    # 报文骨架保留
    assert (out.src, out.dst, out.type) == (4, -1, 'update')
    assert out is not msg


def test_sybil_leaves_other_nodes_advertisements_untouched():
    att = SybilAttacker(node_id=0, num_identities=1)
    att.bind_identities([4], {4: 1})
    msg = _adv(2, [(2, 0, 1), (3, 1, 1)])
    out = att.modify_advertisement(msg, None, None, 0.0)
    assert out is msg                       # 非受控节点 → 原样返回
    assert out.entries == [(2, 0, 1), (3, 1, 1)]


def test_sybil_controller_poisons_flag_default_off():
    msg_entries = [(0, 0, 1), (1, 1, 1), (2, 2, 1)]
    off = SybilAttacker(node_id=0, num_identities=1)
    off.bind_identities([4], {4: 1})
    assert off.controller_poisons is False
    assert off.modify_advertisement(_adv(0, msg_entries), None, None, 0.0).entries == msg_entries

    on = SybilAttacker(node_id=0, num_identities=1, controller_poisons=True)
    on.bind_identities([4], {4: 1})
    out = on.modify_advertisement(_adv(0, msg_entries), None, None, 0.0)
    assert {d: m for d, m, _ in out.entries} == {0: 0, 1: 0, 2: 0}


def test_sybil_respects_active_window():
    att = SybilAttacker(node_id=0, num_identities=1, active_since=100.0,
                        active_until=200.0)
    att.bind_identities([4], {4: 1})
    msg = _adv(4, [(4, 0, 1), (1, 1, 1)])
    assert att.modify_advertisement(msg, None, None, 0.0) is msg      # 未激活
    assert att.modify_advertisement(msg, None, None, 250.0) is msg    # 已过期
    out = att.modify_advertisement(msg, None, None, 150.0)            # 激活中
    assert {d: m for d, m, _ in out.entries} == {4: 0, 1: 0}


def test_sybil_bumped_seq_is_monotonic_across_calls():
    att = SybilAttacker(node_id=0, num_identities=1, metric_fake=0)
    att.bind_identities([4], {4: 1})
    seqs = []
    for i in range(5):
        out = att.modify_advertisement(_adv(4, [(4, 0, 1), (7, i, 1)]), None, None, 0.0)
        seqs.append(dict((d, s) for d, _, s in out.entries)[7])
    assert seqs == sorted(seqs) and len(set(seqs)) == 5   # 严格单调递增


def test_sybil_seq_lead_defaults_positive_and_is_configurable():
    """``seq_lead``：伪造 seq 在单调基线上额外领先，避免与更新鲜的合法通告仅打平。"""
    att = SybilAttacker(node_id=0, num_identities=1)
    assert att.seq_lead > 0
    assert create_attacker(0, {'type': 'sybil', 'params': {'seq_lead': 3}}).seq_lead == 3
    assert create_attacker(0, {'type': 'sybil', 'params': {'seq_lead': -5}}).seq_lead == 0

    lead = SybilAttacker(node_id=0, num_identities=1, seq_lead=5)
    lead.bind_identities([4], {4: 1})
    # entries = (dest, metric, seq)：dest 7 原 seq=1
    out = lead.modify_advertisement(_adv(4, [(4, 0, 1), (7, 10, 1)]), None, None, 0.0)
    by_dest = {d: (m, s) for d, m, s in out.entries}
    assert by_dest[7][0] == 0                 # metric 被伪造为 metric_fake
    assert by_dest[7][1] == 1 + 1 + 5         # max(seq, floor) + 1 + seq_lead
    assert by_dest[4] == (0, 1)               # 到自身条目原样保留
    assert lead._seq_floor[7] == by_dest[7][1]  # floor 同步抬升 → 下一周期仍领先
    out2 = lead.modify_advertisement(_adv(4, [(4, 0, 1), (7, 3, 1)]), None, None, 0.0)
    seq7b = dict((d, s) for d, _, s in out2.entries)[7]
    assert seq7b > by_dest[7][1]              # 即使合法 seq 回落也保持单调


def test_seq_lead_is_what_makes_the_poison_stick():
    """回归护栏：无 seq 领先时，伪造通告仅与合法通告打平 → 牵引被立即翻回。

    本用例固定了 E4 实现过程中实测到的关键机制：``DVRouter._process_update`` 只在
    ``seq > current.seq`` 时采纳，而虚假身份的路由知识比目的节点自身通告滞后 2 跳，
    故 ``seq_lead=0`` 时吸引率为 0；默认 ``seq_lead>0`` 时牵引稳定可测。
    """
    flows = [(s, d) for s in range(4) for d in range(4) if s != d]

    def _ratio(seq_lead):
        att = SybilAttacker(node_id=0, num_identities=1, attachment='betweenness',
                            seq_lead=seq_lead)
        exp_edges, node_ids, injs = expand_topology_for_sybils([att], _ring(4),
                                                              [0, 1, 2, 3], seed=0)
        cp = _run_control_plane(exp_edges, num_nodes=max(node_ids) + 1, attackers=[att])
        return compute_sybil_attraction(flows, injs[0].sybil_node_ids,
                                       [cp.get_routing_tables()], exp_edges, 1, 20)

    assert _ratio(0)['sybil_attraction_ratio'] == 0.0     # 仅打平 → 被合法通告翻回
    assert _ratio(8)['sybil_attraction_ratio'] > 0.0      # 领先 → 牵引生效


def test_sybil_should_drop_data_defaults_to_no_drop():
    att = SybilAttacker(node_id=0, num_identities=1)
    assert att.drop_prob == 0.0
    assert all(att.should_drop_data((1, 2), 0.0) is False for _ in range(20))

    drop = SybilAttacker(node_id=0, num_identities=1, drop_prob=1.0,
                         active_since=10.0, active_until=20.0)
    assert drop.should_drop_data((1, 2), 15.0) is True
    assert drop.should_drop_data((1, 2), 5.0) is False    # 窗口外不丢


# ==================== ② 伪造通告被真实邻居采纳（端到端 ControlPlane） ====================

def test_sybil_fake_advertisement_adopted_by_real_neighbor():
    edges = _path(4)                        # 0-1-2-3
    real = [0, 1, 2, 3]
    att = SybilAttacker(node_id=0, num_identities=1, attachment='degree', metric_fake=0)
    exp_edges, node_ids, injs = expand_topology_for_sybils([att], edges, real, seed=0)
    sid = injs[0].sybil_node_ids[0]
    tgt = injs[0].attachment_map[sid]
    assert sid == 4 and tgt in (1, 2)

    cp = _run_control_plane(exp_edges, num_nodes=max(node_ids) + 1, attackers=[att])
    tables = cp.get_routing_tables()

    # 注入边生效：身份只有附着点一个邻居，且附着点视身份为邻居
    assert cp.neighbors[sid] == {tgt}
    assert sid in cp.neighbors[tgt]
    # 身份节点在扩展后的 num_nodes 内拥有 router（E4 难点：必须先扩 ID 空间）
    assert sid in cp.routers

    # 附着点被伪造低 metric 牵引：存在目的地其 next_hop 指向虚假身份
    poisoned = [d for d, e in tables[tgt].items() if e.next_hop == sid]
    assert poisoned, f"附着点 {tgt} 未采纳虚假身份 {sid} 的伪造通告"
    far = [n for n in real if n != tgt and n not in cp.neighbors[tgt]]
    assert set(poisoned) & set(far), "被牵引的目的地应包含非直连节点（真实路由劫持）"
    for d in poisoned:
        assert tables[tgt][d].metric == 1        # metric_fake(0) + 1
        assert tables[tgt][d].seq >= 1           # _bump_seq 后 > 原 seq → 被采纳
        assert d != tgt


def test_without_sybil_no_route_points_to_identity_node():
    """对照组：同拓扑无 Sybil → 路由为真实最短路，不存在身份节点。"""
    edges = _path(4)
    cp = _run_control_plane(edges, num_nodes=4, attackers=[])
    tables = cp.get_routing_tables()
    assert set(tables) == {0, 1, 2, 3}
    assert tables[1][3].next_hop == 2 and tables[1][3].metric == 2
    assert tables[2][0].next_hop == 1 and tables[2][0].metric == 2
    # 数据面可达
    dp = DataPlane(tables, edges, attackers=[], max_hops=20)
    path, _ = dp.compute_path(0, 3, 0)
    assert path == [0, 1, 2, 3]


def test_sybil_identity_is_neighbor_required_for_adoption():
    """``_process_update`` 仅采纳邻居通告 → 未注入边的身份无法生效（反证注入必要性）。"""
    edges = _path(4)
    att = SybilAttacker(node_id=0, num_identities=1)
    att.bind_identities([4], {4: 1})        # 手工绑定，但**不**注入边
    cp = _run_control_plane(edges, num_nodes=5, attackers=[att])
    assert cp.neighbors[4] == set()
    tables = cp.get_routing_tables()
    for node_tbl in tables.values():
        assert all(e.next_hop != 4 for e in node_tbl.values())


# ==================== ③ 吸引率度量（容忍环路） ====================

def test_trace_forwarding_nodes_success_path():
    tables = {0: {3: _entry(1)}, 1: {3: _entry(2)}, 2: {3: _entry(3)}}
    edges = {(0, 1), (1, 2), (2, 3)}
    nodes, reached = trace_forwarding_nodes(tables, edges, 0, 3, max_hops=10)
    assert reached is True
    assert nodes == {0, 1, 2, 3}


def test_trace_forwarding_nodes_tolerates_loop_without_hanging():
    """Sybil 典型后果 R→I→R 环：普通 compute_path 返回 None 丢事实，本追踪器保留。"""
    tables = {0: {2: _entry(1)}, 1: {2: _entry(0)}}   # 0→1→0 成环
    edges = {(0, 1)}
    nodes, reached = trace_forwarding_nodes(tables, edges, 0, 2, max_hops=50)
    assert reached is False
    assert nodes == {0, 1}                  # 已途经节点（含成环节点）被完整记录


def test_trace_forwarding_nodes_stops_on_missing_entry_or_broken_link():
    tables = {0: {2: _entry(1)}, 1: {}}
    edges = {(0, 1), (1, 2)}
    nodes, reached = trace_forwarding_nodes(tables, edges, 0, 2, max_hops=10)
    assert reached is False and nodes == {0, 1}      # 中间节点无条目
    # 下一跳无边（链路不存在）
    tables2 = {0: {2: _entry(9)}}
    nodes2, reached2 = trace_forwarding_nodes(tables2, {(0, 1)}, 0, 2, max_hops=10)
    assert reached2 is False and nodes2 == {0}
    # 源即目的
    nodes3, reached3 = trace_forwarding_nodes({}, set(), 5, 5)
    assert reached3 is True and nodes3 == {5}


def test_trace_forwarding_nodes_respects_max_hops():
    tables = {i: {99: _entry(i + 1)} for i in range(10)}
    edges = {(i, i + 1) for i in range(10)}
    nodes, reached = trace_forwarding_nodes(tables, edges, 0, 99, max_hops=3)
    assert reached is False and len(nodes) <= 4


def test_compute_sybil_attraction_counts_only_flows_through_identities():
    """手工路由表：一条流被牵引经过身份，另一条无路由 → 占比 0.5。"""
    tables = {
        0: {2: _entry(1)},
        1: {2: _entry(3)},      # 被毒化：下一跳为虚假身份 3
        3: {2: _entry(1)},      # 身份只能经附着点回转 → 环
        2: {},
    }
    edges = [{(0, 1), (1, 2), (1, 3)}]
    res = compute_sybil_attraction([(0, 2), (2, 0)], [3], [tables], edges,
                                  num_epochs=1, max_hops=20)
    assert res['sybil_total_trials'] == 2
    assert res['sybil_attracted_trials'] == 1
    assert res['sybil_attraction_ratio'] == pytest.approx(0.5)


def test_compute_sybil_attraction_requires_identity_edge_to_exist():
    tables = {0: {2: _entry(1)}, 1: {2: _entry(3)}, 3: {2: _entry(1)}, 2: {}}
    edges_no_sybil = [{(0, 1), (1, 2)}]      # 身份边不存在 → 追踪在断链处停止
    res = compute_sybil_attraction([(0, 2)], [3], [tables], edges_no_sybil,
                                  num_epochs=1, max_hops=20)
    assert res['sybil_attracted_trials'] == 0
    assert res['sybil_attraction_ratio'] == 0.0


def test_compute_sybil_attraction_no_identities_is_zero():
    tables = {0: {1: _entry(1)}, 1: {}}
    res = compute_sybil_attraction([(0, 1)], [], [tables], [{(0, 1)}], 1, 10)
    assert res['sybil_attraction_ratio'] == 0.0
    assert res['sybil_attracted_trials'] == 0


def test_compute_sybil_attraction_multiplies_trials_by_epochs():
    tables = {0: {1: _entry(2)}, 2: {1: _entry(0)}, 1: {}}
    edges = [{(0, 2), (0, 1)}] * 3
    res = compute_sybil_attraction([(0, 1)], [2], [tables], edges, num_epochs=3,
                                  max_hops=10)
    assert res['sybil_total_trials'] == 3    # 1 flow × 3 epochs
    assert res['sybil_attracted_trials'] == 3
    assert res['sybil_attraction_ratio'] == pytest.approx(1.0)


def test_compute_sybil_attraction_degrades_gracefully_when_edges_shorter():
    """epoch 越界时边集取空 → 追踪在首跳断链，不抛异常（仅该 epoch 不计吸引）。"""
    tables = {0: {1: _entry(2)}, 2: {1: _entry(0)}, 1: {}}
    res = compute_sybil_attraction([(0, 1)], [2], [tables], [{(0, 2), (0, 1)}],
                                  num_epochs=2, max_hops=10)
    assert res['sybil_total_trials'] == 2
    assert res['sybil_attracted_trials'] == 1
    assert res['sybil_attraction_ratio'] == pytest.approx(0.5)


def test_sybil_attraction_ratio_positive_on_synthetic_ring():
    """端到端：4 节点环 + 2 个虚假身份 → 吸引率 > 0（Sybil 确实牵引了流量）。"""
    edges = _ring(4)
    real = [0, 1, 2, 3]
    att = SybilAttacker(node_id=0, num_identities=2, attachment='betweenness',
                        metric_fake=0)
    exp_edges, node_ids, injs = expand_topology_for_sybils([att], edges, real, seed=0)
    sybil_ids = injs[0].sybil_node_ids
    assert len(sybil_ids) == 2

    cp = _run_control_plane(exp_edges, num_nodes=max(node_ids) + 1, attackers=[att])
    tables = cp.get_routing_tables()
    flows = [(s, d) for s in real for d in real if s != d]
    res = compute_sybil_attraction(flows, sybil_ids, [tables], exp_edges,
                                  num_epochs=1, max_hops=20)
    assert res['sybil_total_trials'] == len(flows) == 12
    assert res['sybil_attracted_trials'] > 0
    assert res['sybil_attraction_ratio'] > 0.0

    # 牵引的破坏性后果：数据面出现环路/不可达（delivery_ratio < 无攻击基线 1.0）
    dp = DataPlane(tables, exp_edges, attackers=[att], max_hops=20)
    stats = dp.evaluate_flows(flows, epoch_duration=1.0, base_time=0.0, num_epochs=1)
    assert stats['delivery_ratio'] < 1.0
    assert stats['num_trials'] == len(flows)
    # 注意：DataPlane.compute_path 遇环即返回 None → attacked_count 无法反映 Sybil 牵引
    # （被牵引的流恰好因环路计为不可达），这正是需要专用吸引率度量的原因。
    assert dp.loop_paths, "Sybil 牵引应造成可观测的转发环路"
    assert stats['attacked_count'] >= 0


def test_sybil_more_identities_attract_at_least_as_much():
    """身份数 vs 效果：更多身份（附着更多真实节点）吸引率不降。"""
    ratios = []
    for n_ids in (1, 2):
        edges = _ring(4)
        att = SybilAttacker(node_id=0, num_identities=n_ids, attachment='betweenness')
        exp_edges, node_ids, injs = expand_topology_for_sybils([att], edges,
                                                              [0, 1, 2, 3], seed=0)
        cp = _run_control_plane(exp_edges, num_nodes=max(node_ids) + 1, attackers=[att])
        flows = [(s, d) for s in range(4) for d in range(4) if s != d]
        res = compute_sybil_attraction(flows, injs[0].sybil_node_ids,
                                      [cp.get_routing_tables()], exp_edges, 1, 20)
        ratios.append(res['sybil_attraction_ratio'])
    assert ratios[0] > 0.0
    assert ratios[1] >= ratios[0]


# ==================== ④ 注册与工厂分派 ====================

def test_attacker_classes_registers_sybil():
    assert ATTACKER_CLASSES['sybil'] is SybilAttacker
    assert ATTACKER_CLASSES['SybilAttacker'] is SybilAttacker


def test_create_attacker_dispatches_sybil_with_params():
    att = create_attacker(7, {'type': 'sybil', 'active_since': 0.0,
                              'active_until': float('inf'),
                              'params': {'num_identities': 3, 'attachment': 'degree',
                                         'metric_fake': 0, 'drop_prob': 0.0,
                                         'controller_poisons': False}})
    assert isinstance(att, SybilAttacker) and isinstance(att, Attacker)
    assert att.node_id == 7
    assert att.num_identities == 3 and att.attachment == 'degree'
    assert att.metric_fake == 0 and att.drop_prob == 0.0
    assert att.controller_poisons is False
    assert att.active_until is None            # inf → None（常驻）
    assert att.sybil_node_ids == set()         # 待注入工具绑定


def test_create_attacker_sybil_defaults():
    att = create_attacker(1, {'type': 'SybilAttacker'})
    assert att.num_identities == 1
    assert att.attachment == 'betweenness'
    assert att.drop_prob == 0.0 and att.controller_poisons is False


def test_instantiate_attackers_sybil_from_config():
    edges = _ring(6, epochs=2)
    cfgs = [{'type': 'sybil', 'count': 2, 'placement': 'degree',
             'active_since': 0.0, 'active_until': float('inf'),
             'params': {'num_identities': 3, 'attachment': 'betweenness'}}]
    attackers = instantiate_attackers(cfgs, edges, seed=0, available_nodes=list(range(6)))
    assert len(attackers) == 2
    assert all(isinstance(a, SybilAttacker) for a in attackers)
    assert {a.node_id for a in attackers}.issubset(set(range(6)))
    assert all(a.num_identities == 3 and a.attachment == 'betweenness' for a in attackers)
    # 注入后每个受控物理节点各获得 3 个不重叠身份
    exp_edges, node_ids, injs = expand_topology_for_sybils(attackers, edges,
                                                          list(range(6)), seed=0)
    assert len(injs) == 2
    assert len(set(node_ids)) == 6 + 6
    assert max(node_ids) + 1 == 12
    assert not (attackers[0].sybil_node_ids & attackers[1].sybil_node_ids)


def test_sybil_coexists_with_other_attacker_types():
    edges = _ring(5, epochs=1)
    cfgs = [{'type': 'blackhole', 'count': 1, 'placement': 'degree',
             'params': {'drop_prob': 1.0, 'metric_fake': 0}},
            {'type': 'sybil', 'count': 1, 'placement': 'betweenness',
             'params': {'num_identities': 2, 'attachment': 'degree'}}]
    attackers = instantiate_attackers(cfgs, edges, seed=0, available_nodes=list(range(5)))
    assert sum(isinstance(a, BlackholeAttacker) for a in attackers) == 1
    assert sum(isinstance(a, SybilAttacker) for a in attackers) == 1
    exp_edges, node_ids, injs = expand_topology_for_sybils(attackers, edges,
                                                          list(range(5)), seed=0)
    assert len(injs) == 1 and node_ids == list(range(7))
    # 黑洞攻击者的 controls 语义未受 Sybil 注入影响
    bh = next(a for a in attackers if isinstance(a, BlackholeAttacker))
    assert bh.controls(bh.node_id) and not bh.controls(5) and not bh.controls(6)


# ==================== runner 接线（e3 / e2）与指标键 ====================

def _e3_config(attackers, name='e4_sybil_tiny', duration=60, num_flows=6):
    return {
        'experiment': {'name': name, 'duration': duration},
        'topology': {'shell': 'TEST', 'epoch_interval': 30, 'node_limit': None,
                     'cache_path': 'unused.pkl', 'positions_cache': None},
        'routing': {'t_adv': 2.0, 'tick': 1.0, 'max_hops': 20},
        'traffic': {'num_flows': num_flows},
        'attack': {'attackers': attackers},
        'output': {'raw_dir': 'unused', 'agg_dir': 'unused', 'figures_dir': 'unused'},
    }


def test_e3_runner_sybil_wiring_metrics_and_metadata():
    import run_e3_blackhole_experiment as e3

    edges = _ring(6, epochs=2)
    real = list(range(6))
    attackers_cfg = [{'type': 'sybil', 'count': 1, 'placement': 'degree',
                      'active_since': 0.0, 'active_until': float('inf'),
                      'params': {'num_identities': 2, 'attachment': 'betweenness',
                                 'metric_fake': 0, 'drop_prob': 0.0}}]
    rec = e3.run_experiment(42, _e3_config(attackers_cfg), copy.deepcopy(edges),
                            None, list(real))

    md = rec['metadata']
    assert md['sybil_injected'] is True
    assert md['sybil_num_identities'] == 2
    assert md['num_real_nodes'] == 6
    assert md['num_nodes'] == 8                # 节点空间已扩展
    # 匹配键字段（shell/node_limit/num_eval_epochs/num_flows）不受注入影响 → 仍与基线可比
    assert (md['shell'], md['node_limit'], md['num_eval_epochs'], md['num_flows']) == \
           ('TEST', None, 2, 6)

    ds = rec['data_stats']
    for key in SYBIL_METRIC_KEYS:
        assert key in ds
    assert ds['sybil_num_identities'] == 2
    assert 0.0 <= ds['sybil_attraction_ratio'] <= 1.0
    assert ds['sybil_attraction_ratio'] > 0.0     # Sybil 确实牵引到了流量
    assert ds['sybil_attracted_trials'] <= ds['num_trials']
    # 流端点仅用真实节点 → trials 基数不变
    assert ds['num_trials'] == 6 * 2

    sy = rec['sybil_stats']
    assert sy['num_identities'] == 2
    assert len(sy['sybil_node_ids']) == 2
    assert all(sid >= 6 for sid in sy['sybil_node_ids'])   # 身份 ID 在真实节点之后
    assert sy['total_trials'] == 12
    inj0 = sy['injections'][0]
    assert inj0['attachment'] == 'betweenness'
    assert inj0['num_identities'] == 2
    assert set(inj0['attachment_map']).issubset({str(s) for s in sy['sybil_node_ids']})
    assert all(v < 6 for v in inj0['attachment_map'].values())
    assert inj0['controller_node'] < 6


def test_e3_runner_baseline_has_no_sybil_keys():
    """纯附加验证：无 Sybil 臂的既有 e3 记录不含任何 sybil 键（不破坏旧 schema）。"""
    import run_e3_blackhole_experiment as e3

    rec = e3.run_experiment(42, _e3_config([], num_flows=4), copy.deepcopy(_ring(6, 2)),
                            None, list(range(6)))
    assert 'sybil_stats' not in rec
    assert 'sybil_injected' not in rec['metadata']
    assert all(k not in rec['data_stats'] for k in SYBIL_METRIC_KEYS)
    assert rec['metadata']['num_nodes'] == 6
    assert rec['data_stats']['num_trials'] == 4 * 2


def test_e2_runner_sybil_wiring_metrics_and_metadata():
    import run_e2_jamming_experiment as e2

    edges = _ring(6, epochs=2)
    config = _e3_config([{'type': 'sybil', 'count': 1, 'placement': 'degree',
                          'active_since': 0.0, 'active_until': float('inf'),
                          'params': {'num_identities': 2, 'attachment': 'degree'}}],
                        name='e4_sybil_e2_tiny', duration=60, num_flows=5)
    flow_pairs = e2.generate_flows(list(range(6)), 5, 42)
    assert all(s < 6 and d < 6 for s, d in flow_pairs)

    res = e2.run_experiment_with_topology(config, 42, copy.deepcopy(edges),
                                         [None, None], flow_pairs)
    assert res['metadata']['sybil_injected'] is True
    assert res['metadata']['sybil_num_identities'] == 2
    assert res['metadata']['num_real_nodes'] == 6
    assert res['metadata']['num_nodes'] == 8
    assert res['sybil_num_identities'] == 2
    assert 0.0 <= res['sybil_attraction_ratio'] <= 1.0
    # 平铺 schema 下额外提供只含 Sybil 键的 data_stats 块，供 T6 聚合提取
    assert set(res['data_stats']) == set(SYBIL_METRIC_KEYS)
    assert res['sybil_stats']['num_identities'] == 2
    assert res['num_trials'] == 5 * 2


def test_extract_metrics_and_aggregate_include_sybil_keys(tmp_path):
    """T6 统计框架兼容：Sybil 指标可被 extract_metrics / aggregate_experiment 聚合。"""
    import run_e3_blackhole_experiment as e3
    from starlink_sim.analytics import stats as st
    import run_experiment_sweep as sw

    attackers_cfg = [{'type': 'sybil', 'count': 1, 'placement': 'degree',
                      'params': {'num_identities': 1, 'attachment': 'betweenness'}}]
    files = []
    for seed in (42, 43):
        rec = e3.run_experiment(seed, _e3_config(attackers_cfg, num_flows=4),
                                copy.deepcopy(_ring(6, 2)), None, list(range(6)))
        m = st.extract_metrics(rec)
        for key in SYBIL_METRIC_KEYS:
            assert key in m
        p = tmp_path / f"e4_sybil_seed{seed}.json"
        p.write_text(json.dumps(rec), encoding='utf-8')
        files.append(p)

    # sweep 的聚合指标列表 = 默认指标 + Sybil 指标（纯附加）
    assert set(st.DEFAULT_METRICS).issubset(set(sw.SWEEP_METRICS))
    assert set(SYBIL_METRIC_KEYS).issubset(set(sw.SWEEP_METRICS))

    agg = st.aggregate_experiment([str(p) for p in files], metrics=sw.SWEEP_METRICS,
                                 n_boot=2000, alpha=0.05, rng=0)
    for key in SYBIL_METRIC_KEYS:
        assert key in agg['metrics']
        assert 'mean' in agg['metrics'][key]
    assert agg['metrics']['sybil_num_identities']['mean'] == pytest.approx(1.0)
    # 匹配键不含 num_nodes → 节点空间扩展不破坏与基线臂的可比性
    assert agg['cardinality']['match_key'] == {'shell': 'TEST', 'node_limit': None,
                                              'num_eval_epochs': 2, 'num_flows': 4}


def test_compare_sybil_arm_vs_baseline_still_comparable(tmp_path):
    """Sybil 臂（节点空间扩展）与同配置基线臂匹配键一致 → 可配对比较。"""
    import run_e3_blackhole_experiment as e3
    from starlink_sim.analytics import stats as st
    import run_experiment_sweep as sw

    atk_files, base_files = [], []
    for seed in (42, 43):
        atk = e3.run_experiment(seed, _e3_config([{'type': 'sybil', 'count': 1,
                                                  'placement': 'degree',
                                                  'params': {'num_identities': 2,
                                                             'attachment': 'degree'}}],
                                                num_flows=4),
                                copy.deepcopy(_ring(6, 2)), None, list(range(6)))
        base = e3.run_experiment(seed, _e3_config([], num_flows=4),
                                 copy.deepcopy(_ring(6, 2)), None, list(range(6)))
        pa = tmp_path / f"atk_seed{seed}.json"
        pb = tmp_path / f"base_seed{seed}.json"
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
    # Sybil 牵引造成环路/不可达 → 交付率不高于基线
    assert grp['comparisons']['delivery_ratio']['median_diff'] <= 0.0
