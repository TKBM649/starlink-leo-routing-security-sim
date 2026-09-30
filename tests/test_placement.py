# tests/test_placement.py
"""
统一攻击者放置模块（``starlink_sim.net.placement``）单元测试。

覆盖：
- 五种放置策略（degree / random / betweenness / k_core / last_epoch_degree）均返回
  ``count`` 个**确实存在于拓扑**的合法节点；
- betweenness / k_core 用 networkx 正确计算（在已知图上验证选中的是高介数/高核数节点）；
- degree 默认策略与既有 runner 逐位一致（累计度降序）；
- 攻击者实例化（类型映射、node_id 显式指定、active_until=inf→None）；
- 边界：count<=0、count>可用节点数、非法策略、available_nodes 过滤。

纯合成小图，秒级，不碰真实拓扑。
"""
import random

import pytest

from starlink_sim.net.placement import (
    ATTACKER_CLASSES,
    PLACEMENT_STRATEGIES,
    cumulative_degree,
    all_nodes,
    select_attackers,
    create_attacker,
    instantiate_attackers,
)
from starlink_sim.net.attack import BlackholeAttacker, JammingAttacker, SybilAttacker


def _path_graph(n=5):
    """单 epoch 路径图 0-1-2-...-(n-1)。介数中心性以中间节点最高。"""
    return [{(i, i + 1) for i in range(n - 1)}]


def _clique_plus_pendants():
    """4-团 {0,1,2,3}（核数 3）+ 两个挂点 4,5（接到 0，核数 1）。"""
    clique = {(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)}
    pendants = {(0, 4), (0, 5)}
    return [clique | pendants]


def _two_epoch_degree_shift():
    """epoch0 以 0 为中心（星），epoch1 以 5 为中心（星）→ 检验 last_epoch_degree。"""
    epoch0 = {(0, 1), (0, 2), (0, 3)}
    epoch1 = {(5, 6), (5, 7), (5, 8)}
    return [epoch0, epoch1]


# ==================== 通用契约：所有策略返回合法存在节点 ====================

@pytest.mark.parametrize("strategy", list(PLACEMENT_STRATEGIES))
def test_every_strategy_returns_valid_existing_nodes(strategy):
    g = _clique_plus_pendants()
    present = all_nodes(g)
    rng = random.Random(123)
    chosen = select_attackers(g, 3, strategy=strategy, rng=rng)
    assert len(chosen) == 3
    assert len(set(chosen)) == 3            # 不重复
    assert set(chosen).issubset(present)    # 全部落在拓扑内


@pytest.mark.parametrize("strategy", list(PLACEMENT_STRATEGIES))
def test_every_strategy_deterministic_with_same_seed(strategy):
    g = _clique_plus_pendants()
    a = select_attackers(g, 3, strategy=strategy, rng=random.Random(7))
    b = select_attackers(g, 3, strategy=strategy, rng=random.Random(7))
    assert a == b


# ==================== degree（默认，累计度） ====================

def test_degree_picks_highest_cumulative_degree():
    g = _two_epoch_degree_shift()
    # 累计度：0→3, 5→3, 其余→1；稳定排序下 0 先于 5（插入顺序）
    chosen = select_attackers(g, 1, strategy='degree')
    assert chosen == [0]
    chosen2 = select_attackers(g, 2, strategy='degree')
    assert set(chosen2) == {0, 5}


def test_degree_is_default_strategy():
    g = _clique_plus_pendants()
    assert select_attackers(g, 2) == select_attackers(g, 2, strategy='degree')


# ==================== last_epoch_degree ====================

def test_last_epoch_degree_uses_only_last_epoch():
    g = _two_epoch_degree_shift()
    # 最后一个 epoch 以 5 为中心 → 度最高的是 5
    chosen = select_attackers(g, 1, strategy='last_epoch_degree')
    assert chosen == [5]


# ==================== random ====================

def test_random_respects_rng_and_validity():
    g = _path_graph(8)
    present = all_nodes(g)
    a = select_attackers(g, 3, strategy='random', rng=random.Random(1))
    b = select_attackers(g, 3, strategy='random', rng=random.Random(2))
    assert set(a).issubset(present) and set(b).issubset(present)
    # 不同种子（大概率）给出不同选择；即便相同也都合法
    assert len(a) == len(b) == 3


# ==================== betweenness（networkx） ====================

def test_betweenness_picks_center_of_path():
    nx = pytest.importorskip("networkx")
    g = _path_graph(5)  # 0-1-2-3-4，中心节点 2 介数最高
    bc = nx.betweenness_centrality(nx.path_graph(5))
    center = max(bc, key=lambda n: (bc[n], -n))
    chosen = select_attackers(g, 1, strategy='betweenness')
    assert chosen == [center]
    assert center == 2


def test_betweenness_top_k_are_high_centrality():
    nx = pytest.importorskip("networkx")
    g = _path_graph(7)
    bc = nx.betweenness_centrality(nx.path_graph(7))
    order = sorted(bc, key=lambda n: (-bc[n], n))
    chosen = select_attackers(g, 3, strategy='betweenness')
    assert chosen == order[:3]


# ==================== k_core（networkx） ====================

def test_k_core_picks_clique_nodes():
    nx = pytest.importorskip("networkx")
    g = _clique_plus_pendants()
    G = nx.Graph()
    G.add_edges_from(g[0])
    core = nx.core_number(G)
    # 团内节点核数为 3，挂点为 1
    assert core[0] == core[1] == core[2] == core[3] == 3
    assert core[4] == core[5] == 1
    chosen = select_attackers(g, 3, strategy='k_core')
    # 选中的必须是高核数的团内节点（绝不含挂点 4,5）
    assert set(chosen).issubset({0, 1, 2, 3})
    assert len(chosen) == 3


# ==================== 边界 ====================

def test_count_non_positive_returns_empty():
    g = _path_graph(5)
    assert select_attackers(g, 0) == []
    assert select_attackers(g, -3) == []
    assert select_attackers(g, None) == []


def test_count_exceeds_available_returns_all_present():
    g = _path_graph(4)  # 只有 4 个节点
    for strategy in ('degree', 'random', 'betweenness', 'k_core', 'last_epoch_degree'):
        chosen = select_attackers(g, 99, strategy=strategy, rng=random.Random(0))
        assert set(chosen).issubset(all_nodes(g))
        assert len(chosen) <= 4


def test_invalid_strategy_raises():
    g = _path_graph(4)
    with pytest.raises(ValueError):
        select_attackers(g, 2, strategy='not_a_strategy')


def test_available_nodes_filters_to_present():
    g = _path_graph(6)  # 节点 0..5
    # available_nodes 含拓扑外节点（99）与拓扑内节点；只应返回拓扑内的
    chosen = select_attackers(g, 3, strategy='random', rng=random.Random(0),
                              available_nodes=[1, 3, 5, 99])
    assert set(chosen).issubset({1, 3, 5})


def test_empty_graph_returns_empty():
    assert select_attackers([], 3) == []
    assert select_attackers([set()], 3, strategy='degree') == []


# ==================== 攻击者实例化 ====================

def test_create_attacker_types_and_inf_normalization():
    bh = create_attacker(4, {'type': 'blackhole', 'active_since': 0.0,
                             'active_until': float('inf'),
                             'params': {'drop_prob': 0.8, 'metric_fake': 0}})
    assert isinstance(bh, BlackholeAttacker)
    assert bh.node_id == 4 and bh.drop_prob == 0.8
    assert bh.active_until is None  # inf → None（常驻）

    jam = create_attacker(2, {'type': 'jamming', 'params': {'jamming_ratio': 0.5}})
    assert isinstance(jam, JammingAttacker) and jam.node_id == 2

    syb = create_attacker(9, {'type': 'sybil'})
    assert isinstance(syb, SybilAttacker) and syb.node_id == 9


def test_create_attacker_unknown_type_raises():
    with pytest.raises(ValueError):
        create_attacker(1, {'type': 'not_an_attacker'})


def test_attacker_classes_aliases():
    assert ATTACKER_CLASSES['blackhole'] is BlackholeAttacker
    assert ATTACKER_CLASSES['BlackholeAttacker'] is BlackholeAttacker
    assert ATTACKER_CLASSES['jamming'] is JammingAttacker


def test_instantiate_attackers_count_and_placement():
    g = _two_epoch_degree_shift()
    cfgs = [{'type': 'blackhole', 'count': 2, 'placement': 'degree',
             'active_since': 0.0, 'active_until': float('inf'),
             'params': {'drop_prob': 1.0, 'metric_fake': 0}}]
    attackers = instantiate_attackers(cfgs, g, seed=0, available_nodes=sorted(all_nodes(g)))
    assert len(attackers) == 2
    assert all(isinstance(a, BlackholeAttacker) for a in attackers)
    # degree 策略 → 累计度最高的 {0,5}
    assert {a.node_id for a in attackers} == {0, 5}
    assert all(a.active_until is None for a in attackers)


def test_instantiate_attackers_explicit_node_id():
    g = _path_graph(5)
    cfgs = [{'type': 'blackhole', 'count': 1, 'node_id': 3,
             'params': {'drop_prob': 0.5}}]
    attackers = instantiate_attackers(cfgs, g, seed=0)
    assert len(attackers) == 1 and attackers[0].node_id == 3


def test_instantiate_attackers_skips_nonpositive_count():
    g = _path_graph(5)
    cfgs = [{'type': 'blackhole', 'count': 0, 'params': {}},
            {'type': 'jamming', 'count': None, 'params': {}}]
    assert instantiate_attackers(cfgs, g, seed=0) == []


def test_instantiate_attackers_reproducible_across_calls():
    g = _clique_plus_pendants()
    cfgs = [{'type': 'blackhole', 'count': 3, 'placement': 'random', 'params': {}}]
    a = [x.node_id for x in instantiate_attackers(cfgs, g, seed=42)]
    b = [x.node_id for x in instantiate_attackers(cfgs, g, seed=42)]
    assert a == b
