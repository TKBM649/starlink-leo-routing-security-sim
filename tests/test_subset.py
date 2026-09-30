# tests/test_subset.py
"""
跨 epoch 连通子集（``starlink_sim.topology.subset``）单元测试。

核心验收：在合成动态图上证明 ``select_connected_subset`` 的逐 epoch 连通性
**严格优于** 既有 epoch-0 BFS（``epoch0_bfs``）。合成图设计：

- 稳定核：节点 0..7，在所有 epoch 都构成路径 0-1-...-7（逐 epoch 连通）。
- 瞬时节点：8,9,10,11，仅在 epoch-0 挂到核上（靠近节点 0），epoch-1/2 完全孤立。

epoch-0 BFS 从节点 0 出发会优先抓到瞬时节 8,9,10,11（挤掉核心节点 4,5,6,7），
导致后续 epoch 诱导子图碎裂（最大连通分量占比跌到 0.5）；而累计度/稳定核方法
选中整段稳定核 {0..7}，逐 epoch 占比恒为 1.0。全部秒级、纯合成、不碰真实拓扑。
"""
import pytest

from starlink_sim.topology.subset import (
    SUBSET_METHODS,
    cumulative_degree,
    all_nodes,
    edge_persistence,
    persistent_core,
    epoch0_bfs,
    max_connected_component_ratio,
    evaluate_subset_connectivity,
    filter_edges_to_subset,
    select_connected_subset,
)


def _dynamic_graph():
    """稳定核 0..7（逐 epoch 路径）+ 瞬时节点 8..11（仅 epoch-0 挂靠）。"""
    core = {(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)}
    ephemeral = {(0, 8), (8, 10), (0, 9), (9, 11)}
    epoch0 = core | ephemeral
    epoch1 = set(core)
    epoch2 = set(core)
    return [epoch0, epoch1, epoch2]


TARGET = 8


# ==================== 基础工具 ====================

def test_all_nodes_and_cumulative_degree():
    g = _dynamic_graph()
    nodes = all_nodes(g)
    assert nodes == set(range(12))
    deg = cumulative_degree(g)
    # 节点 1..6 在三个 epoch 都是路径内部点（每 epoch 度 2）→ 累计 6
    assert deg[1] == deg[2] == deg[3] == deg[4] == deg[5] == deg[6] == 6
    # 节点 0：epoch0 度 3（1,8,9）+ epoch1/2 各度 1 → 5
    assert deg[0] == 5
    # 瞬时节点只在 epoch0 出现
    assert deg[8] == 2 and deg[10] == 1 and deg[11] == 1


def test_max_connected_component_ratio_denominator_is_full_subset():
    # 分母必须是 |subset|：孤立/脱离节点应拉低比例（对齐 T7 "~42% 在最大连通分量" 口径）
    edges = {(0, 1), (1, 2)}
    subset = [0, 1, 2, 3, 4]  # 3,4 无边 → 孤立
    # 最大连通分量 {0,1,2} 占 5 个被选节点的 3/5
    assert max_connected_component_ratio(edges, subset) == pytest.approx(3 / 5)
    assert max_connected_component_ratio(edges, []) == 0.0
    assert max_connected_component_ratio([], [0, 1]) == 0.0


def test_filter_edges_to_subset():
    g = _dynamic_graph()
    sub = [0, 1, 2, 3, 4, 5, 6, 7]
    filtered = filter_edges_to_subset(g, sub)
    # 瞬时边 (0,8) 等被剔除；每个 epoch 只剩核内边
    assert all((0, 8) not in e and (8, 10) not in e for e in filtered)
    assert filtered[1] == {(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)}


# ==================== epoch-0 BFS 的缺陷 ====================

def test_epoch0_bfs_grabs_ephemeral_nodes():
    g = _dynamic_graph()
    bfs = epoch0_bfs(g, TARGET)
    assert len(bfs) == TARGET
    # BFS 从 0 出发先抓到瞬时节点 8,9,10,11，挤掉核心 4,5,6,7
    assert set(bfs) == {0, 1, 2, 3, 8, 9, 10, 11}
    conn = evaluate_subset_connectivity(g, bfs)
    # epoch0 全连通（1.0），epoch1/2 仅剩 {0,1,2,3} 连通、瞬时节点孤立 → 0.5
    assert conn['per_epoch_ratio'][0] == pytest.approx(1.0)
    assert conn['min_ratio'] == pytest.approx(0.5)
    assert conn['mean_ratio'] == pytest.approx((1.0 + 0.5 + 0.5) / 3)


# ==================== 跨 epoch 连通子集优于 BFS ====================

@pytest.mark.parametrize("method", list(SUBSET_METHODS))
def test_select_connected_subset_beats_epoch0_bfs(method):
    g = _dynamic_graph()
    bfs = epoch0_bfs(g, TARGET)
    sub = select_connected_subset(g, TARGET, method=method)

    assert len(sub) == TARGET
    assert set(sub).issubset(all_nodes(g))

    bfs_conn = evaluate_subset_connectivity(g, bfs)
    sub_conn = evaluate_subset_connectivity(g, sub)

    # 逐 epoch 连通性严格优于 epoch-0 BFS（min 与 mean 都不劣，且 min 严格更优）
    assert sub_conn['min_ratio'] > bfs_conn['min_ratio']
    assert sub_conn['mean_ratio'] >= bfs_conn['mean_ratio']


def test_cumulative_degree_selects_stable_core_perfectly_connected():
    g = _dynamic_graph()
    sub = select_connected_subset(g, TARGET, method='cumulative_degree')
    # 恰好选中整段稳定核 {0..7}
    assert set(sub) == set(range(8))
    conn = evaluate_subset_connectivity(g, sub)
    # 每个 epoch 诱导子图都是连通路径 → 占比恒为 1.0
    assert conn['min_ratio'] == pytest.approx(1.0)
    assert conn['mean_ratio'] == pytest.approx(1.0)
    assert conn['num_epochs'] == 3


def test_stable_core_also_perfect():
    g = _dynamic_graph()
    sub = select_connected_subset(g, TARGET, method='stable_core')
    conn = evaluate_subset_connectivity(g, sub)
    assert conn['min_ratio'] == pytest.approx(1.0)


# ==================== 持久核机制（本模块的核心修复） ====================

def test_edge_persistence_counts_epochs():
    g = _dynamic_graph()
    persist = edge_persistence(g)
    # 核路径边出现在全部 3 个 epoch
    assert persist[(0, 1)] == 3 and persist[(6, 7)] == 3
    # 瞬时边只出现在 epoch0
    assert persist[(0, 8)] == 1 and persist[(8, 10)] == 1
    # 无向规范化：(1,0) 与 (0,1) 同键
    assert (0, 1) in persist and (1, 0) not in persist


def test_persistent_core_is_the_all_epoch_connected_core():
    g = _dynamic_graph()
    core, adj, frac = persistent_core(g, target_size=TARGET)
    # 最严格阈值（边存在于全部 epoch）即可满足 target → frac=1.0
    assert frac == 1.0
    # 稳定核恰为逐 epoch 都存在的路径核 {0..7}，不含瞬时节点
    assert core == set(range(8))
    assert adj[0] == {1} and adj[3] == {2, 4}


def test_greedy_growth_below_core_size_stays_connected():
    g = _dynamic_graph()
    # target < 稳定核(8) → 触发核内连通贪心生长
    for k in (3, 5, 7):
        sub = select_connected_subset(g, k, method='cumulative_degree')
        assert len(sub) == k
        conn = evaluate_subset_connectivity(g, sub)
        # 生长出的子集诱导持久路径 → 逐 epoch 全连通
        assert conn['min_ratio'] == pytest.approx(1.0), f"k={k} 碎裂: {conn}"


def test_rejects_high_degree_ephemeral_hub():
    """真实 LEO 的关键陷阱：高度数但**瞬时**的枢纽节点必须被持久核排除。

    朴素"累计度 top-K"会选中只在 epoch0 出现的高度数 hub（后续 epoch 它孤立 →
    子图碎裂）；本模块的稳定核只用持久边，故排除该 hub，逐 epoch 占比恒为 1.0。
    """
    core = {(0, 1), (1, 2), (2, 3), (3, 4)}          # 持久路径，3 个 epoch 都在
    hub_edges = {(10, 0), (10, 1), (10, 2), (10, 3), (10, 4)}  # 瞬时 hub（仅 epoch0）
    g = [core | hub_edges, set(core), set(core)]

    deg = cumulative_degree(g)
    # hub 节点 10 累计度=5，高于端点 0/4（=3）→ 朴素 top-5 会误选它
    naive_top5 = {n for n, _ in sorted(deg.items(), key=lambda x: (-x[1], x[0]))[:5]}
    assert 10 in naive_top5

    sub = select_connected_subset(g, 5, method='cumulative_degree')
    assert 10 not in sub                 # 持久核排除瞬时 hub
    assert set(sub) == {0, 1, 2, 3, 4}   # 选中整段持久路径核
    conn = evaluate_subset_connectivity(g, sub)
    assert conn['min_ratio'] == pytest.approx(1.0)
    # 对照：朴素 top-5 在 epoch1/2 因 hub 孤立而碎裂
    naive_conn = evaluate_subset_connectivity(g, sorted(naive_top5))
    assert naive_conn['min_ratio'] < 1.0


# ==================== 边界与参数 ====================

def test_target_size_none_returns_all():
    g = _dynamic_graph()
    assert select_connected_subset(g, None) == sorted(range(12))


def test_target_size_ge_full_returns_all():
    g = _dynamic_graph()
    assert select_connected_subset(g, 999) == sorted(range(12))
    assert select_connected_subset(g, 12) == sorted(range(12))


def test_target_size_non_positive_returns_empty():
    g = _dynamic_graph()
    assert select_connected_subset(g, 0) == []
    assert select_connected_subset(g, -5) == []


def test_invalid_method_raises():
    g = _dynamic_graph()
    with pytest.raises(ValueError):
        select_connected_subset(g, 4, method='not_a_method')


def test_empty_graph():
    assert select_connected_subset([], 5) == []
    assert epoch0_bfs([], 5) == []
    assert all_nodes([]) == set()
