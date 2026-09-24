# tests/test_attack_injection.py
"""
Issue #2 回归测试：验证控制面攻击（黑洞 / 干扰）确实改写 DV 通告 ``entries``，
且被篡改通告会被接收端采纳、攻击窗口结束后恢复。

覆盖 DECISIONS/Issue 验收标准：
- 攻击窗口内通告条目确实变化；
- 邻居路由表接收被修改的度量；
- 窗口结束后通告恢复。
仅使用 routing_dv 与 attack，不依赖拓扑缓存，运行极快。
"""
import random

from starlink_sim.net.attack import BlackholeAttacker, JammingAttacker
from starlink_sim.net.routing_dv import DVMessage, DVRouter


def _metric_of(entries, dest):
    return {d: m for d, m, s in entries}[dest]


def _sample_message():
    return DVMessage(
        type="update", src=1, dst=-1, seq=1,
        visited=[1], entries=[(1, 0, 1), (2, 1, 1), (3, 5, 1)],
    )


def test_blackhole_modifies_entries_within_window():
    router = DVRouter(1)
    router.set_neighbors({2})
    bh = BlackholeAttacker(1, drop_prob=1.0, metric_fake=0, active_since=0, active_until=40)
    out = bh.modify_advertisement(_sample_message(), router, None, 30).entries
    # 到非自身目的地被伪造为 metric_fake=0（Issue #2 期望）
    assert _metric_of(out, 3) == 0
    assert _metric_of(out, 2) == 0
    # 保留到自身的条目
    assert _metric_of(out, 1) == 0
    assert out != _sample_message().entries


def test_blackhole_ignored_outside_window():
    router = DVRouter(1)
    router.set_neighbors({2})
    bh = BlackholeAttacker(1, drop_prob=1.0, metric_fake=0, active_since=0, active_until=40)
    original = _sample_message()
    out = bh.modify_advertisement(_sample_message(), router, None, 100)
    # 窗口外原样返回，通告恢复
    assert out.entries == original.entries


def test_jamming_raises_affected_neighbor_metric():
    router = DVRouter(1)
    router.set_neighbors({2})
    random.seed(0)
    jm = JammingAttacker(1, jamming_ratio=1.0, inf_metric=9999, active_since=0, active_until=40)
    out = jm.modify_advertisement(_sample_message(), router, None, 30).entries
    # 受影响邻居 2 被抬升为不可达度量（Issue #2 期望）
    assert _metric_of(out, 2) == 9999
    # 自身条目保留
    assert _metric_of(out, 1) == 0


def test_neighbor_adopts_poisoned_route():
    """被篡改通告（bump seq）必须被接收端路由表实际采纳。"""
    victim = DVRouter(2)
    victim.set_neighbors({1})  # 攻击者节点 1 是邻居
    bh = BlackholeAttacker(1, drop_prob=1.0, metric_fake=0, active_since=0, active_until=40)

    msg = DVMessage(type="update", src=1, dst=-1, seq=1, visited=[1],
                    entries=[(1, 0, 1), (3, 9, 1)])  # 攻击者谎称到 3 度量 9（先建立一个较差基线）
    victim._process_update(msg, current_time=1.0)
    assert victim.get_route(3).metric == 10  # 9 + 1

    # 攻击窗口内改写为 metric_fake=0 且 bump seq，接收端应采纳更低的度量
    poisoned = bh.modify_advertisement(
        DVMessage(type="update", src=1, dst=-1, seq=2, visited=[1], entries=[(1, 0, 1), (3, 9, 1)]),
        DVRouter(1), None, 30.0,
    )
    victim._process_update(poisoned, current_time=2.0)
    assert victim.get_route(3).metric == 1   # metric_fake(0) + 1
    assert victim.get_route(3).next_hop == 1  # 流量被吸引到攻击者


def test_blackhole_should_drop_is_pure_predicate():
    random.seed(0)
    bh = BlackholeAttacker(1, drop_prob=1.0, metric_fake=0, active_since=0, active_until=40)
    # 纯判定：活动窗口内按 drop_prob 丢弃；窗口外不丢弃
    assert bh.should_drop_data((0, 7), 30) is True
    assert bh.should_drop_data((0, 7), 100) is False
    # 关键回归：should_drop_data 不得自行累加计数
    # （计数由 DataPlane.evaluate_flows 统一维护，否则会与旧行为叠加造成双重统计）
    assert bh.attracted_count == 0
    assert bh.dropped_count == 0
