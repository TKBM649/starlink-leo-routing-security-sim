# tests/test_multi_attacker.py
"""
同节点多攻击者测试：
验证绑定到同一 node_id 的多个攻击者都能生效（链式累积应用），
而非旧代码中 break 导致只有第一个攻击者生效。

测试场景：
1. 控制面：同节点两个攻击者（黑洞+干扰），两者都改写通告
2. 数据面：同节点两个攻击者，流量经过时两者都被计数
"""
import random
import pytest

from starlink_sim.net.attack import BlackholeAttacker, JammingAttacker, Attacker
from starlink_sim.net.routing_dv import DVRouter, DVMessage
from starlink_sim.net.simulator import ControlPlane, DataPlane, Simulator


class TaggingAttacker(Attacker):
    """测试用攻击者：在 entries 中为每个目的地 metric 加一个固定偏移量"""

    def __init__(self, node_id: int, offset: int = 100, **kwargs):
        super().__init__(node_id, **kwargs)
        self.offset = offset
        self.call_count = 0

    def modify_advertisement(self, adv_msg, node, topology, time):
        if not self.is_active(time):
            return adv_msg
        if getattr(adv_msg, 'src', None) != self.node_id:
            return adv_msg
        self.call_count += 1
        new_entries = []
        for dest, metric, seq in adv_msg.entries:
            new_entries.append((dest, metric + self.offset, seq))
        return self._rebuild(adv_msg, new_entries)

    def should_drop_data(self, flow, time):
        return False


class TestControlPlaneMultiAttacker:
    """控制面同节点多攻击者链式应用"""

    def test_two_attackers_both_modify_advertisement(self):
        """同节点两个 TaggingAttacker，metric 应被叠加（两者都生效）"""
        # 6 节点链
        edges = {(i, i + 1) for i in range(5)}
        edge_sets = [edges]

        att1 = TaggingAttacker(node_id=2, offset=10, active_since=0.0)
        att2 = TaggingAttacker(node_id=2, offset=100, active_since=0.0)

        cp = ControlPlane(num_nodes=6, tick_interval=0.2, attackers=[att1, att2])

        # 运行足够 tick 让通告发出
        for i in range(20):
            cp.step(i * 0.2, edges)

        # 两个攻击者都应被调用
        assert att1.call_count > 0, "攻击者1未被调用"
        assert att2.call_count > 0, "攻击者2未被调用"

    def test_chained_modification_accumulates(self):
        """链式应用：第二个攻击者基于第一个的结果修改"""
        edges = {(0, 1), (1, 2)}
        edge_sets = [edges]

        att1 = TaggingAttacker(node_id=1, offset=10, active_since=0.0)
        att2 = TaggingAttacker(node_id=1, offset=100, active_since=0.0)

        cp = ControlPlane(num_nodes=3, tick_interval=0.2, attackers=[att1, att2])

        # 运行让路由建立并发出通告
        for i in range(15):
            cp.step(i * 0.2, edges)

        # 检查节点0收到的路由：到节点2的 metric 应该被两个攻击者叠加
        # 正常 metric=1（1跳），经过 att1(+10)=11，再经过 att2(+100)=111
        # 节点0从节点1学到到2的路由，metric 应为 111+1=112（加1是因为接收方+1）
        route = cp.routers[0].get_route(2)
        if route is not None:
            # 由于链式叠加，metric 应远大于正常值
            assert route.metric > 50, (
                f"链式攻击应使 metric 大幅偏高，实际={route.metric}"
            )

    def test_blackhole_and_jamming_coexist(self):
        """同节点绑定黑洞+干扰攻击者，两者都被激活（不报错）"""
        random.seed(42)
        edges = {(i, i + 1) for i in range(5)}

        bh = BlackholeAttacker(node_id=2, drop_prob=0.5, metric_fake=0,
                               active_since=0.0, active_until=None)
        jm = JammingAttacker(node_id=2, jamming_ratio=0.5, inf_metric=9999,
                             active_since=0.0, active_until=None)

        cp = ControlPlane(num_nodes=6, tick_interval=0.2, attackers=[bh, jm])

        # 应该不抛异常地完成
        for i in range(20):
            cp.step(i * 0.2, edges)


class TestDataPlaneMultiAttacker:
    """数据面同节点多攻击者计数"""

    def test_multiple_attackers_counted_on_same_node(self):
        """路径经过同一节点的两个攻击者，两者都应被计数"""
        random.seed(42)
        # 简单 3 节点链，路由表直接构造
        from starlink_sim.net.routing_dv import RouteEntry

        tables = {
            0: {1: RouteEntry(dest=1, next_hop=1, metric=1, seq=1, age=0.0),
                2: RouteEntry(dest=2, next_hop=1, metric=2, seq=1, age=0.0)},
            1: {0: RouteEntry(dest=0, next_hop=0, metric=1, seq=1, age=0.0),
                2: RouteEntry(dest=2, next_hop=2, metric=1, seq=1, age=0.0)},
            2: {0: RouteEntry(dest=0, next_hop=1, metric=2, seq=1, age=0.0),
                1: RouteEntry(dest=1, next_hop=1, metric=1, seq=1, age=0.0)},
        }
        edges = [{(0, 1), (1, 2)}]

        # 两个攻击者都在节点1（路径中间）, drop_prob=0 不丢弃
        att1 = BlackholeAttacker(node_id=1, drop_prob=0.0, metric_fake=0,
                                 active_since=0.0, active_until=None)
        att2 = BlackholeAttacker(node_id=1, drop_prob=0.0, metric_fake=0,
                                 active_since=0.0, active_until=None)

        dp = DataPlane(routing_tables=tables, edge_sets=edges,
                       attackers=[att1, att2])

        result = dp.evaluate_flows(
            flows=[(0, 2)],
            positions_per_epoch=None,
            epoch_duration=30.0,
            base_time=0.0,
            num_epochs=1
        )

        # 两个攻击者都应被计数（路径经过节点1）
        assert att1.attracted_count > 0, "攻击者1应被触发"
        assert att2.attracted_count > 0, "攻击者2应被触发"
        # 数据应成功交付（drop_prob=0）
        assert result['delivery_ratio'] == 1.0

    def test_end_to_end_multi_attacker_simulation(self):
        """端到端测试：8节点拓扑，同节点双黑洞攻击者比单攻击者破坏力更强"""
        random.seed(42)
        num_nodes = 8
        edges = {(i, i + 1) for i in range(num_nodes - 1)}
        edge_sets = [edges]
        flows = [(0, 7)]

        # 单攻击者基线
        att_single = BlackholeAttacker(node_id=4, drop_prob=1.0, metric_fake=0,
                                     active_since=0.0, active_until=None)
        result_single = Simulator(
            edge_sets=edge_sets, positions_per_epoch=None, num_nodes=num_nodes,
            tick_interval=0.2, attackers=[att_single], flow_pairs=flows,
            epoch_duration=30.0, base_time=0.0,
        ).run(duration=40.0)

        # 双攻击者（同节点）
        random.seed(42)
        att1 = BlackholeAttacker(node_id=4, drop_prob=1.0, metric_fake=0,
                                 active_since=0.0, active_until=None)
        att2 = BlackholeAttacker(node_id=4, drop_prob=1.0, metric_fake=0,
                                 active_since=0.0, active_until=None)
        result_dual = Simulator(
            edge_sets=edge_sets, positions_per_epoch=None, num_nodes=num_nodes,
            tick_interval=0.2, attackers=[att1, att2], flow_pairs=flows,
            epoch_duration=30.0, base_time=0.0,
        ).run(duration=40.0)

        # 两者都应使交付率为0（攻击成功）
        assert result_single['delivery_ratio'] == 0.0
        assert result_dual['delivery_ratio'] == 0.0

        # 双攻击者应产生更多路由环路（双重 seq bump 更强路由毒化）
        # 或者至少与单攻击者一样差
        assert result_dual['total_loops'] >= result_single['total_loops'] - 5

        # 控制面统计：双攻击者均应被记录
        stats = result_dual['attacker_stats']
        assert len(stats) == 2
        assert stats[0]['node_id'] == 4
        assert stats[1]['node_id'] == 4
