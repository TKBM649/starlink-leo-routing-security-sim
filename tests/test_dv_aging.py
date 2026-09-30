# tests/test_dv_aging.py
"""
DV 路由老化 + 触发更新测试：
1. 邻居消失后指向它的坏路由被清除
2. 路由老化超时后自动失效
3. 触发更新在拓扑变化时立即发生（而非等待周期广告）
"""
import pytest
from starlink_sim.net.routing_dv import DVRouter, DVMessage, RouteEntry
from starlink_sim.net.simulator import ControlPlane


class TestRouteAging:
    """路由老化机制测试"""

    def test_expired_route_removed(self):
        """超过 aging_timeout 未刷新的路由应被自动删除"""
        router = DVRouter(node_id=0, tick_interval=0.2, adv_interval=2.0,
                          aging_timeout=3.0)
        router.set_neighbors({1})

        # 注入一条路由（age=0.0）
        msg = DVMessage(type='update', src=1, dst=-1, seq=1,
                        visited=[1], entries=[(1, 0, 1), (2, 1, 1)])
        router._process_update(msg, current_time=0.0)
        assert router.get_route(2) is not None

        # 推进时间到超过 aging_timeout (3.0s) 但不刷新该路由
        # tick 在 time=4.0 时检查老化
        router.process_tick(current_time=4.0, received_msgs=[])
        # 路由应已被老化删除
        assert router.get_route(2) is None

    def test_refreshed_route_not_expired(self):
        """在 aging_timeout 内被刷新的路由不应被删除"""
        router = DVRouter(node_id=0, tick_interval=0.2, adv_interval=2.0,
                          aging_timeout=3.0)
        router.set_neighbors({1})

        # 初始路由
        msg = DVMessage(type='update', src=1, dst=-1, seq=1,
                        visited=[1], entries=[(1, 0, 1), (2, 1, 1)])
        router._process_update(msg, current_time=0.0)

        # 在 time=2.0 时刷新（seq 更高）
        msg2 = DVMessage(type='update', src=1, dst=-1, seq=2,
                         visited=[1], entries=[(1, 0, 2), (2, 1, 2)])
        router._process_update(msg2, current_time=2.0)

        # time=4.0: 距上次刷新只过了 2s < aging_timeout=3s，不应过期
        router.process_tick(current_time=4.0, received_msgs=[])
        assert router.get_route(2) is not None
        assert router.get_route(2).age == 2.0

    def test_aging_triggers_update(self):
        """路由老化失效应触发更新通知邻居"""
        router = DVRouter(node_id=0, tick_interval=0.2, adv_interval=2.0,
                          aging_timeout=1.0)
        router.set_neighbors({1})

        # 注入路由
        msg = DVMessage(type='update', src=1, dst=-1, seq=1,
                        visited=[1], entries=[(1, 0, 1), (2, 1, 1)])
        router._process_update(msg, current_time=0.0)

        # tick 到超时后，process_tick 应该产生触发更新报文
        outgoing = router.process_tick(current_time=2.0, received_msgs=[])
        # 应发出触发更新（路由失效 + trigger_update 标志）
        assert len(outgoing) >= 1
        assert router.triggered_updates_sent >= 1


class TestNeighborPurge:
    """邻居消失后路由清除测试"""

    def test_purge_neighbor_routes(self):
        """purge_neighbor_routes 应清除所有 next_hop 指向该邻居的条目"""
        router = DVRouter(node_id=0, tick_interval=0.2, adv_interval=2.0)
        router.set_neighbors({1, 2})

        # 通过邻居1学到路由到 dest=3, dest=4
        msg = DVMessage(type='update', src=1, dst=-1, seq=1,
                        visited=[1], entries=[(1, 0, 1), (3, 2, 1), (4, 3, 1)])
        router._process_update(msg, current_time=0.0)
        assert router.get_route(3) is not None
        assert router.get_route(4) is not None
        assert router.get_route(3).next_hop == 1

        # 邻居1消失
        router.purge_neighbor_routes(1)
        assert router.get_route(3) is None
        assert router.get_route(4) is None
        assert router.trigger_update is True

    def test_control_plane_purges_on_neighbor_loss(self):
        """ControlPlane.update_neighbors 在邻居消失时自动清除坏路由"""
        # 3节点链：0 - 1 - 2
        cp = ControlPlane(num_nodes=3, tick_interval=0.2)
        edges_full = {(0, 1), (1, 2)}
        cp.update_neighbors(edges_full)

        # 跑几个 tick 让路由收敛
        for i in range(15):
            cp.step(i * 0.2, edges_full)

        # 节点0应该学到了到节点2的路由（via 1）
        route_to_2 = cp.routers[0].get_route(2)
        assert route_to_2 is not None
        assert route_to_2.next_hop == 1

        # 断开 0-1 链路
        edges_broken = {(1, 2)}
        cp.update_neighbors(edges_broken)

        # 节点0的路由到节点2应被清除（next_hop=1已不可达）
        assert cp.routers[0].get_route(2) is None


class TestTriggeredUpdate:
    """触发更新机制测试"""

    def test_neighbor_change_triggers_immediate_advertisement(self):
        """邻居集变化时应立即触发通告，不等待 adv_interval"""
        cp = ControlPlane(num_nodes=4, tick_interval=0.2)
        edges = {(0, 1), (1, 2), (2, 3)}

        # 初始运行一步建立邻居
        cp.step(0.0, edges)

        # 确认 router 0 的 trigger_update 在邻居变化后被置位
        # 先跑足够 tick 让初始触发消耗掉
        for i in range(1, 5):
            cp.step(i * 0.2, edges)

        # 重置计数
        cp.routers[0].triggered_updates_sent = 0

        # 新增邻居 0-3
        edges_new = {(0, 1), (1, 2), (2, 3), (0, 3)}
        # 下一个 tick 应该触发更新
        cp.step(1.0, edges_new)
        # 邻居变化 → 触发更新 → triggered_updates_sent 增加
        assert cp.routers[0].triggered_updates_sent >= 1

    def test_triggered_update_faster_than_periodic(self):
        """触发更新比周期广告更快响应拓扑变化"""
        router = DVRouter(node_id=0, tick_interval=0.2, adv_interval=10.0,
                          aging_timeout=30.0)
        router.set_neighbors({1})

        # 先收到一条路由
        msg = DVMessage(type='update', src=1, dst=-1, seq=1,
                        visited=[1], entries=[(1, 0, 1), (2, 1, 1)])
        router._process_update(msg, current_time=0.0)
        router.trigger_update = False  # 清除初始触发

        # 邻居变化
        router.set_neighbors({1, 2})
        assert router.trigger_update is True

        # 下一 tick（0.2s）就应该发出通告，远小于 adv_interval=10s
        outgoing = router.process_tick(current_time=0.2, received_msgs=[])
        assert len(outgoing) == 1
        assert router.triggered_updates_sent == 1
