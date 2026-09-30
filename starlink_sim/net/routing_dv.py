# starlink_sim/net/routing_dv.py
import time
import heapq
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
import random

@dataclass
class RouteEntry:
    dest: int           # 目标节点ID
    next_hop: int       # 下一跳节点ID
    metric: int         # 跳数
    seq: int            # 序列号（用于防旧）
    age: float          # 最后更新时间（秒，相对于仿真开始）
    flags: Set[str] = field(default_factory=set)  # 例如 "stale", "poisoned"
    path: List[int] = field(default_factory=list)  # 路径矢量：路由信息传播经过的节点序列

class DVMessage:
    """
    报文格式
    type: 'hello' 或 'update'
    src: 源节点ID
    dst: 目标节点ID（单播或广播）
    seq: 消息序列号（由源节点递增）
    visited: List[int]   # 已经过的节点路径（用于环路检测）
    entries: List[Tuple[dest, metric, seq]]  # 路由通告
    """
    __slots__ = ('type', 'src', 'dst', 'seq', 'visited', 'entries')
    def __init__(self, type: str, src: int, dst: int, seq: int,
                 visited: Optional[List[int]] = None,
                 entries: Optional[List[Tuple[int, int, int]]] = None):
        self.type = type
        self.src = src
        self.dst = dst
        self.seq = seq
        self.visited = visited if visited is not None else []
        self.entries = entries if entries is not None else []

class DVRouter:
    """
    DV 路由协议实例，运行在一个节点上。
    需要外部注入：
        - node_id: 自身ID
        - tick_callback: 每个tick调用，用于发送报文
        - neighbors: 当前活跃邻居列表（由拓扑提供）
    """
    def __init__(self, node_id: int, tick_interval: float = 0.2, adv_interval: float = 2.0,
                 aging_timeout: Optional[float] = None):
        self.node_id = node_id
        self.tick_interval = tick_interval   # 200ms
        self.adv_interval = adv_interval     # 2s
        # 老化超时：默认 3 倍广告周期（6s），超时未刷新的路由失效删除
        self.aging_timeout = aging_timeout if aging_timeout is not None else 3.0 * adv_interval
        self.routing_table: Dict[int, RouteEntry] = {}  # dest -> RouteEntry
        self.sequences: Dict[int, int] = {}  # 每目的地的序列号（用于邻居排序）
        self.neighbors: Set[int] = set()     # 当前邻居列表（由外部更新）
        self.msg_seq = 0
        self.hello_seq = 0
        self.adv_timer = 0.0                 # 累计时间，触发广告
        self.tick_counter = 0
        # 触发更新标志：邻居变化/路由失效时置位，下一 tick 立即发送通告
        self.trigger_update = False
        # 统计
        self.loops_detected: List[List[int]] = []  # 检测到的环路路径
        self.updates_sent = 0
        self.updates_received = 0
        self.triggered_updates_sent = 0  # 触发更新计数
        # 用于收敛检测
        self.last_change_tick = 0
        self.stable_since = None
        self.converged = False

    def set_neighbors(self, neighbors: Set[int]):
        """更新邻居集合（由拓扑通知），检测变化并触发更新"""
        old_neighbors = self.neighbors
        self.neighbors = neighbors
        # 邻居集变化时触发更新
        if old_neighbors != neighbors:
            self.trigger_update = True

    def process_tick(self, current_time: float, received_msgs: List[DVMessage]) -> List[DVMessage]:
        """
        在一个 tick 内处理收到的消息，返回本 tick 要发出的消息（列表）。
        current_time: 仿真时间（秒）
        """
        self.tick_counter += 1
        outgoing = []

        # 处理收到的消息
        for msg in received_msgs:
            self._handle_message(msg, current_time)

        # 路由老化：清除超时未刷新的路由条目
        self._age_routes(current_time)

        # 触发更新（邻居变化/路由失效时立即通告）或周期性广告
        self.adv_timer += self.tick_interval
        should_advertise = False
        is_triggered = False

        if self.trigger_update:
            should_advertise = True
            is_triggered = True
            self.trigger_update = False
            self.adv_timer = 0.0  # 重置周期计时器
        elif self.adv_timer >= self.adv_interval:
            should_advertise = True
            self.adv_timer -= self.adv_interval

        if should_advertise:
            update_msg = self._build_update_message()
            if update_msg:
                update_msg.dst = -1  # 广播
                outgoing.append(update_msg)
                self.updates_sent += 1
                if is_triggered:
                    self.triggered_updates_sent += 1

        # 检查收敛（连续3个tick无变化）
        if hasattr(self, 'last_change_tick') and self.last_change_tick > 0:
            if self.tick_counter - self.last_change_tick >= 3:
                self.converged = True

        return outgoing

    def _handle_message(self, msg: DVMessage, current_time: float):
        if msg.type == 'hello':
            # 处理Hello（通常只用于邻居发现，此处略过）
            pass
        elif msg.type == 'update':
            self._process_update(msg, current_time)

    def _process_update(self, msg: DVMessage, current_time: float):
        self.updates_received += 1
        # 路径矢量环路检测：若自己的ID已在visited中，说明路由信息回环
        if self.node_id in msg.visited:
            idx = msg.visited.index(self.node_id)
            loop_path = msg.visited[idx:]  # 从自身位置截断到末尾
            if len(loop_path) >= 3:  # 至少3个节点构成环路
                self.loops_detected.append(loop_path)
                # 记录环路但继续处理（DV通常忽略，此处保持兼容）

        # 对每条通告条目，尝试更新路由表
        for dest, metric, seq in msg.entries:
            # 如果通告来自邻居（msg.src），且metric+1小于当前metric，则更新
            if msg.src not in self.neighbors:
                continue  # 只处理来自邻居的更新
            # 忽略到自身的条目
            if dest == self.node_id:
                continue
            # 检查是否有更好路径
            current_entry = self.routing_table.get(dest)
            if current_entry is None:
                # 新条目
                self._add_entry(dest, msg.src, metric + 1, seq, current_time,
                                path=list(msg.visited))
            else:
                # 比较序列号（防止旧广告），若相等则比较metric
                if seq > current_entry.seq:
                    self._add_entry(dest, msg.src, metric + 1, seq, current_time,
                                    path=list(msg.visited))
                elif seq == current_entry.seq and metric + 1 < current_entry.metric:
                    self._add_entry(dest, msg.src, metric + 1, seq, current_time,
                                    path=list(msg.visited))
                else:
                    # 路由未改变但仍被确认——刷新 age 防止误老化
                    # （来自同一 next_hop 的相同 seq 广告表明路由仍有效）
                    if current_entry.next_hop == msg.src:
                        current_entry.age = current_time

    def _add_entry(self, dest: int, next_hop: int, metric: int, seq: int,
                   current_time: float, path: Optional[List[int]] = None):
        self.routing_table[dest] = RouteEntry(
            dest=dest, next_hop=next_hop, metric=metric,
            seq=seq, age=current_time,
            path=path if path is not None else []
        )
        self.last_change_tick = self.tick_counter

    def _build_update_message(self) -> Optional[DVMessage]:
        """构建更新报文，包含路由表中所有条目以及自身条目。
        
        visited 字段使用路径矢量累积：取所有路由条目中最长的已传播路径，
        再追加自身 node_id，使接收方能通过 visited 检测环路。
        """
        entries = []
        # 始终包含自身条目（metric=0）
        entries.append((self.node_id, 0, self.msg_seq))
        for dest, entry in self.routing_table.items():
            entries.append((dest, entry.metric, entry.seq))
        if not entries:
            return None
        self.msg_seq += 1

        # 路径矢量构建：取路由表中最长的 path，追加自身
        longest_path: List[int] = []
        for entry in self.routing_table.values():
            if entry.path and len(entry.path) > len(longest_path):
                longest_path = entry.path
        # visited = 已传播路径 + 自身（保证接收方能看到完整传播链）
        visited = list(longest_path) + [self.node_id]

        msg = DVMessage(
            type='update',
            src=self.node_id,
            dst=-1,
            seq=self.msg_seq,
            visited=visited,
            entries=entries
        )
        return msg

    def _age_routes(self, current_time: float):
        """路由老化：删除超时未刷新的路由条目，失效时触发更新"""
        expired = []
        for dest, entry in self.routing_table.items():
            if current_time - entry.age > self.aging_timeout:
                expired.append(dest)
        if expired:
            for dest in expired:
                del self.routing_table[dest]
            self.last_change_tick = self.tick_counter
            # 路由失效触发更新，通知邻居
            self.trigger_update = True

    def purge_neighbor_routes(self, lost_neighbor: int):
        """清除所有 next_hop 指向已失效邻居的路由条目，并触发更新"""
        to_remove = [dest for dest, entry in self.routing_table.items()
                     if entry.next_hop == lost_neighbor]
        if to_remove:
            for dest in to_remove:
                del self.routing_table[dest]
            self.last_change_tick = self.tick_counter
            self.trigger_update = True

    def get_next_hop(self, dest: int) -> Optional[int]:
        """查询下一跳"""
        entry = self.routing_table.get(dest)
        if entry:
            return entry.next_hop
        return None

    def get_route(self, dest: int) -> Optional[RouteEntry]:
        return self.routing_table.get(dest)

    def get_routing_table(self) -> Dict[int, RouteEntry]:
        return self.routing_table.copy()

    def add_hello(self) -> DVMessage:
        """生成一个Hello报文（用于邻居发现）"""
        self.hello_seq += 1
        return DVMessage(type='hello', src=self.node_id, dst=-1, seq=self.hello_seq)