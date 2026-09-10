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
    def __init__(self, node_id: int, tick_interval: float = 0.2, adv_interval: float = 2.0):
        self.node_id = node_id
        self.tick_interval = tick_interval   # 200ms
        self.adv_interval = adv_interval     # 2s
        self.routing_table: Dict[int, RouteEntry] = {}  # dest -> RouteEntry
        self.sequences: Dict[int, int] = {}  # 每目的地的序列号（用于邻居排序）
        self.neighbors: Set[int] = set()     # 当前邻居列表（由外部更新）
        self.msg_seq = 0
        self.hello_seq = 0
        self.adv_timer = 0.0                 # 累计时间，触发广告
        self.tick_counter = 0
        # 统计
        self.loops_detected: List[List[int]] = []  # 检测到的环路路径
        self.updates_sent = 0
        self.updates_received = 0
        # 用于收敛检测
        self.last_change_tick = 0
        self.stable_since = None
        self.converged = False

    def set_neighbors(self, neighbors: Set[int]):
        """更新邻居集合（由拓扑通知）"""
        self.neighbors = neighbors

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

        # 周期性广告
        self.adv_timer += self.tick_interval
        if self.adv_timer >= self.adv_interval:
            self.adv_timer -= self.adv_interval
            # 构建 Update 报文发送给所有邻居
            update_msg = self._build_update_message()
            if update_msg:
                # 假设广播：dst = -1 表示广播
                update_msg.dst = -1
                outgoing.append(update_msg)
                self.updates_sent += 1

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
        # 检测环路：若自己的ID已在visited中，说明出现了环路
        if self.node_id in msg.visited:
            # 记录环路路径（从msg.visited中的self开始，截断到末尾）
            idx = msg.visited.index(self.node_id)
            loop_path = msg.visited[idx:]  # 包含自身后续
            if len(loop_path) >= 3:  # 至少一个环
                self.loops_detected.append(loop_path)
                # 可以根据策略丢弃该消息或继续处理，这里我们继续处理（但标记）
                # 实际DV通常忽略该更新，但我们可以记录并继续

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
                self._add_entry(dest, msg.src, metric + 1, seq, current_time)
            else:
                # 比较序列号（防止旧广告），若相等则比较metric
                if seq > current_entry.seq:
                    self._add_entry(dest, msg.src, metric + 1, seq, current_time)
                elif seq == current_entry.seq and metric + 1 < current_entry.metric:
                    self._add_entry(dest, msg.src, metric + 1, seq, current_time)

    def _add_entry(self, dest: int, next_hop: int, metric: int, seq: int, current_time: float):
        self.routing_table[dest] = RouteEntry(
            dest=dest, next_hop=next_hop, metric=metric,
            seq=seq, age=current_time
        )
        self.last_change_tick = self.tick_counter

    def _build_update_message(self) -> Optional[DVMessage]:
        """构建更新报文，包含路由表中所有条目以及自身条目"""
        entries = []
        # 始终包含自身条目（metric=0）
        entries.append((self.node_id, 0, self.msg_seq))
        for dest, entry in self.routing_table.items():
            entries.append((dest, entry.metric, entry.seq))
        if not entries:
            return None
        self.msg_seq += 1
        msg = DVMessage(
            type='update',
            src=self.node_id,
            dst=-1,
            seq=self.msg_seq,
            visited=[self.node_id],
            entries=entries
        )
        return msg

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