# starlink_sim/net/attack.py
import random
from typing import Dict, List, Optional, Any, Tuple
from starlink_sim.net.routing_dv import DVRouter, DVMessage


class Attacker:
    """攻击者基类"""
    def __init__(self, node_id: int, config: dict):
        self.node_id = node_id
        self.active_since = config.get('active_since', 0.0)
        self.active_until = config.get('active_until', float('inf'))
        self.config = config
        self.attracted_count = 0
        self.dropped_count = 0

    def is_active(self, current_time: float) -> bool:
        return self.active_since <= current_time < self.active_until

    def modify_advertisement(self, msg: DVMessage, router: DVRouter,
                             topology: Any, current_time: float) -> DVMessage:
        return msg

    def should_drop_data(self, flow: tuple, current_time: float) -> bool:
        return False


def _get_entries(msg: DVMessage) -> List[Tuple[int, int, int]]:
    """获取路由通告条目：(dest, metric, seq) 三元组列表，与 routing_dv.DVMessage 定义一致"""
    if hasattr(msg, 'entries'):
        return msg.entries
    else:
        raise AttributeError(f"DVMessage 没有 'entries' 属性，当前属性：{dir(msg)}")


def _make_message_from_original(original: DVMessage,
                                new_entries: List[Tuple[int, int, int]]) -> DVMessage:
    """基于原始消息创建新消息，保留其他字段（visited 拷贝以避免与原消息别名共享）"""
    return DVMessage(
        src=original.src,
        dst=original.dst,
        entries=new_entries,
        seq=getattr(original, 'seq', 0),
        type=getattr(original, 'type', 'update'),
        visited=list(getattr(original, 'visited', []))
    )


def _bump_seq(seq_floor: Dict[int, int], dest: int, seq: int) -> int:
    """为被篡改条目生成单调递增的 seq，保证接收端防旧序比较（routing_dv._process_update）
    会接受该通告（seq 更大即采纳）；攻击窗口结束后随网络自然收敛恢复。"""
    s = max(seq, seq_floor.get(dest, 0)) + 1
    seq_floor[dest] = s
    return s


class BlackholeAttacker(Attacker):
    def __init__(self, node_id: int, config: dict):
        super().__init__(node_id, config)
        self.fake_metric = config.get('fake_metric', 1)
        self.drop_prob = config.get('drop_prob', 0.8)
        self._seq_floor: Dict[int, int] = {}

    def modify_advertisement(self, msg: DVMessage, router: DVRouter,
                             topology: Any, current_time: float) -> DVMessage:
        if not self.is_active(current_time):
            return msg
        if msg.src != self.node_id:
            return msg
        new_entries = []
        for dest, metric, seq in _get_entries(msg):
            if dest == self.node_id:
                # 保留自身条目，避免污染到自身的距离
                new_entries.append((dest, metric, seq))
            else:
                # 伪造低度量吸引流量；bump seq 确保接收端接受该通告
                new_entries.append((dest, self.fake_metric,
                                    _bump_seq(self._seq_floor, dest, seq)))
        return _make_message_from_original(msg, new_entries)

    def should_drop_data(self, flow: tuple, current_time: float) -> bool:
        if not self.is_active(current_time):
            return False
        return random.random() < self.drop_prob


class JammingAttacker(Attacker):
    def __init__(self, node_id: int, config: dict):
        super().__init__(node_id, config)
        self.jamming_ratio = config.get('jamming_ratio', 0.3)
        self.inf_metric = config.get('inf_metric', 9999)
        self._seq_floor: Dict[int, int] = {}

    def modify_advertisement(self, msg: DVMessage, router: DVRouter,
                             topology: Any, current_time: float) -> DVMessage:
        if not self.is_active(current_time):
            return msg
        if msg.src != self.node_id:
            return msg

        neighbors = list(router.neighbors)
        if not neighbors:
            return msg

        n_jam = max(1, int(len(neighbors) * self.jamming_ratio))
        jammed = set(random.sample(neighbors, min(n_jam, len(neighbors))))

        new_entries = []
        for dest, metric, seq in _get_entries(msg):
            if dest == self.node_id:
                new_entries.append((dest, metric, seq))
                continue
            # 受干扰链路的影响面：dest 为被干扰邻居，或本表路由下一跳落在被干扰邻居
            via_jammed = dest in jammed
            if not via_jammed:
                entry = router.routing_table.get(dest)
                via_jammed = entry is not None and entry.next_hop in jammed
            if via_jammed:
                # 通告不可达度量（路由撤回）；bump seq 确保接收端接受撤回
                new_entries.append((dest, self.inf_metric,
                                    _bump_seq(self._seq_floor, dest, seq)))
            else:
                new_entries.append((dest, metric, seq))
        return _make_message_from_original(msg, new_entries)


class SybilAttacker(Attacker):
    def __init__(self, node_id: int, config: dict):
        super().__init__(node_id, config)

    def modify_advertisement(self, msg: DVMessage, router: DVRouter,
                             topology: Any, current_time: float) -> DVMessage:
        return msg