# starlink_sim/net/attack.py
"""
统一后的攻击者实现，供 E2 干扰、E3 黑洞等实验入口共用。

设计要点（修复 Issue #2：控制面攻击未注入）：
- ``DVMessage`` 的路由通告保存在 ``entries``（List[(dest, metric, seq)]）。
  黑洞 / 干扰攻击均直接改写 ``entries``，而非旧版误用的 ``routes`` 字段。
- 被篡改条目通过单调递增的 seq（``_bump_seq``）确保接收端
  ``routing_dv.DVRouter._process_update`` 的防旧序比较会采纳该通告；
  攻击窗口结束后恢复正常通告，网络随之收敛恢复。
- 构造接口保持关键字参数（node_id + 各攻击专有参数 + active_since/active_until），
  与 run_e3_blackhole_experiment.py 的 ``att_class(node_id=..., **params)`` 及回归用例一致。
"""
import random
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from starlink_sim.net.routing_dv import DVMessage

logger = logging.getLogger(__name__)


class Attacker(ABC):
    def __init__(self, node_id: int, active_since: float = 0.0,
                 active_until: Optional[float] = None, **kwargs):
        self.node_id = node_id
        self.active_since = active_since
        self.active_until = active_until
        self.attracted_count = 0
        self.dropped_count = 0
        # 为每个被篡改目的地维护单调递增 seq，保证接收端持续采纳被修改的通告
        self._seq_floor: Dict[int, int] = {}

    def is_active(self, time: float) -> bool:
        if time < self.active_since:
            return False
        if self.active_until is not None and time > self.active_until:
            return False
        return True

    @abstractmethod
    def modify_advertisement(self, adv_msg: Any, node: Any, topology: Any, time: float) -> Any:
        pass

    @abstractmethod
    def should_drop_data(self, flow: Any, time: float) -> bool:
        pass

    def reset_stats(self):
        self.attracted_count = 0
        self.dropped_count = 0

    # ---------------- 供子类复用的报文改写工具 ----------------
    def _bump_seq(self, dest: int, seq: int) -> int:
        """为被篡改条目生成单调递增 seq，保证接收端（seq 更大即采纳）接受该通告。"""
        new_seq = max(seq, self._seq_floor.get(dest, 0)) + 1
        self._seq_floor[dest] = new_seq
        return new_seq

    def _rebuild(self, original: DVMessage,
                 new_entries: List[Tuple[int, int, int]]) -> DVMessage:
        """基于原始通告构造新报文，保留 src/dst/type/seq；visited 做拷贝避免别名共享。"""
        return DVMessage(
            type=getattr(original, 'type', 'update'),
            src=original.src,
            dst=original.dst,
            seq=getattr(original, 'seq', 0),
            visited=list(getattr(original, 'visited', [])),
            entries=new_entries,
        )


class BlackholeAttacker(Attacker):
    """黑洞攻击：向邻居伪造到各目的地的低度量以吸引流量，并按 drop_prob 丢弃过境数据。"""

    def __init__(self, node_id: int, drop_prob: float = 0.5, metric_fake: int = 0,
                 active_since: float = 0.0, active_until: Optional[float] = None, **kwargs):
        super().__init__(node_id, active_since, active_until, **kwargs)
        self.drop_prob = drop_prob
        self.metric_fake = metric_fake

    def modify_advertisement(self, adv_msg, node, topology, time):
        if not self.is_active(time):
            return adv_msg
        # 攻击者只能篡改自身发出的通告
        if getattr(adv_msg, 'src', None) != self.node_id:
            return adv_msg
        new_entries = []
        for dest, metric, seq in adv_msg.entries:
            if dest == self.node_id:
                # 保留到自身的条目，避免污染本地距离
                new_entries.append((dest, metric, seq))
            else:
                # 伪造低度量吸引流量；bump seq 保证接收端采纳
                new_entries.append((dest, self.metric_fake, self._bump_seq(dest, seq)))
        return self._rebuild(adv_msg, new_entries)

    def should_drop_data(self, flow, time):
        # 纯判定：是否丢弃该过境数据。
        # attracted_count / dropped_count 的累加统一由仿真器 DataPlane.evaluate_flows
        # 维护；此处不再自增，避免与数据面循环计数叠加造成双重统计。
        if not self.is_active(time):
            return False
        return random.random() < self.drop_prob


class JammingAttacker(Attacker):
    """干扰攻击：将经被干扰邻居转发的通告抬升为不可达度量（inf_metric），触发路由撤回 / 绕行。"""

    def __init__(self, node_id: int, jamming_ratio: float = 0.3, inf_metric: int = 9999,
                 active_since: float = 0.0, active_until: Optional[float] = None, **kwargs):
        super().__init__(node_id, active_since, active_until, **kwargs)
        self.jamming_ratio = jamming_ratio
        self.inf_metric = inf_metric

    def modify_advertisement(self, adv_msg, node, topology, time):
        if not self.is_active(time):
            return adv_msg
        if getattr(adv_msg, 'src', None) != self.node_id:
            return adv_msg
        neighbors = list(getattr(node, 'neighbors', set())) if node is not None else []
        if not neighbors:
            return adv_msg
        n_jam = max(1, int(len(neighbors) * self.jamming_ratio))
        jammed = set(random.sample(neighbors, min(n_jam, len(neighbors))))
        routing_table = getattr(node, 'routing_table', {})
        new_entries = []
        for dest, metric, seq in adv_msg.entries:
            if dest == self.node_id:
                new_entries.append((dest, metric, seq))
                continue
            # 受干扰链路影响面：dest 本身是被干扰邻居，或本表到 dest 的下一跳落在被干扰邻居
            via_jammed = dest in jammed
            if not via_jammed:
                entry = routing_table.get(dest)
                via_jammed = entry is not None and entry.next_hop in jammed
            if via_jammed:
                # 通告不可达度量（路由撤回）；bump seq 确保接收端接受撤回
                new_entries.append((dest, self.inf_metric, self._bump_seq(dest, seq)))
            else:
                new_entries.append((dest, metric, seq))
        return self._rebuild(adv_msg, new_entries)

    def should_drop_data(self, flow, time):
        # 干扰作用于控制面（路由撤回/绕行），数据面不由攻击者主动丢弃
        return False


class SybilAttacker(Attacker):
    """Sybil 攻击占位实现：当前不修改通告，也不丢弃数据。"""

    def modify_advertisement(self, adv_msg, node, topology, time):
        return adv_msg

    def should_drop_data(self, flow, time):
        return False
