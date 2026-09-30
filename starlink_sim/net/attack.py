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

    def controls(self, node_id: int) -> bool:
        """该攻击者是否**控制**指定节点（可改写其通告 / 在数据面与之匹配）。

        基类语义：仅控制自身 ``node_id``——与既有 ``att.node_id == node_id`` 判定逐位
        等价，故 blackhole/jamming 行为完全不变。Sybil 攻击者覆盖此方法以同时控制其
        注入的多个虚假身份节点（见 :class:`SybilAttacker`）。simulator 的控制面通告
        改写与数据面攻击匹配统一改用本方法，以支持"一个攻击者控制多个节点"。
        """
        return node_id == self.node_id

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
    """Sybil（虚假身份）攻击：一个被劫持的物理节点对外呈现多个虚假身份。

    与黑洞/干扰不同，Sybil 的虚假身份是**注入到拓扑中的新节点**（扩大节点 ID 空间，
    见 :mod:`starlink_sim.net.sybil`），每个身份附着到一个高价值真实节点。本攻击者
    控制其全部虚假身份（:meth:`controls`），并让这些身份对外**发布伪造的低 metric
    通告**（复用 :meth:`_bump_seq` 保证接收端采纳），从而把真实节点的路由牵引到虚假
    身份上（吸引/牵引流量）。被劫持的物理节点（``node_id``）默认**不**自行毒化路由
    （``controller_poisons=False``），以把可观测效果干净地归因于虚假身份；如需让物理
    节点也充当黑洞可置 ``controller_poisons=True``。虚假身份默认只牵引不丢弃
    （``drop_prob=0.0``），其破坏性体现为路由环路/不可达；置 ``drop_prob>0`` 则同时丢包。

    构造签名兼容工厂（``create_attacker(node_id=..., **params)``）：专有 kwargs 为
    ``num_identities`` / ``attachment`` / ``metric_fake`` / ``drop_prob`` /
    ``controller_poisons`` / ``seq_lead``。虚假身份 ID 由外部注入工具经
    :meth:`bind_identities` 绑定。

    为何需要 ``seq_lead``（与黑洞的关键差异）
    ---------------------------------------
    ``DVRouter._process_update`` 仅在 ``seq > 当前条目 seq``（或 seq 相等且 metric 更小）
    时采纳通告。虚假身份的路由知识来自其附着点，比目的节点自身的通告**滞后 2 跳**，
    因此仅把 seq 提升 1（``_bump_seq`` 的默认幅度）恰好与更新鲜的合法通告**打平**，
    随后在 metric tie-break 中落败 → 牵引效果被合法通告立即翻回（实测小拓扑吸引率为 0）。
    序列号在本协议中不受认证，虚假身份可自由伪造，故 ``seq_lead`` 让伪造 seq 额外领先
    若干，使被牵引的路由在多个广告周期内保持；由于 ``_seq_floor`` 单调递增且每周期
    再领先 ``seq_lead``，合法通告的 seq 增速（每周期 +1）永远追不上 → 牵引稳定持续。
    置 ``seq_lead=0`` 即退化为与黑洞同幅度的 seq 提升。
    """

    def __init__(self, node_id: int, num_identities: int = 1,
                 attachment: str = 'betweenness', metric_fake: int = 0,
                 drop_prob: float = 0.0, controller_poisons: bool = False,
                 seq_lead: int = 8,
                 active_since: float = 0.0, active_until: Optional[float] = None, **kwargs):
        super().__init__(node_id, active_since, active_until, **kwargs)
        self.num_identities = int(num_identities)
        self.attachment = attachment
        self.metric_fake = metric_fake
        self.drop_prob = drop_prob
        self.controller_poisons = bool(controller_poisons)
        self.seq_lead = max(0, int(seq_lead))
        # 由 sybil.expand_topology_for_sybils 经 bind_identities 注入
        self.sybil_node_ids: set = set()
        self.attachment_map: Dict[int, int] = {}

    def bind_identities(self, sybil_node_ids, attachment_map: Optional[Dict[int, int]] = None) -> None:
        """绑定注入工具分配的虚假身份节点 ID（及身份->附着真实节点映射）。"""
        self.sybil_node_ids = set(sybil_node_ids)
        if attachment_map:
            self.attachment_map = dict(attachment_map)

    def controls(self, node_id: int) -> bool:
        """控制被劫持物理节点 + 其全部虚假身份节点。"""
        return node_id == self.node_id or node_id in self.sybil_node_ids

    def _poisons(self, src: Optional[int]) -> bool:
        """通告来源 ``src`` 是否应被本攻击者毒化（虚假身份恒毒化；物理节点看开关）。"""
        if src is None:
            return False
        if src in self.sybil_node_ids:
            return True
        return src == self.node_id and self.controller_poisons

    def _fake_seq(self, dest: int, seq: int) -> int:
        """伪造条目的 seq：在 :meth:`_bump_seq` 的单调基线上再加 ``seq_lead`` 前瞻量。

        保证接收端 ``seq > current.seq`` 成立（而非仅打平），使低 metric 伪造通告被真实
        采纳并在多个广告周期内不被更新鲜的合法通告翻回。seq_floor 随之抬升，维持单调。
        """
        bumped = self._bump_seq(dest, seq) + self.seq_lead
        if bumped > self._seq_floor.get(dest, 0):
            self._seq_floor[dest] = bumped
        return bumped

    def modify_advertisement(self, adv_msg, node, topology, time):
        if not self.is_active(time):
            return adv_msg
        src = getattr(adv_msg, 'src', None)
        if not self._poisons(src):
            return adv_msg
        new_entries = []
        for dest, metric, seq in adv_msg.entries:
            if dest == src:
                # 保留到自身的条目，避免污染本地距离
                new_entries.append((dest, metric, seq))
            else:
                # 虚假身份伪造低 metric 牵引流量；seq 领先保证接收端采纳
                new_entries.append((dest, self.metric_fake, self._fake_seq(dest, seq)))
        return self._rebuild(adv_msg, new_entries)

    def should_drop_data(self, flow, time):
        # 纯判定：是否丢弃过境数据（计数统一由 DataPlane.evaluate_flows 维护）。
        # Sybil 默认只牵引不丢弃（drop_prob=0）；置 drop_prob>0 则按概率丢弃。
        if not self.is_active(time):
            return False
        if self.drop_prob <= 0.0:
            return False
        return random.random() < self.drop_prob


class WormholeAttacker(Attacker):
    """虫洞（Wormhole）攻击：**一个攻击者同时控制两个物理相距很远的真实节点** A、B。

    A、B 通过私有隧道串通，对彼此邻域伪造可达性，使网络误以为它们**相邻**：一条
    "短 metric 跳"实为超长物理距离（数千公里被当作 1 跳）。后果是流量被牵引、路由
    环路、地理路由被破坏。隧道边本身由 :mod:`starlink_sim.net.wormhole` 在
    ``ControlPlane`` 构建**之前**注入每个 epoch 的 edge_sets，并经
    :meth:`bind_endpoints` 把双端点绑回本攻击者。

    与 Sybil 的关键差异
    ------------------
    虫洞**不新增节点身份**——A、B 都是既有真实节点，故**不扩展节点 ID 空间**
    （``num_nodes`` 不变）；而 Sybil 的虚假身份是新节点（见
    :class:`SybilAttacker` / :mod:`starlink_sim.net.sybil`）。

    双端点控制的实现方式（**未改动 Attacker ABC**）
    --------------------------------------------
    ``node_id`` 存 A，新增实例属性 ``second_endpoint`` 存 B；覆盖基类的
    :meth:`controls`，对 ``x ∈ {A, B}`` 返回 True。``simulator.ControlPlane.step``
    与 ``DataPlane.evaluate_flows`` 已统一改用 ``att.controls(node)``（E4 引入），
    因此**simulator 无需任何改动**即可让一个攻击者改写两个节点的通告并在数据面
    匹配两个端点。基类签名 ``Attacker(node_id, active_since, active_until, **kwargs)``
    保持不变，blackhole / jamming / sybil 行为逐位不受影响。

    通告伪造语义
    ------------
    A 向其邻域、B 向其邻域，分别发布"经隧道可达对端"的伪造低 metric 通告：把
    ``dest == peer`` 的条目改写为 ``metric_fake``（默认 0 → 邻居计算得 metric 1，
    即"对端 1 跳可达"）。若通告中不含对端条目，主动**补入**一条（虫洞的核心谎言：
    让远端看起来相邻）。对端**一侧**的其余目的地不做篡改——它们经隧道由正常 DV
    收敛自然获得缩短后的 metric，这正是虫洞"制造捷径、牵引流量"的机制。

    ``poison_scope`` 提供两档强度（E6 强度对比臂可直接切换）：

    - ``'peer_only'``（**默认**）：只伪造对端本身。得到的是一个**健全的捷径**：流量被
      牵引经隧道、跳数变少而物理距离/时延暴涨（``path_stretch < 1``、
      ``geo_stretch > 1``），且不会自伤成环。
    - ``'peer_side'``：额外把本节点路由表中 ``next_hop == peer`` 的**整个对端一侧**也改写为
      ``metric_fake``。该谎言过强（等于宣称自己与对端一侧每个节点同址），会让 B 把
      到自己直接邻居的路由也改指向 A → **自伤环路**、送达率崩塌。保留它作为
      "极端强度"对照臂（其破坏性由 ``total_loops`` / ``delivery_ratio`` 体现），
      但不宜作默认。

    seq 策略：为何对端条目**不**抬 seq，而对端一侧条目需要 ``seq_lead``
    --------------------------------------------------------------------
    ``DVRouter._process_update`` 仅在 ``seq > 当前条目 seq``（或 seq 相等且 metric 更小）
    时采纳。两个方向的取舍不同：

    - ``dest == peer``：**保留自然 seq**，只降 metric。因为 A 关于 B 的知识直接来自 B
      的自身通告（``_build_update_message`` 每周期递增 ``msg_seq``），已是全网**最新鲜**
      的，无需抬 seq 就能在 seq 比较或 metric tie-break 中胜出。反之，若抬 seq，
      这个被抬高的 seq 会经邻居**反射回 A 自身**（邻居学到"B metric 1 seq S"后回传给 A），
      并以 ``S > A 当前 seq`` 压过 A 的**直连**路由 → A 把到 B 的下一跳改成邻居，
      形成 A↔邻居 的转发环，所有以 B 为终点的流全部失败。
    - ``dest ∈ 对端一侧``（仅 ``'peer_side'``）：A 的知识经 B 中转，相对目的地自身的
      新鲜通告可能**滞后**，仅 ``_bump_seq`` 的 +1 会与之打平而在 metric tie-break 中
      落败 → 牵引被立即翻回（与 E4 Sybil 同一教训）。故用 ``_fake_seq``：
      ``_bump_seq(dest, seq) + seq_lead``，``_seq_floor`` 单调递增且每周期再领先
      ``seq_lead``，合法 seq 每周期只 +1 永远追不上 → 谎言稳定持续。
      置 ``seq_lead=0`` 即退化为与黑洞同幅度。

    构造签名兼容工厂（``create_attacker(node_id=..., **params)``）：专有 kwargs 为
    ``second_endpoint`` / ``endpoint_strategy`` / ``pool_size`` / ``metric_fake`` /
    ``drop_prob`` / ``seq_lead`` / ``poison_scope``。数据面默认**只牵引不丢包**
    （``drop_prob=0.0``），其破坏性体现为绕远路/时延暴涨/环路；置 ``drop_prob>0``
    则两个端点同时按概率丢弃过境数据。
    """

    #: 毒化范围：'peer_only' = 仅对端本身（默认，健全捷径）；
    #:           'peer_side' = 对端 + 经隧道学到的整个对端一侧（极端强度，会自伤成环）
    POISON_SCOPES: Tuple[str, ...] = ('peer_only', 'peer_side')
    DEFAULT_POISON_SCOPE: str = 'peer_only'

    def __init__(self, node_id: int, second_endpoint: Optional[int] = None,
                 endpoint_strategy: str = 'farthest', pool_size: int = 48,
                 metric_fake: int = 0, drop_prob: float = 0.0, seq_lead: int = 8,
                 poison_scope: str = 'peer_only',
                 active_since: float = 0.0, active_until: Optional[float] = None, **kwargs):
        super().__init__(node_id, active_since, active_until, **kwargs)
        # B 端：可由配置显式指定（second_endpoint），否则由 wormhole.select_wormhole_peer
        # 按 endpoint_strategy 选出并经 bind_endpoints 绑定
        self.second_endpoint: Optional[int] = None if second_endpoint is None else int(second_endpoint)
        self.endpoint_strategy = endpoint_strategy
        self.pool_size = int(pool_size)
        self.metric_fake = metric_fake
        self.drop_prob = drop_prob
        self.seq_lead = max(0, int(seq_lead))
        self.poison_scope = poison_scope if poison_scope in self.POISON_SCOPES \
            else self.DEFAULT_POISON_SCOPE

    # ---------------- 双端点绑定 ----------------
    def bind_endpoints(self, node_a: int, node_b: int) -> None:
        """绑定隧道两端点（A 覆盖 ``node_id``，B 存入 ``second_endpoint``）。

        由 :func:`starlink_sim.net.wormhole.expand_topology_for_wormholes` 在注入隧道边
        的同时调用；绑定后 :meth:`controls` 才同时覆盖 A 与 B。
        """
        self.node_id = int(node_a)
        self.second_endpoint = int(node_b)

    @property
    def endpoints(self) -> Optional[Tuple[int, int]]:
        """隧道端点对 ``(A, B)``；未绑定对端时为 ``None``。"""
        if self.second_endpoint is None:
            return None
        return (self.node_id, self.second_endpoint)

    @property
    def tunnel(self) -> Optional[Tuple[int, int]]:
        """规范化隧道边 ``(min, max)``（与 isl / wormhole 的边存储约定一致）。"""
        ep = self.endpoints
        return None if ep is None else (min(ep), max(ep))

    def controls(self, node_id: int) -> bool:
        """同时控制隧道两端 A 与 B（未绑定对端时退化为仅控制 A）。"""
        return node_id == self.node_id or (
            self.second_endpoint is not None and node_id == self.second_endpoint)

    def _peer_of(self, src: Optional[int]) -> Optional[int]:
        """``src`` 为本攻击者控制的端点时返回其**隧道对端**，否则 None。"""
        if src is None or self.second_endpoint is None:
            return None
        if src == self.node_id:
            return self.second_endpoint
        if src == self.second_endpoint:
            return self.node_id
        return None

    def _fake_seq(self, dest: int, seq: int) -> int:
        """伪造条目 seq：``_bump_seq`` 单调基线 + ``seq_lead`` 前瞻量（同 SybilAttacker）。

        仅用于 ``'peer_side'`` 下对**对端一侧**目的地的篡改；对端本身的条目保留自然
        seq（见类文档），否则会因邻居反射而破坏端点自身的直连路由。
        """
        bumped = self._bump_seq(dest, seq) + self.seq_lead
        if bumped > self._seq_floor.get(dest, 0):
            self._seq_floor[dest] = bumped
        return bumped

    def _via_peer(self, dest: int, node: Any, peer: int) -> bool:
        """``node`` 的路由表中到 ``dest`` 的下一跳是否为隧道对端（即 dest 属对端一侧）。"""
        rt = getattr(node, 'routing_table', None) or {}
        entry = rt.get(dest)
        return entry is not None and getattr(entry, 'next_hop', None) == peer

    def modify_advertisement(self, adv_msg, node, topology, time):
        if not self.is_active(time):
            return adv_msg
        src = getattr(adv_msg, 'src', None)
        peer = self._peer_of(src)
        if peer is None:
            # 只能篡改自己两个端点发出的通告（与 blackhole/jamming 的"只改自身"约束一致）
            return adv_msg
        new_entries: List[Tuple[int, int, int]] = []
        seen: set = set()
        for dest, metric, seq in adv_msg.entries:
            seen.add(dest)
            if dest == src:
                # 保留到自身的条目，避免污染本地距离
                new_entries.append((dest, metric, seq))
            elif dest == peer:
                # 对端本身：只降 metric，**不抬 seq**（A 关于 B 的知识已是全网最新鲜；
                # 抬 seq 会被邻居反射回 A 并压过其直连路由 → 以 B 为终点的流成环）
                new_entries.append((dest, self.metric_fake, seq))
            elif self.poison_scope == 'peer_side' and self._via_peer(dest, node, peer):
                # 对端一侧：伪造低 metric + 领先 seq（否则会被更新鲜的合法通告翻回）
                new_entries.append((dest, self.metric_fake, self._fake_seq(dest, seq)))
            else:
                new_entries.append((dest, metric, seq))
        if peer not in seen:
            # A 尚未学到对端（首个广告周期）时主动补入"对端 1 跳可达"的伪造条目。
            # 用不带 seq_lead 的 ``_bump_seq``：一旦 A 从 B 直接学到新鲜通告，
            # 上面的自然 seq 分支即接管，不会遗留一个压死直连路由的高 seq。
            new_entries.append((peer, self.metric_fake, self._bump_seq(peer, 0)))
        return self._rebuild(adv_msg, new_entries)

    def should_drop_data(self, flow, time):
        # 纯判定：是否丢弃过境数据（计数统一由 DataPlane.evaluate_flows 维护）。
        # 虫洞默认只牵引不丢弃（drop_prob=0）；置 drop_prob>0 则两端点同时按概率丢弃。
        if not self.is_active(time):
            return False
        if self.drop_prob <= 0.0:
            return False
        return random.random() < self.drop_prob
