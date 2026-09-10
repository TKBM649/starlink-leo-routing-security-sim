# starlink_sim/net/attack.py
import random
import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

logger = logging.getLogger(__name__)

class Attacker(ABC):
    def __init__(self, node_id: int, active_since: float = 0.0, active_until: Optional[float] = None, **kwargs):
        self.node_id = node_id
        self.active_since = active_since
        self.active_until = active_until
        self.attracted_count = 0
        self.dropped_count = 0

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

class BlackholeAttacker(Attacker):
    def __init__(self, node_id: int, drop_prob: float = 0.5, metric_fake: int = 0,
                 active_since: float = 0.0, active_until: Optional[float] = None, **kwargs):
        super().__init__(node_id, active_since, active_until, **kwargs)
        self.drop_prob = drop_prob
        self.metric_fake = metric_fake

    def modify_advertisement(self, adv_msg, node, topology, time):
        if not self.is_active(time):
            return adv_msg
        if hasattr(adv_msg, 'routes') and isinstance(adv_msg.routes, dict):
            for dst in list(adv_msg.routes.keys()):
                _, _, seq = adv_msg.routes[dst]
                adv_msg.routes[dst] = (self.metric_fake, self.node_id, seq)
        return adv_msg

    def should_drop_data(self, flow, time):
        if not self.is_active(time):
            return False
        self.attracted_count += 1
        if random.random() < self.drop_prob:
            self.dropped_count += 1
            return True
        return False

class JammingAttacker(Attacker):
    def modify_advertisement(self, adv_msg, node, topology, time): return adv_msg
    def should_drop_data(self, flow, time): return False

class SybilAttacker(Attacker):
    def modify_advertisement(self, adv_msg, node, topology, time): return adv_msg
    def should_drop_data(self, flow, time): return False