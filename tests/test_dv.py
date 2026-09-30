# tests/test_dv.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from starlink_sim.net.routing_dv import DVRouter, DVMessage

def test_basic():
    r1 = DVRouter(1)
    r2 = DVRouter(2)
    r1.set_neighbors({2})
    r2.set_neighbors({1})

    # r2 向 r1 通告到自身
    update = DVMessage(type='update', src=2, dst=1, seq=1, visited=[2], entries=[(2, 0, 1)])
    r1._process_update(update, 0.0)
    route = r1.get_route(2)
    assert route is not None
    assert route.next_hop == 2
    assert route.metric == 1
    print("Basic test passed")

if __name__ == "__main__":
    test_basic()