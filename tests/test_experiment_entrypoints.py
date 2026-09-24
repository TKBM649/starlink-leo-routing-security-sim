# tests/test_experiment_entrypoints.py
"""
Issue #1 回归 / smoke 测试：

1) 保证实验入口依赖的关键符号可从 ``starlink_sim.net.simulator`` 导入
   （旧版缺失 ``Simulator``、``ControlPlane`` 无 ``attackers`` 参数会分别触发
   ImportError / TypeError）；
2) 保证两个实验入口脚本可被成功导入（其模块顶层 import 即复现旧崩溃点）；
3) 在极小拓扑上端到端跑通 ``Simulator.run``，检查命令产出结果字段齐全，
   并对比有/无攻击者，验证攻击确实改变结果（与 Issue #2 联动）。

不依赖 data/ 拓扑缓存，运行 < 数秒。
"""
import importlib.util
import inspect
import random
from pathlib import Path

import pytest

from starlink_sim.net.simulator import Simulator, ControlPlane, DataPlane

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_simulator_symbols_and_attackers_param():
    # Issue #1：Simulator 必须存在，控制面/数据面必须支持 attackers 参数
    assert 'attackers' in inspect.signature(ControlPlane.__init__).parameters
    assert 'attackers' in inspect.signature(DataPlane.__init__).parameters


@pytest.mark.parametrize("script", [
    "run_e2_jamming_experiment.py",
    "run_e3_blackhole_experiment.py",
])
def test_entry_scripts_import(script):
    # 导入入口脚本会执行其顶层 import，直接覆盖旧崩溃点（ImportError / 构造函数签名）
    path = PROJECT_ROOT / "scripts" / script
    assert path.exists()
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert hasattr(module, "run_experiment")


def _path_topology(num_nodes=8):
    edges = {(i, i + 1) for i in range(num_nodes - 1)}
    return [{(u, v) for u, v in edges}]  # 单 epoch 边集


def test_micro_simulator_attack_changes_result():
    random.seed(42)
    edge_sets = _path_topology(8)
    flows = [(0, 7)]

    # 无攻击基线
    base = Simulator(
        edge_sets=edge_sets, positions_per_epoch=None, num_nodes=8,
        tick_interval=0.2, attackers=[], flow_pairs=flows,
        epoch_duration=30.0, base_time=0.0,
    ).run(duration=40.0)

    # 在关键路径节点 4 放置黑洞（drop_prob=1.0 全程活跃）
    from starlink_sim.net.attack import BlackholeAttacker
    attacker = BlackholeAttacker(4, drop_prob=1.0, metric_fake=0,
                                 active_since=0.0, active_until=None)
    attacked = Simulator(
        edge_sets=edge_sets, positions_per_epoch=None, num_nodes=8,
        tick_interval=0.2, attackers=[attacker], flow_pairs=flows,
        epoch_duration=30.0, base_time=0.0,
    ).run(duration=40.0)

    # 结果字段齐全（Issue #1 验收：结果包含预期字段）
    expected = {
        'delivery_ratio', 'avg_hops', 'avg_latency_ms', 'avg_success_hops',
        'avg_success_latency_ms', 'num_success', 'num_trials',
        'attacked_count', 'dropped_by_attacker', 'total_loops', 'attacker_stats',
    }
    assert expected.issubset(attacked.keys()), f"缺少字段: {expected - set(attacked.keys())}"

    # 无攻击时应能路由到终点；有攻击（choke 节点丢弃）时交付率被压到 0
    assert base['delivery_ratio'] > 0.0
    assert attacked['delivery_ratio'] == 0.0
    assert attacked['dropped_by_attacker'] >= 1
    # 防双重计数回归：drop_prob=1.0 时每次吸引即丢弃，
    # 数据面只计一次 → attacked_count 应等于 dropped_by_attacker
    assert attacked['attacked_count'] == attacked['dropped_by_attacker']
    a0 = attacked['attacker_stats'][0]
    assert a0['attracted_count'] == a0['dropped_count'] == attacked['dropped_by_attacker']
