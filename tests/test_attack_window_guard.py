# tests/test_attack_window_guard.py
"""
攻击窗口守卫（``starlink_sim.net.placement`` 的 B3 部分）单元测试。

守卫职责：校验每个攻击者的 ``[active_since, active_until]`` 是否与数据面评估时刻
（``base_time + i*epoch_duration``）有重叠；若攻击在评估期**完全失活**（静默无效），
告警（``strict=False``）或报错（``strict=True``）。这正是 T7 发现的隐患：有限窗口
（如 20–40s）配上末 epoch 评估时，攻击者会在评估时刻之前/之后失活，实验测不到攻击效果。

纯逻辑、秒级。
"""
import pytest

from starlink_sim.net.placement import (
    evaluation_times,
    attack_window_overlaps,
    check_attack_windows,
)


# ==================== evaluation_times ====================

def test_evaluation_times_basic():
    assert evaluation_times(0.0, 3, 30.0) == [0.0, 30.0, 60.0]


def test_evaluation_times_with_base_offset():
    # 末窗口评估：base_time=60，2 个 epoch，间隔 30 → [60, 90]
    assert evaluation_times(60.0, 2, 30.0) == [60.0, 90.0]


def test_evaluation_times_zero_or_negative_count():
    assert evaluation_times(0.0, 0, 30.0) == []
    assert evaluation_times(0.0, -2, 30.0) == []


# ==================== attack_window_overlaps ====================

def test_persistent_window_always_overlaps():
    # active_until=None（常驻）→ 与任何评估时刻重叠
    assert attack_window_overlaps(0.0, None, [0.0, 30.0, 60.0]) is True
    assert attack_window_overlaps(None, None, [100.0]) is True  # active_since=None→0


def test_window_before_eval_times_no_overlap():
    # 攻击在评估开始前就结束 → 无重叠（静默失活）
    assert attack_window_overlaps(0.0, 20.0, [30.0, 60.0]) is False


def test_window_after_eval_times_no_overlap():
    # 攻击在评估全部结束后才激活 → 无重叠
    assert attack_window_overlaps(65.0, float('inf'), [0.0, 30.0, 60.0]) is False


def test_window_partially_covers_overlaps():
    # 至少覆盖一个评估时刻即算重叠（闭区间端点也算）
    assert attack_window_overlaps(0.0, 45.0, [0.0, 30.0, 60.0]) is True   # 覆盖 0,30
    assert attack_window_overlaps(30.0, 30.0, [0.0, 30.0, 60.0]) is True  # 端点 30
    assert attack_window_overlaps(50.0, 70.0, [0.0, 30.0, 60.0]) is True  # 覆盖 60


def test_empty_eval_times_no_overlap():
    assert attack_window_overlaps(0.0, None, []) is False


# ==================== check_attack_windows ====================

def _cfg(**kw):
    base = {'type': 'blackhole', 'count': 1, 'active_since': 0.0,
            'active_until': float('inf'), 'params': {}}
    base.update(kw)
    return base


def test_persistent_attacker_no_warning():
    warns = check_attack_windows([_cfg()], [0.0, 30.0, 60.0])
    assert warns == []


def test_deactivated_window_produces_warning():
    # 攻击窗口 [100,200] 与评估时刻 [0,30,60] 完全无重叠 → 1 条告警
    bad = _cfg(active_since=100.0, active_until=200.0)
    warns = check_attack_windows([bad], [0.0, 30.0, 60.0], strict=False)
    assert len(warns) == 1
    assert '完全失活' in warns[0]


def test_attack_starts_after_eval_window_warns():
    # active_since 晚于所有评估时刻（inf 结束也救不了）→ 告警
    bad = _cfg(active_since=65.0, active_until=float('inf'))
    warns = check_attack_windows([bad], [0.0, 30.0, 60.0])
    assert len(warns) == 1


def test_strict_mode_raises_on_deactivated():
    bad = _cfg(active_since=100.0, active_until=200.0)
    with pytest.raises(ValueError):
        check_attack_windows([bad], [0.0, 30.0, 60.0], strict=True)


def test_strict_mode_ok_for_persistent():
    # 常驻窗口在 strict 下也不应报错
    check_attack_windows([_cfg()], [0.0, 30.0], strict=True)


def test_zero_count_attacker_skipped():
    # count<=0 的攻击者不会真正实例化 → 即使窗口失活也不告警
    skipped = _cfg(count=0, active_since=100.0, active_until=200.0)
    assert check_attack_windows([skipped], [0.0, 30.0]) == []


def test_multiple_attackers_only_bad_flagged():
    good = _cfg(active_since=0.0, active_until=float('inf'))
    bad = _cfg(active_since=100.0, active_until=200.0)
    warns = check_attack_windows([good, bad], [0.0, 30.0, 60.0])
    assert len(warns) == 1
    assert '攻击者[1]' in warns[0]  # 索引指向失活的那条


def test_empty_eval_times_no_warnings():
    assert check_attack_windows([_cfg(active_since=100.0, active_until=200.0)], []) == []


def test_no_attackers_no_warnings():
    assert check_attack_windows([], [0.0, 30.0]) == []


def test_inf_active_until_normalized_in_message():
    # active_until=inf 归一为 None 参与判定；窗口 [65, inf) 对 [0,30,60] 仍失活
    bad = _cfg(active_since=65.0, active_until=float('inf'))
    warns = check_attack_windows([bad], [0.0, 30.0, 60.0])
    assert len(warns) == 1
    assert 'inf' in warns[0]
