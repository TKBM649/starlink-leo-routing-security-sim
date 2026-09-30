# tests/test_analytics_stats.py
"""
统计严谨性框架（starlink_sim.analytics.stats）单元测试。

全部使用合成小数据，秒级完成，不跑真实仿真、不依赖 data/ 拓扑缓存：
- bootstrap_ci：已知分布覆盖率、n_boot 下限守卫
- mannwhitney_test：显著/不显著判定、效应量方向
- paired_by_seed：同 seed → Wilcoxon；不重叠 → Mann-Whitney U 退回；全零差值退化
- signed_rank_biserial：配对效应量符号约定（>0 = 攻击臂更大）、并列平均秩、退化情形
- 符号修复的防回归护栏：修复**不改变** p 值与显著性判定（逐案对标 scipy 原值）
- describe_cardinality / check_comparable：trials 基数三元组与匹配键守卫
- aggregate_experiment：新版/E2 旧版/E3 旧版 raw JSON 兼容聚合
- compare_attack_vs_baseline：匹配键一致 → 配对比较；不一致 → 拒绝
- run_simulation.run_one_seed：极小合成拓扑端到端产出合规 raw 记录
"""
import importlib.util
import json
from pathlib import Path

import numpy as np
import pytest

from starlink_sim.analytics import stats as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ==================== bootstrap_ci ====================

def test_bootstrap_ci_coverage_on_known_distribution():
    """正态样本均值的 95% percentile CI，300 次重复覆盖率应 >= 0.80（理论 ~0.95）。"""
    rng = np.random.default_rng(7)
    true_mean = 5.0
    covered = 0
    reps = 300
    for i in range(reps):
        sample = rng.normal(true_mean, 2.0, size=30)
        res = st.bootstrap_ci(sample, n_boot=2000, alpha=0.05, rng=i)
        assert res['ci_low'] <= res['ci_high']
        if res['ci_low'] <= true_mean <= res['ci_high']:
            covered += 1
    assert covered / reps >= 0.80


def test_bootstrap_ci_point_estimate_and_reproducible():
    values = [1.0, 2.0, 3.0, 4.0, 100.0]
    r1 = st.bootstrap_ci(values, n_boot=2000, rng=42)
    r2 = st.bootstrap_ci(values, n_boot=2000, rng=42)
    assert r1['point_estimate'] == pytest.approx(np.mean(values))
    assert (r1['ci_low'], r1['ci_high']) == (r2['ci_low'], r2['ci_high'])
    assert r1['confidence_level'] == pytest.approx(0.95)
    # 中位数统计量也应可用
    r3 = st.bootstrap_ci(values, stat=np.median, n_boot=2000, rng=0)
    assert r3['point_estimate'] == pytest.approx(3.0)


def test_bootstrap_ci_guards():
    with pytest.raises(ValueError, match='n_boot'):
        st.bootstrap_ci([1, 2, 3], n_boot=100)
    with pytest.raises(ValueError):
        st.bootstrap_ci([])
    with pytest.raises(ValueError):
        st.bootstrap_ci([1.0, np.nan])
    # 小样本告警
    res = st.bootstrap_ci([1.0, 2.0, 3.0], n_boot=2000, rng=0)
    assert any('仅供参考' in w for w in res['warnings'])


# ==================== mannwhitney_test ====================

def test_mannwhitney_significant_and_not():
    rng = np.random.default_rng(1)
    a = rng.normal(0.9, 0.05, size=12)   # 攻击臂：交付率被压低
    b = rng.normal(0.5, 0.05, size=12)   # 基线臂
    res = st.mannwhitney_test(a, b)
    assert res['test'] == 'mannwhitneyu'
    assert res['p_value'] < 0.05
    assert res['significant'] is True
    # a > b → rank-biserial 为正（>0 表示攻击组更大）
    assert res['effect_size']['rank_biserial'] > 0.5
    assert res['median_diff'] > 0

    # 不显著：两组完全重叠（确定性数据，不依赖 RNG 抽样运气）
    same_vals = [0.50, 0.51, 0.49, 0.52, 0.48, 0.50, 0.51, 0.49, 0.50, 0.52, 0.48, 0.51]
    res2 = st.mannwhitney_test(same_vals, list(same_vals))
    assert res2['significant'] is False
    assert res2['p_value'] >= 0.05


def test_mannwhitney_degenerate_all_equal():
    res = st.mannwhitney_test([0.5] * 6, [0.5] * 6)
    assert res['p_value'] == 1.0
    assert res['significant'] is False
    assert res['warnings']


# ==================== paired_by_seed ====================

def test_paired_by_seed_wilcoxon_when_seeds_match():
    base = {s: 0.95 - 0.01 * (s % 3) for s in range(42, 54)}          # 12 seeds
    atk = {s: v - 0.30 for s, v in base.items()}                       # 一致压低 0.30
    res = st.paired_by_seed(atk, base)
    assert res['test'] == 'wilcoxon'
    assert res['n_pairs'] == 12
    assert res['p_value'] < 0.05
    assert res['significant'] is True
    assert res['median_diff'] == pytest.approx(-0.30, abs=1e-9)
    assert res['effect_size']['rank_biserial'] < 0  # 攻击组更小


def test_paired_by_seed_fallback_mannwhitney_when_disjoint():
    atk = {1: 0.6, 2: 0.62, 3: 0.58, 4: 0.61, 5: 0.59, 6: 0.63}
    base = {7: 0.95, 8: 0.94, 9: 0.96, 10: 0.93, 11: 0.95, 12: 0.97}
    res = st.paired_by_seed(atk, base)
    assert res['test'] == 'mannwhitneyu'
    assert res['n_pairs'] == 0
    assert res['significant'] is True
    assert any('退回' in w for w in res['warnings'])


def test_paired_by_seed_partial_overlap_and_zero_diff():
    atk = {1: 0.6, 2: 0.5, 3: 0.7, 4: 0.65}
    base = {3: 0.9, 4: 0.95, 5: 0.9}
    res = st.paired_by_seed(atk, base)
    assert res['test'] == 'wilcoxon'
    assert res['n_pairs'] == 2
    assert res['paired_seeds'] == [3, 4]
    assert any('丢弃' in w for w in res['warnings'])

    same = {1: 0.9, 2: 0.8}
    res2 = st.paired_by_seed(same, dict(same))
    assert res2['p_value'] == 1.0
    assert res2['significant'] is False
    assert any('差值为 0' in w for w in res2['warnings'])


# ==================== 配对效应量符号约定（防回归）====================
#
# 为什么这一组测试存在：scipy >= 1.7 起
# ``wilcoxon(diff, alternative='two-sided').statistic`` 返回的是 **min(T+, T-)**
# 而不是 T+，全部配对差值同号时它恒为 0，与「攻击臂全面更小」和「攻击臂
# 全面更大」两种相反情形不可区分（实测 scipy 1.15.3：wilcoxon([1,2]).statistic == 0.0
# 且 wilcoxon([-1,-2]).statistic == 0.0）。旧实现把该值当作 T+ 代入 r=(2V-T)/T，
# 导致配对效应量符号失效且幅度饱和（恒为 -1），与 median_diff 方向矛盾。
# 实例：step3 的 e6_wormhole/t3 delivery_ratio median_diff=+0.0500 但旧 rank_biserial=-1.000。
# 修复：stats.signed_rank_biserial 直接从配对差值重算 T+，作为**单一实现点**。
# 下面钉住三件事：① 符号方向 ② 并列平均秩 ③ **p 值与显著性判定零变化**。

_SEEDS_10 = list(range(42, 52))
_BASE_DR = {s: 0.8950 for s in _SEEDS_10}      # step3 基线实测值
_UP_DR = {s: 0.9450 for s in _SEEDS_10}        # e6_wormhole/t3 实测值（高于基线）
_DN_DR = {s: 0.0450 for s in _SEEDS_10}        # e4_sybil/ids1 实测值（低于基线）


def test_signed_rank_biserial_direction_and_magnitude():
    """符号约定：攻击臂严格更大 → r>0；严格更小 → r<0；对称 → r≈0。"""
    r_up = st.signed_rank_biserial(_UP_DR, _BASE_DR)
    assert r_up['rank_biserial_signed'] > 0
    assert r_up['rank_biserial_signed'] == pytest.approx(1.0)
    assert r_up['t_plus'] == pytest.approx(55.0)          # T = 10·11/2
    assert r_up['n_eff'] == 10
    assert r_up['rb_note'] == ''

    r_dn = st.signed_rank_biserial(_DN_DR, _BASE_DR)
    assert r_dn['rank_biserial_signed'] < 0
    assert r_dn['rank_biserial_signed'] == pytest.approx(-1.0)
    assert r_dn['t_plus'] == pytest.approx(0.0)
    assert r_dn['n_eff'] == 10

    # 两种相反情形必须可区分（scipy 的 min(T+,T-) 统计量做不到这点）
    assert r_up['rank_biserial_signed'] == pytest.approx(-r_dn['rank_biserial_signed'])

    # 对称样本 A：一半 seed 抬高、一半压低，|差值| 全相等（全并列）
    # → 每个差值都拿到平均秩 (1+10)/2 = 5.5，T+ = 5×5.5 = 27.5 = T/2 → r = 0
    half = dict(_BASE_DR)
    for i, s in enumerate(sorted(_BASE_DR)):
        half[s] = _BASE_DR[s] + (0.30 if i % 2 == 0 else -0.30)
    r_half = st.signed_rank_biserial(half, _BASE_DR)
    assert r_half['rank_biserial_signed'] == pytest.approx(0.0)
    assert r_half['t_plus'] == pytest.approx(27.5)

    # 对称样本 B：|差值| = 0.1/0.2/0.3/0.4，正负号安排使 T+ = 1+4 = 5 = T/2 → r = 0
    sym_base = {1: 0.90, 2: 0.80, 3: 0.70, 4: 0.60}
    sym_atk = {1: 1.00, 2: 0.60, 3: 0.40, 4: 1.00}      # 差值 +0.1, -0.2, -0.3, +0.4
    r_sym = st.signed_rank_biserial(sym_atk, sym_base)
    assert r_sym['rank_biserial_signed'] == pytest.approx(0.0)
    assert r_sym['t_plus'] == pytest.approx(5.0)
    assert r_sym['n_eff'] == 4


def test_signed_rank_biserial_ties_use_average_rank():
    """并列（|差值| 相等）必须取平均秩，否则 T+ 会依赖输入顺序而不可复现。"""
    base = {1: 1.0, 2: 1.0, 3: 1.0, 4: 1.0, 5: 1.0}
    # 差值：+0.5, -0.5, -0.5, +2.0, 0.0（seed5 为零，不参与赋秩）
    # n_eff=4 → |差值| 升序为 [0.5, 0.5, 0.5, 2.0]，前三位并列取平均秩 (1+2+3)/3 = 2，
    # 第四位秩 4；T = 4·5/2 = 10；T+ = 2 + 4 = 6 → r = (2·6 - 10)/10 = 0.2
    # （若错误地不取平均秩，T+ 会变成 1+4=5 → r=0.0，下面断言就能拦住）
    atk = {1: 1.5, 2: 0.5, 3: 0.5, 4: 3.0, 5: 1.0}
    r = st.signed_rank_biserial(atk, base)
    assert r['n_eff'] == 4
    assert r['t_plus'] == pytest.approx(6.0)
    assert r['rank_biserial_signed'] == pytest.approx(0.2)

    # 打乱 dict 插入顺序不得改变结果 → 证明确实按 |差值| 赋秩而非按位置
    order = [5, 3, 1, 4, 2]
    r2 = st.signed_rank_biserial({k: atk[k] for k in order},
                                {k: base[k] for k in order})
    assert r2['t_plus'] == pytest.approx(r['t_plus'])
    assert r2['rank_biserial_signed'] == pytest.approx(r['rank_biserial_signed'])


def test_signed_rank_biserial_degenerate_zero_diff():
    """退化情形：全零差值 / 无共有 seed → r=0、T+=0、n_eff=0 并给出说明。"""
    same = {s: 0.9 for s in _SEEDS_10}
    r = st.signed_rank_biserial(same, dict(same))
    assert r['rank_biserial_signed'] == 0.0
    assert r['t_plus'] == 0.0
    assert r['n_eff'] == 0
    assert r['rb_note']                       # 必须如实标注而不是默默返回 0

    r2 = st.signed_rank_biserial({1: 0.9, 2: 0.8}, {3: 0.5, 4: 0.4})
    assert r2['n_eff'] == 0
    assert r2['rank_biserial_signed'] == 0.0

    # 部分差值为 0：只有非零差值参与赋秩（seed1 差值 0 被排除）
    r3 = st.signed_rank_biserial({1: 0.9, 2: 0.8, 3: 0.5}, {1: 0.9, 2: 0.6, 3: 0.1})
    assert r3['n_eff'] == 2
    assert r3['t_plus'] == pytest.approx(3.0)          # 秩 1(|0.2|) + 秩 2(|0.4|)
    assert r3['rank_biserial_signed'] == pytest.approx(1.0)


def test_paired_by_seed_sign_follows_median_diff_direction():
    """paired_by_seed 的效应量符号必须与 median_diff 同号（钉住 e6/t3 方向矛盾案例）。"""
    res_up = st.paired_by_seed(_UP_DR, _BASE_DR)
    assert res_up['test'] == 'wilcoxon'
    assert res_up['median_diff'] > 0
    assert res_up['effect_size']['rank_biserial'] > 0        # 修复前恒为 -1.0
    assert res_up['effect_size']['rank_biserial'] == pytest.approx(1.0)
    assert res_up['effect_size']['t_plus'] == pytest.approx(55.0)
    assert res_up['effect_size']['n_eff'] == 10

    res_dn = st.paired_by_seed(_DN_DR, _BASE_DR)
    assert res_dn['median_diff'] < 0
    assert res_dn['effect_size']['rank_biserial'] < 0
    assert res_dn['effect_size']['rank_biserial'] == pytest.approx(-1.0)

    # scipy 的 statistic 在两种相反情形下完全相同（都是 0.0）—— 这就是旧 bug 的根源，
    # 也是为什么效应量必须另行重算而不能取自 statistic。
    assert res_up['statistic'] == res_dn['statistic'] == pytest.approx(0.0)
    assert 'min(T+, T-)' in res_up['statistic_semantics']
    # 但修复后的效应量必须能区分两者
    assert (res_up['effect_size']['rank_biserial']
            == pytest.approx(-res_dn['effect_size']['rank_biserial']))

    # 单一实现点：paired_by_seed 与 signed_rank_biserial 必须给出同一数值
    direct = st.signed_rank_biserial(_UP_DR, _BASE_DR)
    assert res_up['effect_size']['rank_biserial'] == pytest.approx(
        direct['rank_biserial_signed'])

    # 混合方向：符号跟随差值中位数（T+ = 5×8 = 40，T = 55 → r = +0.4545）
    deltas = [+0.4, -0.1] * 5
    mix = {s: _BASE_DR[s] + d for s, d in zip(_SEEDS_10, deltas)}
    res_mix = st.paired_by_seed(mix, _BASE_DR)
    assert res_mix['median_diff'] > 0
    assert res_mix['effect_size']['rank_biserial'] > 0
    assert res_mix['effect_size']['rank_biserial'] == pytest.approx(0.4545454545, rel=1e-6)
    assert np.sign(res_mix['median_diff']) == np.sign(res_mix['effect_size']['rank_biserial'])

    # 全零差值退化分支：也必须带上审计字段
    res_zero = st.paired_by_seed(_BASE_DR, dict(_BASE_DR))
    assert res_zero['effect_size']['rank_biserial'] == 0.0
    assert res_zero['effect_size']['t_plus'] == 0.0
    assert res_zero['effect_size']['n_eff'] == 0
    assert res_zero['effect_size']['note']


def test_paired_by_seed_sign_fix_does_not_change_p_value():
    """**防回归护栏**：修复只补正效应量，p 值 / statistic / significant 必须逐位不变。

    逐案直接对标 scipy 双侧 Wilcoxon 的原值（那就是修复前 paired_by_seed 用的
    同一来源），并钉住几个可手算的精确 p：n 个全同号差值的最小双侧 p = 2/2ⁿ。
    """
    from scipy import stats as sps

    mix = {s: _BASE_DR[s] + d for s, d in zip(_SEEDS_10, [+0.4, -0.1] * 5)}
    with_zeros = {s: (_BASE_DR[s] - 0.30 if s % 3 else _BASE_DR[s]) for s in _SEEDS_10}
    ranked = {s: _BASE_DR[s] - 0.05 * (i + 1) for i, s in enumerate(_SEEDS_10)}
    cases = {
        'all_lower_n10': (_DN_DR, _BASE_DR),
        'all_higher_n10': (_UP_DR, _BASE_DR),
        'mixed_n10': (mix, _BASE_DR),
        'with_zeros_n10': (with_zeros, _BASE_DR),
        'graded_n10': (ranked, _BASE_DR),
        'all_higher_n5': ({s: 0.945 for s in range(42, 47)},
                          {s: 0.895 for s in range(42, 47)}),
        'all_higher_n4': ({s: 0.945 for s in range(42, 46)},
                          {s: 0.895 for s in range(42, 46)}),
        'all_zero_n10': (dict(_BASE_DR), _BASE_DR),
        'partial_overlap': ({3: 0.7, 4: 0.65, 9: 0.1}, {3: 0.9, 4: 0.95, 5: 0.9}),
    }
    for name, (atk, base) in cases.items():
        res = st.paired_by_seed(atk, base)
        shared = sorted(set(atk) & set(base))
        diff = np.array([atk[s] - base[s] for s in shared], dtype=float)
        if diff.size == 0 or np.allclose(diff, 0.0):
            # 退化分支：不进入 scipy，固定为 p=1.0 不显著
            assert res['p_value'] == 1.0, name
            assert res['significant'] is False, name
            continue
        ref = None
        try:
            ref = sps.wilcoxon(diff, alternative='two-sided')
        except ValueError:
            # 与 paired_by_seed 内部的退回分支保持完全一致（n 太小时精确法不可用）
            ref = sps.wilcoxon(diff, alternative='two-sided', mode='approx')
        assert res['p_value'] == pytest.approx(float(ref.pvalue), rel=1e-12, abs=0.0), name
        assert res['statistic'] == pytest.approx(float(ref.statistic), rel=1e-12, abs=0.0), name
        assert res['significant'] is bool(float(ref.pvalue) < 0.05), name

    # 可手算的精确 p 值（证明显著性判定行为本来就是正确的，修复不得改变它）
    assert st.paired_by_seed(_DN_DR, _BASE_DR)['p_value'] == pytest.approx(2 / 2 ** 10)
    assert st.paired_by_seed(_UP_DR, _BASE_DR)['p_value'] == pytest.approx(2 / 2 ** 10)
    assert st.paired_by_seed(_UP_DR, _BASE_DR)['significant'] is True
    n5_a = {s: 0.945 for s in range(42, 47)}
    n5_b = {s: 0.895 for s in range(42, 47)}
    assert st.paired_by_seed(n5_a, n5_b)['p_value'] == pytest.approx(2 / 2 ** 5)
    # n=5 全同号时 p=0.0625 > 0.05 → 不显著（方向正确但样本不足），修复后仍如此
    assert st.paired_by_seed(n5_a, n5_b)['significant'] is False
    assert st.paired_by_seed(n5_a, n5_b)['effect_size']['rank_biserial'] == pytest.approx(1.0)


def test_mannwhitney_sign_convention_unchanged():
    """非配对路径（Mann-Whitney U）符号本来就正确，本次修复未动它。"""
    a_hi = [0.90, 0.91, 0.92, 0.93, 0.94, 0.95]
    a_lo = [0.10, 0.11, 0.12, 0.13, 0.14, 0.15]
    b = [0.50, 0.51, 0.52, 0.53, 0.54, 0.55]
    r_hi = st.mannwhitney_test(a_hi, b)
    r_lo = st.mannwhitney_test(a_lo, b)
    # scipy U₁ = #{a_i > b_j} + ½ties；a 全大于 b 时 U₁ = 36 = n1·n2
    assert r_hi['U'] == pytest.approx(36.0)
    assert r_hi['effect_size']['rank_biserial'] == pytest.approx(1.0)
    assert r_hi['median_diff'] > 0
    assert r_lo['U'] == pytest.approx(0.0)
    assert r_lo['effect_size']['rank_biserial'] == pytest.approx(-1.0)
    assert r_lo['median_diff'] < 0


def test_paired_and_unpaired_sign_conventions_agree():
    """同一批数值下，配对（Wilcoxon）与非配对（MWU）两条路径的符号必须一致。"""
    atk_vals = [0.9450] * 10
    base_vals = [0.8950] * 10
    seeds_a = list(range(42, 52))
    seeds_b = list(range(100, 110))       # 与攻击臂完全不重叠 → 退回 MWU
    paired = st.paired_by_seed(dict(zip(seeds_a, atk_vals)),
                              dict(zip(seeds_a, base_vals)))
    unpaired = st.paired_by_seed(dict(zip(seeds_a, atk_vals)),
                                dict(zip(seeds_b, base_vals)))
    assert paired['test'] == 'wilcoxon'
    assert unpaired['test'] == 'mannwhitneyu'
    assert paired['effect_size']['rank_biserial'] == pytest.approx(
        unpaired['effect_size']['rank_biserial'])
    assert paired['median_diff'] == pytest.approx(unpaired['median_diff'])
    assert paired['effect_size']['rank_biserial'] > 0


# ==================== trials 基数 / 匹配键 ====================

def test_describe_cardinality_semantics():
    card = st.describe_cardinality(num_flows=100, num_eval_epochs=121,
                                   trials_per_flow_epoch=1, total_trials=12100)
    assert card['total_trials'] == 12100
    assert set(card['match_key'].keys()) == set(st.MATCH_KEY_FIELDS)
    # 三元组乘积与 total_trials 不一致 → 必须拦截
    with pytest.raises(st.TrialsCardinalityError):
        st.describe_cardinality(num_flows=100, num_eval_epochs=4,
                                trials_per_flow_epoch=1, total_trials=12100)


def test_check_comparable_rejects_mismatch():
    e1 = st.describe_cardinality(100, 121, 1, 12100)
    e1['match_key'] = st.cardinality_match_key('53°', None, 121, 100)
    e3 = st.describe_cardinality(100, 1, 1, 100)
    e3['match_key'] = st.cardinality_match_key('53°', None, 1, 100)
    # E1 全量基线 vs E3 单 epoch：必须拒绝
    with pytest.raises(st.TrialsCardinalityError):
        st.check_comparable(e1, e3, raise_on_mismatch=True)
    res = st.check_comparable(e1, e3, raise_on_mismatch=False)
    assert res['comparable'] is False
    assert any(m['field'] == 'num_eval_epochs' for m in res['mismatches'])
    # 匹配键一致 → 可比
    same = st.describe_cardinality(100, 121, 1, 12100)
    same['match_key'] = st.cardinality_match_key('53°', None, 121, 100)
    assert st.check_comparable(e1, same)['comparable'] is True


# ==================== raw JSON 构造工具 ====================

def _write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False)


def _new_format_record(seed, dr, name='e1_baseline', shell='53°', node_limit=None,
                       num_flows=100, num_epochs=121):
    """新版 schema（run_simulation.py 产出格式）"""
    return {
        'schema_version': 2,
        'experiment': name,
        'seed': seed,
        'metadata': {'seed': seed, 'shell': shell, 'node_limit': node_limit,
                     'num_flows': num_flows, 'num_eval_epochs': num_epochs,
                     'trials_per_flow_epoch': 1,
                     'total_trials': num_flows * num_epochs},
        'config_snapshot': {},
        'config': {'experiment': {'name': name, 'duration': num_epochs * 30},
                   'topology': {'shell': shell, 'node_limit': node_limit,
                                'epoch_interval': 30},
                   'traffic': {'num_flows': num_flows},
                   'routing': {'t_adv': 2.0, 'tick': 0.2, 'max_hops': 100}},
        'control_stats': {'total_loops': 10 + seed, 'loop_paths_count': 10 + seed},
        'data_stats': {'delivery_ratio': dr, 'avg_hops': 8.0, 'avg_latency_ms': 130.0,
                       'avg_success_hops': 8.0, 'avg_success_latency_ms': 130.0,
                       'num_success': int(dr * num_flows * num_epochs),
                       'num_trials': num_flows * num_epochs,
                       'attacked_count': 0, 'dropped_by_attacker': 0},
    }


# ==================== aggregate_experiment ====================

def test_aggregate_experiment_new_format(tmp_path):
    files = []
    drs = [0.98, 0.99, 1.0]
    for i, seed in enumerate([42, 43, 44]):
        p = tmp_path / f"e1_baseline_seed{seed}.json"
        _write_json(p, _new_format_record(seed, drs[i]))
        files.append(p)
    agg = st.aggregate_experiment(str(tmp_path / "e1_baseline_seed*.json"), rng=0)
    assert agg['n_seeds'] == 3
    assert agg['seeds'] == [42, 43, 44]
    dr = agg['metrics']['delivery_ratio']
    assert dr['mean'] == pytest.approx(np.mean(drs))
    assert dr['ci95_low'] <= dr['mean'] <= dr['ci95_high']
    assert dr['per_seed'][42] == pytest.approx(0.98)
    # trials 基数：12100 = 100 × 121 × 1，匹配键完整且跨 seed 一致
    card = agg['cardinality']
    assert card['detail']['total_trials'] == 12100
    assert card['consistent_across_seeds'] is True
    assert card['match_key'] == {'shell': '53°', 'node_limit': None,
                                 'num_eval_epochs': 121, 'num_flows': 100}
    # n=3 小样本告警
    assert any('仅供参考' in w for w in agg['warnings'])
    # total_loops 从 control_stats 提取
    assert agg['metrics']['total_loops']['mean'] == pytest.approx(np.mean([52, 53, 54]))


def test_aggregate_experiment_legacy_e2_and_e3(tmp_path):
    # E2 旧版：指标平铺 + config 快照，num_trials=400 → epochs=400/100=4
    e2 = {'delivery_ratio': 0.775, 'avg_hops': 2.7, 'avg_latency_ms': 0.0,
          'avg_success_hops': 3.4, 'avg_success_latency_ms': 0.0,
          'num_success': 310, 'num_trials': 400, 'attacked_count': 179,
          'dropped_by_attacker': 0, 'total_loops': 47, 'seed': 42,
          'config': {'experiment': {'name': 'e2_jamming', 'duration': 120},
                     'topology': {'shell': '53°', 'node_limit': 96, 'epoch_interval': 30},
                     'traffic': {'num_flows': 100}, 'routing': {}}}
    _write_json(tmp_path / 'e2_jamming_seed42.json', e2)
    agg2 = st.aggregate_experiment(str(tmp_path / "e2_jamming_seed*.json"), rng=0)
    key2 = agg2['cardinality']['match_key']
    assert key2 == {'shell': '53°', 'node_limit': 96, 'num_eval_epochs': 4, 'num_flows': 100}

    # E3 旧版：data_stats/control_stats 嵌套、无 config → 匹配键字段缺失但可聚合
    e3 = {'seed': 42,
          'control_stats': {'total_loops': 100122, 'loop_paths_count': 100122},
          'data_stats': {'delivery_ratio': 0.83, 'avg_hops': 6.7, 'avg_latency_ms': 94.6,
                         'avg_success_hops': 8.0, 'avg_success_latency_ms': 114.0,
                         'num_success': 83, 'num_trials': 100,
                         'attacked_count': 18, 'dropped_by_attacker': 17},
          'attacker_stats': []}
    _write_json(tmp_path / 'attack_e3_blackhole_seed42.json', e3)
    agg3 = st.aggregate_experiment(str(tmp_path / "attack_e3_*_seed*.json"), rng=0)
    assert agg3['metrics']['delivery_ratio']['mean'] == pytest.approx(0.83)
    assert agg3['metrics']['total_loops']['mean'] == pytest.approx(100122)
    # num_flows 未知 → epochs 无法反推，须给出补齐提示
    assert agg3['cardinality']['match_key']['num_eval_epochs'] is None
    assert any('match_key_overrides' in w for w in agg3['warnings'])
    # overrides 补齐后匹配键完整（E3 已知为全量单 epoch 100 flows）
    agg3b = st.aggregate_experiment(str(tmp_path / "attack_e3_*_seed*.json"), rng=0,
                                    match_key_overrides={'shell': '53°', 'node_limit': None,
                                                         'num_flows': 100, 'num_eval_epochs': 1})
    assert agg3b['cardinality']['match_key'] == {'shell': '53°', 'node_limit': None,
                                                 'num_eval_epochs': 1, 'num_flows': 100}
    assert agg3b['cardinality']['detail']['total_trials'] == 100


# ==================== compare_attack_vs_baseline ====================

def test_compare_matched_keys_pairs_by_seed(tmp_path):
    atk_files, base_files = [], []
    for seed, dr_a, dr_b in [(42, 0.62, 0.97), (43, 0.60, 0.98), (44, 0.65, 0.96),
                             (45, 0.61, 0.97), (46, 0.63, 0.95), (47, 0.59, 0.98)]:
        pa = tmp_path / f"atk_seed{seed}.json"
        pb = tmp_path / f"base_seed{seed}.json"
        _write_json(pa, _new_format_record(seed, dr_a, name='atk', node_limit=96, num_epochs=4))
        _write_json(pb, _new_format_record(seed, dr_b, name='base', node_limit=96, num_epochs=4))
        atk_files.append(pa)
        base_files.append(pb)
    cmp = st.compare_attack_vs_baseline(
        str(tmp_path / "atk_seed*.json"), str(tmp_path / "base_seed*.json"))
    assert cmp['n_comparable_groups'] == 1
    g = cmp['groups'][0]
    assert g['comparable'] is True
    assert g['paired_seeds'] == [42, 43, 44, 45, 46, 47]
    dr = g['comparisons']['delivery_ratio']
    assert dr['test'] == 'wilcoxon'
    assert dr['significant'] is True
    assert dr['median_diff'] < 0


def test_compare_rejects_cardinality_mismatch(tmp_path):
    """E1 全量 121-epoch 基线 vs 单 epoch 攻击臂：无共享匹配键 → 拒绝比较。"""
    pa = tmp_path / "atk_seed42.json"
    pb = tmp_path / "base_seed42.json"
    _write_json(pa, _new_format_record(42, 0.83, name='atk', node_limit=None, num_epochs=1))
    _write_json(pb, _new_format_record(42, 1.00, name='base', node_limit=None, num_epochs=121))
    with pytest.raises(st.TrialsCardinalityError):
        st.compare_attack_vs_baseline(str(tmp_path / "atk_seed*.json"),
                                      str(tmp_path / "base_seed*.json"), strict=True)
    # 非严格模式：返回不可比标记而非抛错
    cmp = st.compare_attack_vs_baseline(str(tmp_path / "atk_seed*.json"),
                                        str(tmp_path / "base_seed*.json"), strict=False)
    assert cmp['n_comparable_groups'] == 0
    assert all(not g.get('comparable') for g in cmp['groups'])


# ==================== run_simulation.run_one_seed 端到端（合成极小拓扑） ====================

def _load_run_simulation_module():
    path = PROJECT_ROOT / 'scripts' / 'run_simulation.py'
    spec = importlib.util.spec_from_file_location('run_simulation_t6', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tiny_config(name='e1_tiny', duration=40.0, num_flows=4, node_limit=None):
    """与 load_experiment_config 输出同构的极小配置。"""
    return {
        'experiment': {'name': name, 'duration': duration, 'seed': None},
        'topology': {'shell': '53°', 'epoch_interval': 30.0, 'node_limit': node_limit,
                     'cache_path': 'nonexistent_cache.pkl', 'positions_cache': None},
        'routing': {'t_adv': 2.0, 'tick': 0.2, 'max_hops': 100},
        'traffic': {'num_flows': num_flows},
        'attack': {'attackers': []},
        'output': {'raw_dir': 'results/raw/', 'agg_dir': 'results/aggregated/',
                   'figures_dir': 'results/figures/'},
    }


def test_run_one_seed_produces_compliant_record():
    rs = _load_run_simulation_module()
    n = 10
    edges = [{(i, i + 1) for i in range(n - 1)}]  # 单 epoch 路径拓扑
    node_ids = list(range(n))
    config = _tiny_config()
    rec = rs.run_one_seed(42, config, edges, None, node_ids)

    # 结构合规：schema_version / metadata / config 快照 / 基数三元组
    assert rec['schema_version'] == 2
    assert rec['seed'] == 42
    md = rec['metadata']
    assert md['seed'] == 42
    assert md['num_flows'] == 4
    assert md['num_eval_epochs'] == 1          # duration 40s // 30s = 1 epoch
    assert md['trials_per_flow_epoch'] == 1
    assert md['total_trials'] == 4 == rec['data_stats']['num_trials']
    assert md['shell'] == '53°'
    assert 'timestamp_utc' in md and 't0' in md
    assert rec['config_snapshot'] == config
    assert rec['experiment'] == 'e1_tiny'
    # JSON 可序列化（numpy 标量已转换）
    json.dumps(rec, ensure_ascii=False)
    # 统计框架能直接消费该记录：匹配键完整
    card = st.extract_match_key(rec)
    assert card['match_key'] == {'shell': '53°', 'node_limit': None,
                                 'num_eval_epochs': 1, 'num_flows': 4}
    # 路径拓扑无攻击 → 全部可达
    assert rec['data_stats']['delivery_ratio'] == pytest.approx(1.0)


def test_run_one_seed_seed_drives_flows():
    rs = _load_run_simulation_module()
    n = 30
    edges = [{(i, (i + 1) % n) for i in range(n)}]  # 环
    node_ids = list(range(n))
    r1 = rs.run_one_seed(42, _tiny_config(num_flows=8), edges, None, node_ids)
    r2 = rs.run_one_seed(43, _tiny_config(num_flows=8), edges, None, node_ids)
    r1b = rs.run_one_seed(42, _tiny_config(num_flows=8), edges, None, node_ids)
    assert r1['flows'] != r2['flows']    # 不同 seed → 不同 flows（旧版硬编码 seed=42 的替换）
    assert r1['flows'] == r1b['flows']   # 同 seed → 可复现
