# tests/test_analytics_stats.py
"""
统计严谨性框架（starlink_sim.analytics.stats）单元测试。

全部使用合成小数据，秒级完成，不跑真实仿真、不依赖 data/ 拓扑缓存：
- bootstrap_ci：已知分布覆盖率、n_boot 下限守卫
- mannwhitney_test：显著/不显著判定、效应量方向
- paired_by_seed：同 seed → Wilcoxon；不重叠 → Mann-Whitney U 退回；全零差值退化
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
