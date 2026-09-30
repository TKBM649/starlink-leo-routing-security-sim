"""
starlink_sim/analytics
统计聚合与严谨性检验层。

公开 API 见 :mod:`starlink_sim.analytics.stats`：
- bootstrap_ci / mannwhitney_test / paired_by_seed
- describe_cardinality / check_comparable（trials 基数守卫）
- aggregate_experiment / compare_attack_vs_baseline（多种子聚合与匹配基线比较）
"""
from starlink_sim.analytics.stats import (
    DEFAULT_METRICS,
    MATCH_KEY_FIELDS,
    SMALL_SAMPLE_N,
    TrialsCardinalityError,
    aggregate_experiment,
    bootstrap_ci,
    cardinality_match_key,
    check_comparable,
    compare_attack_vs_baseline,
    describe_cardinality,
    extract_match_key,
    extract_metrics,
    mannwhitney_test,
    paired_by_seed,
)

__all__ = [
    'DEFAULT_METRICS', 'MATCH_KEY_FIELDS', 'SMALL_SAMPLE_N',
    'TrialsCardinalityError',
    'aggregate_experiment', 'bootstrap_ci', 'cardinality_match_key',
    'check_comparable', 'compare_attack_vs_baseline', 'describe_cardinality',
    'extract_match_key', 'extract_metrics', 'mannwhitney_test', 'paired_by_seed',
]
