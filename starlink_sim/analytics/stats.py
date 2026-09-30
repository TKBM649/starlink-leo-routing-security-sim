"""
starlink_sim/analytics/stats.py
统计严谨性框架：bootstrap CI、假设检验、trials 基数可比性守卫、多种子聚合。

方法学约定
==========
1. **trials 基数语义**（跨实验可比性的根源问题）：
       total_trials = num_flows × num_eval_epochs × trials_per_flow_epoch
   其中 trials_per_flow_epoch 为每个 (flow, epoch) 组合的试验次数（当前实现恒为 1）。
   历史数据不可比的根源：E1=12100（4284 节点全量 × 121 epoch × 100 flows）、
   E2=400（96 节点子集 × 4 epoch × 100 flows）、E3=100（全量 × 1 epoch × 100 flows）。

2. **匹配基线原则**：攻击臂只能与"同 shell / 同 node_limit / 同评估 epoch 数 /
   同 flow 数"（即匹配键一致）的 no-attack 基线臂做**按 seed 配对**比较，
   严禁拿 E1 全量基线去比 E3 单 epoch 攻击臂。匹配键不一致时
   :func:`compare_attack_vs_baseline` 抛出 ``ValueError`` 拒绝比较。

3. **检验选择**：同 seed 成对时优先 Wilcoxon signed-rank 配对检验
   （消除 seed 间共同随机性——同 seed 使用相同 flows/攻击者布点）；
   无法配对（seed 不重叠）时退回双侧 Mann-Whitney U。效应量报告
   rank-biserial 相关系数与中位数差。

4. **小样本告警**：n < :data:`SMALL_SAMPLE_N`（默认 10）时照常计算，
   但在输出 warnings 中标注"n 偏小，CI/检验仅供参考"。

依赖：numpy（bootstrap）、scipy.stats（mannwhitneyu / wilcoxon）。
"""
from __future__ import annotations

import glob as _glob
import json
import warnings
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Union

import numpy as np
from scipy import stats as _sps

__all__ = [
    'SMALL_SAMPLE_N',
    'MATCH_KEY_FIELDS',
    'DEFAULT_METRICS',
    'TrialsCardinalityError',
    'bootstrap_ci',
    'mannwhitney_test',
    'paired_by_seed',
    'describe_cardinality',
    'cardinality_match_key',
    'check_comparable',
    'extract_metrics',
    'extract_match_key',
    'aggregate_experiment',
    'compare_attack_vs_baseline',
]

# n 小于该值时输出"仅供参考"告警（框架不假设固定 seed 数，>=10 seeds 为推荐规模）
SMALL_SAMPLE_N = 10

# 匹配键字段：攻击臂与基线臂必须逐项一致才允许配对比较
MATCH_KEY_FIELDS = ('shell', 'node_limit', 'num_eval_epochs', 'num_flows')

# 聚合默认覆盖的指标（缺失自动跳过）
DEFAULT_METRICS = (
    'delivery_ratio', 'avg_hops', 'avg_latency_ms',
    'avg_success_hops', 'avg_success_latency_ms',
    'total_loops', 'attacked_count', 'dropped_by_attacker',
    'num_success', 'num_trials',
)


class TrialsCardinalityError(ValueError):
    """trials 基数 / 匹配键不一致，拒绝跨基数比较。"""


# ==================== 基础工具 ====================

def _to_float_array(values: Union[Sequence[float], np.ndarray], name: str = 'values') -> np.ndarray:
    arr = np.asarray(values, dtype=float).ravel()
    if arr.size == 0:
        raise ValueError(f"{name} 不能为空")
    if not np.all(np.isfinite(arr)):
        raise ValueError(f"{name} 含 NaN/Inf，无法统计")
    return arr


def _py(obj: Any) -> Any:
    """numpy 标量 → 原生 python 类型（保证 json 可序列化）"""
    if isinstance(obj, (bool, np.bool_)):
        return bool(obj)
    if isinstance(obj, (int, np.integer)):
        return int(obj)
    if isinstance(obj, (float, np.floating)):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _py(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_py(v) for v in obj]
    return obj


def _small_sample_note(n: int) -> Optional[str]:
    if n < SMALL_SAMPLE_N:
        return (f"n={n} < {SMALL_SAMPLE_N}：样本量偏小，CI/检验结果仅供参考，"
                f"建议 >= {SMALL_SAMPLE_N} seeds")
    return None


def _mean_std(values: np.ndarray) -> Dict[str, float]:
    return {
        'mean': float(np.mean(values)),
        'std': float(np.std(values, ddof=1)) if values.size > 1 else 0.0,
        'min': float(np.min(values)),
        'max': float(np.max(values)),
    }


# ==================== bootstrap CI ====================

def bootstrap_ci(values: Union[Sequence[float], np.ndarray],
                 stat: Callable[[np.ndarray], float] = np.mean,
                 n_boot: int = 2000,
                 alpha: float = 0.05,
                 rng: Optional[Union[int, np.random.Generator]] = None) -> Dict[str, Any]:
    """
    percentile 法 bootstrap 置信区间。

    参数
    ----
    values : 观测样本（一维，不得含 NaN/Inf）
    stat   : 点估计统计量，默认均值；须满足 f(ndarray) -> float
    n_boot : 重采样次数，必须 >= 2000（低于该值拒绝计算，防止 CI 抖动）
    alpha  : 显著性水平，默认 0.05 → 95% CI
    rng    : 随机源（int 种子或 np.random.Generator），保证可复现

    返回
    ----
    dict: point_estimate, ci_low, ci_high, confidence_level, n, n_boot,
          stat_name, warnings（小样本时含"仅供参考"标注）
    """
    arr = _to_float_array(values)
    if n_boot < 2000:
        raise ValueError(f"n_boot 必须 >= 2000（收到 {n_boot}），过小会导致 percentile CI 不稳定")
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha 必须在 (0,1) 内（收到 {alpha}）")

    gen = rng if isinstance(rng, np.random.Generator) else np.random.default_rng(rng)
    point = float(stat(arr))
    idx = gen.integers(0, arr.size, size=(n_boot, arr.size))
    boot_stats = np.array([stat(arr[row]) for row in idx], dtype=float)
    lo, hi = np.percentile(boot_stats, [100 * alpha / 2.0, 100 * (1 - alpha / 2.0)])

    warns: List[str] = []
    note = _small_sample_note(arr.size)
    if note:
        warns.append(note)
    return {
        'point_estimate': point,
        'ci_low': float(lo),
        'ci_high': float(hi),
        'confidence_level': 1.0 - alpha,
        'n': int(arr.size),
        'n_boot': int(n_boot),
        'stat_name': getattr(stat, '__name__', repr(stat)),
        'warnings': warns,
    }


# ==================== 独立样本检验 ====================

def mannwhitney_test(attack_vals: Union[Sequence[float], np.ndarray],
                     baseline_vals: Union[Sequence[float], np.ndarray],
                     alpha: float = 0.05) -> Dict[str, Any]:
    """
    双侧 Mann-Whitney U 检验（独立样本，不要求正态性）。

    返回 dict：test='mannwhitneyu', U, p_value, significant(p<alpha),
    effect_size（rank-biserial r = 2U/(n1·n2) - 1，U 为 scipy 的 U₁；
    >0 表示攻击组更大）, median_diff（攻击 - 基线）, n_attack, n_baseline, warnings。
    两组完全相同（U 无定义 / 全零差异）时 scipy 可能报 p=nan，按不显著处理并告警。
    """
    a = _to_float_array(attack_vals, 'attack_vals')
    b = _to_float_array(baseline_vals, 'baseline_vals')
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha 必须在 (0,1) 内（收到 {alpha}）")

    warns: List[str] = []
    try:
        res = _sps.mannwhitneyu(a, b, alternative='two-sided')
        U, p = float(res.statistic), float(res.pvalue)
    except ValueError:
        # 全部观测值相同等退化情形
        U, p = float('nan'), 1.0
        warns.append("两组取值完全退化（无秩差），按 p=1.0 不显著处理")
    if np.isnan(p):
        p = 1.0
        warns.append("p 值为 NaN，按 1.0 不显著处理")

    # scipy U₁ = #{(a_i,b_j): b_j > a_i} + ½·ties → a 全大于 b 时 U₁=0，
    # 故 rank-biserial（>0 = 攻击组更大）= 2U₁/(n1·n2) - 1
    r_rb = 2.0 * U / (a.size * b.size) - 1.0
    note = _small_sample_note(min(a.size, b.size))
    if note:
        warns.append(note)
    return {
        'test': 'mannwhitneyu',
        'U': U,
        'p_value': p,
        'significant': bool(p < alpha),
        'alpha': alpha,
        'effect_size': {'rank_biserial': float(r_rb)},
        'median_diff': float(np.median(a) - np.median(b)),
        'median_attack': float(np.median(a)),
        'median_baseline': float(np.median(b)),
        'n_attack': int(a.size),
        'n_baseline': int(b.size),
        'warnings': warns,
    }


# ==================== 按 seed 配对检验 ====================

def paired_by_seed(attack_by_seed: Mapping[Union[int, str], float],
                   baseline_by_seed: Mapping[Union[int, str], float],
                   alpha: float = 0.05) -> Dict[str, Any]:
    """
    按 seed 配对后检验攻击臂 vs 基线臂。

    - 同 seed 成对数 >= 2：优先 Wilcoxon signed-rank 配对检验
      （同 seed 共享 flows / 攻击者布点等共同随机性，配对可消噪）。
      若差值全为零（统计量无定义），如实报告 p=1.0 不显著。
    - seed 完全不重叠：退回双侧 Mann-Whitney U，并在 warnings 中说明
      "未配对，检验功效较低，建议以相同 seed 集重跑两臂"。
    - 部分重叠：仅用重叠 seed 配对，warnings 标注被丢弃的 seed。

    参数均为 {seed: 指标值} 映射。返回 dict：test, statistic, p_value,
    significant, effect_size（rank-biserial，符号约定与 mannwhitney_test 一致：
    >0 表示攻击臂更大）, median_diff（配对时为差值中位数，攻击 - 基线）,
    n_pairs, paired_seeds, warnings。
    """
    a_keys = {int(k): float(v) for k, v in attack_by_seed.items()}
    b_keys = {int(k): float(v) for k, v in baseline_by_seed.items()}
    if not a_keys or not b_keys:
        raise ValueError("attack_by_seed / baseline_by_seed 不能为空")
    if not all(np.isfinite(list(a_keys.values()) + list(b_keys.values()))):
        raise ValueError("配对值含 NaN/Inf")
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha 必须在 (0,1) 内（收到 {alpha}）")

    shared = sorted(set(a_keys) & set(b_keys))
    warns: List[str] = []

    if len(shared) < 2:
        # 无法配对 → 退回独立样本检验
        fallback = mannwhitney_test(list(a_keys.values()), list(b_keys.values()), alpha=alpha)
        fallback['n_pairs'] = len(shared)
        fallback['paired_seeds'] = shared
        fb_warns = ['seed 不重叠（成对数 < 2），退回非配对 Mann-Whitney U；'
                    '两臂应使用相同 seed 集以获得配对检验功效']
        only_a = sorted(set(a_keys) - set(b_keys))
        only_b = sorted(set(b_keys) - set(a_keys))
        if only_a:
            fb_warns.append(f"仅攻击臂含有的 seed: {only_a}")
        if only_b:
            fb_warns.append(f"仅基线臂含有的 seed: {only_b}")
        fb_warns.extend(fallback['warnings'])
        fallback['warnings'] = fb_warns
        return fallback

    a = np.array([a_keys[s] for s in shared], dtype=float)
    b = np.array([b_keys[s] for s in shared], dtype=float)
    diff = a - b
    if np.allclose(diff, 0.0):
        result = {
            'test': 'wilcoxon',
            'statistic': float('nan'),
            'p_value': 1.0,
            'significant': False,
            'alpha': alpha,
            'effect_size': {'rank_biserial': 0.0},
            'median_diff': 0.0,
            'median_attack': float(np.median(a)),
            'median_baseline': float(np.median(b)),
        }
        warns.append("所有配对差值为 0，Wilcoxon 统计量无定义，按 p=1.0 不显著处理")
    else:
        try:
            res = _sps.wilcoxon(diff, alternative='two-sided')
            stat_v, p = float(res.statistic), float(res.pvalue)
        except ValueError:
            # n 太小等退化情形 → 退回符号翻转正态近似（zero_method='wilcox' 默认已处理）
            res = _sps.wilcoxon(diff, alternative='two-sided', mode='approx')
            stat_v, p = float(res.statistic), float(res.pvalue)
            warns.append("精确 Wilcoxon 不可用，退回正态近似")
        n_eff = int(np.count_nonzero(diff))
        # rank-biserial（配对）：r = (2V - T) / T，V=正秩和（scipy 统计量），
        # T=n_eff(n_eff+1)/2；符号约定：>0 表示攻击臂更大（与 Mann-Whitney 路径一致）
        t_ranks = n_eff * (n_eff + 1) / 2.0
        r_rb = (2.0 * stat_v - t_ranks) / t_ranks if n_eff > 0 else 0.0
        result = {
            'test': 'wilcoxon',
            'statistic': stat_v,
            'p_value': p if not np.isnan(p) else 1.0,
            'significant': bool((p if not np.isnan(p) else 1.0) < alpha),
            'alpha': alpha,
            'effect_size': {'rank_biserial': float(r_rb)},
            'median_diff': float(np.median(diff)),
            'median_attack': float(np.median(a)),
            'median_baseline': float(np.median(b)),
        }

    only_a = sorted(set(a_keys) - set(b_keys))
    only_b = sorted(set(b_keys) - set(a_keys))
    if only_a:
        warns.append(f"未配对（仅攻击臂）而被丢弃的 seed: {only_a}")
    if only_b:
        warns.append(f"未配对（仅基线臂）而被丢弃的 seed: {only_b}")
    note = _small_sample_note(len(shared))
    if note:
        warns.append(note)
    result['n_pairs'] = len(shared)
    result['paired_seeds'] = shared
    result['warnings'] = warns
    return result


# ==================== trials 基数 / 匹配键 ====================

def describe_cardinality(num_flows: Optional[int],
                         num_eval_epochs: Optional[int],
                         trials_per_flow_epoch: int = 1,
                         total_trials: Optional[int] = None) -> Dict[str, Any]:
    """
    记录/推导 trials 基数三元组，并做一致性校验。

    total_trials = num_flows × num_eval_epochs × trials_per_flow_epoch。
    若显式给出 total_trials 且与推导值不一致，抛 :class:`TrialsCardinalityError`
    （说明记录方与结果方对基数的理解不一致，属于必须拦截的方法学错误）。
    """
    derived = None
    if num_flows is not None and num_eval_epochs is not None:
        derived = int(num_flows) * int(num_eval_epochs) * int(trials_per_flow_epoch)
    if total_trials is not None and derived is not None and int(total_trials) != derived:
        raise TrialsCardinalityError(
            f"trials 基数不一致：total_trials={total_trials} 但 "
            f"num_flows({num_flows}) × num_eval_epochs({num_eval_epochs}) × "
            f"trials_per_flow_epoch({trials_per_flow_epoch}) = {derived}")
    resolved = derived if derived is not None else (int(total_trials) if total_trials is not None else None)
    return {
        'num_flows': None if num_flows is None else int(num_flows),
        'num_eval_epochs': None if num_eval_epochs is None else int(num_eval_epochs),
        'trials_per_flow_epoch': int(trials_per_flow_epoch),
        'total_trials': resolved,
        'match_key': cardinality_match_key(num_flows=num_flows,
                                           num_eval_epochs=num_eval_epochs),
        'semantics': ("total_trials = num_flows × num_eval_epochs × trials_per_flow_epoch；"
                      "跨实验比较要求匹配键 (shell, node_limit, num_eval_epochs, num_flows) 完全一致"),
    }


def cardinality_match_key(shell: Optional[str] = None,
                          node_limit: Optional[int] = None,
                          num_eval_epochs: Optional[int] = None,
                          num_flows: Optional[int] = None,
                          **_: Any) -> Dict[str, Any]:
    """构造匹配键（dict 形式，字段固定为 MATCH_KEY_FIELDS）。"""
    return {
        'shell': shell,
        'node_limit': None if node_limit is None else int(node_limit),
        'num_eval_epochs': None if num_eval_epochs is None else int(num_eval_epochs),
        'num_flows': None if num_flows is None else int(num_flows),
    }


def check_comparable(card_a: Mapping[str, Any],
                     card_b: Mapping[str, Any],
                     raise_on_mismatch: bool = True) -> Dict[str, Any]:
    """
    校验两份 trials 基数记录的匹配键是否一致。

    返回 {comparable, mismatches: [{field, left, right}], message}。
    raise_on_mismatch=True 且不一致时抛 :class:`TrialsCardinalityError`。
    任一字段在两侧都为 None（旧数据缺失）视为"未知但暂不拦截"，计入 warnings。
    """
    key_a = card_a.get('match_key') or cardinality_match_key(**{
        f: card_a.get(f) for f in MATCH_KEY_FIELDS})
    key_b = card_b.get('match_key') or cardinality_match_key(**{
        f: card_b.get(f) for f in MATCH_KEY_FIELDS})
    mismatches = []
    unknowns = []
    for field in MATCH_KEY_FIELDS:
        va, vb = key_a.get(field), key_b.get(field)
        if va is None and vb is None:
            unknowns.append(field)
        elif va != vb:
            mismatches.append({'field': field, 'left': va, 'right': vb})
    comparable = not mismatches
    msg = "匹配键一致，可比较" if comparable else \
        "匹配键不一致，拒绝比较: " + "; ".join(
            f"{m['field']}: {m['left']!r} vs {m['right']!r}" for m in mismatches)
    if unknowns:
        msg += f"（注意：字段 {unknowns} 两侧均缺失，未参与拦截）"
    if not comparable and raise_on_mismatch:
        warnings.warn(msg, stacklevel=2)
        raise TrialsCardinalityError(msg)
    return {'comparable': comparable, 'mismatches': mismatches,
            'unknown_fields': unknowns, 'message': msg}


# ==================== raw JSON 记录解析 ====================

def _load_records(source: Union[str, Path, Iterable[Union[str, Path]]]) -> List[Dict[str, Any]]:
    """从 glob 模式 / 单文件 / 文件列表加载 raw JSON 记录。"""
    if isinstance(source, (str, Path)):
        s = str(source)
        paths = sorted(_glob.glob(s)) if any(c in s for c in '*?[') else [s]
    else:
        paths = [str(p) for p in source]
    if not paths:
        raise FileNotFoundError(f"未匹配到任何 raw JSON 文件: {source!r}")
    records = []
    for p in paths:
        with open(p, 'r', encoding='utf-8') as f:
            rec = json.load(f)
        rec.setdefault('_source_file', p)
        records.append(rec)
    return records


def extract_metrics(record: Mapping[str, Any]) -> Dict[str, float]:
    """
    从 raw JSON 记录提取指标，兼容三种既有 schema：
    - 新版（E1 / schema_version 2）：data_stats + control_stats 嵌套
    - E3 旧版：seed/control_stats/data_stats/attacker_stats
    - E2 旧版：指标平铺在顶层（total_loops 亦在顶层）
    """
    out: Dict[str, float] = {}
    data = record.get('data_stats')
    if isinstance(data, Mapping):
        for k, v in data.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out[k] = float(v)
    ctrl = record.get('control_stats')
    if isinstance(ctrl, Mapping) and 'total_loops' in ctrl:
        out['total_loops'] = float(ctrl['total_loops'])
    # 平铺 schema（E2）：顶层数值键直接作为指标
    for k, v in record.items():
        if k in DEFAULT_METRICS and isinstance(v, (int, float)) and not isinstance(v, bool):
            out.setdefault(k, float(v))
    return out


def extract_match_key(record: Mapping[str, Any],
                      overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """
    从 raw JSON 记录推导 trials 基数与匹配键。

    优先级：overrides > metadata（新版）> config 快照（E2 有）> 由
    num_trials / num_flows 反推 num_eval_epochs。旧记录（如 E3 raw，无 config）
    缺失的字段留 None，调用方应通过 overrides 补齐，否则该记录只能与
    同样缺失该字段的记录比较（见 check_comparable 的 unknown 语义）。
    """
    overrides = dict(overrides or {})
    config = record.get('config') or {}
    metadata = record.get('metadata') or {}
    metrics = extract_metrics(record)

    topo = config.get('topology', {}) if isinstance(config, Mapping) else {}
    traffic = config.get('traffic', {}) if isinstance(config, Mapping) else {}
    exp = config.get('experiment', {}) if isinstance(config, Mapping) else {}
    routing = config.get('routing', {}) if isinstance(config, Mapping) else {}

    shell = overrides.get('shell', metadata.get('shell', topo.get('shell')))
    node_limit = overrides.get('node_limit', metadata.get('node_limit', topo.get('node_limit', 'unset')))
    if node_limit == 'unset':
        node_limit = None
    num_flows = overrides.get('num_flows', metadata.get('num_flows', traffic.get('num_flows')))
    num_epochs = overrides.get('num_eval_epochs', metadata.get('num_eval_epochs'))
    trials_per = overrides.get('trials_per_flow_epoch',
                               metadata.get('trials_per_flow_epoch', 1))
    total_trials = overrides.get('total_trials', metrics.get('num_trials'))

    # 反推评估 epoch 数：num_eval_epochs = num_trials / (num_flows × trials_per_flow_epoch)
    if num_epochs is None and num_flows and total_trials is not None:
        denom = int(num_flows) * int(trials_per)
        if denom > 0 and float(total_trials) % denom == 0:
            num_epochs = int(total_trials) // denom
    # 再退回 duration / epoch_interval（E2 config 快照可推）
    if num_epochs is None and exp.get('duration') and topo.get('epoch_interval'):
        num_epochs = max(1, int(float(exp['duration']) // float(topo['epoch_interval'])))

    cardinality = describe_cardinality(num_flows, num_epochs, trials_per,
                                       None if total_trials is None else int(total_trials))
    cardinality['match_key'] = cardinality_match_key(
        shell=shell, node_limit=node_limit,
        num_eval_epochs=num_epochs, num_flows=num_flows)
    cardinality['source'] = {
        'has_config_snapshot': bool(config),
        'has_metadata': bool(metadata),
        'overrides_applied': sorted(overrides.keys()),
        'file': record.get('_source_file'),
        'seed': record.get('seed', metadata.get('seed')),
    }
    # routing 参数不参与匹配键，但记录下来供人工审计
    cardinality['aux'] = {'t_adv': routing.get('t_adv'), 'tick': routing.get('tick'),
                          'max_hops': routing.get('max_hops'),
                          'duration': exp.get('duration')}
    return cardinality


# ==================== 单实验多种子聚合 ====================

def aggregate_experiment(raw_json_glob: Union[str, Path, Iterable[Union[str, Path]]],
                         metrics: Sequence[str] = DEFAULT_METRICS,
                         n_boot: int = 2000,
                         alpha: float = 0.05,
                         match_key_overrides: Optional[Mapping[str, Any]] = None,
                         rng: Optional[Union[int, np.random.Generator]] = None) -> Dict[str, Any]:
    """
    读入某实验所有 seed 的 raw JSON，对每个指标产出 mean±std + bootstrap 95% CI。

    参数
    ----
    raw_json_glob : glob 模式（如 ``results/raw/e1_baseline_seed*.json``）、
                    单文件路径或路径列表
    metrics       : 需聚合的指标名（缺失自动跳过）
    n_boot/alpha  : 传给 :func:`bootstrap_ci`
    match_key_overrides : 旧记录缺失字段时人工补齐匹配键
                          （如 ``{'shell': '53°', 'node_limit': None}``）
    rng           : bootstrap 随机源

    返回 dict：experiment, n_seeds, seeds, per_seed（逐 seed 指标+基数）、
    cardinality（含一致性与匹配键）、metrics（每指标 mean/std/ci）、warnings。
    """
    records = _load_records(raw_json_glob)
    warns: List[str] = []

    seeds: List[Optional[int]] = []
    per_seed: List[Dict[str, Any]] = []
    cards: List[Dict[str, Any]] = []
    values_by_metric: Dict[str, Dict[Any, float]] = {m: {} for m in metrics}
    exp_names = set()

    for i, rec in enumerate(records):
        seed = rec.get('seed')
        if seed is None:
            seed = (rec.get('metadata') or {}).get('seed')
        if seed is not None:
            seed = int(seed)
        else:
            seed = f'__noid_{i}'
            warns.append(f"记录 {rec.get('_source_file')} 缺 seed 字段，用占位键 {seed}")
        if seed in seeds:
            warns.append(f"seed={seed} 重复出现（{rec.get('_source_file')}），后写入覆盖先写入")
        seeds.append(seed)
        m = extract_metrics(rec)
        card = extract_match_key(rec, match_key_overrides)
        cards.append(card)
        per_seed.append({'seed': seed, 'file': rec.get('_source_file'),
                         'metrics': _py(m), 'cardinality': _py(card)})
        for name in metrics:
            if name in m:
                values_by_metric[name][seed] = m[name]
        exp_name = ((rec.get('config') or {}).get('experiment') or {}).get('name') \
            or rec.get('experiment') or (rec.get('metadata') or {}).get('experiment')
        if isinstance(exp_name, str):
            exp_names.add(exp_name)

    n_seeds = len(records)
    note = _small_sample_note(n_seeds)
    if note:
        warns.append(note)

    # 基数一致性：所有 seed 的匹配键应完全相同（同一实验内部）
    cardinality_consistent = True
    if n_seeds > 1:
        for card in cards[1:]:
            cmp = check_comparable(cards[0], card, raise_on_mismatch=False)
            if not cmp['comparable']:
                cardinality_consistent = False
                warns.append(f"同一实验内部基数不一致: {cmp['message']}")
    unknown = cards[0].get('match_key', {}) if cards else {}
    missing_fields = [f for f in MATCH_KEY_FIELDS if unknown.get(f) is None]
    if missing_fields:
        warns.append(f"匹配键字段 {missing_fields} 无法从记录推导（旧格式？），"
                     f"跨实验比较前请用 match_key_overrides 补齐")

    metrics_out: Dict[str, Any] = {}
    for name in metrics:
        vals = values_by_metric.get(name) or {}
        if not vals:
            continue
        arr = np.array(list(vals.values()), dtype=float)
        summary = _mean_std(arr)
        if n_seeds >= 2:
            ci = bootstrap_ci(arr, n_boot=n_boot, alpha=alpha, rng=rng)
            summary['ci95_low'] = ci['ci_low']
            summary['ci95_high'] = ci['ci_high']
            summary['n_boot'] = ci['n_boot']
        else:
            summary['ci95_low'] = None
            summary['ci95_high'] = None
            warns_once = f"指标 {name}: 单 seed 无法计算 CI"
            if warns_once not in warns:
                warns.append(warns_once)
        summary['n'] = int(arr.size)
        summary['per_seed'] = _py(vals)
        metrics_out[name] = summary

    return _py({
        'experiment': sorted(exp_names)[0] if len(exp_names) == 1 else (sorted(exp_names) or None),
        'n_seeds': n_seeds,
        'seeds': seeds,
        'cardinality': {
            'match_key': cards[0]['match_key'] if cards else None,
            'detail': cards[0] if cards else None,
            'consistent_across_seeds': cardinality_consistent,
        },
        'metrics': metrics_out,
        'per_seed': per_seed,
        'warnings': warns,
    })


# ==================== 攻击臂 vs 匹配基线臂 ====================

def compare_attack_vs_baseline(attack_records: Union[str, Path, Iterable, Sequence[Mapping]],
                               baseline_records: Union[str, Path, Iterable, Sequence[Mapping]],
                               metrics: Sequence[str] = DEFAULT_METRICS,
                               alpha: float = 0.05,
                               attack_overrides: Optional[Mapping[str, Any]] = None,
                               baseline_overrides: Optional[Mapping[str, Any]] = None,
                               strict: bool = True) -> Dict[str, Any]:
    """
    匹配基线比较：按匹配键分组 → 组内 attack vs baseline 按 seed 配对检验。

    参数可为 glob/路径（内部加载）或已加载的记录列表。匹配键不一致时：
    strict=True（默认）抛 :class:`TrialsCardinalityError` 拒绝比较；
    strict=False 返回 comparable=False + mismatches，由调用方决定如何呈现。

    返回 dict：groups[{match_key, attack/baseline 概要, comparable,
    mismatches, comparisons{metric: paired_by_seed 结果}, warnings}]。
    """
    def _as_records(src):
        if isinstance(src, (list, tuple)) and src and isinstance(src[0], Mapping):
            return [dict(r) for r in src]
        return _load_records(src)

    atk_recs = _as_records(attack_records)
    base_recs = _as_records(baseline_records)

    def _index(recs, overrides):
        idx: Dict[str, Dict[int, Dict[str, Any]]] = {}
        cards: Dict[str, Dict[str, Any]] = {}
        for rec in recs:
            card = extract_match_key(rec, overrides)
            key = json.dumps(card['match_key'], sort_keys=True, ensure_ascii=False)
            seed = rec.get('seed')
            if seed is None:
                seed = (rec.get('metadata') or {}).get('seed')
            if seed is None:
                raise ValueError(f"记录缺 seed，无法配对比较: {rec.get('_source_file')}")
            idx.setdefault(key, {})[int(seed)] = extract_metrics(rec)
            cards.setdefault(key, card)
        return idx, cards

    atk_idx, atk_cards = _index(atk_recs, attack_overrides)
    base_idx, base_cards = _index(base_recs, baseline_overrides)

    groups = []
    all_keys = sorted(set(atk_idx) | set(base_idx))
    for key in all_keys:
        match_key = json.loads(key)
        group: Dict[str, Any] = {
            'match_key': match_key,
            'attack_seeds': sorted(atk_idx.get(key, {}).keys()),
            'baseline_seeds': sorted(base_idx.get(key, {}).keys()),
            'cardinality': {
                'attack': _py(atk_cards.get(key)),
                'baseline': _py(base_cards.get(key)),
            },
        }
        if key not in atk_idx or key not in base_idx:
            group['comparable'] = False
            group['mismatches'] = []
            group['warnings'] = [f"匹配键 {key} 仅存在于{'攻击臂' if key in atk_idx else '基线臂'}，无对照，跳过"]
            groups.append(group)
            continue

        # trials 基数守卫：匹配键不一致 → 拒绝比较
        card_a = atk_cards[key]
        card_b = base_cards[key]
        groups_same_key = (card_a['match_key'] == card_b['match_key'])  # 恒真（同组），保留显式检查
        assert groups_same_key, "内部分组错误：同组匹配键应一致"
        try:
            cmp = check_comparable(card_a, card_b, raise_on_mismatch=True)
        except TrialsCardinalityError as exc:
            if strict:
                raise
            group['comparable'] = False
            group['mismatches'] = str(exc)
            group['warnings'] = [f"trials 基数不匹配，已拒绝比较: {exc}"]
            groups.append(group)
            continue

        # 组内配对检验
        comparisons: Dict[str, Any] = {}
        group_warns: List[str] = [cmp['message']] if cmp.get('message') else []
        atk_metrics = atk_idx[key]
        base_metrics = base_idx[key]
        shared_seeds = sorted(set(atk_metrics) & set(base_metrics))
        for name in metrics:
            a_vals = {s: atk_metrics[s][name] for s in shared_seeds if name in atk_metrics[s]}
            b_vals = {s: base_metrics[s][name] for s in shared_seeds if name in base_metrics[s]}
            if not a_vals or not b_vals:
                continue
            comparisons[name] = _py(paired_by_seed(a_vals, b_vals, alpha=alpha))
        group['comparable'] = True
        group['mismatches'] = []
        group['paired_seeds'] = shared_seeds
        group['comparisons'] = comparisons
        group['warnings'] = group_warns
        groups.append(group)

    comparable_groups = [g for g in groups if g.get('comparable')]
    if strict and not comparable_groups:
        atk_keys = sorted(atk_idx.keys())
        base_keys = sorted(base_idx.keys())
        msg = ("trials 基数/匹配键不一致，拒绝比较：攻击臂与基线臂无任何共享匹配键。"
               f" 攻击臂匹配键: {atk_keys}; 基线臂匹配键: {base_keys}。"
               " 请用同 shell/node_limit/epoch 数/flow 数的配置重跑，"
               "或用 attack_overrides/baseline_overrides 补齐旧记录缺失字段")
        warnings.warn(msg, stacklevel=2)
        raise TrialsCardinalityError(msg)
    return _py({
        'n_groups': len(groups),
        'n_comparable_groups': len(comparable_groups),
        'groups': groups,
        'policy': ("攻击臂仅与同匹配键 (shell/node_limit/num_eval_epochs/num_flows) "
                   "的基线臂做按 seed 配对比较；不匹配即拒绝"),
    })
