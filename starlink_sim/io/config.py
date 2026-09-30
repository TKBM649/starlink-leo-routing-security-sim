"""
starlink_sim/io/config.py
统一实验配置加载层。

设计决策（9 个死配置键处置）：
- routing.t_adv        → WIRE：传递到 DVRouter.adv_interval（默认 2.0）
- routing.max_hops     → WIRE：传递到 DataPlane.compute_path（默认 100）
- topology.node_limit  → WIRE：BFS 子集规模（默认 96，null=全量）
- routing.protocol     → RESERVED：当前仅支持 "dv"，解析层忽略
- topology.use_lattice → REMOVED：拓扑从 pkl 缓存加载，该键无实际代码路径
- topology.isl_distance_limit → RESERVED：T4 决定维持现状不改动建链行为
- topology.gimbal_limit → REMOVED：无实际代码路径
- traffic.flow_duration → REMOVED：当前流模型无持续时间概念
- traffic.start_offset  → REMOVED：当前流模型无偏移概念
- topology.tle_file     → REMOVED：拓扑从 pkl 缓存加载，非直接从 TLE

统一 schema 结构（嵌套风格）：
    experiment:
      name: str
      duration: float
      seed: int|null
    topology:
      shell: str
      epoch_interval: float
      node_limit: int|null
      cache_path: str
      positions_cache: str|null
    routing:
      t_adv: float
      tick: float
      max_hops: int
    traffic:
      num_flows: int
    attack:
      attackers: list[dict]   # 每项含 type/count/placement/active_since/active_until/params
    output:
      raw_dir: str
      agg_dir: str
      figures_dir: str
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# ==================== 默认值 ====================
_DEFAULTS = {
    'experiment': {
        'name': 'unnamed',
        'duration': 60.0,
        'seed': None,
    },
    'topology': {
        'shell': '53°',
        'epoch_interval': 30.0,
        'node_limit': 96,
        'cache_path': 'data/topology/topology_results.pkl',
        'positions_cache': None,
    },
    'routing': {
        't_adv': 2.0,
        'tick': 0.2,
        'max_hops': 100,
    },
    'traffic': {
        'num_flows': 100,
    },
    'attack': {
        'attackers': [],
    },
    'output': {
        'raw_dir': 'results/raw/',
        'agg_dir': 'results/aggregated/',
        'figures_dir': 'results/figures/',
    },
}

# 解析层静默忽略的 reserved/removed 键（不报错，不传递到下游）
_IGNORED_KEYS = {
    'topology': {'use_lattice', 'isl_distance_limit', 'gimbal_limit', 'tle_file'},
    'routing': {'protocol'},
    'traffic': {'flow_duration', 'start_offset'},
}


def _deep_merge(base: dict, override: dict) -> dict:
    """递归合并 override 到 base（不修改原 dict）"""
    result = copy.deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


def _normalize_legacy_e3(raw: dict) -> dict:
    """
    将旧版 e3 扁平 schema 转换为统一嵌套 schema。
    旧 schema 示例：
        experiment: e3_blackhole
        duration: 60
        topology_epoch: 30
        control_tick: 0.2
        num_flows: 100
        topology_cache: "..."
        positions_cache: "..."
        shell: "53°"
        attackers: [...]
    """
    nested: Dict[str, Any] = {}

    # experiment
    exp_name = raw.get('experiment', 'unnamed')
    if isinstance(exp_name, dict):
        # 已经是嵌套格式
        return raw
    nested['experiment'] = {
        'name': exp_name if isinstance(exp_name, str) else 'unnamed',
        'duration': raw.get('duration', 60.0),
        'seed': raw.get('seed', None),
    }

    # topology
    nested['topology'] = {
        'shell': raw.get('shell', '53°'),
        'epoch_interval': raw.get('topology_epoch', 30.0),
        'node_limit': raw.get('node_limit', None),  # e3 默认全量
        'cache_path': raw.get('topology_cache', 'data/topology/topology_results.pkl'),
        'positions_cache': raw.get('positions_cache', None),
    }

    # routing
    nested['routing'] = {
        't_adv': raw.get('t_adv', 2.0),
        'tick': raw.get('control_tick', 0.2),
        'max_hops': raw.get('max_hops', 100),
    }

    # traffic
    nested['traffic'] = {
        'num_flows': raw.get('num_flows', 100),
    }

    # attack - 旧版 attackers 是顶层列表
    attackers_raw = raw.get('attackers', [])
    attackers = []
    for att in attackers_raw:
        entry = dict(att)
        # 将 drop_prob/metric_fake 等移入 params
        params = entry.pop('params', {})
        for key in ('drop_prob', 'metric_fake', 'jamming_ratio', 'inf_metric'):
            if key in entry:
                params[key] = entry.pop(key)
        entry['params'] = params
        entry.setdefault('placement', 'degree')
        attackers.append(entry)
    nested['attack'] = {'attackers': attackers}

    # output
    nested['output'] = {
        'raw_dir': raw.get('output_raw_dir', 'results/raw/'),
        'agg_dir': raw.get('output_agg_dir', 'results/aggregated/'),
        'figures_dir': raw.get('output_figures_dir', 'results/figures/'),
    }

    return nested


def _normalize_e2_attack(raw: dict) -> dict:
    """
    将 e2 旧版单攻击者格式转为统一列表格式。
    旧：attack: {type, count, placement, active_since, active_until, params}
    新：attack: {attackers: [{type, count, placement, active_since, active_until, params}]}
    """
    attack = raw.get('attack', {})
    if 'attackers' in attack:
        return raw  # 已是新格式

    # 旧格式转换
    attackers = []
    count = attack.get('count', 0)
    if count > 0:
        entry = {
            'type': attack.get('type', 'BlackholeAttacker'),
            'count': count,
            'placement': attack.get('placement', 'degree'),
            'active_since': attack.get('active_since', 0.0),
            'active_until': attack.get('active_until', float('inf')),
            'params': attack.get('params', {}),
        }
        attackers.append(entry)

    result = copy.deepcopy(raw)
    result['attack'] = {'attackers': attackers}
    return result


def _strip_ignored(config: dict) -> dict:
    """移除被标记为 ignored/reserved 的键，避免下游误用"""
    result = copy.deepcopy(config)
    for section, keys in _IGNORED_KEYS.items():
        if section in result and isinstance(result[section], dict):
            for k in keys:
                result[section].pop(k, None)
    return result


def load_experiment_config(path: str | Path) -> dict:
    """
    加载实验配置 YAML 并归一化为统一 schema。

    支持：
    - 新版统一嵌套 schema（直接使用）
    - 旧版 e2 嵌套 schema（attack 单条 → 列表）
    - 旧版 e3 扁平 schema（自动转换）

    返回带完整默认值的 dict，可直接传入 run_experiment。
    """
    path = Path(path)
    with open(path, 'r', encoding='utf-8') as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raw = {}

    # 检测是否为旧版 e3 扁平格式（experiment 为字符串而非 dict）
    exp_field = raw.get('experiment')
    if exp_field is None or isinstance(exp_field, str):
        normalized = _normalize_legacy_e3(raw)
    else:
        normalized = copy.deepcopy(raw)

    # e2 旧版 attack 格式归一化
    normalized = _normalize_e2_attack(normalized)

    # 合并默认值
    config = _deep_merge(_DEFAULTS, normalized)

    # 移除 ignored/reserved 键
    config = _strip_ignored(config)

    return config


def get_attacker_configs(config: dict) -> List[Dict[str, Any]]:
    """从统一配置中提取攻击者列表"""
    return config.get('attack', {}).get('attackers', [])
