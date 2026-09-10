# 目录整理与命名规范化变更日志

**执行日期**：2026-09-10
**依据**：`PLAN.md` §8 目录约定 + PEP 8 模块命名规范
**原则**：只按文件名判断分类与规范化，不修改代码逻辑

---

## 一、命名规范（本次统一遵循）

| 类别 | 规范 | 反例 → 正例 |
|---|---|---|
| Python 模块 | `snake_case.py`，纯 ASCII，无空格/大写/连字符 | `Black hole attack.py` → `attack.py` |
| 实验脚本 | `run_e{N}_{attack}_experiment.py` | `run_Black hole attack_experiment.py` → `run_e3_blackhole_experiment.py` |
| 数据文件 | ASCII 安全，度符号 `°` → `deg`，小数点 → `_` | `events_97.5°.txt` → `events_97_5deg.txt` |
| 结果 JSON | `{type}_e{N}_{attack}_seed{N}.json` | `attack_e3_Black hole_seed42.json` → `attack_e3_blackhole_seed42.json` |
| 结果 CSV/PNG | `{name}_seed{range}.{ext}` | `attack_42_44.csv` → `attack_seed42_44.csv` |
| 可视化 HTML | `{obj}_{dim}_{version}.html` | `starlink_3d_final1.html` → `starlink_3d_final_v1.html` |

---

## 二、结构变更（对齐 PLAN §8）

### 2.1 新建目录
- `tools/`（PLAN 要求，此前缺失）

### 2.2 根目录清理
| 操作 | 原路径 | 新路径 |
|---|---|---|
| 移动 | `check_imports.py` | `tools/check_imports.py` |
| 移动 | `check_shell.py` | `tools/check_shell.py` |
| 删除 | `starlink.tle`（1.8 MB 冗余副本） | 保留 `data/tle/starlink.tle` |

### 2.3 `starlink_sim/net/` 重命名（5 项）
| 原名 | 新名 | 依据 |
|---|---|---|
| `simulation_engine.py` | `simulator.py` | PLAN §1 L3 明确要求 |
| `Black hole attack.py` | `attack.py` | PLAN §1 L3 明确要求 |
| `e2_jamming attack.py` | `attack_jamming.py` | E2 干扰攻击变体 |
| `simulator_Black hole attack.py` | `simulator_blackhole.py` | 黑洞攻击专用仿真器 |
| `e2_jamming simulator.py` | `simulator_jamming.py` | 干扰攻击专用仿真器 |

### 2.4 `starlink_sim/topology/` 重命名（1 项）
| 原名 | 新名 | 依据 |
|---|---|---|
| `isl_builder.py` | `isl.py` | PLAN §1 L2 明确要求 |

### 2.5 `scripts/` 重命名（2 项）
| 原名 | 新名 |
|---|---|
| `run_Black hole attack_experiment.py` | `run_e3_blackhole_experiment.py` |
| `run_e2_jamming attack_experiment.py` | `run_e2_jamming_experiment.py` |

### 2.6 `data/topology/` 重命名（4 项，消除非 ASCII）
| 原名 | 新名 |
|---|---|
| `events_43°.txt` | `events_43deg.txt` |
| `events_53°.txt` | `events_53deg.txt` |
| `events_70°.txt` | `events_70deg.txt` |
| `events_97.5°.txt` | `events_97_5deg.txt` |

### 2.7 `results/raw/` 重命名（6 项）+ 归档（1 项）
| 原名 | 新名 |
|---|---|
| `aggregated_Black hole attack_e3 42.json` | `aggregated_blackhole_e3_seed42.json` |
| `aggregated_Black hole attack_e3 43.json` | `aggregated_blackhole_e3_seed43.json` |
| `aggregated_Black hole attack_e3 44.json` | `aggregated_blackhole_e3_seed44.json` |
| `attack_e3_Black hole_seed42.json` | `attack_e3_blackhole_seed42.json` |
| `attack_e3_Black hole_seed43.json` | `attack_e3_blackhole_seed43.json` |
| `attack_e3_Black hole_seed44.json` | `attack_e3_blackhole_seed44.json` |
| `results/routing_tables.pkl`（散落） | `results/raw/routing_tables.pkl` |

### 2.8 `results/figures/` 重命名（4 项）
| 原名 | 新名 |
|---|---|
| `attack_42_44.csv` | `attack_seed42_44.csv` |
| `e2_analysis_42_44.png` | `e2_analysis_seed42_44.png` |
| `no_attack_42_44.csv` | `no_attack_seed42_44.csv` |
| `paired_42_44.csv` | `paired_seed42_44.csv` |

### 2.9 `results/viz/` 重命名（2 项）
| 原名 | 新名 |
|---|---|
| `starlink_3d_final1.html` | `starlink_3d_final_v1.html` |
| `starlink_3d_final2.html` | `starlink_3d_final_v2.html` |

### 2.10 `results/aggregated/` 归档（1 项）
| 原路径 | 新路径 |
|---|---|
| `results/simulation_summary.json`（散落） | `results/aggregated/simulation_summary.json` |

---

## 三、代码引用同步更新

因模块重命名导致的 `import` 断链已同步修复：

| 文件 | 原引用 | 新引用 |
|---|---|---|
| `scripts/run_simulation.py` | `from starlink_sim.topology.isl_builder import propagate_satellite` | `from starlink_sim.topology.isl import propagate_satellite` |
| `scripts/build_topology.py` | `from starlink_sim.topology.isl_builder import build_topology_for_shell, compute_edge_overlap` | `from starlink_sim.topology.isl import ...` |
| `scripts/build_topology_from_tle.py` | 同上 | 同上 |
| `starlink_sim/topology/isl.py` | 头部注释 `# starlink_sim/topology/isl_builder.py` | `# starlink_sim/topology/isl.py` |

**说明**：脚本原本引用的 `starlink_sim.net.simulator` 与 `starlink_sim.net.attack`（此前不存在，属断链）已因 `simulation_engine.py → simulator.py`、`Black hole attack.py → attack.py` 自动修复。

---

## 四、清理项

- 删除全部 `__pycache__/`（5 处：`scripts/`、`starlink_sim/`、`starlink_sim/net/`、`starlink_sim/orbit/`、`starlink_sim/topology/`），避免旧 `.pyc` 缓存掩盖新命名。

---

## 五、最终结构（对齐 PLAN §8）

```
starlink/
├── PLAN.md
├── .gitignore
├── REORGANIZE_LOG.md          （本文件）
├── configs/
│   └── experiments/
│       ├── e2_jamming.yaml
│       └── e3_blackhole.yaml
├── data/
│   ├── lattice/               lattice_result.pkl, lattice_summary.json
│   ├── snapshots/             （空，gitignore）
│   ├── tle/                   starlink.tle, filtered_records.pkl, filter_report.json
│   └── topology/              events_{43,53,70,97_5}deg.txt, topology_results.pkl, topology_summary.json
├── docs/                      （空，PLAN 要求存在）
├── results/
│   ├── aggregated/            simulation_summary.json
│   ├── figures/               attack_seed42_44.csv, e2_analysis_seed42_44.png, ...
│   ├── raw/                   aggregated_blackhole_e3_seed4{2,3,4}.json, routing_tables.pkl, ...
│   └── viz/                   starlink_3d_final{,_v1,_v2}.html
├── scripts/
│   ├── analyze_e2.py
│   ├── analyze_e3_results.py
│   ├── build_lattice.py
│   ├── build_topology.py
│   ├── build_topology_from_tle.py
│   ├── import_tle.py
│   ├── run_e2_jamming_experiment.py
│   ├── run_e3_blackhole_experiment.py
│   ├── run_simulation.py
│   └── visualize_3d_optimized.py
├── starlink_sim/
│   ├── __init__.py
│   ├── analytics/             （空）
│   ├── io/                    （空）
│   ├── net/
│   │   ├── attack.py
│   │   ├── attack_jamming.py
│   │   ├── routing_dv.py
│   │   ├── simulator.py
│   │   ├── simulator_blackhole.py
│   │   └── simulator_jamming.py
│   ├── orbit/
│   │   ├── lattice.py
│   │   ├── shells.py
│   │   └── tle.py
│   └── topology/
│       └── isl.py
├── tests/
│   ├── test_dv.py
│   └── test_tle.py
└── tools/
    ├── check_imports.py
    └── check_shell.py
```

---

## 六、PLAN §8 要求但当前仍缺失的项（不在本次"整理"范围）

以下为 PLAN 要求存在但项目尚未创建的文件/目录，本次仅整理不新建：

- `README.md`
- `docs/THREAT_MODEL.md`、`docs/DESIGN.md`、`docs/METHODOLOGY.md`、`docs/REPORT.md`
- `configs/base.yaml`、`configs/topology_starlink.yaml`
- `configs/experiments/e1_baseline.yaml`、`e4_sybil.yaml`、`e5_sensitivity.yaml`、`e6_wormhole.yaml`、`e7_combo.yaml`
- `tools/tle_probe.py`、`tle_shells.py`、`tle_planes.py`、`tle_plane_check.py`、`tle_isl_geom.py`、`tle_lattice_fit.py`、`tle_grid_build.py`（PLAN 提及的 7 个只读探针）
- `starlink_sim/orbit/sgp4.py`、`frames.py`
- `starlink_sim/topology/ground.py`、`events.py`
- `starlink_sim/net/stmp.py`
- `starlink_sim/analytics/sensitivity.py`、`viz.py`、`html_topo.py`、`cross_validate_orbit.py`
- `scripts/run_experiment.py`、`run_all.py`、`cross_validate_orbit.py`

---

## 七、运行注意事项

1. `tools/check_shell.py` 使用相对路径 `data/topology/topology_results.pkl`，需以**项目根目录**为 cwd 运行：
   ```powershell
   cd C:\Users\CWQ20\Desktop\starlink
   python tools\check_shell.py
   ```
2. 所有脚本运行前需激活 venv：`.\starlink-venv\Scripts\Activate.ps1`
3. `data/topology/events_*deg.txt` 内的正文如包含原度符号，本次仅改文件名不改内容。
