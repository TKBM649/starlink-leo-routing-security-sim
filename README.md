# 🛰️ Starlink LEO Routing Security Sim

> **基于真实 TLE 的 Starlink LEO 星座路由安全仿真平台**
> DV 距离矢量路由协议 · E2 干扰 / E3 黑洞 / E4 Sybil 对抗攻击 · 4284 节点全规模仿真

[![Python 3.11](https://img.shields.io/badge/python-3.11.9-blue.svg)](https://www.python.org/downloads/release/python-3119/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#-license)
[![Status](https://img.shields.io/badge/status-E1✅_E2✅_E3✅_E4📋-brightgreen.svg)](#-实验矩阵)

---

## ✨ 项目特点

| 特点 | 说明 |
|---|---|
| 🌍 **真实 TLE 驱动** | 基于 2026-08-22 Starlink 快照（10744 条记录，SHA256 校验），非理想化星座模型 |
| 🛰️ **全规模仿真** | 4284 节点 × 121 epochs（30s 间隔），覆盖 53° 主壳层 + 97.5° 极轨壳层 |
| 🔗 **面锚定 +Grid 建链** | 同面前后各 1 + 异面相邻面各 1 + 面外几何回退，边重合率 >99%（kNN 仅 41%） |
| 📡 **DV + 路径矢量路由** | 暴露环路便于攻击观测，控制面 200ms tick / 数据面 30s epoch 双粒度 |
| ⚔️ **多类对抗攻击** | 黑洞（E3）/ 干扰（E2）/ Sybil（E4 规划中），攻击窗口可配置 |
| 📊 **可复现实验** | 固定 seed + YAML 配置 + JSON 结果，三阶段交接文档完整 |

---

## 🏗️ 架构

```
starlink_sim/
├── orbit/          # 轨道层：TLE 解析、SGP4 传播、壳层识别、格点拟合
│   ├── tle.py          parse_tle_file / filter_records
│   ├── lattice.py      面锚定格点拟合（P=72/90）
│   └── shells.py       53°/97.5°/70°/43° 壳层分类
├── topology/       # 拓扑层：ISL 建链、边集生成、重叠率分析
│   └── isl.py          build_topology_for_shell / compute_edge_overlap / propagate_satellite
├── net/            # 网络层：DV 路由 + 攻击注入 + 仿真引擎
│   ├── routing_dv.py       DV 协议核心（路径矢量防环）
│   ├── simulator.py        ControlPlane / DataPlane 基类
│   ├── attack.py           BlackholeAttacker / JammingAttacker / SybilAttacker
│   ├── attack_jamming.py   E2 干扰攻击特化
│   ├── simulator_blackhole.py  E3 黑洞仿真引擎
│   └── simulator_jamming.py    E2 干扰仿真引擎
├── analytics/      # 分析层：指标计算、结果聚合
└── io/             # I/O 层：配置加载、结果持久化
```

**数据流**：`TLE → orbit → topology → net(routing+attack) → analytics → results/`

---

## 🧪 实验矩阵

| ID | 名称 | 规模 | 攻击参数 | 状态 | 结果文件 |
|---|---|---|---|---|---|
| **E1** | 真实演化基线（无攻击） | 4284 节点 × 121 epochs | — | ✅ 完成 | `results/aggregated/simulation_summary.json` |
| **E2** | 链路干扰风暴 | 96 节点子集 × 120s | `jamming_ratio=0.9`, `inf_metric=9999` | ✅ 完成 | `results/raw/e2_jamming_seed4{2,3,4}_{1,2}.json` |
| **E3** | 黑洞/灰洞攻击 | 4284 节点 × 60s | 3 attackers, `drop_prob=0.8`, `metric_fake=0` | ✅ 完成 | `results/raw/attack_e3_blackhole_seed4{2,3,4}.json` |

---

## 📊 核心结果

### E1 基线（无攻击）

| 指标 | 值 |
|---|---|
| delivery_ratio | **1.000** |
| avg_hops | 7.96 |
| avg_latency_ms | 133.90 |
| num_success / num_trials | 12100 / 12100 |
| total_loops | 0 |

### E3 黑洞攻击（seed=42）

| 指标 | 基线 | 攻击下 | Δ |
|---|---|---|---|
| delivery_ratio | 1.000 | **0.830** | **−17.0%** |
| avg_hops | 7.96 | 6.70 | −1.26 |
| num_success / trials | 12100/12100 | 83/100 | — |
| attacked_count | — | 18 | — |
| dropped_by_attacker | — | **17** | — |
| total_loops | 0 | 0 | 无环路 ✅ |

**攻击者分布**：node 124（吸引 7 / 丢弃 7）、node 403（5/4）、node 1572（6/6）

### E2 干扰攻击（seed=42, 96 节点子集）

| 指标 | 值 | 说明 |
|---|---|---|
| delivery_ratio | 0.8775 | ≈基线（干扰效果有限） |
| avg_hops | 3.13 | 子集规模小，跳数低 |
| num_success / trials | 351/400 | — |
| attacked_count | 0 | 干扰不直接攻击节点 |
| total_loops | 0 | — |

**关键发现**：干扰攻击（抬高邻居度量至 9999）未显著降低交付率 → 转向 Sybil 攻击路线（E4）。

---

## 🚀 快速开始

### 环境要求

- Python 3.11.9
- 依赖：`numpy`, `scipy`, `sgp4`, `skyfield`, `matplotlib`, `seaborn`, `plotly`, `pandas`, `pyyaml`, `tqdm`

### 安装

```bash
# 克隆仓库
git clone https://github.com/TKBM649/starlink-leo-routing-security-sim.git
cd starlink-leo-routing-security-sim

# 创建虚拟环境
python -m venv starlink-venv
starlink-venv\Scripts\activate    # Windows
# source starlink-venv/bin/activate  # Linux/macOS

# 安装依赖
pip install numpy scipy sgp4 skyfield matplotlib seaborn plotly pandas pyyaml tqdm
```

### 运行实验

```bash
# E1: 基线仿真（无攻击）
python scripts/run_simulation.py

# E3: 黑洞攻击实验
python scripts/run_e3_blackhole_experiment.py --seed 42

# E2: 干扰攻击实验
python scripts/run_e2_jamming_experiment.py --seed 42

# 拓扑构建（从 TLE 生成 topology_results.pkl）
python scripts/build_topology_from_tle.py

# 结果分析
python scripts/analyze_e3_results.py
python scripts/analyze_e2.py
```

### 配置

实验参数通过 YAML 配置：
- `configs/experiments/e3_blackhole.yaml` — 黑洞攻击（duration/attackers/drop_prob/active窗口）
- `configs/experiments/e2_jamming.yaml` — 干扰攻击（jamming_ratio/inf_metric/placement）

---

## 📁 项目结构

```
starlink-leo-routing-security-sim/
├── README.md                     ← 本文件
├── REORGANIZE_LOG.md             目录整理与命名规范化日志
├── .gitignore
├── configs/
│   └── experiments/              e2_jamming.yaml, e3_blackhole.yaml
├── data/
│   ├── tle/                      starlink.tle (1.8MB, 10744 记录) + 过滤产物
│   ├── topology/                 topology_results.pkl (24MB) + events_*.txt (4 壳层)
│   ├── lattice/                  lattice_result.pkl (3MB) + summary.json
│   └── snapshots/                位置缓存（.gitignore 排除，可重新生成）
├── docs/
│   └── DECISIONS_AND_ISSUES.md   三阶段关键决策/已知问题/失败方案汇编
├── results/
│   ├── aggregated/               simulation_summary.json (E1 基线)
│   ├── raw/                      E2/E3 逐 seed JSON（排除 800MB routing_tables.pkl）
│   ├── figures/                  分析图表 CSV/PNG
│   └── viz/                      3D 可视化 HTML（.gitignore 排除，可重新生成）
├── scripts/                      9 个实验/构建/分析脚本
├── starlink_sim/                 核心包（orbit/topology/net/analytics/io）
├── tests/                        test_dv.py, test_tle.py
└── tools/                        check_imports.py, check_shell.py
```

---

## 📚 文档

| 文档 | 内容 |
|---|---|
| [`REORGANIZE_LOG.md`](./REORGANIZE_LOG.md) | 目录整理与命名规范化变更日志（27 项文件操作） |
| [`docs/DECISIONS_AND_ISSUES.md`](./docs/DECISIONS_AND_ISSUES.md) | 三阶段关键技术决策 / 已知问题 / 失败方案汇编 |
| `部分操作解析和常见问题.pdf` | 操作解析与常见问题（中文） |

---

## 🛠️ 技术栈

| 层 | 技术 |
|---|---|
| 轨道传播 | `sgp4`（自研内核）+ `skyfield`（Step 9 外部校验） |
| 数据处理 | `numpy`, `scipy`, `pandas` |
| 可视化 | `matplotlib`, `seaborn`, `plotly`（3D HTML） |
| 配置 | `pyyaml` |
| 数据源 | CelesTrak TLE 快照（2026-08-22，SHA256 `852E79A4...`） |

---

## 🔑 数据源

- **TLE 快照**：`data/tle/starlink.tle`
  - 记录数：10744
  - SHA256：`852E79A4D2EB28EE5864FC86BC204CB50DDE2FEE83F27A7F5B9D2356932FC97B`
  - 来源：CelesTrak（2026-08-22 抓取）
  - 壳层分布：53°（主壳层, P=72）、97.5°（极轨, P=90）、70°、43°

---

## ⚠️ 已知限制

1. **位置缓存缺失**：`data/snapshots/positions_per_epoch.pkl` 未生成 → E2/E3 的 `avg_latency_ms` 为 0（E1 基线有值 133.9ms）
2. **E2 子集规模**：干扰实验限于 96 节点 BFS 连通子图（全规模 DV 收敛过慢）
3. **E4 Sybil 未实现**：`SybilAttacker.modify_advertisement` 仍为占位
4. **STMP 防御未实现**：ODTA / TESLA / 信誉机制待开发

详见 [`docs/DECISIONS_AND_ISSUES.md`](./docs/DECISIONS_AND_ISSUES.md)。

---

## 📄 License

MIT License — 详见 [LICENSE](./LICENSE)（待添加）。

---

## 📧 联系

- **GitHub**: [@TKBM649](https://github.com/TKBM649)
- **Issues**: [提交问题](https://github.com/TKBM649/starlink-leo-routing-security-sim/issues)

---

<p align="center">
  <sub>Built with ❤️ for LEO satellite network security research</sub>
</p>
