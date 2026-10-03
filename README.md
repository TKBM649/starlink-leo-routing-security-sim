# 🛰️ Starlink LEO 星座路由安全仿真平台

> **基于真实 TLE 的 Starlink 星座路由安全仿真平台**：DV / 路径矢量路由 + 五类对抗攻击（黑洞 / 干扰 / Sybil / 虫洞 / 组合）+ 跨壳与规模档对比 + 严格的统计与可复现约定。
> 纯 Python，易复现；含基于真实 TLE 的 3D 可视化。

[![Python 3.11](https://img.shields.io/badge/python-3.11.9-blue.svg)](https://www.python.org/downloads/release/python-3119/)
[![Tests](https://img.shields.io/badge/tests-286%20passed-brightgreen.svg)](#回归测试)
[![Step3](https://img.shields.io/badge/step3-530%2F630%20raw%2C%207%2F9%20sweeps-yellow.svg)](#-实验矩阵)
[![License](https://img.shields.io/badge/license-not%20specified-lightgrey.svg)](#-license)

---

## ⚠️ 读任何数字之前：三套口径互不可直接比较

本仓库同时存在**三代实验口径**，把它们并列比较会得出错误结论（例如"性能下降 10.5%"）。完整论述见 [`report.md` §1.4](./report.md) 与 §4.9。

| 口径 | 规模 | 评估窗口 | trials/seed | 基线 DR | 出处 |
|---|---|---|---|---|---|
| **① 历史 E1**（原仓库，3 seeds） | `num_nodes=4284`（产物自记） | `num_epochs=121` | **12100**（= 100 flows × 121 epochs） | **1.0000** | `results/aggregated/simulation_summary.json` |
| **② step3 攻击矩阵（B 档，当前主口径）** | 53° 持久核子集 `node_limit=1024` | **2 epochs**（`duration=60s` / `epoch_interval=30s`） | **40**（= 2 × 20 flows × 1），seeds 42–51 | **0.8950** ± 0.0643，CI95 [0.8550, 0.9300] | `results/aggregated/step3/` |
| **③ 跨壳对比** | `node_limit=256`（四壳最大公共 2 的幂档） | 2 epochs，动态 | 40 × 10 seeds | 0.7900（53°） | 同上，`sweep=shell256` |

- 口径②与③的**匹配键不同**（`shell` / `node_limit` / `num_eval_epochs` / `num_flows`），跨口径调用 `compare_attack_vs_baseline()` 会（正确地）抛 `TrialsCardinalityError`。
- 口径②的 411 次比较**未做任何多重校正**（`step3_comparisons.csv` 22 列中无校正后 p 值列；全仓 `.py` 中 `bonferroni` / `holm` / `fdr` 命中 0）。见 `report.md` §6 **L9**。
- 本 README 的每个数字都附带**可在仓库内复核的路径**；若与任何文档冲突，**以产物字段为准**。

---

## ✨ 项目特点

| 特点 | 说明 | 复核路径 |
|---|---|---|
| 🌍 **真实 TLE 驱动** | CelesTrak Starlink 快照 2026-08-22，10744 条三行组记录，SGP4 传播；禁用 Walker / 理想星座模型（DC-1~DC-5） | `data/tle/starlink.tle`（1,772,759 B / 32,232 行）、`docs/DESIGN.md` §3 |
| 🛰️ **四壳层真实拓扑** | 53°(4284) / 43°(3262) / 97.5°(1076) / 70°(702)，逐 epoch 边集；53° 平均度 5.713，300 s 边重合率 0.868 | `data/topology/topology_summary.json` |
| 🔗 **面锚定 +Grid 建链** | 同面前后各 1 + 异面相邻面各 1 + 面外几何回退；格点拟合与 off-lattice 比例随产物给出 | `data/lattice/lattice_summary.json`、`starlink_sim/topology/isl.py` |
| 📡 **DV + 路径矢量路由** | 刻意选择 DV 作为"分布式路由脆弱性参照系"（**不声称是 Starlink 实际路由**），老化 / 触发更新 / 环路可观测；控制面 200 ms tick、数据面 30 s epoch 双粒度 | `starlink_sim/net/routing_dv.py`、`docs/DESIGN.md` §1.1 |
| ⚔️ **五类攻击 × 39 个攻击臂** | 黑洞（E3/E5）、干扰（E2/E7）、Sybil（E4）、虫洞（E6）、组合（E7）；放置策略 5 种、强度双梯度、规模 5 档、壳层 4 个 | `configs/experiments/step3/`、`starlink_sim/net/attack.py` |
| 📊 **严谨统计框架** | bootstrap 95% CI（`n_boot=4000`、`rng=0`、下限 2000 门禁）、同 seed ≥2 用 Wilcoxon 否则 Mann-Whitney U、匹配键不一致即判不可比 | `starlink_sim/analytics/stats.py`、`results/aggregated/step3/step3_summary.json` |
| ✅ **可复现** | 固定 seed + YAML 配置 + JSON 结果 + raw 内嵌出身字段（TLE/拓扑哈希、基数三元组、匹配键）；`pytest -q tests` 286 通过 | `results/step3_raw/*/*.json`、`tools/verify_step3_raw.py` |
| ⚠️ **诚实局限** | 17 条已编号局限（L1–L17）与其重建过程随报告一并发布 | `report.md` §6 与 §6.1 |

---

## 🧪 实验矩阵

**Phase 0/1 已交付**（下表），故本仓库全部数字都是**攻击侧效应**，不存在任何"防御后"对照（`report.md` **L12①**）。

| ID | 名称 | sweep key | 臂 / raw | 状态 | 结果文件 |
|---|---|---|---|---|---|
| **E1** | 真实演化基线（无攻击，历史口径） | — | 1 臂 / 3 seeds | ✅ 历史 | `results/aggregated/simulation_summary.json` |
| **E2** | 链路干扰风暴（96 子集，历史口径） | — | 10 attackers / 3 seeds | ✅ 历史 | `results/raw/e2_jamming_seed4{2,3,4}.json` + `e2_noattack_*` |
| **E3** | 黑洞/灰洞攻击（全量节点，历史口径） | — | 3 attackers / 3 seeds | ✅ 历史 | `results/raw/attack_e3_blackhole_seed4{2,3,4}.json` |
| **E4** | Sybil 身份数梯度（1/2/4/8/16/32） | `e4_sybil` | 7 / **70** | ✅ | `results/aggregated/step3/step3_arms.csv` |
| **E5-a** | 黑洞 count 梯度（c1–c24）+ drop_prob 梯度（p00–p100） | `e5_intensity` | 10 / **100** | ✅ | 同上 |
| **E5-b** | 放置策略排序（random / betweenness / last-epoch-degree / degree / k-core） | `e5_placement` | 6 / **60** | ✅ | 同上 |
| **E5-c** | 规模阶梯（nl = 48 / 96 / 256 / 512 / 1024） | `e5a_scale_small` | 10 / **100** | ✅（**无 nl=2048 顶档**） | 同上 |
| **E6** | 虫洞攻击与检测器（t1 / t3 / extreme + 基线） | `e6_wormhole` | 4 / **40** | ✅（结果反直觉，见下） | 同上 |
| **E7** | 组合攻击协同性（bh3 / jm3 / sy8 及其 2、3 元组合） | `e7_combo` | 8 / **80** | ✅（含 Sybil 组合不可判定，**L6**） | 同上 |
| **跨壳** | 四壳同一攻击配置（43°/53°/70°/97.5°，nl=256） | `shell256` | 8 / **80** | ✅（**唯一主口径**） | 同上 |

**合计**：门禁目标 630 raw → 实际交付 **530 raw**（差额 100 = `shell1024` 80 + `e5a_scale_top` 20）；7/9 个 sweep 齐全。
复算：`results/step3_raw/<sweep>/*.json` 计数应为 `e4_sybil 70 + e5_intensity 100 + e5_placement 60 + e6_wormhole 40 + e7_combo 80 + shell256 80 + e5a_scale_small 100 = 530`，与 `results/aggregated/step3/step3_completeness.csv`（63 条目，其中 10 条未完成）和 `report.md` **L17** 一致。

---

## 📊 核心结果（step3，B 档 = 53° / nl=1024 / 10 seeds / 40 trials·seed⁻¹）

下表全部取自 `results/aggregated/step3/step3_arms.csv`（603 数据行 × 14 列，指标 `delivery_ratio`），**mean 为 10 seeds 的均值、CI 为 bootstrap 95% 区间**。

| sweep | 臂 | delivery_ratio mean | CI95 | 一句话解读 |
|---|---|---|---|---|
| 基线（三档共用） | `base` | **0.8950** | [0.8550, 0.9300] | 参照点 |
| E4 Sybil | `ids1` / `ids2` | 0.0450 | [0.0200, 0.0750] | **1 个虚假身份即近饱和**（吸引率 0.9125） |
| E4 Sybil | `ids4` | 0.0250 | [0.0050, 0.0550] | 梯度不可分辨 |
| E4 Sybil | `ids8` / `ids16` / `ids32` | **0.0000** | [0, 0] | 唯一把 DR 压到 0 的单攻击 |
| E5 强度 | `c1`→`c24` | 0.5575 → 0.0275 | — | count 单调压制 |
| E5 强度 | `p00`（**不丢包**） | **0.5450** | [0.4825, 0.6100] | 仅"广告为最优下一跳"的**路由吸引**就造成 35% 损失 |
| E5 强度 | `p20`/`p50`/`p100` | 0.4625 / 0.3700 / 0.2550 | — | 丢包概率的第二条轴 |
| E5 放置 | `rnd` | 0.6050 | [0.5200, 0.6825] | 最弱 |
| E5 放置 | `btw` / `led` | 0.3425 / 0.3300 | — | 中间 |
| E5 放置 | `degree` ≈ `kcore` | **0.3000** | [0.2374, 0.3675] | 拓扑感知使攻击效力 ≈ 翻倍 |
| E5-c 规模 | `base_n48`…`base_n1024` | 1.0 / 1.0 / 0.7900 / 0.8800 / 0.8950 | — | base **非单调** |
| E5-c 规模 | `bh3_n48`…`bh3_n1024` | 0.1325 / 0.2775 / 0.4475 / 0.4500 / 0.3000 | — | 平均度混杂（2.875→5.726）→ **不主张规模律**（**L5**） |
| E6 虫洞 | `t3` | **0.9450** | [0.9200, 0.9725] | **显著高于基线**（p=0.0039）→ `peer_only` 语义在本拓扑上是**改善**而非攻击 |
| E6 虫洞 | `t1` | 0.9175 | [0.8825, 0.9525] | 同上方向 |
| E6 虫洞 | `extreme` | **0.0000** | [0, 0] | 只有 `peer_side` 语义才是破坏性攻击 |
| E7 组合 | `jm3` | 0.8950 | [0.8550, 0.9300] | 与基线**逐位相同**（p=1.0）→ 干扰对数据面**完全惰性** |
| E7 组合 | `bh3` / `bh3_jm3` | 0.3000 / 0.2900 | — | 未观察到超加性（偏差 p=0.7266） |
| E7 组合 | `sy8` / `bh3_sy8` / `jm3_sy8` / `bh3_jm3_sy8` | **0.0000** | [0, 0] | DR 触底删失 → 协同性**不可判定**（**L6**） |
| 跨壳 nl=256 | `base_43`/`base_53`/`base_70`/`base_975` | 0.6800 / 0.7900 / 1.0000 / 1.0000 | — | 同一子集规模下的壳间差异 |
| 跨壳 nl=256 | `bh3_43`/`bh3_53`/`bh3_70`/`bh3_975` | 0.2350 / 0.4475 / 0.6100 / 0.4500 | — | 壳内配对（10 pairs/壳） |

**七条关键结论**（含机理与限制条件）见 [`report.md` §0.3](./report.md)。**每一条都必须与 §6 的 L1–L17 同读**。

> ⚠️ **`avg_hops` / `avg_latency_ms` 在攻击臂不可单独解读**：被丢弃的流一律记 0，均值被零填充稀释（恒有 `avg_hops ≡ avg_success_hops × num_success / num_trials`，530/530 成立）。"177 ms → 2 ms"**不是性能改善**。要看干净口径请用 `avg_success_hops` / `avg_success_latency_ms`。详见 **L8**。
> ⚠️ **`total_loops` 不作攻击效应指标**：基线 nl=1024/2 epochs 即 25031.0（10 seeds 逐位相同），是控制面收敛产物。详见 **L10**。

---

## 📊 历史 E1 / E2 / E3（原仓库口径，**仅 3 seeds，不满足本平台统计规范**）

下列数字**不满足** ≥10 seeds + bootstrap CI + 配对检验的规范，仅作历史参照，**不得**与上表并列（`report.md` §4.9）。

**E1 基线**（`results/aggregated/simulation_summary.json` 自记字段）：`num_nodes=4284`、`num_epochs=121`、`num_ticks=1000`、`flows` 100 条、`total_routing_entries=18,348,372`、`loop_events_count=0`、DR **1.0000**、`avg_hops` 7.96、`avg_latency_ms` 133.90、`num_success/num_trials` = 12100/12100。

**E3 黑洞**（4284 节点 / `duration=60s` / 3 attackers `placement=degree`、`drop_prob=0.8`、`metric_fake=0`、窗口 20–40 s；`configs/experiments/e3_blackhole.yaml`）：

| seed | DR | avg_hops | num_success/trials | attacked_count | dropped_by_attacker | total_loops |
|---|---|---|---|---|---|---|
| 42 | 0.83 | 6.70 | 83/100 | 18 | 17 | **100122** |
| 43 | 0.87 | 6.84 | 87/100 | 14 | 13 | 0 |
| 44 | 0.83 | 6.40 | 83/100 | 20 | 17 | 0 |
| **均值 ± 标准差** | **0.843 ± 0.023** | 6.65 ± 0.22 | — | 17.3 ± 3.1 | 15.7 ± 2.3 | — |

*标准差为 3 个 seed 的样本标准差（`ddof=1`）；旧版 README 所写 `avg_hops 6.65 ± 0.23` 系该值的错误四舍五入（实为 0.2248）。*

> ⚠️ 三点更正：① 该组逐 seed 值的出处是 `results/raw/attack_e3_blackhole_seed4{2,3,4}.json` 的 `data_stats`，**不是** `results/figures/attack_seed42_44.csv`（后者与 E2 干扰 raw 逐字段相同，属 **E2** 表）；② `results/raw/aggregated_attack_e3.json` 的 `num_seeds = 1`，它是 **seed42 单体**的聚合（`mean_total_loops = 100122.0`），不得当作 3 seeds 均值引用；③ seed 43/44 的 `avg_latency_ms` 为 `0.0`（该代产物未填时延），且 `total_loops` 在 seed42 为 100122 而 43/44 为 0 —— 旧版"无环路 ✅"的说法不成立，本指标依 **L10** 不作效应解读。

**E2 干扰**（96 节点 BFS 子集 / `duration=120s` / 10 attackers `placement=degree`、`jamming_ratio=0.9`、`inf_metric=9999`、窗口 20–40 s；`configs/experiments/e2_jamming.yaml`）：

| seed | DR（攻击） | DR（无攻击基线） | attacked_count | total_loops | avg_hops | num_success/trials |
|---|---|---|---|---|---|---|
| 42 | 0.775 | 0.8775 | 179 | 47 | 2.7025 | 310/400 |
| 43 | 0.815 | 0.9350 | 191 | 54 | 2.7175 | 326/400 |
| 44 | 0.840 | 0.9400 | 184 | 49 | 2.7850 | 336/400 |
| **均值 ± 标准差** | **0.810 ± 0.033** | **0.9175 ± 0.0347** | 184.7 ± 6.0 | 50 ± 3.6 | 2.735 ± 0.044 | — |

> 出处：`results/raw/e2_jamming_seed4{2,3,4}.json` 与 `results/raw/e2_noattack_seed4{2,3,4}.json`；同口径的两两对照见 `results/figures/paired_seed42_44.csv`。⚠️ 旧版 README 把无攻击基线写成"≈0.84"，实为 **0.9175**（0.84 是 seed44 的攻击值）；`num_trials = 400` = 100 flows × 4 epochs（`duration=120s / epoch_interval=30s`）；`dropped_by_attacker` 在 3 个 seed 均为 0（干扰作用于控制面度量，不在数据面主动丢包）。
> 修复说明（Issue #1/#2）：旧结果 `attacked_count=0`、"干扰完全无效"源于入口配置 `count=0`（实际未部署攻击者）且通告注入未生效；修复后以 `count=10` 部署并使 `inf_metric=9999` 撤回真实生效。**注意**：该结论只在 96 子集/120 s 口径下成立，B 档的 `jm3` 臂显示干扰对数据面**完全惰性**（**L12①** §0.3 第 6 条）。

---

## 🧮 统计方法学

- **聚合策略**（`results/aggregated/step3/step3_summary.json` 的 `policy`）：bootstrap 95% CI；同 seed ≥2 用 **Wilcoxon**，否则 **Mann-Whitney U**；`compare_attack_vs_baseline(strict=True)` —— 匹配键不一致即判为不可比，**不做任何放宽**。
- **确定性**：`n_boot = 4000`、`alpha = 0.05`，全部聚合调用点固定 `rng=0`（`scripts/aggregate_step3.py:253`、`run_experiment_sweep.py:541`、`aggregate_stats.py:144` 与 `:156`、`run_simulation.py:271`）；`starlink_sim/analytics/stats.py:150-151` 对 `n_boot < 2000` 直接 `raise ValueError`。**改动 `rng` 或 `n_boot` 会使所有 CI 偏移**。
- **规模**：39 组攻击/基线对比 → `step3_comparisons.csv` **411 数据行 × 22 列**，`failures = 0`；指标全集 **25 项**（= `step3_summary.json.metrics_universe`）。
- **效应量符号已修复**：`scipy ≥1.7` 的 `wilcoxon(...).statistic` 返回 `min(T⁺,T⁻)` 而非 `T⁺`，旧代码按 `T⁺` 口径代入 → `rank_biserial` 符号失效（p 值与显著性判定**从未受影响**，修复前后 271→411 行逐条校验为 0 差异，证据 `results/step3_logs/pvalue_zero_change_check.txt`）。修复于 commit `89c6dcb`（`signed_rank_biserial()` + 7 个回归测试）。
- ⚠️ **陈旧产物不得引用其 `rank_biserial` 符号**：`results/aggregated/step3_partial/`（61 条目，修复前快照）与 `results/step3_agg/{e4_sybil,e5_intensity,e5_placement,e6_wormhole}/comparison_*.json`。**唯一权威来源是 `results/aggregated/step3/`**（97 条目）。
- ⚠️ **未做多重校正**（**L9**）、**评估窗口仅 2 epochs / 40 trials·seed⁻¹**，因此无法观察攻击的时序演化（收敛期 vs 稳态期）。
- ⚠️ **敌手假设偏向攻击上界**（**L13**）：`seq_lead = 8`（`starlink_sim/net/attack.py:192`）使伪造序号永远追不上；`metric_fake = 0`（`:87`）与 `inf_metric = 9999`（`:121`）同为最有利于攻击者的取值。
- ⚠️ **39/39 攻击臂均为常驻窗口**（`active_since: 0.0` / `active_until: .inf`）→ 间歇性/择时攻击**完全未测**（**L14**）。

---

## 🚀 快速开始

### 环境要求

- Python **3.11.9**（`metadata.python_version` 即此值）
- 依赖见 `requirements.txt`：`numpy>=1.26,<2.0`、`scipy>=1.15,<2.0`、`sgp4>=2.23,<3.0`、`pandas>=2.2,<4.0`、`matplotlib>=3.8`、`seaborn>=0.13`、`plotly>=5.18`、`networkx>=3.2`、`pyyaml>=6.0`、`tqdm>=4.60`、`pytest>=8.0`（`skyfield` 在 `requirements.txt` 中为注释掉的可选依赖，仅用于外部轨道校验）

```bash
git clone https://github.com/TKBM649/starlink-leo-routing-security-sim.git
cd starlink-leo-routing-security-sim
python -m venv starlink-venv
starlink-venv\Scripts\activate        # Windows
# source starlink-venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
```

### 复现拓扑缓存（**必需**，pkl 不入库）

```bash
# TLE -> 过滤产物 + 格点拟合
python scripts/import_tle.py
python scripts/build_lattice.py

# TLE -> data/topology/topology_results.pkl（≈98 MiB，逐 epoch 边集）
python scripts/build_topology_from_tle.py
```

⚠️ `scripts/build_topology.py:48` 与 `scripts/build_topology_from_tle.py:48` 均以 **`max_dist_km=99999.0`** 调用（距离门限事实上被禁用）→ 这使 E6 的距离检测器**无可分离阈值**（**L2**）。**重跑这两个脚本会改变 `topology_cache_sha256`（现行 `f23f7ecdef89…`），本仓库全部数字随之失效**（**L16②**）。

### 跑 step3 攻击矩阵（B 档）

```bash
# 0) 先看计划，不执行
python scripts/gen_step3_configs.py --list
python scripts/run_step3_matrix.py --list

# 1) 齐套性 / 口径校验（只读）
python tools/verify_step3_raw.py --only shell256 -v

# 2) 跑单个 sweep（示例：跨壳档；并行度与内存预算见 docs/STEP3_SHELL_SCALE_RUNBOOK.md §4）
python scripts/run_experiment_sweep.py \
  --sweep-config configs/experiments/step3/sweep_shell256.yaml \
  --seeds 42 43 44 45 46 47 48 49 50 51 --workers 8

# 3) 断点续跑整张矩阵（注意：runbook §2 的 --only 清单已被 D2/D3 取代，见下）
python scripts/run_step3_matrix.py --skip-existing

# 4) 聚合 + 7 张图（默认 n_boot=4000 / alpha=0.05 / rng=0）
python scripts/aggregate_step3.py --only shell256
python scripts/aggregate_step3.py            # 全量：97 条目写入 results/aggregated/step3/
```

⚠️ `docs/STEP3_SHELL_SCALE_RUNBOOK.md` 的 §1/§2/§7.2（"630 = 350 已有 + 280 本轮"、`--only e5a_scale_small shell256 shell1024 e5a_scale_top`）**已被 D2/D3 取代**：`shell1024` 与 `e5a_scale_top` 两档目录不存在，照抄会走偏（见 `report.md` **L17**）。其 §3 之后的 dry-run、内存档位、workers、中断续跑章节仍可用。

### 跑历史 E1 / E2 / E3（原仓库口径）

```bash
python scripts/run_simulation.py --config configs/experiments/e1_baseline.yaml --seeds 42
python scripts/run_e3_blackhole_experiment.py --config configs/experiments/e3_blackhole.yaml --seeds 42
python scripts/run_e2_jamming_experiment.py   --config configs/experiments/e2_jamming.yaml   --seeds 42
python scripts/analyze_e3_results.py
python scripts/analyze_e2.py
python scripts/visualize_3d_optimized.py     # 3D HTML 输出到 results/viz/（不入库，目录当前不存在）
```

### 回归测试

```bash
python -m pytest -q tests
# 2026-10-03 在本仓库根实测：286 passed, 2 warnings in 5.60s（Python 3.11.9）
```

15 个测试文件覆盖：DV 与路径矢量、老化、攻击注入与窗口门禁、多攻击者链式、Sybil、虫洞、放置策略、持久核子集、统计框架（含 7 个符号约定回归测试）、配置加载、TLE 解析、sweep 入口一致性。

---

## 🏗️ 架构

```
starlink_sim/                       # 核心包，16 个模块
├── orbit/          轨道层：TLE 解析 / SGP4 传播 / 壳层识别 / 格点拟合
│   ├── tle.py          parse_tle_file / filter_records
│   ├── lattice.py      面锚定格点拟合（53° 拟合 P=180，off_lattice 9.20%）
│   └── shells.py       53°/97.5°/70°/43° 壳层分类
├── topology/       拓扑层：ISL 建链、逐 epoch 边集、重叠率、持久核子集
│   ├── isl.py          build_topology_for_shell / compute_edge_overlap / propagate_satellite
│   └── subset.py       cumulative_degree / stable_core 子集选择（355 行）
├── net/            网络层：DV 路由 + 攻击注入 + 仿真引擎
│   ├── routing_dv.py       DV 核心（老化 / 触发更新 / 路径矢量防环）
│   ├── simulator.py        Simulator / ControlPlane / DataPlane（支持 attackers 链式）
│   ├── attack.py           Blackhole / Jamming / Sybil（改写 DVMessage.entries，含 controls()）
│   ├── placement.py        5 种放置策略 + check_attack_windows() 窗口门禁
│   ├── sybil.py            叙比尔身份与吸引（298 行）
│   └── wormhole.py         虫洞隧道与距离/时延检测器（943 行）
├── analytics/stats.py    bootstrap CI / Wilcoxon / Mann-Whitney / signed_rank_biserial / 匹配键门禁
└── io/config.py          load_experiment_config（schema v2 YAML）
```

**数据流**：`TLE → orbit → topology(逐 epoch 边集) → subset(持久核) → net(routing + attack + sim) → analytics(stats) → results/`

---

## 📁 项目结构（与 `git ls-files` 一致：入库 1054 个文件）

```
starlink-leo-routing-security-sim/
├── README.md                     本文件
├── report.md                     ★ 综合实验报告（§0 摘要 / §3 方法学 / §4 结果 / §5 交付物 / §6 诚实局限 L1–L17）
├── requirements.txt              依赖（版本区间）
├── conftest.py                   pytest 根夹具
├── .gitignore                    73 行；:31/:36/:42/:45/:55/:56/:71 被 report.md 按行号引用，勿随意改动
├── configs/experiments/          27 个 YAML（E1/E2/E3/E4/E5/E6 历史与演示档）
│   └── step3/                    61 个 YAML = 52 臂定义（13 基线 + 39 攻击/组合）+ 9 个 sweep_*.yaml
├── data/
│   ├── tle/                      ★ starlink.tle（1.77 MB / 10744 记录，入库）+ filter_report.json
│   │                             └ filtered_records.pkl（2.96 MB，*.pkl 排除，需自行生成）
│   ├── topology/                 ★ topology_summary.json + 8 份 events_*.{txt}（入库）
│   │                             └ topology_results.pkl（102,763,675 B = 98.00 MiB，被 .gitignore:36/:42 排除，必须自行生成）
│   ├── lattice/                  lattice_summary.json（入库）+ lattice_result.pkl（3.01 MB，排除）
│   └── snapshots/                不存在（.gitignore:45 排除位置缓存，可重新生成）
├── docs/                         DESIGN.md / THREAT_MODEL.md / DECISIONS_AND_ISSUES.md / STEP3_SHELL_SCALE_RUNBOOK.md
├── results/
│   ├── step3_raw/                ★ 530 个 raw JSON（B 档逐 seed 全量证据，schema_version=2，含出身字段）
│   ├── aggregated/step3/         ★ 权威聚合（97 条目 = 53 agg_ + 39 cmp_ + 4 张表 + step3_summary.json）
│   ├── aggregated/step3_partial/ 修复前快照（61 条目，保留作 L1 对照；符号不可信）
│   ├── figures/                  19 个（fig1–fig7 的 png+csv，及历史 E2/E3 三张 seed 对照 CSV）
│   ├── step3_logs/               18 个入库证据（`_verify_all.txt`、`pvalue_zero_change_check.txt`、`_matrix_summary.json`、
│   │                             shell_scale_equivalence.json、dryrun/checkpoint 等）；11 份 *.log 被 .gitignore:71 排除
│   ├── step3_agg/                67 个早期聚合产物（修复前，符号不可信）
│   ├── raw/  aggregated/         历史 E1/E2/E3 产物（10 + 1 个）
│   └── raw_t7/ aggregated_t7/ sweep_demo_*/ sweep_e4_*/ _smoke_*/   早期与冒烟运行残留
├── scripts/                      15 个：矩阵驱动 / sweep 执行 / 聚合 / 配置生成 / E1–E3 入口 / 拓扑与格点构建 / 可视化 / 分析
├── starlink_sim/                 核心包（16 模块）
├── tests/                        15 个测试文件，286 用例
└── tools/                        check_imports.py / check_shell.py / verify_step3_raw.py / probe_shell_scale_equivalence.py
```

**刻意未入库**（工作区 `git status --porcelain` 恒为 6 条）：仓库根的 5 个会话调试脚本 `_cmp_pvalues.py`、`_det_check.py`、`_merge_summary.py`、`_report_extract.py`、`_x2.py`，以及隔离目录 `results/step3_logs_jason/`（3 个 UTF-16LE 文件：`shell256.log` / `e5a_scale_small.log` / `_mem_baseline.txt`）。
⚠️ 其中两份日志是 `report.md` §3.3 那对 CI（0.8400 vs 0.8350）的**唯一物证**，故该论点在仓库内**不可复算**（见 `report.md` **L11**、**L16⑥** 与 §6 第 11 条声明）。

---

## 🔑 数据源指纹（以实测为准）

| 对象 | 实测值 | 出处 |
|---|---|---|
| `data/tle/starlink.tle` | **1,772,759 B**，SHA256 `212276b98b2b75d05abeda23e091cf7e9a9c20dd6a373d1d887eb76a4b6c9be1`；32,232 行 = 10,744 条记录 | 本地 `sha256sum`；与全部 **530/530** 个 raw 的 `metadata.tle_sha256` 一致 |
| `data/topology/topology_results.pkl` | SHA256 `f23f7ecdef8972e0e4d7292a0576116f06713baa0c1a3dbc51cf8cab8d940f9d`（98.00 MiB，**不入库**） | 530/530 个 raw 的 `metadata.topology_cache_sha256` |
| TLE 抓取原件 | SHA256 `852E79A4D2EB28EE5864FC86BC204CB50DDE2FEE83F27A7F5B9D2356932FC97B` | `data/tle/filter_report.json` 的 `source_sha256`（由 `scripts/import_tle.py:30` **硬编码**，非计算值） |
| 过滤统计 | `total_parsed=10744`、`error_count=0`、380 km 门限后 `after_filter_count=9905`、`bstar<0` 1026 / `bstar>1e-3` 8879 | `data/tle/filter_report.json` |
| 壳层（topology_summary） | 53° 4284（avg_degree 5.713 / overlap300s 0.868 / 首 epoch 12238 边 / 全时 60714 边）；43° 3262（5.503 / 0.988）；97.5° 1076（4.647 / 0.975）；70° 702（5.635 / 0.976） | `data/topology/topology_summary.json` |
| 格点（lattice_summary） | 53° P=180（off_lattice 394 = 9.20%）；43° P=99；97.5° P=93；70° P=36 | `data/lattice/lattice_summary.json` |

> ⚠️ **两个 SHA256 不是同一个东西**：`852E79A4…` 是"抓取原件"的**硬编码声称值**，`212276b9…` 是仓库内 `starlink.tle` 的**实测值**（也是所有实验实际使用的指纹）。旧版 README 与 `docs/DESIGN.md:85`（DC-2）、`:97` 都写的是前者，故**请勿据其校验当前文件**；引用数据源指纹一律用 `212276b9…`。

---

## 📚 文档

| 文档 | 内容 | 状态 |
|---|---|---|
| [`report.md`](./report.md) | **综合实验报告**：执行摘要、三套口径、Phase 0 地基修复、方法学、§4 攻击矩阵实测（4.1–4.9）、交付物清单、**§6 诚实局限 L1–L17 + §6.1 重建说明（十一条边界声明）** | ✅ 权威；引用 §4 的任何数字都必须同引 §6 对应条目 |
| [`docs/DESIGN.md`](./docs/DESIGN.md) | 设计定位与保真度声明（协议定位、保留 vs 简化对比表、DC-1~DC-5 硬约束、文献锚定、外推边界） | ⚠️ 10 处引用标注"待核验"；DC-2 的 SHA256 已过时（见上） |
| [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) | 威胁模型 8 章（资产/边界、敌手能力与上限、攻击面 AS-1~AS-6、STRIDE、DREAD、信任假设、缓解措施映射） | ⚠️ 13 处引用"待核验"；DREAD 事前评分与实测不一致（Sybil 事前最低 → 实测最强），见 `report.md` §1.2 |
| [`docs/DECISIONS_AND_ISSUES.md`](./docs/DECISIONS_AND_ISSUES.md) | 原仓库三阶段（Step 3 DV / Step 4 E3 / Step 5 E2）决策、已知问题、失败方案汇编 | ⚠️ 部分数值（P=72/90、2000 km 门限、>99% 重合率）与现行产物不符；"E5 敏感性分析"承诺未兑现（**L15**） |
| [`docs/STEP3_SHELL_SCALE_RUNBOOK.md`](./docs/STEP3_SHELL_SCALE_RUNBOOK.md) | Task #12 实跑 runbook（门禁、启动命令、dry-run、内存/workers、监测、中断续跑） | ⚠️ **§1/§2/§7.2 已被 D2/D3 取代**，照其执行会走偏（**L17**） |

---

## 📄 License

**当前仓库未包含 LICENSE 文件**

---

## 📧 联系

- **GitHub**: [@TKBM649](https://github.com/TKBM649)
- **Issues**: [提交问题](https://github.com/TKBM649/starlink-leo-routing-security-sim/issues)
- 引用本仓库结果时，请**同时引用** `report.md` §6 中对应的局限条目（L1–L17），并注明所用口径（①/②/③）。

---

<p align="center">
  <sub>Built for LEO satellite network security research · DV 参照系 · 真实 TLE · 攻击侧实测</sub>
</p>
