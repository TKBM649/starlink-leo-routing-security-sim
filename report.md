# Starlink LEO 星座路由安全仿真平台 — 综合实验报告

**报告日期**：2026-09-30
**仓库根**：`starlink-leo-routing-security-sim-main/starlink-leo-routing-security-sim-main/`（下文所有相对路径均以此为根）
**数据源**：CelesTrak Starlink TLE 快照 2026-08-22，10744 条记录，`tle_sha256 = 212276b98b2b...`，`topology_cache_sha256 = f23f7ecdef89...`
**代码版本**：git commit `89c6dcb65076802f2f10b0dcb93e1ef89a535311`
**测试状态**：`pytest -q tests` → **286 passed, 2 warnings**
**交付定位**：学术安全评估平台（严谨统计 + 威胁模型 + 攻防闭环 + 完全可复现）

> **口径声明（必读）**：本报告存在**三套互不可直接比较**的实验口径，任何数字都必须与其口径联读。详见 §1.4。

---

## 0. 执行摘要

### 0.1 完成度

| 阶段 | 范围 | 状态 |
|---|---|---|
| **Phase 0** | 地基修复 7 项（威胁模型 / DV 加固 / 时延修复 / 可复现性 / 统计框架 / 集成验证） | ✅ **全部完成** |
| **Phase 1** | 攻击矩阵扩展 E4/E5/E6/E7 + 并行化 + 跨壳 + 规模阶梯 | ⚠️ **大部分完成**：530/630 任务，7/9 sweep |
| **Phase 2** | STMP 防御侧（Defender 框架 / ODTA / TESLA / 信誉评分） | ❌ **未开始**（预算耗尽） |
| **Phase 3** | 综合报告与交付物 | ✅ 本文档 |

### 0.2 核心数字（统一 B 档口径：53° 壳，node_limit=1024，10 seeds，40 trials/seed）

| 项 | 值 |
|---|---|
| 无攻击基线 delivery_ratio | **0.8950 ± 0.0643**，CI95 0.8550–0.9300 |
| 基线 avg_hops / avg_latency_ms | 9.335 / 177.428 ms |
| 最强单攻击（Sybil 8 身份） | DR **0.0000 ± 0**（完全瘫痪） |
| 最强放置 vs 随机放置 | DR 0.3000 vs 0.6050 → **拓扑感知使攻击效力翻倍** |
| 已完成对比行数 | 411 行配对比较，**failures = 0** |

### 0.3 七条关键科学结论

1. **黑洞攻击的"强度"是两个正交因子的叠加**：`drop_prob = 0.0`（完全不丢包）仍使 DR 从 0.895 降到 0.545（中位差 −0.3625）。仅"把自己广告成度量为 0 的最优下一跳"这一**路由吸引**本身就造成 35% 的送达损失。解读任何剂量-响应曲线都必须区分"防吸引"与"防丢包"。
2. **放置策略决定攻击成败，而非攻击强度**：`degree ≈ k_core > last_epoch_degree > betweenness ≫ random`，最强与最弱相差 0.305 DR，`attacked_count` 11.6 vs 5.3。
3. **Sybil 攻击在 1 个虚假身份时即近饱和**：吸引率 0.9125，身份数 1→32 的梯度**实质不可分辨**且吸引率非单调。放大拓扑规模（96→1024）**并未**打开分辨空间，饱和点反而前移。
4. **虫洞攻击出现反直觉结果**：`peer_only` 语义的隧道在本拓扑上是**改善而非攻击**——t3 臂 DR 0.9450 **显著高于**基线 0.8950（p = 0.0039）。只有 `peer_side` 语义（extreme 臂，DR = 0）才是破坏性攻击。
5. **基于距离不一致的虫洞检测器在真实拓扑上完全无判别力**：无攻击基线的误报率 0.200952 与攻击臂 0.200408 几乎相同（10 seeds 标准差全为 0），`detection_rate = 1.0` 因此**毫无意义**。根因是 ISL 距离门限被禁用（见 L2）。
6. **干扰攻击对数据面完全惰性**：`jm3` 臂的 DR 与基线**逐位相同**（p = 1.0），但 `attacked_count = 19.9`（基线 0）——控制面确实被扰动，但持久核子集的冗余路径使节点直接绕开，`avg_hops` 与基线逐位一致。
7. **组合攻击未观察到超加性**：`bh3_jm3` 与加性预测**统计不可区分**（逐 seed 偏差 p = 0.7266）；含 Sybil 的三个组合臂因 DR 触底删失而**不可判定**，且机理上 Sybil 的路由劫持**完全抢占**了黑洞的攻击面（二者争夺同一资源）。

### 0.4 三项已记录的降级决策（均为用户明确批准，非遗漏）

| 决策 | 内容 | 依据 |
|---|---|---|
| **D1** | **彻底放弃**全量 4284 节点的 canonical E1 重标定 | 实测内存物理不可行：需 ≈222 GB（见 §3.5） |
| **D2** | **取消** `shell1024` sweep（跨壳对比只保留 nl=256 单口径） | 97.5° 壳在 nl=1024 严重碎裂、70° 壳规模不等价（见 §4.7） |
| **D3** | **未跑** `e5a_scale_top`（nl=2048 顶档） | 预算耗尽；该档内存全项目从未实测（见 L5） |

---

## 1. 交付定位、威胁模型与口径

### 1.1 协议定位声明（学术风险规避）

本平台的 DV（距离矢量）路由协议**定位为"分布式路由脆弱性参照系"**，不声称模仿 Starlink 的实际路由实现。选择 DV 的理由是它**暴露环路便于攻击观测**，而非它是真实的星座路由方案。完整论述见 `docs/DESIGN.md`。

### 1.2 威胁模型摘要

见 `docs/THREAT_MODEL.md`（8 章，STRIDE + DREAD）。

| 攻击类型 | DREAD 总分 | 优先级 |
|---|---|---|
| Blackhole（黑洞） | 39 | **P0** |
| Jamming（干扰） | 33 | P1 |
| Wormhole（虫洞） | 30 | P1 |
| Sybil（叙比尔） | 27 | P2 |

**敌手定位**：受限内部人（可篡改自身发出的路由通告、可选择性丢弃数据面流量，但不能破解密码学原语、不能修改其他节点的合法通告）。攻击面 AS-1 ~ AS-6。

> **实测校正**：DREAD 的事前评分与本轮实测效应量**并不一致**。Sybil 事前评为最低优先级（27/P2），实测却是**唯一能把 DR 压到 0.000 的攻击**；Jamming 事前评为 P1，实测对数据面**完全无效**。这本身是一条有价值的发现：**事前威胁评分不能替代实测**。Phase 3 之后若要更新威胁模型，应据此重排。

### 1.3 数据保真度硬约束

全程使用真实 TLE，禁用理想化星座模型（DC-1 ~ DC-5，见 `docs/DESIGN.md`）。SGP4 传播，TEME 坐标系，面锚定 +Grid 建链（同面前后各 1 + 异面相邻面各 1 + 面外几何回退）。

### 1.4 ⚠️ 三套口径（互不可直接比较）

| 口径 | 规模 | 评估窗口 | trials | 基线 DR | 来源 |
|---|---|---|---|---|---|
| **① README 历史 E1** | node_limit=512 | 20 epochs，**静态固定拓扑** | 12100 | **1.000** | `results/aggregated/simulation_summary.json` |
| **② step3 攻击矩阵（B 档，本报告主口径）** | node_limit=1024 持久核子集 | 2 epochs，**动态多 epoch** | 40/seed × 10 seeds | **0.8950** | `results/aggregated/step3/` |
| **③ 跨壳对比** | node_limit=256 | 2 epochs，动态 | 40/seed × 10 seeds | 0.7900（53°） | 同上 |

**严禁**把口径①的 DR = 1.000 与口径②的 0.895 并列，暗示"性能下降 10.5%"——两者一个是静态固定拓扑、一个是动态多 epoch，且规模不同。口径②与③之间也因 `node_limit` 不同而**匹配键不同**，跨口径做 `compare_attack_vs_baseline` 会（正确地）抛出 `TrialsCardinalityError`。

---

## 2. Phase 0：地基修复（7 项，全部验收通过）

调研阶段发现原仓库存在多处"README 声称与实际不符"及三个真实缺陷，Phase 0 逐项修复。

### 2.1 威胁模型与设计定位文档
- 新增 `docs/THREAT_MODEL.md`（STRIDE 表、DREAD 评分、攻击面 AS-1~AS-6、敌手定位、缓解映射）
- 新增 `docs/DESIGN.md`（协议定位声明、保留 vs 简化对比表、数据保真度硬约束 DC-1~DC-5、文献锚定）

### 2.2 DV 协议与控制面加固（`starlink_sim/net/routing_dv.py`、`simulator.py`）

| 缺陷 | 修复 |
|---|---|
| **路径矢量防环实际失效**：`visited` 恒为 `[src]`，导致 `len(loop_path) >= 3` 永不成立 | `RouteEntry` 新增 `path: List[int]`；`_build_update_message` 改为 `visited = 最长 path + [self.node_id]`，真实累积 next_hop 链 |
| **无路由老化**：失效路由永久驻留 | 新增 `_age_routes()`（`aging_timeout` 默认 3 × adv_interval = 6s，超时删除 + 触发更新） |
| **邻居消失不清路由** | 新增 `purge_neighbor_routes()`；`ControlPlane.update_neighbors` 对消失邻居调用 |
| **同节点多攻击者只有第一个生效**（`step()` 中的 `break`） | 移除 `break`，改为链式依次应用；`DataPlane.evaluate_flows` 同步修复 |

### 2.3 时延指标修复（`starlink_sim/topology/isl.py`）

`avg_latency_ms` 此前**恒为 0**，三处断链：`topology_results.pkl` 无 `positions_per_epoch` 键、`run_e3_blackhole_experiment.py:155` 硬编码 `None`、`data/snapshots/` 不存在且被 `.gitignore` 排除。

修复：`build_topology_for_shell` 返回值新增 `positions_per_epoch`（`List[Dict[int, np.ndarray]]`，len=121，SGP4 TEME，km）；新增 `_SATREC_CACHE` + `_get_satrec()` 避免重复构造；时延唯一实现点为 `dist / 299792.458 * 1000` ms。修复后时延恢复至 88–130 ms 量级（静态口径）/ 177.428 ms（B 档动态口径）。

### 2.4 工程可复现性与配置统一
- 新增 `starlink_sim/io/config.py::load_experiment_config`，实验参数统一走 YAML
- 迁移 3 个实验入口到统一配置；`requirements.txt`、`conftest.py` 规整
- `ControlPlane` 新增 `adv_interval=2.0`、`DataPlane` 新增 `max_hops=100`（此前在 `:128` 硬编码）、`Simulator` 透传（均为新增可选参数，默认行为不变）

### 2.5 统计严谨性框架（`starlink_sim/analytics/stats.py`，~730 行）

公开 API：`bootstrap_ci`（percentile 法，`n_boot < 2000` 拒绝）、`mannwhitney_test`、`paired_by_seed`（同 seed ≥2 用 Wilcoxon，否则 MWU）、`aggregate_experiment`、`compare_attack_vs_baseline`、`signed_rank_biserial`（`89c6dcb` 新增）。

**基数守卫**：匹配键 `MATCH_KEY_FIELDS = (shell, node_limit, num_eval_epochs, num_flows)`；基数三元组 `total_trials = num_flows × num_eval_epochs × trials_per_flow_epoch`；不匹配抛 `TrialsCardinalityError`。本轮 411 行对比**未触发任何一次**该异常，证明配置口径严格一致。

### 2.6 Phase 1 基础设施（并行化与子集选择）

| 组件 | 说明 |
|---|---|
| `starlink_sim/topology/subset.py`（355 行） | `select_connected_subset` / `persistent_core` / `evaluate_subset_connectivity` / `epoch0_bfs` |
| `starlink_sim/net/placement.py`（337 行） | 5 种放置策略 + `instantiate_attackers` + `check_attack_windows` + `ATTACKER_CLASSES` 注册表 |
| `scripts/run_experiment_sweep.py` | Windows spawn `Pool(initializer=_init_worker)`，每进程加载 pkl 一次入 `_TOPO_CACHE`；`_emit_raw` **逐任务即时落盘**（这是 530 个 raw 零损坏的直接原因） |
| `scripts/run_step3_matrix.py` | 矩阵总驱动器，`--list` / `--only` / `--skip-existing` 续跑判定 |
| `scripts/aggregate_step3.py` | 聚合 + 7 张图 |

**持久核子集方法学的关键教训**：53° 壳的**持久边图**（10830 条边存在于全部 121 个 epoch）的最大连通分量为 **GCC = 1064**。用持久核 + 连通贪心生长选出的子集，逐 epoch 连通比为 **1.000**；而 epoch-0 BFS 只有 0.5–0.7，朴素"累计度 top-K"**比 BFS 更差**——因为真实 LEO 的高度数节点分散在不同轨道面、互不相邻。此结论由 `test_rejects_high_degree_ephemeral_hub` 锁定。

---

## 3. 实验方法学

### 3.1 统一口径（B 档）

所有攻击臂与其配对基线臂**完全一致**：

```
shell = 53°          node_limit = 1024（持久核连通子集）
subset_method = cumulative_degree      seeds = 42,43,...,51（10 个）
匹配键 = {shell: 53°, node_limit: 1024, num_eval_epochs: 2, num_flows: 20}
runner = e3          duration = 60s    epoch_interval = 30s
total_trials = 40/seed（= 2 epochs × 20 flows × 1）
n_boot = 4000        alpha = 0.05      配对检验 = Wilcoxon signed-rank
```

### 3.2 统计报告约定

- **效应量一律使用带符号 rank-biserial**（`rb_signed`，>0 = 攻击臂更大）。
- Wilcoxon n=10 双侧**最小可能 p 值 = 0.001953 = 2/2¹⁰**，其含义仅为"10 对全部同向"，**不代表效应大**。必须与中位差联读。
- 反例警示：E6 的 `wormhole_false_positive_rate` 得到 p = 0.001953"显著"，但差值恒定仅 −0.0005 —— 这是**统计显著但实际无意义**的典型案例。

### 3.3 可复现性证据（三重确定性验证）

| 验证 | 结果 |
|---|---|
| **跨 sweep 同配置同结果** | `bh3` 在 `e7_combo` / `e5_placement.degree` / `e5_intensity.c3` / `e5a_scale_small.bh3_n1024` **四处**得到 DR = 0.3000 ± 0.1155、CI95 0.2374–0.3675，**完全相同** |
| **跨 sweep 同配置同结果（nl=256）** | `shell256.bh3_53` = `e5a_scale_small.bh3_n256` = 0.4475 ± 0.1017 |
| **零效应臂逐位复现** | `jm3` 与 `base` 在 **10/10 seed 逐位相同** |
| **重跑幂等性** | `e7_combo` 整 sweep 重跑，30 个被重写的 raw 的科学内容 SHA256：**IDENTICAL = 30 / DIFFERENT = 0 / NEW = 50 / MISSING = 0** |
| **代码版本时序** | 修复 commit `89c6dcb` @22:36:13 **早于** sweep 启动 @22:58:18 达 22 分钟，且 `starlink_sim/**` + `scripts/**` 全程 clean → 80 个 raw **全部产自修复后代码** |

⚠️ **一处非逐位可复现**：`mean` / `std` 完全确定，但 **bootstrap CI 有 ±0.005 量级抖动**（同一 53°@nl=256 臂在两个 sweep 中 CI 上界为 0.84 vs 0.835）。根因是 bootstrap 的 RNG 未固定种子。见 L11。

### 3.4 git 与产物溯源

| commit | 时间 | 内容 |
|---|---|---|
| `608b4b7` | 22:21:18 | git init 基线快照，675 files，`.git` 2.57 MB，**0 个 pkl、0 个 >5MB 文件** |
| `89c6dcb` | 22:36:13 | 修 `stats.py` 配对 rank-biserial 符号 + `_emit_raw` 透传 `subset_method` + 7 个符号约定回归测试 |

**未做第三次 commit**（遵停止令），故本轮之后产出的新 raw / 聚合 / 图表**留在磁盘未入库**。

### 3.5 内存与并行度实测（本轮重要的工程结论）

机器：物理 RAM **31.72 GiB**，commit 上限（RAM + pagefile）**67.61 GiB**，非 Python 桌面基线 **9.20 GiB = 29.0%**。

> **方法学更正**：Windows 的硬失败边界是 **commit charge**（耗尽时报 `WinError 1455 分页文件太小`），**不是物理 RAM**（耗尽只会换页变慢）。且**禁止用 Σ WorkingSetSize 做容量规划**——本机内存压力下的工作集裁剪可导致低估达 45%（实测某 sweep 父进程 Private 1.503 GiB 而 WS 仅 0.004 GiB，差 375 倍）。所有数字用**启动前后 FreeRAM / FreeCommit 差值**实测。

| 场景 | 实测 |
|---|---|
| 四壳 pkl 全量反序列化 | **1.226 GiB** 峰值 RSS（双源互证） |
| `e7_combo` W=10（nl=1024，单壳） | 物理 14.5 GiB / commit 31.2 GiB；worker WS 1.388–1.450、PeakWS 1.588–1.600、Private 2.906–2.968 GiB；FreeRAM 在 **4.56–15.82 GiB 震荡（占用 50.1%–85.6%）**，周期 3–4 min |
| `shell256` W=8（四壳，剔壳不生效） | Δ物理 **9.10 GiB** / Δcommit **23.83 GiB**；80 任务墙钟 **<110 s** |
| `e5a_scale_small` W=10（单壳 53°） | Δ物理 **15.56 GiB ≈ 1.56 GiB/worker**（独立复现头注的 1.62 GB）/ Δcommit **33.62 GiB ≈ 3.06 GiB/进程** |
| **nl=4284 全量（不可行）** | 无攻击 + 仅 2 epochs → **WS ≥ 20.7 GiB @393–462s CPU 仍未结束，被强制终止** |
| nl=2048（**未实测**） | 反推 物理 ≈6.2 GiB/worker、commit ≈12.2 GiB/worker → W=2 需 ~12.5 GiB 物理 / ~26 GiB commit |

**全量不可行的根因与内存模型**：`RouteEntry` 携带 `path: List[int]` 路径矢量，且 `Simulator.run` 每 epoch 执行 `routing_table_history[epoch] = get_routing_tables()`。模型 `常驻 ≈ 1100B·N² + 48B·N²·epochs`（在实测点校验：预测 22 GB vs 实测 20.7 GB）→ **N=4284 × 121 epochs 仅历史项就 ≈222 GB**；N=2048 × 121ep ≈29 GB 亦不可行；**N=1024 × 121ep ≈7.6 GB 可行**。这直接导致降级决策 **D1**。

**吞吐基线**：W=10 时 **11.06–11.67 s/task**（单任务延迟 ~114 s），与攻击类型几乎无关；`e7_combo` 因组合臂最多含 7 个攻击者，实测 **15.42 s/task（慢 35%）**。

---

## 4. 攻击矩阵实测结果

### 4.1 E5-a 黑洞强度：count 梯度（`drop_prob = 0.8`，`placement = degree`）

| 臂 | count | DR mean ± sd | CI95 | 中位差 | rb | p | avg_latency_ms |
|---|---|---|---|---|---|---|---|
| base | 0 | 0.8950 ± 0.0643 | 0.8550–0.9300 | — | — | — | 177.43 |
| c1 | 1 | 0.5575 ± 0.0928 | 0.5025–0.6075 | −0.3375 | −1.000 | 0.001953 | 105.87 |
| c3 | 3 | 0.3000 ± 0.1155 | 0.2374–0.3675 | −0.6250 | −1.000 | 0.001953 | 50.92 |
| c6 | 6 | 0.1725 ± 0.1227 | 0.1074–0.2475 | −0.7500 | −1.000 | 0.001953 | 19.59 |
| c12 | 12 | 0.0800 ± 0.0771 | 0.0425–0.1300 | −0.8250 | −1.000 | 0.001953 | 7.29 |
| c24 | 24 | 0.0275 ± 0.0381 | 0.0100–0.0525 | −0.9000 | −1.000 | 0.001953 | 2.01 |

**单调可分辨** ✅。但注意 `avg_latency_ms` 的暴跌（177 → 2 ms）**不是性能改善**，而是幸存者偏差（L8）。

### 4.2 E5-b 黑洞强度：drop_prob 梯度（`count = 3`，`placement = degree`）

| 臂 | drop_prob | DR mean ± sd | CI95 | 中位差 | p |
|---|---|---|---|---|---|
| **p00** | **0.0（完全不丢包）** | **0.5450 ± 0.1092** | 0.4825–0.6100 | **−0.3625** | 0.001953 |
| p20 | 0.2 | 0.4625 ± 0.1082 | 0.4000–0.5250 | −0.4500 | 0.001953 |
| p50 | 0.5 | 0.3700 ± 0.1171 | 0.3025–0.4375 | −0.5125 | 0.001953 |
| p100 | 1.0 | 0.2550 ± 0.1327 | 0.1775–0.3300 | −0.6250 | 0.001953 |

**这是本轮最重要的机理发现之一**：`drop_prob = 0` 的攻击者**一个包都不丢**，却仍造成 36% 的送达损失。原因是 `metric_fake = 0` 把自己广告成"度量为 0 的最优下一跳"，流量被引向次优或成环路径。**黑洞攻击的破坏力主要来自路由吸引，而非数据面丢包。**

### 4.3 E5-c 放置策略排序（5 种策略全覆盖，`count = 3`，`drop_prob = 0.8`）

| 排名 | 策略 | DR mean ± sd | 中位差 | attacked_count | p |
|---|---|---|---|---|---|
| 1（并列最强） | `degree` | 0.3000 ± 0.1155 | −0.6250 | 11.6 | 0.001953 |
| 1（并列最强） | `k_core` | 0.3000 ± 0.1155 | −0.6250 | 11.6 | 0.001953 |
| 3 | `last_epoch_degree` | 0.3300 ± 0.1301 | −0.6000 | 12.1 | 0.001953 |
| 4 | `betweenness` | 0.3425 ± 0.1167 | −0.5375 | 9.9 | 0.001953 |
| 5（最弱） | `random` | **0.6050 ± 0.1403** | −0.2625 | 5.3 | 0.001953 |

- `degree` 与 `k_core` 在持久核子集上**选出完全相同的节点集**（三项指标逐位相同）——因为持久核子集本身已是高 k-core 结构，两者退化重合。
- **拓扑感知放置使攻击效力翻倍**（0.605 → 0.300，差 0.305 DR）。这是 E5 最有价值的一条结论，也意味着**防御评估必须面对最强放置（degree/k_core），而非 random**。

### 4.4 E4 Sybil：身份数梯度（`attachment = betweenness`，`seq_lead = 8`）

| 臂 | 身份数 | DR mean ± sd | CI95 | sybil_attraction_ratio | 中位差 | p |
|---|---|---|---|---|---|---|
| base | — | 0.895 ± 0.0643 | 0.855–0.930 | — | — | — |
| ids1 | 1 | 0.045 ± 0.0497 | 0.020–0.075 | 0.9125 ± 0.059 | −0.850 | 0.001953 |
| ids2 | 2 | 0.045 ± 0.0497 | 0.020–0.075 | **0.8775** ± 0.066 | −0.850 | 0.001953 |
| ids4 | 4 | 0.025 ± 0.0486 | 0.005–0.055 | 0.9325 ± 0.053 | −0.8875 | 0.001953 |
| ids8 | 8 | **0.000 ± 0** | 0–0 | 0.9825 ± 0.021 | −0.900 | 0.001953 |
| ids16 | 16 | **0.000 ± 0** | 0–0 | 0.995 ± 0.011 | −0.900 | 0.001953 |
| ids32 | 32 | **0.000 ± 0** | 0–0 | 0.9875 ± 0.018 | −0.900 | 0.001953 |

**结论（如实）**：身份数从 1 到 32 只让 DR 从 0.045 挪到 0.000，**梯度实质不可分辨**；吸引率序列 `0.9125 → 0.8775 → 0.9325 → 0.9825 → 0.995 → 0.9875` **非单调**（ids2 反低于 ids1，ids32 反低于 ids16）。

**饱和点 = 最低档 ids1**（吸引率已 0.9125）。此前在 nl=96 小拓扑上观察到饱和，曾判断"需在 ≥1024 重测方能分辨"——**重测后证实：放大到 1024 并未打开分辨空间，饱和点反而前移到 1 个身份**。

**机理**：`attachment = betweenness` 把虚假身份挂到最高介数的真实节点，而 nl=1024 持久核子集是**高度中心化的稀疏连通子图**（GCC 仅 1064/4284），单个高介数枢纽即可拦截绝大多数最短路径 → 1 个身份就足以近饱和，增加身份只是冗余覆盖。

**实现要点（`starlink_sim/net/sybil.py`，298 行）**：
- **节点 ID 空间扩展**必须在 `ControlPlane.__init__` **之前**注入（ControlPlane 用 `range(num_nodes)`，`num_nodes = max(all_node_ids) + 1`，`update_neighbors` 会丢弃端点 ≥ num_nodes 的边）；`base_node_id = max(真实) + 1`；`edge_sets` 必须**新建 set 扩充**（只读纪律，`_TOPO_CACHE` 跨任务共享）。
- **`seq_lead` 机制（关键洞见）**：Sybil 的路由知识滞后 2 跳，若只做 `_bump_seq + 1`，会与更新鲜的合法通告 seq **打平** → metric tie-break 落败 → **吸引率恒为 0**。引入 `seq_lead = 8`：伪造 `seq = max(seq, floor) + 1 + seq_lead`，floor 每周期领先 8，而合法 seq 每周期只 +1，**永远追不上**。护栏测试已固化（`seq_lead=0` → 吸引率 0.0；`seq_lead=8` → >0）。

### 4.5 E6 Wormhole：反直觉结果 + 检测器无判别力

| 臂 | poison_scope | 隧道数 | DR mean ± sd | 中位差 | rb | p | 判定 |
|---|---|---|---|---|---|---|---|
| base_det | — | 0 | 0.8950 ± 0.0643 | — | — | — | — |
| t1 | peer_only | 1 | 0.9175 ± 0.0602 | **+0.0125** | **+1.000** | 0.0625 | 不显著 |
| **t3** | peer_only | 3 | **0.9450 ± 0.0453** | **+0.0500** | **+1.000** | **0.003906** | **显著「改善」** |
| extreme | peer_side | 3 | **0.0000 ± 0** | −0.9000 | −1.000 | 0.001953 | 完全瘫痪 |

**攻击效果度量（E6 在本数据上的主信号）**：

| 指标 | base_det | t1 | t3 | extreme |
|---|---|---|---|---|
| `wormhole_attracted_ratio` | 0 | 0.2275 ± 0.084 | 0.395 ± 0.126 | **0.9575 ± 0.035** |
| `attacked_count` | 0 | 23.9 ± 6.9 | 52.9 ± 11.8 | 0 |
| `wormhole_path_stretch` | — | 0.9519 ± 0.028 | **0.9185 ± 0.037** | 0（无成功流） |
| `wormhole_geo_stretch` | — | 1.0565 ± 0.036 | 1.1249 ± 0.047 | 0 |
| `wormhole_mean_tunnel_km` | — | 13243.7 | 13482.5 | 13482.5 |
| `avg_latency_ms` | 177.43 | 185.81 | 198.34 | 0 |

**发现 1 — `peer_only` 虫洞是"改善"而非"攻击"**：`farthest` 端点策略选出的是**近对踵真实节点对**（隧道 13243–13482 km ≈ 地球直径量级），在 nl=1024 稀疏子集里这等于凭空增加了一条真实捷径——`geo_stretch = 1.125`（几何上绕远 12.5%）但 `path_stretch = 0.918`（**跳数路径变短 8%**），且 `drop_prob = 0` 不丢包 → 原本因跳数上限或路由缺失而失败的流被救回。只有 `peer_side`（extreme，DR = 0）才是破坏性攻击。

> **这是防御侧必须显式处理的设计约束**：若防御策略是"检测到隧道就阻断"，在 `peer_only` 场景下会**降低**送达率（阻断真实捷径），引入净损害。

**发现 2 — `attracted_ratio` 是唯一干净的剂量-响应信号**：0 → 0.2275 → 0.395 → 0.9575，单调 ✅。

**发现 3 — 距离检测器完全无判别力**（决定性证据）：

| 臂 | `detection_rate` | `false_positive_rate`（mean ± **sd**） |
|---|---|---|
| **base_det（无攻击）** | — | **0.200952 ± 0** |
| t1 | 1.0 ± 0 | 0.200884 ± 0 |
| t3 | 1.0 ± 0 | 0.200408 ± 0 |
| extreme | 1.0 ± 0 | 0.200408 ± 0 |

**无攻击基线的误报率（0.200952）与攻击臂（0.200408）仅差 5×10⁻⁴，且 10 个 seed 的标准差全为 0**（每 seed 完全相同的 591/2941 条边被标记）。因此 `detection_rate = 1.0` **毫无意义**——检测器把 20% 的**合法 ISL 边**判为可疑，隧道只是恰好落在这 20% 里。

**根因**：`scripts/build_topology*.py:44` 调用 `build_topology_for_shell(..., max_dist_km=99999.0)`，即**距离门限被完全禁用**（YAML 里的 `isl_distance_limit: 800.0` 从未生效）→ shipped `topology_results.pkl` 的合法边最大 ≈1.37×10⁴ km（≈对踵距离），**与隧道长度分布完全重叠，不存在可分离阈值**。检测器的真阳能力目前**仅由 `tests/test_wormhole.py` 在受限合成拓扑上证明**（合法边 800 km、隧道 ~5600 km → `detection_rate = 1.0`、基线 `fp = 0.0`）。

**双端点控制的实现方式**（`starlink_sim/net/wormhole.py`，943 行；`simulator.py` **零改动**）：虫洞与 Sybil 的关键差异是 A、B 皆为**既有真实节点**，故**不扩展节点 ID 空间**（`num_nodes` 不变）。`Attacker.controls()` 覆盖为对 A、B **均返回 True**；隧道边每 epoch 生成**新 set** 注入 `edge_sets`（只读拓扑纪律，绝不原地改输入，避免污染 sweep worker 共享的 `_TOPO_CACHE`）。

### 4.6 E7 组合攻击：协同性判定

| 臂 | 组成 | DR mean ± sd | CI95 | 中位差 | rb | p | attacked_count |
|---|---|---|---|---|---|---|---|
| base | 无 | 0.8950 ± 0.0643 | 0.8550–0.9300 | — | — | — | 0.0 |
| bh3 | blackhole×3, degree, drop 0.8 | 0.3000 ± 0.1155 | 0.2374–0.3675 | −0.6250 | −1.000 | 0.001953 | 11.6 |
| jm3 | jamming×3, degree, ratio 0.3 | 0.8950 ± 0.0643 | 0.8550–0.9300 | **0.0000** | 0.000 | **1.0（ns）** | 19.9 |
| sy8 | sybil 1 ctrl × 8 id, betweenness, seq_lead 8 | **0.0000 ± 0** | 0–0 | −0.9000 | −1.000 | 0.001953 | 0.0 |
| **bh3_jm3** | bh3 + jm3 | 0.2900 ± 0.1370 | 0.2075–0.3650 | −0.5750 | −1.000 | 0.001953 | 17.8 |
| bh3_sy8 | bh3 + sy8 | 0.0000 ± 0 | 0–0 | −0.9000 | −1.000 | 0.001953 | 0.0 |
| jm3_sy8 | jm3 + sy8 | 0.0000 ± 0 | 0–0 | −0.9000 | −1.000 | 0.001953 | 0.0 |
| bh3_jm3_sy8 | 三者 | 0.0000 ± 0 | 0–0 | −0.9000 | −1.000 | 0.001953 | 0.0 |

**判定 1 — `bh3_jm3` = 加性（与加性统计不可区分）**
- 口径 A（中位差加性预测）：偏差 = +0.0500（次加性方向）
- 口径 B（逐 seed `delta = loss(combo) − Σ loss(成分)`）：median = −0.0125、mean = +0.0100、sd = 0.0603、3 正 / 2 零 / 5 负、W = 15.0、**p = 0.7266（不显著）**
- 偏离幅度 |Δ| ≤ 0.05 DR ≈ 基线的 5.6%，且**小于 delta 的标准差** → 噪声量级。两口径方向一致。
- 与此前预判相符（`jm3` 单独效应 = 0 → `bh3_jm3` ≈ `bh3`）。

**判定 2 — 含 Sybil 的三个组合臂 = 不可判定（DR 下界删失）**
- `sy8` 单臂 DR ≡ 0.000（10/10 seed 触底），加性预测 `DR_pred = −0.625`（**物理不可实现**）→ delta 必然 ≤ 0（−0.625，p = 0.001953）。**不得把这个"显著"解读为拮抗**——它是删失伪影。
- `jm3_sy8` 的逐 seed delta **全为 0.0**（完全等价于 `sy8` 单臂）。

**机理证据（seed 42）**：含 sy8 的三臂 `data_stats` 与 `sy8` **逐位相同**，其黑洞条目 `attracted_count = 0` / `dropped_count = 0` → **Sybil 的 `seq_lead = 8` 路由劫持完全抢占了黑洞的攻击面**（两者争夺同一资源：路由吸引），属**机制冗余**而非协同。且 `bh3` 与 `sy8` 的 placement **同为 degree** → 落在同一批节点 403 / 22 / 269（**node 403 同时是 Sybil 控制器与黑洞攻击者**），并非两个独立攻击面。`sy8` 归零的机制是**环路 / TTL 耗尽**（`sybil_attraction_ratio = 0.975`、39/40 trials 被吸引、`drop_prob = 0.0`、`total_loops ≈ 20.3k`），而非丢包计数。

**要能真正判定超加性所需的配置**（后续工作）：
1. **弱化 Sybil** 使成分臂 DR 落在 0.3–0.7：用 `attachment = random` 或 `seq_lead ≤ 2`。注意**降低身份数不够**（ids1/ids2 已达 DR = 0.045）。
2. **成分臂 placement 分开**（如 bh3 = degree、sy8 = random），以消除同节点链式叠加。
3. 保证 `Σ loss(成分) < DR(base)`，使加性预测落在 0–1 区间内。
4. `jm3` 需先换成**对数据面有效**的强度——当前 `inf_metric = 9999` 只让被攻击节点自身通告"不可吸引"，DV 直接绕开 → 完全惰性。

### 4.7 跨壳对比（nl = 256，壳内配对 bh3 vs base，n_pairs = 10）

| 壳 | base DR | bh3 DR | 中位差 | rb | p |
|---|---|---|---|---|---|
| 53° | 0.7900 ± 0.0775（CI95 0.7450–0.8350） | 0.4475 ± 0.1017 | −0.3250 | −1.000 | 0.001953 |
| 70° | **1.0000 ± 0.0000** | 0.6100 ± 0.1226 | −0.4000 | −1.000 | 0.001953 |
| 97.5° | **1.0000 ± 0.0000** | 0.4500 ± 0.0979 | **−0.5500** | −1.000 | 0.001953 |
| 43° | 0.6800 ± 0.1274（CI95 0.6000–0.7500） | 0.2350 ± 0.0937 | −0.4500 | −1.000 | 0.001953 |

**损失排序：97.5°（0.55）> 43°（0.45）> 70°（0.40）> 53°（0.325）**，四壳全部 `sig = 1`。

⚠️ **三条解读限制（必须随结论带上）**：
1. **70° / 97.5° 的基线 sd = 0**（DR ≡ 1.0，基线无变异）→ `rb = −1.0` 是"攻击臂全低于无变异基线"的**必然结果**，其效应量幅度**不可与他壳等量齐观**。
2. **43° 基线本身最弱**（0.68）→ 其绝对损失中**含基线脆弱性成分**，不能纯归因于攻击。
3. 跨壳**不做** `compare_attack_vs_baseline`：`shell` 属匹配键四字段之一，跨壳必然抛 `TrialsCardinalityError`。本表口径是**各壳壳内配对**的中位差再横向制表。

**为何只有 nl=256 一个档（降级决策 D2 的实测依据）**：

| 壳 | 节点数 | 持久核 GCC | nl=256 min/mean | nl=512 min/mean | nl=1024 min/mean | nl=1024 实得子集 |
|---|---|---|---|---|---|---|
| 53° | 4284 | **1064** | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1024 |
| 70° | **702** | 380 | 1.000 / 1.000 | 0.557 / 0.898 | 1.000 / 1.000 | **702（全量退化）** |
| 97.5° | 1075 | **287** | 1.000 / 1.000 | **0.377 / 0.436** | **0.280 / 0.615** | 1024 |
| 43° | 3262 | 3249 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1024 |

- **97.5° 壳持久核 GCC 仅 287** → nl=1024 时逐 epoch 连通比 min 0.280 / mean 0.615（全 121 epoch 口径），严重碎裂。在 e3 实际触达的评估窗口内（`duration=60 / epoch_interval=30` → 仅 `edges_by_epoch[0:2]`）为 min 0.634 / mean 0.669——碎裂**确实发生在真正影响 DR 的窗口内**，但数值不同于全 epoch 口径。
- **97.5°@512 比 @1024 更碎**（0.377 < 0.634，**非单调**）→ **不存在折中档位**。
- **70° 壳只有 702 节点 < 1024** → `select_connected_subset` 在 `target_size >= len(nodes)` 时提前返回全量 702，与 53°/43° 的 1024 **规模不等价**；其连通比其实是 1.000/1.000（**不是碎裂**），降级性质是"规模不等价 + 攻击者相对密度 0.43% vs 53° 的 0.29%"。
- → **最大公共可用档 = nl=256**（四壳 `inside_core` 均为 1.000）。

### 4.8 规模阶梯（53° 壳，档内配对，nl = 48 → 1024）

| nl | base DR | bh3 DR | 中位差 | rb | p | 评估窗口平均度 |
|---|---|---|---|---|---|---|
| 48 | 1.0000 ± 0 | 0.1325 ± 0.0882 | −0.8875 | −1.000 | 0.001953 | 2.875 |
| 96 | 1.0000 ± 0 | 0.2775 ± 0.0854 | −0.7125 | −1.000 | 0.001953 | 2.875 |
| 256 | 0.7900 ± 0.0775 | 0.4475 ± 0.1017 | −0.3250 | −1.000 | 0.001953 | 3.359 |
| 512 | 0.8800 ± 0.0675 | 0.4500 ± 0.1269 | −0.4125 | −1.000 | 0.001953 | 3.359 → 4.457 |
| 1024 | 0.8950 ± 0.0643 | 0.3000 ± 0.1155 | −0.6250 | −1.000 | 0.001953 | 5.726 |

**嵌套性**：五档在 53° 壳上**严格嵌套**（48 ⊂ 96 ⊂ 256 ⊂ 512 ⊂ 1024，全部落在严格持久核 GCC = 1064 内、逐 epoch 全连通）。

⚠️ **混杂警示（这是本表最重要的限定）**：
- **评估窗口平均度随 nl 单调上升 2.875 → 5.726**（接近全壳的 5.713）→ **平均度是混杂变量**。小档稀疏、绕路少；大档稠密、替代路径多。而黑洞攻击的效果恰恰取决于"绕不绕得开"。故**效应量随规模的变化不得纯归因于节点数**，必须与平均度联读。
- **base DR 非单调**（1.0 / 1.0 / 0.79 / 0.88 / 0.895），**|中位差| 呈 U 形**（0.8875 → 0.7125 → 0.3250 → 0.4125 → 0.6250）→ **不能读作单调规模律**，只能档内配对读。
- **跨档不可比 p 值**：各档 `node_limit` 不同 → 匹配键不同。
- **阶梯无顶档**：`nl=2048`（`e5a_scale_top`）**非嵌套**且未跑（D3）；`nl=4284` 内存不可行（D1）。故规模律**仅为下段趋势**。

### 4.9 历史 E2 / E3 结果（原仓库口径，未在本轮重跑）

| 实验 | 口径 | 关键结果 |
|---|---|---|
| E1（README） | nl=512，静态固定拓扑，20 epochs | DR 1.000，avg_hops 7.96，latency 133.90 ms，12100 trials |
| E2 干扰 | 96 节点子集，120s，10 attackers，`jamming_ratio=0.9` | DR 0.810 ± 0.033，`attacked_count` 184.7 ± 6.0，`total_loops` 50 ± 3.6 |
| E3 黑洞 | 4284 节点，60s，3 attackers，`drop_prob=0.8` | DR 0.843 ± 0.023（3 seeds），`dropped_by_attacker` 15.7 ± 2.3 |

这些数字来自**只有 3 seeds、口径不统一**的历史运行，**不满足**本平台的统计规范（≥10 seeds + bootstrap CI + 配对检验），仅作历史参照，不应与 §4 的 B 档结果并列。

---

## 5. 交付物清单

### 5.1 文档

| 路径 | 内容 |
|---|---|
| `report.md` | **本文档** |
| `docs/THREAT_MODEL.md` | 威胁模型（8 章，STRIDE + DREAD + 攻击面 AS-1~AS-6） |
| `docs/DESIGN.md` | 设计定位（5 章，协议定位声明 + 数据保真度硬约束 DC-1~DC-5） |
| `docs/STEP3_SHELL_SCALE_RUNBOOK.md` | Task #12 实跑 runbook（12 节）。⚠️ **§1/§2 仍是旧门禁与 matrix 命令，已被后续决策取代，需修订**（见 L17） |
| `docs/DECISIONS_AND_ISSUES.md` | 原仓库三阶段决策/已知问题/失败方案汇编 |

### 5.2 代码（新增 / 修改）

| 路径 | 行数 | 性质 |
|---|---|---|
| `starlink_sim/net/sybil.py` | 298 | 新增（E4） |
| `starlink_sim/net/wormhole.py` | 943 | 新增（E6） |
| `starlink_sim/topology/subset.py` | 355 | 新增（持久核子集） |
| `starlink_sim/net/placement.py` | 337 | 新增（5 种放置策略） |
| `starlink_sim/analytics/stats.py` | ~730 | 新增（统计框架；`89c6dcb` 修符号 + 新增 `signed_rank_biserial:233`） |
| `starlink_sim/io/config.py` | — | 新增（`load_experiment_config`） |
| `starlink_sim/net/routing_dv.py` | 183 → 252 | 修改（老化 / 触发更新 / 路径矢量真实化） |
| `starlink_sim/net/simulator.py` | 319 → 328 | 修改（链式多攻击者 / 邻居清除 / 参数透传 / `controls()`） |
| `starlink_sim/net/attack.py` | — | 修改（`Attacker.controls()` + `SybilAttacker` 重写 + `WormholeAttacker`） |
| `starlink_sim/topology/isl.py` | 167 → — | 修改（`positions_per_epoch` + `_SATREC_CACHE`） |
| `scripts/run_experiment_sweep.py` | 628 | 新增（并行 sweep 执行器） |
| `scripts/run_step3_matrix.py` | 199 | 新增（矩阵驱动器） |
| `scripts/aggregate_step3.py` | ~760 | 新增（聚合 + 7 图） |
| `scripts/gen_step3_configs.py` | 524 | 新增（配置生成器，头注含完整内存证据链） |
| `scripts/run_simulation.py` | 432 | 重写（`--seeds` / `--node-limit` / `--skip-existing` / `--subset-method`） |
| `tools/probe_shell_scale_equivalence.py` | — | 新增（四壳等价性探针） |
| `tools/verify_step3_raw.py` | — | 新增（raw 完整性校验，实测可用） |
| `tests/` | **286 用例** | 新增 `test_sybil.py`(52) / `test_wormhole.py`(87) / `test_subset.py` / `test_placement.py` / `test_attack_window_guard.py` / `test_sweep.py` / `test_analytics_stats.py`(16) / `test_dv_aging.py` / `test_path_vector.py` / `test_multi_attacker.py` / 7 个符号约定回归测试 |

### 5.3 数据与结果产物

| 路径 | 内容 |
|---|---|
| `results/step3_raw/` | **530 个** raw JSON（零损坏；`schema_version=2`，metadata 含 TLE SHA256 / 基数 / 匹配键）。子目录：`e4_sybil`(70) / `e5_intensity`(100) / `e5_placement`(60) / `e6_wormhole`(40) / `e7_combo`(80) / `shell256`(80) / `e5a_scale_small`(100) |
| `results/aggregated/step3/` | **权威聚合产物（interim）**：`sweeps=7, arms=53, comparison_rows=411, failures=0`。含 `step3_arms.csv` / `step3_comparisons.csv`(411 行) / `step3_summary.json` / `step3_completeness.csv`(63 行，10 项计划内不完整) / `step3_failures.csv`(**0 行**) |
| `results/figures/step3_fig1..fig7.{png,csv}` | fig1 E4 梯度 / fig2 放置排序 / fig3 强度 / fig4 wormhole / fig5 E7 协同 / **fig6 跨壳（62.4 KB，首次有真实数据）** / **fig7 规模律（65.4 KB，首次有真实数据）** |
| `results/step3_logs/` | `_matrix_summary.json`（**已合并为 5 条**）、`_matrix_summary_prev.json`（从 git 逐字节抢救的旧 4 条证据）、`pvalue_zero_change_check.txt`(8949 B)、`pytest_after_sign_fix.txt`、`shell_scale_equivalence.json`(44 KB)、`dryrun_all_sweeps.txt`、`checkpoint_inventory.txt` |
| `results/step3_logs_jason/` | Jason 的隔离日志（`shell256.log` / `e5a_scale_small.log` / `_mem_baseline.txt`） |
| `configs/experiments/step3/` | 61 个 YAML（52 臂 + 9 sweep） |
| `configs/experiments/e1_canonical_1024.yaml` | 降级配置，**保留作证据但永不执行**（D1） |

**⚠️ 陈旧产物（其 `rank_biserial` 符号不可信，不得引用）**：`results/aggregated/step3_partial/`、`results/step3_agg/{e4_sybil, e5_intensity, e5_placement, e6_wormhole}/comparison_*.json` —— 这些是**符号修复前**的快照。**唯一权威来源是 `results/aggregated/step3/`。**

### 5.4 计时记录（`_matrix_summary.json`，已合并 5 条）

| sweep | 任务 | workers | wall_s | s/task | exit |
|---|---|---|---|---|---|
| e6_wormhole | 40 | 10 | 456.8 | 11.42 | 0 |
| e4_sybil | 70 | 10 | 817.0 | 11.67 | 0 |
| e5_placement | 60 | 10 | 663.7 | 11.06 | 0 |
| e5_intensity | 100 | 10 | 1141.0 | 11.41 | 0 |
| e7_combo | 80 | 10 | 1233.2（20.55 min） | **15.42**（组合臂最多 7 攻击者，慢 35%） | 0 |

`shell256` 80 任务 W=8 墙钟 **<110 s**；`e5a_scale_small` 100 任务 W=10 未单独记录（见 §3.5 内存表）。

---

## 6. 诚实局限

> 本节是本报告不可分割的一部分。任何引用 §4 数字的人都必须同时引用本节对应条目。

| 编号 | 局限 | 状态与影响 |
|---|---|---|
| **L1** | `stats.py` 配对 rank-biserial **符号失效**：原代码假设 `scipy.wilcoxon(..., alternative='two-sided').statistic` 返回 T+，但 scipy ≥1.7 返回 `min(T+, T−)`（实测 `wilcoxon([1,2]).statistic == 0.0`）→ 效应量符号错 + 幅度饱和（全同号时恒得 −1） | ✅ **已修复**（`89c6dcb`，`signed_rank_biserial` 为单一实现点 + 7 个回归测试钉住符号约定）。**p 值与显著性判定从未受影响**（`wilcoxon([1,2,3,4,5])` → p=0.0625=2/2⁵ 正确），`mannwhitney_test` 非配对路径符号本就正确。**修复前后校验 CONFIRMED**：pre 271 行 vs post 411 行，shared 271 行中 p_value 不一致 **0**、significant 不一致 **0**、其他检验列不一致 **0**、`post.rank_biserial != pre.rank_biserial_signed` **0**、自洽性 `rb=(2T+−T)/T` 不符 **0**；`rank_biserial` 变化 58 行，含关键案例 `e6_wormhole/t3/delivery_ratio`（中位差 +0.0500：**−1.000 → +1.000**，p=0.00390625 与 sig=1 不变）。⚠️ 但**陈旧产物仍带错符号**（见 §5.3） |
| **L2** | **E6 距离检测器在 shipped 拓扑上无判别力** | ❌ **未解决，需重生成数据**。`fp ≈ 0.2009`（无攻击基线亦然，sd = 0），`det_rate = 1.0` 无意义。根因 = `max_dist_km=99999` 禁用距离门限 → 合法边达对踵 1.37×10⁴ km，与隧道长度分布完全重叠，**不存在可分离阈值**。复位门限并重生成 `data/topology/` 后该问题**自动消解**，但这属于原计划明令禁止的操作，未获批准。**E6 在本数据上的主信号只能是攻击效果度量**（attracted_ratio / path_stretch / geo_stretch / DR 对比）；检测器真阳能力仅由合成受限拓扑测试证明 |
| **L3** | **无全量绝对参照数**（D1） | ❌ 永久缺失。nl=4284 × 121 epochs 需 ≈222 GB。要获得全量参照，唯一出路是改 `simulator.py` 的 `routing_table_history` 存储策略（只存摘要/差量或不存历史），但这会改 `total_loops` / `loop_paths_count` 语义并**要求重跑所有受影响臂**，属重大改动 |
| **L4** | **跨壳对比只有 nl=256 单口径**（D2） | 见 §4.7。且 70° 壳在 nl=1024 会退化为全量 702 节点（规模不等价 + 攻击者相对密度 0.43% vs 53° 的 0.29%）；97.5° 壳在 nl=512 与 nl=1024 均碎裂且**非单调**，无折中出路 |
| **L5** | **规模阶梯无顶档**（D3） | `nl=2048` 未跑且**非嵌套**；`nl=4284` 不可行。加上**平均度混杂**（2.875 → 5.726）与 base DR 非单调、\|中位差\| 呈 U 形 → **本报告不主张任何"规模律"结论**，只报告下段五档的档内配对事实。nl=2048 的内存**全项目从未实测**（源码头注的 ~4 GB 自标"推算"，同 N² 模型重算为 4.75 GiB PeakWS / ~10.8 GiB commit，**可能低估 19%**）——这是当前最大的未量化风险 |
| **L6** | **E7 超加性对含 Sybil 组合不可判定** | DR 下界删失（`sy8` 单臂已 ≡0.000）。`delta = −0.625, p = 0.001953` **不得解读为显著拮抗**。且 `bh3` 与 `sy8` 的 placement **同为 `degree`**（实测 `results/step3_raw/e7_combo/` 全部 8 臂的 `config.attack.attackers[*].placement` 均为 `degree`）→ 二者被引到同一批高度数节点上，争夺的是同一种资源（路由吸引），属**机制冗余**而非可判定的交互效应。要真正给出超加性结论，须按 §4.6 末所列 4 项配置变更（`:331–334`，逐条一一对应：① 弱化 Sybil 使成分臂 DR 落在 0.3–0.7、② 成分臂 placement 分开、③ 保证 `Σ loss(成分) < DR(base)`、④ 把 `jm3` 换成对数据面有效的强度）重跑。 |
| **L7** | **raw JSON 的溯源字段只覆盖 260/530 个产物，且出身字段有一处系统性失真** | ⚠️ **部分消解，仍影响 270 个**。`89c6dcb`（2026-09-30 22:36 +08:00，`fix(stats): correct paired rank-biserial sign + passthrough subset_method in raw metadata`）补上了 `git_commit` / `subset_method` 的透传，但只对其后产出的 raw 生效。本轮逐档计数（`results/step3_raw/*/*.json`，共 530）并用 `metadata.timestamp_utc` 定向：**① `e5a_scale_small` 100 + `shell256` 80 + `e7_combo` 80 = 260 个两字段齐全**，时间戳 `2026-09-30T15:00:08Z–15:36:22Z`（本地 23:00–23:36），**晚于**两个 commit → 可由 commit 直接锚定；**② `e4_sybil` 70 + `e5_intensity` 100 + `e5_placement` 60 + `e6_wormhole` 40 = 270 个 `git_commit` 为 `null` 且完全没有 `subset_method` 键**，时间戳 `2026-09-29T22:39:19Z–23:28:46Z`，比 `608b4b7`（git init，09-30 22:21 +08:00）**还早约 15 小时** → 它们产自 git 基线**之前**，也就必然产自符号修复**之前**的代码，版本**无法由产物字段自证**。⚠️ **本轮复核补充**：字段自证失败 ≠ 内容无锚——这 270 个（连同 `e7_combo` 被重跑覆盖前的 30 个共 **300 个**）**已在 `608b4b7` 之内**，且 `git diff --name-only` 在这 270 个中命中 **0** → 其字节内容由该 commit 固定，可在仓库内复核（详见 L16⑤）。⚠️ 正文 `:169` 那句"commit 22:36 早于 sweep 启动"**只对 ① 成立，不可外推到 ②**。② 的子集方法须回溯 9/9 均写作 `subset_method: cumulative_degree` 的 `configs/experiments/step3/sweep_*.yaml` 才能确定。**③ 本轮复核新增的出身失真**：530 个 raw 的 `metadata.runner` **恒为 `"e3_blackhole"`**（7 个 sweep 皆然，含 `e4_sybil` / `e6_wormhole` / `e7_combo`）→ 按产物自证会误得"所有臂都由 e3 黑洞 runner 产出"，真实出身目前只能靠所在目录名与 `config` 快照判定。**④** 相对地，`tle_sha256`、`topology_cache_sha256`、基数三元组（`num_flows` × `num_eval_epochs` × `trials_per_flow_epoch`，另附 `total_trials` / `num_nodes` / `cardinality_semantics`）与匹配键四字段在 **530/530 全部齐全**，且 530 个 raw 与源树（`2026-09-29\chat-3` 副本，1,163 个同名文件全量 SHA256 比对）逐字节一致 → **§4 的效应量与 p 值不受本条影响**。 |
| **L8** | **`avg_hops` / `avg_latency_ms` 在攻击臂不可单独解读：零填充稀释为主、幸存者选择为辅**（§4.1 的"177 → 2 ms 不是性能改善"即本条） | ❌ **未修（指标定义固有）**。实测（`results/aggregated/step3/step3_arms.csv`）：基线 `num_success` 35.80 / `avg_hops` 9.3350 / `avg_latency_ms` 177.4277 → `ids1` 1.80 / 0.2200 / 5.0784 → `c1` 22.30 / 5.3775 / 105.8698 → `c24` 1.10 / 0.1000 / 2.0100 → `ids8`、`sy8` 与一切 DR ≡ 0 的组合臂 **0 / 0 / 0**。**这不是"路径变短 / 性能变好"**，机制分两层：**① 零填充稀释（主因）**——`starlink_sim/net/simulator.py:222-224` 与 `:232-234` 对被丢弃的流一律 `hop_counts.append(0)` / `latencies.append(0)`，`:240` 再对含零的全序列取均值，故恒有 `avg_hops ≡ avg_success_hops × num_success / num_trials`（**530/530 个 raw 严格成立，容差 1e-9，0 例外**），跌幅主要由 `num_success` 从 35.80 崩到 1.10 乃至 0 带动；**② 幸存者选择（次因）**——成功流确实变短，但它体现在 `avg_success_hops` 上：基线 **10.4547** → `ids1` 3.20 → `c24` 2.58。⚠️ **重建过程中的更正**：本条第一版写作"长路径流失败后被**排除在均值之外**"，与 ① 的零填充实现相反，已改写；若要谈"成功路径的长短"，产物里已有干净口径 `avg_success_hops` / `avg_success_latency_ms`（二者均在 25 项指标全集中，本轮正文未使用）。→ **这两个指标必须与 `delivery_ratio` / `num_success` 联读。** 例外是 E6 的 `t1` / `t3`（DR 0.9175 / 0.9450、成功流 36.7 / 37.8，`avg_hops` 8.9925 / 8.9775 与基线可比）。 |
| **L9** | **评估窗口只有 2 个 epoch（40 trials/seed）；且 411 次比较未做任何多重校正** | ❌ **B 档折中的固有代价 + 一项本轮复核新增的统计缺口**。B 档口径 `duration=60s / epoch_interval=30s` → `num_eval_epochs=2`、`total_trials=40`/seed（**§3.1** 的 `= 2 epochs × 20 flows × 1`，见 `:151`；该口径也逐臂打印在 `results/step3_logs/e*_*.log` 的汇总块表头，例如 `e5_placement.log:534` 的匹配键里写明 `num_eval_epochs: 2` / `num_flows: 20`）；seeds 42–51 共 10 个、合计 400 trials/臂，单次检验功效足够（Wilcoxon 精确下界 2/2^10 = 0.001953125），但**每 seed 只看到 2 张拓扑快照** → 无法观察攻击的时序演化（收敛期 vs 稳态期），也无法验证 E7 原定的"收敛窗口丢包显著 > 稳态期"这一验收门槛。§4.7 中 97.5° 壳"全 121 epoch 口径 min 0.280 / mean 0.615"与"e3 实际触达窗口 min 0.634 / mean 0.669"的差别正是这一狭窗口的直接后果。⚠️ **本轮补充（非恢复原文）**：`step3_comparisons.csv` 共 **411 行 × 22 列**，无任何校正后 p 值列；全仓 `.py` 中 `bonferroni` / `holm` / `benjamini` / `fdr` / `multipletests` / `p_adjust` 命中 **0** → §4 大量 `p = 0.001953` 与 `significant = 1` 是**未校正**的族内结果（39 臂 × 多指标），**族错误率未声明亦未控制**，不得作为全局显著性引用。 |
| **L10** | **环路计数 `total_loops` 量级异常（既有行为，未修）** | ❌ **未修**——修改会改其语义并要求重跑所有受影响臂。nl=1024 / 2 epochs 下基线 `total_loops` = **25031.0，且 10 个 seed 逐位相同**（仓库内可直接读到：`results/step3_logs/e4_sybil.log:325` 打印 `total_loops mean=25031.0000 std=0.0000`，`e5_placement.log:540` 的 degree 臂为 `25022.0000 / std=0.0000`；std 恒 0 即 10 seed 同值）→ 说明它度量的是控制面收敛产物，而非攻击效应，而 **§4.9** 的历史参照表（`:389`）中 96 节点 E2 口径仅 **50 ± 3.6** → 量级差 ~500×。根因：`ControlPlane.loop_paths` 在 `starlink_sim/net/simulator.py:96` **无界 `extend`**（该累加器只在 `:26` 初始化，全程不清）；`DataPlane.loop_paths` 于 `:182` 清空，但该句位于 `evaluate_flows()`（定义于 `:176`）**函数首**，即**每次调用清空**；而 `:325` 是全文件对该函数的**唯一**调用点，`:310-311` 先算出本次 run 的 `num_epochs = min(len(self.edge_sets), int(duration // self.epoch_duration))`（本档为 2，与日志匹配键里的 `num_eval_epochs: 2` 一致）并由 `:330` 一次性传入，epoch 循环在函数内部（`:201` 遍历流、`:202` 遍历 epoch）→ 实为**每次 run 清一次、跨 epoch 累加**，而非"每 epoch 清一次"（本轮复核更正，不影响本条关于控制面无界累加的主结论）；`:337` 把两者相加作为 `total_loops` 上报。⚠️ **命名与出处（本轮复核更正）**：`loop_paths_count` **确实是 raw 产物的键**——`control_stats.loop_paths_count` 在 **530/530** 存在且与 `control_stats.total_loops` **逐文件相等（0 例外）**；它**不是聚合表的指标名**——`step3_arms.csv` 的指标全集共 **25 项**（与 `step3_summary.json` 的 `metrics_universe` 完全一致），其中只有 `total_loops`。→ 引用**聚合结果**一律用 `total_loops`；引用**单个 raw** 时两键同值可互换，L3 与 §4.9 的写法不算笔误。→ **`total_loops` 不作攻击效应指标**；§4.6 中"sy8 归零的机制是环路 / TTL 耗尽"（`:328`）仅作定性机制证据（§4.6 那 4 个 DR ≡ 0 组合臂为 20351.0 / 20352.3 / 20636.8 / 20664.0，与基线 25031 的差异同样由上述实现主导；放宽到全部 8 个 DR ≡ 0 臂则为 20351–23766，`ids32` 最高）。 |
| **L11** | **§3.3 的两个断言须拆开：RNG 未固定系误记，CI ±0.005 抖动属实且有产物支撑（其唯一物证未入库）**（§3.3 的"见 L11"即本条） | ⚠️ **原句一半被否证、一半被证实**（本条第一版曾判其整句"不成立"，系把 UTF-16LE 日志按 UTF-8 解码后检索得 0 命中造成的漏证，详见本节第 9 条）。**① RNG 已固定**：`scripts/aggregate_step3.py:253`、`scripts/run_experiment_sweep.py:541`、`scripts/aggregate_stats.py:144` 与 `:156`、`scripts/run_simulation.py:271` 一律以 `rng=0` 调用 `aggregate_experiment`（形参见 `starlink_sim/analytics/stats.py:132`，经 `:155` 传入 `np.random.default_rng(rng)`；函数体 `:128-159`（重抽样 `:157-158`、取分位 `:159`），并带 `n_boot < 2000` 即 `raise ValueError` 的下限门禁于 `:150-151`）。**② 产物一致**：`results/aggregated/step3/`（53 个 `agg_*.json`）与 `results/aggregated/step3_partial/`（30 个）的**全部 30 个同名文件逐字节相同**，SHA256 差异 **0**。**③ 跨 sweep 一致**：§3.3 所举"同一 53°@nl=256 臂在两个 sweep 中 CI 上界 0.84 vs 0.835"在 `step3_arms.csv` 里是**同一个数**——`shell256/base_53` 与 `e5a_scale_small/base_n256` 均为 mean 0.7900、CI [0.745, **0.8350**]（这是**现行入库聚合**的取值）；`step3_arms.csv` 中 `ci95_high` 无一行等于 0.8400。本轮对该表之外再作编码自适应全文检索：`results/step3_logs/`（28 个目录条目 / 递归 29 个文件）内 `0.84` 仅 1 处子串命中（`e5_placement.log:538` 的 `10.8435`，是 `avg_success_hops` 的 **CI 上界**小数片段）、`0.835` 与 `bootstrap` 各 **0 命中**，故**该目录内确无 §3.3 那对数的出处**——但出处存在于隔壁 `results/step3_logs_jason/`，见下。⚠️ **CI 数值在仓库内的分布（本轮逐目录重算）**：`results/step3_logs/` 里 5 份 sweep 日志（`e4_sybil` / `e5_intensity` / `e5_placement` / `e6_wormhole` / `e7_combo` 的 `.log`，UTF-8）**确实含逐臂 `CI95=[lo, hi]` 汇总块**（该目录 29 个文件逐行、大小写敏感地数 `CI95` 得 **423** 行；若把 `e7_synergy_analysis.txt` 里的 4 处小写列名 `ci95_low` / `ci95_high` / `ci95` 一并计入则为 427 处），因此不能笼统说"仓库内没有 CI 数值"；该目录内 `shell256` 只有 `_dryrun_shell256.txt` 而无运行日志，`task12/e5a_scale_small.log`（802 行、`[done]` 进度行 80 条、`CI95` 0 行）只记 `[done] arm=… seed=…` 进度行。**但 §3.3 那一对数的出处确实在仓库里**——§5 已登记的隔离目录 `results/step3_logs_jason/`（3 个文件均 UTF-16LE；其中两份 `.log` 被 `.gitignore:71` 排除，`git ls-files` 0 件）：`shell256.log:765` 对 53°/nl=256 基线臂印 `delivery_ratio mean=0.7900 std=0.0775 CI95=[0.7450, 0.8400]`，`e5a_scale_small.log:1007` 对同一匹配键印 `… CI95=[0.7450, 0.8350]`；bh3 臂亦成对 （`shell256.log:778` = [0.3875, 0.5075] 与 `e5a_scale_small.log:1020` = [0.3875, 0.5050]，mean 0.4475 / std 0.1017 逐位相同）。两日志 mean/std 逐位相同而区间不同（`avg_hops` 为 [9.0899, 11.5501] 与 [9.0499, 11.5600]，`num_success`、`avg_latency_ms` 亦异）→ **§3.3 记录的 ±0.005 抖动可复算，不属笔误**。→ **影响边界**：`n_boot=4000` / `alpha=0.05`（`step3_summary.json`，`generated_utc = 2026-09-30T15:42:38+00:00`）下 §4 的区间全部可复现，无需重算；复现的**前提**是沿用 `rng=0` 与 `n_boot=4000`——任何一项改动都会使所有 CI 偏移。至于 0.8400 与 0.8350 之差，它比的是**同一批样本的两条汇总路径**（sweep 运行内打印 vs 最终重聚合），本报告**不复算该差值的成因**（需完整重跑聚合链路；日志打印时该 sweep 的 10 个 seed 是否已跑满亦未核实——`shell256.log` 的 mtime 15:29:29 早于最后一个 raw 的 15:36:22），只确证"两个数都能在磁盘读到，而 0.8400 仅见于未入库日志"。 |
| **L12** | **计划内工作项未完成：防御侧 0/1、引用核验 0/23** | ❌ **未完成，直接限定本报告的可声称范围**。**① Phase 2**（STMP 防御侧：Defender 框架 / ODTA / TESLA / 信誉评分）**未开始**（§0.1 表第 22 行"❌ 未开始（预算耗尽）"；`docs/DECISIONS_AND_ISSUES.md:56–57` 亦记为已知问题 4"STMP 防御未实现…后续需实现 ODTA、TESLA、信誉等机制"）→ 本轮全部数字都是**攻击侧效应**，不存在任何"防御后"的对照；因此 **§4.3**（`:240`）"防御评估必须面对最强放置 degree/k_core"与 **§4.5**（`:286`）"检测到隧道就阻断…在 `peer_only` 场景会降低送达率、引入净损害"两条均为**推论而非实测**，不得表述为安全性结论。**②** `docs/DESIGN.md` **10 处** + `docs/THREAT_MODEL.md` **13 处**引用标注"待核验"（DOI/URL 未逐条核实，合计 23 处），本轮未做。**③ `README.md`**（mtime 2026-09-29 09:51，早于本轮全部实验）**未回写更正**：`:19` 仍称"4284 节点 × 121 epochs 全规模仿真"、`:67` 仍给 `delivery_ratio 1.000`、`:73/:77/:84` 仍以 3 seeds 给黑洞 DR 0.830 / 0.843 ± 0.023、`:33/:214` 仍称 53° 主壳 `P=72` → 与 §1.4 的三套口径声明并存时极易被误引（声明"仅作历史参照"的是 **§4.9 的 `:392`**，而非 §5.2——后者是代码清单）。⚠️ **本轮新增矛盾点**：README `:84` 的每 seed 值"0.83 / 0.87 / 0.83"在仓库内**找不到支撑产物**，唯一的黑洞逐 seed 数据 `results/figures/attack_seed42_44.csv` 给出的是 **0.775 / 0.815 / 0.84**（seed 42/43/44，`is_attack = True`）。二者口径均未标注，无法判定孰是孰非，但**任一方都不得被单独引用**。 |
| **L13** | **`seq_lead=8` 是实现层人为增益 → DR = 0 是攻击上界，不是协议下界** | ⚠️ **刻意设计，但限制解释范围**。`starlink_sim/net/attack.py:192`（`SybilAttacker`）与 `:335`（`WormholeAttacker`）的默认 `seq_lead: int = 8` 使伪造 seq = `_bump_seq + 8`，而合法通告每周期仅 +1 → **永远追不上**（源文档 `:177–186` 自陈此点，并说明"置 `seq_lead=0` 即退化为与黑洞同幅度的 seq 提升"；§4.4 亦记"若只做 `_bump_seq + 1`，会与更新鲜的合法通告打平 → 吸引率恒为 0"）。§4.4 的实测两端：`ids1` 吸引率 0.9125 ± 0.059（DR 0.045）、`ids16` 0.995 ± 0.011（DR 0.000）。真实敌手的 seq 领先能力取决于通告速率与实现细节，**介于两端之间且未知** → "Sybil 是唯一把 DR 压到 0 的攻击"须读作"在具备持续 seq 领先能力的敌手假设下"。同理，黑洞 `metric_fake = 0`（`:87`）与干扰 `inf_metric = 9999`（`:121`）都是 DV 度量语义下最有利于攻击者的取值，而 §4.6 第 4 项已指出 `inf_metric = 9999` 在数据面**完全惰性** → 本轮结果整体偏向攻击能力上界，且不同攻击类型之间不可按 DR 降幅直接排名。**其余未扫描的默认值同样构成假设**：`WormholeAttacker` 的 `pool_size = 48` / `endpoint_strategy = 'farthest'` / `poison_scope = 'peer_only'`（`:333-336`）、`JammingAttacker` 的 `jamming_ratio = 0.3`（`:121`）、`SybilAttacker` 的 `attachment = 'betweenness'` / `controller_poisons = False` / `drop_prob = 0.0`（`:189-192`）都无敏感性档；§4.5 的 `peer_only` 反直觉结果同时依赖 `farthest` 与 `pool_size = 48`，单独归因于 `seq_lead` 并不充分。 |
| **L14** | **攻击的时间维度被完全消元：39 个攻击臂全部使用常驻窗口** | ⚠️ **配置选择造成的覆盖面缺口**。实测 `configs/experiments/step3/`：61 个 YAML = 52 个臂定义（13 个基线臂，无攻击段 + **39 个攻击/组合臂**）+ 9 个 `sweep_*.yaml`；**39/39** 攻击臂均为 `active_since: 0.0` + `active_until: .inf`（raw 的 config 快照把该值记为 `null`，JSON 无无穷字面量）。这规避了"攻击窗口与数据面评估时刻不重叠 → 攻击静默无效"的陷阱（`starlink_sim/net/placement.py:301` 的 `check_attack_windows` 在 `strict=False` 时只由 `scripts/run_experiment_sweep.py:355` 打印 `[attack-window-guard]` 告警而不抛错；`:396` 的 dry-run 预检亦为非阻断），但代价是**间歇性 / 择时攻击（闪断、收敛期集中丢包、慢速渗透）完全未测**，检测器对间歇攻击的响应同样未测。⚠️ **该缺口本可阻断而未启用**：`run_experiment_sweep.py` 已提供 `--strict-window`（`:618`）/ `--non-strict`（`:620`），并有 `:139` → `:171` → `:207-208` → `:312` 的完整接线，而 9 个 `sweep_*.yaml` **全部**写作 `strict_window: false` + `non_strict: false`。→ 本报告所有结论只适用于"攻击者永久在岗"这一最坏情形，**不构成对间歇攻击的界**。 |
| **L15** | **建链规则的敏感性未量化（`off_lattice` 几何回退链路）——属计划外流失，非显式降级** | ❌ **承诺未兑现**。`docs/DECISIONS_AND_ISSUES.md:49–51`（§1.2 已知问题 2）记录"几何回退链路在极少数 epoch 可能切换，但整体重叠率仍 ≥0.97"，并明确 **"已接受：在 E5 敏感性分析中专门评估其影响"**。本轮实测：`results/aggregated/step3/step3_completeness.csv` 的 63 个计划条目中 10 个未完成项**全部**是 `e5a_scale_top`(2) + `shell1024`(8)，E5 系列里没有任何敏感性档；`configs/experiments/step3/` 的 61 个 YAML 全文（不分大小写）中 `off_lattice` / `sensitiv` / `fallback` / `lattice_fidelity` 命中 **0**；仓库内也不存在 `sensitivity/` 配置目录或 `lattice_fidelity` 类产物。→ 与 D1–D3 的显式降级不同，本条从未进入执行计划。拓扑是所有攻击结论的自变量，而它对建链规则的稳健性**至今未验证**。 |
| **L16** | **复现依赖被 `.gitignore` 排除的产物与仓库外的绝对路径，且 22:36 之后未再 commit** | ⚠️ **溯源链有断裂**。**①** `data/topology/topology_results.pkl`（实测 102,763,675 B = **98.00 MiB**）被 `.gitignore:36`（`*.pkl`）与 `:42`（显式路径）双重排除，`:31` 注释自陈"= 98.00MB（超 GitHub 100MB 硬限的下限余量极小）"；`:45` 还排除了 `data/snapshots/`，而该目录**实际不存在** → 仅凭 `608b4b7` / `89c6dcb` **无法复现**，必须同时固定 `topology_cache_sha256 = f23f7ecdef89…`（该哈希在 530 个 raw 中齐全，见 L7④）。**②** 任何重跑 `scripts/build_topology.py:48` / `scripts/build_topology_from_tle.py:48`（两处均以 `max_dist_km=99999.0` 调用）的行为都会换掉该哈希，本报告全部数字随之失效——这与 L2 所要求的"复位门限并重生成 `data/topology/`"直接冲突，故 L2 的修复在本数据上不可行。**③ 聚合产物把复现链钉在仓库外的绝对路径**：`step3_summary.json` 的 `raw_root` 与 `out_dir` 均指向 `…\2026-09-29\chat-3\…` 那棵源树而非本仓库。本轮已做全树比对（1,163 个同名文件逐个 SHA256，仅 `.git\index` 与 `report.md` 不同）→ 530 个 raw **逐字节一致**，数值不受影响，但"重跑聚合"这步在当前目录下默认会去读另一棵树。**④ `schema_version` 无聚合侧校验**：530 个 raw 全部写作 2，但 `scripts/aggregate_step3.py`、`scripts/run_experiment_sweep.py`、`starlink_sim/io/config.py` 中该词命中 **0**（仅 `tools/verify_step3_raw.py` 有 6 处）→ 未来字段变更会被聚合静默读取。**⑤** 22:36 后**未做第三次 commit**，且入库覆盖面在产物各层极不一致（本轮 `git ls-files` / `git diff` / `git status --porcelain` 逐项实测）：`git status --porcelain` 的 **121** 条 = **81 条 `??`（从未入库，含本报告 `report.md`）+ 40 条 `M`（已入库后被改写）**，后者由 30 个 raw + 4 个 sweep YAML + 5 个图 + `results/step3_logs/_matrix_summary.json` 构成。raw：磁盘 530 / **已入库 300**——`e4_sybil` 70、`e5_intensity` 100、`e5_placement` 60、`e6_wormhole` 40 **整档入库且相对 HEAD 无改动**（正是 L7② 那 270 个），`e7_combo` 入库 **30/80**，而交付 §4.7/§4.8 的 `e5a_scale_small` 100 与 `shell256` 80 **入库 0** → 未入库 230 个。⚠️ 已入库的 30 个随后被重跑覆盖，工作区与 HEAD **逐字节相同者 0/30**，但差异**只在出身三元组**：`timestamp_utc`（`2026-09-29T23:30:43Z` → `2026-09-30T15:00:12Z`）、`git_commit`（`null` → `89c6dcb…`）、`subset_method`（键缺失 → `cumulative_degree`）；而 `delivery_ratio` / `avg_hops` / `num_success` / `total_loops` / `avg_success_hops` 在 **30/30 完全一致** → git 里存的是一份被取代的副本，§4 数值不受影响，同时反向印证 `rng=0` 下重跑的确定性。聚合层：`results/aggregated/step3/` 的 **97 个条目（53 `agg_*.json` + 39 `cmp_*.json` + `step3_arms/comparisons/completeness/failures.csv` 与 `step3_summary.json`）入库 0 个**，而**修复前快照 `step3_partial/` 的 61 个条目全部入库且无改动** → git 里有的是"修复前"、没有的是"修复后"，L1 的对照因此是"已锚定的 pre vs 未锚定的 post"。图：18 入库 / 19 在盘，其中 `step3_fig5_e7_combo_synergy.csv/.png`、`step3_fig6_shell_compare.csv/.png`、`step3_fig7_e5a_scale_law.csv` **入库后被重新生成**。另有 4 个 `sweep_*.yaml` 入库后被改写，但差异**仅为头部注释**（文件自陈"**仅注释**，无任何行为字段改动"、"重跑生成器会覆盖订正"），故 L14 所引的行为字段在 HEAD 与工作区一致。至于本报告自身：`git ls-files --error-unmatch report.md` 报 `error: pathspec 'report.md' did not match any file(s) known to git`（`git ls-files report.md` 输出为空、`git status --porcelain -- report.md` 给 `?? report.md`、`git log -- report.md` 无历史）。→ 本条的结论修正为：**"与 commit 的对应关系只存在于文字中"仅对 230 个 raw、全部主聚合产物与本报告成立，对那 270 个 raw 与 `step3_partial/` 不成立。** **⑥ 另注（本轮新增，四项均可在仓库内直接复核）**：仓库根与 `results/step3_logs/` 下现存 **4 个从未入库、也不被 `.gitignore` 忽略的证据文件**（`git check-ignore -v` 对四者均无输出，`git status --porcelain` 一律给 `??`）：`_cmp_pvalues.py`（9,863 B，mtime 09-30 23:26:56，文档串首行自题"**临时脚本（用完即删）**：修复前后 p 值零变化逐条对照"）、它的输出 `results/step3_logs/pvalue_zero_change_check.txt`（8,949 B / 83 行，CRLF 各 83 且以换行收尾，末行即 `[cmp] VERDICT: P-VALUE ZERO-CHANGE CONFIRMED`，mtime 09-30 23:43:27，即 L1 那组计数的原始载体）、`_x2.py`（3,296 B，mtime 09-30 23:43:18，同样自题"临时脚本（用完即删）"，其文档串第 2–3 行写明"8 = shell256 四壳横向表（nl=256，壳内配对 bh3 vs base）／9 = e5a_scale_small 五档规模律"）、以及 `results/step3_logs/_verify_all.txt`（3,410 B / 32 行内容，mtime 09-30 23:21:13，UTF-8 with BOM，中文为 GBK/UTF-8 互错的 mojibake、仅 ASCII 与数字可读）。四者恰是 L1、§4.7、§4.8 与 L17 若干数字的**实际证据载体**，却与本报告同样从未入库；`_verify_all.txt` 内打印的路径亦指向 `…\2026-09-29\chat-3\…`（与③同类）。⚠️ 另需记录一处陈旧注释：`_cmp_pvalues.py` 文档串第 4 行仍写 post = **321 行**，而它自己产出的输出第 2 行是 `post_rows=411`（第 1 行 `pre_rows=271` 则与现存 271 行一致）——注释未随最后一次重算更新，引用该脚本时应以其输出为准；本节第 5 条已据此改引输出文件。 |
| **L17** | **`docs/STEP3_SHELL_SCALE_RUNBOOK.md` 的 §1/§2/§7.2 已被后续决策取代**（§5.1 的"见 L17"即本条） | ❌ **照其执行会走偏，须修订后方可作操作依据**。该 runbook（mtime 2026-09-30 23:25:09，早于 §6.1 所述 41,678 B 截断态的 23:50:44）通篇以"**630 = 350 已有 + 280 本轮**"为目标（`:15`、`:275`、`:291`、`:326`），§2.1 的 matrix 命令写作 `--only e5a_scale_small shell256 shell1024 e5a_scale_top`（`:74`），§7.2 又把"630 全齐"设为聚合前置（`:296`）。本轮实际交付 **530 个 raw**：`shell1024` 与 `e5a_scale_top` 两个目录**根本不存在**（`step3_completeness.csv` 中这 10 个计划臂各 10 seed 的 `n_found` 均为 0），差额 630 − 530 = **100** 恰为 `shell1024` 80 + `e5a_scale_top` 20 → D2/D3 两项降级已使该命令的两个目标档成为空集。仓库内有直接记录：`results/step3_logs/_verify_all.txt`（09-30 23:21:13，**起跑前**快照）列出 `e6_wormhole` 40/40、`e4_sybil` 70/70、`e5_placement` 60/60、`e5_intensity` 100/100、`e7_combo` 80/80 已齐（合计 **350**，即所谓已有），而 `e5a_scale_small` 100、`shell256` 80、`shell1024` 80、`e5a_scale_top` 20 四项 `found = 0`（合计 **280**，即本轮待跑；末行结论 `NOT COMPLETE / HAS INVALID`）。本轮实际只补跑了其中 `e5a_scale_small` + `shell256` = **180** 个 → 终态缺口 = 280 − 180 = **100**，与上式吻合；而聚合已在 530/630 状态下产出（`step3_summary.json` 的 `generated_utc = 2026-09-30T15:42:38+00:00`）→ 前置条件被违反，其正当性仅由 D2/D3 与 L7 事后支撑。⚠️ **归属更正（本轮复核）**：第一版把"§4 数字的真正来源"整体说成"`--only` 清单一个都不含"，**这是错的**——§4.7 的跨壳表**全部**来自 `shell256`（8 臂 = base/bh3 × 43°/53°/70°/97.5°，`node_limit` 恒 256，80 raw），§4.8 的规模阶梯**全部**来自 `e5a_scale_small`（`node_limit` ∈ 48/96/256/512/1024，100 raw），二者**恰恰在 `--only` 清单之内**，合计 180 raw（该归属另有仓库内自证：`_x2.py` 的首行注释将第 8 项写为 `shell256` 四壳横向表（nl=256，壳内配对 bh3 vs base）、第 9 项写为 `e5a_scale_small` 五档规模律（nl=48/96/256/512/1024，档内配对）；而 `_verify_all.txt` 把这两档列在本轮待跑一侧，可见它们并非 runbook §7.2 所称的已有）。正确的划分是：**§4.1–§4.6** 的数字来自另外 5 个 sweep（`e4_sybil` 70 + `e5_intensity` 100 + `e5_placement` 60 + `e6_wormhole` 40 + `e7_combo` 80 = **350**，即 runbook `:5` 划入"已有"的那部分），`--only` 清单不含它们；§4.7/§4.8 虽由 `--only` 覆盖，却从未被该 runbook 的门禁检验过（GATE1 只校 `e7_combo` 的 8 臂 / 80 任务）。→ 该 runbook 的真实失败模式不是"命令与结论无关"，而是**门禁只盯一个 sweep，对交付 §4.7/§4.8 的两档既无验收也无降级说明**。**临时处置**：实验口径一律以本报告 §3.1（B 档）+ §1.4（三套口径）+ §4.7（跨壳只用 nl=256）+ §0.4（D1/D2/D3）为准，取代该 runbook 的 §1/§2/§7.2；其 §3 之后的实操章节（dry-run、内存档位、workers、中断与续跑）仍可用，GATE1 与 GATE2（含 "fix(stats): correct paired rank-biserial sign" 的 commit）现均已满足，可降级为验收清单复用。 |

### 6.1 本节的重建说明（必须与 §6 同读）

> **L7–L17 不是原稿文字的重述，而是 2026-10-03 的回溯重建，且已经过一轮独立复核与修订。** 原稿写到 L6 句中即中断：磁盘上的 `report.md` 为 41,678 B / 470 行，末字节为 `` `sy8` `` + 空格且无换行符。本轮可独立复验的是三件事：工作区副本与 `2026-09-29\chat-3` 原件同为 41,678 B、SHA256 同为 `a8a38076…E0A58E5D`，以及 git 中从未有该文件的历史版本（见 L16⑤）。会话工作目录的 `_limits_recovered.txt` 记录了 6 处 IDE 缓存探针（experts 收件箱与 `ai_tracker` 的 preview / snapshot），但**这些快照各自的字节数本轮未能独立复验，故不作为本节论据**。→ 结论不变：L6 之后的原文**从未落盘**，本节是**按可核验证据重写缺失部分**并逐条标注可信度。

| 档 | 条目 | 来源与性质 |
|---|---|---|
| **A 逐字恢复** | **L8、L9、L10** | 上一会话从 IDE 多智能体缓存（`.qoder-cn/cache/experts/0229fc84-…/inboxes/leader.json`）抽出的 Task 报告"未解决局限"章原文，转码结果保留于会话工作目录 `_limits_recovered.txt`（UTF-16LE，14,654 B，SHA256 前缀 `63CA5293`）**第 39–46 行**——L8 @39、L9 @42、L10 @45；第 33 / 36 行是 L6 / L7 槽，第 37 行是一段恢复脚本正文，均非本档来源。**"逐字"仅指编号、主题与中文措辞的沿用**：该文件的中文在本轮仍为 GBK/UTF-8 互错的 mojibake，只有 ASCII 与数字可读（可读到 `9.335 / .22 / 0.10 / 25031 / loop_paths_count / median_diff = −206 / extend` 等，与本档数字同向）。**状态列与所有数字已由本轮对磁盘产物复核，且复核改写了其中两处内容**：L8 的机制由"排除在均值之外"更正为"零填充稀释为主"，L10 的 `loop_paths_count` 由"不是产物指标名"更正为"是 raw 键、但不是聚合指标名"（详见 L8、L10 内的"本轮复核更正"）。 |
| **B 据正文交叉引用** | **L11、L17** | 原报告 §3.3"见 L11"（`report.md:171`）与 §5.1"见 L17"（`report.md:405`）唯一确定了这两条的编号与主题。正文断言"CI 有 ±0.005 抖动、RNG 未固定种子"，本轮实测**只有后半句被否证**：五个聚合调用点均已 `rng=0`、30 个同名聚合 JSON 逐字节相同、`step3_arms.csv` 内跨 sweep 的同一臂 CI 完全一致。**前半句属实且有仓库内物证**：同一 53°/nl=256 臂在 `step3_logs_jason/shell256.log:765` 印 CI 上界 0.8400、在 `e5a_scale_small.log:1007` 印 0.8350，mean/std 逐位相同而区间不同（注意这两份日志是 UTF-16LE 且被 `.gitignore:71` 排除，按 UTF-8 解码检索会得到 0 命中——L11 第一版正是如此误判为"整句不成立"，已于第 9 条更正）。故 L11 只推翻"RNG 未固定"，保留"CI 抖动"（按"保持既有内容不变"的要求，`report.md:171` 原文未改，以本条为准）。L17 的"旧门禁与 matrix 命令"由 runbook 行号与 raw 计数差额（630 − 530 = 100）实证，但其**数据归属**在本轮被更正（§4.7/§4.8 实际出自 `--only` 清单内的两档）。 |
| **C 据仓库证据新立** | **L7、L12、L13、L14、L15、L16** | **原稿未留任何文字**，条目由本轮从可核验证据建立：`results/step3_raw` 的 530 条逐档字段与时间戳计数、`control_stats` / `data_stats` 的键级核对、`step3_arms.csv`（25 项指标全集）与 `step3_comparisons.csv`（411 行 × 22 列）与 `step3_completeness.csv`（63 条）、`step3_summary.json`（含 `metrics_universe` / `raw_root` / `out_dir`）、`configs/experiments/step3/` 的 52 臂窗口参数与 9 个 sweep 的 `subset_method` / `strict_window`、`starlink_sim/{net/analytics}/**.py` 与 `scripts/*.py` 的行号级核对、`docs/{DECISIONS_AND_ISSUES,DESIGN,THREAT_MODEL,STEP3_SHELL_SCALE_RUNBOOK}.md` 与 `README.md`、`results/figures/attack_seed42_44.csv`、`.gitignore`、`results/step3_logs/` 的 29 个文件（5 份 sweep 日志的逐臂 `CI95` 汇总块、`_verify_all.txt` 的齐套性表、`pvalue_zero_change_check.txt` 的 L1 原始断言）、仓库根的 `_cmp_pvalues.py` 与 `_x2.py`，以及 `git log` / `git status --porcelain` / `git ls-files` / `git diff --name-only` / `git check-ignore -v` 的 tracked-vs-磁盘计数。 |

**十条边界声明**

1. C 档 6 条的编号（12 → 16）与排列顺序是**重建时的编排选择**，不代表原作者的排序意图；A 档虽保留原编号，但其**状态列已被本轮复核改写**（见上表）。若日后寻得原稿，应以原稿为准，本节降级为"补充局限"。
2. 本节**不新增任何实验结论**。L7–L17 中出现的每一个数字都可在 §1–§5 正文或上表所列**仓库内**文件出处复核；核验用的只读脚本与输出**按前缀成族且不闭合**（截至本节定稿：`_verify_*.py` 9 个、`_v*.txt` 11 个（`_v2.txt`–`_v12.txt`）、`_cmp*.txt` 2 个、`_x*.py` 与 `_x*.txt` 各 30 余个且逐轮递增，故此处只给前缀与写作本条时的计数，不给闭集清单），连同**快照族 `_payload_l7_l17*.md`**（其中已定稿且字节/哈希可复核的四份：v1 16,923 B / `65287367`、v2 25,772 B / `38cf6c78`、v3 28,701 B / `49412e1e`、v4 35,487 B / `1cec5c13`；v5 起每轮修订各留一份、只增不减，本文件所在的追加段即其中最新一份）与一份更早的作废草稿 `_append_l7_l17.md`（13,500 B）一并留在**会话工作目录，未写入本仓库**，仓库内读者无从复核（故本节凡论及产物一致性处均给出可仓库内复核的路径与计数，而非仅指向这些工件）。
3. **未发现即不写**：原稿若在 L11 处引用过 `results/step3_logs/compare_bootstrap.txt`，该文件**在仓库中不存在**（`results/step3_logs/` 为 28 个目录条目 / 递归 29 个文件，逐项枚举后无任何同名条目）；§3.3 的"0.84 vs 0.835"在全部产物中也找不到第二个来源。故本条不假设有该日志、不引用其中任何数字。同一纪律反向适用：若原稿在 L7–L17 处还写过其它引用具体文件/行号的断言，本轮凡未能在磁盘上找到该出处的，一律**未写入**本节，因此本节是**证据下限**而非原稿全集。
4. **本轮修订记录（v1 → v2）**：第一次追加的 16,923 B（`_payload_l7_l17.md`，SHA256 前缀 `65287367`）经一次独立复核后，更正了 **4 处事实性错误**——L7 的 commit 与时间戳先后方向、L8 的零填充 vs "排除在均值之外"机制、L10 的"24 项指标全集 / `loop_paths_count` 不是产物指标名"、L17 的 §4.7/§4.8 数据归属；以及 **5 处章节指针**（§3.2→§3.1、§5.2→§4.9 两处、§4.5→§4.3、§4.6→§4.5）与 1 处 git 命令归属（`git ls-files` → `git ls-files --error-unmatch`）；另补入 **4 项此前漏记的局限**——L7③ `metadata.runner` 恒为 `e3_blackhole`、L9 的 411 次比较未做多重校正、L12③ README 每 seed 值与 `attack_seed42_44.csv` 不一致、L16③④ 聚合产物的绝对路径与 `schema_version` 无聚合侧校验。**两次追加期间正文前 41,678 字节均未改动**（其 SHA256 恒为 `a8a38076…E0A58E5D`）。`_payload_l7_l17.md` 保留为 v1 快照，`_append_l7_l17.md` 为更早的作废草稿，二者均非当前内容。
5. **第二次修订（v2 → v3）与对正文 L1 的独立复算**：v3 只做一件事——把原先只能指向会话工作目录的论据换成**仓库内可复核**的产物：L11 补入 `_verify_all.txt` 的性质澄清，L16 补入⑥（3 个未跟踪的证据脚本及其陈旧注释），L17 补入 280 → 180 → 终态缺口 100 的分档记录与 §4.7/§4.8 归属的仓库内自证。顺带重算正文 **L1**（属未改动区，本次未改）的修复前后校验：`step3_partial/step3_comparisons.csv` **271 行** × `step3/step3_comparisons.csv` **411 行**，按 `(sweep, attack, baseline, metric)` 取 shared **271** 组，得 `p_value` / `significant` / `n_pairs` / `median_diff` / `statistic` 不一致 **0**、`post.rank_biserial ≠ pre.rank_biserial_signed` **0**、`rank_biserial` 自身变化 **58** 行、自洽式 `rb = (2T+ − T)/T`（T = n_eff(n_eff+1)/2）不符 **0**；关键案例 `e6_wormhole/t3/delivery_ratio` 为 median_diff +0.05、`rank_biserial` **−1.0 → +1.0**（`signed` 恒为 1.0）、p = 0.00390625、sig = 1 → **L1 的五项计数均可从磁盘复算，正文该条无需更正**。而且这组计数在仓库内本就有原始输出可直接读：`results/step3_logs/pvalue_zero_change_check.txt` 第 1–3 行为 `pre_rows=271 (unique keys=271)` / `post_rows=411` / `shared=271  only_post=140  only_pre=0`，第 7–11 行的 `[1]`～`[4]` 全为 0、第 12 行 `[5] rank_biserial 发生变化的行数 = 58`、第 13 行 `[5b] 方向判据不成立 = 0`，第 20 行 `[6] 自洽性不符 = 0`，第 71 行即上引关键案例（`t_plus=45.0` / `n_eff=9` / `-1.000 → 1.000`），第 83 行 `VERDICT: P-VALUE ZERO-CHANGE CONFIRMED`。
6. **第三次修订（v3 → v4，由本次审查直接触发）**：为核对"追加段有无正文未声明的事实性改动"，本轮把 L7–L17 的每一处 git 级论断改写成 `git ls-files` / `git diff` / `git check-ignore` 的逐项计数，由此发现 **v3 自身有两处过度断言，已更正**——**① L16⑤** 原写作"530 个 raw、聚合产物、图与本报告和 commit 之间的对应关系目前**只存在于文字中**"，实测为：530 个 raw 中 **300 个已在 `608b4b7` 内**（正是 L7② 那 270 个加 `e7_combo` 的 30 个），且这 270 个相对 HEAD **无改动**；porcelain 的 121 条是 **81 条 `??` + 40 条 `M`**，不是"121 条未提交变更"；`results/aggregated/step3/` 的 97 个条目入库 **0**，而修复前快照 `step3_partial/` 的 61 个条目 **全部入库**；另有 30 个已入库 raw、4 个 sweep YAML、5 个图与 1 个 `_matrix_summary.json` **入库后被改写**（`M`）。**② L11** 原称 `_verify_all.txt` 是"该目录内唯一的校验类产物、不含任何 CI 数值"，而 `results/step3_logs/` 里 5 份 sweep 日志**确实逐臂打印 `CI95=[lo, hi]`**；已改为可复核的否证形式（29 个文件内 `0.84` / `0.835` / `bootstrap` 仅 1 处子串命中：`e5_placement.log:538` 的 `10.8435`）。同时新增：L7 的"270 个内容已由 `608b4b7` 锚定"、L9 与 L10 的日志行号级出处、L16⑥ 的第 4 份证据文件，并把本节第 5 条的 L1 复算结论改挂到仓库内的 `pvalue_zero_change_check.txt`。**三次替换期间正文前 41,678 字节始终未改动**（其 SHA256 恒为 `a8a38076…E0A58E5D`）。
7. **第四次修订（v4 → v5，由第二轮独立审查触发）**：本轮不改变任何结论，只做一件事——把追加区里的每一处引用与每一个计数**重新从磁盘复算一遍**。**① 行号级引用全部命中现存行**（口径：只取反引号内的 `路径:行号` 与裸 `:NNN` 两类，范围 = 追加区中本条之前的全部文本，即 L6 补句 + L7–L17 + §6.1 表 + 声明 1–6；本条及其后各条所举行号属复核动作本身，不计入。**同一口径下的计数随修订递增**：v4 文本 68 处、v7（补 `stats.py` 子行号）70 处、v10（改写 L10 调用层次与 L11 的 CI 出处）80 处 = 28 处 `路径:行号` + 52 处裸号，去重 76 个。⚠️ 本条初稿所记"68 处 / 其中 17 处写作 `路径:行号`"是 v4 文本上的旧值，且后一个子数与本轮按上述口径重数的 22 不符、其生成脚本未留存，已不可复原，故 v11 起以本节第 10 条所记口径为唯一口径。80 处中 71 处可按"同句内最近一次显式文件名"自动归属并命中现存行；另 9 处是该归属规则的错归属、不是引用错误——`:151`/`:169`/`:240`/`:286`/`:331–334`/`:392` 实为 `report.md` 的正文内部锚点，`:31`/`:42`/`:45` 实为 `.gitignore`，人工归属后逐一打开均命中且语义相符；语义上仅 1 处跨度少记一行（已改正，见本条末））：`stats.py:128-159`（`:128` = `def bootstrap_ci(...)`、`:132` = `rng` 形参、`:150-151` = `n_boot < 2000` 下限、`:155` = `np.random.default_rng`、`:157-158` = 重抽样、`:159` = percentile 取分位）、`attack.py:192`（`seq_lead: int = 8`）与 `:335`（`metric_fake: int = 0, ...`）、`simulator.py:96`（`self.loop_paths.extend(router.loops_detected)`）/ `:182`（`self.loop_paths = []`）/ `:337`（`results['total_loops'] = ...`）、`aggregate_step3.py:253` 与 `run_experiment_sweep.py:541` / `aggregate_stats.py:144` 与 `:156` / `run_simulation.py:271`（五处调用点均 `rng=0`，`aggregate_stats.py` 全文 `rng` 只出现在这两行）、门禁调用链 `run_experiment_sweep.py` 的 `:139`→`:171`→`:207-208`→`:312`→`:355`、`placement.py:301`、`build_topology*.py:48`、`README.md:19/:67/:84`、`.gitignore:31/:36/:42/:45`、runbook `:3/:5/:14/:15/:74/:275/:291/:296/:326`，以及正文内部锚点 `:151/:169/:171/:240/:286/:328/:331-334/:389/:392/:405`；唯一指向不存在文件的引用是第 3 条里明确声明"该文件在仓库中不存在"的 `results/step3_logs/compare_bootstrap.txt`，属否证用法而非悬空指针。**② 产物计数全部可复算**：raw 磁盘 **530**（`e4_sybil` 70 + `e5_intensity` 100 + `e5_placement` 60 + `e6_wormhole` 40 = **270**；`e7_combo` 80 + `shell256` 80 + `e5a_scale_small` 100 = **260**；两批 raw 自身的 `timestamp_utc` 分别落在 2026-09-29T22:39:19Z–23:28:46Z 与 2026-09-30T15:00:08Z–15:36:22Z）、`git ls-files results/step3_raw` **300**、`git status --porcelain` **121 = 81 条 `??` + 40 条 `M`**、门禁目标 **630**（runbook `:14` 拆为 100+80+80+20，`:15` 记为 350 已有 + 280 本轮）− 530 = **100**，与 `step3_completeness.csv` 的 63 条中 10 条未完成（`e5a_scale_top` 2 + `shell1024` 8）× 10 seed 精确吻合，且 `results/step3_raw/shell1024`、`.../e5a_scale_top` 两目录确不存在、`results/aggregated/step3/` **97 条目**（53 `agg_` + 39 `cmp_` + 5 表/摘要）、`step3_partial/` **61 条目**（30 `agg_` + 25 `cmp_` + 6）、同名 `agg_*.json` **30 个且逐字节相同**（同名的 25 个 `cmp_*.json` 与 5 个表/摘要**全部不同**，本节的"逐字节相同"只就 `agg_*` 而言）、指标全集 **25 项**且与 `step3_summary.json` 的 `metrics_universe` 集合完全相同（修复前后两目录皆为 25 项，故 v1 曾写的"24 项"确系笔误）、`control_stats.loop_paths_count` 与 `total_loops` 在 **530/530** 逐文件相等但**不在**指标全集中、`avg_hops ≡ avg_success_hops × num_success / num_trials` 在 **530/530** 成立、39 个攻击臂 YAML 的 `active_since` / `active_until` 取值集合恰为 `0.0` / `.inf`（0 个例外，raw 快照里 390 个文件的 `active_until` 记为 `null`）、跨 sweep 重臂的 10 组 (arm, shell, node_limit, metric) CI 在**该表内 10/10 完全一致**、`step3_arms.csv` 内 `delivery_ratio` 的 `ci95_high` **无一行等于 0.8400** 而 0.8350 仅出现在两个 53°/nl=256 基线臂且取值相同（第 9 条已把该结论限定到本表：0.8400 确见于未入库的 `step3_logs_jason/shell256.log:765`）、8 个 DR ≡ 0 臂的 `total_loops` 为 20351.0–23766.0（`ids32` 最高）。**③ 审查结论**：追加区内**未发现无法从磁盘复算的论断，也未发现正文未声明的事实性改动**（本句只覆盖到 v5 为止：第六轮发现一处相反情形——一个否证断言本身无法从磁盘复算，见第 9 条）——正文前 41,678 字节与备份 `report.md.bak-truncated` 逐字节相同、裸 LF 计数为 0、§6 表 L1–L17 共 17 行且每行 3 列；已废弃的三处措辞（v4 时为"排除在均值之外"3 次、"只存在于文字中"2 次、"唯一的校验类产物"1 次；本条自身的引证使三者各加 1，**全文现为 4 / 3 / 2 次且前缀始终为 0 次**）经逐处核查**全部只出现在更正或引证语境**中。本轮自查出的缺陷有两处：一是本节第 2 条的工件清单随四次追加而失真（仍写作"两份负载快照"，而会话目录实为五份快照 + 一份作废草稿；且 `_x*` 族已无法用闭集列举）；二是正文 L11 把 `bootstrap_ci` 的函数体跨度记为 `:128-158`，而 percentile 取分位行实为 `:159`，本条初稿亦把 `rng=0` 调用点记为四处、实为五处（漏 `aggregate_stats.py:156`）。两处均已在正文与本条就地更正；其后第三轮审查又发现三处，见第 8 条。本轮修订仅改第 2 条、L16⑤ 的一处标点、L11 的 `stats.py` 跨度并新增本条，**正文前 41,678 字节仍未改动**（SHA256 恒为 `a8a38076…E0A58E5D`）；追加段大小为 v1 16,923 → v2 25,772 → v3 28,701 → v4 35,487 B，v5 起读者可用 `report.md` 现字节数减去 41,678 直接复算。
8. **第五次修订（v7 → v8，由第三轮独立审查触发）**：本轮把引用拆成"仓库内文件"与"会话目录工件"两类分别定位。**① 追加区内出现的每一个路径串（含本条自身新写者，故此处不给定数）都按 basename 在仓库 / 本会话目录 / 上一会话目录三处回溯，除第 3 条主动否证的那一个之外全部有落点**：此前按"仓库根相对路径"判为可疑的 `step3/step3_comparisons.csv` 与 `step3_partial/step3_comparisons.csv` 实为正文省略 `results/aggregated/` 前缀的分段写法，磁盘落点 `results/aggregated/step3/step3_comparisons.csv`（411 数据行 × 22 列）与 `results/aggregated/step3_partial/step3_comparisons.csv`（271 数据行）均在；正文的 `step3_arms/comparisons/completeness/failures.csv` 是四张表的缩写列举，磁盘实为 `step3_arms.csv` / `step3_comparisons.csv` / `step3_completeness.csv` / `step3_failures.csv` 四份 CSV 加 `step3_summary.json`，恰为 97 条目中除 53 个 `agg_*` 与 39 个 `cmp_*` 之外的 5 项；`inboxes/leader.json` 指向 IDE 多智能体缓存 `experts/0229fc84-79cf-4672-a6a0-19d89d669d40/inboxes/leader.json`（173,911 B，正文按省略号写作 `0229fc84-…`），属外部缓存而非仓库指针；`_limits_recovered.txt` / `_payload_l7_l17.md` / `_v2.txt`–`_v12.txt` 均声明为会话目录件，实测在盘。**② 本轮发现并已更正三处**：其一，L11 把 `task12/e5a_scale_small.log` 记为 803 行，磁盘实为 802 行（CRLF 各 802、以换行收尾，`[done]` 进度行 80 条）；其二，同句"`shell256` 只有 `_dryrun_shell256.txt` 而无运行日志"未限定目录——`results/step3_logs/` 内确无，但 §5 已登记的 `results/step3_logs_jason/shell256.log`（UTF-16LE、880 行）是一份运行日志，已补目录限定；⚠️ 但本条初稿据"检索 `CI95` 得 0 命中"宣称该日志不含 CI 块，是**把 UTF-16LE 按 UTF-8 解码**造成的漏检（该文件实有 80 行 `CI95`，:765 即 §3.3 的 0.8400），已由第 9 条推翻并改写 L11；其三，声明第 2 条把 `_verify_*.py` 记为 11 个，会话目录实为 9 个（`_v*.txt` 11 个属实），而 `_x*` 族已达脚本与输出各 30 余个、`_payload_l7_l17*.md` 亦随修订递增，故第 2 条改为"已定稿四份给字节与哈希、其余按前缀成族"的非闭合写法。**③ 本轮收口复算**：`git status --porcelain` 仍为 121（81 `??` + 40 `M`，`report.md` 属 `??`）、`git ls-files results/step3_raw` 为 300、磁盘 `results/step3_raw/*/*.json` 为 530、`configs/experiments/step3/sweep_*.yaml` 为 9、`results/step3_logs/e*_*.log` 为 6、`results/step3_logs_jason/` 为 3 项、`results/aggregated/step3/` 与 `step3_partial/` 为 97 / 61 条目；三处废弃措辞全文计数 4 / 3 / 2 且前缀恒为 0，与本条第 7 项的自述一致（v10 未新增该三串的引证，故计数未动）；除上述更正外**未发现正文未声明的事实性改动**（但本条②其二所凭的"检索 0 命中"已于第 9 条被推翻），亦未发现指向不存在文件的悬空指针（唯一否证用法仍是第 3 条的 `results/step3_logs/compare_bootstrap.txt`）。v8 之后读者仍可用 `report.md` 现字节数减去 41,678 复算追加段大小，正文前 41,678 字节自始至终未改动（SHA256 恒为 `a8a38076…E0A58E5D`）。
9. **第六次修订（v9 → v10，由一次独立代码复核触发；本轮是结论级更正，非措辞级）**：本轮首次由独立复核者把引用与计数重新跑回磁盘，结果是**追加段自己的一个论断被推翻**，故单列一条。**① 缺陷本体**：L11 第一版宣称"§3.3 关于 bootstrap CI 抖动的说法不成立"，v8 补写的那句又写下 `results/step3_logs_jason/shell256.log`"经检索同样不含任何 CI 汇总块"。两处都错。该目录 3 个文件是 **UTF-16LE（BOM `fffe`）**，而此前所有检索脚本一律按 UTF-8 解码：ASCII 串在 UTF-16 里每个字符后跟一个 `0x00`，`CI95` / `0.84` 的匹配数**必然为 0**——那不是"产物里没有"，是"没读到"。改为编码自适应解码后重算：`shell256.log` 含 **80** 行逐臂 `CI95=[lo, hi]`，其中 :765 是 53°/nl=256 基线臂的 `delivery_ratio mean=0.7900 std=0.0775 CI95=[0.7450, 0.8400]`；`e5a_scale_small.log` 含 **100** 行，同一匹配键在 :1007 印 `… [0.7450, 0.8350]`；bh3 臂亦成对（:778 与 :1020 分别为 [0.3875, 0.5075] 与 [0.3875, 0.5050]）。两日志 mean/std 逐位相同而 `avg_hops`、`avg_latency_ms`、`num_success` 的区间互不相同 → **§3.3 的"±0.005 量级抖动、0.84 vs 0.835"可复算，不是笔误**；`_mem_baseline.txt` 亦为 UTF-16LE（2 行、无 CI）。**② 仍然成立的部分**：五个调用点 `rng=0`、30 个同名 `agg_*.json` 逐字节相同、`step3_arms.csv` 内`ci95_high` 无一行等于 0.8400 且两个 53°/nl=256 基线臂同为 0.8350、跨 sweep 重臂 10 组 CI **在该表内** 10/10 一致——即 §3.3 的"RNG 未固定"确系误记。L11 已按此二分改写：只推翻"RNG 未固定"，保留"CI 抖动"。**③ 由此新增的仓库事实**：`results/step3_logs_jason/` 的 3 个文件均 UTF-16LE，其中两份 `.log` 被 `.gitignore:71`（`*.log`）排除（`git check-ignore -v` 对二者均输出该行），而 `_mem_baseline.txt` 不被任何规则排除，只是随目录折成单条 `?? results/step3_logs_jason/` 出现在 porcelain 里；整个目录 `git ls-files` 输出 0 件、`git log -- 该目录` 无历史；mtime 为 09-30 15:29:29 / 15:31:07 / 15:36:24 UTC，正落在第二批 raw（15:00:08–15:36:22）与最终聚合（`step3_summary.json` 15:42:38）之间。也就是说 §3.3 那对 CI 的**唯一物证从未入库**，与 L16"复现依赖被 `.gitignore` 排除的产物"同构，已并入 L11 的影响边界；0.8400 与 0.8350 之差的成因本报告不下结论（见 L11 末）。**④ 本轮同时更正的另外四处**（均已改写进正文）：其一，L10 把 `simulator.py:325` 说成"每 epoch 调一次 `evaluate_flows`、故等价于每 epoch 清一次 `loop_paths`"，实测 `:325` 是全文件唯一调用点、一次传入 `num_epochs=2`（epoch 循环在函数内部 `:201-202`），故为**每 run 清一次、跨 epoch 累加**；其二，L16⑥ 把 `pvalue_zero_change_check.txt` 记为 84 行，磁盘 CRLF 各 83 且以换行收尾，并与本节第 5 条"第 83 行 VERDICT"自相矛盾，已统一为 83；其三，L11 把 `e5_placement.log:538` 的 `10.8435`称作"CI 下界"，实为该臂 `avg_success_hops` 的 **CI 上界**（`CI95=[7.5736, 10.8435]`）。其四（本轮自查所得）：本条初稿把 L10 写成"一次调用传入 `num_epochs=2`"，把变量值写成了字面量——`:330` 传入的是 `:310-311` 算出的变量，本档恰为 2（与两份日志匹配键里的 `num_eval_epochs: 2` 一致），已改为行号级表述。**⑤ 方法教训（写给后续核验者）**：做任何"某串 0 命中"式的否证之前必须先确定编码。本仓库产物混用三种编码——UTF-8（`results/step3_logs/*.log`）、UTF-8 with BOM 且中文为 mojibake（`_verify_all.txt`）、UTF-16LE（`_limits_recovered.txt` 与 `results/step3_logs_jason/*`）；"能用 UTF-8 解码成功"与"字节数对得上"都不能排除 UTF-16。据此本轮把 `results/step3_logs/` 的清点也改为编码自适应，得到该目录 29 个文件 `CI95` 逐行 423 行（含小写列名则 427 处）、`0.84` 1 处、`0.835` 0 处、`bootstrap` 0 处。v10 之后读者仍可用 `report.md` 现字节数减去 41,678 复算追加段大小，**正文前 41,678 字节自始至终未改动**（SHA256 恒为 `a8a38076…E0A58E5D`）。⚠️ 本条 ⑤ 所说的"定数会随轮次失真"在本轮又应验一次：本条所属的第 7 条自述"68 处"已因 v7、v10 的正文改写而变为 80 处，详见第 10 条。
10. **第七次修订（v10 → v11，本轮由"复核动作自身"触发，不涉任何仓库结论）**：第 7 条 ① 自述"行号级引用 68 处全部命中现存行"，其中 17 处写作 `路径:行号`。本轮把同一句话的计数用同一脚本在 v4 / v7 / v10 三份负载快照上各跑一遍，得到 **68 / 70 / 80**——**68 是 v4 文本上的值，此后每轮正文改写都会使它上涨**：v7 把 L11 里 `stats.py` 的函数体跨度由 `:128-158` 改为 `:128-159`、新增 `:157-158` 与 `:159` 两个子行号（净 +2），v10 为 L10 的调用层次补 `simulator.py:201`/`:202`/`:310-311`/`:330`、为 L11 与 §6.1 的 CI 出处补 `shell256.log:765`/`:778`、`e5a_scale_small.log:1007`（两处）/`:1020`、`step3_logs_jason/shell256.log:765`（+10）。至于"17 处写作 `路径:行号`"，本轮在同一口径下重数为 22（v4）与 28（v10），**初稿的 17 无法复算，且其生成脚本未留存**——这是本节第 7 条与第 8 条已两度记录过的"审查记录自身递归失真"的第三次发生，前两次的处置也是同一结论：**自述的定数必须连口径一起写，且需可复算**。**本轮处置**：把第 7 条 ① 改写为"版本化计数 + 唯一口径 + 归属规则失效的 9 处清单"，口径固定为——只取反引号内的 `路径:行号` 与裸 `:NNN` 两类、范围取追加区中第 7 条之前的全部文本（L6 补句 + L7–L17 + §6.1 表 + 声明 1–6，第 7/8/9/10 条自身所举行号不计入）。**复核结果（v11 落盘后的 v10 文本，80 处）**：71 处自动归属命中现存行；9 处为"最近显式文件名"规则的错归属，人工改归后全部命中——`:151` = `total_trials = 40/seed（= 2 epochs × 20 flows × 1）`、`:169` = "代码版本时序"行、`:240` = §4.3 的"防御评估必须面对最强放置"、`:286` = §4.5 的"检测到隧道就阻断…引入净损害"、`:331–334` = §5 后续工作第 1 项、`:392` = §4.9 的"仅作历史参照"，六者皆 `report.md` 正文内部锚点（`report.md` 自身行数远大于此六数，故均在范围内）；`:31`/`:42`/`:45` = `.gitignore` 的体积注释、`data/topology/topology_results.pkl`、`data/snapshots/` 三行。**无一处越界，也无一处指向不存在的文件**；本节第 7 条那句"唯一指向不存在文件的引用是第 3 条主动否证的 `results/step3_logs/compare_bootstrap.txt`"仍然成立。**本轮未改动任何结论、未新增任何仓库事实**，只改第 7 条 ① 的计数自述、第 9 条末的一句指引，并新增本条；正文前 41,678 字节仍未改动（SHA256 恒为 `a8a38076…E0A58E5D`）。v11 起，追加段大小仍可用 `report.md` 现字节数减去 41,678 直接复算。
