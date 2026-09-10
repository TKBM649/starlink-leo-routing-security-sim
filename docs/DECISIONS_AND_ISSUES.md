# 三阶段决策与问题汇编（DECISIONS_AND_ISSUES）

> **整合日期**：2026-09-10
> **数据来源**：`新建 文本文档 (2).txt`（三阶段交接文档节选，原文按 Step 4 → Step 5 → Step 3 逆序）
> **关联文档**：[`../REORGANIZE_LOG.md`](../REORGANIZE_LOG.md) — 目录整理与命名映射
> **说明**：本文档专注于三个阶段的 **关键技术决策 / 已知问题 / 尝试过但失败的方案** 三类内容的横向汇编，便于跨阶段检索技术判断。已按时间正序重排（Step 3 → Step 4 → Step 5）。

---

## 目录

| 阶段 | 日期 | Step | 主题 | 状态 |
|---|---|---|---|---|
| [阶段一](#阶段一--step-3--dv-路由基线2026-09-07) | 2026-09-07 | Step 3 | DV 路由基线（拓扑构建 + 协议验证） | ✅ |
| [阶段二](#阶段二--step-4--e3-黑洞攻击2026-09-08) | 2026-09-08 | Step 4 | E3 黑洞攻击注入 | ✅ |
| [阶段三](#阶段三--step-5--e2-干扰攻击2026-09-09) | 2026-09-09 | Step 5 | E2 干扰攻击注入 | ✅ |
| [跨阶段合并观察](#跨阶段合并观察) | — | — | 位置缓存 / 攻击者策略 / 数据面评估演进 | — |

---

## 阶段一 · Step 3 · DV 路由基线（2026-09-07）

> **原始 PROJECT_STATUS 摘要**
> - **项目名称**：Starlink 星座运动状态与路由安全仿真
> - **当前阶段**：Step 3 已完成（DV 路由基线验证），即将进入 Step 4（攻击注入与 STMP 防御）
> - **工作区**：`D:\starlink`（原 `c:\Users\CWQ20\Documents\QoderCN\2026-09-05\chat-3`；已迁移至 `C:\Users\CWQ20\Desktop\starlink`）
> - **Python 环境**：`starlink-venv` (Python 3.11.9)
> - **入口脚本**：`python scripts/run_simulation.py`

### 1.1 关键技术决策

| 决策点 | 选择 | 理由 |
|---|---|---|
| 数据源 | 固定 TLE 快照 `starlink_20260822.tle`（SHA256 校验） | 保证可复现性，避免每日 TLE 漂移 |
| 轨道传播 | `sgp4` 库 + `skyfield` 外部校验 | 自研内核为主，skyfield 仅做 Step 9 比对 |
| 拓扑建链 | 面锚定 +Grid（同面前后各 1，异面相邻面各 1）+ 面外几何回退（kNN） | 实测 kNN 边重合率仅 41%，面锚定达 >99% |
| 距离门限 | 取消固定门限，使用 2000 km 宽松值（实际几乎不滤边） | 实测面内邻距 >800 km，800 km 门限会砍掉骨架 |
| 面外卫星 | 不丢弃，采用几何回退（最近 4 颗，距离 ≤2000 km） | 保证全网连通，避免孤立节点 |
| 路由协议 | DV（距离矢量）+ 路径矢量（`visited` 列表） | 暴露环路，便于攻击观测 |
| 仿真粒度 | 控制面：逐报文（200ms tick）；数据面：流级（30s epoch） | 平衡精度与速度，支持大规模实验 |

### 1.2 已知问题

1. **数据面评估使用固定拓扑**
   - 当前 `run_simulation.py` 将路由表与第一个 epoch 的边集匹配，未使用动态拓扑快照。
   - **影响**：无法评估拓扑变化（虽然变化极小）对数据面的影响。
   - **计划**：在 Step 4 攻击实验中，将为每个 epoch 保存路由表快照或实时查询。

2. **off_lattice 卫星回退链路可能引入轻微抖动**
   - 几何回退链路在极少数 epoch 可能切换，但整体重叠率仍 ≥0.97。
   - **已接受**：在 E5 敏感性分析中专门评估其影响。

3. **仿真时间与规模**
   - 4284 节点、5000 tick 单次运行约 1-2 分钟（单核）。全因子实验（10 seeds × 6 场景）需数小时，可并行化。

4. **STMP 防御未实现**
   - 当前仅为 DV 基线，后续需实现 ODTA、TESLA、信誉等机制。

### 1.3 尝试过但失败的方案

| 方案 | 失败原因 | 替代方案 |
|---|---|---|
| 全局 800 km 距离门限 | 面内邻距（~1033 km）被过滤，骨架全灭 | 取消门限（或 2000 km） |
| 固定 kNN 建链（每星 4 最近） | 300s 边重合率仅 41%，拓扑剧烈抖动 | 面锚定 +Grid |
| 一阶 J₂ 解析外推 RAAN | 误差导致格点拟合 P=180，off_lattice 失真 | 改用 SGP4 传播 + 位置/速度反算 RAAN |
| 强制 53° 壳 P=90 且容忍度 0.6° | 孤立节点数 1818（42%），影响连通性 | 容忍度保持 0.6°，但增加几何回退 |
| 数据面评估使用动态路由表（未保存快照） | 用最终路由表匹配早期边集，交付率剧降 | 使用固定拓扑验证协议正确性（已通过） |

---

## 阶段二 · Step 4 · E3 黑洞攻击（2026-09-08）

> **交付**：E3 黑洞攻击注入并跑通，delivery_ratio 从基线 1.00 → 0.83，17 条流被丢弃。
> **相关代码**（当前命名）：
>   - `starlink_sim/net/attack.py`（原 `Black hole attack.py`）
>   - `starlink_sim/net/simulator_blackhole.py`（原 `simulator_Black hole attack.py`）
>   - `scripts/run_e3_blackhole_experiment.py`（原 `run_Black hole attack_experiment.py`）

### 2.1 关键技术决策

| 决策点 | 选择 | 理由 |
|---|---|---|
| 攻击者修改广告的频率 | 每次节点发送广告时（`T_adv=2s`）都修改，而非每个 tick 都修改 | 避免路由更新风暴，保持性能可接受 |
| 攻击者选择策略 | 选择拓扑中**历史度数最高**的节点（从所有 epoch 边集累计） | 提高攻击者出现在数据路径中的概率 |
| 数据面评估 epoch 对齐 | 使用最后一个 epoch 的边集，并传入其起始时间 `base_time` 用于攻击者活跃判断 | 确保路由表时刻与边集匹配，且攻击者活跃状态正确 |
| 节点 ID 提取 | 从边集中收集所有出现过的节点 ID，而非假设连续编号 | 避免因节点 ID 不连续导致无效流 |
| 数据面时延 | 暂不计算（位置缓存缺失），设为零 | 位置文件不存在，但交付率和跳数不受影响 |

### 2.2 已知问题

1. **位置缓存缺失**
   - `data/snapshots/positions_per_epoch.pkl` 不存在，导致数据面时延（`avg_latency_ms`）始终为 0。
   - **影响**：无法评估攻击对时延的影响。
   - **解决**：后续可运行 `build_topology.py` 或单独生成位置缓存文件，但当前不影响交付率和跳数评估。

2. **攻击者选择依赖历史度数**
   - 攻击者根据累计边频选择度数最高的节点，但最后一个 epoch 的实际度数可能变化。
   - **影响**：攻击者在评估 epoch 可能不是最高度，但仍能吸引部分流量（当前实验已成功）。
   - **解决**：可改为在最后一个 epoch 动态选择，但当前方案已够用。

3. **攻击窗口需手工配置**
   - `active_since` 和 `active_until` 必须与仿真时长和最后 epoch 时间对齐，否则攻击可能不触发。
   - **建议**：在配置文件中使用注释说明。

4. **单次运行耗时**
   - 优化后 60 秒仿真约需 1~2 分钟，完整 3600 秒仿真可能仍需数十分钟。
   - **对策**：全量实验时可缩短验证时长，或使用多进程并行。

### 2.3 尝试过但失败的方案

| 方案 | 失败原因 | 替代方案 |
|---|---|---|
| 攻击者每个 tick（0.2s）都修改广告 | 引起路由更新风暴，单次仿真耗时长达 2 小时 | 改为仅在节点发送广告（`T_adv=2s`）时修改 |
| 使用 `_modified` 标志让攻击者只修改一次 | 后续广告恢复原状，路由表被其他节点覆盖，攻击未生效 | 取消标志，每次广告都修改（但频率低，性能可接受） |
| 数据面评估所有 epoch（遍历整个仿真） | 路由表与早期拓扑不匹配，交付率极低（~6%） | 仅使用最后一个 epoch，且传入正确的 `base_time` |
| 攻击者随机选择 | 常选到孤立节点，无法吸引流量 | 改为选择度数最高的节点 |

---

## 阶段三 · Step 5 · E2 干扰攻击（2026-09-09）

> **交付**：E2 干扰攻击注入并跑通，96 节点子集 120 秒仿真，delivery_ratio=0.8389（≈基线）。
> **发现**：干扰攻击效果有限（交付率未下降），转向 Sybil 攻击路线。
> **相关代码**（当前命名）：
>   - `starlink_sim/net/attack_jamming.py`（原 `e2_jamming attack.py`）
>   - `starlink_sim/net/simulator_jamming.py`（原 `e2_jamming simulator.py`）
>   - `scripts/run_e2_jamming_experiment.py`（原 `run_e2_jamming attack_experiment.py`）

### 3.1 关键技术决策

| 决策点 | 选择 | 理由 |
|---|---|---|
| 拓扑加载 | 使用 `build_topology.py` 预生成的 `topology_results.pkl`，不再实时计算 | 加速实验，避免重复计算 |
| 节点子集提取 | 使用 BFS 从第一个 epoch 边集中提取连通分量，取前 N 个节点（默认 96） | 保证子图连通，DV 收敛较快 |
| 攻击者选择 | 基于全边集累计度数，选择度数最高的节点 | 与 E3 保持一致，提高路径覆盖概率 |
| 干扰攻击实现 | 抬高 DV 广告中部分邻居的度量（`inf_metric=9999`） | 模拟链路不可用，不涉及物理层 |
| 攻击窗口 | 在配置文件中可调（`active_since`/`active_until`） | 灵活控制攻击时序 |

### 3.2 已知问题

1. **位置缓存缺失**
   - `topology_results.pkl` 中未包含 `positions_per_epoch`，导致 `avg_latency_ms` 始终为 0。
   - **影响**：无法评估时延相关指标。
   - **解决**：后续可由 `build_topology.py` 生成时添加位置数据，或从 TLE 传播计算。

2. **子集规模固定为 96**
   - 当前 BFS 提取固定 96 节点，可能不足以代表全规模拓扑行为。
   - **影响**：E2 结果仅适用于小子集。
   - **解决**：可在 `build_topology_from_tle` 中增加 `node_limit` 参数，逐步扩大规模（如 30 面≈1430 节点）。

3. **DV 收敛时间**
   - 96 节点子集需要 > 60 秒才能接近收敛（交付率 83.89%），全规模收敛更慢。
   - **影响**：短时实验可能得到未收敛路由结果。
   - **建议**：延长仿真时长（如 300 秒）或优化收敛算法。

4. **攻击者修改广告的持续性**
   - 攻击者每次发送广告都修改，可能造成路由震荡。
   - **现状**：攻击窗口内持续修改，窗口外恢复正常。
   - **可接受**：符合攻击模型。

### 3.3 尝试过但失败的方案

| 方案 | 失败原因 | 替代方案 |
|---|---|---|
| 取 ID 最小的 96 个节点 | 子图不连通，路由无法收敛 | 使用 BFS 提取连通分量 |
| 取最大连通分量全量（4284 节点） | DV 收敛极慢，60 秒交付率仅 8% | 限制为 96 节点连通子图 |
| 干扰攻击强度逐步增加（0.3→0.5→0.9） | 交付率始终未下降 | 记录为"干扰攻击效果有限"，转向 Sybil 攻击 |

---

## 跨阶段合并观察

### 观察 1 · 位置缓存缺失（Step 4 + Step 5 共有）

- **表现**：
  - Step 4：`data/snapshots/positions_per_epoch.pkl` 不存在
  - Step 5：`topology_results.pkl` 未包含 `positions_per_epoch`
- **共同后果**：`avg_latency_ms` 恒为 0
- **影响**：无法评估攻击对时延的影响（两个 Step 均受限）
- **合并解决**：由 `build_topology.py` 生成时补齐位置数据（一次性修复，两个 Step 都受益）
- **优先级**：⚠️ 中高 — 影响 PLAN §L4 时延类指标评估

### 观察 2 · 攻击者选择策略（Step 4 → Step 5 沿用）

- **Step 4（E3 黑洞）**：首次采用"历史度数最高的节点"（累计所有 epoch 边频）
- **Step 5（E2 干扰）**：沿用 Step 4 策略，保持跨实验一致性
- **验证**：两个实验均成功吸引流量（E3 dropped_by_attacker=17，E2 attacked_count=145）
- **潜在改进**：可改为"最后一个 epoch 动态选择"（Step 4 已知问题 2），但当前方案够用

### 观察 3 · 攻击窗口配置接口（Step 4 → Step 5 沿用）

- **接口**：`active_since` / `active_until` 在 YAML 配置文件中可调
- **共同要求**：必须与仿真时长和最后 epoch 时间对齐，否则攻击不触发
- **建议**：在 `configs/experiments/*.yaml` 中统一使用注释说明取值约束

### 观察 4 · 数据面评估策略演进（Step 3 → Step 4）

| 阶段 | 评估策略 | 结果 |
|---|---|---|
| Step 3 | 路由表 × 第一个 epoch 边集（固定拓扑） | ✅ 交付率 1.000（协议验证通过） |
| Step 3 尝试 | 最终路由表 × 早期边集（动态） | ❌ 交付率剧降（失败方案） |
| Step 4 | 路由表 × 最后一个 epoch 边集 + `base_time` | ✅ 交付率 0.83（攻击生效） |
| Step 4 尝试 | 遍历所有 epoch | ❌ 交付率 ~6%（失败方案） |

**教训**：动态路由表必须与拓扑快照严格对齐（时刻匹配），否则交付率剧降。

---

## 附录 · 与当前项目结构映射

原始 txt 中提到的旧文件名 → 当前项目新命名（完整清单见 [`../REORGANIZE_LOG.md`](../REORGANIZE_LOG.md)）：

| 交接文档旧名 | 当前命名 |
|---|---|
| `D:\starlink` | `C:\Users\CWQ20\Desktop\starlink` |
| `starlink_20260822.tle` | `data/tle/starlink.tle`（SHA256 一致） |
| `simulation_engine.py` | `starlink_sim/net/simulator.py` |
| `isl_builder.py` | `starlink_sim/topology/isl.py` |
| `Black hole attack.py` | `starlink_sim/net/attack.py` |
| `e2_jamming attack.py` | `starlink_sim/net/attack_jamming.py` |
| `simulator_Black hole attack.py` | `starlink_sim/net/simulator_blackhole.py` |
| `e2_jamming simulator.py` | `starlink_sim/net/simulator_jamming.py` |
| `run_Black hole attack_experiment.py` | `scripts/run_e3_blackhole_experiment.py` |
| `run_e2_jamming attack_experiment.py` | `scripts/run_e2_jamming_experiment.py` |
| `run_attack_experiment.py` | 已拆分为上述两个 e2/e3 脚本 |

---

**文档结束**
