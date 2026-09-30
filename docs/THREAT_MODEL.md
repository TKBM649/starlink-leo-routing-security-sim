# 威胁模型（THREAT MODEL）

> **文档定位**：本文档遵循"威胁模型先行（threat-model-first）"的工程规范，在实现任何防御机制（STMP：ODTA / TESLA / 信誉 + FRR）之前，先明确界定**被保护资产、敌手能力、攻击面、信任假设**，并将每一类威胁映射到规划中的缓解措施。
> **配套文档**：设计定位与保真度声明见 [`DESIGN.md`](./DESIGN.md)；三阶段决策与已知问题见 [`DECISIONS_AND_ISSUES.md`](./DECISIONS_AND_ISSUES.md)。
> **代码锚点**：本模型逐项对应 [`starlink_sim/net/attack.py`](../starlink_sim/net/attack.py)、[`routing_dv.py`](../starlink_sim/net/routing_dv.py)、[`simulator.py`](../starlink_sim/net/simulator.py) 的实际实现，凡涉及"当前行为"的断言均可在上述源码中核验。
> **状态标注**：`[已实现]` = 代码可运行并被 E2/E3 实验验证；`[占位]` = 已有类骨架但无实际攻击逻辑；`[规划]` = 尚未编码。

---

## 目录

| # | 章节 | 内容 |
|---|---|---|
| 1 | [系统与作用域](#1-系统与作用域) | 被保护资产、仿真边界、非目标 |
| 2 | [敌手能力（Adversary Capability）](#2-敌手能力adversary-capability) | 被动 / 主动、知识、能力上限 |
| 3 | [攻击面（Attack Surface）](#3-攻击面attack-surface) | 逐项对应代码的攻击入口 |
| 4 | [STRIDE 分类表](#4-stride-分类表) | 六类威胁在路由安全场景的映射 |
| 5 | [DREAD 评分](#5-dread-评分) | Blackhole / Jamming / Sybil / Wormhole 优先级排序 |
| 6 | [信任假设](#6-信任假设) | DV 无条件信任邻居通告等关键缺口 |
| 7 | [缓解措施映射](#7-缓解措施映射) | 威胁条目 → STMP 防御机制 |
| 8 | [引用](#8-引用) | 可核验出处清单 |

---

## 1. 系统与作用域

### 1.1 被保护资产（Assets）

本仿真保护的核心资产是**分布式路由系统的可信性与数据交付的完整性**，具体拆分为两项：

| 资产 ID | 资产 | 完整性目标 | 代码载体 |
|---|---|---|---|
| **A1** | **DV 路由控制面完整性** | 每个节点的路由表 `routing_table` 反映真实拓扑度量（跳数），不被伪造/篡改的通告污染 | `DVRouter.routing_table`、`DVMessage.entries`（[`routing_dv.py`](../starlink_sim/net/routing_dv.py)） |
| **A2** | **数据面交付完整性** | 数据流按真实最短（跳数）路径端到端送达，不被非法丢弃或劫持绕行 | `DataPlane.compute_path` / `evaluate_flows`（[`simulator.py`](../starlink_sim/net/simulator.py)） |

**派生资产**：A1 的完整性直接决定 A2——控制面被污染（伪造低度量）会把数据流吸引到攻击者节点，进而被丢弃。二者构成"控制面 → 数据面"的因果链，是本威胁模型的主线。

### 1.2 仿真边界（Scope）

**在作用域内（in-scope）**：

- 星座规模：4284 节点（53° 主壳层 + 97.5° 极轨壳层），基于真实 TLE 快照（10744 记录，2026-08-22，SHA256 `852E79A4...`）。
- 控制面：DV + 路径矢量（`visited` 防环），逐报文 200 ms tick，广告周期 `T_adv = 2 s`。
- 数据面：流级事后评估，30 s epoch，时延仅按 `dist / c`（`SPEED_OF_LIGHT = 299792.458 km/s`）计算传播时延。
- 攻击者注入点：控制面通告改写（`modify_advertisement`）与数据面丢包判定（`should_drop_data`）。

**不在作用域内（out-of-scope，明确排除）**：

| 排除项 | 原因 | 对结论的影响 |
|---|---|---|
| 物理层 / 链路层干扰（真实 RF 功率、误码） | 干扰被抽象为控制面度量抬升（`inf_metric=9999`），非物理信号建模 | E2 结论仅适用于"路由层可观测的干扰后果"，不外推到物理层抗干扰能力 |
| 数据面队列 / 拥塞 / 缓冲丢包 | 数据面为无状态的事后流评估，不建模排队 | 交付率下降只归因于攻击丢弃或路径不可达，不含拥塞丢包 |
| 处理时延 / 排队时延 | 时延模型仅 `dist / c` | 几何度量下界防御（见 §7）依赖此简化，真实系统需扩展时延模型 |
| 星地链路 / 地面站信任 | 仿真只覆盖星间 ISL 与星上路由 | 不涉及地面段攻防 |
| 集中式 / 预计算路由 | 本仿真采用分布式 DV 作为脆弱性参照系（见 [`DESIGN.md`](./DESIGN.md) §1） | **关键**：结论不外推到 Starlink 真实（疑似确定性/预计算）路由 |

---

## 2. 敌手能力（Adversary Capability）

### 2.1 被动 vs 主动能力

| 能力类别 | 具体行为 | 本仿真中的体现 | 状态 |
|---|---|---|---|
| **被动（Passive）** | 窃听通告、流量分析、推断拓扑/路由表 | 当前**未建模**为独立攻击者；但敌手知识假设（§2.2）允许其"已知拓扑" | `[假设]` |
| **主动 · 篡改通告** | 改写自身发出的 `DVMessage.entries`（metric / seq） | `BlackholeAttacker.modify_advertisement`（伪造 `metric_fake=0`）、`JammingAttacker`（抬升 `inf_metric=9999`） | `[已实现]` |
| **主动 · 数据面丢包** | 选择性丢弃过境数据流 | `BlackholeAttacker.should_drop_data`（按 `drop_prob` 概率丢弃） | `[已实现]` |
| **主动 · 伪造身份** | 注入虚假节点身份（Sybil） | `SybilAttacker` 类存在但为空壳（不改通告、不丢包） | `[占位]` |
| **主动 · 跨节点隧道** | 两个被劫持节点伪造不存在的高速链路（Wormhole） | 尚未编码 | `[规划]` |

### 2.2 敌手知识（Knowledge）

| 知识维度 | 假设 | 依据 |
|---|---|---|
| 是否知晓网络拓扑 | **完全知晓**（Kerckhoffs 原则）：敌手掌握星座星历与 ISL 拓扑 | 星历（TLE）本质公开，Starlink 轨道参数可被 CelesTrak 等公开源获取；防御方不能依赖拓扑保密 |
| 是否知晓路由协议细节 | **完全知晓**：DV + 路径矢量、seq 单调递增采纳规则、无认证 | 协议为公开算法；采纳逻辑见 `_process_update`（[`routing_dv.py`](../starlink_sim/net/routing_dv.py)） |
| 是否知晓其他节点路由表 | **不直接知晓**，仅能观测自身收到/发出的通告 | 攻击者只能访问其宿主节点 `node.routing_table`（见 `JammingAttacker.modify_advertisement`） |
| 是否知晓防御机制 | 遵循 Kerckhoffs：即便未来部署 STMP，也假设敌手知晓其算法（仅密钥保密） | 密码学设计惯例 |

### 2.3 能力上限（Capability Ceiling）

明确界定攻击者**能做**与**不能做**，避免威胁模型过度膨胀：

| 维度 | 上限 | 代码约束 |
|---|---|---|
| **能劫持多少节点** | 由配置 `attack.count` 决定（E2=10，E3=3）；选择策略为**历史累计度数最高**的节点（`placement: degree`） | 实验入口按度数排序选取，非任意节点 |
| **能改写哪些报文** | **仅能改写自身发出（`msg.src == self.node_id`）的通告**，不能篡改他人报文 | `modify_advertisement` 首行守卫：`if getattr(adv_msg, 'src', None) != self.node_id: return adv_msg` |
| **能改写报文的哪些字段** | 能改写 `entries` 的 `metric` 与 `seq`（通过 `_bump_seq` 单调递增，确保接收端采纳）；**不能**改写 `src`（身份仍为宿主节点）、不能凭空注入不存在的邻居关系 | `_rebuild` 保留 `src/dst/type`；`_bump_seq` 维护 `_seq_floor` |
| **能否协同（collusion）** | 当前各攻击者**独立行动**（无共享状态/联合调度）；Wormhole 需两节点协同，尚未实现 | `ControlPlane.attackers` 为独立列表，逐个 `is_active` 判定 |
| **攻击时序** | 受 `active_since` / `active_until` 窗口约束（E2/E3 均为 20 s–40 s）；窗口外恢复正常通告，网络收敛复原 | `Attacker.is_active(time)` |
| **能否绕过 seq 防旧序** | **能**：`_bump_seq` 生成比历史更大的 seq，正是利用了"接收端 seq 更大即无条件采纳"的信任缺口 | `_process_update`：`if seq > current_entry.seq: self._add_entry(...)` |

> **结论**：敌手是**"受限的内部人（bounded insider）"**——已劫持少量高连接度节点，能完全控制这些节点对外发出的通告内容与自身的数据转发行为，但**不能**篡改他人报文、不能伪造物理不存在的链路（除非 Wormhole 协同）、不能突破节点数量配置上限。

---

## 3. 攻击面（Attack Surface）

逐项对应代码的攻击入口。每一行给出：入口函数 → 被利用的信任缺口 → 攻击效果。

| 攻击面 ID | 攻击类型 | 入口（代码） | 被利用的信任缺口 | 攻击效果 | 状态 |
|---|---|---|---|---|---|
| **AS-1** | **控制面通告篡改 · 黑洞** | `BlackholeAttacker.modify_advertisement` 改写 `entries` 的 `metric → metric_fake=0` | 接收端无条件信任邻居通告的低度量（`metric+1 < current` 即采纳） | 伪造"我离所有目的地最近"，把过境流量吸引到攻击者节点 | `[已实现]` |
| **AS-2** | **控制面通告篡改 · 干扰** | `JammingAttacker.modify_advertisement` 改写 `metric → inf_metric=9999` | 接收端无条件信任"不可达"通告（高 seq 即采纳撤回） | 谎称部分邻居/路径不可达，触发路由撤回、绕行、瞬时环路 | `[已实现]` |
| **AS-3** | **数据面丢包** | `BlackholeAttacker.should_drop_data`（`random.random() < drop_prob`） | 数据面无源认证/无逐跳完整性校验，中间节点可自由丢弃 | 吸引流量后按 `drop_prob`（E3=0.8）丢弃，交付率下降 | `[已实现]` |
| **AS-4** | **身份注入 · Sybil** | `SybilAttacker`（空壳，`modify_advertisement` 直接返回原报文） | 无节点身份认证，理论上一个物理节点可伪造多个逻辑身份 | 虚增节点/边，污染拓扑与路由决策 | `[占位]` |
| **AS-5** | **跨节点隧道 · Wormhole** | 尚未编码 | 无几何一致性校验（无法验证"链路时延 ≥ dist/c"） | 两个远端被劫持节点伪造高速直连隧道，制造虚假短路径吸引流量 | `[规划]` |
| **AS-6** | **seq 单调性滥用** | `Attacker._bump_seq`（生成 `max(seq, _seq_floor)+1`） | seq 无认证、无签名，任何节点可自增 seq 抢占采纳优先级 | 保证被篡改通告持续压过真实通告（AS-1/AS-2 的使能条件） | `[已实现]` |

**攻击面收敛说明**：AS-6 是 AS-1/AS-2 的**技术使能器**——若 seq 受认证保护，攻击者无法保证其伪造通告被采纳。AS-5（Wormhole）与 AS-4（Sybil）是当前唯一"无法仅靠通告字段约束"的攻击，必须引入几何/身份认证才能防御，这正是 STMP 的核心动机。

---

## 4. STRIDE 分类表

将 §3 的攻击面映射到 STRIDE 六类威胁。每类给出：本场景语义、对应攻击、代码证据、受影响资产。

| STRIDE 类别 | 本路由安全场景的映射 | 对应攻击（攻击面） | 代码证据 | 受影响资产 | 状态 |
|---|---|---|---|---|---|
| **S · Spoofing（假冒）** | 伪造节点身份，虚增逻辑实体参与路由 | Sybil（AS-4）；Wormhole 端点身份伪装（AS-5） | `SybilAttacker` 空壳 | A1（拓扑/路由表被虚假身份污染） | `[占位]`/`[规划]` |
| **T · Tampering（篡改）** | 篡改路由通告的度量字段，伪造"最优路径" | 黑洞伪造 `metric_fake=0`（AS-1）；seq 抢占（AS-6） | `BlackholeAttacker.modify_advertisement` → `new_entries.append((dest, self.metric_fake, self._bump_seq(dest, seq)))` | A1 → A2（吸引流量后丢弃） | `[已实现]` |
| **R · Repudiation（抵赖）** | 被劫持节点事后否认发过伪造通告；无签名导致无法归因 | 所有主动攻击（AS-1/2/3/6）均不可归因 | 通告无数字签名，`DVMessage` 无认证字段 | 审计能力（取证/归因缺失） | `[缺口]` |
| **I · Information Disclosure（信息泄露）** | 窃听通告/流量，推断拓扑、路由表、流量矩阵 | 被动窃听（§2.1，未建模为攻击者） | 通告广播（`dst=-1`）至所有邻居，无加密 | 拓扑/路由机密性 | `[假设]` |
| **D · Denial of Service（拒绝服务）** | 抬升度量为不可达，撤回路由，制造环路与绕行 | 干扰抬升 `inf_metric=9999`（AS-2）；黑洞数据面丢包（AS-3） | `JammingAttacker` → `inf_metric`；`should_drop_data` | A2（交付率下降）、A1（瞬时环路，E2 约 50 次） | `[已实现]` |
| **E · Elevation of Privilege（权限提升）** | 通过伪造度量使攻击者节点成为"最优下一跳"，获得本不应有的流量转发权 | 黑洞（AS-1）—— `metric_fake=0` 使攻击者成为几乎所有目的地的下一跳 | `_process_update` 采纳低度量 → `next_hop = 攻击者` | A1（路由决策权被劫持） | `[已实现]` |

> **STRIDE 观察**：本场景中 **Tampering（篡改度量）与 Elevation of Privilege（劫持下一跳）在黑洞攻击中是同一枚硬币的两面**——篡改 metric 是手段，获得转发权（进而 DoS/丢包）是目的。Repudiation 与 Information Disclosure 当前**未建模为主动攻击者行为**，但作为信任缺口存在（无签名 → 不可归因；广播明文 → 可窃听），是 STMP 需补齐的次级目标。

---

## 5. DREAD 评分

对四类攻击（2 类已实现 + 2 类规划/占位）按 DREAD 五维打分。**评分标度：0（无）/ 3（低）/ 6（中）/ 9（高）**，总分 45，均值 = 总分 / 5，据均值划分优先级。

**维度定义（本场景语义）**：

- **D · Damage（损害潜力）**：攻击成功对 A1/A2 造成的破坏程度（交付率下降幅度、环路数量）。
- **R · Reproducibility（可复现性）**：在固定 seed + YAML 配置下重放攻击的难易度。
- **E · Exploitability（可利用性）**：发动攻击所需的前置条件（需劫持节点数、是否需协同、是否需特殊知识）。
- **A · Affected users（影响范围）**：受攻击影响的流量/节点比例。
- **D · Discoverability（可发现性）**：漏洞（无认证 DV）被敌手发现的容易程度；**分数越高表示缺口越易被利用**。

| 攻击 | 状态 | Damage | Reproduc. | Exploit. | Affected | Discover. | 总分/45 | 均值 | 优先级 |
|---|---|---|---|---|---|---|---|---|---|
| **Blackhole（黑洞）** | `[已实现]` | 9 | 9 | 6 | 6 | 9 | **39** | 7.8 | **P0 · 最高** |
| **Wormhole（虫洞）** | `[规划]` | 9 | 3 | 3 | 9 | 6 | **30** | 6.0 | **P1 · 高** |
| **Sybil（女巫）** | `[占位]` | 6 | 3 | 6 | 6 | 6 | **27** | 5.4 | **P2 · 中** |
| **Jamming（干扰）** | `[已实现]` | 6 | 9 | 6 | 3 | 9 | **33** | 6.6 | **P1 · 高** |

**评分依据（逐条）**：

- **Blackhole = 39（P0）**：Damage 9（E3 交付率 1.000 → 0.83，−17%，且含"吸引流量 + 数据面丢弃"双重机制）；Reproducibility 9（配置驱动、seed 固定、已由 `tests/test_attack_injection.py` 独立验证）；Exploitability 6（需劫持高连接度节点，但无需协同）；Affected 6（seed42 攻击者吸引 7+5+6 条流经其转发）；Discoverability 9（"无认证 DV 可被低度量欺骗"是教科书级漏洞）。
- **Jamming = 33（P1）**：Damage 6（E2 交付率较基线小幅下降，但引发约 50 次瞬时转发环路）；Reproducibility 9；Exploitability 6；Affected 3（作用于 96 节点子集，范围受限）；Discoverability 9（`inf_metric=9999` 撤回同样无认证）。
- **Wormhole = 30（P1）**：Damage 9（虚假短路径可吸引大量流量）；Reproducibility 3（尚未实现）；Exploitability 3（需两节点协同 + 隧道基础设施）；Affected 9（伪直连可影响跨区流量）；Discoverability 6（需理解几何一致性才能防御，但漏洞本身易发现）。
- **Sybil = 27（P2）**：Damage 6（虚增节点污染拓扑，但当前空壳无实际损害）；Reproducibility 3（未实现）；Exploitability 6（无身份认证 → 注入身份门槛低）；Affected 6（潜在网络级）；Discoverability 6。

> **优先级结论**：**Blackhole（P0）> Jamming ≈ Wormhole（P1）> Sybil（P2）**。防御资源应优先投向 P0——即"控制面通告完整性 + 数据面丢包检测"，这直接对应 STMP 的**几何度量下界（dist/c）**与**信誉 + FRR** 机制（见 §7）。Wormhole 虽未实现，但因"仅靠通告字段无法防御、必须几何认证"而列为 P1。

---

## 6. 信任假设

本节列出仿真当前**成立但脆弱**的信任假设。这些假设正是 STMP 防御要显式打破的缺口。

| 假设 ID | 信任假设 | 代码依据 | 是否为安全约束 | STMP 是否需打破 |
|---|---|---|---|---|
| **TA-1** | **部分节点可被劫持**：敌手控制少量（配置化，E2=10 / E3=3）高连接度节点，完全支配其通告与转发行为 | `ControlPlane.attackers` + `placement: degree` | 攻击前提 | 否（这是威胁前提，非防御目标） |
| **TA-2** | **DV 无条件信任邻居通告**：接收端仅比较 seq 与 metric，不验证通告真实性 | `_process_update`：`if seq > current_entry.seq: self._add_entry(...)` | **否——这是核心缺口** | **是**（ODTA/TESLA 认证通告来源与内容） |
| **TA-3** | **唯一的过滤是拓扑约束，非安全约束**：`if msg.src not in self.neighbors: continue` 只排除"非邻居"，不排除"邻居发的假内容" | `_process_update` 首行守卫 | **否——属拓扑连通性检查，非认证** | **是**（需区分"是邻居"与"邻居说的是真话"） |
| **TA-4** | **无认证 / 无签名**：`DVMessage` 无 MAC/签名字段，任何节点可自增 seq 抢占采纳 | `DVMessage.__slots__ = ('type','src','dst','seq','visited','entries')` 无认证字段 | **否——缺口** | **是**（TESLA 密钥链提供逐报文认证） |
| **TA-5** | **无时间同步假设**：seq 为逻辑计数器，不绑定物理时间；无时间戳可校验 | `_bump_seq` 纯逻辑递增 | **否——缺口** | **部分**（TESLA 依赖松同步；ODTA 依赖星历时间可推导） |
| **TA-6** | **几何一致性未被校验**：链路时延默认等于 `dist/c`，但无机制验证"通告的度量/路径不违反光速下界" | `DataPlane.compute_path`：`total_delay += dist / SPEED_OF_LIGHT * 1000.0` | **否——缺口** | **是**（几何度量下界可检测 Wormhole 的"不可能短路径"） |
| **TA-7** | **数据面无逐跳完整性**：中间节点可自由丢弃过境数据，无源认证/无丢包问责 | `should_drop_data` 纯本地判定 | **否——缺口** | **是**（信誉机制记录节点转发行为，FRR 快速重路由绕过坏节点） |

> **核心论断**：TA-2 / TA-3 / TA-4 构成"**信任传递链断裂**"——DV 协议的安全完全建立在"邻居诚实"这一未经认证的假设上。`msg.src in neighbors` 只是拓扑可达性检查（防串扰），**不是**身份或内容认证。攻击者只需是一个"合法的邻居"即可完全绕过该检查，这正是 AS-1/AS-2/AS-6 得以成立的根本原因。

---

## 7. 缓解措施映射

将 §3–§6 的威胁条目映射到规划中的 **STMP（Secure Topology-aware Multi-Path / 安全拓扑感知路由）** 防御机制。STMP 当前**尚未实现**（见 [`DECISIONS_AND_ISSUES.md`](./DECISIONS_AND_ISSUES.md) §1.2 已知问题 4），本节为设计蓝图。

| 威胁 / 缺口 | 对应 STRIDE | 规划缓解机制 | 机制原理 | 打破的信任假设 | 优先级 |
|---|---|---|---|---|---|
| AS-1 黑洞伪造 metric / AS-6 seq 抢占 | Tampering / EoP | **ODTA（Orbit-Derived Topology Authentication，轨道导出认证）** | 利用星历（TLE）公开且可独立验证的特性，由轨道位置**离线推导**期望拓扑，节点通告须与推导拓扑一致方可采纳 | TA-2 / TA-3 | P0 |
| AS-4 身份伪造 / AS-6 无签名 | Spoofing / Repudiation | **TESLA 密钥链（Timed Efficient Stream Loss-tolerant Authentication）** | 基于哈希链的延迟披露密钥，为通告提供逐报文认证与不可否认性（松同步假设下） | TA-4 / TA-5 | P0 |
| AS-5 Wormhole 虚假短路径 | Spoofing / Tampering | **几何度量下界（dist / c 校验）** | 任何合法路径的时延不得低于端到端直线距离 / 光速；违反下界的通告判定为伪造隧道 | TA-6 | P1 |
| AS-3 数据面丢包 | DoS | **信誉机制（Reputation）+ FRR（Fast Re-Route，快速重路由）** | 逐跳记录节点转发成功率，低信誉节点从候选下一跳剔除；FRR 在检测到丢包时预置备份路径快速绕行 | TA-7 | P1 |
| 被动窃听 / 流量分析 | Information Disclosure | **通告加密 / 最小化广播范围**（规划外，低优先） | 限制明文广播，缩小可观测面 | §2.1 被动能力 | P3 |

**缓解措施与 DREAD 优先级的对应关系**：

- P0 攻击（Blackhole）→ 由 **ODTA + TESLA** 联合防御：ODTA 校验通告与轨道推导拓扑的一致性（拦截 `metric_fake=0` 的非法低度量），TESLA 提供不可抵赖的报文认证（拦截 seq 抢占）。
- P1 攻击（Jamming / Wormhole）→ Jamming 的 `inf_metric=9999` 撤回可由 ODTA 识别为"与真实拓扑不符的不可达声明"；Wormhole 由几何度量下界识别。
- P1 数据面丢包 → 信誉 + FRR：即使攻击者短暂吸引流量，低信誉会使其被快速剔除，FRR 保证备份路径的交付连续性。

> **防御设计的学术诚实声明**：STMP 的几何度量下界依赖本仿真"时延 = dist/c"的简化模型（见 [`DESIGN.md`](./DESIGN.md) §2 简化项）。真实系统需扩展为"传播时延 + 处理时延 + 排队时延"，届时下界仍成立（时延只会更大），但检测阈值需重新标定。此点已列入 §6 TA-6 的落地约束。

---

## 8. 引用

> 引用仅限 arXiv / ACM / IEEE / MDPI 原文或官方仓库。**DOI/URL 若不确定一律标注"待核验"，不编造。**

| # | 出处 | 用途 | 核验状态 |
|---|---|---|---|
| [1] | Perrig, A., Canetti, R., Tygar, J. D., & Song, D. *"Efficient Authentication and Signing of Multicast Streams over Lossy Channels."* IEEE Symposium on Security and Privacy (S&P), 2000. | TESLA 密钥链原始提案（§7 缓解机制） | 作者/标题/会议/年份可核验；**DOI 待核验** |
| [2] | Perrig, A., Szewczyk, R., Tygar, J. D., Wen, V., & Culler, D. E. *"SPINS: Security Protocols for Sensor Networks."* ACM MobiCom 2001 / Wireless Networks 2002. | TESLA 在受限网络的扩展（μTESLA） | 作者/标题/会议可核验；**DOI 待核验** |
| [3] | Douceur, J. R. *"The Sybil Attack."* International Workshop on Peer-to-Peer Systems (IPTPS), 2002. | Sybil 攻击定义（AS-4 / STRIDE-Spoofing） | 作者/标题/会议/年份可核验；**DOI 待核验** |
| [4] | Hu, Y.-C., Perrig, A., & Johnson, D. B. *"Packet Leashes: A Defense against Wormhole Attacks in Wireless Networks."* IEEE INFOCOM 2003. | Wormhole 攻击与几何/时延下界防御（AS-5 / §7 几何度量下界） | 作者/标题/会议/年份可核验；**DOI 待核验** |
| [5] | Karlof, C., & Wagner, D. *"Secure Routing in Wireless Sensor Networks: Attacks and Countermeasures."* Ad Hoc Networks, 2003. | 路由层攻击分类（黑洞/虫洞/Sybil）与 STRIDE 映射参考 | 作者/标题/期刊/年份可核验；**DOI 待核验** |
| [6] | Butler, K. R. B., Farley, T. R. A. M., McDaniel, P., & Rexford, J. *"A Survey of BGP Security Issues and Solutions."* Proceedings of the IEEE, 2010. | 路径矢量协议安全缺口类比（本仿真 DV+路径矢量） | 作者/标题/期刊/年份可核验；**DOI 待核验** |
| [7] | Wood, L. J., Clerici, A. C., & Longstaff, A. J. *"Providing Survivability in LEO Satellite Networks."* Information & Space Systems, 2001（相关期刊/会议待精确核对）. | +Grid 拓扑与星间链路可生存性（§1 拓扑背景） | **作者/标题/venue/年份均待核验** |
| [8] | Bhattacherjee, D., & Singla, A. *"Network Topology Design at 27,000 km/hour."* ACM CoNEXT 2019. | LEO 星座拓扑设计与 +Grid 建链规则锚定（§1 / [`DESIGN.md`](./DESIGN.md) §4） | 作者/标题/会议/年份可核验；**DOI 待核验**（任务描述提及"ToN 2019"，venue 归属待核验） |
| [9] | CelesTrak. *"SATCAT / TLE 数据源."* 官方站点：`https://celestrak.org/` | 真实 TLE 快照来源（§1.2 数据保真度） | 官方仓库/站点可核验；具体访问路径见 [`DESIGN.md`](./DESIGN.md) §3 |
| [10] | Reinhold, B. *"SGP4 / python-sgp4."* 官方仓库：`https://github.com/brandon-rhodes/python-sgp4` | 轨道传播内核（§1.2 SGP4） | 官方仓库可核验 |

> **待核验清单汇总**（供后续统一核对，勿在未核验前引用 DOI）：[1][2][3][4][5][6][8] 的 DOI；[7] 的作者/标题/venue/年份**全部待核验**；[8] 的 venue（CoNEXT vs ToN）归属待核验。

---

**文档结束** · 威胁模型 v0.1 · 配套设计定位见 [`DESIGN.md`](./DESIGN.md)
