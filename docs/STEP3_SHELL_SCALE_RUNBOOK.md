# STEP3 规模阶梯（E5-a）与跨壳对比 —— 实跑 Runbook

> **适用 sweep**：`shell256`、`e5a_scale_small`、`shell1024`、`e5a_scale_top`（共 **280** 任务）
> **仓库根**：`starlink-leo-routing-security-sim-main/starlink-leo-routing-security-sim-main/`（下文所有命令均在此目录下执行）
> **前置**：本 runbook 假设 step3 前 5 个 sweep（`e6_wormhole`/`e4_sybil`/`e5_placement`/`e5_intensity`/`e7_combo`，共 350 任务）已完成。
> **维护**：Task #12 产出。所有数字均来自本机实测，实测时间与命令附在各节。

---

## 0. 结论速览（照做前必读）

| 项 | 值 |
|---|---|
| 总任务数 | **280** = `e5a_scale_small` 100 + `shell256` 80 + `shell1024` 80 + `e5a_scale_top` 20 |
| 跑完后全库 raw 目标 | **630** 个 JSON（350 已有 + 280 本轮） |
| 预计总墙钟 | **75–140 min**（点估 ~100 min，实测值见 §9） |
| 峰值 RAM 需求 | FreeRAM ≥ **20 GB**（`e5a_scale_small` W=10 阶段） |
| 硬上限 | `WORKERS_TOP=2` **不得调高**；`node_limit` **不得**出现 4284 |
| 串行/并行 | sweep 之间**串行**，sweep 内部 seed×臂**并行**（spawn Pool） |

**实际执行顺序由 `scripts/run_step3_matrix.py` 的 `ORDER` 常量决定，`--only` 只筛选、不重排**（实测确认，见 §8 纠正 #5）：

```
e5a_scale_small  →  shell256  →  shell1024  →  e5a_scale_top
   (100, W10)        (80, W8)     (80, W8)       (20, W2)
```

这个顺序同样满足「由轻到重、早发现问题」：`e5a_scale_small` 的头两档 `nl=48/96` 单任务 <10 s，若配置有误会在**开跑 1 分钟内**暴露；最重的 `nl=2048` 排在最后。

---

## 1. 启动前门禁（四条全绿才可开跑）

```powershell
# GATE1：Jimmy 的 e7_combo 必须已齐全
python scripts\run_step3_matrix.py --list
#   → 期望看到 e7_combo  arms=8 seeds=10 tasks=80 workers=10 complete=True

# GATE2：stats.py 配对 rank-biserial 符号修复必须已 commit（否则效应量符号是错的）
git log --oneline
#   → 期望 ≥2 个 commit，且含 "fix(stats): correct paired rank-biserial sign"

# GATE3：无残留 sweep worker（自己的分析进程除外）
(Get-Process python -ErrorAction SilentlyContinue | Measure-Object).Count
#   → 期望 0

# GATE4：FreeRAM ≥ 20GB
[math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1MB, 2)
#   → 期望 ≥ 20.00
```

**本轮实测（2026-09-30，四条全绿后启动）**：

| 门禁 | 实测值 | 判定 |
|---|---|---|
| GATE1 | `e7_combo arms=8 seeds=10 tasks=80 workers=10 complete=True` | ✅ |
| GATE2 | `89c6dcb fix(stats): correct paired rank-biserial sign + passthrough subset_method in raw metadata`<br>`608b4b7 chore(repo): git init baseline snapshot with step3 attack-matrix evidence` | ✅ |
| GATE3 | `0` | ✅ |
| GATE4 | `22.29` GB | ✅ |

> **门禁未全绿时的纪律**：只做只读分析与 dry-run，自身内存占用 ≤ 4 GB，每 3–5 min 重核一次。**抢跑导致 OOM 会损坏已有的 350 个 raw checkpoint**，那是不可接受的失败；「只交分析 + runbook」是完全可接受的交付。

---

## 2. 精确启动命令

### 2.1 推荐：单次 matrix 调用跑完 4 个 sweep（可断点续跑）

```powershell
New-Item -ItemType Directory -Force -Path results\step3_logs\task12 | Out-Null
$env:PYTHONIOENCODING = "utf-8"

python -u scripts\run_step3_matrix.py `
  --only e5a_scale_small shell256 shell1024 e5a_scale_top `
  --skip-existing `
  --log-dir results\step3_logs\task12 `
  *> results\step3_logs\task12\_driver.log
```

要点：
- `-u`：关闭 Python stdout 缓冲。**不加 `-u` 时 PowerShell 重定向下父进程日志会到进程结束才落盘**（见 §8 纠正 #1）。
- `--skip-existing`：**sweep 粒度**跳过 —— 只跳过「raw 已齐全」的整个 sweep，不做任务粒度续跑（见 §5）。
- `--log-dir results\step3_logs\task12`：**隔离日志目录**。`run_step3_matrix.py` 会用 `"w"` 模式**覆盖** `<log-dir>\_matrix_summary.json`，不隔离就会抹掉别人（如 `e7_combo` 重跑）留下的墙钟证据。
- 每个 sweep 的完整 stdout 由 matrix 落到 `results\step3_logs\task12\<sweep>.log`，逐 sweep 落盘 summary（中途被打断也保留已完成记录）。

### 2.2 逐个手动跑（想在每步之间人工检查时用）

```powershell
python -u scripts\run_experiment_sweep.py --sweep-config configs\experiments\step3\sweep_e5a_scale_small.yaml
python -u scripts\run_experiment_sweep.py --sweep-config configs\experiments\step3\sweep_shell256.yaml
python -u scripts\run_experiment_sweep.py --sweep-config configs\experiments\step3\sweep_shell1024.yaml
python -u scripts\run_experiment_sweep.py --sweep-config configs\experiments\step3\sweep_e5a_scale_top.yaml
```

> ⚠️ **不要**用 `run_step3_matrix.py --only X --dry-run` —— matrix **没有** `--dry-run` 参数，会报 `error: unrecognized arguments: --dry-run`。dry-run 只能用 `run_experiment_sweep.py`（见 §3）。

---

## 3. 开跑前的 dry-run 校验（轻量，不加载 pkl）

```powershell
$env:PYTHONIOENCODING = "utf-8"
foreach ($s in @("e5a_scale_small","shell256","shell1024","e5a_scale_top")) {
  python scripts\run_experiment_sweep.py `
    --sweep-config "configs\experiments\step3\sweep_$s.yaml" --dry-run
  Write-Output "$s exit=$LASTEXITCODE"
}
```

**逐条核对项**（每个 sweep 都要看）：

| 核对项 | 期望 |
|---|---|
| `runner` | `e3` |
| `subset_method` | `cumulative_degree` |
| `seeds` | `[42, 43, ..., 51]`（10 个） |
| 任务矩阵 | `arms × 10 seeds` 与 §4 表一致 |
| `workers` | 10 / 8 / 8 / 2（依次） |
| 每臂 `~num_eval_epochs` | `2` |
| 每臂 `attackers` | base 臂 `0`，攻击臂 `3` |
| `duration` | `60.0` |
| window-guard 告警 | **无**（有告警说明攻击窗口与评估时刻不重叠，臂设计有问题） |
| 末行 | `对比: attack='...' vs baseline='...'（同 runner=e3）` |

**本轮实测 dry-run 结果（4 个全部 exit=0）**：

| sweep | 臂数 | 任务数 | workers | 对比对 |
|---|---|---|---|---|
| `e5a_scale_small` | 10 | 100 | 10 | `bh3_n1024` vs `base_n1024` |
| `shell256` | 8 | 80 | 8 | `bh3_43` vs `base_43`（末对；实际聚合会逐壳配对） |
| `shell1024` | 8 | 80 | 8 | `bh3_43` vs `base_43`（同上） |
| `e5a_scale_top` | 2 | 20 | 2 | `bh3_n2048` vs `base_n2048` |

另实测：全部 **52 个臂配置** 的 `(num_flows, duration, epoch_interval)` 三元组统一为 `(20, 60, 30)`，无一处偏离。

> **dry-run 不加载 pkl、不跑仿真**（`run_experiment_sweep._dry_run` docstring 明示），内存开销可忽略，四个可以连续跑，无需逐个释放。

---

## 4. 每步 RAM 预算 / workers / 预计墙钟

内存模型：`~500 B·N²`（活路由表，含 `RouteEntry.path` 路径矢量）`+ ~100 B·N²·epochs`（`routing_table_history` 逐 epoch 快照）。
pkl 缓存：`topology_results.pkl` 102.8 MB，每个 spawn worker 加载一次；四壳全量驻留 ~1.13 GB/worker，`keep_shells` 剔壳后单壳 ~0.55 GB/worker。

| # | sweep | nl | 臂×seed | workers | 单 worker RAM | sweep RAM 预算 | 单任务墙钟 | 预计 sweep 墙钟 |
|---|---|---|---|---|---|---|---|---|
| 1 | `e5a_scale_small` | 48/96/256/512/1024 | 10×10 | **10** | ~1.62 GB（nl=1024 主导） | ~16.2 GB | 48–96 档 <10 s；256 档 ~15 s；512 档 ~40 s；1024 档 ~114 s | **12–20 min** |
| 2 | `shell256` | 256 | 8×10 | **8** | ~1.4 GB（四壳 pkl 无法剔壳 + 小路由表） | ~11.2 GB | ~15–25 s | **5–10 min** |
| 3 | `shell1024` | 1024 | 8×10 | **8** | ~2.2 GB（四壳 pkl + 1024 路由表） | ~17.6 GB | ~114–155 s | **19–26 min** |
| 4 | `e5a_scale_top` | 2048 | 2×10 | **2** | ~4.0 GB | ~8.0 GB | ~450–600 s（≈4× nl=1024） | **40–100 min** |

**单任务墙钟的实测锚点**（来自已完成的 5 个 sweep 的 `_matrix_summary.json`）：

| sweep | 任务 | wall_s | workers | 推算 |
|---|---|---|---|---|
| `e6_wormhole`（nl=1024, 单壳） | 40 | 456.8 | 10 | 4 批 × **114 s**/任务 |
| `e5_placement`（nl=1024, 单壳） | 60 | 663.7 | 10 | 6 批 × **110 s**/任务 |
| `e4_sybil`（nl=1024, 单壳） | 70 | 817.0 | 10 | 7 批 × **117 s**/任务 |
| `e5_intensity`（nl=1024, 单壳） | 100 | 1141.0 | 10 | 10 批 × **114 s**/任务 |
| `e7_combo`（nl=1024, 多攻击者组合） | 80 | 1233.2 | 10 | 8 批 × **154 s**/任务 |

→ **nl=1024 单壳基线 ~110–117 s；带多攻击者的组合臂 ~154 s。** `nl=2048` 按 O(N²) 外推 ≈ 4× 即 450–600 s，是全流程最大的不确定项，故排在最后并给宽区间。

**内存红线**：
- `W=20` **必然 OOM**（24 逻辑核 ≠ 内存够用），不要因为是 24 核就调高。
- 跑 `e5a_scale_small` / `shell1024` 期间 FreeRAM 会被压到 ~4–8 GB，这是正常的；但若出现 `MemoryError` 或系统开始剧烈换页，**立即按 §6 安全停止**并降 workers。
- `nl=4284`（全量）已被实测否决：无攻击 2 epochs 即吃到 WS 20743 MB @393 s 未完成被 kill；按内存模型 4284×121 ep ≈ **222 GB**。**绝对不要恢复。**

---

## 5. 进度监测

### 5.1 主监测：raw 计数（**唯一可靠**的实时指标）

```powershell
# 全库总数，目标 630
(Get-ChildItem results\step3_raw -Recurse -Filter *.json).Count

# 本轮 4 个 sweep 的分项进度
foreach ($s in @("e5a_scale_small","shell256","shell1024","e5a_scale_top")) {
  $n = (Get-ChildItem "results\step3_raw\$s" -Filter *.json -ErrorAction SilentlyContinue | Measure-Object).Count
  Write-Output "$s : $n"
}
# 目标：e5a_scale_small=100, shell256=80, shell1024=80, e5a_scale_top=20
```

> **为什么不用日志**：PowerShell 重定向下 Python stdout 被块缓冲，`<sweep>.log` 在进程结束前基本为空（只有 matrix 自己 `flush` 过的 START 行）。父进程加 `-u` 可缓解，但 **spawn 出来的 worker 的输出仍会缓冲**。所以：**看 raw 文件计数，不要看日志。**

### 5.2 内存监测（跑重档时建议开着第二个窗口）

```powershell
while ($true) {
  $free = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory/1MB, 2)
  $py   = Get-Process python -ErrorAction SilentlyContinue
  $ws   = [math]::Round((($py | Measure-Object WorkingSet64 -Sum).Sum)/1GB, 2)
  Write-Output "$(Get-Date -Format HH:mm:ss)  FreeRAM=${free}GB  pyProcs=$($py.Count)  pyWS=${ws}GB"
  Start-Sleep 30
}
```

判据：`FreeRAM` 持续 < 1.5 GB 或 `pyWS` 超过 §4 预算 20% 以上 → 准备停止并降 workers。

### 5.3 完成判定

```powershell
python scripts\run_step3_matrix.py --list
#   → 4 个 sweep 全部 complete=True，9/9 齐全
python tools\verify_step3_raw.py --only e5a_scale_small shell256 shell1024 e5a_scale_top
#   → 期望末行 "结论：ALL GREEN"，exit=0
```

---

## 6. 中断与安全停止

### 6.1 安全停止（**必须做两遍**）

```powershell
# 第一遍：杀 matrix 父进程 + 当前 worker
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 5

# 第二遍：孤儿 worker 会 respawn 一批新 worker，必须再清一次
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 3

# 复查：必须为 0，不为 0 就重复上面两行
(Get-Process python -ErrorAction SilentlyContinue | Measure-Object).Count
```

> **踩坑（已实证）**：`Stop-Process` 掉 `multiprocessing.Pool` 的父进程后，spawn 出的 worker 变成孤儿并**继续 respawn 一批新 worker**。只做一遍清理会看到「杀完之后进程数又涨回来」，且这些孤儿会继续写 raw、继续吃内存。必须再执行一次全量 `Get-Process python | Stop-Process` 并**复查计数为 0**。
>
> 注意：这会连带杀掉别人（如 Jimmy）正在跑的 python 进程。共享机器上先确认归属再动手。

### 6.2 续跑

```powershell
# sweep 粒度续跑：已齐全的 sweep 直接跳过，未齐的重跑
python -u scripts\run_step3_matrix.py `
  --only e5a_scale_small shell256 shell1024 e5a_scale_top `
  --skip-existing --log-dir results\step3_logs\task12 `
  *> results\step3_logs\task12\_driver_resume.log
```

**`--skip-existing` 的真实语义（实测源码 `run_step3_matrix.is_complete`）**：
- 判据是 `len(expected_raw_files(item)) >= n_tasks`，其中 `expected_raw_files` 用 glob `{label}__*_seed{seed}.json` 逐 (label, seed) 匹配。
- 它是 **sweep 粒度的全有/全无**：只要缺 1 个 raw，整个 sweep 就会被重跑（**全部** 100 个任务重来）。
- `run_experiment_sweep.py` **自身没有任务级 skip 逻辑** —— 它总是重跑全部任务并覆盖 raw。

**这样安全吗？安全。** 已有 raw 会被重写，但因 `seed + 配置` 完全确定，逐位一致、无损。这一点已被实证：`bh3` 臂在三个不同 sweep（`e5_intensity` / `e7_combo` / `e5_placement`）中得到 **DR=0.3000 / sd=0.1155 / CI 0.2374–0.3675 完全相同**。

> **踩坑**：`--arm LABEL=CONFIG` 是**覆盖/追加**语义，**不是缩减**。你无法用它「只跑缺失的那个臂」—— 它只会在 sweep YAML 的臂列表上覆盖同名 label 或追加新 label，其余臂照跑。想只补缺失臂，唯一办法是临时另写一个只含该臂的 sweep YAML（`raw_dir` 指向同一目录），跑完把 raw 拷回去。

---

## 7. raw 完整性判据 + 跑完后聚合

### 7.1 完整性判据（四条，缺一不可）

1. **JSON 可解析**（utf-8）；
2. **`schema_version == 2`**（顶层与 `metadata` 内均写有此字段）；
3. **`data_stats.num_trials > 0`**（`num_trials == 0` 表示一条流都没送达，通常是配置错误而非「攻击太强」）；
4. **匹配键四字段齐全**：`metadata.shell` / `metadata.node_limit` / `metadata.num_eval_epochs` / `metadata.num_flows`。

另有统一口径一致性告警（不判失败）：`num_eval_epochs==2`、`num_flows==20`、`total_trials==40`、`runner` 以 `e3` 开头、`duration==60`、`epoch_interval==30`、`subset_method=='cumulative_degree'`、`seed ∈ 42..51`。

**用工具一次校验（推荐）**：

```powershell
python tools\verify_step3_raw.py                     # 全部 9 个 sweep，630 任务
python tools\verify_step3_raw.py --only shell256 -v  # 单 sweep + 逐文件明细
python tools\verify_step3_raw.py --json results\step3_logs\task12\verify.json
```

输出样例（本轮门禁时刻，350/630 已齐全）：

```
============================================================
sweep              tasks  found  miss  inval  warn  complete
------------------------------------------------------------
e6_wormhole           40     40     0      0     0  YES
e4_sybil              70     70     0      0     0  YES
e5_placement          60     60     0      0     0  YES
e5_intensity         100    100     0      0     0  YES
e7_combo              80     80     0      0     0  YES
e5a_scale_small      100      0   100      0     0  NO
shell256              80      0    80      0     0  NO
shell1024             80      0    80      0     0  NO
e5a_scale_top         20      0    20      0     0  NO
============================================================
合计：350/630 任务矩阵齐全，缺失 280，INVALID 0
```

退出码：`0` = 全绿；`1` = 有缺口或 INVALID；`2` = 用法错误。

### 7.2 聚合（**只在 630 全齐 + stats.py 符号修复已 commit 后跑**）

```powershell
$env:PYTHONIOENCODING = "utf-8"
python scripts\aggregate_step3.py --n-boot 4000
```

可选参数：`--alpha 0.05`（默认）、`--only <sweep...>`（仅聚合指定 sweep）、`--no-figures`（跳过画图，省时间）、`--raw-root` / `--out-dir` / `--figures-dir`。
输出：`results/step3_agg/<sweep>/` 的聚合 JSON + `results/figures/` 的图。

> **为什么必须等符号修复**：`starlink_sim/analytics/stats.py` 的配对 rank-biserial 曾把符号算反（攻击臂 vs 基线臂的方向倒置），修复在 commit `89c6dcb`。**在此之前跑聚合，所有效应量的符号都是错的**，且错得很隐蔽（绝对值看起来合理）。

### 7.3 结果解读口径（**违反会得出反向结论**）

1. **跨壳只能用「壳内配对 → 横向制表」**。`shell` 是匹配键四字段之一，`compare_attack_vs_baseline` 跨壳必然抛 `TrialsCardinalityError`。正确做法：每个壳内部算 `bh3_<shell>` vs `base_<shell>` 的效应量/中位差，再把四壳的结果并排成一张表。
2. **`avg_hops` / `avg_latency_ms` 有严重幸存者偏差**。强攻击臂下只有极短的流能成功送达，长路径流全部失败被排除在均值之外 → 均值**反而变小**。必须与 `delivery_ratio` / `num_success` **联读**，绝不能单独解读为「性能变好」。`data_stats` 里另有 `avg_success_hops` / `avg_success_latency_ms`，语义更显式（仅成功流），但同样带偏差。
3. **效应量用带符号 rank-biserial，且必须与 p 值联读**。Wilcoxon n=10 的**双侧最小 p = 0.001953**（= 2/2¹⁰），p 触底只说明「10 对全部同向」，**不代表效应大**。反之 p 不显著也可能是效应量大但方向不一致。
4. **`nl=1024` 档的四壳不等价**（见 §10）。跨壳横向对比请用 `nl=256` 主口径。
5. **`nl=2048` 不是 `nl=1024` 的延伸**，是独立观测点（见 §10）。规模律曲线只在 `48→96→256→512→1024` 五档上单调合法。
6. **任何臂失败/被跳过/结果异常都要如实列出**，不得静默丢弃；某壳数据不可用就标注不可用，不要硬凑。

---

## 8. 对上游指令的实测纠正（照做前看这里）

| # | 流传的说法 | 实测事实 |
|---|---|---|
| 1 | 「PowerShell 重定向下日志为空」 | 属实。根因是块缓冲；父进程可用 `python -u` 缓解，**worker 输出仍缓冲**。→ 用 raw 计数监测（§5.1） |
| 2 | `run_step3_matrix.py --only X --dry-run` | **该参数不存在**，实测报 `error: unrecognized arguments: --dry-run`。dry-run 只能用 `run_experiment_sweep.py --sweep-config ... --dry-run` |
| 3 | 「dry-run 也会加载 pkl，一次只验一个」 | **不加载**。`_dry_run` 只校验配置/任务矩阵/攻击窗口。四个可连续跑，内存开销可忽略 |
| 4 | 「执行全部 300 任务」 | 本轮 4 个 sweep 实为 **280** 任务（100+80+80+20）。630 − 350 已有 = 280 |
| 5 | 「`--only A B C` 按给定顺序跑」 | **不是**。`--only` 只做集合筛选，实际顺序恒为 `ORDER` 常量顺序 |
| 6 | 「`--skip-existing` 可续跑缺失任务」 | **sweep 粒度**全有/全无，缺 1 个就整 sweep 重跑（重跑无损，见 §6.2） |
| 7 | 「`pytest -q tests` 279 passed」 | 实测 **286 passed**（stats.py 符号修复附带了新测试） |
| 8 | 「`_matrix_summary.json` 是累积记录」 | **每次 matrix 调用都 `"w"` 覆盖**，只含本次的 runs。→ 用 `--log-dir` 隔离（§2.1） |

---

## 9. 本轮实跑记录

（跑完后填写；`--log-dir` 隔离在 `results\step3_logs\task12\`）

| sweep | 任务 | workers | 启动 UTC | 墙钟 | exit | raw_found |
|---|---|---|---|---|---|---|
| `e5a_scale_small` | 100 | 10 | — | — | — | — |
| `shell256` | 80 | 8 | — | — | — | — |
| `shell1024` | 80 | 8 | — | — | — | — |
| `e5a_scale_top` | 20 | 2 | — | — | — | — |

权威来源：`results\step3_logs\task12\_matrix_summary.json`。

---

## 10. 跨壳/规模口径的设计依据（实测数据，改配置前必读）

数据来源：`tools/probe_shell_scale_equivalence.py`（只读探测器，走生产路径 `starlink_sim.topology.subset`），
证据 JSON：`results/step3_logs/shell_scale_equivalence.json`、`results/step3_logs/shell_scale_equivalence_stablecore_53.json`。
探测峰值 RSS **1.226 GB**（逐壳 `pop` + `gc.collect()`，合规 ≤4 GB）。

### 10.1 四壳基础事实

| 壳 | pkl 节点数 | summary 卫星数 | epochs | strict core GCC | core frac |
|---|---|---|---|---|---|
| 53° | 4284 | 4284 | 121 | **1064** | 1.0 |
| 70° | 702 | 702 | 121 | **380** | 1.0 |
| 97.5° | 1075 | 1076 | 121 | **287** | 1.0 |
| 43° | 3262 | 3262 | 121 | **3249** | 1.0 |

（97.5° 差 1：该壳有 1 颗卫星在全部 121 epoch 中度数为 0，见 `topology_summary.json` 的 `"0": 1`。）

### 10.2 e3 runner 只触达前 2 个 epoch（**关键口径**）

`scripts/run_e3_blackhole_experiment.py`：
```python
last_epoch_idx = int(duration / epoch_duration) - 1        # 60 // 30 - 1 = 1
num_eval_epochs = max(1, min(last_epoch_idx + 1, len(edges_by_epoch)))
eval_edges = edges_by_epoch[start_epoch_idx:last_epoch_idx+1]   # = edges_by_epoch[0:2]
```
配合 `simulator.run_ticks`（`epoch_idx = int(current_time / epoch_duration)`，num_ticks=300）→ **pkl 的 121 个 epoch 中只有前 2 个进入仿真**，其余 119 个只用于子集选择与攻击者布点。

因此连通性必须**双口径**度量：
- `all121`：子集选择器的设计保证（`select_connected_subset` 对全 121 epoch）；
- `evalwin`：**真正影响 `delivery_ratio` 的那 2 个 epoch**。

两者可能背离，且背离方向不固定 —— 见 97.5° 的 nl=512 vs nl=1024。

### 10.3 nl=1024 档四壳判定（`cumulative_degree`）

| 壳 | 节点数 | strict core GCC | nl=1024 实际子集 | inside_core | all121 min/mean | **evalwin min/mean** | 判定 |
|---|---|---|---|---|---|---|---|
| 53° | 4284 | 1064 | 1024 | 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | ✅ 有效 |
| 43° | 3262 | 3249 | 1024 | 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | ✅ 有效 |
| 70° | 702 | 380 | **702（全量退化）** | 0.541 | 1.000 / 1.000 | 1.000 / 1.000 | ⚠️ 规模不等价 |
| 97.5° | 1075 | 287 | 1024 | **0.280** | **0.280 / 0.615** | **0.634 / 0.669** | ❌ 碎裂，不可用 |

- **70°**：`select_connected_subset` 在 `target_size >= len(nodes)` 时提前返回全量 702 → `node_limit` 名义 1024、实际 702。但连通比 **min=mean=1.000（双口径均是）** → **壳内配对完全合法**，降级性质是「规模不等价」而非「碎裂」。附带混杂因子：攻击者相对密度 3/702=**0.43%** vs 53° 的 3/1024=**0.29%**。
- **97.5°**：`inside_core` 仅 287/1024=0.280，evalwin 内连通比 min=**0.634** → 评估窗口里就有 1/3 以上时刻子集不连通，`delivery_ratio` 被拓扑碎裂污染，**无法归因于攻击**。此档数据只能标注为不可用。
- **不能折中到 512**：97.5° nl=512 的 evalwin min=**0.377** < nl=1024 的 0.634（**非单调**！）。512 档比 1024 档更碎，没有出路。

### 10.4 主口径 = nl=256

四壳 strict core GCC 的最小值 = **287**（97.5°）→ 能保证全部四壳都落在严格核内（`core_frac=1.0`、`inside_core=1.000`、双口径连通比 1.000/1.000）的最大 2 的幂 = **256**。

实测满足档位：**48 / 96 / 256**（四壳全部 OK）。
`max_common_nl_all_epochs = max_common_nl_eval_window = 256`。

额外优势：nl=256 时四壳**攻击者相对密度相同**（3/256 = 1.17%），nl=1024 时不同（0.29% vs 0.43%）→ 跨壳效应量可比性更强。

**残留混杂（必须写进结论的局限）**：nl=256 时四壳的诱导子图**平均度不同** —— 70°=4.820、97.5°=5.125、53°=3.359、43°=2.672。「同规模」≠「同密度」，壳间效应量差异中混杂了密度差异，无法在本轮设计内分离。

### 10.5 nl=2048 是独立观测点，**不是** 1024 的延伸

53° 壳，`cumulative_degree`，nl=2048 vs 更小档的子集重叠（实测）：

| 对比 | 交集 | 较小档包含率 | Jaccard | 嵌套？ |
|---|---|---|---|---|
| 2048 ∩ 1024 | **70** | 70/1024 = **6.8%** | 0.023 | ❌ |
| 2048 ∩ 512 | 69 | 69/512 = 13.5% | 0.028 | ❌ |
| 2048 ∩ 256 | 69 | 69/256 = 27.0% | 0.031 | ❌ |
| 2048 ∩ 96 | 69 | 69/96 = 71.9% | 0.033 | ❌ |
| 2048 ∩ 48 | 48 | 48/48 = 100% | — | ✅ |

nl=2048 子集内属于 strict core 的比例仅 **3.4%**；`core_frac` 被放宽到 **0.35**；evalwin 平均度从 nl=1024 的 **5.726 掉到 5.392**（**非单调**）。

**根因**：`persistent_core(edges, 2048)` 因 strict GCC=1064 < 2048，被迫沿 `_FRAC_LADDER` 放宽到 `frac=0.35` 才凑够 2048；随后 `_connected_greedy` 在这个大得多的核里**从全局最高累计度节点重新起生长**，落到了另一片节点群。

→ **E5-a 规模律只在 `48→96→256→512→1024` 五档上是合法的单调曲线；2048 档只能作为「另一种拓扑采样下的独立观测点」报告，不得画进同一条规模律拟合。**

对照实验（`stable_core` 方法，53° nl=2048）：`core_frac=0.35`、`inside_core=1.0%`、`all121 min=0.901`、**`evalwin min=0.991 < 1.000`**、与 nl=1024 仅重叠 19/1024 → **比 `cumulative_degree` 更差**。故维持 `cumulative_degree` 不变（同时也保证与已完成的 350 个 raw 同口径）。

### 10.6 五档规模阶梯的完整连通性（53°，`cumulative_degree`）

| nl | 子集大小 | core_frac | inside_core | all121 min/mean | evalwin min/mean | evalwin 平均度 |
|---|---|---|---|---|---|---|
| 48 | 48 | 1.0 | 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 2.875 |
| 96 | 96 | 1.0 | 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 2.875 |
| 256 | 256 | 1.0 | 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 3.359 |
| 512 | 512 | 1.0 | 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 4.457 |
| 1024 | 1024 | 1.0 | 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | **5.726** |
| 2048 | 2048 | **0.35** | **0.034** | 0.996 / 0.999 | 1.000 / 1.000 | **5.392** |

→ 五档（48..1024）连通性完美且**嵌套**；平均度**单调上升** 2.875→5.726，这是规模律解读时的第二个混杂变量（大规模档不仅节点多，还更稠密、路径更短）。

---

## 11. 遗留问题（超出 Task #12 权限，需上游决策）

1. **`select_connected_subset` 需支持「固定种子 + 单调生长」**才能让 nl=2048 档嵌套于 nl=1024 档。当前实现每次都从全局最高分节点重新起生长，核放宽后落点漂移。修改位置 `starlink_sim/topology/subset.py`，**不在本任务可编辑清单内**（本任务只能改 `configs/experiments/step3/*shell*` 与 `*e5a*` YAML）。建议方案：缓存上一档的选中集合作为下一档的生长起点（真正的 nested ladder）。
2. **臂配置共享**：`a_base_53_1024.yaml` / `a_bh3_53_1024.yaml` 被 **6 个 sweep** 共用（`e4_sybil` / `e5_placement` / `e5_intensity` / `e7_combo` / `shell1024` / `e5a_scale_small`）。改这两个文件的任何**行为字段**都会破坏已完成 350 个 raw 的可比性。本轮只给 6 个**单 sweep 独占**的臂配置（`a_{base,bh3}_{70,975}_1024.yaml`、`a_{base,bh3}_53_2048.yaml`）加了注释横幅，**零行为字段改动**。
3. **YAML 已与生成器发散**：`scripts/gen_step3_configs.py` 是配置的单一事实源，但**不在本任务可编辑清单内**。本轮所有 YAML 改动都是**纯注释**，故重新运行生成器会**抹掉这些注释**（行为字段不受影响）。已在每个改过的头注里写明这一点。
4. **`num_eval_epochs=2`**：只有 2 个拓扑快照、40 trials/seed（20 flows × 2 epochs），**无法观察时序演化**，也无法把「攻击生效延迟」与「拓扑变化」分离。若要研究时序，需提高 `duration` 或降低 `epoch_interval`，但那会改变匹配键、破坏与已有 350 个 raw 的可比性。

---

## 12. 快速检查清单

开跑前：
- [ ] §1 四条门禁全绿（贴出实测值）
- [ ] §3 四个 dry-run 全 exit=0，核对项无偏离
- [ ] FreeRAM ≥ 20 GB
- [ ] `--log-dir` 已指向隔离目录
- [ ] `python -u` 已加

跑中：
- [ ] §5.1 raw 计数每 5 min 递增
- [ ] §5.2 FreeRAM 未跌破 1.5 GB

跑完：
- [ ] `verify_step3_raw.py` → ALL GREEN，630/630
- [ ] `_matrix_summary.json` 中 4 个 exit_code 全 0，`n_raw_found == n_tasks`
- [ ] §7.2 聚合
- [ ] §7.3 六条解读口径逐条自检
- [ ] 失败/异常臂如实列出，不静默丢弃
