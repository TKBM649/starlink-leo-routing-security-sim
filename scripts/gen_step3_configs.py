# -*- coding: utf-8 -*-
"""
scripts/gen_step3_configs.py
生成 **step3 / Phase 1 攻击矩阵（B 档）** 的全部臂配置与 sweep 规格。

为什么用生成器而不是手写 60 个 YAML
----------------------------------
step3 需要在统一口径下跑 9 个 sweep、约 50 个臂配置。手写极易出现「匹配键不一致」
（shell / node_limit / num_eval_epochs / num_flows 四元组任一不同即触发
``TrialsCardinalityError``）。本脚本把口径写成**单一事实源**：所有臂共用同一模板，
仅 node_limit / shell / attackers 三处可变，从构造上保证同 sweep 内匹配键对齐。
脚本幂等（重跑覆盖同名文件），可 review、可复现。

B 档口径（用户 2026-09-30 确认，不得自行更改）
--------------------------------------------
- ``topology.node_limit = 1024``（53° 壳持久核 GCC=1064 → 逐 epoch 连通比恒 1.000）
- ``seeds = 42..51``（10 个）
- ``traffic.num_flows = 20``、``experiment.duration = 60``（→ num_eval_epochs=2，
  total_trials = 20 × 2 × 1 = 40/seed）
- ``n_boot = 4000``（≥ 用户硬要求的 2000）
- 例外：E5-a 规模阶梯本身就变 node_limit（每档自带同档基线）；壳层对比在 nl=256
  与 nl=1024 两处跑（97.5° 壳 nl=1024 属**降级档**，见 sweep_shell1024 头部说明）。

并行度依据（实测，31.7GB 总内存 / 23.6GB 可用 / 24 逻辑核）
----------------------------------------------------------
内存而非 CPU 是约束：

=========================  ============  ===========================
场景                        峰值 RSS/worker  依据
=========================  ============  ===========================
4 壳 pkl 反序列化（未剔壳）  ~1.13GB       实测
仅留 53° 壳（剔壳后）        ~0.55GB       实测 → _init_worker 的 keep_shells
nl=1024 单任务（剔壳）       ~1.62GB       2.22GB − (1.13−0.55)GB
nl=1024 单任务（未剔壳）     ~2.22GB       实测
nl=2048 单任务（顶档）       ~4GB（推算）  500B·N² + 100B·N²·epochs 模型外推
nl=4284 全量单任务           **≥20.7GB**   实测；2 epochs 跑 462s CPU 仍未结束 → 强制终止
=========================  =============  ===========================

故：单壳 sweep 取 10 worker（~16.2GB）、四壳 sweep 取 8 worker（~17.6GB）、
顶档 nl=2048 取 2 worker（~8GB）。**原计划的 4284 全量档已从矩阵中移除**
（实测内存不可行，根因与降级证据见 sweep_e5a_scale_top.yaml 头部）。
用户原建议 W=20 是按 CPU 核数给的；实测内存约束下 W=20 会直接 OOM，故降至 10。

用法::

    python scripts/gen_step3_configs.py            # 生成到 configs/experiments/step3/
    python scripts/gen_step3_configs.py --list      # 仅列出将生成的 sweep 与臂数
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).parent.parent
OUT_DIR = PROJECT_ROOT / "configs" / "experiments" / "step3"

# ==================== B 档统一口径（单一事实源）====================
SEEDS: List[int] = list(range(42, 52))          # 42..51，共 10 个
NUM_FLOWS: int = 20
DURATION: int = 60                              # → num_eval_epochs = 2
EPOCH_INTERVAL: int = 30
N_BOOT: int = 4000
ALPHA: float = 0.05
NL_MAIN: int = 1024                             # B 档主规模
WORKERS_MAIN: int = 10                          # 单壳 sweep（仅 53°）：剔除无关壳后 ~1.62GB/worker
WORKERS_SHELL: int = 8                          # 四壳 sweep：无法剔壳，基线 ~1.13GB/worker
NL_TOP: int = 2048                              # E5-a 顶档（4284 实测内存不可行 → 降级）
WORKERS_TOP: int = 2                            # nl=2048 顶档：单任务 ~4GB，2 worker ~8GB

RAW_ROOT = "results/step3_raw"
AGG_ROOT = "results/step3_agg"

SHELLS: Tuple[str, ...] = ("53°", "70°", "97.5°", "43°")
# 文件名/label 用的 ASCII 壳名（避免非 ASCII 进入路径）
SHELL_TAG = {"53°": "53", "70°": "70", "97.5°": "975", "43°": "43"}

# E6 虫洞检测参数（四臂逐字一致，保证 det_rate / fp_rate 同口径可比）
WORMHOLE_DETECTION: Dict[str, Any] = {
    "enabled": True,
    "max_isl_km": 2000.0,
    "distance_factor": 1.5,
    "adaptive_factor": 3.0,
    "latency_factor": 1.0,
}


# ==================== 攻击者构造速记 ====================

def blackhole(count: int = 3, placement: str = "degree",
              drop_prob: float = 0.8, metric_fake: int = 0) -> Dict[str, Any]:
    return {"type": "blackhole", "count": count, "placement": placement,
            "params": {"drop_prob": drop_prob, "metric_fake": metric_fake}}


def jamming(count: int = 3, placement: str = "degree",
            jamming_ratio: float = 0.3, inf_metric: int = 9999) -> Dict[str, Any]:
    return {"type": "jamming", "count": count, "placement": placement,
            "params": {"jamming_ratio": jamming_ratio, "inf_metric": inf_metric}}


def sybil(num_identities: int = 8, placement: str = "degree",
          attachment: str = "betweenness", seq_lead: int = 8,
          drop_prob: float = 0.0) -> Dict[str, Any]:
    return {"type": "sybil", "count": 1, "placement": placement,
            "params": {"num_identities": num_identities, "attachment": attachment,
                       "metric_fake": 0, "seq_lead": seq_lead,
                       "drop_prob": drop_prob, "controller_poisons": False}}


def wormhole(count: int = 1, poison_scope: str = "peer_only",
             endpoint_strategy: str = "farthest", placement: str = "degree",
             pool_size: int = 48) -> Dict[str, Any]:
    return {"type": "wormhole", "count": count, "placement": placement,
            "params": {"endpoint_strategy": endpoint_strategy,
                       "poison_scope": poison_scope, "metric_fake": 0,
                       "seq_lead": 8, "drop_prob": 0.0, "pool_size": pool_size}}


# ==================== YAML 渲染 ====================

def _scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if v == float("inf"):
            return ".inf"
        return repr(v)
    if isinstance(v, int):
        return str(v)
    if v is None:
        return "null"
    return '"%s"' % str(v).replace('"', '\\"')


def _attackers_block(attackers: Sequence[Dict[str, Any]]) -> str:
    if not attackers:
        return "attack:\n  attackers: []\n"
    out = ["attack:", "  attackers:"]
    for a in attackers:
        out.append(f'    - type: "{a["type"]}"')
        out.append(f"      count: {int(a.get('count', 1))}")
        out.append(f'      placement: "{a.get("placement", "degree")}"')
        out.append(f"      active_since: {_scalar(float(a.get('active_since', 0.0)))}")
        out.append("      active_until: .inf")   # 常驻：适配 e3 末窗口评估
        params = a.get("params") or {}
        if params:
            out.append("      params:")
            for k in sorted(params):
                out.append(f"        {k}: {_scalar(params[k])}")
    return "\n".join(out) + "\n"


ARM_TMPL = """\
# configs/experiments/step3/{fname}
# {desc}
#
# 本文件由 scripts/gen_step3_configs.py 生成 —— **请勿手工编辑**；
# 需改口径时改生成器后重跑该脚本（幂等覆盖）。
# 匹配键四元组 (shell, node_limit, num_eval_epochs, num_flows) = \
({shell}, {nl_disp}, 2, {num_flows})；total_trials = 40/seed。

experiment:
  name: "{name}"
  duration: {duration}
  seed: null

topology:
  shell: "{shell}"
  epoch_interval: {epoch_interval}
  node_limit: {nl}
  subset_method: "cumulative_degree"
  cache_path: "data/topology/topology_results.pkl"
  positions_cache: null

routing:
  t_adv: 2.0
  tick: 0.2
  max_hops: 100

traffic:
  num_flows: {num_flows}
{detection}
{attackers}
output:
  raw_dir: "{raw_root}/"
  agg_dir: "{agg_root}/"
  figures_dir: "results/figures/"
"""


def _detection_block(wormhole_det: bool) -> str:
    if not wormhole_det:
        return ""
    lines = ["", "# 与攻击臂逐字一致的检测参数（基线臂靠它度量**误报率**）。",
             "detection:", "  wormhole:"]
    for k in ("enabled", "max_isl_km", "distance_factor", "adaptive_factor",
              "latency_factor"):
        lines.append(f"    {k}: {_scalar(WORMHOLE_DETECTION[k])}")
    return "\n".join(lines) + "\n"


class ArmRegistry:
    """按 (shell, node_limit, attackers, detection) 去重的臂配置注册表。"""

    def __init__(self) -> None:
        self.files: Dict[str, str] = {}       # fname -> yaml text
        self.desc: Dict[str, str] = {}

    def add(self, fname: str, name: str, desc: str, shell: str = "53°",
            node_limit: Optional[int] = NL_MAIN,
            attackers: Sequence[Dict[str, Any]] = (),
            wormhole_det: bool = False,
            num_flows: int = NUM_FLOWS, duration: int = DURATION) -> str:
        if fname in self.files:
            return fname
        nl_disp = "null(全量4284)" if node_limit is None else str(node_limit)
        text = ARM_TMPL.format(
            fname=fname, desc=desc, shell=shell, nl_disp=nl_disp,
            nl="null" if node_limit is None else node_limit,
            num_flows=num_flows, duration=duration,
            epoch_interval=EPOCH_INTERVAL, name=name,
            detection=_detection_block(wormhole_det),
            attackers=_attackers_block(attackers),
            raw_root=RAW_ROOT, agg_root=AGG_ROOT)
        self.files[fname] = text
        self.desc[fname] = desc
        return fname


SWEEP_TMPL = """\
# configs/experiments/step3/sweep_{key}.yaml
# {title}
#
# {note}
#
# 本文件由 scripts/gen_step3_configs.py 生成 —— 请勿手工编辑。
# 任务数 = {n_arms} 臂 × {n_seeds} seeds = {n_tasks}。
#
# 运行（先 dry-run 核对臂数/匹配键/注入预览，再实跑）::
#
#   python scripts/run_experiment_sweep.py --sweep-config \
#       configs/experiments/step3/sweep_{key}.yaml --dry-run
#   python scripts/run_experiment_sweep.py --sweep-config \
#       configs/experiments/step3/sweep_{key}.yaml

sweep:
  name: "{key}"
  runner: "e3"
  seeds: [{seeds}]
  workers: {workers}
  raw_dir: "{raw_root}/{key}/"
  agg_dir: "{agg_root}/{key}/"
  subset_method: "cumulative_degree"
  strict_window: false
  non_strict: false
  alpha: {alpha}
  n_boot: {n_boot}
  arms:
{arms}
  comparison:
    attack: "{cmp_atk}"
    baseline: "{cmp_base}"
"""


def _sweep_text(key: str, title: str, note: str, arms: Sequence[Tuple[str, str]],
                comparison: Tuple[str, str], workers: int = WORKERS_MAIN) -> str:
    arm_lines = "\n".join(
        f'    - label: "{label}"\n      config: "configs/experiments/step3/{fname}"'
        for label, fname in arms)
    return SWEEP_TMPL.format(
        key=key, title=title, note=note, n_arms=len(arms), n_seeds=len(SEEDS),
        n_tasks=len(arms) * len(SEEDS), seeds=", ".join(str(s) for s in SEEDS),
        workers=workers, raw_root=RAW_ROOT, agg_root=AGG_ROOT, alpha=ALPHA,
        n_boot=N_BOOT, arms=arm_lines, cmp_atk=comparison[0],
        cmp_base=comparison[1])


# ==================== sweep 定义 ====================

def build() -> Tuple[ArmRegistry, List[Tuple[str, str]]]:
    R = ArmRegistry()
    sweeps: List[Tuple[str, str]] = []

    def base_arm(shell: str, nl: Optional[int], wormhole_det: bool = False) -> str:
        tag = SHELL_TAG[shell]
        nlt = "full" if nl is None else str(nl)
        suffix = "_whdet" if wormhole_det else ""
        return R.add(
            fname=f"a_base_{tag}_{nlt}{suffix}.yaml",
            name=f"s3_base_{tag}_{nlt}{suffix}",
            desc=(f"无攻击基线臂（shell={shell}, node_limit={nl}"
                  f"{', 虫洞检测开启以度量误报率' if wormhole_det else ''}）。"),
            shell=shell, node_limit=nl, attackers=(), wormhole_det=wormhole_det)

    def bh3_arm(shell: str, nl: Optional[int]) -> str:
        tag = SHELL_TAG[shell]
        nlt = "full" if nl is None else str(nl)
        return R.add(
            fname=f"a_bh3_{tag}_{nlt}.yaml",
            name=f"s3_bh3_{tag}_{nlt}",
            desc=(f"黑洞攻击臂：3 个攻击者、degree 放置、drop_prob=0.8、metric_fake=0"
                  f"（shell={shell}, node_limit={nl}）。"),
            shell=shell, node_limit=nl, attackers=[blackhole(3, "degree", 0.8)])

    # ---------- 1) E4 Sybil 身份数梯度 ----------
    e4_arms = [("base", base_arm("53°", NL_MAIN))]
    for n in (1, 2, 4, 8, 16, 32):
        e4_arms.append((f"ids{n}", R.add(
            fname=f"a_ids{n}_53_1024.yaml", name=f"s3_ids{n}_53_1024",
            desc=(f"E4 Sybil 身份数梯度臂：1 个被劫持物理节点对外呈现 {n} 个虚假身份"
                  f"（attachment=betweenness, seq_lead=8, drop_prob=0）。"
                  f"nl=96 小拓扑上该梯度已饱和，nl=1024 需重新验证可分辨性。"),
            attackers=[sybil(n)])))
    sweeps.append(("e4_sybil", _sweep_text(
        "e4_sybil",
        "E4 Sybil：虚假身份数梯度（1/2/4/8/16/32）vs 无攻击基线 —— B 档 nl=1024",
        "梯度可分辨性是本轮重点：nl=96 时身份数梯度已饱和（牵引率不再随身份数上升），\n"
        "# nl=1024（真实节点 1024，虚假身份最多 32 = 3.1%）需重新判定饱和点。\n"
        "# comparison 字段只支持一对，其余配对（ids1..ids32 两两 / 各自 vs base）由\n"
        "# scripts/aggregate_step3.py 从 raw JSON 统一补齐。",
        e4_arms, ("ids8", "base"))))

    # ---------- 2) E5 放置策略对比 ----------
    e5p_arms = [("base", base_arm("53°", NL_MAIN)),
                ("degree", bh3_arm("53°", NL_MAIN))]
    for strat, tag in (("random", "rnd"), ("betweenness", "btw"),
                       ("k_core", "kcore"), ("last_epoch_degree", "led")):
        e5p_arms.append((tag, R.add(
            fname=f"a_bh3pl_{tag}_53_1024.yaml", name=f"s3_bh3pl_{tag}_53_1024",
            desc=(f"E5 放置策略对比臂：blackhole×3、placement={strat}、drop_prob=0.8。"
                  f"与 degree 臂仅 placement 不同 → 严格可比。"),
            attackers=[blackhole(3, strat, 0.8)])))
    sweeps.append(("e5_placement", _sweep_text(
        "e5_placement",
        "E5 攻击者放置策略对比（degree/random/betweenness/k_core/last_epoch_degree）",
        "五策略同一攻击强度（blackhole×3, drop_prob=0.8）→ 差异纯归因于**布点**。\n"
        "# betweenness / k_core 用 networkx 聚合图计算，tie-break 确定性（小 id 优先）。",
        e5p_arms, ("degree", "base"))))

    # ---------- 3) E5 强度梯度（数量 × 丢包率）----------
    e5i_arms = [("base", base_arm("53°", NL_MAIN)),
                ("c3", bh3_arm("53°", NL_MAIN))]
    for c in (1, 6, 12, 24):
        e5i_arms.append((f"c{c}", R.add(
            fname=f"a_bhc{c}_53_1024.yaml", name=f"s3_bhc{c}_53_1024",
            desc=(f"E5 攻击者**数量**梯度臂：blackhole×{c}、degree、drop_prob=0.8。"),
            attackers=[blackhole(c, "degree", 0.8)])))
    for pct, p in ((0, 0.0), (20, 0.2), (50, 0.5), (100, 1.0)):
        e5i_arms.append((f"p{pct:02d}", R.add(
            fname=f"a_bhp{pct:02d}_53_1024.yaml", name=f"s3_bhp{pct:02d}_53_1024",
            desc=(f"E5 **丢包率**梯度臂：blackhole×3、degree、drop_prob={p}"
                  f"（drop_prob=0.8 档即 c3 臂，不重复生成）。"),
            attackers=[blackhole(3, "degree", p)])))
    sweeps.append(("e5_intensity", _sweep_text(
        "e5_intensity",
        "E5 攻击强度梯度：攻击者数量 1/3/6/12/24 × 丢包率 0/0.2/0.5/0.8/1.0",
        "两条正交梯度共用 c3 臂（count=3 且 drop_prob=0.8）作为交点，避免重复计算。\n"
        "# 数量梯度检验「攻击者数 → 送达率」是否线性；丢包率梯度检验数据面破坏的剂量效应。",
        e5i_arms, ("c12", "base"))))

    # ---------- 4) E6 Wormhole ----------
    e6_arms = [("base_det", base_arm("53°", NL_MAIN, wormhole_det=True))]
    for label, cnt, scope, extra in (
            ("t1", 1, "peer_only", "1 条隧道，仅毒化对端（健全捷径）"),
            ("t3", 3, "peer_only", "3 条隧道，仅毒化对端"),
            ("extreme", 3, "peer_side", "3 条隧道，毒化经对端的**全部**路由（破坏性）")):
        e6_arms.append((label, R.add(
            fname=f"a_wh_{label}_53_1024.yaml", name=f"s3_wh_{label}_53_1024",
            desc=(f"E6 Wormhole 攻击臂：{extra}。endpoint_strategy=farthest、"
                  f"seq_lead=8、drop_prob=0（虫洞不丢包，效果体现为路径牵引）。"),
            attackers=[wormhole(cnt, scope)], wormhole_det=True)))
    sweeps.append(("e6_wormhole", _sweep_text(
        "e6_wormhole",
        "E6 Wormhole：隧道数 1/3 + peer_only/peer_side 极端臂 vs 检测基线 —— nl=1024",
        "**诚实性前置声明**：shipped topology_results.pkl 的合法 ISL 未受距离上限约束\n"
        "# （plan item 0.7 记载 max_dist_km=99999 禁用了门限），实测 nl=1024 时\n"
        "# det_rate=1.0 但 **fp_rate=0.201** → 距离检测器在 shipped 数据上**不可分离**，\n"
        "# 结论为 inconclusive；E6 的**主信号**是攻击效果度量（attracted_ratio /\n"
        "# path_stretch / delivery_ratio 对比），严禁把 det_rate=1.0 单独包装成「检测有效」。",
        e6_arms, ("t3", "base_det"))))

    # ---------- 5) E7 组合攻击（超加性检验）----------
    BH3 = blackhole(3, "degree", 0.8)
    JM3 = jamming(3, "degree", 0.3)
    SY8 = sybil(8, "degree")
    e7_arms = [("base", base_arm("53°", NL_MAIN)),
               ("bh3", bh3_arm("53°", NL_MAIN)),
               ("jm3", R.add(fname="a_jm3_53_1024.yaml", name="s3_jm3_53_1024",
                             desc="E7 单攻击臂：jamming×3、degree、jamming_ratio=0.3。",
                             attackers=[JM3])),
               ("sy8", R.add(fname="a_sy8_53_1024.yaml", name="s3_sy8_53_1024",
                             desc="E7 单攻击臂：sybil×1（8 个虚假身份）、degree。",
                             attackers=[SY8]))]
    for label, combo, desc in (
            ("bh3_jm3", [BH3, JM3], "黑洞×3 + 干扰×3（同一批 degree top-3 节点，链式叠加）"),
            ("bh3_sy8", [BH3, SY8], "黑洞×3 + sybil 8 身份（数据面丢弃 + 控制面牵引）"),
            ("jm3_sy8", [JM3, SY8], "干扰×3 + sybil 8 身份（路由撤回 + 虚假身份牵引）"),
            ("bh3_jm3_sy8", [BH3, JM3, SY8], "三攻击协同：黑洞 + 干扰 + sybil")):
        e7_arms.append((label, R.add(
            fname=f"a_{label}_53_1024.yaml", name=f"s3_{label}_53_1024",
            desc=f"E7 组合攻击臂：{desc}。", attackers=combo)))
    sweeps.append(("e7_combo", _sweep_text(
        "e7_combo",
        "E7 组合攻击：3 个单攻击臂 + 4 个组合臂 + 基线 → 协同是否**超加性**",
        "超加性判据：Δ(combo) 与 Δ(A)+Δ(B) 的差（Δ = 攻击臂指标 − 基线指标，同 seed\n"
        "# 配对）。|Δ(combo)| 显著大于 |Δ(A)+Δ(B)| → 超加性；反之则为亚加性（互相遮蔽）。\n"
        "# 注意 instantiate_attackers **不跨配置去重**：degree 放置的黑洞与干扰会落在\n"
        "# **同一批** top-3 枢纽上（同节点链式叠加，T3 已验证生效），这是刻意设计。",
        e7_arms, ("bh3_jm3_sy8", "base"))))

    # ---------- 6) 壳层对比 nl=256（四壳均逐 epoch 全连通的公共规模）----------
    sh256_arms: List[Tuple[str, str]] = []
    for shell in SHELLS:
        tag = SHELL_TAG[shell]
        sh256_arms.append((f"base_{tag}", base_arm(shell, 256)))
        sh256_arms.append((f"bh3_{tag}", bh3_arm(shell, 256)))
    sweeps.append(("shell256", _sweep_text(
        "shell256",
        "壳层对比（nl=256）：53° / 70° / 97.5° / 43° 四壳同一攻击配置",
        "nl=256 是四壳**都能**保持逐 epoch 最大连通分量占比 = 1.000 的最大公共规模\n"
        "# （实测 97.5° 壳持久核 GCC 仅 287 → nl=256 是其可用上界附近）。\n"
        "# 跨壳不做 compare_attack_vs_baseline（shell 属匹配键，跨壳必然不可比）；\n"
        "# 跨壳对比口径 = 各壳**壳内**配对得到的效应量 / 中位差，再横向制表。",
        sh256_arms, ("bh3_53", "base_53"), workers=WORKERS_SHELL)))

    # ---------- 7) 壳层对比 nl=1024（含降级档）----------
    sh1k_arms: List[Tuple[str, str]] = []
    for shell in SHELLS:
        tag = SHELL_TAG[shell]
        sh1k_arms.append((f"base_{tag}", base_arm(shell, NL_MAIN)))
        sh1k_arms.append((f"bh3_{tag}", bh3_arm(shell, NL_MAIN)))
    sweeps.append(("shell1024", _sweep_text(
        "shell1024",
        "壳层对比（nl=1024）：53° / 43° 正常，70° / 97.5° 为**降级档**（如实记录）",
        "探测结果（生成器落盘前的一次性连通性探测，数据如下）：\n"
        "#   53°  总节点 4284，持久核 GCC=1064 → nl=1024 逐 epoch 连通比 min=mean=1.000 ✅\n"
        "#   43°  总节点 3262，持久核 GCC=3249 → nl=1024 连通比 min=mean=1.000        ✅\n"
        "#   70°  总节点仅 702 < 1024 → select_connected_subset 提前返回**全量 702**，\n"
        "#        metadata.node_limit 仍记配置值 1024 而 num_nodes=702（**降级：规模不等价**）⚠️\n"
        "#   97.5° 总节点 1075，持久核 GCC 仅 **287** → nl=1024 需用核外节点补齐，实测\n"
        "#        连通比 **min=0.280 / mean=0.615**（严重碎裂，**降级：非全连通档**）❌\n"
        "# 70°/97.5° 两档结果必须在报告中显式标注为降级，不得与 53°/43° 等量齐观。",
        sh1k_arms, ("bh3_43", "base_43"), workers=WORKERS_SHELL)))

    # ---------- 8) E5-a 规模阶梯（nl<=1024 五档）----------
    small_arms: List[Tuple[str, str]] = []
    for nl in (48, 96, 256, 512, 1024):
        small_arms.append((f"base_n{nl}", base_arm("53°", nl)))
        small_arms.append((f"bh3_n{nl}", bh3_arm("53°", nl)))
    sweeps.append(("e5a_scale_small", _sweep_text(
        "e5a_scale_small",
        "E5-a 规模阶梯（48/96/256/512/1024 五档，53° 壳，每档自带同档基线）",
        "规模律：同一攻击配置（blackhole×3, degree, drop_prob=0.8）在不同 node_limit 下\n"
        "# 的效应量随规模如何变化。**每档 node_limit 不同 → 匹配键不同 → 只能档内配对**，\n"
        "# 跨档比较用效应量（rank-biserial）与中位差，不用 p 值直接对比。\n"
        "# 4284 全量档**内存不可行**（见 sweep_e5a_scale_top.yaml 头注实测证据），顶档降为 2048。",
        small_arms, ("bh3_n1024", "base_n1024"))))

    # ---------- 9) E5-a 规模阶梯顶档（nl=2048；4284 档内存不可行，已降级）----------
    top_arms = [("base_n2048", base_arm("53°", NL_TOP)),
                ("bh3_n2048", bh3_arm("53°", NL_TOP))]
    sweeps.append(("e5a_scale_top", _sweep_text(
        "e5a_scale_top",
        "E5-a 规模阶梯顶档 —— node_limit=2048（53° 壳）",
        "**原计划的 4284 全量档在本机内存不可行，已如实降级为 2048。**\n"
        "# 实测证据（31.7GB 总 / 23.6GB 可用）：\n"
        "#   nl=4284 + blackhole×3 + 仅 2 epochs + 20 flows → 峰值 RSS **≥20.7GB @462s CPU\n"
        "#   仍未结束**，被强制终止（FreeRAM 一度跌至 4.5GB，逼近系统级 OOM）。\n"
        "#   nl=4284 + **无攻击**基线 + 2 epochs + 20 flows → WS **20.7GB @393s CPU** 同样未完成。\n"
        "# 根因（非攻击特有，是协议实现的固有标度）：\n"
        "#   routing_dv.RouteEntry 携带 path: List[int]（路径向量），且\n"
        "#   Simulator.run_ticks 每 epoch 存 routing_table_history[epoch]=get_routing_tables()\n"
        "#   （dict 浅拷贝，条目对象共享但 dict 槽位逐份新建）。\n"
        "#   → 常驻内存 ≈ 500B·N²（活路由表）+ ~100B·N²·epochs（历史快照）。\n"
        "#   N=4284, epochs=2 时 ≈ 9.1GB + 1.8GB，与实测 20.7GB 同量级（含报文缓冲）；\n"
        "#   N=4284, epochs=121 时仅历史项就 ≈ **222GB** → 物理不可行，与攻击无关。\n"
        "# 顶档改取 nl=2048：常驻 ≈ 2.1GB + 0.4GB（2 epochs）→ 单任务 ~4GB，workers=2 安全。\n"
        "# 六档规模阶梯因此为 48/96/256/512/1024/2048（档数不变，顶档下移）。",
        top_arms, ("bh3_n2048", "base_n2048"), workers=WORKERS_TOP)))

    return R, sweeps


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="生成 step3 攻击矩阵（B 档）全部配置")
    ap.add_argument("--list", action="store_true", help="仅列出 sweep 与臂数，不写文件")
    ap.add_argument("--out-dir", default=str(OUT_DIR))
    args = ap.parse_args(argv)

    reg, sweeps = build()
    out_dir = Path(args.out_dir)

    if args.list:
        for fname in sorted(reg.files):
            print(f"  arm  {fname}")
        total = 0
        for key, _text in sweeps:
            n = _text.count('- label:')
            total += n * len(SEEDS)
            print(f"  sweep {key:<18} arms={n:<3} tasks={n * len(SEEDS)}")
        print(f"TOTAL arm_files={len(reg.files)} sweeps={len(sweeps)} tasks={total}")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    for fname, text in reg.files.items():
        (out_dir / fname).write_text(text, encoding="utf-8", newline="\n")
    for key, text in sweeps:
        (out_dir / f"sweep_{key}.yaml").write_text(text, encoding="utf-8", newline="\n")

    total = sum(t.count("- label:") * len(SEEDS) for _k, t in sweeps)
    workers_of = {"shell256": WORKERS_SHELL, "shell1024": WORKERS_SHELL,
                  "e5a_scale_top": WORKERS_TOP}
    print(f"[gen_step3_configs] 写出 {len(reg.files)} 个臂配置 + {len(sweeps)} 个 sweep 到 {out_dir}")
    print(f"[gen_step3_configs] 总任务数 = {total}（seeds={SEEDS[0]}..{SEEDS[-1]}）")
    for key, text in sweeps:
        n = text.count("- label:")
        print(f"    sweep_{key:<18} arms={n:<3} tasks={n * len(SEEDS):<4} "
              f"workers={workers_of.get(key, WORKERS_MAIN)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
