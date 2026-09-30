# scripts/build_lattice.py
import sys
from pathlib import Path
import pickle
import json
import numpy as np
sys.path.append(str(Path(__file__).parent.parent))
from starlink_sim.orbit.shells import classify_satellites
from starlink_sim.orbit.lattice import fit_planes_for_shell

def main():
    # 加载过滤后的记录
    with open(Path("data/tle/filtered_records.pkl"), 'rb') as f:
        records = pickle.load(f)

    # 分类壳层
    classified = classify_satellites(records)
    print(f"Classified {len(classified)} satellites into shells.")

    # 按壳层分组
    shells = {}
    for rec in classified:
        shell = rec['shell']
        shells.setdefault(shell, []).append(rec)

    # 定义公共历元 t0（由 PLAN 给出：2026-08-22 10:13:50 UTC）
    # 计算儒略日
    from sgp4.api import jday
    t0_jd, t0_fr = jday(2026, 8, 22, 10, 13, 50)

    # 对每个壳层进行格点拟合
    lattice_results = {}
    for shell_name, recs in shells.items():
        P, phi, updated_recs = fit_planes_for_shell(recs, shell_name, t0_jd, t0_fr)
        lattice_results[shell_name] = {
            'P': P,
            'phi': phi,
            'records': updated_recs
        }

    # 保存结果
    output_dir = Path("data/lattice")
    output_dir.mkdir(parents=True, exist_ok=True)
    # 保存为 pickle
    with open(output_dir / "lattice_result.pkl", 'wb') as f:
        pickle.dump(lattice_results, f)

    # 保存摘要 JSON
    summary = {}
    for shell, data in lattice_results.items():
        recs = data['records']
        total = len(recs)
        off_lattice = sum(1 for r in recs if r.get('off_lattice', False))
        summary[shell] = {
            'P': data['P'],
            'phi': data['phi'],
            'total_satellites': total,
            'off_lattice': off_lattice,
            'off_lattice_ratio': off_lattice / total if total > 0 else 0
        }
    with open(output_dir / "lattice_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)

    print("Lattice fitting completed. Results saved to data/lattice/")

if __name__ == "__main__":
    main()