import json
from pathlib import Path
import sys
import pickle
sys.path.append(str(Path(__file__).parent.parent))
from starlink_sim.orbit.tle import parse_tle_file, filter_altitude

def main():
    tle_path = Path("data/tle/starlink.tle")
    if not tle_path.exists():
        print("TLE file not found. Please copy it to data/tle/")
        sys.exit(1)
    
    # 解析
    result = parse_tle_file(tle_path)
    print(f"Parsed {result['parsed_count']} satellites, {result['error_count']} errors.")
    
    records = result['records']
    # 高度过滤
    filtered = filter_altitude(records, min_alt_km=380.0)
    print(f"After altitude filter (>=380km): {len(filtered)} satellites remain.")
    
    # 统计 bstar 标签
    bstar_neg = [r for r in filtered if r.bstar < 0]
    bstar_large = [r for r in filtered if r.bstar > 1e-3]
    print(f"bstar<0: {len(bstar_neg)}, bstar>1e-3: {len(bstar_large)}")
    
    # 保存报告
    report = {
        "source_sha256": "852E79A4D2EB28EE5864FC86BC204CB50DDE2FEE83F27A7F5B9D2356932FC97B",
        "total_parsed": result['parsed_count'],
        "error_count": result['error_count'],
        "altitude_filter_threshold_km": 380.0,
        "after_filter_count": len(filtered),
        "bstar_negative_count": len(bstar_neg),
        "bstar_large_count": len(bstar_large),
        "errors": result['errors'][:10]
    }
    report_path = Path("data/tle/filter_report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # 保存过滤后的卫星信息（可序列化，不含 Satrec）
    filtered_info = []
    for rec in filtered:
        filtered_info.append({
            'name': rec.name,
            'line1': rec.line1,
            'line2': rec.line2,
            'catalog_number': rec.catalog_number,
            'altitude_km': rec.altitude_km,
            'bstar': rec.bstar,
            'inclination': rec.inclination,
            'raan': rec.raan,
            'eccentricity': rec.eccentricity,
            'arg_perigee': rec.arg_perigee,
            'mean_anomaly': rec.mean_anomaly,
            'mean_motion': rec.mean_motion,
            'epoch_year': rec.epoch_year,
            'epoch_day': rec.epoch_day,
            'launch_year': rec.launch_year,
            'classification': rec.classification,
        })
    with open(Path("data/tle/filtered_records.pkl"), 'wb') as f:
        pickle.dump(filtered_info, f)
    
    print("Import completed. Report saved to data/tle/filter_report.json")

if __name__ == "__main__":
    main()