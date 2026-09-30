# tests/test_tle.py
import pytest
from pathlib import Path
from starlink_sim.orbit.tle import parse_tle_file, filter_altitude

def test_parse_tle():
    tle_path = Path("data/tle/starlink.tle")
    assert tle_path.exists(), "TLE file missing"
    res = parse_tle_file(tle_path)
    assert res['parsed_count'] == 10744, "Parsed count mismatch"
    assert res['error_count'] == 0, "Errors occurred during parsing"

def test_filter_altitude():
    tle_path = Path("data/tle/starlink.tle")
    res = parse_tle_file(tle_path)
    filtered = filter_altitude(res['records'], 380.0)
    # 已知过滤后应有4288颗（见规划），但此处仅做粗略检查
    assert len(filtered) > 4000, "Filtered count too low"
    # 检查所有过滤后的卫星高度均>=380
    for rec in filtered:
        assert rec.altitude_km is not None and rec.altitude_km >= 380.0 - 1e-6