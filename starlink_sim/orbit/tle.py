# starlink_sim/orbit/tle.py
import re
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any
import numpy as np
from sgp4.api import Satrec
from sgp4.api import SGP4_ERRORS

@dataclass
class TleRecord:
    name: str
    line1: str
    line2: str
    satrec: Satrec
    catalog_number: int
    classification: str
    launch_year: int
    launch_number: int
    piece: str
    epoch_year: int
    epoch_day: float
    inclination: float       # degrees
    raan: float              # degrees
    eccentricity: float
    arg_perigee: float       # degrees
    mean_anomaly: float      # degrees
    mean_motion: float       # rev/day
    bstar: float
    # 以下字段在解析后计算
    altitude_km: Optional[float] = None
    shell: Optional[str] = None
    epoch_datetime: Optional[str] = None
    off_lattice: bool = False

def parse_tle_file(filepath: Path) -> Dict[str, Any]:
    """
    读取 TLE 文件，逐条解析，返回包含卫星记录列表和统计信息的字典。
    对每条记录，使用 sgp4.api.Satrec.twoline2rv 构建 Satrec 对象。
    """
    lines = filepath.read_text(encoding='utf-8').splitlines()
    records = []
    errors = []
    i = 0
    while i < len(lines) - 2:
        name = lines[i].strip()
        line1 = lines[i+1].strip()
        line2 = lines[i+2].strip()
        # 基本格式校验：行首和长度
        if not (line1.startswith('1 ') and line2.startswith('2 ') and len(line1) == 69 and len(line2) == 69):
            errors.append(f"Invalid format at line {i+1}")
            i += 3
            continue
        try:
            satrec = Satrec.twoline2rv(line1, line2)
            # 提取基本字段（按 TLE 规范）
            catalog = int(line1[2:7])
            classification = line1[7]
            launch_year = int(line1[9:11]) + 1900 if int(line1[9:11]) >= 57 else int(line1[9:11]) + 2000
            launch_num = int(line1[11:14])
            piece = line1[14:17].strip()
            epoch_year = int(line1[18:20]) + 2000  # 注意：需要根据实际情况调整（两位年份）
            epoch_day = float(line1[20:32])
            # 轨道根数
            inclination = float(line2[8:16])   # deg
            raan = float(line2[17:25])         # deg
            eccentricity = float('0.' + line2[26:33])  # 小数
            arg_perigee = float(line2[34:42])  # deg
            mean_anomaly = float(line2[43:51]) # deg
            mean_motion = float(line2[52:63])  # rev/day
            bstar = float(line1[53:59]) * 10 ** int(line1[59:61])  # 带指数

            records.append(TleRecord(
                name=name, line1=line1, line2=line2, satrec=satrec,
                catalog_number=catalog, classification=classification,
                launch_year=launch_year, launch_number=launch_num, piece=piece,
                epoch_year=epoch_year, epoch_day=epoch_day,
                inclination=inclination, raan=raan, eccentricity=eccentricity,
                arg_perigee=arg_perigee, mean_anomaly=mean_anomaly,
                mean_motion=mean_motion, bstar=bstar
            ))
        except Exception as e:
            errors.append(f"Parsing error for {name}: {e}")
        i += 3

    return {
        'records': records,
        'errors': errors,
        'total_lines': len(lines),
        'parsed_count': len(records),
        'error_count': len(errors)
    }

def filter_altitude(records: List[TleRecord], min_alt_km: float = 380.0) -> List[TleRecord]:
    """
    使用 SGP4 传播到卫星自身历元时刻，计算海拔高度，过滤掉低于阈值者。
    """
    filtered = []
    for rec in records:
        # 使用 satrec 自带的历元儒略日
        jd = rec.satrec.jdsatepoch
        fr = rec.satrec.jdsatepochF
        error_code, r, _ = rec.satrec.sgp4(jd, fr)
        if error_code == 0:
            alt = np.linalg.norm(r) - 6371.0   # 地球平均半径 km
            rec.altitude_km = alt
            if alt >= min_alt_km:
                filtered.append(rec)
        else:
            rec.altitude_km = None
            # 可根据需要记录错误，此处静默跳过
    return filtered

# 将来可扩展计算RAAN(t0)等