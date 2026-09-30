# starlink_sim/orbit/shells.py
from typing import List, Tuple, Optional
import numpy as np

# 壳层定义： (倾角范围, 高度范围(km), 壳层名称)
SHELL_DEFS = [
    ( (40, 44), (440, 500), '43°' ),
    ( (43, 60), (440, 500), '53°' ),
    ( (90, 100), (440, 500), '97.5°' ),
    ( (65, 75), (520, 600), '70°' ),
]

def assign_shell(inclination: float, altitude: float) -> Optional[str]:
    """根据倾角和高度返回壳层名称，若不在任何定义内则返回 None"""
    for (i_min, i_max), (h_min, h_max), name in SHELL_DEFS:
        if i_min <= inclination <= i_max and h_min <= altitude <= h_max:
            return name
    return None

def classify_satellites(records: List[dict]) -> List[dict]:
    """
    输入：记录列表（每个 dict 包含 altitude_km, inclination 等字段）
    输出：添加 'shell' 字段，并过滤掉无法归类的卫星（返回保留的列表）
    """
    kept = []
    for rec in records:
        shell = assign_shell(rec['inclination'], rec['altitude_km'])
        if shell is not None:
            rec['shell'] = shell
            kept.append(rec)
    return kept