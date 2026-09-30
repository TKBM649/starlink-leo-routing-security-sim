# conftest.py - 仓库根目录
"""
pytest 全局配置：
1. 将仓库根插入 sys.path，确保 `import starlink_sim` 稳定可用
2. 将 cwd 切换到仓库根，确保相对路径 data/ results/ 等稳定
3. 不依赖测试运行时的 cwd 位置
"""
import sys
from pathlib import Path

# 仓库根目录（conftest.py 所在目录）
PROJECT_ROOT = Path(__file__).resolve().parent

# 确保 starlink_sim 包可导入
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 确保 scripts/ 下的模块也可被测试导入
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def pytest_configure(config):
    """将 cwd 切换到仓库根，使相对路径 data/tle/starlink.tle 等稳定。"""
    import os
    os.chdir(str(PROJECT_ROOT))
