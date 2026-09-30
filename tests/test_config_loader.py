# tests/test_config_loader.py
"""
统一配置解析层 (starlink_sim.io.config) 单元测试。

验证：
1. 3 个现有 YAML 均可成功加载并归一化为统一 schema
2. wire 的参数（t_adv / max_hops / node_limit）确实出现在解析结果中
3. 死键（reserved/removed）被安全忽略，不出现在输出中
4. 旧版 e3 扁平 schema 自动转换为嵌套格式
"""
import tempfile
from pathlib import Path

import pytest
import yaml

from starlink_sim.io.config import load_experiment_config, get_attacker_configs

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIGS_DIR = PROJECT_ROOT / "configs" / "experiments"


class TestLoadExistingConfigs:
    """验证仓库中 3 个 YAML 均可成功加载"""

    @pytest.mark.parametrize("name", ["e2_jamming", "e2_noattack", "e3_blackhole"])
    def test_load_success(self, name):
        path = CONFIGS_DIR / f"{name}.yaml"
        assert path.exists(), f"Config file missing: {path}"
        config = load_experiment_config(path)
        # 统一 schema 必须包含所有顶层 section
        assert 'experiment' in config
        assert 'topology' in config
        assert 'routing' in config
        assert 'traffic' in config
        assert 'attack' in config
        assert 'output' in config

    @pytest.mark.parametrize("name", ["e2_jamming", "e2_noattack", "e3_blackhole"])
    def test_experiment_name_preserved(self, name):
        config = load_experiment_config(CONFIGS_DIR / f"{name}.yaml")
        assert config['experiment']['name'] == name


class TestWiredParameters:
    """验证 wire 的参数确实出现在解析结果中并传达正确值"""

    def test_t_adv_present(self):
        config = load_experiment_config(CONFIGS_DIR / "e2_jamming.yaml")
        assert config['routing']['t_adv'] == 2.0

    def test_max_hops_present(self):
        config = load_experiment_config(CONFIGS_DIR / "e2_jamming.yaml")
        assert config['routing']['max_hops'] == 100

    def test_node_limit_e2(self):
        config = load_experiment_config(CONFIGS_DIR / "e2_jamming.yaml")
        assert config['topology']['node_limit'] == 96

    def test_node_limit_e3_null(self):
        config = load_experiment_config(CONFIGS_DIR / "e3_blackhole.yaml")
        assert config['topology']['node_limit'] is None

    def test_wired_params_reach_simulator(self):
        """验证 t_adv 和 max_hops 能传递到 Simulator 构造"""
        from starlink_sim.net.simulator import Simulator, ControlPlane, DataPlane
        import inspect

        # Simulator 接受 adv_interval 和 max_hops
        sig = inspect.signature(Simulator.__init__)
        assert 'adv_interval' in sig.parameters
        assert 'max_hops' in sig.parameters
        # 默认值保持不变
        assert sig.parameters['adv_interval'].default == 2.0
        assert sig.parameters['max_hops'].default == 100

        # ControlPlane 接受 adv_interval
        sig_cp = inspect.signature(ControlPlane.__init__)
        assert 'adv_interval' in sig_cp.parameters
        assert sig_cp.parameters['adv_interval'].default == 2.0

        # DataPlane 接受 max_hops
        sig_dp = inspect.signature(DataPlane.__init__)
        assert 'max_hops' in sig_dp.parameters
        assert sig_dp.parameters['max_hops'].default == 100


class TestDeadKeysRemoved:
    """验证 reserved/removed 死键不出现在解析输出中"""

    REMOVED_KEYS = {
        'topology': ['use_lattice', 'gimbal_limit', 'tle_file'],
        'routing': ['protocol'],
        'traffic': ['flow_duration', 'start_offset'],
    }

    @pytest.mark.parametrize("name", ["e2_jamming", "e2_noattack", "e3_blackhole"])
    def test_removed_keys_absent(self, name):
        config = load_experiment_config(CONFIGS_DIR / f"{name}.yaml")
        for section, keys in self.REMOVED_KEYS.items():
            for key in keys:
                assert key not in config.get(section, {}), \
                    f"Dead key '{section}.{key}' should be removed but found in {name}"

    def test_isl_distance_limit_absent(self):
        """isl_distance_limit 标记为 reserved，解析层应忽略"""
        config = load_experiment_config(CONFIGS_DIR / "e2_jamming.yaml")
        assert 'isl_distance_limit' not in config.get('topology', {})


class TestLegacyE3Conversion:
    """验证旧版 e3 扁平 schema 能自动转换"""

    def test_flat_schema_converted(self):
        legacy = {
            'experiment': 'e3_test',
            'duration': 30,
            'topology_epoch': 15,
            'control_tick': 0.1,
            'num_flows': 50,
            'topology_cache': 'data/topology/topology_results.pkl',
            'shell': '53°',
            'attackers': [
                {'type': 'blackhole', 'count': 2, 'drop_prob': 0.5,
                 'metric_fake': 0, 'active_since': 5.0, 'active_until': 20.0}
            ],
        }
        # 写入临时文件
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False,
                                         encoding='utf-8') as f:
            yaml.dump(legacy, f)
            tmp_path = f.name

        config = load_experiment_config(tmp_path)
        Path(tmp_path).unlink()

        assert config['experiment']['name'] == 'e3_test'
        assert config['experiment']['duration'] == 30
        assert config['topology']['epoch_interval'] == 15
        assert config['routing']['tick'] == 0.1
        assert config['traffic']['num_flows'] == 50
        # 攻击者参数归一化到 params 子字典
        attackers = get_attacker_configs(config)
        assert len(attackers) == 1
        assert attackers[0]['params']['drop_prob'] == 0.5
        assert attackers[0]['active_since'] == 5.0


class TestAttackerExtraction:
    """验证攻击者配置提取"""

    def test_e2_jamming_has_attackers(self):
        config = load_experiment_config(CONFIGS_DIR / "e2_jamming.yaml")
        attackers = get_attacker_configs(config)
        assert len(attackers) == 1
        assert attackers[0]['count'] == 10

    def test_e2_noattack_empty(self):
        config = load_experiment_config(CONFIGS_DIR / "e2_noattack.yaml")
        attackers = get_attacker_configs(config)
        assert len(attackers) == 0

    def test_e3_blackhole_has_attackers(self):
        config = load_experiment_config(CONFIGS_DIR / "e3_blackhole.yaml")
        attackers = get_attacker_configs(config)
        assert len(attackers) == 1
        assert attackers[0]['type'] == 'blackhole'
        assert attackers[0]['count'] == 3
