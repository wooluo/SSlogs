"""
配置管理器单元测试
"""
import pytest
import tempfile
import os
from pathlib import Path
from core.config_manager import ConfigManager, ConfigurationError


class TestConfigManager:
    """配置管理器测试"""

    @pytest.fixture
    def valid_config_file(self):
        """创建有效的配置文件"""
        config_content = """
log_path: logs/*.log
server:
  ip: 192.168.1.100

log_format:
  type: web
  timestamp_format: '%d/%b/%Y:%H:%M:%S %z'
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)
    timestamp: \\[(.*?)\\]
    request_line: '"([A-Z]+\\s+[^\\s]+\\s+HTTP/[\\d\\.]+)"'

rule_dir: rules
output_dir: output

ai:
  type: local
  local_provider: ollama

ollama:
  model: deepseek-r1:14b
  base_url: http://localhost:11434/api/chat
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    @pytest.fixture
    def invalid_config_file(self):
        """创建无效的配置文件（缺少必需字段）"""
        config_content = """
log_path: logs/*.log
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    def test_load_valid_config(self, valid_config_file):
        """测试加载有效配置"""
        manager = ConfigManager(valid_config_file)
        config = manager.load_config()

        assert config is not None
        assert 'log_path' in config
        assert config['log_path'] == 'logs/*.log'
        assert 'server' in config
        assert config['server']['ip'] == '192.168.1.100'

    def test_load_invalid_config_missing_fields(self, invalid_config_file):
        """测试加载缺少必需字段的配置"""
        manager = ConfigManager(invalid_config_file)

        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()

        assert '缺少必需字段' in str(exc_info.value)

    def test_load_nonexistent_config(self):
        """测试加载不存在的配置文件"""
        manager = ConfigManager('nonexistent_config.yaml')

        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()

        assert '配置文件不存在' in str(exc_info.value)

    def test_get_config_auto_load(self, valid_config_file):
        """测试自动加载配置"""
        manager = ConfigManager(valid_config_file)
        config = manager.get_config()

        assert config is not None
        assert manager._config is not None  # 确认配置已加载

    def test_reload_config(self, valid_config_file):
        """测试重新加载配置"""
        manager = ConfigManager(valid_config_file)
        config1 = manager.load_config()
        config2 = manager.reload_config()

        assert config1 is not None
        assert config2 is not None
        # 重新加载应该创建新的配置对象
        assert config1 is not config2

    def test_default_values(self, valid_config_file):
        """测试默认值设置"""
        manager = ConfigManager(valid_config_file)
        config = manager.load_config()

        # 检查默认值
        assert 'analysis' in config
        assert config['analysis']['batch_size'] == 1000
        assert config['analysis']['max_events'] == 100

        assert 'ai_analysis' in config
        assert config['ai_analysis']['high_risk_only'] is True
        assert config['ai_analysis']['max_ai_analysis'] == 5

    def test_environment_variable_substitution(self):
        """测试环境变量替换"""
        # 设置环境变量
        os.environ['TEST_SERVER_IP'] = '10.0.0.1'

        config_content = """
server:
  ip: ${TEST_SERVER_IP}
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)
            config = manager.load_config()

            assert config['server']['ip'] == '10.0.0.1'
        finally:
            os.unlink(temp_path)
            del os.environ['TEST_SERVER_IP']

    def test_missing_environment_variable(self):
        """测试缺少必需的环境变量"""
        config_content = """
server:
  ip: ${NONEXISTENT_VAR}
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_config()

            assert '缺少必需的环境变量' in str(exc_info.value)
        finally:
            os.unlink(temp_path)

    def test_get_safe_config(self, valid_config_file):
        """测试获取安全配置（隐藏敏感信息）"""
        # 创建包含API密钥的配置
        config_content = """
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output

deepseek:
  api_key: sk-1234567890abcdef
  model: deepseek-ai/DeepSeek-V3
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)
            manager.load_config()
            safe_config = manager.get_safe_config()

            # 检查API密钥被隐藏
            assert 'sk-1234****bcdef' == safe_config['deepseek']['api_key']
        finally:
            os.unlink(temp_path)

    def test_get_safe_config_custom(self):
        """测试自定义端点 custom.api_key 同样被脱敏"""
        config_content = """
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output

custom:
  api_key: sk-1234567890abcdef
  base_url: https://api.openai.com/v1
  model: gpt-4o-mini
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)
            manager.load_config()
            safe_config = manager.get_safe_config()

            # 自定义端点的 API 密钥也应被脱敏（保留首4/末4，中间以 * 替换）
            masked = safe_config['custom']['api_key']
            assert masked != 'sk-1234567890abcdef'   # 已脱敏，不再是明文
            assert masked.startswith('sk-1') and masked.endswith('cdef')
            assert '*' in masked
            # base_url 等非敏感字段保持不变
            assert 'https://api.openai.com/v1' == safe_config['custom']['base_url']
        finally:
            os.unlink(temp_path)



class TestConfigValidation:
    """配置验证测试"""

    @pytest.fixture
    def config_with_invalid_ranges(self):
        """创建包含无效范围值的配置"""
        config_content = """
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output

analysis:
  batch_size: 200000  # 超出有效范围
  max_events: -5      # 负数

deepseek:
  timeout: 500        # 超出有效范围
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    def test_validate_numeric_ranges(self, config_with_invalid_ranges):
        """测试数值范围验证"""
        manager = ConfigManager(config_with_invalid_ranges)

        with pytest.raises(ConfigurationError) as exc_info:
            manager.load_config()

        error_message = str(exc_info.value)
        # 应该有范围验证错误
        assert 'batch_size' in error_message or 'max_events' in error_message or 'timeout' in error_message

    def test_validate_enum_values(self):
        """测试枚举值验证"""
        config_content = """
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output

ai:
  type: invalid_type  # 无效的AI类型

report_type: invalid_format  # 无效的报告格式
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_config()

            error_message = str(exc_info.value)
            assert '值无效' in error_message
        finally:
            os.unlink(temp_path)

    def test_custom_cloud_provider_accepted(self):
        """测试 cloud_provider=custom 且 custom 配置完整时通过校验"""
        config_content = """
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output

ai:
  type: cloud
  cloud_provider: custom

custom:
  base_url: https://api.openai.com/v1
  api_key: sk-1234567890abcdef
  model: gpt-4o-mini
  timeout: 30
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)
            # 配置完整时不应抛出校验异常
            manager.load_config()
            assert manager.get_config()['ai']['cloud_provider'] == 'custom'
        finally:
            os.unlink(temp_path)

    def test_custom_cloud_provider_missing_base_url_rejected(self):
        """测试 cloud_provider=custom 但缺少 base_url 时被校验拦截"""
        config_content = """
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output

ai:
  type: cloud
  cloud_provider: custom

custom:
  base_url: ""
  model: gpt-4o-mini
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)
            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_config()
            assert 'base_url' in str(exc_info.value)
        finally:
            os.unlink(temp_path)



class TestConfigValidationMethods:
    """配置验证方法测试"""

    @pytest.fixture
    def minimal_config(self):
        """创建最小有效配置"""
        config_content = """
log_path: logs/*.log
log_format:
  type: web
  fields:
    src_ip: (\\d+\\.\\d+\\.\\d+\\.\\d+)

rule_dir: rules
output_dir: output
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    def test_get_validation_report(self, minimal_config):
        """测试获取验证报告"""
        manager = ConfigManager(minimal_config)
        manager.load_config()
        report = manager.get_validation_report()

        assert report['valid'] is True
        assert isinstance(report['errors'], list)
        assert isinstance(report['warnings'], list)
        assert isinstance(report['suggestions'], list)
        assert 'total_issues' in report

    def test_validate_config_change(self, minimal_config):
        """测试配置更改验证"""
        manager = ConfigManager(minimal_config)
        manager.load_config()

        # 测试有效的配置更改
        valid_changes = {
            'analysis.batch_size': 500,
            'server.ip': '192.168.1.200'
        }

        is_valid, errors = manager.validate_config_change(valid_changes)
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_invalid_config_change(self, minimal_config):
        """测试无效的配置更改验证"""
        manager = ConfigManager(minimal_config)
        manager.load_config()

        # 测试无效的配置更改
        invalid_changes = {
            'analysis.batch_size': -100,  # 负数
            'ai.type': 'invalid_type'     # 无效值
        }

        is_valid, errors = manager.validate_config_change(invalid_changes)
        assert is_valid is False
        assert len(errors) > 0


class TestConfigManagerEdgeCases:
    """配置管理器边界情况测试"""

    def test_empty_config_file(self):
        """测试空配置文件"""
        config_content = ""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_config()

            assert '配置文件为空' in str(exc_info.value)
        finally:
            os.unlink(temp_path)

    def test_malformed_yaml(self):
        """测试格式错误的YAML"""
        config_content = """
log_path: logs/*.log
server:
  ip: 192.168.1.100
  invalid_yaml: [unclosed bracket
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(config_content)
            temp_path = f.name

        try:
            manager = ConfigManager(temp_path)

            with pytest.raises(ConfigurationError) as exc_info:
                manager.load_config()

            assert 'YAML解析失败' in str(exc_info.value)
        finally:
            os.unlink(temp_path)
