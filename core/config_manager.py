import os
import logging
import re
from typing import Dict, Any, List, Optional, Callable, Tuple
from pathlib import Path
import yaml
from string import Template
from datetime import timedelta

class ConfigurationError(Exception):
    """配置相关错误"""
    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message)
        self.errors = errors or []
        self.message = message

    def __str__(self):
        if self.errors:
            return f"{self.message}\n" + "\n".join(f"  - {error}" for error in self.errors)
        return self.message

class ConfigManager:
    """增强的配置管理器 - 支持环境变量和配置验证"""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self._config = None
        self.logger = logging.getLogger(__name__)

    def load_config(self) -> Dict[str, Any]:
        """加载配置并处理环境变量"""
        try:
            if not os.path.exists(self.config_path):
                raise ConfigurationError(f"配置文件不存在: {self.config_path}")

            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_content = f.read()

            # 使用Template替换环境变量
            template = Template(config_content)
            try:
                rendered_content = template.substitute(os.environ)
            except KeyError as e:
                raise ConfigurationError(f"缺少必需的环境变量: {e}")

            self._config = yaml.safe_load(rendered_content)

            # 验证配置
            validation_errors = self._validate_config()
            if validation_errors:
                raise ConfigurationError(f"配置验证失败:\n" + "\n".join(validation_errors))

            # 设置默认值
            self._set_defaults()

            return self._config

        except yaml.YAMLError as e:
            raise ConfigurationError(f"YAML解析失败: {e}")
        except Exception as e:
            raise ConfigurationError(f"加载配置失败: {e}")

    def _validate_config(self) -> List[str]:
        """验证配置完整性，包括字段存在性、类型、值范围和依赖关系

        Returns:
            List[str]: 验证错误列表，空列表表示验证通过
        """
        errors = []

        if not self._config:
            errors.append("配置文件为空")
            return errors

        # 1. 检查必需字段
        required_fields = ['log_format', 'log_path', 'rule_dir', 'output_dir']
        for field in required_fields:
            if field not in self._config:
                errors.append(f"缺少必需字段: {field}")

        # 2. 验证字段类型
        type_validations = {
            'analysis.batch_size': (int, lambda x: x > 0, "batch_size必须是正整数"),
            'analysis.max_events': (int, lambda x: x > 0, "max_events必须是正整数"),
            'analysis.memory_limit_mb': (int, lambda x: x > 0, "memory_limit_mb必须是正整数"),
            'ai_analysis.max_ai_analysis': (int, lambda x: x > 0, "max_ai_analysis必须是正整数"),
            'context_lines': (int, lambda x: x >= 0, "context_lines必须是非负整数"),
        }

        for field_path, (expected_type, validator, error_msg) in type_validations.items():
            value = self._get_nested_value(field_path)
            if value is not None:
                if not isinstance(value, expected_type):
                    errors.append(f"{field_path} 类型错误: {error_msg}")
                elif validator and not validator(value):
                    errors.append(f"{field_path} 值范围错误: {error_msg}")

        # 3. 验证AI配置
        ai_config = self._config.get('ai', {})
        if ai_config.get('type') == 'cloud':
            cloud_provider = ai_config.get('cloud_provider')
            if cloud_provider == 'deepseek':
                deepseek_config = self._config.get('deepseek', {})
                api_key = deepseek_config.get('api_key', '')
                if not api_key or api_key in ['your-api-key-here', 'YOUR_API_KEY', 'demo_key_for_testing']:
                    errors.append("DeepSeek API密钥未正确配置 (当前使用占位符)")
            elif cloud_provider == 'custom':
                # 自定义 OpenAI 兼容端点：必须有 base_url（api_key 允许留空走环境变量）
                custom_config = self._config.get('custom', {})
                if not custom_config.get('base_url'):
                    errors.append("自定义AI配置(custom)缺少 base_url")
                if not custom_config.get('model'):
                    errors.append("自定义AI配置(custom)缺少 model")
            elif cloud_provider == 'zhipu':
                # 智谱 GLM：要求 model；base_url 允许留空（由 coding_plan 派生默认），
                # api_key 允许留空（走环境变量 SSLOGS_AI_API_KEY）
                zhipu_config = self._config.get('zhipu', {})
                if not zhipu_config.get('model'):
                    errors.append("智谱AI配置(zhipu)缺少 model")

        # 4. 验证路径字段
        for path_field in ['rule_dir', 'output_dir']:
            if path_field in self._config:
                path_value = self._config[path_field]
                if not isinstance(path_value, str):
                    errors.append(f"{path_field} 必须是字符串路径")
                else:
                    # 检查路径是否包含非法字符
                    if any(char in path_value for char in ['\x00', '\n', '\r']):
                        errors.append(f"{path_field} 包含非法字符")

        # 5. 验证枚举类型字段
        enum_validations = {
            'ai.type': ['cloud', 'local'],
            'ai.cloud_provider': ['deepseek', 'openai', 'custom', 'zhipu'],
            'ai.local_provider': ['ollama', 'lm_studio'],
            'report_type': ['html', 'json', 'markdown'],
        }

        for field_path, allowed_values in enum_validations.items():
            value = self._get_nested_value(field_path)
            if value is not None and value not in allowed_values:
                errors.append(f"{field_path} 值无效: 必须是 {allowed_values} 之一")

        # 6. 验证依赖关系
        # AI类型为cloud时必须有有效的云端配置
        if ai_config.get('type') == 'cloud' and not ai_config.get('cloud_provider'):
            errors.append("AI类型为cloud时必须指定cloud_provider")

        # AI类型为local时必须有本地提供商配置
        if ai_config.get('type') == 'local' and not ai_config.get('local_provider'):
            errors.append("AI类型为local时必须指定local_provider")

        # 7. 验证数值范围合理性
        range_validations = {
            'analysis.batch_size': (1, 100000, "批处理大小应在1-100000之间"),
            'analysis.max_events': (1, 10000, "最大事件数应在1-10000之间"),
            'analysis.memory_limit_mb': (100, 10000, "内存限制应在100MB-10GB之间"),
            'ai_analysis.max_ai_analysis': (1, 100, "AI分析数量应在1-100之间"),
            'deepseek.timeout': (5, 300, "DeepSeek超时应在5-300秒之间"),
            'ollama.timeout': (5, 600, "Ollama超时应在5-600秒之间"),
            'custom.timeout': (5, 600, "自定义AI超时应在5-600秒之间"),
            'zhipu.timeout': (5, 600, "智谱AI超时应在5-600秒之间"),
        }

        for field_path, (min_val, max_val, error_msg) in range_validations.items():
            value = self._get_nested_value(field_path)
            if value is not None and isinstance(value, (int, float)):
                if not (min_val <= value <= max_val):
                    errors.append(f"{field_path} {error_msg} (当前值: {value})")

        # 8. 验证URL格式
        url_validations = [
            'deepseek.base_url',
            'ollama.base_url',
            'custom.base_url',
        ]

        for field_path in url_validations:
            value = self._get_nested_value(field_path)
            if value and isinstance(value, str):
                if not (value.startswith('http://') or value.startswith('https://')):
                    errors.append(f"{field_path} 必须是有效的HTTP(S) URL")

        # 9. 验证GeoIP数据库路径
        geoip_path = self._get_nested_value('geoip_db_path')
        if geoip_path and isinstance(geoip_path, str):
            if not os.path.exists(geoip_path):
                errors.append(f"geoip_db_path 指定的文件不存在: {geoip_path}")
            elif not geoip_path.endswith('.mmdb'):
                errors.append(f"geoip_db_path 必须指向.mmdb文件: {geoip_path}")

        # 10. 验证日志格式配置
        log_format = self._get_nested_value('log_format')
        if log_format and isinstance(log_format, dict):
            if 'fields' not in log_format or not log_format['fields']:
                errors.append("log_format.fields 不能为空")
            elif not isinstance(log_format['fields'], dict):
                errors.append("log_format.fields 必须是字典类型")

        # 11. 验证规则目录
        rule_dir = self._get_nested_value('rule_dir')
        if rule_dir and isinstance(rule_dir, str):
            if not os.path.exists(rule_dir):
                errors.append(f"rule_dir 指定的目录不存在: {rule_dir}")
            elif not os.path.isdir(rule_dir):
                errors.append(f"rule_dir 必须是目录: {rule_dir}")

        # 12. 验证输出目录
        output_dir = self._get_nested_value('output_dir')
        if output_dir and isinstance(output_dir, str):
            try:
                # 尝试创建输出目录（如果不存在）
                os.makedirs(output_dir, exist_ok=True)
            except Exception as e:
                errors.append(f"无法创建或访问输出目录 {output_dir}: {e}")

        # 13. 验证日志文件路径模式
        log_path = self._get_nested_value('log_path')
        if log_path and isinstance(log_path, str):
            # 验证日志路径模式的有效性
            if not any(c in log_path for c in ['*', '?', '[']):
                # 如果不包含通配符，检查具体文件
                if not os.path.exists(log_path):
                    # 文件不存在，但不一定是错误（可能是运行时路径）
                    self.logger.warning(f"log_path 指定的文件不存在: {log_path}")

        # 14. 验证白名单配置
        whitelist = self._get_nested_value('whitelist')
        if whitelist and isinstance(whitelist, dict):
            # 验证白名单字段类型
            list_fields = ['safe_agents', 'static_extensions', 'health_paths', 'internal_ips']
            for field in list_fields:
                field_value = whitelist.get(field)
                if field_value is not None and not isinstance(field_value, list):
                    errors.append(f"whitelist.{field} 必须是列表类型")

        # 15. 验证报告配置
        report_config = self._get_nested_value('report')
        if report_config and isinstance(report_config, dict):
            # 验证输出格式
            output_format = report_config.get('output_format')
            if output_format and output_format not in ['html', 'json', 'markdown', 'txt']:
                errors.append(f"report.output_format 必须是 html/json/markdown/txt 之一")

            # 验证模板文件存在性
            template = report_config.get('template')
            if template and isinstance(template, str):
                if not os.path.exists(template):
                    errors.append(f"report.template 指定的文件不存在: {template}")

        return errors

    def _get_nested_value(self, path: str) -> Any:
        """获取嵌套配置值

        Args:
            path: 点分隔的配置路径，如 'analysis.batch_size'

        Returns:
            配置值，如果路径不存在则返回None
        """
        keys = path.split('.')
        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value

    def _set_defaults(self):
        """设置默认配置值"""
        if not self._config:
            self._config = {}

        # 分析配置默认值
        self._config.setdefault('analysis', {})
        analysis = self._config['analysis']
        analysis.setdefault('batch_size', 1000)
        analysis.setdefault('max_events', 100)
        analysis.setdefault('memory_limit_mb', 500)

        # AI分析配置默认值
        self._config.setdefault('ai_analysis', {})
        ai_analysis = self._config['ai_analysis']
        ai_analysis.setdefault('high_risk_only', True)
        ai_analysis.setdefault('successful_attacks_only', True)
        ai_analysis.setdefault('success_status_codes', ['200', '201', '202', '204', '301', '302', '304'])
        ai_analysis.setdefault('max_ai_analysis', 5)
        ai_analysis.setdefault('high_risk_severity', 'high')

        # 服务器配置默认值
        self._config.setdefault('server', {})
        self._config['server'].setdefault('ip', '未知')

        # AI配置默认值
        self._config.setdefault('ai', {})
        ai = self._config['ai']
        ai.setdefault('type', 'cloud')
        ai.setdefault('cloud_provider', 'deepseek')
        ai.setdefault('local_provider', 'ollama')

        # DeepSeek配置默认值
        self._config.setdefault('deepseek', {})
        deepseek = self._config['deepseek']
        deepseek.setdefault('model', 'deepseek-ai/DeepSeek-V3')
        deepseek.setdefault('base_url', 'https://api.siliconflow.cn/v1/chat/completions')
        deepseek.setdefault('timeout', 30)
        deepseek.setdefault('max_tokens', 2048)

        # Ollama配置默认值
        self._config.setdefault('ollama', {})
        ollama = self._config['ollama']
        ollama.setdefault('model', 'deepseek-r1:14b')
        ollama.setdefault('base_url', 'http://localhost:11434/api/chat')
        ollama.setdefault('timeout', 60)

        # 自定义 OpenAI 兼容端点默认值（cloud_provider=custom 时启用）
        self._config.setdefault('custom', {})
        custom = self._config['custom']
        custom.setdefault('base_url', '')
        custom.setdefault('api_key', '')
        custom.setdefault('model', '')
        custom.setdefault('timeout', 30)
        custom.setdefault('max_tokens', 2048)

        # 智谱 GLM 默认值（cloud_provider=zhipu 时启用）
        self._config.setdefault('zhipu', {})
        zhipu = self._config['zhipu']
        zhipu.setdefault('base_url', '')          # 留空则由 coding_plan 派生默认端点
        zhipu.setdefault('api_key', '')           # 留空则读取环境变量 SSLOGS_AI_API_KEY
        zhipu.setdefault('model', 'glm-4.6')
        zhipu.setdefault('coding_plan', False)
        zhipu.setdefault('timeout', 120)
        zhipu.setdefault('max_tokens', 4096)      # GLM-5 等推理模型需要更大空间产出正式回答

        # 重试配置默认值
        ai.setdefault('max_retries', 3)
        ai.setdefault('retry_delay', 1)
        ai.setdefault('retry_backoff', 2)
        ai.setdefault('default_timeout', 30)

    def get_config(self) -> Dict[str, Any]:
        """获取配置，自动加载如果未加载"""
        if self._config is None:
            self.load_config()
        return self._config

    def reload_config(self) -> Dict[str, Any]:
        """重新加载配置"""
        self._config = None
        return self.load_config()

    def get_safe_config(self) -> Dict[str, Any]:
        """获取安全的配置（隐藏敏感信息）"""
        config = self.get_config().copy()

        # 隐藏敏感信息（deepseek、智谱与自定义端点的 api_key 均需脱敏）
        for section_name in ('deepseek', 'custom', 'zhipu'):
            section = config.get(section_name)
            if isinstance(section, dict) and 'api_key' in section:
                api_key = section['api_key']
                if api_key and len(api_key) > 8:
                    config[section_name]['api_key'] = api_key[:4] + '*' * (len(api_key) - 8) + api_key[-4:]
                else:
                    config[section_name]['api_key'] = '***'

        return config

    def validate_config_change(self, changes: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """验证配置更改是否有效

        Args:
            changes: 要更改的配置字典

        Returns:
            Tuple[bool, List[str]]: (是否有效, 错误列表)
        """
        # 创建临时配置副本
        temp_config = self.get_config().copy()
        self._update_nested_config(temp_config, changes)

        # 验证临时配置
        original_config = self._config
        self._config = temp_config
        errors = self._validate_config()
        self._config = original_config

        return len(errors) == 0, errors

    def _update_nested_config(self, config: Dict[str, Any], changes: Dict[str, Any]) -> None:
        """更新嵌套配置

        Args:
            config: 原始配置字典
            changes: 要更改的配置 (支持点分隔的路径)
        """
        for path, value in changes.items():
            keys = path.split('.')
            current = config
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            current[keys[-1]] = value

    def get_validation_report(self) -> Dict[str, Any]:
        """获取详细的配置验证报告

        Returns:
            Dict[str, Any]: 包含验证状态、错误和建议的报告
        """
        errors = self._validate_config()
        warnings = []
        suggestions = []

        # 生成警告和建议
        config = self.get_config()

        # 性能相关建议
        batch_size = self._get_nested_value('analysis.batch_size')
        if batch_size and batch_size > 10000:
            warnings.append("analysis.batch_size 设置较大，可能影响内存使用")

        # 安全相关建议
        if config.get('deepseek', {}).get('api_key') == 'demo_key_for_testing':
            warnings.append("DeepSeek API密钥仍为演示值，请配置真实密钥")

        # AI分析配置建议
        max_ai_analysis = self._get_nested_value('ai_analysis.max_ai_analysis')
        if max_ai_analysis and max_ai_analysis > 10:
            suggestions.append("ai_analysis.max_ai_analysis 设置较高，可能增加API调用成本")

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'suggestions': suggestions,
            'total_issues': len(errors) + len(warnings) + len(suggestions)
        }