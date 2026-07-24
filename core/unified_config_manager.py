import os
import yaml
import json
import logging
import hashlib
import hmac
import base64
from typing import Dict, Any, Optional, List, Union, Callable
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import threading
import time

from .interfaces import IConfigManager
from .exceptions import ConfigurationError, SecurityError


class UnifiedConfigManager(IConfigManager):
    """统一配置管理器 - 支持安全存储、验证和热重载"""

    def __init__(self, config_path: str = 'config.yaml', encryption_key: Optional[str] = None):
        self.config_path = Path(config_path)
        self.encryption_key = encryption_key or os.environ.get('CONFIG_ENCRYPTION_KEY')
        self._config: Dict[str, Any] = {}
        self._encrypted_config: Dict[str, Any] = {}
        self._validators: Dict[str, List[Callable]] = {}
        self._watchers: List[Callable] = []
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__)
        self._last_modified = 0
        self._auto_reload = True
        self._reload_interval = 5  # 秒

        # 初始化加密
        self._init_encryption()

        # 加载配置
        self.load_config(str(self.config_path))

    def _init_encryption(self):
        """初始化加密功能"""
        if self.encryption_key:
            try:
                # 使用PBKDF2从密钥派生加密密钥
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'sslogs_config_salt',  # 固定盐值
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(self.encryption_key.encode()))
                self.cipher = Fernet(key)
                self._logger.info("配置加密已启用")
            except Exception as e:
                self._logger.error(f"初始化加密失败: {e}")
                self.cipher = None
        else:
            self.cipher = None
            self._logger.warning("配置加密未启用，敏感信息将以明文存储")

    def _encrypt_value(self, value: str) -> str:
        """加密敏感值"""
        if not self.cipher:
            return value
        try:
            encrypted = self.cipher.encrypt(value.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            self._logger.error(f"加密值失败: {e}")
            return value

    def _decrypt_value(self, encrypted_value: str) -> str:
        """解密敏感值"""
        if not self.cipher:
            return encrypted_value
        try:
            encrypted = base64.b64decode(encrypted_value.encode())
            decrypted = self.cipher.decrypt(encrypted)
            return decrypted.decode()
        except Exception as e:
            self._logger.error(f"解密值失败: {e}")
            return encrypted_value

    def _is_sensitive_key(self, key: str) -> bool:
        """判断是否为敏感配置项"""
        sensitive_keywords = [
            'password', 'secret', 'key', 'token', 'api_key',
            'credential', 'auth', 'private', 'certificate'
        ]
        key_lower = key.lower()
        return any(keyword in key_lower for keyword in sensitive_keywords)

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                self._logger.warning(f"配置文件不存在: {config_path}")
                return {}

            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.suffix.lower() == '.json':
                    raw_config = json.load(f)
                else:
                    raw_config = yaml.safe_load(f)

            with self._lock:
                self._config = raw_config or {}
                self._encrypted_config = {}

                # 处理加密的配置项
                self._process_encrypted_config()

                # 验证配置
                errors = self.validate_config(self._config)
                if errors:
                    raise ConfigurationError(f"配置验证失败: {', '.join(errors)}")

                self._last_modified = config_file.stat().st_mtime
                self._logger.info(f"成功加载配置文件: {config_path}")

                # 通知观察者
                self._notify_watchers()

            return self._config

        except Exception as e:
            self._logger.error(f"加载配置文件失败: {e}")
            raise ConfigurationError(f"无法加载配置文件 {config_path}: {e}")

    def _process_encrypted_config(self):
        """处理加密的配置项"""
        if 'encrypted' in self._config:
            encrypted_section = self._config.pop('encrypted')
            for key, encrypted_value in encrypted_section.items():
                if isinstance(encrypted_value, str):
                    try:
                        decrypted_value = self._decrypt_value(encrypted_value)
                        # 放置到原始配置的相应位置
                        self._set_nested_value(key, decrypted_value)
                        self._encrypted_config[key] = encrypted_value
                    except Exception as e:
                        self._logger.error(f"解密配置项 {key} 失败: {e}")

    def _set_nested_value(self, key: str, value: Any):
        """设置嵌套配置值"""
        keys = key.split('.')
        current = self._config
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        current[keys[-1]] = value

    def _get_nested_value(self, key: str, default: Any = None) -> Any:
        """获取嵌套配置值"""
        keys = key.split('.')
        current = self._config
        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default

    def save_config(self, config: Dict[str, Any], config_path: str) -> bool:
        """保存配置文件"""
        try:
            config_file = Path(config_path)
            config_file.parent.mkdir(parents=True, exist_ok=True)

            # 处理敏感信息加密
            save_config = config.copy()
            encrypted_section = {}

            # 识别并加密敏感配置项
            self._encrypt_sensitive_values(save_config, encrypted_section)

            # 如果有加密项，添加到配置中
            if encrypted_section:
                save_config['encrypted'] = encrypted_section

            with open(config_file, 'w', encoding='utf-8') as f:
                if config_file.suffix.lower() == '.json':
                    json.dump(save_config, f, indent=2, ensure_ascii=False)
                else:
                    yaml.dump(save_config, f, default_flow_style=False,
                             allow_unicode=True, indent=2)

            self._logger.info(f"配置文件已保存: {config_path}")
            return True

        except Exception as e:
            self._logger.error(f"保存配置文件失败: {e}")
            return False

    def _encrypt_sensitive_values(self, config: Dict[str, Any], encrypted_section: Dict[str, Any], prefix: str = ""):
        """递归加密敏感配置值"""
        for key, value in config.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                self._encrypt_sensitive_values(value, encrypted_section, full_key)
            elif isinstance(value, str) and self._is_sensitive_key(key):
                encrypted_value = self._encrypt_value(value)
                encrypted_section[full_key] = encrypted_value
                # 从原配置中移除明文值
                config[key] = f"[ENCRYPTED:{len(value)}]"

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        # 自动重载检查
        if self._auto_reload and self._should_reload():
            self.reload_config()

        with self._lock:
            return self._get_nested_value(key, default)

    def set(self, key: str, value: Any) -> None:
        """设置配置项"""
        with self._lock:
            self._set_nested_value(key, value)

            # 如果是敏感信息，同时更新加密存储
            if isinstance(value, str) and self._is_sensitive_key(key):
                encrypted_value = self._encrypt_value(value)
                self._encrypted_config[key] = encrypted_value

            # 通知观察者
            self._notify_watchers()

    def should_encrypt(self, key: str) -> bool:
        """检查配置项是否应该加密"""
        return self._is_sensitive_key(key)

    def encrypt_sensitive_config(self, key: str) -> bool:
        """手动加密敏感配置项"""
        with self._lock:
            value = self._get_nested_value(key)
            if isinstance(value, str) and self._is_sensitive_key(key):
                encrypted_value = self._encrypt_value(value)
                self._encrypted_config[key] = encrypted_value
                self._set_nested_value(key, f"[ENCRYPTED:{len(value)}]")
                return True
            return False

    def decrypt_sensitive_config(self, key: str) -> Optional[str]:
        """手动解密敏感配置项"""
        with self._lock:
            if key in self._encrypted_config:
                return self._decrypt_value(self._encrypted_config[key])
            return None

    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """验证配置"""
        errors = []

        # 基础验证
        required_sections = ['ai', 'logging', 'rules']
        for section in required_sections:
            if section not in config:
                errors.append(f"缺少必需的配置节: {section}")

        # AI配置验证
        if 'ai' in config:
            ai_config = config['ai']
            if ai_config.get('type') == 'cloud':
                if 'cloud_provider' not in ai_config:
                    errors.append("云端AI配置缺少cloud_provider")
                elif ai_config['cloud_provider'] == 'deepseek':
                    deepseek_config = ai_config.get('deepseek', {})
                    if not deepseek_config.get('api_key'):
                        errors.append("DeepSeek配置缺少api_key")
                elif ai_config['cloud_provider'] == 'custom':
                    # 自定义 OpenAI 兼容端点：要求 base_url 与 model
                    # (api_key 允许留空，走环境变量 SSLOGS_AI_API_KEY)
                    custom_config = ai_config.get('custom', {})
                    if not custom_config.get('base_url'):
                        errors.append("自定义AI配置缺少base_url")
                    if not custom_config.get('model'):
                        errors.append("自定义AI配置缺少model")

        # 规则配置验证
        if 'rules' in config:
            rules_config = config['rules']
            rules_path = rules_config.get('path', 'rules/')
            if not Path(rules_path).exists():
                errors.append(f"规则目录不存在: {rules_path}")

        # 日志配置验证
        if 'logging' in config:
            logging_config = config['logging']
            log_level = logging_config.get('level', 'INFO')
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if log_level not in valid_levels:
                errors.append(f"无效的日志级别: {log_level}")

        # 执行自定义验证器
        for key, validators in self._validators.items():
            if key in config:
                value = config[key]
                for validator in validators:
                    try:
                        if not validator(value):
                            errors.append(f"配置项 {key} 验证失败")
                    except Exception as e:
                        errors.append(f"配置项 {key} 验证器异常: {e}")

        return errors

    def add_validator(self, key: str, validator: Callable[[Any], bool]) -> None:
        """添加配置验证器"""
        if key not in self._validators:
            self._validators[key] = []
        self._validators[key].append(validator)

    def add_watcher(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """添加配置变化观察者"""
        self._watchers.append(callback)

    def remove_watcher(self, callback: Callable) -> None:
        """移除配置变化观察者"""
        if callback in self._watchers:
            self._watchers.remove(callback)

    def _notify_watchers(self):
        """通知所有观察者"""
        for watcher in self._watchers:
            try:
                watcher(self._config.copy())
            except Exception as e:
                self._logger.error(f"通知观察者失败: {e}")

    def _should_reload(self) -> bool:
        """检查是否需要重载配置"""
        try:
            current_mtime = self.config_path.stat().st_mtime
            return current_mtime > self._last_modified
        except Exception:
            return False

    def reload_config(self) -> bool:
        """重载配置文件"""
        try:
            self.load_config(str(self.config_path))
            return True
        except Exception as e:
            self._logger.error(f"重载配置失败: {e}")
            return False

    def get_encrypted_keys(self) -> List[str]:
        """获取所有加密的配置项键"""
        return list(self._encrypted_config.keys())

    def get_config_summary(self) -> Dict[str, Any]:
        """获取配置摘要（不包含敏感信息）"""
        summary = {
            'config_path': str(self.config_path),
            'last_modified': self._last_modified,
            'encryption_enabled': self.cipher is not None,
            'encrypted_keys_count': len(self._encrypted_config),
            'validators_count': len(self._validators),
            'watchers_count': len(self._watchers),
            'sections': list(self._config.keys())
        }
        return summary

    def export_config(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """导出配置"""
        with self._lock:
            config_copy = self._config.copy()

            if not include_sensitive:
                # 移除敏感信息
                self._remove_sensitive_values(config_copy)

            return config_copy

    def _remove_sensitive_values(self, config: Dict[str, Any]):
        """递归移除敏感值"""
        for key, value in config.items():
            if self._is_sensitive_key(key):
                config[key] = "[REDACTED]"
            elif isinstance(value, dict):
                self._remove_sensitive_values(value)

    def merge_config(self, other_config: Dict[str, Any]) -> None:
        """合并其他配置"""
        with self._lock:
            self._deep_merge(self._config, other_config)
            self._notify_watchers()

    def _deep_merge(self, target: Dict[str, Any], source: Dict[str, Any]):
        """深度合并字典"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value

    def reset_to_defaults(self) -> None:
        """重置为默认配置"""
        default_config = {
            'ai': {
                'type': 'local',
                'local_provider': 'ollama',
                'max_retries': 3,
                'retry_delay': 1,
                'default_timeout': 30
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'rules': {
                'path': 'rules/',
                'auto_reload': True
            },
            'performance': {
                'max_memory_usage': 0.8,
                'chunk_size': 8192,
                'batch_size': 100
            }
        }

        with self._lock:
            self._config = default_config.copy()
            self._notify_watchers()


# 全局配置管理器实例
_global_config_manager: Optional[UnifiedConfigManager] = None


def get_config_manager() -> UnifiedConfigManager:
    """获取全局配置管理器实例"""
    global _global_config_manager
    if _global_config_manager is None:
        _global_config_manager = UnifiedConfigManager()
    return _global_config_manager


def init_config_manager(config_path: str = 'config.yaml',
                       encryption_key: Optional[str] = None) -> UnifiedConfigManager:
    """初始化全局配置管理器"""
    global _global_config_manager
    _global_config_manager = UnifiedConfigManager(config_path, encryption_key)
    return _global_config_manager


# 便捷函数
def get_config(key: str, default: Any = None) -> Any:
    """获取配置项的便捷函数"""
    return get_config_manager().get(key, default)


def set_config(key: str, value: Any) -> None:
    """设置配置项的便捷函数"""
    get_config_manager().set(key, value)