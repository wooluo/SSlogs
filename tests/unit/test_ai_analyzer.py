"""
AI分析器单元测试
"""
import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
from core.ai_analyzer import AIAnalyzer, fetch_available_models
from core.exceptions import (
    AIServiceError,
    AIServiceUnavailableError,
    AIAuthenticationError,
    AIRateLimitError
)


class TestAIAnalyzer:
    """AI分析器基础测试"""

    @pytest.fixture
    def mock_config(self):
        """创建模拟配置"""
        return {
            'ai': {
                'type': 'cloud',
                'cloud_provider': 'deepseek',
                'local_provider': 'ollama',
                'max_retries': 3,
                'retry_delay': 1,
                'retry_backoff': 2,
                'default_timeout': 30
            },
            'deepseek': {
                'api_key': 'test-api-key',
                'model': 'deepseek-ai/DeepSeek-V3',
                'base_url': 'https://api.test.com/v1/chat/completions',
                'timeout': 30,
                'max_tokens': 2048
            },
            'ollama': {
                'model': 'deepseek-r1:14b',
                'base_url': 'http://localhost:11434/api/chat',
                'timeout': 60
            }
        }

    @pytest.fixture
    def analyzer(self, mock_config):
        """创建AI分析器实例"""
        with patch('core.ai_analyzer.AIAnalyzer._init_http_session'):
            return AIAnalyzer(config_path='dummy_config.yaml')

    @pytest.fixture
    def analyzer_with_session(self, mock_config):
        """创建带有会话的AI分析器"""
        with patch('core.ai_analyzer.AIAnalyzer._load_config', return_value=mock_config):
            analyzer = AIAnalyzer(config_path='dummy_config.yaml')
            analyzer.session = MagicMock()
            return analyzer


class TestAIServiceErrors:
    """AI服务错误处理测试"""

    @pytest.fixture
    def analyzer(self):
        """创建测试用分析器"""
        config = {
            'ai': {
                'type': 'cloud',
                'cloud_provider': 'deepseek',
                'max_retries': 2,
                'retry_delay': 0.1  # 短延迟用于测试
            },
            'deepseek': {
                'api_key': 'test-key',
                'base_url': 'https://api.test.com/v1/chat/completions',
                'timeout': 10,
                'max_tokens': 1000
            }
        }
        with patch('core.ai_analyzer.AIAnalyzer._load_config', return_value=config):
            with patch('core.ai_analyzer.AIAnalyzer._init_http_session'):
                analyzer = AIAnalyzer(config_path='dummy')
                analyzer.session = MagicMock()
                return analyzer

    def test_authentication_error_401(self, analyzer):
        """测试401认证错误处理"""
        # 模拟401响应
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = 'Unauthorized'
        mock_response.raise_for_status.side_effect = Exception("HTTP 401")

        analyzer.session.post.return_value = mock_response

        with pytest.raises(AIAuthenticationError) as exc_info:
            analyzer._make_request_with_retry(
                'https://api.test.com',
                {'Authorization': 'Bearer test-key'},
                {'model': 'test'},
                10
            )

        assert '认证失败' in str(exc_info.value)
        assert exc_info.value.error_code == 'AUTHENTICATION_FAILED'

    def test_rate_limit_error_429(self, analyzer):
        """测试429频率限制错误处理"""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = 'Too Many Requests'
        mock_response.raise_for_status.side_effect = Exception("HTTP 429")

        analyzer.session.post.return_value = mock_response

        with pytest.raises(AIRateLimitError) as exc_info:
            analyzer._make_request_with_retry(
                'https://api.test.com',
                {'Authorization': 'Bearer test-key'},
                {'model': 'test'},
                10
            )

        assert '频率限制' in str(exc_info.value)
        assert exc_info.value.error_code == 'RATE_LIMIT'

    def test_service_unavailable_500(self, analyzer):
        """测试500服务器错误处理"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_response.raise_for_status.side_effect = Exception("HTTP 500")

        analyzer.session.post.return_value = mock_response

        with pytest.raises(AIServiceUnavailableError) as exc_info:
            analyzer._make_request_with_retry(
                'https://api.test.com',
                {'Authorization': 'Bearer test-key'},
                {'model': 'test'},
                10
            )

        assert '服务器错误' in str(exc_info.value)
        assert exc_info.value.error_code == 'SERVER_ERROR'

    def test_connection_error(self, analyzer):
        """测试连接错误处理"""
        from requests.exceptions import ConnectionError

        analyzer.session.post.side_effect = ConnectionError("Connection refused")

        with pytest.raises(AIServiceUnavailableError) as exc_info:
            analyzer._make_request_with_retry(
                'https://api.test.com',
                {'Authorization': 'Bearer test-key'},
                {'model': 'test'},
                10
            )

        assert '无法连接' in str(exc_info.value)
        assert exc_info.value.error_code == 'CONNECTION_ERROR'

    def test_timeout_error(self, analyzer):
        """测试超时错误处理"""
        from requests.exceptions import Timeout

        analyzer.session.post.side_effect = Timeout("Request timeout")

        with pytest.raises(AIServiceUnavailableError) as exc_info:
            analyzer._make_request_with_retry(
                'https://api.test.com',
                {'Authorization': 'Bearer test-key'},
                {'model': 'test'},
                10
            )

        assert '请求超时' in str(exc_info.value)
        assert exc_info.value.error_code == 'TIMEOUT'


class TestCloudAICalls:
    """云端AI调用测试"""

    @pytest.fixture
    def analyzer(self):
        """创建配置好的分析器"""
        config = {
            'ai': {'type': 'cloud', 'cloud_provider': 'deepseek'},
            'deepseek': {
                'api_key': 'test-key',
                'base_url': 'https://api.test.com/v1/chat/completions',
                'timeout': 10,
                'max_tokens': 1000
            }
        }
        with patch('core.ai_analyzer.AIAnalyzer._load_config', return_value=config):
            with patch('core.ai_analyzer.AIAnalyzer._init_http_session'):
                analyzer = AIAnalyzer(config_path='dummy')
                analyzer.session = MagicMock()
                return analyzer

    def test_analyze_with_cloud_success(self, analyzer):
        """测试成功的云端AI分析"""
        # 模拟成功响应
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{
                'message': {
                    'content': 'AI分析结果：检测到SQL注入攻击'
                }
            }]
        }
        analyzer.session.post.return_value = mock_response

        result = analyzer._analyze_with_cloud('测试日志内容')

        assert result == 'AI分析结果：检测到SQL注入攻击'
        analyzer.session.post.assert_called_once()

    def test_analyze_with_cloud_no_api_key(self, analyzer):
        """测试缺少API密钥的情况"""
        analyzer.api_key = ''

        with pytest.raises(AIAuthenticationError) as exc_info:
            analyzer._analyze_with_cloud('测试日志内容')

        assert '未配置API密钥' in str(exc_info.value)

    def test_analyze_with_cloud_invalid_response(self, analyzer):
        """测试无效响应格式"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'invalid_format': 'missing choices field'
        }
        analyzer.session.post.return_value = mock_response

        with pytest.raises(AIServiceError) as exc_info:
            analyzer._analyze_with_cloud('测试日志内容')

        assert '响应格式异常' in str(exc_info.value)

    def test_analyze_with_cloud_empty_content(self, analyzer):
        """测试空内容响应"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{
                'message': {
                    'content': ''
                }
            }]
        }
        analyzer.session.post.return_value = mock_response

        with pytest.raises(AIServiceError) as exc_info:
            analyzer._analyze_with_cloud('测试日志内容')

        assert '内容为空' in str(exc_info.value)


class TestOllamaAICalls:
    """Ollama本地AI调用测试"""

    @pytest.fixture
    def analyzer(self):
        """创建配置好的Ollama分析器"""
        config = {
            'ai': {'type': 'local', 'local_provider': 'ollama'},
            'ollama': {
                'model': 'deepseek-r1:14b',
                'base_url': 'http://localhost:11434/api/chat',
                'timeout': 60
            }
        }
        with patch('core.ai_analyzer.AIAnalyzer._load_config', return_value=config):
            with patch('core.ai_analyzer.AIAnalyzer._init_http_session'):
                analyzer = AIAnalyzer(config_path='dummy')
                analyzer.session = MagicMock()
                analyzer.ai_type = 'local'
                analyzer.local_provider = 'ollama'
                return analyzer

    def test_analyze_with_ollama_success(self, analyzer):
        """测试成功的Ollama分析"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'message': {
                'content': '本地AI分析结果：检测到XSS攻击'
            }
        }
        analyzer.session.post.return_value = mock_response

        result = analyzer._analyze_with_ollama('测试日志内容')

        assert result == '本地AI分析结果：检测到XSS攻击'
        analyzer.session.post.assert_called_once()

    def test_analyze_with_ollama_invalid_response(self, analyzer):
        """测试Ollama无效响应"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'invalid_format': 'missing message field'
        }
        analyzer.session.post.return_value = mock_response

        with pytest.raises(AIServiceError) as exc_info:
            analyzer._analyze_with_ollama('测试日志内容')

        assert '响应格式异常' in str(exc_info.value)


class TestAnalyzeLogIntegration:
    """analyze_log集成测试"""

    @pytest.fixture
    def analyzer(self):
        """创建测试分析器"""
        config = {
            'ai': {'type': 'cloud', 'cloud_provider': 'deepseek'},
            'deepseek': {
                'api_key': 'test-key',
                'base_url': 'https://api.test.com/v1/chat/completions',
                'timeout': 10,
                'max_tokens': 1000
            }
        }
        with patch('core.ai_analyzer.AIAnalyzer._load_config', return_value=config):
            with patch('core.ai_analyzer.AIAnalyzer._init_http_session'):
                analyzer = AIAnalyzer(config_path='dummy')
                analyzer.session = MagicMock()
                return analyzer

    def test_analyze_log_with_empty_context(self, analyzer):
        """测试空日志上下文"""
        result = analyzer.analyze_log('')
        assert '无有效日志内容' in result

    def test_analyze_log_with_whitespace_only(self, analyzer):
        """测试仅包含空白的日志"""
        result = analyzer.analyze_log('   \\t\\n   ')
        assert '无有效日志内容' in result

    def test_analyze_log_with_long_context_truncation(self, analyzer):
        """测试长日志上下文截断"""
        long_context = 'A' * 6000
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{
                'message': {'content': '分析结果'}
            }]
        }
        analyzer.session.post.return_value = mock_response

        analyzer.analyze_log(long_context)

        # 验证调用时使用的上下文被截断
        call_args = analyzer.session.post.call_args
        prompt = call_args[1]['json']['messages'][0]['content']
        assert len(prompt) < 5500  # 应该被截断

    def test_analyze_log_with_fallback_on_error(self, analyzer):
        """测试错误时使用备用分析"""
        # 模拟所有重试都失败
        from requests.exceptions import ConnectionError
        analyzer.session.post.side_effect = ConnectionError("Connection failed")

        result = analyzer.analyze_log('测试日志', attack_category='injection', threat_score=7.0)

        # 应该返回备用分析结果
        assert 'SQL注入攻击分析' in result or '安全威胁分析' in result
        assert '威胁评分' in result

    def test_analyze_log_with_threat_score(self, analyzer):
        """测试带威胁评分的分析"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{
                'message': {'content': '高威胁评分分析结果'}
            }]
        }
        analyzer.session.post.return_value = mock_response

        result = analyzer.analyze_log('测试日志', threat_score=8.5)

        # 验证威胁评分信息包含在请求中
        call_args = analyzer.session.post.call_args
        prompt = call_args[1]['json']['messages'][0]['content']
        assert '威胁评分' in prompt
        assert '8.5' in prompt
        assert '紧急' in prompt


class TestSpecializedPrompts:
    """专用AI提示词测试"""

    @pytest.fixture
    def analyzer(self):
        """创建测试分析器"""
        config = {
            'ai': {'type': 'cloud', 'cloud_provider': 'deepseek'},
            'deepseek': {
                'api_key': 'test-key',
                'base_url': 'https://api.test.com/v1/chat/completions'
            }
        }
        with patch('core.ai_analyzer.AIAnalyzer._load_config', return_value=config):
            with patch('core.ai_analyzer.AIAnalyzer._init_http_session'):
                return AIAnalyzer(config_path='dummy')

    def test_injection_attack_prompt(self, analyzer):
        """测试SQL注入攻击专用提示词"""
        prompt = analyzer._get_attack_specific_prompt(
            '测试日志',
            attack_category='injection'
        )
        assert '数据库安全专家' in prompt
        assert 'SQL注入攻击' in prompt
        assert '注入类型' in prompt

    def test_xss_attack_prompt(self, analyzer):
        """测试XSS攻击专用提示词"""
        prompt = analyzer._get_attack_specific_prompt(
            '测试日志',
            attack_category='xss'
        )
        assert 'Web应用安全专家' in prompt
        assert 'XSS攻击' in prompt
        assert '跨站脚本' in prompt

    def test_rce_attack_prompt(self, analyzer):
        """测试RCE攻击专用提示词"""
        prompt = analyzer._get_attack_specific_prompt(
            '测试日志',
            attack_category='rce'
        )
        assert '系统安全专家' in prompt
        assert '远程代码执行' in prompt
        assert '代码执行' in prompt

    def test_attack_name_inference(self, analyzer):
        """测试从攻击名称推断类别"""
        prompt = analyzer._get_attack_specific_prompt(
            '测试日志',
            attack_name='SQL Injection Attack'
        )
        assert '数据库安全专家' in prompt

    def test_generic_prompt(self, analyzer):
        """测试通用提示词"""
        prompt = analyzer._get_attack_specific_prompt(
            '测试日志',
            attack_category='unknown_category'
        )
        assert '攻击技术分析' in prompt
        assert '影响范围评估' in prompt


class TestCustomCloudProvider:
    """自定义 OpenAI 兼容云端 provider 测试 (cloud_provider='custom')"""

    @pytest.fixture
    def analyzer(self):
        """创建配置为 custom provider 的分析器"""
        config = {
            'ai': {'type': 'cloud', 'cloud_provider': 'custom'},
            'custom': {
                'api_key': 'custom-key',
                'base_url': 'https://api.openai.com/v1',
                'model': 'gpt-4o-mini',
                'timeout': 15,
                'max_tokens': 500
            }
        }
        with patch('core.ai_analyzer.AIAnalyzer._load_config', return_value=config):
            with patch('core.ai_analyzer.AIAnalyzer._init_http_session'):
                return AIAnalyzer(config_path='dummy')

    def test_custom_provider_config_loaded(self, analyzer):
        """custom provider 正确加载 custom: 配置段"""
        assert analyzer.cloud_provider == 'custom'
        assert analyzer.cloud_model == 'gpt-4o-mini'
        assert analyzer.cloud_base_url == 'https://api.openai.com/v1'
        assert analyzer.api_key == 'custom-key'
        assert analyzer.cloud_max_tokens == 500
        assert analyzer.cloud_timeout == 15

    def test_custom_chat_and_models_url_derivation(self, analyzer):
        """base_url 为 base 形式时派生正确的 chat / models 端点"""
        assert analyzer._chat_url() == 'https://api.openai.com/v1/chat/completions'
        assert analyzer._models_url() == 'https://api.openai.com/v1/models'

    @patch('core.ai_analyzer.requests.post')
    def test_analyze_with_custom_success(self, mock_post, analyzer):
        """自定义 provider 成功调用云端分析（mock requests.post，避免真实网络）"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            'choices': [{'message': {'content': '自定义分析结果'}}]
        }
        mock_post.return_value = mock_response

        result = analyzer._analyze_with_cloud('测试日志内容')

        assert result == '自定义分析结果'
        mock_post.assert_called_once()
        # 请求 URL 应为派生的 chat 端点
        assert mock_post.call_args.args[0] == 'https://api.openai.com/v1/chat/completions'
        # payload 应使用 custom 的 model 与 max_tokens
        payload = mock_post.call_args.kwargs['json']
        assert payload['model'] == 'gpt-4o-mini'
        assert payload['max_tokens'] == 500

    @patch('core.ai_analyzer.requests.post')
    def test_analyze_with_custom_no_api_key(self, mock_post, analyzer):
        """custom provider 缺少 api_key 时抛出认证错误"""
        analyzer.api_key = ''
        with pytest.raises(AIAuthenticationError):
            analyzer._analyze_with_cloud('测试日志内容')
        mock_post.assert_not_called()


class TestFetchAvailableModels:
    """fetch_available_models 模块函数测试"""

    @patch('core.ai_analyzer.requests.get')
    def test_fetch_models_success(self, mock_get):
        """成功拉取模型列表，并带 Bearer 认证"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            'data': [{'id': 'gpt-4o'}, {'id': 'gpt-4o-mini'}, {'no_id': True}]
        }
        mock_get.return_value = mock_response

        models = fetch_available_models('https://api.openai.com/v1', api_key='sk-xxx')

        assert models == ['gpt-4o', 'gpt-4o-mini']
        # URL 派生为 /models
        assert mock_get.call_args.args[0] == 'https://api.openai.com/v1/models'
        # 请求头带 Bearer
        assert mock_get.call_args.kwargs['headers']['Authorization'] == 'Bearer sk-xxx'

    @patch('core.ai_analyzer.requests.get')
    def test_fetch_models_from_full_chat_url(self, mock_get):
        """base_url 为完整 chat 地址时也能正确派生 /models"""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {'data': [{'id': 'm1'}]}
        mock_get.return_value = mock_response

        models = fetch_available_models('https://api.siliconflow.cn/v1/chat/completions')

        assert models == ['m1']
        assert mock_get.call_args.args[0] == 'https://api.siliconflow.cn/v1/models'

    def test_fetch_models_empty_url(self):
        """空 base_url 返回空列表"""
        assert fetch_available_models('') == []

    @patch('core.ai_analyzer.requests.get')
    def test_fetch_models_failure_returns_empty(self, mock_get):
        """网络/HTTP 错误时返回空列表，不抛异常"""
        mock_get.side_effect = requests.exceptions.ConnectionError('boom')
        assert fetch_available_models('https://api.openai.com/v1') == []

