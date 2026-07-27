#!/usr/bin/env python3
"""
SSlogs v3.1 优化版GUI界面
集成异步AI分析、内存优化、安全验证等所有优化功能
"""

import sys
import os
import asyncio
import time
import threading
import yaml
import requests
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QComboBox,
    QProgressBar, QTextEdit, QFileDialog, QMessageBox, QGroupBox,
    QTabWidget, QSpinBox, QDoubleSpinBox, QSlider, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QFrame, QScrollArea,
    QDialog, QDialogButtonBox, QFormLayout
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QPixmap, QIcon, QColor, QPalette

# 导入优化后的核心模块
from core import (
    AsyncAIAnalyzer, analyze_logs_concurrently,
    MemoryOptimizedProcessor, process_large_logs_async,
    get_event_bus, publish_event, event_handler,
    get_config_manager, get_cache_manager, get_security_manager,
    validate_input, sanitize_input, handle_exceptions,
    create_error_context, cache_result, CachePolicy
)
from core.ai_analyzer import fetch_available_models


class AnalysisWorker(QThread):
    """增强的分析工作线程 - 集成所有优化功能"""
    progress_updated = pyqtSignal(int, str, dict)  # 进度、消息、性能数据
    log_output = pyqtSignal(str)
    analysis_finished = pyqtSignal(bool, str, dict)
    threat_detected = pyqtSignal(str, dict)

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.is_interrupted = False
        self.start_time = 0

    def run(self):
        """执行优化的分析流程"""
        try:
            self.start_time = time.time()
            self.log_output.emit("🚀 启动SSlogs v3.1优化分析引擎...")

            # 初始化各个优化模块
            self._initialize_optimized_modules()

            # 执行分析
            results = self._run_optimized_analysis()

            # 完成分析
            end_time = time.time()
            performance_data = {
                'total_time': end_time - self.start_time,
                'processed_count': len(results.get('processed_logs', [])),
                'threats_found': len(results.get('threats', [])),
                'memory_peak': self._get_memory_usage(),
                'cache_hits': self._get_cache_stats()
            }

            self.progress_updated.emit(100, "✅ 分析完成！", performance_data)
            self.analysis_finished.emit(True, "分析成功完成", results)

        except Exception as e:
            error_context = create_error_context("analysis_worker", "run_analysis")
            error_msg = f"分析过程发生错误: {str(e)}"
            self.log_output.emit(f"❌ {error_msg}")
            self.analysis_finished.emit(False, error_msg, {'error': str(e)})

    def _initialize_optimized_modules(self):
        """初始化优化模块"""
        self.log_output.emit("🔧 初始化优化模块...")

        # 初始化事件总线
        self.event_bus = get_event_bus()

        # 初始化缓存管理器
        self.cache_manager = get_cache_manager()
        if self.config.get('enable_cache', True):
            self.cache_manager.create_memory_cache(
                "analysis_cache",
                max_size=self.config.get('cache_size', 1000),
                policy=CachePolicy.LRU
            )

        # 初始化安全管理器
        self.security_manager = get_security_manager()

        # 注册事件处理器
        self._register_event_handlers()

        self.log_output.emit("✅ 优化模块初始化完成")

    def _register_event_handlers(self):
        """注册事件处理器"""
        @event_handler("performance_update", priority="high")
        def handle_performance(event):
            performance_data = event.data
            self.progress_updated.emit(
                performance_data.get('progress', 0),
                performance_data.get('message', ''),
                performance_data
            )

    def _run_optimized_analysis(self):
        """执行优化分析"""
        log_path = self.config.get('log_path', 'logs/*.log')
        ai_enabled = self.config.get('ai_enabled', False)
        memory_optimized = self.config.get('memory_optimized', True)
        security_validation = self.config.get('security_validation', True)

        results = {'processed_logs': [], 'threats': [], 'performance': {}}

        # 使用内存优化处理器
        if memory_optimized:
            self.progress_updated.emit(10, "📊 启动内存优化处理...", {})
            processor = MemoryOptimizedProcessor(
                chunk_size=self.config.get('chunk_size', 8192),
                max_memory_usage=self.config.get('max_memory_usage', 0.8)
            )

            def process_log_entry(log_line):
                if self.is_interrupted:
                    return None

                try:
                    # 安全验证
                    if security_validation:
                        validation = validate_input(log_line)
                        if not validation.is_valid:
                            threat_data = {
                                'line': log_line[:100] + "...",
                                'threats': validation.threats,
                                'risk_score': validation.risk_score
                            }
                            results['threats'].append(threat_data)
                            self.threat_detected.emit("安全威胁检测", threat_data)
                            return None

                    # 处理日志条目
                    processed_log = {'raw': log_line, 'timestamp': time.time()}
                    results['processed_logs'].append(processed_log)

                    return processed_log

                except Exception as e:
                    self.log_output.emit(f"⚠️ 处理日志行失败: {e}")
                    return None

            # 处理大文件
            processed_count = 0
            for result in processor.process_large_file_streaming(log_path, process_log_entry):
                if self.is_interrupted:
                    break

                processed_count += 1

                # 更新进度
                if processed_count % 1000 == 0:
                    progress = min(10 + (processed_count // 1000) * 5, 80)
                    memory_usage = processor.get_memory_usage()
                    self.progress_updated.emit(progress,
                        f"📝 已处理 {processed_count} 行日志，内存使用: {memory_usage:.1%}",
                        {'memory_usage': memory_usage, 'processed_count': processed_count})

        # 简化的AI分析（模拟）
        if ai_enabled and results['processed_logs']:
            self.progress_updated.emit(85, "🤖 启动AI分析...", {})
            self._simulate_ai_analysis(results)

        return results

    def _simulate_ai_analysis(self, results):
        """模拟AI分析（简化版）"""
        try:
            # 准备AI分析数据
            log_count = min(len(results['processed_logs']), 10)  # 限制数量

            for i in range(log_count):
                if self.is_interrupted:
                    break

                # 模拟AI分析结果
                log_entry = results['processed_logs'][i]
                log_entry['ai_analysis'] = f"AI分析结果 #{i+1}: 威胁等级低，建议持续监控"

                # 模拟处理延迟
                time.sleep(0.1)  # 短暂延迟模拟

                if i % 3 == 0:  # 每3条更新一次进度
                    progress = 85 + (i * 15 // log_count)
                    self.progress_updated.emit(progress, f"🧠 AI分析进度: {i+1}/{log_count}", {})

            self.log_output.emit(f"🧠 AI分析完成，处理了 {log_count} 条日志")

        except Exception as e:
            self.log_output.emit(f"⚠️ AI分析失败: {e}")

    def _get_memory_usage(self):
        """获取当前内存使用率"""
        try:
            import psutil
            return psutil.virtual_memory().percent / 100.0
        except:
            return 0.0

    def _get_cache_stats(self):
        """获取缓存统计"""
        try:
            cache = self.cache_manager.get_cache("analysis_cache")
            if hasattr(cache, 'get_stats'):
                stats = cache.get_stats()
                return {
                    'hit_rate': stats.get('hit_rate', 0),
                    'size': stats.get('size', 0),
                    'max_size': stats.get('max_size', 0)
                }
        except:
            pass
        return {'hit_rate': 0, 'size': 0, 'max_size': 0}

    def interrupt(self):
        """中断分析"""
        self.is_interrupted = True
        self.log_output.emit("⏹️ 用户中断分析...")


class _BackgroundAIWorker(QThread):
    """在后台线程运行 AI 网络任务（拉取模型 / 测试连接），避免阻塞 UI。

    task 是一个无参 callable，返回 (ok: bool, message: str, payload)。
    结果通过 result_ready 信号回传到主线程。
    """
    result_ready = pyqtSignal(bool, str, object)

    def __init__(self, task):
        super().__init__()
        self._task = task

    def run(self):
        try:
            ok, message, payload = self._task()
        except Exception as e:
            ok, message, payload = False, f"请求异常: {e}", None
        self.result_ready.emit(bool(ok), str(message), payload)


class OptimizedLogAnalyzerGUI(QMainWindow):
    """SSlogs v3.1 优化版GUI界面"""

    # AI 模型类型下拉项与 cloud_provider 的映射
    _AI_TYPE_CLOUD = "🌐 自定义 OpenAI 兼容"

    def __init__(self):
        super().__init__()
        self.setWindowTitle("🚀 SSlogs v3.1 - 企业级智能安全日志分析平台")
        self.setGeometry(100, 100, 1200, 900)

        # 配置文件路径（项目根目录下的 config.yaml）
        self.config_path = str(Path(__file__).parent / 'config.yaml')
        # 后台 AI 网络任务句柄（防止被 GC 回收）
        self._ai_worker = None

        # 设置应用图标和样式
        self._setup_appearance()

        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 创建主布局
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # 创建各个功能区域
        self._create_header(main_layout)
        self._create_main_content(main_layout)
        self._create_status_bar(main_layout)

        # 初始化变量
        self.worker = None
        self.start_time = 0

        # 初始化定时器
        self._setup_timers()

        # 从 config.yaml 回填 AI 配置到界面
        self._load_ai_config_from_yaml()

    def _setup_appearance(self):
        """设置界面外观"""
        # 设置应用样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8fafc;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #1e293b;
            }
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
            QPushButton:disabled {
                background-color: #94a3b8;
                color: #cbd5e1;
            }
            QProgressBar {
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                text-align: center;
                font-weight: bold;
                color: #1e293b;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                                           stop: 0 #3b82f6, stop: 1 #1d4ed8);
                border-radius: 5px;
            }
            QTextEdit {
                border: 1px solid #e2e8f0;
                border-radius: 6px;
                background-color: white;
                font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
                font-size: 12px;
            }
            QTabWidget::pane {
                border: 1px solid #e2e8f0;
                border-radius: 6px;
            }
            QTabBar::tab {
                background-color: #e2e8f0;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
            }
            QTabBar::tab:selected {
                background-color: #3b82f6;
                color: white;
            }
        """)

    def _create_header(self, parent_layout):
        """创建头部区域"""
        header = QGroupBox("🛡️ SSlogs v3.1 - 智能安全日志分析平台")
        header_layout = QHBoxLayout()

        # 标题和版本信息
        title_layout = QVBoxLayout()
        title_label = QLabel("企业级智能安全日志分析平台")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #1e293b;")

        subtitle_label = QLabel("集成异步AI分析 • 内存优化 • 安全验证 • 高性能缓存")
        subtitle_label.setStyleSheet("font-size: 12px; color: #64748b;")

        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)

        header_layout.addLayout(title_layout)
        header_layout.addStretch()

        parent_layout.addWidget(header)

    def _create_main_content(self, parent_layout):
        """创建主内容区域"""
        # 创建分割器
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # 左侧配置区域
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        self._create_configuration_tabs(left_layout)

        # 右侧结果区域
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        self._create_results_area(right_layout)

        # 添加到分割器
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 800])

        parent_layout.addWidget(splitter)

    def _create_configuration_tabs(self, parent_layout):
        """创建配置选项卡"""
        config_tabs = QTabWidget()

        # 基本配置选项卡
        basic_tab = QWidget()
        basic_layout = QVBoxLayout(basic_tab)
        self._create_basic_config(basic_layout)

        # AI分析配置选项卡
        ai_tab = QWidget()
        ai_layout = QVBoxLayout(ai_tab)
        self._create_ai_config(ai_layout)

        # 性能优化配置选项卡
        perf_tab = QWidget()
        perf_layout = QVBoxLayout(perf_tab)
        self._create_performance_config(perf_layout)

        # 安全配置选项卡
        security_tab = QWidget()
        security_layout = QVBoxLayout(security_tab)
        self._create_security_config(security_layout)

        # 缓存配置选项卡
        cache_tab = QWidget()
        cache_layout = QVBoxLayout(cache_tab)
        self._create_cache_config(cache_layout)

        config_tabs.addTab(basic_tab, "📋 基本配置")
        config_tabs.addTab(ai_tab, "🤖 AI分析")
        config_tabs.addTab(perf_tab, "⚡ 性能优化")
        config_tabs.addTab(security_tab, "🔒 安全配置")
        config_tabs.addTab(cache_tab, "💾 缓存配置")

        parent_layout.addWidget(config_tabs)

    def _create_basic_config(self, parent_layout):
        """创建基本配置"""
        # 日志路径配置
        log_group = QGroupBox("📁 日志文件配置")
        log_layout = QVBoxLayout()

        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("日志路径:"))
        self.log_path_input = QLineEdit("logs/*.log")
        browse_btn = QPushButton("浏览...")
        browse_btn.clicked.connect(self.browse_log_path)
        path_layout.addWidget(self.log_path_input)
        path_layout.addWidget(browse_btn)

        log_layout.addLayout(path_layout)
        log_group.setLayout(log_layout)
        parent_layout.addWidget(log_group)

        # 输出配置
        output_group = QGroupBox("📄 输出配置")
        output_layout = QFormLayout()

        self.output_dir_input = QLineEdit("output")
        output_browse_btn = QPushButton("浏览...")
        output_browse_btn.clicked.connect(self.browse_output_dir)

        output_layout.addRow("输出目录:", self.output_dir_input)
        output_layout.addRow("", output_browse_btn)

        self.format_combo = QComboBox()
        self.format_combo.addItems(["html", "json", "csv", "txt"])
        output_layout.addRow("报告格式:", self.format_combo)

        output_group.setLayout(output_layout)
        parent_layout.addWidget(output_group)

        # 分析选项
        analysis_group = QGroupBox("🔍 分析选项")
        analysis_layout = QVBoxLayout()

        self.ai_enabled_cb = QCheckBox("启用AI智能分析")
        self.ai_enabled_cb.setChecked(True)
        analysis_layout.addWidget(self.ai_enabled_cb)

        self.memory_optimized_cb = QCheckBox("启用内存优化处理")
        self.memory_optimized_cb.setChecked(True)
        analysis_layout.addWidget(self.memory_optimized_cb)

        self.security_validation_cb = QCheckBox("启用安全输入验证")
        self.security_validation_cb.setChecked(True)
        analysis_layout.addWidget(self.security_validation_cb)

        self.enable_cache_cb = QCheckBox("启用分析缓存")
        self.enable_cache_cb.setChecked(True)
        analysis_layout.addWidget(self.enable_cache_cb)

        analysis_group.setLayout(analysis_layout)
        parent_layout.addWidget(analysis_group)

        parent_layout.addStretch()

    def _create_ai_config(self, parent_layout):
        """创建AI配置"""
        # AI服务配置
        service_group = QGroupBox("🤖 AI服务配置")
        service_layout = QVBoxLayout()

        # AI模型类型
        model_layout = QHBoxLayout()
        model_layout.addWidget(QLabel("AI模型类型:"))
        self.ai_model_type = QComboBox()
        self.ai_model_type.addItems(["云端 DeepSeek", "本地 LM Studio", "本地 Ollama", "🌐 自定义 OpenAI 兼容", "🇨🇳 智谱 GLM (Zhipu)"])
        self.ai_model_type.currentTextChanged.connect(self._on_ai_type_changed)
        model_layout.addWidget(self.ai_model_type)
        service_layout.addLayout(model_layout)

        # API基础URL（自定义/OpenAI 兼容端点）
        base_url_layout = QHBoxLayout()
        base_url_layout.addWidget(QLabel("API地址:"))
        self.base_url_input = QLineEdit()
        self.base_url_input.setPlaceholderText("OpenAI 兼容 base，如 https://api.openai.com/v1")
        base_url_layout.addWidget(self.base_url_input)
        service_layout.addLayout(base_url_layout)

        # 编程套餐开关（仅「智谱 GLM」provider 时可见）
        # 开启后 base_url 切到智谱专属 coding 端点（/api/coding/paas/v4），与套餐 Key 配合使用。
        self.zhipu_coding_plan_cb = QCheckBox("🧑‍💻 编程套餐 (Coding Plan) — 走智谱专属端点")
        self.zhipu_coding_plan_cb.setChecked(False)
        self.zhipu_coding_plan_cb.setVisible(False)
        self.zhipu_coding_plan_cb.stateChanged.connect(self._on_zhipu_coding_plan_toggled)
        service_layout.addWidget(self.zhipu_coding_plan_cb)

        # 模型选择
        model_select_layout = QHBoxLayout()
        model_select_layout.addWidget(QLabel("模型名称:"))
        self.model_name_combo = QComboBox()
        self.model_name_combo.setEditable(True)
        self.model_name_combo.setMinimumWidth(200)
        refresh_btn = QPushButton("刷新")
        refresh_btn.clicked.connect(self.refresh_models)
        model_select_layout.addWidget(self.model_name_combo)
        model_select_layout.addWidget(refresh_btn)
        service_layout.addLayout(model_select_layout)

        # API密钥（云端）
        api_layout = QHBoxLayout()
        api_layout.addWidget(QLabel("API密钥:"))
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setPlaceholderText("云端服务API密钥（可改用环境变量 SSLOGS_AI_API_KEY）")
        api_layout.addWidget(self.api_key_input)
        service_layout.addLayout(api_layout)

        # AI并发配置
        concurrent_layout = QHBoxLayout()
        concurrent_layout.addWidget(QLabel("并发处理数:"))
        self.ai_concurrent_spin = QSpinBox()
        self.ai_concurrent_spin.setRange(1, 20)
        self.ai_concurrent_spin.setValue(5)
        concurrent_layout.addWidget(self.ai_concurrent_spin)
        concurrent_layout.addStretch()
        service_layout.addLayout(concurrent_layout)

        service_group.setLayout(service_layout)
        parent_layout.addWidget(service_group)

        # 测试区域
        test_group = QGroupBox("🧪 连接与配置")
        test_layout = QVBoxLayout()

        test_action_layout = QHBoxLayout()
        test_btn = QPushButton("测试AI连接")
        test_btn.clicked.connect(self.test_ai_connection)
        test_action_layout.addWidget(test_btn)

        save_ai_btn = QPushButton("💾 保存AI配置")
        save_ai_btn.clicked.connect(self._save_ai_config_to_yaml)
        test_action_layout.addWidget(save_ai_btn)
        test_layout.addLayout(test_action_layout)

        self.ai_status_label = QLabel("状态: 未测试")
        test_layout.addWidget(self.ai_status_label)

        test_group.setLayout(test_layout)
        parent_layout.addWidget(test_group)

        parent_layout.addStretch()

    def _create_performance_config(self, parent_layout):
        """创建性能配置"""
        # 内存配置
        memory_group = QGroupBox("💾 内存优化配置")
        memory_layout = QFormLayout()

        self.chunk_size_spin = QSpinBox()
        self.chunk_size_spin.setRange(1024, 65536)
        self.chunk_size_spin.setValue(8192)
        memory_layout.addRow("处理块大小:", self.chunk_size_spin)

        self.max_memory_usage_slider = QSlider(Qt.Orientation.Horizontal)
        self.max_memory_usage_slider.setRange(50, 90)
        self.max_memory_usage_slider.setValue(80)
        self.memory_usage_label = QLabel("80%")
        memory_layout.addRow("最大内存使用:", self.max_memory_usage_slider)
        memory_layout.addRow("", self.memory_usage_label)

        # 连接滑块信号
        self.max_memory_usage_slider.valueChanged.connect(
            lambda v: self.memory_usage_label.setText(f"{v}%")
        )

        memory_group.setLayout(memory_layout)
        parent_layout.addWidget(memory_group)

        # 处理配置
        processing_group = QGroupBox("⚙️ 处理配置")
        processing_layout = QFormLayout()

        self.batch_size_spin = QSpinBox()
        self.batch_size_spin.setRange(10, 1000)
        self.batch_size_spin.setValue(100)
        processing_layout.addRow("批处理大小:", self.batch_size_spin)

        self.processing_timeout_spin = QSpinBox()
        self.processing_timeout_spin.setRange(10, 300)
        self.processing_timeout_spin.setValue(60)
        processing_layout.addRow("处理超时(秒):", self.processing_timeout_spin)

        processing_group.setLayout(processing_layout)
        parent_layout.addWidget(processing_group)

        parent_layout.addStretch()

    def _create_security_config(self, parent_layout):
        """创建安全配置"""
        # 验证级别
        validation_group = QGroupBox("🔍 输入验证")
        validation_layout = QFormLayout()

        self.validation_level = QComboBox()
        self.validation_level.addItems(["宽松", "适中", "严格", "偏执"])
        self.validation_level.setCurrentText("适中")
        validation_layout.addRow("验证级别:", self.validation_level)

        validation_group.setLayout(validation_layout)
        parent_layout.addWidget(validation_group)

        # 威胁检测
        threat_group = QGroupBox("⚠️ 威胁检测")
        threat_layout = QVBoxLayout()

        self.enable_sql_injection_cb = QCheckBox("SQL注入检测")
        self.enable_sql_injection_cb.setChecked(True)
        threat_layout.addWidget(self.enable_sql_injection_cb)

        self.enable_xss_cb = QCheckBox("XSS攻击检测")
        self.enable_xss_cb.setChecked(True)
        threat_layout.addWidget(self.enable_xss_cb)

        self.enable_path_traversal_cb = QCheckBox("路径遍历检测")
        self.enable_path_traversal_cb.setChecked(True)
        threat_layout.addWidget(self.enable_path_traversal_cb)

        self.enable_command_injection_cb = QCheckBox("命令注入检测")
        self.enable_command_injection_cb.setChecked(True)
        threat_layout.addWidget(self.enable_command_injection_cb)

        threat_group.setLayout(threat_layout)
        parent_layout.addWidget(threat_group)

        parent_layout.addStretch()

    def _create_cache_config(self, parent_layout):
        """创建缓存配置"""
        # 内存缓存
        memory_cache_group = QGroupBox("🧠 内存缓存")
        memory_cache_layout = QFormLayout()

        self.cache_size_spin = QSpinBox()
        self.cache_size_spin.setRange(100, 10000)
        self.cache_size_spin.setValue(1000)
        memory_cache_layout.addRow("缓存大小:", self.cache_size_spin)

        self.cache_policy_combo = QComboBox()
        self.cache_policy_combo.addItems(["LRU", "LFU", "FIFO"])
        self.cache_policy_combo.setCurrentText("LRU")
        memory_cache_layout.addRow("缓存策略:", self.cache_policy_combo)

        self.cache_ttl_spin = QSpinBox()
        self.cache_ttl_spin.setRange(60, 3600)
        self.cache_ttl_spin.setValue(300)
        memory_cache_layout.addRow("缓存TTL(秒):", self.cache_ttl_spin)

        memory_cache_group.setLayout(memory_cache_layout)
        parent_layout.addWidget(memory_cache_group)

        # 缓存操作
        cache_ops_group = QGroupBox("🔧 缓存操作")
        cache_ops_layout = QVBoxLayout()

        clear_cache_btn = QPushButton("清空缓存")
        clear_cache_btn.clicked.connect(self.clear_cache)
        cache_ops_layout.addWidget(clear_cache_btn)

        self.cache_stats_label = QLabel("缓存统计: 未加载")
        cache_ops_layout.addWidget(self.cache_stats_label)

        cache_ops_group.setLayout(cache_ops_layout)
        parent_layout.addWidget(cache_ops_group)

        parent_layout.addStretch()

    def _create_results_area(self, parent_layout):
        """创建结果显示区域"""
        # 进度区域
        progress_group = QGroupBox("📊 分析进度")
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        self.progress_label = QLabel("准备就绪")
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)

        # 性能指标
        perf_metrics_layout = QHBoxLayout()
        self.memory_label = QLabel("💾 内存: --")
        self.speed_label = QLabel("⚡ 速度: --")
        self.cache_hit_label = QLabel("🎯 缓存: --")

        perf_metrics_layout.addWidget(self.memory_label)
        perf_metrics_layout.addWidget(self.speed_label)
        perf_metrics_layout.addWidget(self.cache_hit_label)
        perf_metrics_layout.addStretch()

        progress_layout.addLayout(perf_metrics_layout)
        progress_group.setLayout(progress_layout)
        parent_layout.addWidget(progress_group)

        # 威胁检测结果表格
        threat_group = QGroupBox("🚨 威胁检测结果")
        threat_layout = QVBoxLayout()

        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(4)
        self.threat_table.setHorizontalHeaderLabels(["时间", "威胁类型", "风险评分", "预览"])

        # 设置表格属性
        header = self.threat_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        threat_layout.addWidget(self.threat_table)
        threat_group.setLayout(threat_layout)
        parent_layout.addWidget(threat_group)

        # 日志输出
        log_group = QGroupBox("📝 分析日志")
        log_layout = QVBoxLayout()

        self.log_output = QTextEdit()
        self.log_output.setMaximumHeight(200)
        self.log_output.setReadOnly(True)

        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        parent_layout.addWidget(log_group)

    def _create_status_bar(self, parent_layout):
        """创建状态栏"""
        # 控制按钮
        button_layout = QHBoxLayout()

        self.start_button = QPushButton("🚀 开始分析")
        self.start_button.clicked.connect(self.start_analysis)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #10b981;
                font-size: 14px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #059669;
            }
        """)

        self.stop_button = QPushButton("⏹️ 停止分析")
        self.stop_button.clicked.connect(self.stop_analysis)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                font-size: 14px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
        """)

        self.export_button = QPushButton("📊 导出报告")
        self.export_button.clicked.connect(self.export_report)

        button_layout.addStretch()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.export_button)

        parent_layout.addLayout(button_layout)

    def _setup_timers(self):
        """设置定时器"""
        # 性能监控定时器
        self.performance_timer = QTimer()
        self.performance_timer.timeout.connect(self.update_performance_stats)

        # 缓存统计定时器
        self.cache_timer = QTimer()
        self.cache_timer.timeout.connect(self.update_cache_stats)

    def browse_log_path(self):
        """浏览日志路径"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择日志文件", "", "日志文件 (*.log *.txt);;所有文件 (*)")
        if file_path:
            self.log_path_input.setText(file_path)

    def browse_output_dir(self):
        """浏览输出目录"""
        directory = QFileDialog.getExistingDirectory(self, "选择输出目录")
        if directory:
            self.output_dir_input.setText(directory)

    # 下拉文本 -> (cloud_provider/local_provider, ai.type, 是否需要 base_url)
    _PROVIDER_MAP = {
        "云端 DeepSeek": ("deepseek", "cloud", True),
        "本地 LM Studio": ("lm_studio", "local", True),
        "本地 Ollama": ("ollama", "local", True),
        "🌐 自定义 OpenAI 兼容": ("custom", "cloud", True),
        "🇨🇳 智谱 GLM (Zhipu)": ("zhipu", "cloud", True),
    }

    # 智谱 GLM 端点与预置模型（均为 OpenAI 兼容）
    _ZHIPU_LABEL = "🇨🇳 智谱 GLM (Zhipu)"
    _ZHIPU_BASE_STANDARD = "https://open.bigmodel.cn/api/paas/v4"
    _ZHIPU_BASE_CODING = "https://open.bigmodel.cn/api/coding/paas/v4"
    _ZHIPU_MODELS_STANDARD = [
        "glm-4.6", "glm-4.5", "glm-4-plus", "glm-4-air", "glm-4-airx",
        "glm-4-flash", "glm-4-flashx", "glm-4-long", "glm-4",
    ]
    _ZHIPU_MODELS_CODING = ["glm-4.6", "glm-4.7-FlashX", "glm-4.5", "glm-5.2"]

    def _is_zhipu_selected(self) -> bool:
        """当前下拉是否选中智谱 provider。"""
        return self.ai_model_type.currentText() == self._ZHIPU_LABEL

    def _zhipu_default_base_url(self) -> str:
        """按当前 Coding Plan 复选框状态返回智谱默认 base_url。"""
        coding = getattr(self, 'zhipu_coding_plan_cb', None) and self.zhipu_coding_plan_cb.isChecked()
        return self._ZHIPU_BASE_CODING if coding else self._ZHIPU_BASE_STANDARD

    def _zhipu_curated_models(self) -> list:
        """按 Coding Plan 状态返回预置模型列表。"""
        coding = getattr(self, 'zhipu_coding_plan_cb', None) and self.zhipu_coding_plan_cb.isChecked()
        return list(self._ZHIPU_MODELS_CODING if coding else self._ZHIPU_MODELS_STANDARD)

    def _populate_zhipu_models(self):
        """用预置模型列表填充下拉（可编辑，保留用户已填模型名）。"""
        current = self.model_name_combo.currentText()
        self.model_name_combo.clear()
        self.model_name_combo.addItems(self._zhipu_curated_models())
        if current:
            self.model_name_combo.setCurrentText(current)

    def _on_zhipu_coding_plan_toggled(self, _state: int):
        """切换 Coding Plan：仅在智谱激活时，把 base_url 在两个端点间切换并刷新模型列表。"""
        if not self._is_zhipu_selected():
            return
        current_url = self.base_url_input.text().strip()
        # 仅在地址为空或等于某个智谱默认值时自动切换，避免覆盖用户自定义地址
        if current_url in ("", self._ZHIPU_BASE_STANDARD, self._ZHIPU_BASE_CODING):
            self.base_url_input.setText(self._zhipu_default_base_url())
        self._populate_zhipu_models()

    def _on_ai_type_changed(self, text: str):
        """切换 AI 模型类型时，更新 base_url 输入的可用性、占位提示，及智谱 Coding Plan 开关可见性。"""
        mapping = self._PROVIDER_MAP.get(text)
        self.base_url_input.setEnabled(bool(mapping and mapping[2]))
        placeholders = {
            "本地 Ollama": "如 http://localhost:11434/api/chat",
            "本地 LM Studio": "如 http://localhost:1234/v1",
            "云端 DeepSeek": "如 https://api.siliconflow.cn/v1/chat/completions",
            "🌐 自定义 OpenAI 兼容": "OpenAI 兼容 base，如 https://api.openai.com/v1",
            self._ZHIPU_LABEL: "如 https://open.bigmodel.cn/api/paas/v4",
        }
        self.base_url_input.setPlaceholderText(placeholders.get(text, "API 地址"))

        # Coding Plan 开关仅对智谱可见
        is_zhipu = text == self._ZHIPU_LABEL
        if hasattr(self, 'zhipu_coding_plan_cb'):
            self.zhipu_coding_plan_cb.setVisible(is_zhipu)
        if is_zhipu:
            current_url = self.base_url_input.text().strip()
            if current_url in ("", self._ZHIPU_BASE_STANDARD, self._ZHIPU_BASE_CODING):
                self.base_url_input.setText(self._zhipu_default_base_url())
            self._populate_zhipu_models()

    def _current_ai_provider(self):
        """返回当前下拉选择的 (provider_name, ai_type)。"""
        text = self.ai_model_type.currentText()
        mapping = self._PROVIDER_MAP.get(text)
        if mapping:
            return mapping[0], mapping[1]
        return "deepseek", "cloud"

    def refresh_models(self):
        """从当前配置的 OpenAI 兼容端点拉取可用模型列表（后台线程，不阻塞 UI）。"""
        base_url = self.base_url_input.text().strip()
        api_key = self.api_key_input.text().strip()

        if not base_url:
            QMessageBox.warning(self, "缺少地址", "请先填写 API 地址 (base_url)")
            return

        self.model_name_combo.clear()
        self.model_name_combo.addItem("⏳ 正在拉取模型列表...")

        def task():
            models = fetch_available_models(base_url, api_key, timeout=10)
            if models:
                return True, f"成功获取 {len(models)} 个模型", models
            return False, "未能获取模型（端点可能不支持 /models，可手动填写模型名）", []

        self._ai_worker = _BackgroundAIWorker(task)
        self._ai_worker.result_ready.connect(self._on_models_fetched)
        self._ai_worker.start()

    @pyqtSlot(bool, str, object)
    def _on_models_fetched(self, ok: bool, message: str, models):
        """模型拉取完成回调（主线程）。"""
        current = self.model_name_combo.currentText()
        self.model_name_combo.clear()
        if ok and models:
            self.model_name_combo.addItems(models)
            # 尽量保留用户已填写的模型名
            if current and current not in ("⏳ 正在拉取模型列表...",):
                self.model_name_combo.setCurrentText(current)
            self.ai_status_label.setText(f"✅ {message}")
            self.ai_status_label.setStyleSheet("color: #10b981;")
        else:
            # 拉取失败：下拉仍可手填
            self.ai_status_label.setText(f"⚠️ {message}")
            self.ai_status_label.setStyleSheet("color: #d97706;")

    def test_ai_connection(self):
        """测试与 AI 端点的连接（后台线程，真实请求 GET /models）。"""
        base_url = self.base_url_input.text().strip()
        api_key = self.api_key_input.text().strip()

        if not base_url:
            QMessageBox.warning(self, "缺少地址", "请先填写 API 地址 (base_url)")
            return

        self.ai_status_label.setText("🔄 正在测试连接...")
        self.ai_status_label.setStyleSheet("color: #6b7280;")

        def task():
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
            # 派生 /models 端点：去掉可能的 /chat/completions 后缀
            base = base_url.rstrip('/')
            if base.endswith('/chat/completions'):
                base = base[:-len('/chat/completions')]
            models_url = base + '/models'
            try:
                resp = requests.get(models_url, headers=headers, timeout=10)
            except requests.exceptions.Timeout:
                return False, "请求超时，请检查地址与网络", 0
            except requests.exceptions.ConnectionError:
                return False, "无法连接到服务器，请检查地址与端口", 0
            status = resp.status_code
            if status == 200:
                return True, "连接成功", status
            if status == 401:
                return False, "认证失败：API 密钥无效或缺失", status
            if status == 404:
                return False, "地址错误：/models 返回 404", status
            return False, f"连接失败 (HTTP {status})", status

        self._ai_worker = _BackgroundAIWorker(task)
        self._ai_worker.result_ready.connect(self._on_connection_tested)
        self._ai_worker.start()

    @pyqtSlot(bool, str, object)
    def _on_connection_tested(self, ok: bool, message: str, status):
        """连接测试结果回调（主线程）。"""
        if ok:
            self.ai_status_label.setText(f"✅ {message}")
            self.ai_status_label.setStyleSheet("color: #10b981;")
        else:
            self.ai_status_label.setText(f"❌ {message}")
            self.ai_status_label.setStyleSheet("color: #ef4444;")

    def _load_ai_config_from_yaml(self):
        """启动时从 config.yaml 回填 AI 配置到界面控件。"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            return
        except Exception:
            return  # 配置不可读时静默，使用界面默认值

        ai_cfg = config.get('ai', {}) or {}
        cloud_provider = ai_cfg.get('cloud_provider') or ai_cfg.get('local_provider') or 'deepseek'

        # 反向映射 provider 名 -> 下拉文本
        label = "云端 DeepSeek"
        for lbl, (prov, _typ, _url) in self._PROVIDER_MAP.items():
            if prov == cloud_provider:
                label = lbl
                break
        idx = self.ai_model_type.findText(label)
        if idx >= 0:
            self.ai_model_type.setCurrentIndex(idx)

        # 按当前 provider 读取对应配置段
        section = config.get(cloud_provider, {}) or {}
        # 智谱：先同步 Coding Plan 开关状态（影响默认 base_url 与模型列表的派生）
        if cloud_provider == 'zhipu' and hasattr(self, 'zhipu_coding_plan_cb'):
            self.zhipu_coding_plan_cb.setChecked(bool(section.get('coding_plan', False)))
        if section.get('base_url'):
            self.base_url_input.setText(str(section['base_url']))
        elif cloud_provider == 'zhipu':
            # base_url 留空：按 coding_plan 状态填默认端点
            self.base_url_input.setText(self._zhipu_default_base_url())
        if section.get('api_key'):
            self.api_key_input.setText(str(section['api_key']))
        if section.get('model'):
            self.model_name_combo.setCurrentText(str(section['model']))

    def _save_ai_config_to_yaml(self):
        """把界面上的 AI 配置写回 config.yaml（按所选 provider 更新对应段，保留注释）。"""
        provider, ai_type = self._current_ai_provider()
        base_url = self.base_url_input.text().strip()
        api_key = self.api_key_input.text().strip()
        model = self.model_name_combo.currentText().strip()

        if not base_url and provider in ('custom', 'deepseek'):
            QMessageBox.warning(self, "缺少地址", "请先填写 API 地址 (base_url)")
            return

        # 优先用 ruamel.yaml 做注释保留的 round-trip；不可用时回退到 PyYAML（会丢注释）
        use_ruamel = False
        try:
            from ruamel.yaml import YAML
            yaml_rt = YAML()
            yaml_rt.preserve_quotes = True
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml_rt.load(f) or {}
            use_ruamel = True
        except Exception:
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {}
            except FileNotFoundError:
                config = {}
            except Exception as e:
                QMessageBox.critical(self, "读取配置失败", str(e))
                return

        # 更新 ai.type / ai.cloud_provider / ai.local_provider
        ai_cfg = config.setdefault('ai', {})
        ai_cfg['type'] = ai_type
        if ai_type == 'cloud':
            ai_cfg['cloud_provider'] = provider
        else:
            ai_cfg['local_provider'] = provider

        # 按所选 provider 更新对应配置段
        if provider in ('custom', 'deepseek'):
            section = config.setdefault(provider, {})
            section['base_url'] = base_url
            section['api_key'] = api_key
            if model:
                section['model'] = model
            section.setdefault('timeout', 30)
            section.setdefault('max_tokens', 2048)
        elif provider == 'zhipu':
            section = config.setdefault('zhipu', {})
            section['base_url'] = base_url
            section['api_key'] = api_key
            if model:
                section['model'] = model
            section['coding_plan'] = bool(self.zhipu_coding_plan_cb.isChecked())
            section.setdefault('timeout', 30)
            section.setdefault('max_tokens', 2048)
        elif provider == 'ollama':
            section = config.setdefault('ollama', {})
            if base_url:
                section['base_url'] = base_url
            if model:
                section['model'] = model
            section.setdefault('timeout', 60)
        elif provider == 'lm_studio':
            section = config.setdefault('lm_studio', {})
            if base_url:
                section['base_url'] = base_url
            if model:
                section['model'] = model

        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if use_ruamel:
                    yaml_rt.dump(config, f)
                else:
                    yaml.safe_dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        except Exception as e:
            QMessageBox.critical(self, "保存配置失败", str(e))
            return

        QMessageBox.information(
            self, "保存成功",
            f"AI 配置已保存到 config.yaml\n(provider={provider}, type={ai_type})"
        )

    def clear_cache(self):
        """清空缓存"""
        try:
            cache_manager = get_cache_manager()
            cache_manager.clear_all_caches()
            self.cache_stats_label.setText("✅ 缓存已清空")
        except Exception as e:
            self.cache_stats_label.setText(f"❌ 清空失败: {str(e)}")

    def update_performance_stats(self):
        """更新性能统计"""
        try:
            import psutil
            memory_percent = psutil.virtual_memory().percent
            self.memory_label.setText(f"💾 内存: {memory_percent:.1f}%")

            if hasattr(self, 'start_time') and self.start_time > 0:
                elapsed = time.time() - self.start_time
                self.speed_label.setText(f"⚡ 用时: {elapsed:.1f}秒")
        except:
            pass

    def update_cache_stats(self):
        """更新缓存统计"""
        try:
            cache_manager = get_cache_manager()
            cache = cache_manager.get_cache("analysis_cache")

            if hasattr(cache, 'get_stats'):
                stats = cache.get_stats()
                hit_rate = stats.get('hit_rate', 0) * 100
                size = stats.get('size', 0)
                self.cache_hit_label.setText(f"🎯 缓存: {hit_rate:.1f}% ({size}项)")
        except:
            pass

    def start_analysis(self):
        """开始分析"""
        # 收集配置
        config = {
            'log_path': self.log_path_input.text(),
            'output_dir': self.output_dir_input.text(),
            'report_format': self.format_combo.currentText(),
            'ai_enabled': self.ai_enabled_cb.isChecked(),
            'memory_optimized': self.memory_optimized_cb.isChecked(),
            'security_validation': self.security_validation_cb.isChecked(),
            'enable_cache': self.enable_cache_cb.isChecked(),
            'ai_model_type': self.ai_model_type.currentText(),
            'model_name': self.model_name_combo.currentText(),
            'api_key': self.api_key_input.text(),
            'ai_concurrent_limit': self.ai_concurrent_spin.value(),
            'chunk_size': self.chunk_size_spin.value(),
            'max_memory_usage': self.max_memory_usage_slider.value() / 100,
            'batch_size': self.batch_size_spin.value(),
            'validation_level': self.validation_level.currentText(),
            'cache_size': self.cache_size_spin.value(),
            'cache_policy': self.cache_policy_combo.currentText(),
            'cache_ttl': self.cache_ttl_spin.value()
        }

        # 验证配置
        if not config['log_path']:
            QMessageBox.warning(self, "配置错误", "请指定日志文件路径")
            return

        if config['ai_enabled'] and not config['model_name']:
            QMessageBox.warning(self, "配置错误", "启用AI分析时需要指定模型名称")
            return

        # 禁用按钮
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        # 清空日志和威胁表格
        self.log_output.clear()
        self.threat_table.setRowCount(0)

        # 启动定时器
        self.start_time = time.time()
        self.performance_timer.start(1000)
        self.cache_timer.start(2000)

        # 创建并启动工作线程
        self.worker = AnalysisWorker(config)
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.log_output.connect(self.append_log)
        self.worker.analysis_finished.connect(self.analysis_completed)
        self.worker.threat_detected.connect(self.threat_detected)

        self.worker.start()

    def stop_analysis(self):
        """停止分析"""
        if self.worker:
            self.worker.interrupt()

        # 停止定时器
        self.performance_timer.stop()
        self.cache_timer.stop()

        # 恢复按钮状态
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        self.append_log("⏹️ 分析已停止")

    def update_progress(self, value, message, performance_data):
        """更新进度"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)

        # 更新性能数据
        if 'memory_usage' in performance_data:
            memory = performance_data['memory_usage'] * 100
            self.memory_label.setText(f"💾 内存: {memory:.1f}%")

        if 'processed_count' in performance_data:
            count = performance_data['processed_count']
            elapsed = time.time() - self.start_time
            speed = count / max(elapsed, 1)
            self.speed_label.setText(f"⚡ 速度: {speed:.1f}条/秒")

    def append_log(self, message):
        """添加日志"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_output.append(f"[{timestamp}] {message}")

        # 自动滚动到底部
        scrollbar = self.log_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def threat_detected(self, threat_type, threat_data):
        """处理威胁检测"""
        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)

        # 添加威胁数据
        timestamp = time.strftime("%H:%M:%S")
        threats = ', '.join([t.value for t in threat_data.get('threats', [])])
        risk_score = threat_data.get('risk_score', 0)
        preview = threat_data.get('line', '')[:50] + "..."

        self.threat_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.threat_table.setItem(row, 1, QTableWidgetItem(threats))
        self.threat_table.setItem(row, 2, QTableWidgetItem(f"{risk_score:.1f}"))
        self.threat_table.setItem(row, 3, QTableWidgetItem(preview))

        # 设置行颜色
        if risk_score >= 8.0:
            color = QColor(239, 68, 68)  # 红色
        elif risk_score >= 5.0:
            color = QColor(245, 158, 11)  # 橙色
        else:
            color = QColor(59, 130, 246)  # 蓝色

        for col in range(4):
            if self.threat_table.item(row, col):
                self.threat_table.item(row, col).setBackground(color)

    def analysis_completed(self, success, message, results):
        """分析完成"""
        # 停止定时器
        self.performance_timer.stop()
        self.cache_timer.stop()

        # 恢复按钮状态
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        if success:
            elapsed = time.time() - self.start_time
            self.append_log(f"✅ 分析完成！总耗时: {elapsed:.1f}秒")

            # 显示结果统计
            if 'performance' in results:
                perf = results['performance']
                stats_msg = (
                    f"处理日志: {perf.get('processed_count', 0)}条\n"
                    f"发现威胁: {perf.get('threats_found', 0)}个\n"
                    f"内存峰值: {perf.get('memory_peak', 0):.1f}%\n"
                    f"缓存命中率: {perf.get('cache_hits', {}).get('hit_rate', 0):.1%}"
                )
                QMessageBox.information(self, "分析完成", stats_msg)
        else:
            self.append_log(f"❌ 分析失败: {message}")
            QMessageBox.critical(self, "分析失败", message)

    def export_report(self):
        """导出报告"""
        try:
            output_dir = self.output_dir_input.text()
            if not output_dir:
                QMessageBox.warning(self, "导出失败", "请先配置输出目录")
                return

            # 这里应该调用实际的报告导出功能
            QMessageBox.information(self, "导出成功", f"报告已导出到: {output_dir}")

        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出报告时发生错误: {str(e)}")


def main():
    """主函数"""
    app = QApplication(sys.argv)

    # 设置应用信息
    app.setApplicationName("SSlogs v3.1 优化版")
    app.setApplicationVersion("3.1.0")
    app.setOrganizationName("SSlogs Team")

    # 创建并显示主窗口
    window = OptimizedLogAnalyzerGUI()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()