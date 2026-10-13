import asyncio
import logging
import time
from typing import Dict, List, Callable, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import weakref
from concurrent.futures import ThreadPoolExecutor


class EventPriority(Enum):
    """事件优先级"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Event:
    """事件数据类"""
    name: str
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    timestamp: float = field(default_factory=time.time)
    priority: EventPriority = EventPriority.NORMAL
    correlation_id: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3

    def __post_init__(self):
        if not self.correlation_id:
            self.correlation_id = f"{self.name}_{self.timestamp}_{id(self)}"


@dataclass
class EventHandler:
    """事件处理器"""
    handler_func: Callable
    name: str
    priority: EventPriority = EventPriority.NORMAL
    async_handler: bool = False
    filter_func: Optional[Callable[[Event], bool]] = None
    timeout: Optional[float] = None
    retry_on_error: bool = True


def _normalize_priority(priority: Any) -> EventPriority:
    """将优先级归一化为 EventPriority 枚举。

    兼容调用方传入字符串（如 'high'/'normal'/'low'/'critical'，大小写不敏感；
    'medium'/'default' 视为 NORMAL）。避免后续 handler.priority.value 在字符串上
    触发 'str' object has no attribute 'value'。
    """
    if isinstance(priority, EventPriority):
        return priority
    if isinstance(priority, str):
        key = priority.strip().upper()
        alias = {'MEDIUM': 'NORMAL', 'DEFAULT': 'NORMAL'}
        try:
            return EventPriority[alias.get(key, key)]
        except KeyError:
            return EventPriority.NORMAL
    return EventPriority.NORMAL


class EventBus:
    """事件总线 - 实现模块间的解耦通信"""

    def __init__(self, max_workers: int = 4):
        self._handlers: Dict[str, List[EventHandler]] = {}
        self._global_handlers: List[EventHandler] = []
        self._logger = logging.getLogger(__name__)
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._event_history: List[Event] = []
        self._max_history = 1000
        self._stats = {
            'events_published': 0,
            'events_processed': 0,
            'events_failed': 0,
            'handlers_executed': 0
        }

    def subscribe(self, event_name: str, handler_func: Callable,
                 name: Optional[str] = None, priority: EventPriority = EventPriority.NORMAL,
                 filter_func: Optional[Callable[[Event], bool]] = None,
                 timeout: Optional[float] = None, retry_on_error: bool = True) -> str:
        """订阅事件"""
        priority = _normalize_priority(priority)
        handler_name = name or f"{handler_func.__module__}.{handler_func.__name__}"

        handler = EventHandler(
            handler_func=handler_func,
            name=handler_name,
            priority=priority,
            async_handler=asyncio.iscoroutinefunction(handler_func),
            filter_func=filter_func,
            timeout=timeout,
            retry_on_error=retry_on_error
        )

        if event_name not in self._handlers:
            self._handlers[event_name] = []

        # 按优先级插入
        inserted = False
        for i, existing_handler in enumerate(self._handlers[event_name]):
            if handler.priority.value > existing_handler.priority.value:
                self._handlers[event_name].insert(i, handler)
                inserted = True
                break

        if not inserted:
            self._handlers[event_name].append(handler)

        self._logger.info(f"注册事件处理器: {handler_name} -> {event_name}")
        return handler_name

    def subscribe_global(self, handler_func: Callable,
                        name: Optional[str] = None, priority: EventPriority = EventPriority.NORMAL,
                        filter_func: Optional[Callable[[Event], bool]] = None) -> str:
        """订阅所有事件（全局处理器）"""
        priority = _normalize_priority(priority)
        handler_name = name or f"{handler_func.__module__}.{handler_func.__name__}"

        handler = EventHandler(
            handler_func=handler_func,
            name=handler_name,
            priority=priority,
            async_handler=asyncio.iscoroutinefunction(handler_func),
            filter_func=filter_func
        )

        # 按优先级插入
        inserted = False
        for i, existing_handler in enumerate(self._global_handlers):
            if handler.priority.value > existing_handler.priority.value:
                self._global_handlers.insert(i, handler)
                inserted = True
                break

        if not inserted:
            self._global_handlers.append(handler)

        self._logger.info(f"注册全局事件处理器: {handler_name}")
        return handler_name

    def unsubscribe(self, event_name: str, handler_name: str) -> bool:
        """取消订阅事件"""
        if event_name in self._handlers:
            self._handlers[event_name] = [
                h for h in self._handlers[event_name]
                if h.name != handler_name
            ]
            self._logger.info(f"取消订阅事件处理器: {handler_name} -> {event_name}")
            return True
        return False

    def unsubscribe_global(self, handler_name: str) -> bool:
        """取消订阅全局事件"""
        self._global_handlers = [
            h for h in self._global_handlers
            if h.name != handler_name
        ]
        self._logger.info(f"取消订阅全局事件处理器: {handler_name}")
        return True

    async def publish_async(self, event: Union[str, Event], data: Optional[Dict[str, Any]] = None) -> None:
        """异步发布事件"""
        if isinstance(event, str):
            event = Event(name=event, data=data or {})

        self._stats['events_published'] += 1
        self._event_history.append(event)

        # 保持历史记录大小
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        self._logger.debug(f"发布事件: {event.name} (ID: {event.correlation_id})")

        # 获取所有相关处理器
        handlers = self._global_handlers + self._handlers.get(event.name, [])

        if not handlers:
            self._logger.warning(f"事件 {event.name} 没有处理器")
            return

        # 并发执行处理器
        tasks = []
        for handler in handlers:
            task = asyncio.create_task(
                self._execute_handler_async(event, handler)
            )
            tasks.append(task)

        # 等待所有处理器完成（或超时）
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def publish(self, event: Union[str, Event], data: Optional[Dict[str, Any]] = None) -> None:
        """同步发布事件"""
        if isinstance(event, str):
            event = Event(name=event, data=data or {})

        self._stats['events_published'] += 1
        self._event_history.append(event)

        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]

        self._logger.debug(f"发布事件: {event.name} (ID: {event.correlation_id})")

        # 获取所有相关处理器
        handlers = self._global_handlers + self._handlers.get(event.name, [])

        if not handlers:
            self._logger.warning(f"事件 {event.name} 没有处理器")
            return

        # 执行处理器
        for handler in handlers:
            self._execute_handler_sync(event, handler)

    async def _execute_handler_async(self, event: Event, handler: EventHandler) -> None:
        """异步执行处理器"""
        try:
            # 应用过滤器
            if handler.filter_func and not handler.filter_func(event):
                self._logger.debug(f"事件被过滤器跳过: {handler.name}")
                return

            # 设置超时
            timeout = handler.timeout or 30.0

            if handler.async_handler:
                # 异步处理器
                await asyncio.wait_for(handler.handler_func(event), timeout=timeout)
            else:
                # 同步处理器在线程池中执行
                await asyncio.wait_for(
                    asyncio.get_running_loop().run_in_executor(
                        self._executor, handler.handler_func, event
                    ),
                    timeout=timeout
                )

            self._stats['handlers_executed'] += 1
            self._logger.debug(f"处理器执行成功: {handler.name}")

        except asyncio.TimeoutError:
            self._logger.error(f"处理器超时: {handler.name} (timeout: {timeout}s)")
            self._stats['events_failed'] += 1
        except Exception as e:
            self._logger.error(f"处理器执行失败: {handler.name} - {e}")
            self._stats['events_failed'] += 1

            # 重试逻辑
            if handler.retry_on_error and event.retry_count < event.max_retries:
                event.retry_count += 1
                self._logger.info(f"重试事件处理器: {handler.name} (第 {event.retry_count} 次)")
                await asyncio.sleep(1 * event.retry_count)  # 指数退避
                await self._execute_handler_async(event, handler)

    def _execute_handler_sync(self, event: Event, handler: EventHandler) -> None:
        """同步执行处理器"""
        try:
            # 应用过滤器
            if handler.filter_func and not handler.filter_func(event):
                self._logger.debug(f"事件被过滤器跳过: {handler.name}")
                return

            # 执行处理器
            if handler.async_handler:
                self._logger.warning(f"同步模式中跳过异步处理器: {handler.name}")
                return

            handler.handler_func(event)
            self._stats['handlers_executed'] += 1
            self._stats['events_processed'] += 1
            self._logger.debug(f"处理器执行成功: {handler.name}")

        except Exception as e:
            self._logger.error(f"处理器执行失败: {handler.name} - {e}")
            self._stats['events_failed'] += 1

            # 重试逻辑
            if handler.retry_on_error and event.retry_count < event.max_retries:
                event.retry_count += 1
                self._logger.info(f"重试事件处理器: {handler.name} (第 {event.retry_count} 次)")
                time.sleep(1 * event.retry_count)  # 指数退避
                self._execute_handler_sync(event, handler)

    def get_event_history(self, event_name: Optional[str] = None, limit: int = 100) -> List[Event]:
        """获取事件历史"""
        history = self._event_history
        if event_name:
            history = [e for e in history if e.name == event_name]
        return history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            'handlers_count': sum(len(handlers) for handlers in self._handlers.values()),
            'global_handlers_count': len(self._global_handlers),
            'event_types': list(self._handlers.keys())
        }

    def clear_history(self) -> None:
        """清空事件历史"""
        self._event_history.clear()
        self._logger.info("事件历史已清空")

    def shutdown(self) -> None:
        """关闭事件总线"""
        self._executor.shutdown(wait=True)
        self._logger.info("事件总线已关闭")


# 全局事件总线实例
_global_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """获取全局事件总线实例"""
    global _global_event_bus
    if _global_event_bus is None:
        _global_event_bus = EventBus()
    return _global_event_bus


def init_event_bus(max_workers: int = 4) -> EventBus:
    """初始化全局事件总线"""
    global _global_event_bus
    _global_event_bus = EventBus(max_workers=max_workers)
    return _global_event_bus


# 装饰器函数
def event_handler(event_name: str, name: Optional[str] = None,
                 priority: EventPriority = EventPriority.NORMAL,
                 filter_func: Optional[Callable[[Event], bool]] = None,
                 timeout: Optional[float] = None):
    """事件处理器装饰器"""
    def decorator(func: Callable):
        bus = get_event_bus()
        handler_name = name or f"{func.__module__}.{func.__name__}"
        bus.subscribe(event_name, func, handler_name, priority, filter_func, timeout)
        return func
    return decorator


def global_event_handler(name: Optional[str] = None,
                        priority: EventPriority = EventPriority.NORMAL,
                        filter_func: Optional[Callable[[Event], bool]] = None):
    """全局事件处理器装饰器"""
    def decorator(func: Callable):
        bus = get_event_bus()
        handler_name = name or f"{func.__module__}.{func.__name__}"
        bus.subscribe_global(func, handler_name, priority, filter_func)
        return func
    return decorator


# 便捷函数
async def publish_event(event_name: str, data: Optional[Dict[str, Any]] = None,
                       priority: EventPriority = EventPriority.NORMAL) -> None:
    """发布事件的便捷函数"""
    event = Event(name=event_name, data=data or {}, priority=priority)
    bus = get_event_bus()
    await bus.publish_async(event)


def publish_event_sync(event_name: str, data: Optional[Dict[str, Any]] = None,
                      priority: EventPriority = EventPriority.NORMAL) -> None:
    """同步发布事件的便捷函数"""
    event = Event(name=event_name, data=data or {}, priority=priority)
    bus = get_event_bus()
    bus.publish(event)