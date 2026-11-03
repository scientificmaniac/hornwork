"""事件总线。

模型：主题（topic）+ 异步订阅者（asyncio.Queue）。采集线程通过线程安全的
publish() 投递，主循环的消费协程从队列取出并调用 handler。

背压策略：
- 每个订阅者队列有上限；满时丢弃当前消息并累加 dropped，不阻塞生产侧；
- handler 抛异常计 errors，并调用 DLQ 回调（若设置）。
"""

from __future__ import annotations

import asyncio
import threading
from collections import Counter
from typing import Any, Awaitable, Callable

Handler = Callable[[Any], Awaitable[None] | None]


def topic_match(pattern: str, topic: str) -> bool:
    """支持 `events.*` 前缀通配与精确匹配。"""
    if pattern == topic or pattern == "*":
        return True
    if pattern.endswith(".*"):
        return topic == pattern[:-2] or topic.startswith(pattern[:-1])
    return False


class Bus:
    def __init__(self, maxsize: int = 100000, log=None):
        self.maxsize = int(maxsize)
        self._subs: list[tuple[str, asyncio.Queue, Handler, str]] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._pending: list[tuple[str, Any]] = []
        self._dlq: Callable[[str, Any, str], None] | None = None
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self._lock = threading.Lock()
        self.metrics: Counter = Counter()
        self._log = log

    # ------------------------------------------------------------------ 绑定
    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        if self._pending:
            pending, self._pending = self._pending, []
            for topic, item in pending:
                self._dispatch(topic, item)
            self._pending = []
        self._log_flush()

    def _log_flush(self) -> None:
        if self._log and self.metrics.get("published_before_loop"):
            self._log.info(
                "bus pending events flushed",
                count=self.metrics.get("published_before_loop", 0),
            )
            self.metrics["published_before_loop"] = 0

    def set_dlq(self, fn: Callable[[str, Any, str], None]) -> None:
        self._dlq = fn

    # ------------------------------------------------------------------ 订阅
    def subscribe(self, pattern: str, name: str = "") -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self.maxsize)
        with self._lock:
            self._subs.append((pattern, q, None, name or pattern))  # type: ignore[arg-type]
        return q

    def attach(self, pattern: str, handler: Handler, name: str = "") -> asyncio.Queue:
        q = self.subscribe(pattern, name)
        task = asyncio.create_task(self._consume(q, handler, name or pattern))
        self._tasks.append(task)
        return q

    # 兼容旧名
    def subscribe_handler(self, pattern: str, handler: Handler, name: str = "") -> asyncio.Queue:
        return self.attach(pattern, handler, name)

    # ------------------------------------------------------------------ 消费
    async def _consume(self, q: asyncio.Queue, handler: Handler, name: str) -> None:
        self._running = True
        while self._running:
            item = await q.get()
            try:
                res = handler(item)
                if asyncio.iscoroutine(res):
                    await res
                self.metrics["handled"] += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - 单条消息失败不能拖垮总线
                self.metrics["errors"] += 1
                if self._log:
                    self._log.error("bus handler error", topic=name, error=str(exc))
                if self._dlq:
                    try:
                        self._dlq(name, item, str(exc))
                    except Exception:  # noqa: BLE001
                        pass
            finally:
                q.task_done()

    # ------------------------------------------------------------------ 投递
    def publish(self, topic: str, item: Any) -> None:
        """线程安全投递；主循环尚未绑定时先缓存。"""
        self.metrics["published"] += 1
        loop = self._loop
        if loop is None or loop.is_closed():
            with self._lock:
                if len(self._pending) < 10000:
                    self._pending.append((topic, item))
                    self.metrics["published_before_loop"] += 1
                else:
                    self.metrics["dropped"] += 1
            return
        try:
            loop.call_soon_threadsafe(self._dispatch, topic, item)
        except RuntimeError:
            self.metrics["dropped"] += 1

    def publish_nowait(self, topic: str, item: Any) -> None:
        self.publish(topic, item)

    def _dispatch(self, topic: str, item: Any) -> None:
        with self._lock:
            subs = list(self._subs)
        for pattern, q, _handler, _name in subs:
            if topic_match(pattern, topic):
                try:
                    q.put_nowait(item)
                except asyncio.QueueFull:
                    self.metrics["dropped"] += 1
                    if self._log and self.metrics["dropped"] % 1000 == 1:
                        self._log.warn("bus queue full, dropping", topic=topic, pattern=pattern)

    # ------------------------------------------------------------------ 状态
    def status(self) -> dict:
        with self._lock:
            subs = [
                {"pattern": p, "name": n, "qsize": q.qsize(), "maxsize": q.maxsize}
                for p, q, _h, n in self._subs
            ]
        return {
            "subscribers": subs,
            "metrics": dict(self.metrics),
            "pending": len(self._pending),
        }

    async def drain(self, timeout: float = 5.0) -> None:
        """关闭前排空（给消费协程最多 timeout 秒）。"""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        with self._lock:
            queues = [q for _p, q, _h, _n in self._subs]
        while loop.time() < deadline:
            if all(q.empty() for q in queues):
                return
            await asyncio.sleep(0.05)

    async def stop(self) -> None:
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
