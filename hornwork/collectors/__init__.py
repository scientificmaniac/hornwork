"""采集层公共设施。

为各采集器提供统一的线程骨架、统计计数、事件构造与停止语义：

- 构造函数统一 `(cfg, emit, store=None, emit_alert=None, **kw)`；
- `start()` 启动 daemon 线程后立即返回；`stop()` 最多 join 3 s；
- `status()` 返回 `{"name","running","stats":{...},"errors":int}`；
- 本模块**不做任何 Linux 专属调用**，Windows 上 import 不会报错。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from .. import schema
from ..config import cfg_get
from ..log import get_logger

log = get_logger("collector")

EmitFn = Callable[[dict], Any]


def _noop(_item: dict) -> None:
    """未注入总线时的空回调。"""
    return None


class BaseCollector:
    """采集器线程基类。

    子类实现 `_run()`（循环体，需用 `self.stopping` / `self.sleep()` 响应停止），
    并按需覆写 `_init_stats()`、`start()`（用于平台能力检查）。
    """

    name: str = "base"
    source_product: str = "hornwork-base"
    layer: str = "host"

    def __init__(
        self,
        cfg: dict | None,
        emit: EmitFn | None,
        store: Any = None,
        emit_alert: EmitFn | None = None,
        **kw: Any,
    ) -> None:
        self.cfg: dict = cfg or {}
        self.emit: EmitFn = emit if callable(emit) else _noop
        self.store = store
        self.emit_alert: EmitFn = emit_alert if callable(emit_alert) else _noop
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats: dict[str, Any] = self._init_stats()
        self._errors = 0
        self._stat_lock = threading.Lock()
        self._started_at: float | None = None
        self.kw = kw

    # -------------------------------------------------------------- 生命周期
    def _init_stats(self) -> dict[str, Any]:
        """子类返回统计初始值。"""
        return {}

    def start(self) -> None:
        """启动 daemon 线程并立即返回（重复调用幂等）。"""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._started_at = time.time()
        thread = threading.Thread(target=self._thread_main, name=f"collect-{self.name}")
        thread.daemon = True
        self._thread = thread
        thread.start()
        log.info("采集器已启动", collector=self.name)

    def _thread_main(self) -> None:
        try:
            self._run()
        except Exception as exc:  # noqa: BLE001 - 线程绝不能带着异常静默死掉
            self.error("采集线程异常退出", exc=repr(exc))
        finally:
            log.info("采集线程结束", collector=self.name)

    def _run(self) -> None:  # pragma: no cover - 抽象方法
        raise NotImplementedError

    def stop(self) -> None:
        """请求停止并等待线程退出（总等待不超过 3 s）。"""
        self._stop_evt.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)

    # -------------------------------------------------------------- 状态
    def running(self) -> bool:
        thread = self._thread
        return bool(thread is not None and thread.is_alive() and not self._stop_evt.is_set())

    @property
    def stopping(self) -> bool:
        return self._stop_evt.is_set()

    def status(self) -> dict:
        with self._stat_lock:
            stats = dict(self._stats)
        return {
            "name": self.name,
            "running": self.running(),
            "stats": stats,
            "errors": self._errors,
        }

    def sleep(self, seconds: float) -> bool:
        """可被 `stop()` 打断的等待；True 表示收到停止信号。"""
        return self._stop_evt.wait(max(0.0, float(seconds)))

    # -------------------------------------------------------------- 计数与日志
    def stat_add(self, key: str, n: int = 1) -> None:
        with self._stat_lock:
            self._stats[key] = int(self._stats.get(key, 0) or 0) + int(n)

    def stat_set(self, key: str, value: Any) -> None:
        with self._stat_lock:
            self._stats[key] = value

    def stat_inc(self, key: str) -> None:
        self.stat_add(key, 1)

    def error(self, msg: str, **fields: Any) -> None:
        """记录一次降级/解析失败：计数 + WARN 日志，绝不抛出。"""
        self._errors += 1
        with self._stat_lock:
            self._stats["errors"] = self._errors
        log.warn(msg, collector=self.name, **fields)

    # -------------------------------------------------------------- 配置与事件
    def conf(self, dotted: str, default: Any = None) -> Any:
        """按点路径读配置，例如 `self.conf("collect.proc.interval_ms", 1000)`。"""
        return cfg_get(self.cfg, dotted, default)

    def make_event(
        self,
        event_type: str,
        *,
        ts: Any = None,
        process: dict | None = None,
        file: dict | None = None,
        network: dict | None = None,
        user: dict | None = None,
        rule: dict | None = None,
        raw: dict | None = None,
    ) -> dict:
        """用本采集器的 layer/source_product 构造 CanonicalEvent。"""
        return schema.new_event(
            event_type,
            self.layer,
            self.source_product,
            self.cfg,
            ts=ts,
            process=process,
            file=file,
            network=network,
            user=user,
            rule=rule,
            raw=raw,
        )

    def send(self, event: dict) -> None:
        """投递事件（回调异常隔离，仅计数）。"""
        try:
            self.emit(event)
        except Exception as exc:  # noqa: BLE001
            self.error("事件投递失败", exc=repr(exc))

    def send_alert(self, alert: dict) -> None:
        """投递告警（回调异常隔离，仅计数）。"""
        try:
            self.emit_alert(alert)
        except Exception as exc:  # noqa: BLE001
            self.error("告警投递失败", exc=repr(exc))


# ---------------------------------------------------------------------------
# 子采集器重导出：允许 `from hornwork.collectors import AuditdCollector`
# ---------------------------------------------------------------------------
from .auditd import AuditdCollector  # noqa: E402
from .authlog import AuthLogCollector, BruteForceTracker  # noqa: E402
from .fim import FimCollector  # noqa: E402
from .memscan import MemoryScanner  # noqa: E402
from .netcap import NetPipeline  # noqa: E402
from .netdecode import decode  # noqa: E402
from .persist import PersistenceChecker  # noqa: E402
from .proc import ProcCollector  # noqa: E402

__all__ = [
    "BaseCollector",
    "AuditdCollector",
    "AuthLogCollector",
    "BruteForceTracker",
    "FimCollector",
    "MemoryScanner",
    "NetPipeline",
    "PersistenceChecker",
    "ProcCollector",
    "decode",
]
