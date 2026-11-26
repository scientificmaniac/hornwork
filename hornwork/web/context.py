"""Web 控制台共享上下文：集中持有 cfg/store/token/统计/认证引擎/缓存。

从 server.py 的 WebServer 抽出这些横切状态，使 HTTP 传输层、各 API 域、
鉴权模块都依赖同一个 ctx，而不再各自通过 self.app 的隐式属性访问。

线程模型：ThreadingHTTPServer 每请求一线程；统计与认证引擎构造都在锁内完成，
缓存读写用独立细粒度锁，避免与统计锁互相拖累。
"""

from __future__ import annotations

import threading
import time
from typing import Any

from .. import schema


class TtlCache:
    """轻量 TTL 缓存（只读 GET 用）。

    - key 需为 hashable（路由表用 (path, tuple(sorted(query.items()))) 作为 key）；
    - ttl<=0 时不缓存，get 恒 miss；
    - invalidate(prefix) 按 key 的字符串前缀失效，供 reload/logout 主动清缓存。
    """

    def __init__(self) -> None:
        self._data: dict[Any, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any | None:
        with self._lock:
            hit = self._data.get(key)
            if hit is None:
                return None
            expire_at, value = hit
            if time.monotonic() >= expire_at:
                self._data.pop(key, None)
                return None
            return value

    def put(self, key: Any, value: Any, ttl: float) -> None:
        if ttl <= 0:
            return
        with self._lock:
            self._data[key] = (time.monotonic() + ttl, value)

    def invalidate(self, prefix: str) -> int:
        """删除 key 中含 prefix 段的条目，返回删除数量。

        key 通常是 (namespace, ...) 形式的元组；检查任一元素等于 prefix，
        同时对字符串键检查 startswith，兼顾两种用法。
        """
        with self._lock:
            def match(key: Any) -> bool:
                if isinstance(key, tuple):
                    return any(str(part) == prefix for part in key)
                return str(key).startswith(prefix)

            keys = [key for key in self._data if match(key)]
            for key in keys:
                self._data.pop(key, None)
            return len(keys)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._data)


class WebContext:
    """Web 层的共享状态容器。

    公开属性：cfg / store / token / cache / bind / port（配置信息，供 handler 读取）。
    公开方法：note_request / note_error / request_reload / reload_state /
              stats_snapshot / auth_engine / reset_auth_engine。
    """

    def __init__(
        self,
        cfg: dict,
        store: Any,
        *,
        token: str = "",
        bind: str = "127.0.0.1",
        port: int = 0,
        auth_engine: Any | None = None,
    ) -> None:
        self.cfg = cfg
        self.store = store
        # 允许注入已构造的认证引擎（测试夹具用；生产走惰性构造）。
        self._injected_auth_engine = auth_engine
        self.token = token
        self.bind = bind
        self.port = port
        self.cache = TtlCache()
        self._lock = threading.RLock()
        self._requests = 0
        self._errors = 0
        self._reload_state: dict[str, Any] = {
            "requested_at": None,
            "count": 0,
            "note": "",
        }
        self._auth_engine: Any | None = auth_engine

    # ------------------------------------------------------------ 统计
    def note_request(self) -> None:
        with self._lock:
            self._requests += 1

    def note_error(self) -> None:
        with self._lock:
            self._errors += 1

    def stats_snapshot(self) -> dict[str, Any]:
        """返回统计与重载状态的快照（生命周期字段由 WebServer.status 组合）。"""
        with self._lock:
            return {
                "requests": self._requests,
                "errors": self._errors,
                "reload": dict(self._reload_state),
            }

    # ------------------------------------------------------------ 规则重载标记
    def request_reload(self, note: str = "") -> dict:
        with self._lock:
            self._reload_state = {
                "requested_at": schema.utc_now(),
                "count": int(self._reload_state.get("count") or 0) + 1,
                "note": note,
            }
            # 主动失效规则目录扫描缓存，使热加载请求立即生效
            self.cache.invalidate("rules")
            return dict(self._reload_state)

    def reload_state(self) -> dict:
        with self._lock:
            return dict(self._reload_state)

    # ------------------------------------------------------------ 认证引擎
    def auth_engine(self) -> Any:
        """双检锁惰性构造认证引擎，避免多线程下重复构造（原 getattr 方案存在竞态）。"""
        eng = self._auth_engine
        if eng is None:
            with self._lock:
                if self._auth_engine is None:
                    from ..auth.engine import AuthEngine

                    self._auth_engine = AuthEngine(self.cfg, store=self.store)
                eng = self._auth_engine
        return eng

    def reset_auth_engine(self) -> None:
        """测试或配置变更后重置引擎（清空引用，下次访问重新构造）。

        注入的引擎也一并清除——重置意味着回到"下次惰性构造"的默认行为。
        """
        with self._lock:
            self._injected_auth_engine = None
            self._auth_engine = None
