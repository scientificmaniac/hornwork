"""Web 控制台：标准库 http.server 实现的只读控制台 + 少量写操作。

对外出口（与 docs/CONTRACT.md 第 7 节一致）：
- WebServer(cfg, store)：start()/stop()/status()；
- 路由见，静态页见 static/index.html。
"""

from __future__ import annotations

from .server import WebServer

__all__ = ["WebServer"]
