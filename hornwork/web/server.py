"""Web 控制台服务：标准库 http.server + 单页控制台 + Bearer token 鉴权。

路由严格
- GET  /api/overview /api/events /api/alerts /api/rules /api/intel /api/cases
       /api/validate /api/engine-stats /api/export /healthz /metrics
- POST /api/rules（热加载标记）/api/intel（IOC 导入）/api/cases（建单）
- GET  / 返回 static/index.html

安全约定：
- 只绑定配置的 web.bind（默认 127.0.0.1）；未配置 token 时拒绝绑定非回环地址；
- 有 token 时所有 /api/* 与 /metrics 需要 `Authorization: Bearer <token>`；
- 所有 SQL 都走 store 的参数化方法，用户输入不拼接进 SQL；
- 错误统一 C7 结构：{"code","message","retryable","detail"}。
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .. import __version__
from .context import WebContext
from .errors import HttpError as _HttpError, error_payload as _error_payload
from .routing import build_routes, lookup as _route_lookup
from .api import (
    AuthorizeMixin,
    AuthMixin,
    IntegrationMixin,
    EventsMixin,
    HardenMixin,
    ReportMixin,
    LabMixin,
    ScanMixin,
    OverviewMixin,
    RulesMixin,
    IntelMixin,
    CasesMixin,
    ValidateMixin,
    ExportMixin,
    MetricsMixin,
)
from .common import (
    log,
    iso_now as _iso_now,
    query_dict as _query_dict,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
# Vue 控制台构建产物目录（`frontend/dist` 拷入此处）；缺失时回退到旧版单页。
APP_DIR = STATIC_DIR / "app"
MAX_BODY = 2 * 1024 * 1024
LOOPBACK = {"127.0.0.1", "localhost", "::1", ""}
# 静态资源类型（Vite 产物只会用到这几种；未知按 octet-stream 下载）
_ASSET_TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
}
# 带内容哈希的文件可长期缓存；入口 HTML 必须每次校验（发布后立即生效）
_ASSET_CACHE = "public, max-age=31536000, immutable"
_HTML_CACHE = "no-cache"


# ---------------------------------------------------------------------------
# 请求处理器
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler, AuthorizeMixin, AuthMixin, IntegrationMixin, EventsMixin, HardenMixin, ReportMixin, LabMixin, ScanMixin, OverviewMixin, RulesMixin, IntelMixin, CasesMixin, ValidateMixin, ExportMixin, MetricsMixin):
    """单页控制台的全部路由处理。"""

    server_version = "HornworkWeb/" + __version__
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        """关闭 Nagle：响应头/体分两次写，keep-alive 下避免 40ms delayed-ACK 停顿。"""
        super().setup()
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    # ------------------------------------------------------------ 生命周期
    @property
    def app(self) -> "WebServer":
        return self.server.owner  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
        self._handle("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("HEAD")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._send_json(405, _error_payload(405, "不支持的请求方法：PUT"))

    def do_DELETE(self) -> None:  # noqa: N802
        self._send_json(405, _error_payload(405, "不支持的请求方法：DELETE"))

    def log_message(self, fmt: str, *args: Any) -> None:
        # 访问日志走结构化 logger（debug 级，避免刷屏）；字段名避开 msg 以免与位置参数冲突
        try:
            client = self.client_address[0] if self.client_address else "-"
            log.debug("web access", line=fmt % args, client=client)
        except Exception:  # noqa: BLE001 - 访问日志失败不得影响响应
            pass

    # ------------------------------------------------------------ 分派
    def _handle(self, method: str) -> None:
        self._sent = False
        self._method = method
        self.app.note_request()
        try:
            self._dispatch(method)
        except _HttpError as exc:
            self._send_json(exc.status, exc.payload)
        except Exception as exc:  # noqa: BLE001 - 单请求异常不能拖垮服务
            self.app.note_error()
            log.exception("web 请求处理异常", path=self.path, error=str(exc))
            self._send_json(500, _error_payload(500, "服务内部错误", retryable=True, detail=exc))

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        query = _query_dict(parsed.query)

        # /assets/* 是前缀路由（哈希分块），单独处理；仍只需一次判断
        if path.startswith("/assets/"):
            if method not in ("GET", "HEAD"):
                raise _HttpError(405, "静态资源只支持 GET")
            return self._serve_asset(path[len("/assets/"):])

        # 查静态路由表（启动时构建一次，不再每请求重建字典 + 8 路 getattr）
        route, hint = _route_lookup(self.app.routes, path, method)
        if route is None:
            if hint:
                raise _HttpError(405, f"{path} {hint}")
            raise _HttpError(404, f"未知路由：{path}")

        # 鉴权：静态页/健康检查/认证入口在路由表中标记 needs_auth=False；
        # 其余走统一授权（状态机决策 + 会话绑定 + console_access 审计）
        if route.needs_auth:
            self._authorize(route)

        handler = getattr(self, route.handler)
        kind = route.kind
        if kind == "auth_post":
            return handler(path)
        if kind in ("auth_get", "post", "static", "health", "favicon"):
            return handler()
        # 普通 GET 接口接收 query dict
        return handler(query)

    def _favicon(self) -> None:
        """favicon 固定 204，无内容。"""
        self._send_bytes(204, b"", "image/x-icon")

    # ------------------------------------------------------------ 发送
    # ------------------------------------------------------------ 认证模块/五集成






    # ------------------------------------------------------------ 管理控制台数据接口









    # ------------------------------------------------------------ 靶场模块（靶场/漏洞档案）


    # ------------------------------------------------------------ 扫描模块：漏洞扫描









    # ------------------------------------------------------------ 发送
    def _send(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        if self._sent:
            return
        extra = dict(headers or {})
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # 默认禁止缓存（接口与旧页面）；静态产物用显式 Cache-Control 覆盖
        self.send_header("Cache-Control", extra.pop("Cache-Control", "no-store"))
        self.send_header("X-Content-Type-Options", "nosniff")
        # 连接复用：GET/HEAD 无请求体，可安全 keep-alive（Vue 分块资源显著受益）；
        # POST/PUT 等写请求及错误响应仍关闭连接，避免未读 body 污染下一个请求。
        method = getattr(self, "_method", "GET")
        keep_alive = method in ("GET", "HEAD") and status < 400
        self.send_header("Connection", "keep-alive" if keep_alive else "close")
        for key, value in extra.items():
            self.send_header(key, value)
        self.end_headers()
        if method != "HEAD" and body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self.close_connection = not keep_alive
        self._sent = True

    def _send_json(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", headers)

    def _send_bytes(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        self._send(status, body, content_type, headers)

    # ------------------------------------------------------------ 读体
    def _read_json(self) -> dict:
        """读取并解析 JSON 请求体（限制 2MB）。"""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise _HttpError(413, "请求体过大", retryable=False, detail=f"limit={MAX_BODY}")
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _HttpError(400, "请求体不是合法 JSON", retryable=False, detail=exc) from exc
        if not isinstance(body, dict):
            raise _HttpError(400, "请求体必须是 JSON 对象")
        return body

    # ------------------------------------------------------------ 静态页
    def _serve_index(self) -> None:
        index = STATIC_DIR / "index.html"
        try:
            body = index.read_bytes()
        except OSError as exc:
            raise _HttpError(500, "控制台静态页缺失", detail=exc) from exc
        self._send_bytes(200, body, "text/html; charset=utf-8")

    def _serve_platform(self) -> None:
        """简版控制台页面（/platform）。"""
        page = STATIC_DIR / "platform.html"
        try:
            body = page.read_bytes()
        except OSError as exc:
            raise _HttpError(500, "静态页缺失", detail=exc) from exc
        self._send_bytes(200, body, "text/html; charset=utf-8")

    def _serve_app_index(self) -> None:
        """Vue 控制台入口页；产物缺失时回退旧版单页，保证升级过程中控制台始终可打开。"""
        entry = APP_DIR / "index.html"
        try:
            body = entry.read_bytes()
        except OSError:
            return self._serve_platform()
        self._send_bytes(200, body, "text/html; charset=utf-8", {"Cache-Control": _HTML_CACHE})

    def _serve_asset(self, rel: str) -> None:
        """服务 `/assets/*`：只允许 APP_DIR 内的常规文件，路径穿越一律 404。"""
        name = rel.split("?", 1)[0]
        if not name or "/" in name or "\\" in name or name.startswith("."):
            raise _HttpError(404, "静态资源不存在", retryable=False)
        root = (APP_DIR / "assets").resolve()
        target = (root / name).resolve()
        # is_relative_to 比字符串前缀比较更严格：`/assets-evil/x.js` 不会被误判为目录内
        if not target.is_relative_to(root) or not target.is_file():
            raise _HttpError(404, "静态资源不存在", retryable=False)
        try:
            body = target.read_bytes()
        except OSError as exc:
            raise _HttpError(404, "静态资源不存在", retryable=False, detail=exc) from exc
        ctype = _ASSET_TYPES.get(target.suffix.lower(), "application/octet-stream")
        self._send_bytes(200, body, ctype, {"Cache-Control": _ASSET_CACHE})

    def _healthz(self) -> None:
        self._send_json(
            200,
            {
                "ok": True,
                "service": "hornwork",
                "version": __version__,
                "ts": _iso_now(),
                "auth": bool(self.app.token),
                "web": self.app.status(),
            },
        )

    # ------------------------------------------------------------ 概览

    # ------------------------------------------------------------ 事件/告警


    # ------------------------------------------------------------ 规则




    # ------------------------------------------------------------ 情报


    # ------------------------------------------------------------ 工单


    # ------------------------------------------------------------ 验证

    # ------------------------------------------------------------ 引擎贡献

    # ------------------------------------------------------------ 导出


    # ------------------------------------------------------------ Prometheus


class _ThreadingServer(ThreadingHTTPServer):
    """带 owner 引用的多线程 HTTP 服务（便于 handler 访问 WebServer）。"""

    daemon_threads = True
    allow_reuse_address = True
    # keep-alive 下空闲连接 30s 自动关闭，避免慢客户端长期占用线程
    timeout = 30
    owner: Any = None


# ---------------------------------------------------------------------------
# 服务封装
# ---------------------------------------------------------------------------
class WebServer:
    """Web 控制台：线程方式运行，只绑定配置地址。"""

    def __init__(self, cfg: dict, store, auth_engine=None):
        self.cfg = cfg or {}
        self.store = store
        web = (self.cfg.get("web") or {}) if isinstance(self.cfg, dict) else {}
        self.enabled = bool(web.get("enabled", True))
        self.bind = str(web.get("bind") or "127.0.0.1").strip() or "127.0.0.1"
        self.port = self._resolve_port(web)
        self.token_env = str(web.get("token_env") or "HORNWORK_TOKEN")
        self.token = self._resolve_token(web)
        self._httpd: _ThreadingServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._started_at: float | None = None
        # 共享上下文：统计/重载/认证引擎/缓存的唯一来源（handler 经 app.ctx 访问）
        self.ctx = WebContext(self.cfg, store, token=self.token, bind=self.bind,
                              port=self.port, auth_engine=auth_engine)
        # 静态路由表：启动时构建一次，替代每请求重建字典
        self.routes = build_routes()

    # ------------------------------------------------------------ 配置
    @staticmethod
    def _resolve_port(web: dict) -> int:
        """解析监听端口：0 表示由系统分配空闲端口（测试/临时实例用），缺省 8787。"""
        raw = web.get("port")
        if raw is None or str(raw).strip() == "":
            return 8787
        try:
            port = int(str(raw).strip())
        except (TypeError, ValueError):
            return 8787
        if port < 0 or port > 65535:
            raise ValueError(f"web.port 非法：{raw}")
        return port

    def _resolve_token(self, web: dict) -> str:
        """token 优先级：config.toml 的 web.token > 环境变量 web.token_env。"""
        token = str(web.get("token") or "").strip()
        if token:
            return token
        try:
            return str(os.environ.get(self.token_env, "") or "").strip()
        except (TypeError, ValueError):
            return ""

    # ------------------------------------------------------------ 统计（委托 ctx）
    def note_request(self) -> None:
        self.ctx.note_request()

    def note_error(self) -> None:
        self.ctx.note_error()

    def request_reload(self, note: str = "") -> dict:
        """记录一次规则热加载请求（内存标记，daemon 轮询后执行）。"""
        return self.ctx.request_reload(note)

    def reload_state(self) -> dict:
        return self.ctx.reload_state()

    # ------------------------------------------------------------ 生命周期
    def start(self) -> None:
        """启动服务线程；重复调用幂等。"""
        with self._lock:
            if self._httpd is not None:
                return
            if not self.enabled:
                raise RuntimeError("Web 控制台已在配置中禁用（web.enabled=false）")
            if not self.token and self.bind not in LOOPBACK:
                raise ValueError(f"未配置 token 时只允许绑定回环地址，当前 web.bind={self.bind}")
            try:
                httpd = _ThreadingServer((self.bind, self.port), _Handler)
            except OSError as exc:
                raise OSError(f"Web 控制台无法绑定 {self.bind}:{self.port}（{exc}）") from exc
            httpd.owner = self
            self._httpd = httpd
            self.port = int(httpd.server_address[1])
            self.ctx.port = self.port  # port=0 时回填实际端口，保持 ctx 与实际一致
            self._started_at = time.time()
            thread = threading.Thread(target=httpd.serve_forever, name="hornwork-web", daemon=True)
            self._thread = thread
            thread.start()
        if not self.token:
            log.warn(
                "Web 控制台未配置 token，已限制为本机访问（开发模式）",
                bind=self.bind,
                port=self.port,
                token_env=self.token_env,
            )
        else:
            log.info("Web 控制台已启动", bind=self.bind, port=self.port)

    def stop(self) -> None:
        """停止服务线程并释放端口（3 秒内退出）。"""
        with self._lock:
            httpd, thread = self._httpd, self._thread
            self._httpd = None
            self._thread = None
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception as exc:  # noqa: BLE001 - 停止阶段的异常不应抛出
                log.warn("Web 控制台 shutdown 异常", error=str(exc))
            try:
                httpd.server_close()
            except Exception as exc:  # noqa: BLE001
                log.warn("Web 控制台 server_close 异常", error=str(exc))
        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
        log.info("Web 控制台已停止")

    def status(self) -> dict:
        """服务状态（含 enabled/bind/port/auth/running 四个固定字段）。"""
        with self._lock:
            running = self._httpd is not None and self._thread is not None and self._thread.is_alive()
            uptime = round(time.time() - self._started_at, 2) if self._started_at else 0.0
            stats = self.ctx.stats_snapshot()
            return {
                "enabled": self.enabled,
                "bind": self.bind,
                "port": self.port,
                "auth": bool(self.token),
                "running": running,
                "url": f"http://{self.bind}:{self.port}/",
                "token_env": self.token_env,
                "requests": stats["requests"],
                "errors": stats["errors"],
                "uptime_sec": uptime,
                "reload": stats["reload"],
            }









