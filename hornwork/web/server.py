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

import hmac
import json
import os
import re
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import __version__, schema
from ..config import cfg_get
from ..log import get_logger
from ..verify.metrics import compute_metrics

log = get_logger("web")

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 2 * 1024 * 1024
LOOPBACK = {"127.0.0.1", "localhost", "::1", ""}
# 网络规则/YARA 规则文件里取规则名的轻量正则（只做列表展示，不参与匹配）
_NET_RULE_RE = re.compile(r"^\s*rule\s+([A-Za-z0-9_.\-]+)\s+([A-Za-z0-9_.\-]+)")
_YARA_RULE_RE = re.compile(r"^\s*rule\s+([A-Za-z0-9_]+)")


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _error_payload(code: int, message: str, retryable: bool = False, detail: Any = None) -> dict:
    """C7 统一错误结构。"""
    return {
        "code": int(code),
        "message": str(message),
        "retryable": bool(retryable),
        "detail": None if detail is None else str(detail)[:800],
    }


def _query_dict(query_string: str) -> dict[str, str]:
    """同名参数取最后一个（简单、可预期）。"""
    return {key: values[-1] for key, values in parse_qs(query_string, keep_blank_values=False).items()}


def _q_int(query: dict[str, str], key: str, default: int, minimum: int = 0, maximum: int = 10000) -> int:
    raw = query.get(key)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(float(str(raw).strip()))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


class _HttpError(Exception):
    """路由层主动抛出的 HTTP 错误（由统一异常处理转成 C7 JSON）。"""

    def __init__(self, status: int, message: str, retryable: bool = False, detail: Any = None):
        super().__init__(message)
        self.status = status
        self.payload = _error_payload(status, message, retryable, detail)


# ---------------------------------------------------------------------------
# 请求处理器
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    """单页控制台的全部路由处理。"""

    server_version = "HornworkWeb/" + __version__
    protocol_version = "HTTP/1.1"

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

        # 静态页与健康检查不需要 token：页面本身要能先打开再填 token
        if path == "/":
            if method not in ("GET", "HEAD"):
                raise _HttpError(405, "静态页只支持 GET")
            return self._serve_platform()
        if path == "/index.html":
            if method not in ("GET", "HEAD"):
                raise _HttpError(405, "静态页只支持 GET")
            return self._serve_index()
        if path in ("/platform", "/platform.html"):
            if method not in ("GET", "HEAD"):
                raise _HttpError(405, "静态页只支持 GET")
            return self._serve_platform()
        if path == "/healthz":
            if method not in ("GET", "HEAD"):
                raise _HttpError(405, "健康检查只支持 GET")
            return self._healthz()
        if path == "/favicon.ico":
            return self._send_bytes(204, b"", "image/x-icon")

        # 认证模块登录入口：平台登录认证走三因子（无需静态 token，登录本身即鉴权）
        if path in ("/api/auth/login", "/api/auth/step-up", "/api/auth/logout"):
            if method != "POST":
                raise _HttpError(405, f"{path} 只支持 POST")
            return self._h_auth_post(path)
        if path == "/api/auth/session":
            if method not in ("GET", "HEAD"):
                raise _HttpError(405, "/api/auth/session 只支持 GET")
            return self._h_auth_session()

        if not self._authorized():
            raise _HttpError(401, "未授权：缺少或错误的 Bearer token", retryable=False)

        get_routes = {
            "/api/overview": self._h_overview,
            "/api/events": self._h_events,
            "/api/alerts": self._h_alerts,
            "/api/rules": self._h_rules_get,
            "/api/intel": self._h_intel_get,
            "/api/cases": self._h_cases_get,
            "/api/validate": self._h_validate,
            "/api/engine-stats": self._h_engine_stats,
            "/api/lab/envs": self._h_lab_envs,
            "/api/vuln/records": self._h_vuln_records,
            "/api/export": self._h_export,
            "/api/integration/status": self._h_integration_status,
            "/api/platform/security": self._h_platform_security,
            "/api/events/recent": self._h_events_recent,
            "/api/events/types": self._h_event_types,
            "/api/auth/users": self._h_auth_users,
            "/api/auth/sessions": self._h_auth_sessions,
            "/api/auth/audit": self._h_auth_audit,
            "/api/auth/policy": self._h_auth_policy,
            "/api/harden/status": self._h_harden_status,
            "/api/scan/reports": self._h_scan_reports,
            "/api/report": self._h_report_file,
            "/metrics": self._h_metrics,
        }
        # 扫描模块（scan）的只读 API 可能由其它分支/会话并行开发：按需挂载，
        # 处理器不存在时退化为 404，避免整个路由表在构造阶段因 AttributeError 全挂。
        for _path, _attr in (
            ("/api/scan/overview", "_h_scan_overview"),
            ("/api/scan/plans", "_h_scan_plans"),
            ("/api/scan/tasks", "_h_scan_tasks"),
            ("/api/scan/findings", "_h_scan_findings"),
            ("/api/scan/snapshots", "_h_scan_snapshots"),
            ("/api/scan/diff", "_h_scan_diff"),
            ("/api/scan/coverage", "_h_scan_coverage"),
            ("/api/scan/cve", "_h_scan_cve"),
        ):
            _handler = getattr(self, _attr, None)
            if _handler is not None:
                get_routes[_path] = _handler
        post_routes = {
            "/api/rules": self._h_rules_post,
            "/api/intel": self._h_intel_post,
            "/api/cases": self._h_cases_post,
        }
        if method in ("GET", "HEAD"):
            if path in get_routes:
                return get_routes[path](query)
            if path in post_routes:
                raise _HttpError(405, f"{path} 只支持 POST")
            raise _HttpError(404, f"未知路由：{path}")
        if method == "POST":
            if path in post_routes:
                return post_routes[path]()
            if path in get_routes:
                raise _HttpError(405, f"{path} 只支持 GET")
            raise _HttpError(404, f"未知路由：{path}")
        raise _HttpError(405, f"不支持的请求方法：{method}")

    # ------------------------------------------------------------ 发送
    # ------------------------------------------------------------ 认证模块/五集成
    def _auth_engine(self):
        """按需构造认证模块认证引擎（与平台共用同一 SQLite 库）。"""
        eng = getattr(self.app, "_auth_engine", None)
        if eng is None:
            from ..auth.engine import AuthEngine

            eng = AuthEngine(self.app.cfg, store=self.app.store)
            self.app._auth_engine = eng
        return eng

    def _session_token(self) -> str:
        header = self.headers.get("Authorization") or ""
        if header.startswith("Bearer "):
            given = header[7:].strip()
            if given.startswith("s1."):
                return given
        return (self.headers.get("X-Hornwork-Session") or "").strip()

    def _h_auth_post(self, path: str) -> None:
        """平台登录认证：口令 → 风险 → 动态码 →（LOA3）人脸，返回平台会话。"""
        body = self._read_json()
        eng = self._auth_engine()
        try:
            if path == "/api/auth/login":
                embedding = body.get("embedding")
                if not isinstance(embedding, list):
                    embedding = None
                ip = str(body.get("ip") or self.client_address[0] or "").strip()
                username = str(body.get("username") or "").strip()
                password = str(body.get("password") or "")
                totp_code = str(body.get("totp") or "").strip()
                if totp_code:
                    # 三因子路径（认证模块演示 / CLI 兼容）
                    res = eng.login(
                        username, password, ip=ip,
                        device_token=(str(body.get("device_token") or "").strip() or None),
                        totp_code=totp_code, embedding=embedding,
                    )
                else:
                    # 平台统一登录：账号 + 口令；人脸可选
                    res = eng.login_password_only(
                        username, password, ip=ip, embedding=embedding)
            elif path == "/api/auth/step-up":
                embedding = body.get("embedding")
                res = eng.step_up(
                    str(body.get("token") or self._session_token()),
                    str(body.get("totp") or "").strip(),
                    embedding=embedding if isinstance(embedding, list) else None,
                )
            else:  # logout
                token = str(body.get("token") or self._session_token())
                res = {"status": "ok" if eng.logout(token) else "fail"}
        except Exception as exc:  # noqa: BLE001 - 认证库未初始化等场景返回 503
            log.warn("平台登录接口异常", path=path, error=str(exc))
            raise _HttpError(503, "认证服务不可用（认证模块未初始化）", retryable=True,
                             detail=str(exc)) from exc
        status = 200 if res.get("status") in ("ok", "totp_required", "bio_required", "degraded") else 401
        payload = dict(res)
        payload["ok"] = res.get("status") in ("ok", "degraded")
        payload["ts"] = _iso_now()
        self._send_json(status, payload)

    def _h_auth_session(self) -> None:
        token = self._session_token()
        if not token:
            raise _HttpError(401, "缺少平台会话令牌", retryable=False)
        try:
            info = self._auth_engine().session_info(token)
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(401, "会话无效或已过期", retryable=False, detail=str(exc)) from exc
        self._send_json(200, {"ok": True, "ts": _iso_now(), **info})

    def _h_integration_status(self, query: dict) -> None:
        """五模块集成状态：各模块关键指标与联动证据。"""
        store = self.app.store
        out: dict[str, Any] = {"ts": _iso_now(), "host": None, "modules": {}}

        def count(sql: str) -> int:
            try:
                rows = store.query(sql)
                return int(rows[0]["n"]) if rows else 0
            except Exception:  # noqa: BLE001
                return 0

        # 检测模块
        m1 = {
            "events": count("SELECT COUNT(*) AS n FROM event"),
            "alerts": count("SELECT COUNT(*) AS n FROM alert"),
            "cases": count("SELECT COUNT(*) AS n FROM case_"),
            "audit_rows": count("SELECT COUNT(*) AS n FROM action_audit"),
            "sigma_hits": count("SELECT COUNT(*) AS n FROM sigma_stat WHERE hits>0"),
        }
        try:
            import socket as _socket

            out["host"] = _socket.gethostname()
        except Exception:  # noqa: BLE001
            pass
        try:
            rows = store.query("SELECT host_id FROM meta WHERE key='host_id'") or []
            if rows and rows[0].get("host_id"):
                out["host"] = rows[0]["host_id"]
        except Exception:  # noqa: BLE001
            pass
        out["modules"]["detection"] = m1

        # 靶场模块
        out["modules"]["vuln"] = {
            "records": count("SELECT COUNT(*) AS n FROM vuln_record"),
            "verified": count("SELECT COUNT(*) AS n FROM vuln_record WHERE status='verified'"),
            "lab_envs": count("SELECT COUNT(*) AS n FROM lab_env"),
            "lab_runs": count("SELECT COUNT(*) AS n FROM lab_run"),
        }

        # 扫描模块
        m3 = {
            "assets": count("SELECT COUNT(*) AS n FROM asset"),
            "plans": count("SELECT COUNT(*) AS n FROM scan_plan"),
            "tasks": count("SELECT COUNT(*) AS n FROM scan_task"),
            "snapshots": count("SELECT COUNT(*) AS n FROM scan_snapshot"),
            "findings": count("SELECT COUNT(*) AS n FROM scan_finding"),
            "cve_rows": count("SELECT COUNT(*) AS n FROM cve_cache"),
        }
        try:
            rows = store.query("SELECT task_id, plan_id, status, started_at FROM scan_task"
                               " ORDER BY started_at DESC LIMIT 1") or []
            m3["latest_task"] = rows[0] if rows else None
        except Exception:  # noqa: BLE001
            m3["latest_task"] = None
        out["modules"]["scan"] = m3

        # 认证模块
        m4: dict[str, Any] = {
            "users": count("SELECT COUNT(*) AS n FROM auth_user"),
            "sessions": count("SELECT COUNT(*) AS n FROM auth_session WHERE revoked_at IS NULL"),
            "audit_rows": count("SELECT COUNT(*) AS n FROM auth_audit"),
        }
        try:
            from ..auth import audit as auth_audit

            m4["chain"] = auth_audit.verify_chain(self._auth_engine().store)
        except Exception as exc:  # noqa: BLE001
            m4["chain"] = {"ok": False, "error": str(exc)}
        out["modules"]["auth"] = m4

        # 加固模块：最新一次加固运行
        m5: dict[str, Any] = {}
        try:
            from ..harden import core as harden_core

            runs_dir = harden_core.state(self.app.cfg)["runs"]
            files = sorted(runs_dir.glob("run-*.json"))
            if files:
                data = harden_core.read_json(files[-1]) or {}
                results = data.get("results") or []
                by_status: dict[str, int] = {}
                for item in results:
                    key = str(item.get("status") or "unknown")
                    by_status[key] = by_status.get(key, 0) + 1
                m5 = {
                    "latest_run": data.get("run_id"),
                    "mode": data.get("mode"),
                    "items": len(results),
                    "by_status": by_status,
                    "platform_items": [
                        {"id": r.get("item_id"), "title": r.get("title"),
                         "status": r.get("status")}
                        for r in results
                        if str(r.get("item_id") or "").startswith("H-PL-")
                    ],
                }
            else:
                m5 = {"latest_run": None, "platform_items": []}
        except Exception as exc:  # noqa: BLE001
            m5 = {"error": str(exc), "platform_items": []}
        out["modules"]["harden"] = m5

        self._send_json(200, out)

    def _h_platform_security(self, query: dict) -> None:
        """平台登录面加固状态：HTTPS 反代、锁定策略、目录权限、服务沙箱。"""
        import os
        import socket
        import ssl
        from pathlib import Path

        sec: dict[str, Any] = {"ts": _iso_now(), "https": {}, "lockout": {}, "paths": {},
                               "service": {}}
        # HTTPS 反代（加固模块渲染的 nginx 8443）
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", 8443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname="a.hornwork.local") as tls:
                    sec["https"] = {"ok": True, "protocol": tls.version(),
                                    "cipher": (tls.cipher() or [None])[0]}
        except Exception as exc:  # noqa: BLE001
            sec["https"] = {"ok": False, "error": str(exc)}
        # 登录锁定策略（认证模块策略表，加固模块 H-PL-02 固化）
        try:
            from ..auth import db as auth_db

            eng = self._auth_engine()
            sec["lockout"] = auth_db.get_policy(eng.store, "lockout")
        except Exception as exc:  # noqa: BLE001
            sec["lockout"] = {"error": str(exc)}
        # 数据与密钥目录权限
        for p in ("/var/lib/hornwork", "/var/lib/hornwork/hornwork.db",
                  "/var/lib/hornwork/auth", "/etc/hornwork/harden"):
            try:
                st = os.stat(p)
                sec["paths"][p] = {"mode": oct(st.st_mode & 0o777),
                                   "uid": st.st_uid, "gid": st.st_gid,
                                   "exists": True}
            except OSError:
                sec["paths"][p] = {"exists": False}
        # 服务运行身份与加固单元
        try:
            import subprocess

            user = subprocess.run(["systemctl", "show", "hornwork", "-p", "User", "--value"],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
            sandbox = subprocess.run(["systemctl", "show", "hornwork", "-p", "NoNewPrivileges",
                                      "-p", "ProtectSystem", "--value"],
                                     capture_output=True, text=True, timeout=5).stdout.strip().splitlines()
            sec["service"] = {"unit": "hornwork.service", "user": user or "root",
                              "sandbox": sandbox}
        except Exception as exc:  # noqa: BLE001
            sec["service"] = {"error": str(exc)}
        sec["bind"] = {"host": self.app.bind, "port": self.app.port,
                       "token_auth": bool(self.app.token),
                       "tls_ingress": bool(sec["https"].get("ok"))}
        self._send_json(200, sec)

    # ------------------------------------------------------------ 管理控制台数据接口
    def _h_events_recent(self, query: dict) -> None:
        store = self.app.store
        limit = _q_int(query, "limit", 20, 1, 200)
        try:
            rows = store.query(
                "SELECT ts, event_type AS type, source_layer, host_id, engine, payload"
                " FROM event ORDER BY rowid DESC LIMIT ?", (limit,))
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "读取事件失败", detail=str(exc)) from exc
        self._send_json(200, {"items": rows, "count": len(rows), "ts": _iso_now()})

    def _h_event_types(self, query: dict) -> None:
        store = self.app.store
        try:
            rows = store.query(
                "SELECT event_type AS type, COUNT(*) AS n FROM event GROUP BY event_type"
                " ORDER BY n DESC LIMIT 20")
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "统计事件类型失败", detail=str(exc)) from exc
        self._send_json(200, {"items": rows, "ts": _iso_now()})

    def _h_auth_users(self, query: dict) -> None:
        try:
            users = self._auth_engine().list_users()
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(503, "认证库不可用", detail=str(exc)) from exc
        self._send_json(200, {"items": users, "count": len(users), "ts": _iso_now()})

    def _h_auth_sessions(self, query: dict) -> None:
        store = self.app.store
        try:
            rows = store.query(
                "SELECT session_id, user_id, loa, ip, device_id, created_ts, last_seen_ts,"
                " idle_expires_ts, expires_ts, revoked, revoke_reason FROM auth_session"
                " ORDER BY created_ts DESC LIMIT 50")
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "读取会话失败", detail=str(exc)) from exc
        self._send_json(200, {"items": rows, "ts": _iso_now()})

    def _h_auth_audit(self, query: dict) -> None:
        store = self.app.store
        limit = _q_int(query, "limit", 30, 1, 200)
        try:
            from ..auth import audit as auth_audit

            rows = auth_audit.tail(store, limit=limit)
            chain = auth_audit.verify_chain(store)
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "读取认证审计失败", detail=str(exc)) from exc
        self._send_json(200, {"items": rows, "chain": chain, "ts": _iso_now()})

    def _h_auth_policy(self, query: dict) -> None:
        try:
            from ..auth import db as auth_db

            eng = self._auth_engine()
            keys = list(auth_db.POLICY_DEFAULTS.keys())
            policy = {key: auth_db.get_policy(eng.store, key) for key in keys}
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(503, "读取认证策略失败", detail=str(exc)) from exc
        self._send_json(200, {"policy": policy, "ts": _iso_now()})

    def _h_harden_status(self, query: dict) -> None:
        """加固模块：基线项、计划、运行结果、报告清单（全部来自文件状态）。"""
        import yaml

        from ..harden import core as hcore

        try:
            state = hcore.state(self.app.cfg)
            items_doc = yaml.safe_load(Path(hcore.ITEMS_PATH).read_text(encoding="utf-8")) or {}
            items = items_doc.get("items") or []
            plans = []
            for path in sorted(state["plans"].glob("pln-*.json"))[-5:]:
                data = hcore.read_json(path) or {}
                nitems = sum(len(b.get("items") or []) for b in (data.get("batches") or []))
                if not nitems:
                    nitems = len(data.get("items") or data.get("allowed") or [])
                plans.append({"plan_id": data.get("plan_id"), "role": data.get("role"),
                              "asset": data.get("asset_id"), "items": nitems,
                              "created_at": data.get("created_at")})
            runs = []
            for path in sorted(state["runs"].glob("run-*.json"))[-6:]:
                data = hcore.read_json(path) or {}
                results = data.get("results") or []
                counts: dict[str, int] = {}
                for r in results:
                    key = str(r.get("status") or "unknown")
                    counts[key] = counts.get(key, 0) + 1
                runs.append({"run_id": data.get("run_id"), "plan_id": data.get("plan_id"),
                             "mode": data.get("mode"), "status": data.get("status"),
                             "started_at": data.get("started_at"), "counts": counts,
                             "items": len(results)})
            reports = []
            rdir = state["root"] / "reports"
            for path in sorted(rdir.glob("harden-report-*.md"))[-6:]:
                reports.append({"name": path.name, "size": path.stat().st_size})
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "读取加固状态失败", detail=str(exc)) from exc
        self._send_json(200, {
            "items": [{"id": i.get("id"), "category": i.get("category"),
                       "title": i.get("title"), "risk": i.get("risk"),
                       "scope_A": str((i.get("scope") or {}).get("A", "")).startswith("yes")}
                      for i in items],
            "plans": plans, "runs": runs, "reports": reports, "ts": _iso_now(),
        })

    def _h_scan_reports(self, query: dict) -> None:
        import time as _time

        root = Path("/opt/hornwork/reports")
        items = []
        for path in sorted(root.glob("scan/*.html"), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
            st = path.stat()
            items.append({"name": path.name, "rel": f"scan/{path.name}", "size": st.st_size,
                          "mtime": _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(st.st_mtime))})
        self._send_json(200, {"items": items, "ts": _iso_now()})

    def _h_report_file(self, query: dict) -> None:
        rel = str(query.get("file") or "").strip()
        root = Path("/opt/hornwork/reports").resolve()
        target = (root / rel).resolve()
        if not str(target).startswith(str(root)) or not target.is_file():
            raise _HttpError(404, "报告不存在", retryable=False)
        ctype = "text/html; charset=utf-8" if target.suffix == ".html" else "text/plain; charset=utf-8"
        self._send_bytes(200, target.read_bytes(), ctype)

    # ------------------------------------------------------------ 靶场模块（靶场/漏洞档案）
    def _h_lab_envs(self, query: dict) -> None:
        """GET /api/lab/envs：靶场环境清单 + 最近 lab_run（靶场编排层）。"""
        store = self.app.store
        limit = _q_int(query, "limit", 10, 1, 100)
        envs: list[dict] = []
        runs: list[dict] = []
        try:
            envs = store.query("SELECT * FROM lab_env ORDER BY env_id")
            runs = store.query(
                "SELECT * FROM lab_run ORDER BY started_at DESC LIMIT ?", (limit,)
            )
        except Exception:  # noqa: BLE001 - 未初始化（未用过 lab）时返回空列表
            envs, runs = [], []
        for env in envs:
            for key in ("host_ports", "image_refs"):
                value = env.get(key)
                if isinstance(value, str) and value:
                    try:
                        env[key] = json.loads(value)
                    except json.JSONDecodeError:
                        pass
        self._send_json(200, {"envs": envs, "runs": runs, "ts": _iso_now()})

    def _h_vuln_records(self, query: dict) -> None:
        """GET /api/vuln/records：漏洞档案列表（CWE/等级可过滤）。"""
        store = self.app.store
        limit = _q_int(query, "limit", 200, 1, 1000)
        sql = ("SELECT id, cve, title, component, cwe, cvss_vector, cvss_score, severity,"
               " kind, status, yaml_path, updated_at FROM vuln_record WHERE 1=1")
        args: list = []
        cwe = (query.get("cwe") or [""])[0]
        severity = (query.get("severity") or [""])[0]
        if cwe:
            sql += " AND cwe LIKE ?"
            args.append(f"%{cwe}%")
        if severity:
            sql += " AND severity = ?"
            args.append(severity)
        sql += " ORDER BY cvss_score DESC, id LIMIT ?"
        args.append(limit)
        try:
            rows = store.query(sql, args)
        except Exception:  # noqa: BLE001
            rows = []
        self._send_json(200, {"records": rows, "ts": _iso_now()})

    # ------------------------------------------------------------ 扫描模块：漏洞扫描
    def _scan_api(self):
        """惰性导入扫描模块只读 API（未初始化扫描数据时返回空结构，不抛异常）。"""
        from ..scan import api as scan_api
        from ..scan import store as scan_store

        scan_store.init_schema(self.app.store)
        return scan_api

    def _h_scan_overview(self, query: dict) -> None:
        """GET /api/scan/overview：台账/计划/任务/快照/finding/CVE 计数与最近任务。"""
        try:
            payload = self._scan_api().overview(self.app.store)
        except Exception as exc:  # noqa: BLE001
            payload = {"error": str(exc), "counts": {}}
        self._send_json(200, payload)

    def _h_scan_plans(self, query: dict) -> None:
        """GET /api/scan/plans：扫描计划列表。"""
        try:
            payload = self._scan_api().list_plans(self.app.store)
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "total": 0, "error": str(exc)}
        self._send_json(200, payload)

    def _h_scan_tasks(self, query: dict) -> None:
        """GET /api/scan/tasks?limit=&status=&run=&plan=：扫描任务列表。"""
        limit = _q_int(query, "limit", 50, 1, 1000)
        status = (query.get("status") or [None])[0]
        run_id = (query.get("run") or [None])[0]
        plan_id = (query.get("plan") or [None])[0]
        try:
            from ..scan import store as scan_store

            scan_store.init_schema(self.app.store)
            rows = scan_store.list_tasks(
                self.app.store, run_id=run_id, plan_id=plan_id, status=status, limit=limit
            )
            payload = {"items": rows, "total": len(rows), "ts": _iso_now()}
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "total": 0, "error": str(exc)}
        self._send_json(200, payload)

    def _h_scan_findings(self, query: dict) -> None:
        """GET /api/scan/findings?severity=&status=&kind=&asset=&limit=：finding 列表。"""
        filters = {
            "asset_id": (query.get("asset") or [None])[0],
            "severity": (query.get("severity") or [None])[0],
            "status": (query.get("status") or [None])[0],
            "kind": (query.get("kind") or [None])[0],
            "limit": _q_int(query, "limit", 200, 1, 2000),
        }
        try:
            payload = self._scan_api().list_findings(self.app.store, **filters)
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "total": 0, "error": str(exc)}
        self._send_json(200, payload)

    def _h_scan_snapshots(self, query: dict) -> None:
        """GET /api/scan/snapshots?limit=：快照列表。"""
        try:
            payload = self._scan_api().list_snapshots(
                self.app.store, limit=_q_int(query, "limit", 20, 1, 200)
            )
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "total": 0, "error": str(exc)}
        self._send_json(200, payload)

    def _h_scan_diff(self, query: dict) -> None:
        """GET /api/scan/diff?from=<snap>&to=<snap>：四态差异（缺省取最近两次快照）。"""
        cur = (query.get("from") or [None])[0]
        prev = (query.get("to") or [None])[0]
        try:
            from ..scan import diff as scan_diff, store as scan_store

            scan_store.init_schema(self.app.store)
            if not cur:
                latest = scan_store.list_snapshots(self.app.store, limit=2)
                if latest:
                    cur = latest[0]["snapshot_id"]
                    prev = prev or (latest[1]["snapshot_id"] if len(latest) > 1 else None)
            payload = scan_diff.build(self.app.store, cur, prev) if cur and prev else {
                "items": [], "stats": {}, "error": "快照不足，无法对比"
            }
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "stats": {}, "error": str(exc)}
        self._send_json(200, payload)

    def _h_scan_coverage(self, query: dict) -> None:
        """GET /api/scan/coverage?snapshot=：资产×检查域覆盖率与未覆盖清单。"""
        snapshot = (query.get("snapshot") or [None])[0]
        try:
            from ..scan import coverage as scan_coverage, store as scan_store

            scan_store.init_schema(self.app.store)
            if not snapshot:
                latest = scan_store.latest_snapshot(self.app.store)
                snapshot = latest["snapshot_id"] if latest else None
            payload = (scan_coverage.compute(self.app.store, snapshot, self.app.cfg)
                       if snapshot else {"coverage": 0.0, "uncovered": [], "matrix": []})
        except Exception as exc:  # noqa: BLE001
            payload = {"coverage": 0.0, "uncovered": [], "matrix": [], "error": str(exc)}
        self._send_json(200, payload)

    def _h_scan_cve(self, query: dict) -> None:
        """GET /api/scan/cve：CVE 缓存统计（条数/来源/严重级）。"""
        try:
            payload = self._scan_api().cve_stats(self.app.store)
        except Exception as exc:  # noqa: BLE001
            payload = {"total_cves": 0, "error": str(exc)}
        self._send_json(200, payload)

    # ------------------------------------------------------------ 发送
    def _send(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        if self._sent:
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if getattr(self, "_method", "GET") != "HEAD" and body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self.close_connection = True
        self._sent = True

    def _send_json(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", headers)

    def _send_bytes(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        self._send(status, body, content_type, headers)

    # ------------------------------------------------------------ 鉴权/读体
    def _authorized(self) -> bool:
        # 1) 静态 Bearer token（运维/脚本入口）
        token = self.app.token
        header = self.headers.get("Authorization") or ""
        given = header[7:].strip() if header.startswith("Bearer ") else ""
        if token and given and hmac.compare_digest(given.encode("utf-8"), token.encode("utf-8")):
            return True
        # 2) 认证模块平台会话（三因子登录签发，s1.<...>）
        session_token = self._session_token()
        if session_token:
            try:
                info = self._auth_engine().session_info(session_token)
                if info and info.get("session", {}).get("session_id"):
                    return True
            except Exception:  # noqa: BLE001 - 会话无效按未授权处理
                return False
        # 3) 无 token 配置时只允许本机来源（服务本身也只会绑定回环地址）
        if not token:
            host = self.client_address[0] if self.client_address else ""
            return host in LOOPBACK or host.startswith("127.")
        return False

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
    def _h_overview(self, query: dict[str, str]) -> None:
        store = self.app.store
        days = _q_int(query, "days", 7, 1, 90)
        counts = store.counts()
        latest = store.latest_run_id()
        validation = None
        if latest:
            rows = store.validation_rows(run_id=latest)
            validation = {
                "run_id": latest,
                "case_count": len(rows),
                "metrics": compute_metrics(rows),
            }
        self._send_json(
            200,
            {
                "ts": _iso_now(),
                "counts": counts,
                "engine_stats": store.engine_stats(days),
                "sigma": store.sigma_stats(),
                "recent_scans": store.recent_scans(limit=5),
                "validation": validation,
                "web": self.app.status(),
            },
        )

    # ------------------------------------------------------------ 事件/告警
    def _h_events(self, query: dict[str, str]) -> None:
        limit = _q_int(query, "limit", 100, 1, 1000)
        items = self.app.store.query_events(
            event_type=query.get("type") or query.get("event_type") or None,
            since=query.get("since") or None,
            limit=limit,
            source_layer=query.get("layer") or query.get("source_layer") or None,
        )
        self._send_json(200, {"ts": _iso_now(), "count": len(items), "items": items})

    def _h_alerts(self, query: dict[str, str]) -> None:
        store = self.app.store
        level_min = query.get("level_min")
        rule_id = query.get("rule_id")
        items = store.query_alerts(
            since=query.get("since") or None,
            level_min=int(level_min) if str(level_min or "").isdigit() else None,
            technique=query.get("technique") or None,
            rule_ids=[rule_id] if rule_id else None,
            limit=_q_int(query, "limit", 100, 1, 1000),
        )
        self._send_json(200, {"ts": _iso_now(), "count": len(items), "items": items})

    # ------------------------------------------------------------ 规则
    def _h_rules_get(self, query: dict[str, str]) -> None:
        items, missing, sources = self._collect_rules()
        self._send_json(
            200,
            {
                "ts": _iso_now(),
                "items": items,
                "count": len(items),
                "sources": sources,
                "missing": missing,
                "sigma": self.app.store.sigma_stats(),
                "reload": self.app.reload_state(),
            },
        )

    def _collect_rules(self) -> tuple[list[dict], list[str], dict[str, str]]:
        """扫描配置的规则目录，产出规则/规则文件清单（只读文件系统，不做规则求值）。"""
        cfg = self.app.cfg
        groups = (
            ("yara", "engines.yara_rule_dir", ("*.yar", "*.yara")),
            ("net", "engines.net_rule_dir", ("*.rules",)),
            ("host", "engines.host_rule_dir", ("*.json",)),
            ("sigma", "engines.sigma_rule_dir", ("*.yml", "*.yaml")),
        )
        items: list[dict] = []
        missing: list[str] = []
        sources: dict[str, str] = {}
        for kind, key, patterns in groups:
            raw = str(cfg_get(cfg, key, "") or "")
            sources[kind] = raw
            path = Path(os.path.expanduser(raw)) if raw else None
            if path is None or not path.is_dir():
                if raw:
                    missing.append(raw)
                continue
            for pattern in patterns:
                for file_path in sorted(path.rglob(pattern)):
                    if not file_path.is_file():
                        continue
                    item = self._describe_rule_file(kind, file_path)
                    if item:
                        items.append(item)
        return items, missing, sources

    @staticmethod
    def _describe_rule_file(kind: str, path: Path) -> dict | None:
        """单个规则文件 → 列表项（host JSON 解析元数据，net/yara 抽规则名）。"""
        try:
            stat = path.stat()
        except OSError:
            return None
        item: dict[str, Any] = {
            "source": kind,
            "id": path.stem,
            "name": path.stem,
            "path": str(path),
            "size": int(stat.st_size),
            "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": None,
            "technique": None,
            "rule_count": None,
        }
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return item
        if kind == "host":
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                item["error"] = "JSON 解析失败"
                return item
            if isinstance(doc, dict):
                item["id"] = str(doc.get("id") or item["id"])
                item["name"] = str(doc.get("name") or item["name"])
                item["level"] = doc.get("level")
                mitre = doc.get("mitre") or []
                item["technique"] = str(mitre[0]) if mitre else None
                item["event_types"] = doc.get("event_types") or []
                item["description"] = str(doc.get("description") or "")[:300]
        elif kind == "net":
            ids = [match.group(1) for match in _NET_RULE_RE.finditer(text)]
            item["rule_count"] = len(ids)
            item["rules"] = ids[:50]
        elif kind == "yara":
            ids = [match.group(1) for match in _YARA_RULE_RE.finditer(text)]
            item["rule_count"] = len(ids)
            item["rules"] = ids[:50]
        else:
            # Sigma：不引入 PyYAML 依赖，只按文件计数（加载状态由 store.sigma_stats 提供）
            item["rule_count"] = text.count("\ntitle:") + (1 if text.lstrip().startswith("title:") else 0)
        return item

    def _h_rules_post(self) -> None:
        body = self._read_json()
        action = str(body.get("action") or ("reload" if body.get("reload") else "")).strip()
        if action not in ("reload",):
            raise _HttpError(400, "仅支持 action=reload（规则热加载标记）")
        state = self.app.request_reload(note=str(body.get("note") or "")[:200])
        self._send_json(
            201,
            {
                "ok": True,
                "action": "reload",
                "requested_at": state.get("requested_at"),
                "count": state.get("count"),
                "note": "已记录重载请求，daemon 轮询后生效",
            },
        )

    # ------------------------------------------------------------ 情报
    def _h_intel_get(self, query: dict[str, str]) -> None:
        kind = query.get("kind") or None
        status = query.get("status") or None
        items = self.app.store.ioc_list(kind=kind, limit=_q_int(query, "limit", 500, 1, 5000), status=status)
        by_type = dict(Counter(str(item.get("type") or "unknown") for item in items))
        self._send_json(200, {"ts": _iso_now(), "items": items, "count": len(items), "by_type": by_type})

    def _h_intel_post(self) -> None:
        body = self._read_json()
        try:
            from ..intel.iocstore import IocStore
        except Exception as exc:  # noqa: BLE001 - 情报层缺失时降级为 503
            raise _HttpError(503, "情报层不可用（hornwork.intel.iocstore 导入失败）", detail=exc) from exc

        records: Any = None
        if isinstance(body.get("records"), list):
            records = body["records"]
        elif body.get("path"):
            try:
                from ..intel.feeds import load_feed
            except Exception as exc:  # noqa: BLE001
                raise _HttpError(503, "情报导入器不可用（hornwork.intel.feeds 导入失败）", detail=exc) from exc
            path = Path(os.path.expanduser(str(body["path"])))
            if not path.is_file():
                raise _HttpError(400, "情报文件不存在", detail=str(path))
            try:
                records = load_feed(str(path))
            except Exception as exc:  # noqa: BLE001 - 解析失败属于可重试错误
                raise _HttpError(422, "情报文件解析失败", retryable=True, detail=exc) from exc
        if not isinstance(records, list) or not records:
            raise _HttpError(400, "请求体需要 records 数组或 path 文件路径")

        try:
            result = IocStore(self.app.store, self.app.cfg).import_records(records)
        except Exception as exc:  # noqa: BLE001 - 导入失败按 500 返回
            raise _HttpError(500, "情报导入失败", retryable=True, detail=exc) from exc
        payload = {"ok": True, "ts": _iso_now()}
        if isinstance(result, dict):
            payload.update(result)
        else:
            payload["imported"] = result
        self._send_json(201, payload)

    # ------------------------------------------------------------ 工单
    def _h_cases_get(self, query: dict[str, str]) -> None:
        items = self.app.store.list_cases(
            status=query.get("status") or None,
            limit=_q_int(query, "limit", 100, 1, 1000),
        )
        self._send_json(200, {"ts": _iso_now(), "items": items, "count": len(items)})

    def _h_cases_post(self) -> None:
        body = self._read_json()
        title = str(body.get("title") or "").strip()
        if not title:
            raise _HttpError(400, "缺少工单标题 title")
        severity = str(body.get("severity") or "P3").strip() or "P3"
        verdict = body.get("verdict")
        dedup_key = body.get("dedup_key")
        store = self.app.store
        case_id: str | None = None
        source = "store"
        error: str | None = None
        try:
            from ..respond.case import CaseManager

            created = CaseManager(store, self.app.cfg).create(title=title, severity=severity, dedup_key=dedup_key, verdict=verdict)
            if isinstance(created, dict):
                case_id = str(created.get("case_id") or "") or None
            elif created:
                case_id = str(created)
            source = "casemanager"
        except Exception as exc:  # noqa: BLE001 - 响应层未就绪时退回 store 直接写入
            error = str(exc)
            log.debug("CaseManager 不可用，退回 store 写入", error=error)
        if not case_id:
            case_id = "case-" + uuid.uuid4().hex[:12]
            try:
                store.insert_case(
                    {
                        "case_id": case_id,
                        "title": title,
                        "severity": severity,
                        "status": "open",
                        "dedup_key": dedup_key,
                        "created_at": schema.utc_now(),
                        "verdict": verdict,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - 写库失败明确报错
                raise _HttpError(500, "工单写入失败", retryable=True, detail=exc) from exc
        row = None
        try:
            row = store.get_case(case_id)
        except Exception as exc:  # noqa: BLE001 - 回读失败不影响创建结果
            log.warn("工单回读失败", case_id=case_id, error=str(exc))
        self._send_json(201, {"ok": True, "case_id": case_id, "case": row, "source": source, "fallback_error": error})

    # ------------------------------------------------------------ 验证
    def _h_validate(self, query: dict[str, str]) -> None:
        store = self.app.store
        run_id = query.get("run_id") or store.latest_run_id()
        if not run_id:
            self._send_json(200, {"run_id": None, "rows": [], "metrics": None, "report_path": None, "md_path": None})
            return
        rows = store.validation_rows(run_id=run_id, limit=_q_int(query, "limit", 500, 1, 2000))
        metrics = compute_metrics(rows)
        report_path = md_path = None
        compact: list[dict] = []
        for row in rows:
            payload = row.get("payload") or {}
            if isinstance(payload, dict):
                report_path = report_path or payload.get("report_path")
                md_path = md_path or payload.get("md_path")
            compact.append(
                {
                    "case_id": row.get("case_id"),
                    "technique": row.get("technique"),
                    "expected": row.get("expected"),
                    "observed": row.get("observed"),
                    "verdict": row.get("verdict"),
                    "mttd_sec": row.get("mttd_sec"),
                    "name": (payload or {}).get("name") if isinstance(payload, dict) else None,
                    "error": (payload or {}).get("error") if isinstance(payload, dict) else None,
                }
            )
        self._send_json(
            200,
            {
                "ts": _iso_now(),
                "run_id": run_id,
                "rows": compact,
                "case_count": len(compact),
                "metrics": metrics,
                "report_path": report_path,
                "md_path": md_path,
            },
        )

    # ------------------------------------------------------------ 引擎贡献
    def _h_engine_stats(self, query: dict[str, str]) -> None:
        store = self.app.store
        days = _q_int(query, "days", 7, 1, 90)
        self._send_json(
            200,
            {
                "ts": _iso_now(),
                "days": days,
                "engine_stats": store.engine_stats(days),
                "contribution": store.engine_contribution(days),
                "sigma": store.sigma_stats(),
                "recent_scans": store.recent_scans(limit=_q_int(query, "limit", 20, 1, 200)),
            },
        )

    # ------------------------------------------------------------ 导出
    def _h_export(self, query: dict[str, str]) -> None:
        fmt = str(query.get("format") or "jsonl").strip().lower()
        kind = str(query.get("kind") or "alerts").strip().lower()
        since = query.get("since") or "24h"
        limit = _q_int(query, "limit", 500, 1, 5000)
        store = self.app.store
        if kind == "alerts":
            items = store.query_alerts(since=since, limit=limit)
        elif kind == "events":
            items = store.query_events(since=since, limit=limit)
        elif kind == "validation":
            run_id = query.get("run_id") or store.latest_run_id()
            items = store.validation_rows(run_id=run_id, limit=limit) if run_id else []
        else:
            raise _HttpError(400, "kind 仅支持 alerts/events/validation")

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "jsonl":
            body = ("\n".join(schema.dumps(item) for item in items) + ("\n" if items else "")).encode("utf-8")
            self._send_bytes(
                200,
                body,
                "application/x-ndjson; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="hornwork-{kind}-{stamp}.jsonl"'},
            )
            return
        if fmt in ("md", "markdown"):
            body = self._render_export_markdown(kind, items, since).encode("utf-8")
            self._send_bytes(
                200,
                body,
                "text/markdown; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="hornwork-{kind}-{stamp}.md"'},
            )
            return
        raise _HttpError(400, "format 仅支持 jsonl 或 md")

    def _render_export_markdown(self, kind: str, items: list[dict], since: str) -> str:
        """导出 Markdown：概览计数 + 明细表。"""
        counts = self.app.store.counts()
        lines = [
            f"# Hornwork 导出（{kind}）",
            "",
            f"- 生成时间：{_iso_now()}",
            f"- 时间范围：since={since}",
            f"- 条数：{len(items)}",
            "",
            "## 概览",
            "",
            "| 计数项 | 值 |",
            "|---|---|",
        ]
        for key in ("events_total", "events_24h", "alerts_total", "alerts_24h", "alerts_open", "cases_total", "iocs"):
            lines.append(f"| {key} | {counts.get(key, 0)} |")
        lines.append("")
        if kind == "alerts":
            lines.extend(["## 告警", "", "| 时间 | 规则 | 级别 | 技术 | 状态 |", "|---|---|---|---|---|"])
            for item in items:
                rule = item.get("rule") or {}
                lines.append(
                    f"| {item.get('ts')} | {rule.get('id') or item.get('rule_id')} | {item.get('level')} "
                    f"| {item.get('technique') or '-'} | {item.get('status') or '-'} |"
                )
        elif kind == "events":
            lines.extend(["## 事件", "", "| 时间 | 类型 | 来源层 | 来源组件 |", "|---|---|---|---|"])
            for item in items:
                lines.append(
                    f"| {item.get('ts')} | {item.get('event_type')} | {item.get('source_layer')} | {item.get('source_product')} |"
                )
        else:
            lines.extend(["## 验证结果", "", "| 用例 | 技术 | 期望 | 观测 | 判定 | MTTD(s) |", "|---|---|---|---|---|---|"])
            for item in items:
                lines.append(
                    f"| {item.get('case_id')} | {item.get('technique') or '-'} | {item.get('expected')} "
                    f"| {item.get('observed')} | {item.get('verdict')} | {item.get('mttd_sec') if item.get('mttd_sec') is not None else '-'} |"
                )
        lines.append("")
        return "\n".join(lines)

    # ------------------------------------------------------------ Prometheus
    def _h_metrics(self, query: dict[str, str]) -> None:
        store = self.app.store
        counts = store.counts()
        lines = [
            "# HELP hornwork_up 服务在线标记",
            "# TYPE hornwork_up gauge",
            "hornwork_up 1",
        ]
        for key in sorted(counts):
            lines.extend(
                [
                    f"# HELP hornwork_{key} Hornwork 计数项：{key}",
                    f"# TYPE hornwork_{key} gauge",
                    f"hornwork_{key} {int(counts.get(key) or 0)}",
                ]
            )
        status = self.app.status()
        lines.extend(
            [
                "# HELP hornwork_web_requests_total Web 控制台累计请求数",
                "# TYPE hornwork_web_requests_total counter",
                f"hornwork_web_requests_total {int(status.get('requests') or 0)}",
                "# HELP hornwork_web_errors_total Web 控制台累计错误数",
                "# TYPE hornwork_web_errors_total counter",
                f"hornwork_web_errors_total {int(status.get('errors') or 0)}",
            ]
        )
        latest = store.latest_run_id()
        if latest:
            metrics = compute_metrics(store.validation_rows(run_id=latest))
            for name in ("TP", "TN", "FP", "FN", "inconclusive"):
                lines.extend(
                    [
                        f"# HELP hornwork_validation_{name.lower()} 最近一次验证的 {name} 数",
                        f"# TYPE hornwork_validation_{name.lower()} gauge",
                        f"hornwork_validation_{name.lower()} {int(metrics.get(name) or 0)}",
                    ]
                )
            for name in ("tpr", "fpr", "coverage", "mttd_sec"):
                value = metrics.get(name)
                lines.extend(
                    [
                        f"# HELP hornwork_validation_{name} 最近一次验证的 {name}",
                        f"# TYPE hornwork_validation_{name} gauge",
                        f"hornwork_validation_{name} {0 if value is None else float(value)}",
                    ]
                )
        body = ("\n".join(lines) + "\n").encode("utf-8")
        self._send_bytes(200, body, "text/plain; version=0.0.4; charset=utf-8")


class _ThreadingServer(ThreadingHTTPServer):
    """带 owner 引用的多线程 HTTP 服务（便于 handler 访问 WebServer）。"""

    daemon_threads = True
    allow_reuse_address = True
    owner: Any = None


# ---------------------------------------------------------------------------
# 服务封装
# ---------------------------------------------------------------------------
class WebServer:
    """Web 控制台：线程方式运行，只绑定配置地址。"""

    def __init__(self, cfg: dict, store):
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
        self._requests = 0
        self._errors = 0
        self._reload_state: dict[str, Any] = {"requested_at": None, "count": 0, "note": ""}

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

    # ------------------------------------------------------------ 统计
    def note_request(self) -> None:
        with self._lock:
            self._requests += 1

    def note_error(self) -> None:
        with self._lock:
            self._errors += 1

    def request_reload(self, note: str = "") -> dict:
        """记录一次规则热加载请求（内存标记，daemon 轮询后执行）。"""
        with self._lock:
            self._reload_state = {
                "requested_at": schema.utc_now(),
                "count": int(self._reload_state.get("count") or 0) + 1,
                "note": note,
            }
            return dict(self._reload_state)

    def reload_state(self) -> dict:
        with self._lock:
            return dict(self._reload_state)

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
            return {
                "enabled": self.enabled,
                "bind": self.bind,
                "port": self.port,
                "auth": bool(self.token),
                "running": running,
                "url": f"http://{self.bind}:{self.port}/",
                "token_env": self.token_env,
                "requests": self._requests,
                "errors": self._errors,
                "uptime_sec": uptime,
                "reload": dict(self._reload_state),
            }









