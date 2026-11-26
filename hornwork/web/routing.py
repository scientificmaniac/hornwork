"""静态路由表：启动时构建一次，替代原 _dispatch 每请求重建字典 + 8 路 getattr。

路由元组的唯一来源。分派时只做一次字典查找 + 一次方法绑定（getattr(self, name)），
不再每请求分配两个字典、循环挂载扫描路由。

字段：
- path: URL 路径（不含 query）
- methods: 允许的方法集合（frozenset）
- handler: _Handler 上的方法名（str）
- needs_auth: 是否需要 Bearer/session 鉴权
- kind: 分派类别，决定如何取参数与发送（见 _Handler._dispatch）
  - "static"  静态入口：handler(query=None)，允许 GET/HEAD
  - "asset"   /assets/* 前缀：handler(rel)，允许 GET/HEAD
  - "health"  健康检查
  - "favicon" favicon 固定 204
  - "auth_post" 认证登录入口：handler(path)，需 POST
  - "auth_get"  认证会话查询：handler()，需 GET/HEAD
  - "get"     普通 GET 接口：handler(query)
  - "post"    普通 POST 接口：handler()
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class Route:
    path: str
    methods: FrozenSet[str]
    handler: str
    needs_auth: bool = True
    kind: str = "get"
    #: 授权动作（对应 policy.ACTION_MIN_LOA / ROLE_ACTIONS）；needs_auth=False 时忽略。
    action: str = "read"
    #: 是否写 console_access 审计（静态页/健康检查/登录类接口不写）。
    audit: bool = True

    def allows(self, method: str) -> bool:
        return method in self.methods


GET_HEAD: FrozenSet[str] = frozenset({"GET", "HEAD"})
POST: FrozenSet[str] = frozenset({"POST"})


def build_routes() -> dict[str, Route]:
    """构建完整路由表（模块级纯函数，WebServer.start 时调用一次）。

    扫描类 8 条路由在此显式注册；handler 缺失会在首次请求暴露为 AttributeError，
    而不是像旧版那样静默降级为 404 —— 符合设计文档"显式注册"的约定。
    """
    routes: dict[str, Route] = {}

    def add(path: str, methods: FrozenSet[str], handler: str,
            *, auth: bool = True, kind: str = "get", action: str = "read",
            audit: bool = True) -> None:
        if path in routes:
            raise RuntimeError(f"重复注册路由：{path}")
        routes[path] = Route(path, methods, handler, auth, kind, action, audit)

    # ---- 免鉴权：静态页 / 健康检查 / 认证入口（均不写访问审计）----
    add("/", GET_HEAD, "_serve_app_index", auth=False, kind="static", audit=False)
    add("/index.html", GET_HEAD, "_serve_index", auth=False, kind="static", audit=False)
    add("/platform", GET_HEAD, "_serve_app_index", auth=False, kind="static", audit=False)
    add("/platform.html", GET_HEAD, "_serve_app_index", auth=False, kind="static", audit=False)
    add("/healthz", GET_HEAD, "_healthz", auth=False, kind="health", audit=False)
    add("/favicon.ico", GET_HEAD, "_favicon", auth=False, kind="favicon", audit=False)
    add("/api/auth/login", POST, "_h_auth_post", auth=False, kind="auth_post", audit=False)
    add("/api/auth/step-up", POST, "_h_auth_post", auth=False, kind="auth_post", audit=False)
    add("/api/auth/logout", POST, "_h_auth_post", auth=False, kind="auth_post", audit=False)
    add("/api/auth/session", GET_HEAD, "_h_auth_session", auth=False, kind="auth_get", audit=False)

    # ---- 需鉴权：GET 接口（第三项为 action；默认 read）----
    for path, handler, *rest in (
        ("/api/overview", "_h_overview"),
        ("/api/events", "_h_events"),
        ("/api/alerts", "_h_alerts"),
        ("/api/rules", "_h_rules_get"),
        ("/api/intel", "_h_intel_get"),
        ("/api/cases", "_h_cases_get"),
        ("/api/validate", "_h_validate"),
        ("/api/engine-stats", "_h_engine_stats"),
        ("/api/lab/envs", "_h_lab_envs"),
        ("/api/vuln/records", "_h_vuln_records"),
        ("/api/export", "_h_export", "sensitive"),
        ("/api/integration/status", "_h_integration_status"),
        ("/api/platform/security", "_h_platform_security"),
        ("/api/events/recent", "_h_events_recent"),
        ("/api/events/types", "_h_event_types"),
        ("/api/auth/users", "_h_auth_users", "admin"),
        ("/api/auth/sessions", "_h_auth_sessions", "admin"),
        ("/api/auth/audit", "_h_auth_audit", "admin"),
        ("/api/auth/policy", "_h_auth_policy", "admin"),
        ("/api/harden/status", "_h_harden_status"),
        ("/api/scan/reports", "_h_scan_reports"),
        ("/api/report", "_h_report_file", "sensitive"),
        ("/metrics", "_h_metrics"),
        # 扫描模块（显式注册，不再 getattr 条件挂载）
        ("/api/scan/overview", "_h_scan_overview"),
        ("/api/scan/plans", "_h_scan_plans"),
        ("/api/scan/tasks", "_h_scan_tasks"),
        ("/api/scan/findings", "_h_scan_findings"),
        ("/api/scan/snapshots", "_h_scan_snapshots"),
        ("/api/scan/diff", "_h_scan_diff"),
        ("/api/scan/coverage", "_h_scan_coverage"),
        ("/api/scan/cve", "_h_scan_cve"),
    ):
        add(path, GET_HEAD, handler, action=rest[0] if rest else "read")

    # ---- 需鉴权：POST 接口（与 GET 共用路径，靠 methods 区分）----
    for path, handler in (
        ("/api/rules", "_h_rules_post"),
        ("/api/intel", "_h_intel_post"),
        ("/api/cases", "_h_cases_post"),
    ):
        # 同路径同时注册 GET 与 POST：合并 methods，另建一条 POST 记录
        existing = routes.get(path)
        if existing is not None:
            routes[path] = Route(path, existing.methods | POST, existing.handler, True,
                                 existing.kind, existing.action, existing.audit)
        add_post = Route(path, POST, handler, True, "post", "write")
        # 用 (path, "POST") 复合键存储 POST 分派
        routes[f"POST\x00{path}"] = add_post

    return routes


def lookup(routes: dict[str, Route], path: str, method: str) -> tuple[Route | None, str]:
    """查表：返回 (route, 405提示)。GET/HEAD 走主表，POST 走复合键。"""
    if method in ("GET", "HEAD"):
        route = routes.get(path)
        return (route, "只支持 GET") if route else (None, "")
    if method == "POST":
        post = routes.get(f"POST\x00{path}")
        if post is not None:
            return post, ""
        # 路径存在但只支持 GET → 405
        if path in routes:
            return None, "只支持 GET"
        return None, ""
    return None, "不支持的请求方法"
