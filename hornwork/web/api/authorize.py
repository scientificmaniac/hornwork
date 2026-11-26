"""统一授权 mixin：票据判定 → 状态机决策 → console_access 审计 → HTTP 错误映射。

从 server.py 抽出，保持传输层精简（与其余 api/* 域 mixin 同构）。
关键约定：step-up / 角色不足返回 403，只有票据失效才是 401 —— 前端 client.ts
的拦截器见 401 会清会话跳登录，而这三类情况下会话是有效的。
"""

from __future__ import annotations

import hmac
import json

from ..errors import HttpError as _HttpError
from ...auth import policy as _auth_policy

# 无 token 配置时允许的本机来源（与 server.py 的 LOOPBACK 保持一致）
_LOOPBACK = {"127.0.0.1", "localhost", "::1", ""}

# 需要重新强认证的 reason（403 而非 401）
_STEPUP_REASONS = {
    "stepup_required", "loa_too_low", "strong_auth_expired", "session_ip_drift",
}


class AuthorizeMixin:
    """Web 请求统一授权。依赖 self 上的 app / headers / client_address / path / _session_token。"""

    def _bearer(self) -> str:
        header = self.headers.get("Authorization") or ""
        return header[7:].strip() if header.startswith("Bearer ") else ""

    def _is_static_token(self) -> bool:
        """Q1：静态 Bearer token = 非用户运维通道，不进角色模型。"""
        token = self.app.token
        given = self._bearer()
        return bool(token and given and hmac.compare_digest(
            given.encode("utf-8"), token.encode("utf-8")))

    def _ua(self) -> str | None:
        return self.headers.get("User-Agent")

    def _request_ip(self) -> str | None:
        return self.client_address[0] if self.client_address else None

    def _authorize(self, route) -> dict:
        """统一授权入口。"""
        if self._is_static_token():
            ctx = {"decision": "allow", "reason": "ops_token", "action": route.action,
                   "loa": 3, "role": "ops", "username": "__token__", "user_id": None,
                   "session": None, "risk": None}
        else:
            token = self._session_token()
            if not token:
                host = self._request_ip() or ""
                if not self.app.token and (host in _LOOPBACK or host.startswith("127.")):
                    ctx = {"decision": "allow", "reason": "loopback", "action": route.action,
                           "loa": 3, "role": "ops", "username": "__loopback__",
                           "user_id": None, "session": None, "risk": None}
                else:
                    ctx = {"decision": "deny", "reason": "missing_token",
                           "action": route.action, "loa": 0, "role": "",
                           "username": None, "user_id": None}
            else:
                try:
                    ctx = self._auth_engine().authorize(
                        token, route.action, ua=self._ua(), request_ip=self._request_ip())
                except Exception as exc:  # noqa: BLE001 - 认证库未初始化按 503
                    self.app.note_error()
                    raise _HttpError(503, "认证服务不可用", retryable=True,
                                     detail=str(exc)) from exc

        # 只对真实用户会话写访问审计；静态 token / 回环开发通道为非用户通道（Q1）
        if route.audit and ctx.get("user_id") is not None:
            self._append_console_access(route, ctx)

        if ctx["decision"] == "allow":
            return ctx

        reason = str(ctx.get("reason") or "")
        if reason in _STEPUP_REASONS:
            raise _HttpError(403, "需要提升认证等级", retryable=False,
                             detail=json.dumps({"reason": reason, "loa": ctx.get("loa"),
                                                "action": route.action,
                                                "required_loa": _auth_policy.min_loa(route.action)},
                                               ensure_ascii=False))
        if reason == "role_denied":
            raise _HttpError(403, "当前角色无权执行该操作", retryable=False,
                             detail=json.dumps({"reason": reason, "role": ctx.get("role"),
                                                "required_role": ctx.get("required_role"),
                                                "action": route.action}, ensure_ascii=False))
        # 其余（含 missing_token / 各类会话失效）统一 401
        raise _HttpError(401, "未授权：会话无效或缺少令牌", retryable=False,
                         detail=json.dumps({"reason": reason, "action": route.action},
                                           ensure_ascii=False))

    def _append_console_access(self, route, ctx: dict) -> None:
        """Q3：审计写失败 → 500 拒绝 + DLQ，绝不留下无审计的访问。"""
        from ...auth import audit as auth_audit

        try:
            srow = ctx.get("session") or {}
            auth_audit.append(
                self.app.store, event="console_access", result=ctx["decision"],
                username=ctx.get("username"), user_id=ctx.get("user_id"),
                factor=route.action, loa=ctx.get("loa") or None,
                ip=(srow.get("request_ip") if srow else self._request_ip()),
                device_id=srow.get("device_id") if srow else None,
                detail=json.dumps({
                    "path": self.path, "method": getattr(self, "_method", "?"),
                    "session_id": srow.get("session_id") if srow else None,
                    "reason": ctx.get("reason"), "role": ctx.get("role"),
                    "decision": ctx["decision"],
                }, ensure_ascii=False, default=str),
            )
        except Exception as exc:  # noqa: BLE001
            self.app.note_error()
            try:
                self.app.store.dlq_add("auth.access_audit", {
                    "path": self.path, "action": route.action,
                    "decision": ctx.get("decision"), "username": ctx.get("username"),
                }, repr(exc))
            except Exception:  # noqa: BLE001
                pass
            raise _HttpError(500, "审计写入失败，请求已被拒绝", retryable=True,
                             detail="audit_write_failed") from exc
