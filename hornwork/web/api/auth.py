"""认证域 handler：三因子登录 / 会话 / 用户 / 审计 / 策略。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations


from ..errors import HttpError as _HttpError
from ..common import (
    log,
    iso_now as _iso_now,
    q_int as _q_int,
)


class AuthMixin:
    """认证域 handler：三因子登录 / 会话 / 用户 / 审计 / 策略。"""

    def _auth_engine(self):
        """按需构造认证引擎：委托 WebContext 的双检锁实现，消除并发重复构造。"""
        return self.app.ctx.auth_engine()
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
            from ...auth import audit as auth_audit

            rows = auth_audit.tail(store, limit=limit)
            chain = auth_audit.verify_chain(store)
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "读取认证审计失败", detail=str(exc)) from exc
        self._send_json(200, {"items": rows, "chain": chain, "ts": _iso_now()})
    def _h_auth_policy(self, query: dict) -> None:
        try:
            from ...auth import db as auth_db

            eng = self._auth_engine()
            keys = list(auth_db.POLICY_DEFAULTS.keys())
            policy = {key: auth_db.get_policy(eng.store, key) for key in keys}
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(503, "读取认证策略失败", detail=str(exc)) from exc
        self._send_json(200, {"policy": policy, "ts": _iso_now()})
