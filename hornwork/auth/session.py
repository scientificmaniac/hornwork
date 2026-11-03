"""会话令牌：自研 HMAC-SHA256 签名 + 服务端哈希登记（可即时撤销）。

格式：`s1.<b64u(session_id)>.<b64u(issued_at)>.<b64u(HMAC-SHA256(k_session, 前三段))>`
- 不用 JWT：无状态令牌无法即时踢人，本场景需要"登出/改密后旧 Cookie 立即失效"；
- 服务端只存 sha256(token)，库泄露不能直接拿去用；
- 两段过期：idle（LOA2 30min / LOA3 15min）+ absolute（12h / 8h）。
"""

from __future__ import annotations

import time
from typing import Any

from ..store import now_utc
from . import crypto


class SessionError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _ttl(policy: dict | None, loa: int) -> tuple[int, int]:
    policy = policy or {}
    tier = policy.get(f"loa{int(loa)}") or {}
    default = (1800, 43200) if int(loa) <= 2 else (900, 28800)
    return int(tier.get("idle", default[0])), int(tier.get("absolute", default[1]))


def _now_iso(now: float | None) -> str:
    if now is None:
        return now_utc()
    from datetime import datetime, timezone

    return datetime.fromtimestamp(float(now), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _iso_add(now: float | None, seconds: int) -> str:
    return _now_iso((time.time() if now is None else float(now)) + seconds)


def _sign(keyring: crypto.KeyRing, body: str) -> str:
    return crypto.b64u(crypto.mac(keyring.k_session, body.encode("ascii")))


def issue(store, keyring: crypto.KeyRing, user_id: int, loa: int,
          ip: str | None = None, device_id: str | None = None,
          ua_hash: str | None = None, now: float | None = None,
          policy: dict | None = None, strong_auth: bool = False) -> dict[str, Any]:
    """签发会话：登录成功**重新签发**（防会话固定），返回令牌与行信息。"""
    idle_ttl, abs_ttl = _ttl(policy, loa)
    sid_bytes = crypto.os.urandom(16)
    sid = crypto.b64u(sid_bytes)
    issued = int(time.time() if now is None else now)
    body = f"s1.{sid}.{crypto.b64u(str(issued).encode())}"
    token = f"{body}.{_sign(keyring, body)}"
    ts = _now_iso(now)
    store.execute(
        "INSERT INTO auth_session(session_id, user_id, token_hash, loa, device_id, ip,"
        " ua_hash, created_ts, last_seen_ts, idle_expires_ts, expires_ts, strong_auth_ts)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (sid, int(user_id), crypto.sha256_hex(token.encode()), int(loa), device_id, ip,
         ua_hash, ts, ts, _iso_add(now, idle_ttl), _iso_add(now, abs_ttl),
         ts if strong_auth else None),
    )
    return {"token": token, "session_id": sid, "loa": int(loa),
            "created_ts": ts, "idle_expires_ts": _iso_add(now, idle_ttl),
            "expires_ts": _iso_add(now, abs_ttl), "device_id": device_id}


def verify(store, keyring: crypto.KeyRing, token: str, now: float | None = None,
           touch: bool = True, policy: dict | None = None) -> dict[str, Any]:
    """校验签名 → 查登记 → 未撤销未过期 → 刷新 idle 窗口。"""
    parts = (token or "").split(".")
    if len(parts) != 4 or parts[0] != "s1":
        raise SessionError("malformed")
    body = ".".join(parts[:3])
    if not crypto.const_compare(_sign(keyring, body), parts[3]):
        raise SessionError("bad_mac")
    row = store.query_one(
        "SELECT * FROM auth_session WHERE token_hash=?",
        (crypto.sha256_hex(token.encode()),),
    )
    if not row:
        raise SessionError("unknown")
    if int(row["revoked"]):
        raise SessionError("revoked")
    ts_now = now_iso = _now_iso(now)
    if str(row["expires_ts"]) <= now_iso:
        raise SessionError("expired")
    if str(row["idle_expires_ts"]) <= now_iso:
        raise SessionError("idle_expired")
    if touch:
        idle_ttl, _abs = _ttl(policy, int(row["loa"]))
        new_idle = min(_iso_add(now, idle_ttl), str(row["expires_ts"]))
        store.execute(
            "UPDATE auth_session SET last_seen_ts=?, idle_expires_ts=? WHERE session_id=?",
            (now_iso, new_idle, row["session_id"]),
        )
        row["last_seen_ts"] = now_iso
        row["idle_expires_ts"] = new_idle
    return row


def revoke_token(store, keyring: crypto.KeyRing, token: str, reason: str = "logout") -> bool:
    try:
        row = verify(store, keyring, token, touch=False)
    except SessionError:
        return False
    store.execute(
        "UPDATE auth_session SET revoked=1, revoke_reason=? WHERE session_id=?",
        (reason, row["session_id"]),
    )
    return True


def revoke_user(store, user_id: int, reason: str = "password_changed") -> int:
    cur = store.execute(
        "UPDATE auth_session SET revoked=1, revoke_reason=? WHERE user_id=? AND revoked=0",
        (reason, int(user_id)),
    )
    return cur.rowcount


def list_sessions(store, user_id: int | None = None, active_only: bool = True,
                  limit: int = 50) -> list[dict]:
    sql = "SELECT * FROM auth_session WHERE 1=1"
    args: list[Any] = []
    if user_id is not None:
        sql += " AND user_id=?"
        args.append(int(user_id))
    if active_only:
        sql += " AND revoked=0 AND expires_ts>?"
        args.append(now_utc())
    sql += " ORDER BY created_ts DESC LIMIT ?"
    args.append(int(limit))
    return store.query(sql, args)


def upgrade(store, session_id: str, loa: int,
            policy: dict | None = None) -> None:
    """step-up：提升会话 LOA，刷新 idle/absolute 与强认证时间。"""
    ts = now_utc()
    idle_ttl, abs_ttl = _ttl(policy, loa)
    store.execute(
        "UPDATE auth_session SET loa=?, strong_auth_ts=?, last_seen_ts=?,"
        " idle_expires_ts=?, expires_ts=? WHERE session_id=?",
        (int(loa), ts, ts, _iso_add(None, idle_ttl), _iso_add(None, abs_ttl), session_id),
    )


# ---------------------------------------------------------------------------
# 设备信任：只影响风险分，不减少任何必需因子
# ---------------------------------------------------------------------------
def trust_device(store, keyring: crypto.KeyRing, user_id: int, label: str = "",
                 ttl: int = 604800, now: float | None = None) -> dict[str, Any]:
    device_id = crypto.b64u(crypto.os.urandom(16))
    issued = int(time.time() if now is None else now)
    body = f"d1.{device_id}.{int(user_id)}.{crypto.b64u(str(issued).encode())}"
    token = f"{body}.{_sign(keyring, body)}"
    store.execute(
        "INSERT INTO trusted_device(device_id, user_id, label, issued_ts, expires_ts)"
        " VALUES(?,?,?,?,?)",
        (device_id, int(user_id), label, _now_iso(now), _iso_add(now, ttl)),
    )
    return {"device_id": device_id, "device_token": token, "expires_ts": _iso_add(now, ttl)}


def verify_device(keyring: crypto.KeyRing, token: str | None) -> tuple[str, int] | None:
    parts = (token or "").split(".")
    if len(parts) != 5 or parts[0] != "d1":
        return None
    body = ".".join(parts[:4])
    if not crypto.const_compare(_sign(keyring, body), parts[4]):
        return None
    try:
        return parts[1], int(parts[2])
    except ValueError:
        return None


def device_is_trusted(store, user_id: int, device_id: str | None,
                      now: float | None = None) -> bool:
    if not device_id:
        return False
    row = store.query_one(
        "SELECT * FROM trusted_device WHERE device_id=? AND user_id=? AND revoked=0",
        (device_id, int(user_id)),
    )
    if not row:
        return False
    return str(row["expires_ts"]) > _now_iso(now)


def revoke_devices(store, user_id: int) -> int:
    cur = store.execute(
        "UPDATE trusted_device SET revoked=1 WHERE user_id=? AND revoked=0", (int(user_id),))
    return cur.rowcount
