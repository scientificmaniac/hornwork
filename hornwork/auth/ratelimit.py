"""限流与锁定：账号 / IP / TOTP 三维计数。

- 账号维度：5 次失败 / 5 min → 锁 15 min（落库 `auth_user.locked_until`，重启不失效）；
- IP 维度：20 次请求 / min（内存令牌桶，只限速不锁定，避免 NAT 误伤）；
- TOTP 维度：独立计数（防止用 TOTP 失败把口令侧策略带偏）。
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from . import db


def _dt(now: float | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    return datetime.fromtimestamp(float(now), tz=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _since(window_sec: int, now: float | None = None) -> str:
    return _iso(_dt(now) - timedelta(seconds=int(window_sec)))


class RateLimiter:
    """进程内滑动窗口计数（多实例场景需外部存储，单机足够）。"""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, scope: str, key: str, limit: int, window: float,
              now: float | None = None) -> bool:
        ts = time.time() if now is None else float(now)
        bucket = self._hits[f"{scope}:{key}"]
        while bucket and bucket[0] <= ts - window:
            bucket.popleft()
        if len(bucket) >= int(limit):
            return False
        bucket.append(ts)
        return True

    def count(self, scope: str, key: str, window: float,
              now: float | None = None) -> int:
        ts = time.time() if now is None else float(now)
        bucket = self._hits[f"{scope}:{key}"]
        while bucket and bucket[0] <= ts - window:
            bucket.popleft()
        return len(bucket)

    def reset(self) -> None:
        self._hits.clear()


def locked_until(store, user: dict) -> str | None:
    row = store.query_one("SELECT locked_until FROM auth_user WHERE id=?", (int(user["id"]),))
    return row.get("locked_until") if row else None


def is_locked(store, user: dict, now: float | None = None) -> bool:
    until = locked_until(store, user)
    return bool(until) and str(until) > _iso(_dt(now))


def lock(store, user: dict, seconds: int, now: float | None = None) -> str:
    until = _iso(_dt(now) + timedelta(seconds=int(seconds)))
    store.execute("UPDATE auth_user SET locked_until=? WHERE id=?", (until, int(user["id"])))
    return until


def unlock(store, user: dict) -> None:
    store.execute(
        "UPDATE auth_user SET locked_until=NULL, failed_count=0 WHERE id=?",
        (int(user["id"]),),
    )


def recent_pw_fail(store, username: str, window: int, now: float | None = None) -> int:
    row = store.query_one(
        "SELECT COUNT(*) AS n FROM auth_audit WHERE username=? AND event='logon_fail'"
        " AND factor='pw' AND ts>=?",
        (str(username), _since(window, now)),
    )
    return int(row["n"]) if row else 0


def record_password_failure(store, user: dict, policy: dict | None = None,
                            now: float | None = None) -> dict[str, Any]:
    """失败计数 + 达阈值即锁定；返回 {failed_count, locked_until, locked}。"""
    policy = policy or db.policy_section(store, "lockout")
    threshold = int(policy.get("account_fail", 5))
    window = int(policy.get("account_window", 300))
    count = max(1, recent_pw_fail(store, user["username"], window, now=now))
    store.execute("UPDATE auth_user SET failed_count=? WHERE id=?", (count, int(user["id"])))
    result: dict[str, Any] = {"failed_count": count, "locked_until": None, "locked": False}
    if count >= threshold:
        result["locked_until"] = lock(store, user, int(policy.get("lock_seconds", 900)), now=now)
        result["locked"] = True
    return result


def reset_failures(store, user: dict) -> None:
    store.execute("UPDATE auth_user SET failed_count=0 WHERE id=?", (int(user["id"]),))


def recent_totp_fail(store, username: str, window: int,
                     now: float | None = None) -> int:
    row = store.query_one(
        "SELECT COUNT(*) AS n FROM auth_audit WHERE username=? AND event='logon_fail'"
        " AND factor='totp' AND ts>=?",
        (str(username), _since(window, now)),
    )
    return int(row["n"]) if row else 0


def totp_denied(store, username: str, policy: dict | None = None,
                now: float | None = None) -> bool:
    policy = policy or db.policy_section(store, "lockout")
    return recent_totp_fail(store, username, int(policy.get("totp_window", 300)),
                            now=now) >= int(policy.get("totp_fail", 5))
