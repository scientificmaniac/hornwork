"""风险评分：信号 → 权重 → 分数 → 策略（决定"要几个因子"，而不是"放不放行"）。

规则全部落 `auth_policy` 表（`risk.weights` / `risk.thresholds`），可改权重做对比测试。
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..store import days_ago_iso
from . import db, session

ACTION_LOA = {"read": 2, "write": 3, "admin": 3, "sensitive": 3, "ssh": 3}


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _ip_prefix(ip: str | None) -> str:
    """IPv4 取 /24 粗判网段（本地无 GeoIP，诚实标注不做地理定位）。"""
    if not ip:
        return ""
    parts = str(ip).split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else str(ip)


def known_device(store, user_id: int, device_id: str | None) -> bool:
    return session.device_is_trusted(store, user_id, device_id)


def last_logon(store, user_id: int) -> dict | None:
    return store.query_one(
        "SELECT * FROM auth_audit WHERE user_id=? AND event='logon' AND result='ok'"
        " ORDER BY id DESC LIMIT 1",
        (int(user_id),),
    )


def ip_reputation(store, ip: str | None) -> bool:
    if not ip:
        return False
    row = store.query_one(
        "SELECT 1 AS hit FROM ioc WHERE type='ip' AND value=? AND whitelisted=0"
        " AND (status IS NULL OR status!='whitelisted') LIMIT 1",
        (str(ip),),
    )
    return bool(row)


def recent_fail_count(store, username: str, window_sec: int = 600) -> int:
    row = store.query_one(
        "SELECT COUNT(*) AS n FROM auth_audit WHERE username=? AND event='logon_fail'"
        " AND ts>=?",
        (username, _iso_ago(window_sec)),
    )
    return int(row["n"]) if row else 0


def recent_totp_fail(store, username: str, window_sec: int = 600) -> int:
    row = store.query_one(
        "SELECT COUNT(*) AS n FROM auth_audit WHERE username=? AND event='logon_fail'"
        " AND factor='totp' AND ts>=?",
        (username, _iso_ago(window_sec)),
    )
    return int(row["n"]) if row else 0


def _iso_ago(seconds: int) -> str:
    from datetime import timedelta

    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def unusual_time(store, user_id: int, now: datetime | None = None) -> bool:
    """02:00~06:00 且近 30 天该用户没有深夜登录历史。"""
    now = now or datetime.now(timezone.utc)
    if now.hour not in (2, 3, 4, 5):
        return False
    row = store.query_one(
        "SELECT COUNT(*) AS n FROM auth_audit WHERE user_id=? AND event='logon'"
        " AND result='ok' AND ts>=? AND substr(ts,12,2) IN ('02','03','04','05')",
        (int(user_id), days_ago_iso(30)),
    )
    return int(row["n"] if row else 0) == 0


def score(store, user: dict, *, ip: str | None = None, device_id: str | None = None,
          now: datetime | None = None, weights: dict | None = None,
          totp_failed: bool = False) -> dict:
    """返回 {score, why, level, action}；why 是可直接入审计的字符串数组。"""
    weights = weights or db.policy_section(store, "risk.weights")
    thresholds = db.policy_section(store, "risk.thresholds")
    now = now or datetime.now(timezone.utc)
    user_id = int(user["id"])
    username = str(user["username"])
    total = 0
    why: list[str] = []

    def add(name: str, delta: int, label: str) -> None:
        nonlocal total
        if delta:
            total += int(delta)
            why.append(f"{label or name}{int(delta):+d}")

    trusted = known_device(store, user_id, device_id)
    if not trusted:
        add("new_device", int(weights.get("new_device", 20)), "新设备")
    else:
        add("known_device", int(weights.get("known_device", -20)), "已知设备")

    prev = last_logon(store, user_id)
    if prev and prev.get("ip") and ip and _ip_prefix(prev["ip"]) != _ip_prefix(ip):
        add("ip_change", int(weights.get("ip_change", 15)), "IP段变化")

    if ip_reputation(store, ip):
        add("ioc_ip", int(weights.get("ioc_ip", 30)), "IP命中IOC")

    fails = recent_fail_count(store, username)
    if fails:
        add("fail_each", min(int(weights.get("fail_cap", 30)),
                             fails * int(weights.get("fail_each", 10))), "近期失败")

    if unusual_time(store, user_id, now):
        add("unusual_time", int(weights.get("unusual_time", 10)), "非常用时段")

    if totp_failed or recent_totp_fail(store, username):
        add("totp_fail", int(weights.get("totp_fail", 15)), "TOTP失败")

    total = max(0, min(100, total))
    loa3_at = int(thresholds.get("loa3", 30))
    warn_at = int(thresholds.get("warn", 60))
    lock_at = int(thresholds.get("lock", 80))
    if total >= lock_at:
        level, action = "极高", "lockout"
    elif total >= warn_at:
        level, action = "高", "loa3_warn"
    elif total >= loa3_at:
        level, action = "中", "loa3"
    else:
        level, action = "低", "loa2"
    required_loa = 2 if action == "loa2" else 3
    return {"score": total, "why": why, "level": level, "action": action,
            "required_loa": required_loa, "known_device": trusted}


def explain(store, user: dict, ip: str | None = None,
            device_id: str | None = None) -> dict:
    res = score(store, user, ip=ip, device_id=device_id)
    res["policy"] = {
        "weights": db.policy_section(store, "risk.weights"),
        "thresholds": db.policy_section(store, "risk.thresholds"),
    }
    return res


def required_loa(action: str) -> int:
    return ACTION_LOA.get(action, 2)
