"""认证审计：只追加的哈希链 + 向检测模块 事件总线/事件表 emit `logon`/`logon_fail`。

设计要点（对应开发思路 §3.3 / §5.2）：
- `auth_audit` 独立链，不复用检测模块 的 `action_audit` 链头（避免两个模块抢同一链头）；
- `row_hash = SHA-256(规范化字段 ‖ prev_hash)`，`prev_hash` 串接，链头存 `meta`；
- 事件走检测模块 的同一张 `event` 表与 schema 校验器，`source_layer=host`、
  `source_product=hornwork-auth`，不新增枚举值。
"""

from __future__ import annotations

import json
from typing import Any

from .. import schema
from ..store import now_utc
from . import db

GENESIS = "0" * 64


def _canonical(fields: dict) -> str:
    return json.dumps(fields, ensure_ascii=False, sort_keys=True, default=str,
                      separators=(",", ":"))


def _hash_row(fields: dict, prev_hash: str) -> str:
    return schema.sha256_bytes((prev_hash + "|" + _canonical(fields)).encode("utf-8"))


def chain_head(store) -> str:
    row = store.query_one("SELECT row_hash FROM auth_audit ORDER BY id DESC LIMIT 1")
    head = store.get_meta(db.CHAIN_HEAD_KEY)
    return str(row["row_hash"]) if row else (head or GENESIS)


def append(store, *, event: str, result: str, username: str | None = None,
           user_id: int | None = None, factor: str | None = None,
           loa: int | None = None, risk_score: int | None = None,
           risk_why: Any = None, ip: str | None = None,
           device_id: str | None = None, latency_ms: int | None = None,
           detail: str | None = None, ts: str | None = None) -> int:
    """写一条审计（幂等失败不抛给调用方之外的路径；调用方应保证一定写入）。"""
    ts = ts or now_utc()
    if isinstance(risk_why, (list, dict)):
        risk_why = json.dumps(risk_why, ensure_ascii=False)
    prev = chain_head(store)
    fields = {
        "ts": ts, "username": username, "user_id": user_id, "event": event,
        "factor": factor, "result": result, "loa": loa,
        "risk_score": risk_score, "risk_why": risk_why, "ip": ip,
        "device_id": device_id, "latency_ms": latency_ms, "detail": detail,
        "prev_hash": prev,
    }
    row_hash = _hash_row(fields, prev)
    cur = store.execute(
        "INSERT INTO auth_audit(ts, username, user_id, event, factor, result, loa,"
        " risk_score, risk_why, ip, device_id, latency_ms, detail, prev_hash, row_hash)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, username, user_id, event, factor, result, loa, risk_score, risk_why,
         ip, device_id, latency_ms, detail, prev, row_hash),
    )
    store.set_meta(db.CHAIN_HEAD_KEY, row_hash)
    return int(cur.lastrowid or 0)


def verify_chain(store, limit: int | None = None) -> dict[str, Any]:
    rows = store.query("SELECT * FROM auth_audit ORDER BY id")
    if limit:
        rows = rows[-int(limit):]
    prev = GENESIS
    checked = 0
    for row in rows:
        fields = {k: row[k] for k in (
            "ts", "username", "user_id", "event", "factor", "result", "loa",
            "risk_score", "risk_why", "ip", "device_id", "latency_ms", "detail",
            "prev_hash")}
        expect = _hash_row(fields, prev)
        if str(row["prev_hash"]) != prev or str(row["row_hash"]) != expect:
            return {"ok": False, "checked": checked, "bad_id": row["id"],
                    "reason": "hash_mismatch"}
        prev = str(row["row_hash"])
        checked += 1
    return {"ok": True, "checked": checked, "head": prev}


def tail(store, username: str | None = None, limit: int = 20) -> list[dict]:
    sql = "SELECT * FROM auth_audit WHERE 1=1"
    args: list[Any] = []
    if username:
        sql += " AND username=?"
        args.append(username)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    return store.query(sql, args)


def summary(store, since: str = "24h") -> dict[str, Any]:
    from ..store import parse_since

    since_ts = parse_since(since)
    rows = store.query(
        "SELECT event, result, factor, latency_ms FROM auth_audit WHERE ts>=?", (since_ts,))
    lat = sorted(int(r["latency_ms"]) for r in rows if r.get("latency_ms") is not None)

    def pct(p: float) -> int | None:
        if not lat:
            return None
        idx = min(len(lat) - 1, max(0, int(round((len(lat) - 1) * p))))
        return lat[idx]

    by_event: dict[str, int] = {}
    for row in rows:
        by_event[row["event"]] = by_event.get(row["event"], 0) + 1
    success = sum(1 for r in rows if r["event"] == "logon" and r["result"] == "ok")
    fail = sum(1 for r in rows if r["event"] == "logon_fail")
    degraded = sum(1 for r in rows if r["result"] == "degraded")
    attempts = success + fail
    return {
        "since": since,
        "events": by_event,
        "logon_ok": success,
        "logon_fail": fail,
        "degraded": degraded,
        "intercept_rate": round(1.0 - success / attempts, 4) if attempts else None,
        "latency_ms": {"p50": pct(0.50), "p95": pct(0.95), "n": len(lat)},
    }


def emit_event(store, cfg: dict, event_type: str, *, username: str,
               user_id: int | None = None, result: str = "ok",
               factors: list[str] | None = None, loa: int | None = None,
               risk: dict | None = None, degraded: bool = False,
               latency_ms: int | None = None, ip: str | None = None,
               detail: str | None = None) -> bool:
    """向检测模块 事件表写 `logon` / `logon_fail`（IF-27）。失败写 DLQ，不阻断登录。"""
    try:
        payload = {
            "loa": loa,
            "factors": list(factors or []),
            "risk": (risk or {}).get("score"),
            "risk_why": (risk or {}).get("why"),
            "degraded": bool(degraded),
            "latency_ms": latency_ms,
            "detail": detail,
        }
        ev = schema.new_event(
            event_type, "host", "hornwork-auth", cfg,
            user={"name": username, "id": user_id, "action": event_type},
            network=({"src_ip": ip, "dst_port": 8443, "proto": "tcp",
                      "direction": "inbound"} if ip else None),
            raw={"auth": payload},
        )
        return store.insert_event(ev)
    except Exception as exc:  # noqa: BLE001 - 审计不能因总线/序列化失败而丢
        try:
            store.dlq_add("auth.event", {"event_type": event_type, "username": username},
                          repr(exc))
        except Exception:  # noqa: BLE001
            pass
        return False
