"""认证审计：只追加的哈希链 + 向检测模块 事件总线/事件表 emit `logon`/`logon_fail`。

设计要点：
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


def _build_fields(*, event: str, result: str, username: str | None = None,
                  user_id: int | None = None, factor: str | None = None,
                  loa: int | None = None, risk_score: int | None = None,
                  risk_why: Any = None, ip: str | None = None,
                  device_id: str | None = None, latency_ms: int | None = None,
                  detail: str | None = None, ts: str | None = None,
                  prev: str) -> dict[str, Any]:
    """构造规范化审计字段并计算 row_hash（纯函数，不含任何 IO）。

    调用方负责归一化 ``ts`` 与 ``risk_why``；此处不再重复，以保证 builder 可在
    事务内被调用而不产生非确定性。
    """
    fields: dict[str, Any] = {
        "ts": ts, "username": username, "user_id": user_id, "event": event,
        "factor": factor, "result": result, "loa": loa,
        "risk_score": risk_score, "risk_why": risk_why, "ip": ip,
        "device_id": device_id, "latency_ms": latency_ms, "detail": detail,
        "prev_hash": prev,
    }
    fields["row_hash"] = _hash_row(fields, prev)
    return fields


def append(store, *, event: str, result: str, username: str | None = None,
           user_id: int | None = None, factor: str | None = None,
           loa: int | None = None, risk_score: int | None = None,
           risk_why: Any = None, ip: str | None = None,
           device_id: str | None = None, latency_ms: int | None = None,
           detail: str | None = None, ts: str | None = None) -> int:
    """写一条审计。

    ``console_*``（Web 访问审计）走 ``store.auth_audit_append_atomic``：读链头、
    算哈希、INSERT、推进链头全在同一 SQLite 写事务内，消除命令行/多线程/多进程
    并发写者读到同一 prev_hash 的断链竞态（与 action_audit 的 BUG-03 同款）。

    身份类事件（logon/logon_fail/...）暂走原路径，缩小回归面；后续单独迁移。
    """
    # 归一化只做一次：ts 默认值与 risk_why 的 JSON 化都在事务外完成，
    # 传入 _build_fields 时不再重复，保证 builder 是纯函数。
    ts = ts or now_utc()
    if isinstance(risk_why, (list, dict)):
        risk_why = json.dumps(risk_why, ensure_ascii=False)

    def build(prev: str) -> dict[str, Any]:
        return _build_fields(
            event=event, result=result, username=username, user_id=user_id,
            factor=factor, loa=loa, risk_score=risk_score, risk_why=risk_why,
            ip=ip, device_id=device_id, latency_ms=latency_ms, detail=detail,
            ts=ts, prev=prev,
        )

    if str(event).startswith("console_"):
        # prev 必须由事务内读到的链头决定，不能在外层先算哈希。
        return append_atomic(store, build)

    prev = chain_head(store)
    fields = build(prev)
    row_hash = fields["row_hash"]
    cur = store.execute(
        "INSERT INTO auth_audit(ts, username, user_id, event, factor, result, loa,"
        " risk_score, risk_why, ip, device_id, latency_ms, detail, prev_hash, row_hash)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ts, username, user_id, event, factor, result, loa, risk_score, risk_why,
         ip, device_id, latency_ms, detail, prev, row_hash),
    )
    store.set_meta(db.CHAIN_HEAD_KEY, row_hash)
    return int(cur.lastrowid or 0)


def append_atomic(store, build_fields) -> int:
    """原子追加：``build_fields(prev_hash)`` 在事务内被调用，返回完整字段字典。

    prev_hash 一定来自事务内读到的真实链头，彻底消除竞态；调用方只需保证
    build_fields 是纯计算（不访问 store）。事务实现在 store 层。
    """
    return store.auth_audit_append_atomic(build_fields)


def verify_chain(store, limit: int | None = None) -> dict[str, Any]:
    rows = store.query("SELECT * FROM auth_audit ORDER BY id")
    if limit and len(rows) > int(limit):
        rows = rows[-int(limit):]
        # 截取段的起点不是创世块，用该行声明的 prev_hash 作为校验起点，
        # 否则首行必然与前一块哈希不匹配，导致传 limit 时永远误报断链。
        prev = str(rows[0]["prev_hash"])
    else:
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
