"""SQLite 存储层（WAL）。

对外约定：
- 单连接 + RLock，允许在采集线程/网络线程/Web 线程中并发调用；
- 所有写操作内部 commit，异常向上抛（由调用方决定降级）；
- 复杂查询统一返回 dict 列表（payload 字段已 JSON 解码）；
- 表结构与 一致，另加 meta / mem_hits 两张辅助表。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from . import schema

DDL = [
    """CREATE TABLE IF NOT EXISTS event (
      event_id    TEXT PRIMARY KEY,
      ts          TEXT NOT NULL,
      event_type  TEXT NOT NULL,
      source_layer TEXT NOT NULL,
      host_id     TEXT NOT NULL,
      engine      TEXT,
      payload     JSON NOT NULL,
      created_at  TEXT DEFAULT (datetime('now'))
    )""",
    "CREATE INDEX IF NOT EXISTS idx_event_ts   ON event(ts)",
    "CREATE INDEX IF NOT EXISTS idx_event_type ON event(event_type, ts)",
    "CREATE INDEX IF NOT EXISTS idx_event_host ON event(host_id, ts)",
    """CREATE TABLE IF NOT EXISTS alert (
      alert_id    TEXT PRIMARY KEY,
      ts          TEXT NOT NULL,
      rule_id     TEXT NOT NULL,
      rule_version TEXT,
      engine      TEXT NOT NULL,
      level       INTEGER NOT NULL,
      technique   TEXT,
      confidence  INTEGER,
      dedup_key   TEXT,
      status      TEXT DEFAULT 'open',
      payload     JSON NOT NULL
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_dedup ON alert(dedup_key, substr(ts,1,16))",
    "CREATE INDEX IF NOT EXISTS idx_alert_ts ON alert(ts)",
    "CREATE INDEX IF NOT EXISTS idx_alert_rule ON alert(rule_id, ts)",
    """CREATE TABLE IF NOT EXISTS scan_result (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      ts          TEXT NOT NULL,
      path        TEXT NOT NULL,
      sha256      TEXT,
      size        INTEGER,
      verdict     TEXT,
      score       INTEGER,
      hits        JSON,
      first_hit   TEXT,
      cost_ms     INTEGER
    )""",
    "CREATE INDEX IF NOT EXISTS idx_scan_sha ON scan_result(sha256)",
    "CREATE INDEX IF NOT EXISTS idx_scan_ts ON scan_result(ts)",
    """CREATE TABLE IF NOT EXISTS hash_cache (
      sha256      TEXT PRIMARY KEY,
      verdict     TEXT NOT NULL,
      updated_at  TEXT DEFAULT (datetime('now'))
    )""",
    """CREATE TABLE IF NOT EXISTS ioc (
      ioc_id      TEXT PRIMARY KEY,
      type        TEXT NOT NULL,
      value       TEXT NOT NULL,
      confidence  INTEGER DEFAULT 50,
      tlp         TEXT DEFAULT 'amber',
      source      TEXT,
      status      TEXT DEFAULT 'candidate',
      first_seen  TEXT, last_seen TEXT,
      expires_at  TEXT,
      whitelisted INTEGER DEFAULT 0
    )""",
    "CREATE INDEX IF NOT EXISTS idx_ioc_type_value ON ioc(type, value)",
    """CREATE TABLE IF NOT EXISTS baseline (
      path        TEXT PRIMARY KEY,
      sha256      TEXT, mode TEXT, uid INTEGER, size INTEGER,
      mtime       TEXT, updated_at TEXT DEFAULT (datetime('now'))
    )""",
    """CREATE TABLE IF NOT EXISTS case_ (
      case_id     TEXT PRIMARY KEY,
      title       TEXT,
      severity    TEXT,
      status      TEXT DEFAULT 'open',
      dedup_key   TEXT,
      created_at  TEXT, closed_at TEXT,
      verdict     TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS action_audit (
      seq         INTEGER PRIMARY KEY AUTOINCREMENT,
      ts          TEXT NOT NULL,
      action_id   TEXT NOT NULL,
      case_id     TEXT,
      actor       TEXT,
      action      TEXT,
      target      TEXT,
      mode        TEXT,
      result      TEXT,
      prev_hash   TEXT,
      hash        TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS validation (
      run_id      TEXT,
      case_id     TEXT,
      technique   TEXT,
      expected    TEXT,
      observed    TEXT,
      verdict     TEXT,
      mttd_sec    INTEGER,
      payload     JSON,
      PRIMARY KEY (run_id, case_id)
    )""",
    """CREATE TABLE IF NOT EXISTS sigma_stat (
      rule_id     TEXT PRIMARY KEY,
      supported   INTEGER,
      hits        INTEGER DEFAULT 0,
      fp          INTEGER DEFAULT 0,
      last_hit    TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS engine_stat (
      engine      TEXT,
      day         TEXT,
      files       INTEGER DEFAULT 0,
      hits        INTEGER DEFAULT 0,
      malicious   INTEGER DEFAULT 0,
      cost_ms     INTEGER DEFAULT 0,
      errors      INTEGER DEFAULT 0,
      PRIMARY KEY (engine, day)
    )""",
    """CREATE TABLE IF NOT EXISTS dlq (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      ts          TEXT, topic TEXT, payload TEXT, error TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS meta (
      k TEXT PRIMARY KEY,
      v TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS mem_hits (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      ts          TEXT NOT NULL,
      pid         INTEGER,
      start       INTEGER,
      "end"       INTEGER,
      perms       TEXT,
      pathname    TEXT,
      kind        TEXT,
      sha256      TEXT,
      payload     JSON
    )""",
    "CREATE INDEX IF NOT EXISTS idx_mem_ts ON mem_hits(ts)",
    "CREATE INDEX IF NOT EXISTS idx_mem_pid ON mem_hits(pid)",
    """CREATE TABLE IF NOT EXISTS mem_scan (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      ts          TEXT NOT NULL,
      pid         INTEGER,
      snapshot_dir TEXT,
      verdict     TEXT,
      payload     JSON
    )""",
]


def now_utc() -> str:
    return schema.utc_now()


def days_ago_iso(days: int) -> str:
    """N 天前的 UTC ISO 时间串（用于与 ts 列做字符串比较）。"""
    return (
        datetime.now(timezone.utc) - timedelta(days=int(days))
    ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_since(spec: Any, default_seconds: int = 3600) -> str:
    """把 "5m"/"2h"/"1d"/ISO 时间 归一成 UTC ISO 字符串。"""
    if spec is None:
        spec = f"{default_seconds}s"
    if isinstance(spec, str):
        s = spec.strip()
        if s.endswith(("m", "h", "d", "s")) and s[:-1].replace(".", "", 1).isdigit():
            mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[s[-1]]
            seconds = float(s[:-1]) * mult
            return (
                datetime.now(timezone.utc) - timedelta(seconds=seconds)
            ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if "T" in s or s.count("-") >= 2:
            return schema.to_utc(s)
    if isinstance(spec, (int, float)):
        return schema.to_utc(spec)
    return schema.utc_now()


class Store:
    def __init__(self, db_path: str | Path):
        self.path = Path(str(db_path))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=15)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=15000")
        self.init_schema()

    # ------------------------------------------------------------------ 基础
    def init_schema(self) -> None:
        with self._lock:
            for stmt in DDL:
                self.conn.execute(stmt)
            self.conn.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.commit()
            finally:
                self.conn.close()

    def execute(self, sql: str, args: Iterable = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, tuple(args))
            self.conn.commit()
            return cur

    def query(self, sql: str, args: Iterable = ()) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(sql, tuple(args))
            return [dict(row) for row in cur.fetchall()]

    def query_one(self, sql: str, args: Iterable = ()) -> dict | None:
        rows = self.query(sql, args)
        return rows[0] if rows else None

    # ------------------------------------------------------------------ 事件
    def insert_event(self, ev: dict, engine: str | None = None) -> bool:
        try:
            payload = schema.dumps(ev)
        except (TypeError, ValueError):
            payload = schema.dumps({"raw": str(ev)[:4000]})
        host_id = str((ev.get("host") or {}).get("host_id") or "unknown")
        with self._lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO event(event_id, ts, event_type, source_layer, host_id, engine, payload)"
                " VALUES(?,?,?,?,?,?,?)",
                (
                    ev.get("event_id"), ev.get("ts"), ev.get("event_type"),
                    ev.get("source_layer"), host_id, engine, payload,
                ),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def query_events(
        self,
        event_type: str | None = None,
        since: str | None = None,
        limit: int = 100,
        source_layer: str | None = None,
    ) -> list[dict]:
        sql = "SELECT * FROM event WHERE 1=1"
        args: list[Any] = []
        if event_type:
            sql += " AND event_type=?"
            args.append(event_type)
        if source_layer:
            sql += " AND source_layer=?"
            args.append(source_layer)
        if since:
            sql += " AND ts>=?"
            args.append(parse_since(since))
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        rows = self.query(sql, args)
        out = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                payload = {"raw": row["payload"]}
            payload["_row"] = {
                "engine": row["engine"],
                "created_at": row["created_at"],
            }
            out.append(payload)
        return out

    def count_events(self, since: str | None = None) -> int:
        if since:
            row = self.query_one("SELECT COUNT(*) AS n FROM event WHERE ts>=?", (parse_since(since),))
        else:
            row = self.query_one("SELECT COUNT(*) AS n FROM event")
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------ 告警
    def insert_alert(self, alert: dict) -> bool:
        rule = alert.get("rule") or {}
        try:
            payload = schema.dumps(alert)
        except (TypeError, ValueError):
            payload = schema.dumps({"rule": rule, "ts": alert.get("ts")})
        with self._lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO alert(alert_id, ts, rule_id, rule_version, engine, level,"
                " technique, confidence, dedup_key, status, payload)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    alert.get("alert_id"), alert.get("ts"), rule.get("id"),
                    rule.get("version"), rule.get("engine"), int(alert.get("level", 0)),
                    alert.get("technique"), int(alert.get("confidence", 0)),
                    alert.get("dedup_key"), alert.get("status", "open"), payload,
                ),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def query_alerts(
        self,
        since: str | None = None,
        level_min: int | None = None,
        technique: str | None = None,
        rule_ids: list[str] | None = None,
        limit: int = 100,
    ) -> list[dict]:
        sql = "SELECT * FROM alert WHERE 1=1"
        args: list[Any] = []
        if since:
            sql += " AND ts>=?"
            args.append(parse_since(since))
        if level_min is not None:
            sql += " AND level>=?"
            args.append(int(level_min))
        if technique:
            sql += " AND technique=?"
            args.append(technique)
        if rule_ids:
            sql += " AND rule_id IN (%s)" % ",".join("?" * len(rule_ids))
            args.extend(rule_ids)
        sql += " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        rows = self.query(sql, args)
        out = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                payload = {"raw": row["payload"]}
            payload.setdefault("status", row["status"])
            payload["_row"] = {
                "alert_id": row["alert_id"], "engine": row["engine"],
                "level": row["level"], "status": row["status"],
            }
            out.append(payload)
        return out

    def alerts_in_window(
        self,
        t0: str,
        t1: str | None = None,
        rule_ids: list[str] | None = None,
        technique: str | None = None,
    ) -> list[dict]:
        t1 = t1 or schema.utc_now()
        sql = "SELECT * FROM alert WHERE ts>=? AND ts<=?"
        args: list[Any] = [schema.to_utc(t0), schema.to_utc(t1)]
        if rule_ids:
            sql += " AND rule_id IN (%s)" % ",".join("?" * len(rule_ids))
            args.extend(rule_ids)
        if technique:
            sql += " AND technique=?"
            args.append(technique)
        sql += " ORDER BY ts ASC"
        rows = self.query(sql, args)
        out = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                payload = {"raw": row["payload"]}
            payload["_row"] = {"level": row["level"], "engine": row["engine"]}
            out.append(payload)
        return out

    def count_alerts(self, since: str | None = None, level_min: int | None = None) -> int:
        sql = "SELECT COUNT(*) AS n FROM alert WHERE 1=1"
        args: list[Any] = []
        if since:
            sql += " AND ts>=?"
            args.append(parse_since(since))
        if level_min is not None:
            sql += " AND level>=?"
            args.append(int(level_min))
        row = self.query_one(sql, args)
        return int(row["n"]) if row else 0

    def set_alert_status(self, alert_id: str, status: str) -> None:
        self.execute(
            "UPDATE alert SET status=? WHERE alert_id=?",
            (status, alert_id),
        )

    # ------------------------------------------------------------------ 扫描结果
    def insert_scan_result(self, rec: dict) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO scan_result(ts, path, sha256, size, verdict, score, hits, first_hit, cost_ms)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    rec.get("ts") or now_utc(), rec.get("path"), rec.get("sha256"),
                    rec.get("size"), rec.get("verdict"), rec.get("score"),
                    schema.dumps(rec.get("hits") or []),
                    rec.get("first_hit"), rec.get("cost_ms"),
                ),
            )
            self.conn.commit()
            return int(cur.lastrowid or 0)

    def scan_by_sha(self, sha256: str) -> dict | None:
        return self.query_one(
            "SELECT * FROM scan_result WHERE sha256=? ORDER BY ts DESC LIMIT 1", (sha256,)
        )

    def recent_scans(self, since: str | None = None, limit: int = 50) -> list[dict]:
        sql = "SELECT * FROM scan_result WHERE 1=1"
        args: list[Any] = []
        if since:
            sql += " AND ts>=?"
            args.append(parse_since(since))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        rows = self.query(sql, args)
        for row in rows:
            try:
                row["hits"] = json.loads(row.get("hits") or "[]")
            except (TypeError, json.JSONDecodeError):
                row["hits"] = []
        return rows

    def engine_contribution(self, days: int = 7) -> list[dict]:
        rows = self.query(
            "SELECT first_hit, COUNT(*) AS n FROM scan_result"
            " WHERE verdict='malicious' AND ts >= ?"
            " GROUP BY first_hit ORDER BY n DESC",
            (days_ago_iso(days),),
        )
        return rows

    def get_hash_cache(self, sha256: str) -> str | None:
        row = self.query_one("SELECT verdict FROM hash_cache WHERE sha256=?", (sha256,))
        return row["verdict"] if row else None

    def set_hash_cache(self, sha256: str, verdict: str) -> None:
        self.execute(
            "INSERT INTO hash_cache(sha256, verdict, updated_at) VALUES(?,?,datetime('now'))"
            " ON CONFLICT(sha256) DO UPDATE SET verdict=excluded.verdict, updated_at=datetime('now')",
            (sha256, verdict),
        )

    # ------------------------------------------------------------------ 引擎统计
    def engine_stat_add(
        self,
        engine: str,
        files: int = 0,
        hits: int = 0,
        malicious: int = 0,
        cost_ms: int = 0,
        errors: int = 0,
    ) -> None:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self.execute(
            "INSERT INTO engine_stat(engine, day, files, hits, malicious, cost_ms, errors)"
            " VALUES(?,?,?,?,?,?,?)"
            " ON CONFLICT(engine, day) DO UPDATE SET"
            " files=files+excluded.files, hits=hits+excluded.hits,"
            " malicious=malicious+excluded.malicious, cost_ms=cost_ms+excluded.cost_ms,"
            " errors=errors+excluded.errors",
            (engine, day, int(files), int(hits), int(malicious), int(cost_ms), int(errors)),
        )

    def engine_stats(self, days: int = 7) -> list[dict]:
        return self.query(
            "SELECT * FROM engine_stat WHERE day >= date('now', ?) ORDER BY day DESC, engine",
            (f"-{int(days)} day",),
        )

    def sigma_stat_inc(self, rule_id: str, supported: int) -> None:
        self.execute(
            "INSERT INTO sigma_stat(rule_id, supported) VALUES(?,?)"
            " ON CONFLICT(rule_id) DO UPDATE SET supported=excluded.supported",
            (rule_id, int(supported)),
        )

    def sigma_stat_hit(self, rule_id: str) -> None:
        self.execute(
            "INSERT INTO sigma_stat(rule_id, supported, hits, last_hit) VALUES(?,1,1,?)"
            " ON CONFLICT(rule_id) DO UPDATE SET hits=hits+1, last_hit=excluded.last_hit",
            (rule_id, now_utc()),
        )

    def sigma_stats(self) -> dict:
        row = self.query_one(
            "SELECT COUNT(*) AS total, SUM(supported) AS supported, SUM(hits) AS hits FROM sigma_stat"
        ) or {}
        return {
            "total": int(row.get("total") or 0),
            "supported": int(row.get("supported") or 0),
            "hits": int(row.get("hits") or 0),
        }

    # ------------------------------------------------------------------ 情报
    def ioc_upsert(self, rec: dict) -> bool:
        ioc_id = rec.get("ioc_id") or schema.dedup_key(rec.get("type"), rec.get("value"))
        try:
            with self._lock:
                cur = self.conn.execute(
                    "INSERT INTO ioc(ioc_id,type,value,confidence,tlp,source,status,first_seen,last_seen,expires_at,whitelisted)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(ioc_id) DO UPDATE SET"
                    " confidence=excluded.confidence, last_seen=excluded.last_seen,"
                    " status=excluded.status, whitelisted=excluded.whitelisted",
                    (
                        ioc_id, rec.get("type"), rec.get("value"),
                        int(rec.get("confidence", 50)), rec.get("tlp", "amber"),
                        rec.get("source"), rec.get("status", "candidate"),
                        rec.get("first_seen") or now_utc(), rec.get("last_seen") or now_utc(),
                        rec.get("expires_at"), int(rec.get("whitelisted", 0)),
                    ),
                )
                self.conn.commit()
                return cur.rowcount > 0
        except sqlite3.Error:
            return False

    def ioc_list(self, kind: str | None = None, limit: int = 500, status: str | None = None) -> list[dict]:
        sql = "SELECT * FROM ioc WHERE 1=1"
        args: list[Any] = []
        if kind:
            sql += " AND type=?"
            args.append(kind)
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(int(limit))
        return self.query(sql, args)

    def ioc_values(self, kind: str) -> list[str]:
        return [
            r["value"]
            for r in self.query(
                "SELECT value FROM ioc WHERE type=? AND whitelisted=0 AND status!='expired'", (kind,)
            )
        ]

    def ioc_set_status(self, ioc_id: str, status: str) -> None:
        self.execute("UPDATE ioc SET status=? WHERE ioc_id=?", (status, ioc_id))

    def ioc_aging(self, ttl_days: dict | None = None) -> int:
        """按 TTL 老化：更新 last_seen 过久的记录状态。返回受影响行数。"""
        ttl_days = ttl_days or {}
        changed = 0
        for kind, days in ttl_days.items():
            days = int(days or 0)
            if days <= 0:
                continue
            cur = self.execute(
                "UPDATE ioc SET status='expired' WHERE type=? AND status!='expired'"
                " AND last_seen < ?",
                (kind, days_ago_iso(days)),
            )
            changed += cur.rowcount
        return changed

    # ------------------------------------------------------------------ 基线
    def baseline_upsert(self, rec: dict) -> None:
        self.execute(
            "INSERT INTO baseline(path, sha256, mode, uid, size, mtime, updated_at)"
            " VALUES(?,?,?,?,?,?,datetime('now'))"
            " ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256, mode=excluded.mode,"
            " uid=excluded.uid, size=excluded.size, mtime=excluded.mtime, updated_at=datetime('now')",
            (
                rec.get("path"), rec.get("sha256"), rec.get("mode"),
                rec.get("uid"), rec.get("size"), rec.get("mtime"),
            ),
        )

    def baseline_get(self, path: str) -> dict | None:
        return self.query_one("SELECT * FROM baseline WHERE path=?", (path,))

    def baseline_all(self) -> list[dict]:
        return self.query("SELECT * FROM baseline")

    # ------------------------------------------------------------------ 工单
    def insert_case(self, rec: dict) -> str:
        self.execute(
            "INSERT INTO case_(case_id, title, severity, status, dedup_key, created_at, verdict)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                rec["case_id"], rec.get("title"), rec.get("severity", "P3"),
                rec.get("status", "open"), rec.get("dedup_key"),
                rec.get("created_at") or now_utc(), rec.get("verdict"),
            ),
        )
        return rec["case_id"]

    def update_case(self, case_id: str, **fields: Any) -> bool:
        allowed = {"title", "severity", "status", "verdict", "closed_at", "dedup_key"}
        sets, args = [], []
        for key, val in fields.items():
            if key in allowed:
                sets.append(f"{key}=?")
                args.append(val)
        if not sets:
            return False
        args.append(case_id)
        cur = self.execute(f"UPDATE case_ SET {', '.join(sets)} WHERE case_id=?", args)
        return cur.rowcount > 0

    def get_case(self, case_id: str) -> dict | None:
        return self.query_one("SELECT * FROM case_ WHERE case_id=?", (case_id,))

    def list_cases(self, status: str | None = None, limit: int = 100) -> list[dict]:
        if status:
            return self.query(
                "SELECT * FROM case_ WHERE status=? ORDER BY created_at DESC LIMIT ?",
                (status, int(limit)),
            )
        return self.query("SELECT * FROM case_ ORDER BY created_at DESC LIMIT ?", (int(limit),))

    # ------------------------------------------------------------------ 审计链
    def audit_last(self) -> dict | None:
        return self.query_one("SELECT * FROM action_audit ORDER BY seq DESC LIMIT 1")

    def audit_append(self, rec: dict) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO action_audit(ts, action_id, case_id, actor, action, target, mode, result, prev_hash, hash)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    rec.get("ts") or now_utc(), rec.get("action_id"), rec.get("case_id"),
                    rec.get("actor", "hornwork"), rec.get("action"), rec.get("target"),
                    rec.get("mode"), rec.get("result"), rec.get("prev_hash"), rec.get("hash"),
                ),
            )
            self.conn.commit()
            return int(cur.lastrowid or 0)

    def audit_rows(self) -> list[dict]:
        return self.query("SELECT * FROM action_audit ORDER BY seq ASC")

    # ------------------------------------------------------------------ 验证
    def insert_validation(self, rec: dict) -> None:
        self.execute(
            "INSERT OR REPLACE INTO validation(run_id, case_id, technique, expected, observed, verdict, mttd_sec, payload)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (
                rec.get("run_id"), rec.get("case_id"), rec.get("technique"),
                rec.get("expected"), rec.get("observed"), rec.get("verdict"),
                rec.get("mttd_sec"), schema.dumps(rec.get("payload") or {}),
            ),
        )

    def validation_rows(self, run_id: str | None = None, limit: int = 500) -> list[dict]:
        if run_id:
            rows = self.query(
                "SELECT * FROM validation WHERE run_id=? ORDER BY case_id", (run_id,)
            )
        else:
            rows = self.query("SELECT * FROM validation ORDER BY rowid DESC LIMIT ?", (int(limit),))
        for row in rows:
            try:
                row["payload"] = json.loads(row.get("payload") or "{}")
            except (TypeError, json.JSONDecodeError):
                row["payload"] = {}
        return rows

    def latest_run_id(self) -> str | None:
        row = self.query_one("SELECT run_id FROM validation ORDER BY rowid DESC LIMIT 1")
        return row["run_id"] if row else None

    # ------------------------------------------------------------------ 内存
    def insert_mem_hits(self, ts: str, hits: list[dict]) -> int:
        n = 0
        with self._lock:
            for hit in hits:
                self.conn.execute(
                    'INSERT INTO mem_hits(ts,pid,start,"end",perms,pathname,kind,sha256,payload)'
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        ts, hit.get("pid"), hit.get("start"), hit.get("end"),
                        hit.get("perms"), hit.get("pathname"), hit.get("kind"),
                        hit.get("sha256"), schema.dumps(hit),
                    ),
                )
                n += 1
            self.conn.commit()
        return n

    def query_mem_hits(self, since: str | None = None, pid: int | None = None) -> list[dict]:
        sql = "SELECT * FROM mem_hits WHERE 1=1"
        args: list[Any] = []
        if since:
            sql += " AND ts>=?"
            args.append(parse_since(since))
        if pid is not None:
            sql += " AND pid=?"
            args.append(int(pid))
        sql += " ORDER BY id DESC"
        return self.query(sql, args)

    def insert_mem_scan(self, rec: dict) -> None:
        self.execute(
            "INSERT INTO mem_scan(ts, pid, snapshot_dir, verdict, payload) VALUES(?,?,?,?,?)",
            (
                rec.get("ts") or now_utc(), rec.get("pid"), rec.get("snapshot_dir"),
                rec.get("verdict"), schema.dumps(rec),
            ),
        )

    # ------------------------------------------------------------------ 元数据/DLQ
    def set_meta(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, str(value)),
        )

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.query_one("SELECT v FROM meta WHERE k=?", (key,))
        return row["v"] if row else default

    def dlq_add(self, topic: str, payload: Any, error: str) -> None:
        try:
            body = payload if isinstance(payload, str) else schema.dumps(payload)
        except (TypeError, ValueError):
            body = str(payload)[:4000]
        self.execute(
            "INSERT INTO dlq(ts, topic, payload, error) VALUES(?,?,?,?)",
            (now_utc(), topic, body[:100000], str(error)[:2000]),
        )

    def dlq_count(self) -> int:
        row = self.query_one("SELECT COUNT(*) AS n FROM dlq")
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------ 概览与维护
    def counts(self) -> dict:
        def one(sql: str, args: Iterable = ()) -> int:
            row = self.query_one(sql, args)
            return int(row["n"]) if row and row.get("n") is not None else 0

        since_24h = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        return {
            "events_total": one("SELECT COUNT(*) AS n FROM event"),
            "events_24h": one("SELECT COUNT(*) AS n FROM event WHERE ts>=?", (since_24h,)),
            "alerts_total": one("SELECT COUNT(*) AS n FROM alert"),
            "alerts_24h": one("SELECT COUNT(*) AS n FROM alert WHERE ts>=?", (since_24h,)),
            "alerts_open": one("SELECT COUNT(*) AS n FROM alert WHERE status='open'"),
            "cases_total": one("SELECT COUNT(*) AS n FROM case_"),
            "cases_open": one("SELECT COUNT(*) AS n FROM case_ WHERE status!='closed'"),
            "scans_total": one("SELECT COUNT(*) AS n FROM scan_result"),
            "iocs": one("SELECT COUNT(*) AS n FROM ioc"),
            "dlq": one("SELECT COUNT(*) AS n FROM dlq"),
            "mem_hits": one("SELECT COUNT(*) AS n FROM mem_hits"),
        }

    def prune(self, days: int = 30, scan_days: int = 7) -> dict:
        deleted = {}
        with self._lock:
            if int(days) <= 0:
                cur = self.conn.execute("DELETE FROM event")
            else:
                cur = self.conn.execute("DELETE FROM event WHERE ts < ?", (days_ago_iso(days),))
            deleted["event"] = cur.rowcount
            if int(scan_days) <= 0:
                cur = self.conn.execute("DELETE FROM scan_result")
            else:
                cur = self.conn.execute(
                    "DELETE FROM scan_result WHERE ts < ?", (days_ago_iso(scan_days),)
                )
            deleted["scan_result"] = cur.rowcount
            self.conn.commit()
        return deleted

    def vacuum(self) -> None:
        with self._lock:
            self.conn.execute("VACUUM")
            self.conn.commit()

    def db_size_bytes(self) -> int:
        try:
            size = self.path.stat().st_size
            for suffix in ("-wal", "-shm"):
                extra = Path(str(self.path) + suffix)
                if extra.exists():
                    size += extra.stat().st_size
            return size
        except OSError:
            return 0


def open_store(cfg: dict) -> Store:
    """按配置打开存储（data_dir/hornwork.db）。"""
    base = Path(str((cfg.get("general") or {}).get("data_dir", "/var/lib/hornwork")))
    return Store(base / "hornwork.db")
