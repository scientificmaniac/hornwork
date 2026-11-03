"""靶场环境与动作记录的 SQLite 访问层（靶场编排层）。

复用检测模块的 `hornwork.db`，不新建数据库。表结构见设计，另加：
- `lab_env`：category/cve/title/summary/state/running/expires_at/ports_json/updated_at，
  用于索引同步与运行态跟踪；
- `lab_run`：每次动作一行（ok/error/timeout/auto_cleanup），支撑 §7.5 指标。

所有函数接收 `Store`（hornwork.store.Store），只通过 execute/query/query_one
与数据库交互，避免本模块直接持有 sqlite 连接。
"""

from __future__ import annotations

import json
from typing import Any

from .. import schema
from ..log import get_logger

log = get_logger("lab.store")

DDL = [
    """CREATE TABLE IF NOT EXISTS lab_env (
      env_id TEXT PRIMARY KEY,
      component TEXT NOT NULL,
      cwe_hint TEXT,
      compose_path TEXT NOT NULL,
      host_ports TEXT,
      image_refs TEXT,
      enabled INTEGER DEFAULT 1,
      category TEXT,
      cve TEXT,
      title TEXT,
      summary TEXT,
      state TEXT DEFAULT 'down',
      running INTEGER DEFAULT 0,
      expires_at TEXT,
      ports_json TEXT,
      updated_at TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_lab_env_cat ON lab_env(category, env_id)",
    "CREATE INDEX IF NOT EXISTS idx_lab_env_run ON lab_env(running)",
    """CREATE TABLE IF NOT EXISTS lab_run (
      run_id TEXT PRIMARY KEY,
      env_id TEXT,
      action TEXT NOT NULL,
      started_at TEXT NOT NULL,
      ended_at TEXT,
      elapsed_ms INTEGER,
      result TEXT NOT NULL,
      detail TEXT,
      ports_bound TEXT,
      cleanup_ok INTEGER DEFAULT 0
    )""",
    "CREATE INDEX IF NOT EXISTS idx_lab_run_env ON lab_run(env_id, started_at)",
    "CREATE INDEX IF NOT EXISTS idx_lab_run_ts ON lab_run(started_at)",
]

# 兼容旧库：后续版本可能新增列，启动时按需 ALTER
_EXTRA_COLUMNS = {
    "lab_env": (
        ("category", "TEXT"),
        ("cve", "TEXT"),
        ("title", "TEXT"),
        ("summary", "TEXT"),
        ("state", "TEXT"),
        ("running", "INTEGER DEFAULT 0"),
        ("expires_at", "TEXT"),
        ("ports_json", "TEXT"),
        ("updated_at", "TEXT"),
    ),
    "lab_run": (
        ("ended_at", "TEXT"),
        ("elapsed_ms", "INTEGER"),
        ("detail", "TEXT"),
        ("ports_bound", "TEXT"),
        ("cleanup_ok", "INTEGER DEFAULT 0"),
    ),
}


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _ports_json(ports: dict | None) -> str:
    clean: dict[str, int] = {}
    for key, val in (ports or {}).items():
        try:
            clean[str(int(key))] = int(val)
        except (TypeError, ValueError):
            continue
    return _dumps(clean)


def init_schema(store) -> None:
    """幂等建表（含旧库补列）。"""
    for stmt in DDL:
        store.execute(stmt)
    for table, columns in _EXTRA_COLUMNS.items():
        try:
            rows = store.query(f"PRAGMA table_info({table})")
        except Exception as exc:  # noqa: BLE001 - 建表异常向上抛更利于定位
            log.warn("读取表结构失败", table=table, error=str(exc))
            raise
        existing = {str(row.get("name")) for row in rows}
        for name, decl in columns:
            if name not in existing:
                try:
                    store.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                except Exception as exc:  # noqa: BLE001 - 并发建表时可能已存在
                    log.warn("补列失败", table=table, column=name, error=str(exc))


# ---------------------------------------------------------------------------
# lab_env
# ---------------------------------------------------------------------------
def _env_from_row(row: dict | None) -> dict | None:
    if not row:
        return None
    env = dict(row)
    raw = env.get("ports_json") or env.get("host_ports") or ""
    ports: dict[int, int] = {}
    try:
        parsed = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        parsed = {}
    if isinstance(parsed, dict):
        for key, val in parsed.items():
            try:
                ports[int(key)] = int(val)
            except (TypeError, ValueError):
                continue
    env["ports"] = ports
    try:
        images = json.loads(env.get("image_refs") or "[]")
    except (TypeError, ValueError):
        images = []
    env["images"] = images if isinstance(images, list) else []
    env["running"] = bool(env.get("running"))
    env["enabled"] = bool(env.get("enabled", 1))
    return env


def _entry_ports(entry: dict) -> dict[int, int]:
    ports: dict[int, int] = {}
    for svc in (entry or {}).get("services") or []:
        if not isinstance(svc, dict):
            continue
        for item in svc.get("ports") or []:
            if not isinstance(item, dict):
                continue
            try:
                ports[int(item["container"])] = int(item["host"])
            except (KeyError, TypeError, ValueError):
                continue
    return ports


def upsert_env(store, entry: dict) -> None:
    """把索引条目同步进 lab_env；不覆盖正在运行环境的实际端口与运行态。"""
    env_id = str((entry or {}).get("env_id") or "").strip()
    if not env_id:
        raise ValueError("索引条目缺少 env_id")
    services = entry.get("services") or []
    images = [str(x) for x in (entry.get("images") or []) if x]
    if not images:
        for svc in services:
            image = (svc or {}).get("image")
            if image and str(image) not in images:
                images.append(str(image))
    component = str(
        entry.get("component")
        or entry.get("category")
        or env_id.split("/")[0]
        or env_id
    )
    store.execute(
        "INSERT INTO lab_env("
        " env_id, component, cwe_hint, compose_path, host_ports, image_refs, enabled,"
        " category, cve, title, summary, state, running, updated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,'down',0,?)"
        " ON CONFLICT(env_id) DO UPDATE SET"
        "  component=excluded.component,"
        "  cwe_hint=COALESCE(excluded.cwe_hint, lab_env.cwe_hint),"
        "  compose_path=excluded.compose_path,"
        "  image_refs=excluded.image_refs,"
        "  category=excluded.category, cve=excluded.cve,"
        "  title=excluded.title, summary=excluded.summary,"
        "  host_ports=CASE WHEN lab_env.running=1 THEN lab_env.host_ports"
        "                  ELSE excluded.host_ports END,"
        "  enabled=excluded.enabled, updated_at=excluded.updated_at",
        (
            env_id,
            component,
            entry.get("cwe_hint"),
            str(entry.get("compose_path") or ""),
            _ports_json(_entry_ports(entry)),
            _dumps(images),
            int(entry.get("enabled", 1) or 1),
            entry.get("category"),
            entry.get("cve"),
            entry.get("title"),
            (str(entry.get("summary") or "")[:400] or None),
            schema.utc_now(),
        ),
    )


def ensure_env(store, env_id: str, compose_path: str = "") -> None:
    """确保 lab_env 存在一行（供 lab_run 关联；不覆盖已有数据）。"""
    env_id = str(env_id or "").strip()
    if not env_id:
        return
    component = env_id.split("/")[0] or env_id
    store.execute(
        "INSERT OR IGNORE INTO lab_env("
        " env_id, component, compose_path, enabled, state, running, updated_at)"
        " VALUES(?,?,?,1,'down',0,?)",
        (env_id, component, str(compose_path or ""), schema.utc_now()),
    )


def get_env(store, env_id) -> dict | None:
    row = store.query_one("SELECT * FROM lab_env WHERE env_id=?", (str(env_id),))
    return _env_from_row(row)


def set_env_state(store, env_id, state: str, host_ports: dict | None = None) -> None:
    """只改状态（starting/healthy/error/down），可顺带更新计划端口。"""
    sets = ["state=?", "updated_at=?"]
    args: list[Any] = [str(state), schema.utc_now()]
    if host_ports is not None:
        body = _ports_json(host_ports)
        sets.extend(["host_ports=?", "ports_json=?"])
        args.extend([body, body])
    args.append(str(env_id))
    store.execute(f"UPDATE lab_env SET {', '.join(sets)} WHERE env_id=?", args)


def set_env_running(
    store,
    env_id,
    running: bool,
    host_ports: dict | None,
    expires_at: str | None,
) -> None:
    """记录运行态：running=1/0、实际绑定端口、TTL 到期时间。"""
    body = _ports_json(host_ports or {})
    state = "healthy" if running else "down"
    store.execute(
        "UPDATE lab_env SET running=?, state=?, host_ports=?, ports_json=?,"
        " expires_at=?, updated_at=? WHERE env_id=?",
        (
            1 if running else 0,
            state,
            body,
            body,
            expires_at,
            schema.utc_now(),
            str(env_id),
        ),
    )


def list_envs(store, limit: int = 1000) -> list[dict]:
    rows = store.query("SELECT * FROM lab_env ORDER BY env_id LIMIT ?", (int(limit),))
    return [_env_from_row(row) for row in rows if row]


def running_envs(store) -> list[dict]:
    rows = store.query("SELECT * FROM lab_env WHERE running=1 ORDER BY env_id")
    return [_env_from_row(row) for row in rows if row]


def count_running(store) -> int:
    row = store.query_one("SELECT COUNT(*) AS n FROM lab_env WHERE running=1")
    return int(row["n"]) if row else 0


def expired_envs(store, now_iso: str) -> list[dict]:
    """running=1 且 expires_at 已到点的环境（TTL 清理用）。"""
    rows = store.query(
        "SELECT * FROM lab_env WHERE running=1 AND expires_at IS NOT NULL"
        " AND expires_at<=? ORDER BY expires_at",
        (str(now_iso),),
    )
    return [_env_from_row(row) for row in rows if row]


# ---------------------------------------------------------------------------
# lab_run
# ---------------------------------------------------------------------------
def add_run(store, run: dict) -> None:
    """写入一条动作记录（run_id 冲突时覆盖）。"""
    ports = run.get("ports_bound")
    if isinstance(ports, dict):
        ports = _ports_json(ports)
    elif ports is None:
        ports = None
    else:
        ports = str(ports)
    store.execute(
        "INSERT OR REPLACE INTO lab_run("
        " run_id, env_id, action, started_at, ended_at, elapsed_ms, result,"
        " detail, ports_bound, cleanup_ok)"
        " VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            str(run.get("run_id") or ""),
            str(run.get("env_id") or ""),
            str(run.get("action") or ""),
            str(run.get("started_at") or schema.utc_now()),
            run.get("ended_at"),
            int(run["elapsed_ms"]) if run.get("elapsed_ms") is not None else None,
            str(run.get("result") or "error"),
            str(run.get("detail") or "")[:8000] or None,
            ports,
            1 if run.get("cleanup_ok") else 0,
        ),
    )


def get_run(store, run_id: str) -> dict | None:
    return store.query_one("SELECT * FROM lab_run WHERE run_id=?", (str(run_id),))


def recent_runs(store, limit: int = 20) -> list[dict]:
    return store.query(
        "SELECT * FROM lab_run ORDER BY started_at DESC LIMIT ?", (int(limit),)
    )


def runs_for_env(store, env_id: str, limit: int = 20) -> list[dict]:
    return store.query(
        "SELECT * FROM lab_run WHERE env_id=? ORDER BY started_at DESC LIMIT ?",
        (str(env_id), int(limit)),
    )


def run_summary(store) -> dict:
    """lab_run 汇总：总数 + 按 result 分组 + 最近一条。"""
    total_row = store.query_one("SELECT COUNT(*) AS n FROM lab_run") or {}
    by_result: dict[str, int] = {}
    for row in store.query("SELECT result, COUNT(*) AS n FROM lab_run GROUP BY result"):
        by_result[str(row.get("result") or "unknown")] = int(row.get("n") or 0)
    last = store.query_one("SELECT * FROM lab_run ORDER BY started_at DESC LIMIT 1")
    return {
        "total": int(total_row.get("n") or 0),
        "by_result": by_result,
        "last": last,
    }
