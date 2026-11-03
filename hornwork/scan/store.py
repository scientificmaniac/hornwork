"""扫描模块扫描子系统的数据访问层（复用 ``hornwork.db``，不新建数据库）。

职责边界：
- 只定义**扫描模块自己的表**（``asset`` / ``scan_plan`` / ``scan_task`` / ``scan_finding`` /
  ``cve_cache`` / ``cve_component_map`` / ``scan_oval_fix`` / ``scan_cve_exclude`` /
  ``scan_snapshot`` / ``scan_snapshot_item`` / ``scan_diff_stat``），不改检测模块/二的表；
- 所有函数接收 :class:`hornwork.store.Store`，只通过 ``execute/query/query_one`` 访问数据库，
  便于 CLI（离线）与 daemon（进程内）共用同一套代码；
- SQL 只做"粗筛 + 幂等写入"，版本区间精判在 :mod:`hornwork.scan.cve.matcher`（Python）。

与设计文档的差异（有意为之，写进实现说明）：
1.  的 ``scan_finding`` 上既有 ``UNIQUE(asset_id, finding_key)`` 又用 ``snapshot_id``
   做快照对比，两者语义冲突（同一行只能属于一个快照）。本实现拆成：
   ``scan_finding`` = **当前状态**（每资产每 finding 一行，防库膨胀）；
   ``scan_snapshot_item`` = **每次快照的冻结项**（diff 的唯一数据源）。
2. ``scan_finding`` 增加 ``miss_count``：连续未复现次数，用于"连续 2 次未现 → fixed"的生命周期。
3. 新增 ``scan_oval_fix``：Ubuntu OVAL 的"包 → 修复版本"视图，解决发行版补丁回移误报。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .. import schema
from ..log import get_logger

log = get_logger("scan.store")

#: 扫描模块全部表结构（幂等建表）。命名 snake_case，时间戳为 UTC ISO 字符串。
DDL: list[str] = [
    # ---------------------------------------------------------------- 资产台账
    """CREATE TABLE IF NOT EXISTS asset (
      asset_id TEXT PRIMARY KEY,
      ip TEXT NOT NULL,
      hostname TEXT,
      os_family TEXT,
      os_version TEXT,
      role TEXT,
      criticality INTEGER DEFAULT 3,
      group_name TEXT,
      tags TEXT,
      cred_ref TEXT,
      is_self INTEGER DEFAULT 0,
      enabled INTEGER DEFAULT 1,
      first_seen TEXT,
      last_seen TEXT,
      facts_json TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_asset_group ON asset(group_name, enabled)",
    "CREATE INDEX IF NOT EXISTS idx_asset_ip ON asset(ip)",
    # ---------------------------------------------------------------- 扫描计划
    """CREATE TABLE IF NOT EXISTS scan_plan (
      plan_id TEXT PRIMARY KEY,
      name TEXT,
      kind TEXT,
      profile TEXT,
      selector_json TEXT NOT NULL,
      engines_json TEXT,
      window_start TEXT,
      window_end TEXT,
      rate_limit INTEGER DEFAULT 500,
      max_hosts INTEGER DEFAULT 4,
      enabled INTEGER DEFAULT 1,
      last_run TEXT,
      next_run TEXT,
      params_json TEXT,
      created_at TEXT
    )""",
    # ---------------------------------------------------------------- 扫描任务
    """CREATE TABLE IF NOT EXISTS scan_task (
      task_id TEXT PRIMARY KEY,
      run_id TEXT NOT NULL,
      plan_id TEXT NOT NULL,
      asset_id TEXT NOT NULL,
      slot TEXT NOT NULL,
      profile TEXT,
      status TEXT NOT NULL,
      stage TEXT,
      progress INTEGER DEFAULT 0,
      checkpoint TEXT,
      snapshot_id TEXT,
      started_at TEXT,
      finished_at TEXT,
      cost_ms INTEGER,
      error TEXT,
      UNIQUE(plan_id, asset_id, slot)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_scan_task_run ON scan_task(run_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_task_status ON scan_task(status, started_at)",
    # ---------------------------------------------------------------- 统一 finding
    """CREATE TABLE IF NOT EXISTS scan_finding (
      finding_id TEXT PRIMARY KEY,
      task_id TEXT,
      asset_id TEXT NOT NULL,
      snapshot_id TEXT,
      kind TEXT NOT NULL,
      check_id TEXT NOT NULL,
      title TEXT,
      severity TEXT,
      cvss REAL,
      cvss_source TEXT,
      confidence TEXT,
      status TEXT NOT NULL,
      finding_key TEXT NOT NULL,
      target TEXT,
      evidence_json TEXT,
      vuln_ref TEXT,
      miss_count INTEGER DEFAULT 0,
      first_seen TEXT,
      last_seen TEXT,
      updated_at TEXT,
      UNIQUE(asset_id, finding_key)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_scan_finding_status ON scan_finding(status, severity)",
    "CREATE INDEX IF NOT EXISTS idx_scan_finding_asset ON scan_finding(asset_id, kind)",
    "CREATE INDEX IF NOT EXISTS idx_scan_finding_cve ON scan_finding(check_id)",
    # ---------------------------------------------------------------- CVE 缓存
    """CREATE TABLE IF NOT EXISTS cve_cache (
      cve_id TEXT NOT NULL,
      cpe23 TEXT NOT NULL,
      vulnerable INTEGER DEFAULT 1,
      cpe_version TEXT,
      version_start_incl TEXT,
      version_start_excl TEXT,
      version_end_incl TEXT,
      version_end_excl TEXT,
      cvss REAL,
      severity TEXT,
      published TEXT,
      modified TEXT,
      source TEXT,
      PRIMARY KEY (cve_id, cpe23, version_start_incl, version_start_excl,
                   version_end_incl, version_end_excl)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_cve_cpe ON cve_cache(cpe23)",
    "CREATE INDEX IF NOT EXISTS idx_cve_pub ON cve_cache(published)",
    """CREATE TABLE IF NOT EXISTS cve_component_map (
      comp_norm TEXT NOT NULL,
      cpe23 TEXT NOT NULL,
      source TEXT,
      note TEXT,
      PRIMARY KEY (comp_norm, cpe23)
    )""",
    # ------------------------------------------------ Ubuntu OVAL 修复版本视图
    """CREATE TABLE IF NOT EXISTS scan_oval_fix (
      release TEXT NOT NULL,
      package TEXT NOT NULL,
      cve_id TEXT NOT NULL,
      fixed_version TEXT NOT NULL,
      source TEXT,
      imported_at TEXT,
      PRIMARY KEY (release, package, cve_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_oval_pkg ON scan_oval_fix(release, package)",
    # ---------------------------------------------------------------- 排除项
    """CREATE TABLE IF NOT EXISTS scan_cve_exclude (
      cve_id TEXT NOT NULL,
      comp_norm TEXT NOT NULL,
      version TEXT,
      reason TEXT,
      PRIMARY KEY (cve_id, comp_norm, version)
    )""",
    # ---------------------------------------------------------------- 快照
    """CREATE TABLE IF NOT EXISTS scan_snapshot (
      snapshot_id TEXT PRIMARY KEY,
      plan_id TEXT,
      run_id TEXT,
      ts TEXT NOT NULL,
      kind TEXT,
      label TEXT,
      is_base INTEGER DEFAULT 0,
      task_count INTEGER DEFAULT 0,
      finding_count INTEGER DEFAULT 0,
      stats_json TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS idx_scan_snapshot_ts ON scan_snapshot(ts)",
    """CREATE TABLE IF NOT EXISTS scan_snapshot_item (
      snapshot_id TEXT NOT NULL,
      asset_id TEXT NOT NULL,
      finding_key TEXT NOT NULL,
      kind TEXT,
      check_id TEXT,
      severity TEXT,
      status TEXT,
      cvss REAL,
      PRIMARY KEY (snapshot_id, asset_id, finding_key)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_ssi_asset ON scan_snapshot_item(asset_id, snapshot_id)",
    """CREATE TABLE IF NOT EXISTS scan_diff_stat (
      cur TEXT NOT NULL,
      prev TEXT NOT NULL,
      new INTEGER DEFAULT 0,
      fixed INTEGER DEFAULT 0,
      persisting INTEGER DEFAULT 0,
      regressed INTEGER DEFAULT 0,
      ts TEXT,
      PRIMARY KEY (cur, prev)
    )""",
    # ---------------------------------------------------------------- 辅助视图
    """CREATE VIEW IF NOT EXISTS v_scan_finding_open AS
       SELECT * FROM scan_finding WHERE status IN ('new','observed','confirmed','reopened')""",
]


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def init_schema(store: Any) -> None:
    """幂等建表 + 补列（旧库升级用）。"""
    for statement in DDL:
        store.execute(statement)
    _ensure_columns(store)


def _ensure_columns(store: Any) -> None:
    """为早期版本已建的表补列（SQLite ADD COLUMN 幂等）。"""
    extras = {
        "scan_finding": (("miss_count", "INTEGER DEFAULT 0"),),
    }
    for table, columns in extras.items():
        try:
            rows = store.query(f"PRAGMA table_info({table})")
        except Exception as exc:  # noqa: BLE001 - 建表失败向上抛更利于定位
            log.warn("读取表结构失败", table=table, error=str(exc))
            raise
        existing = {str(row.get("name")) for row in rows}
        for name, decl in columns:
            if name not in existing:
                try:
                    store.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
                except Exception as exc:  # noqa: BLE001 - 并发/已存在时忽略
                    log.warn("补列失败", table=table, column=name, error=str(exc))


def today_utc() -> str:
    return schema.utc_now()


def new_id(prefix: str) -> str:
    """生成 ``PREFIX-YYYYMMDDTHHMMSS-xxxxxx`` 形式的短 ID（可读、可排序、必不重复）。

    同一毫秒内可能连续创建多个 finding，后缀用 ``uuid4`` 而非时间戳哈希。
    """
    import uuid

    stamp = schema.utc_now().replace("-", "").replace(":", "").replace(".", "")[:15]
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:6].upper()}"


def dumps(value: Any) -> str:
    """JSON 序列化（失败降级为 str，绝不抛给上层）。"""
    try:
        return json.dumps(value, ensure_ascii=False, default=str, allow_nan=False)
    except (TypeError, ValueError):
        return json.dumps({"raw": str(value)[:4000]}, ensure_ascii=False)


def loads(text: Any, default: Any = None) -> Any:
    """JSON 反序列化（失败返回 default）。"""
    if isinstance(text, (dict, list)):
        return text
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def finding_key(asset_id: str, kind: str, check_id: str, target: str | None) -> str:
    """去重键：与来源引擎无关，只与"什么东西坏了/是什么"有关。"""
    return schema.dedup_key(str(asset_id), str(kind), str(check_id), str(target or ""))


# ---------------------------------------------------------------------------
# 资产台账
# ---------------------------------------------------------------------------
def upsert_asset(store: Any, rec: dict) -> dict:
    """新增/更新资产（按 asset_id 或 ip 幂等）。"""
    init_schema(store)
    asset_id = str(rec.get("asset_id") or "").strip()
    ip = str(rec.get("ip") or "").strip()
    if not asset_id and not ip:
        raise ValueError("资产需要 asset_id 或 ip")
    if not asset_id:
        existing = store.query_one("SELECT asset_id FROM asset WHERE ip=?", (ip,))
        asset_id = existing["asset_id"] if existing else new_id("ast")
    now = today_utc()
    first_seen = rec.get("first_seen") or now
    facts = rec.get("facts_json")
    if isinstance(facts, (dict, list)):
        facts = dumps(facts)
    if facts is None:
        facts = "{}"
    store.execute(
        """INSERT INTO asset(asset_id, ip, hostname, os_family, os_version, role,
             criticality, group_name, tags, cred_ref, is_self, enabled, first_seen,
             last_seen, facts_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(asset_id) DO UPDATE SET
             ip=excluded.ip,
             hostname=COALESCE(excluded.hostname, asset.hostname),
             os_family=COALESCE(excluded.os_family, asset.os_family),
             os_version=COALESCE(excluded.os_version, asset.os_version),
             role=COALESCE(excluded.role, asset.role),
             criticality=excluded.criticality,
             group_name=COALESCE(excluded.group_name, asset.group_name),
             tags=COALESCE(excluded.tags, asset.tags),
             cred_ref=COALESCE(excluded.cred_ref, asset.cred_ref),
             is_self=excluded.is_self,
             enabled=excluded.enabled,
             last_seen=excluded.last_seen,
             facts_json=CASE WHEN excluded.facts_json='{}' THEN asset.facts_json
                             ELSE excluded.facts_json END""",
        (
            asset_id, ip, rec.get("hostname"), rec.get("os_family"),
            rec.get("os_version"), rec.get("role"), int(rec.get("criticality", 3) or 3),
            rec.get("group_name"), rec.get("tags"), rec.get("cred_ref"),
            int(rec.get("is_self", 0) or 0), int(rec.get("enabled", 1) or 1),
            first_seen, now, facts,
        ),
    )
    return get_asset(store, asset_id) or {"asset_id": asset_id}


def get_asset(store: Any, asset_id: str) -> dict | None:
    row = store.query_one("SELECT * FROM asset WHERE asset_id=?", (str(asset_id),))
    return _decode_asset(row) if row else None


def get_asset_by_ip(store: Any, ip: str) -> dict | None:
    row = store.query_one("SELECT * FROM asset WHERE ip=? ORDER BY enabled DESC LIMIT 1", (str(ip),))
    return _decode_asset(row) if row else None


def list_assets(store: Any, enabled: bool | None = None, limit: int = 500) -> list[dict]:
    sql = "SELECT * FROM asset"
    args: list[Any] = []
    if enabled is not None:
        sql += " WHERE enabled=?"
        args.append(1 if enabled else 0)
    sql += " ORDER BY asset_id LIMIT ?"
    args.append(int(limit))
    return [_decode_asset(row) for row in store.query(sql, args)]


def _decode_asset(row: dict | None) -> dict | None:
    if not row:
        return None
    asset = dict(row)
    asset["facts_json"] = loads(asset.get("facts_json"), {})
    asset["tags"] = _split_tags(asset.get("tags"))
    asset["is_self"] = bool(asset.get("is_self"))
    asset["enabled"] = bool(asset.get("enabled", 1))
    return asset


def _split_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        if raw.startswith("["):
            parsed = loads(raw, None)
            if isinstance(parsed, list):
                return [str(v) for v in parsed]
        return [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]
    return []


def update_asset_facts(store: Any, asset_id: str, patch: dict) -> None:
    """合并式更新 facts_json（只做一次 SELECT+UPDATE，资产量很小）。"""
    asset = get_asset(store, asset_id)
    facts = dict((asset or {}).get("facts_json") or {})
    facts.update(patch or {})
    store.execute(
        "UPDATE asset SET facts_json=?, last_seen=? WHERE asset_id=?",
        (dumps(facts), today_utc(), str(asset_id)),
    )


def set_asset_enabled(store: Any, asset_id: str, enabled: bool) -> bool:
    cur = store.execute(
        "UPDATE asset SET enabled=? WHERE asset_id=?", (1 if enabled else 0, str(asset_id))
    )
    return cur.rowcount > 0


def select_assets(store: Any, selector: dict | None, include_disabled: bool = False) -> list[dict]:
    """按选择器展开目标资产（台账是唯一目标来源，展开逻辑集中在此）。

    选择器字段（全部可选，AND 语义）：
    ``asset_ids`` / ``ids``（显式列表）、``group``、``role``、``tags``（任一命中）、
    ``min_criticality``、``ip``。
    """
    selector = selector or {}
    if isinstance(selector, str):
        selector = loads(selector, {}) or {}
    ids = selector.get("asset_ids") or selector.get("ids")
    assets = list_assets(store, enabled=None if include_disabled else True)
    if ids:
        wanted = {str(x) for x in ids}
        assets = [a for a in assets if a.get("asset_id") in wanted]
    if selector.get("ip"):
        assets = [a for a in assets if a.get("ip") == str(selector["ip"])]
    if selector.get("group"):
        assets = [a for a in assets if a.get("group_name") == str(selector["group"])]
    if selector.get("role"):
        assets = [a for a in assets if a.get("role") == str(selector["role"])]
    tags = _split_tags(selector.get("tags"))
    if tags:
        assets = [a for a in assets if set(tags) & set(a.get("tags") or [])]
    if selector.get("min_criticality") is not None:
        try:
            floor = int(selector["min_criticality"])
            assets = [a for a in assets if int(a.get("criticality") or 3) >= floor]
        except (TypeError, ValueError):
            pass
    return assets


# ---------------------------------------------------------------------------
# 扫描计划
# ---------------------------------------------------------------------------
def upsert_plan(store: Any, rec: dict) -> dict:
    init_schema(store)
    plan_id = str(rec.get("plan_id") or rec.get("id") or "").strip()
    if not plan_id:
        raise ValueError("计划需要 plan_id")
    selector = rec.get("selector_json")
    if selector is None:
        selector = rec.get("selector") or {}
    if isinstance(selector, (dict, list)):
        selector = dumps(selector)
    engines = rec.get("engines_json", rec.get("engines"))
    if isinstance(engines, (dict, list)):
        engines = dumps(engines)
    params = rec.get("params_json", rec.get("params"))
    if isinstance(params, (dict, list)):
        params = dumps(params)
    store.execute(
        """INSERT INTO scan_plan(plan_id, name, kind, profile, selector_json, engines_json,
             window_start, window_end, rate_limit, max_hosts, enabled, last_run, next_run,
             params_json, created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(plan_id) DO UPDATE SET
             name=excluded.name, kind=excluded.kind, profile=excluded.profile,
             selector_json=excluded.selector_json,
             engines_json=COALESCE(excluded.engines_json, scan_plan.engines_json),
             window_start=excluded.window_start, window_end=excluded.window_end,
             rate_limit=excluded.rate_limit, max_hosts=excluded.max_hosts,
             enabled=excluded.enabled,
             params_json=COALESCE(excluded.params_json, scan_plan.params_json)""",
        (
            plan_id, rec.get("name") or plan_id, rec.get("kind") or "manual",
            rec.get("profile") or "weekly", str(selector or "{}"), engines,
            rec.get("window_start"), rec.get("window_end"),
            int(rec.get("rate_limit", 500) or 500), int(rec.get("max_hosts", 4) or 4),
            int(rec.get("enabled", 1) or 1), rec.get("last_run"), rec.get("next_run"),
            params, rec.get("created_at") or today_utc(),
        ),
    )
    return get_plan(store, plan_id) or {"plan_id": plan_id}


def get_plan(store: Any, plan_id: str) -> dict | None:
    row = store.query_one("SELECT * FROM scan_plan WHERE plan_id=?", (str(plan_id),))
    return _decode_plan(row) if row else None


def list_plans(store: Any, enabled: bool | None = None, limit: int = 100) -> list[dict]:
    sql = "SELECT * FROM scan_plan"
    args: list[Any] = []
    if enabled is not None:
        sql += " WHERE enabled=?"
        args.append(1 if enabled else 0)
    sql += " ORDER BY plan_id LIMIT ?"
    args.append(int(limit))
    return [_decode_plan(row) for row in store.query(sql, args)]


def _decode_plan(row: dict | None) -> dict | None:
    if not row:
        return None
    plan = dict(row)
    plan["selector_json"] = loads(plan.get("selector_json"), {})
    plan["engines_json"] = loads(plan.get("engines_json"), None)
    plan["params_json"] = loads(plan.get("params_json"), {})
    plan["enabled"] = bool(plan.get("enabled", 1))
    return plan


def set_plan_enabled(store: Any, plan_id: str, enabled: bool) -> bool:
    cur = store.execute(
        "UPDATE scan_plan SET enabled=? WHERE plan_id=?", (1 if enabled else 0, str(plan_id))
    )
    return cur.rowcount > 0


def touch_plan_run(store: Any, plan_id: str, last_run: str, next_run: str | None) -> None:
    store.execute(
        "UPDATE scan_plan SET last_run=?, next_run=? WHERE plan_id=?",
        (last_run, next_run, str(plan_id)),
    )


# ---------------------------------------------------------------------------
# 扫描任务
# ---------------------------------------------------------------------------
TASK_STATUSES = ("queued", "running", "done", "partial", "failed", "aborted")


def create_task(store: Any, rec: dict) -> tuple[dict, bool]:
    """创建任务；``UNIQUE(plan_id, asset_id, slot)`` 冲突时返回已有任务（幂等）。

    返回 ``(task, created)``：``created=False`` 表示该槽位已有任务（重复触发被数据库挡住）。
    """
    init_schema(store)
    plan_id = str(rec["plan_id"])
    asset_id = str(rec["asset_id"])
    slot = str(rec["slot"])
    existing = store.query_one(
        "SELECT * FROM scan_task WHERE plan_id=? AND asset_id=? AND slot=?",
        (plan_id, asset_id, slot),
    )
    if existing:
        return _decode_task(existing), False
    task_id = str(rec.get("task_id") or new_id("tsk"))
    now = rec.get("started_at")
    store.execute(
        """INSERT OR IGNORE INTO scan_task(task_id, run_id, plan_id, asset_id, slot, profile,
             status, stage, progress, checkpoint, snapshot_id, started_at, finished_at,
             cost_ms, error)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            task_id, rec.get("run_id"), plan_id, asset_id, slot,
            rec.get("profile") or "weekly", rec.get("status") or "queued",
            rec.get("stage"), int(rec.get("progress", 0) or 0),
            dumps(rec.get("checkpoint") or {}), rec.get("snapshot_id"), now, None,
            None, None,
        ),
    )
    row = store.query_one("SELECT * FROM scan_task WHERE task_id=?", (task_id,))
    return _decode_task(row) or {"task_id": task_id}, True


def get_task(store: Any, task_id: str) -> dict | None:
    row = store.query_one("SELECT * FROM scan_task WHERE task_id=?", (str(task_id),))
    return _decode_task(row) if row else None


def list_tasks(
    store: Any, run_id: str | None = None, plan_id: str | None = None,
    status: str | None = None, limit: int = 50,
) -> list[dict]:
    sql = "SELECT * FROM scan_task WHERE 1=1"
    args: list[Any] = []
    if run_id:
        sql += " AND run_id=?"
        args.append(run_id)
    if plan_id:
        sql += " AND plan_id=?"
        args.append(plan_id)
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY started_at DESC, task_id DESC LIMIT ?"
    args.append(int(limit))
    return [_decode_task(row) for row in store.query(sql, args)]


def tasks_for_run(store: Any, run_id: str) -> list[dict]:
    return [_decode_task(row) for row in store.query(
        "SELECT * FROM scan_task WHERE run_id=? ORDER BY asset_id", (str(run_id),)
    )]


def _decode_task(row: dict | None) -> dict | None:
    if not row:
        return None
    task = dict(row)
    task["checkpoint"] = loads(task.get("checkpoint"), {}) or {}
    return task


def update_task(store: Any, task_id: str, **fields: Any) -> bool:
    """更新任务字段（白名单，避免任意列注入）。``checkpoint`` 自动 JSON 序列化。"""
    allowed = {
        "status", "stage", "progress", "checkpoint", "snapshot_id", "started_at",
        "finished_at", "cost_ms", "error", "profile", "run_id",
    }
    sets: list[str] = []
    args: list[Any] = []
    for key, val in fields.items():
        if key not in allowed:
            continue
        if key == "checkpoint" and isinstance(val, (dict, list)):
            val = dumps(val)
        sets.append(f"{key}=?")
        args.append(val)
    if not sets:
        return False
    args.append(str(task_id))
    cur = store.execute(f"UPDATE scan_task SET {', '.join(sets)} WHERE task_id=?", args)
    return cur.rowcount > 0


def set_task_status(store: Any, task_id: str, status: str, *, error: str | None = None,
                    stage: str | None = None) -> bool:
    if status not in TASK_STATUSES:
        raise ValueError(f"非法任务状态：{status}")
    fields: dict[str, Any] = {"status": status}
    if error is not None:
        fields["error"] = str(error)[:4000]
    if stage is not None:
        fields["stage"] = stage
    return update_task(store, task_id, **fields)


# ---------------------------------------------------------------------------
# 统一 finding（当前状态）
# ---------------------------------------------------------------------------
FINDING_STATUSES = ("new", "observed", "confirmed", "false_positive", "fixed", "reopened")


def upsert_finding(store: Any, rec: dict, *, seen: bool = True) -> dict:
    """写入/更新一条 finding（按 ``UNIQUE(asset_id, finding_key)`` 幂等）。

    - 首次出现：插入 ``finding_id``，``first_seen=last_seen=now``；
    - 再次出现：更新证据/严重级/置信度等，``last_seen=now``，``miss_count=0``；
    - ``status`` 由 :mod:`hornwork.scan.normalize` 依据生命周期计算后传入。
    """
    init_schema(store)
    asset_id = str(rec["asset_id"])
    kind = str(rec["kind"])
    check_id = str(rec["check_id"])
    target = rec.get("target")
    key = str(rec.get("finding_key") or finding_key(asset_id, kind, check_id, target))
    now = today_utc()
    row = store.query_one(
        "SELECT * FROM scan_finding WHERE asset_id=? AND finding_key=?", (asset_id, key)
    )
    evidence = rec.get("evidence_json")
    if isinstance(evidence, (dict, list)):
        evidence = dumps(evidence)
    if row is None:
        finding_id = str(rec.get("finding_id") or new_id("fnd"))
        store.execute(
            """INSERT INTO scan_finding(finding_id, task_id, asset_id, snapshot_id, kind,
                 check_id, title, severity, cvss, cvss_source, confidence, status,
                 finding_key, target, evidence_json, vuln_ref, miss_count, first_seen,
                 last_seen, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                finding_id, rec.get("task_id"), asset_id, rec.get("snapshot_id"), kind,
                check_id, rec.get("title"), rec.get("severity"), rec.get("cvss"),
                rec.get("cvss_source"), rec.get("confidence"), rec.get("status") or "new",
                key, target, evidence, rec.get("vuln_ref"),
                0 if seen else 1, now, now, now,
            ),
        )
        return get_finding_by_key(store, asset_id, key) or {"finding_key": key}

    fields: dict[str, Any] = {
        "task_id": rec.get("task_id") or row.get("task_id"),
        "snapshot_id": rec.get("snapshot_id") or row.get("snapshot_id"),
        "title": rec.get("title") or row.get("title"),
        "severity": rec.get("severity") or row.get("severity"),
        "cvss": rec.get("cvss") if rec.get("cvss") is not None else row.get("cvss"),
        "cvss_source": rec.get("cvss_source") or row.get("cvss_source"),
        "confidence": rec.get("confidence") or row.get("confidence"),
        "target": target or row.get("target"),
        "evidence_json": evidence or row.get("evidence_json"),
        "vuln_ref": rec.get("vuln_ref") if rec.get("vuln_ref") is not None else row.get("vuln_ref"),
        "last_seen": now,
        "updated_at": now,
        "miss_count": 0 if seen else int(row.get("miss_count") or 0) + 1,
    }
    if rec.get("status"):
        fields["status"] = rec["status"]
    store.execute(
        "UPDATE scan_finding SET " + ", ".join(f"{k}=?" for k in fields) +
        " WHERE asset_id=? AND finding_key=?",
        list(fields.values()) + [asset_id, key],
    )
    return get_finding_by_key(store, asset_id, key) or {"finding_key": key}


def get_finding(store: Any, finding_id: str) -> dict | None:
    row = store.query_one("SELECT * FROM scan_finding WHERE finding_id=?", (str(finding_id),))
    return _decode_finding(row) if row else None


def get_finding_by_key(store: Any, asset_id: str, key: str) -> dict | None:
    row = store.query_one(
        "SELECT * FROM scan_finding WHERE asset_id=? AND finding_key=?", (str(asset_id), str(key))
    )
    return _decode_finding(row) if row else None


def list_findings(
    store: Any, asset_id: str | None = None, severity: str | None = None,
    status: str | None = None, kind: str | None = None, check_id: str | None = None,
    limit: int = 200,
) -> list[dict]:
    sql = "SELECT * FROM scan_finding WHERE 1=1"
    args: list[Any] = []
    for column, value in (
        ("asset_id", asset_id), ("severity", severity), ("status", status),
        ("kind", kind), ("check_id", check_id),
    ):
        if value:
            sql += f" AND {column}=?"
            args.append(value)
    sql += " ORDER BY CASE severity WHEN '严重' THEN 0 WHEN '高' THEN 1 WHEN '中' THEN 2" \
           " WHEN '低' THEN 3 ELSE 4 END, cvss DESC, last_seen DESC LIMIT ?"
    args.append(int(limit))
    return [_decode_finding(row) for row in store.query(sql, args)]


def _decode_finding(row: dict | None) -> dict | None:
    if not row:
        return None
    finding = dict(row)
    finding["evidence_json"] = loads(finding.get("evidence_json"), {})
    finding["miss_count"] = int(finding.get("miss_count") or 0)
    return finding


def set_finding_status(store: Any, finding_id: str, status: str, reason: str | None = None) -> bool:
    """人工处置：状态流转白名单 + 原因留痕（写 evidence_json._review）。"""
    if status not in FINDING_STATUSES:
        raise ValueError(f"非法 finding 状态：{status}")
    row = store.query_one("SELECT * FROM scan_finding WHERE finding_id=?", (str(finding_id),))
    if not row:
        return False
    evidence = loads(row.get("evidence_json"), {}) or {}
    evidence["_review"] = {"status": status, "reason": reason, "ts": today_utc()}
    store.execute(
        "UPDATE scan_finding SET status=?, evidence_json=?, updated_at=? WHERE finding_id=?",
        (status, dumps(evidence), today_utc(), str(finding_id)),
    )
    return True


def findings_for_asset(store: Any, asset_id: str, status_in: Iterable[str] | None = None) -> list[dict]:
    rows = list_findings(store, asset_id=asset_id, limit=100000)
    if status_in:
        wanted = set(status_in)
        rows = [r for r in rows if r.get("status") in wanted]
    return rows


def missing_findings(store: Any, asset_id: str, seen_keys: set[str]) -> list[dict]:
    """本次任务未复现的既有 finding（用于 miss_count / fixed 判定）。"""
    out = []
    for row in findings_for_asset(
        store, asset_id, status_in=("new", "observed", "confirmed", "reopened")
    ):
        if row.get("finding_key") not in seen_keys:
            out.append(row)
    return out


def finding_counts(store: Any) -> dict:
    by_status = {row["status"]: int(row["n"]) for row in store.query(
        "SELECT status, COUNT(*) AS n FROM scan_finding GROUP BY status"
    )}
    by_kind = {row["kind"]: int(row["n"]) for row in store.query(
        "SELECT kind, COUNT(*) AS n FROM scan_finding WHERE status!='fixed' GROUP BY kind"
    )}
    total = store.query_one("SELECT COUNT(*) AS n FROM scan_finding") or {}
    return {"total": int(total.get("n") or 0), "by_status": by_status, "by_kind": by_kind}


# ---------------------------------------------------------------------------
# 快照
# ---------------------------------------------------------------------------
def create_snapshot(store: Any, rec: dict) -> dict:
    init_schema(store)
    snapshot_id = str(rec.get("snapshot_id") or new_id("S"))
    store.execute(
        """INSERT OR REPLACE INTO scan_snapshot(snapshot_id, plan_id, run_id, ts, kind,
             label, is_base, task_count, finding_count, stats_json)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            snapshot_id, rec.get("plan_id"), rec.get("run_id"),
            rec.get("ts") or today_utc(), rec.get("kind"), rec.get("label"),
            int(rec.get("is_base", 0) or 0), int(rec.get("task_count", 0) or 0),
            int(rec.get("finding_count", 0) or 0), dumps(rec.get("stats_json") or {}),
        ),
    )
    return get_snapshot(store, snapshot_id) or {"snapshot_id": snapshot_id}


def get_snapshot(store: Any, snapshot_id: str) -> dict | None:
    row = store.query_one("SELECT * FROM scan_snapshot WHERE snapshot_id=?", (str(snapshot_id),))
    return _decode_snapshot(row) if row else None


def latest_snapshot(store: Any) -> dict | None:
    row = store.query_one("SELECT * FROM scan_snapshot ORDER BY ts DESC LIMIT 1")
    return _decode_snapshot(row) if row else None


def previous_snapshot(store: Any, snapshot_id: str) -> dict | None:
    """同一计划内、时间早于给定快照的最近一次快照。"""
    current = get_snapshot(store, snapshot_id)
    if not current:
        return None
    row = store.query_one(
        "SELECT * FROM scan_snapshot WHERE ts<? AND (plan_id=? OR ? IS NULL)"
        " ORDER BY ts DESC LIMIT 1",
        (current["ts"], current.get("plan_id"), current.get("plan_id")),
    )
    return _decode_snapshot(row) if row else None


def list_snapshots(store: Any, limit: int = 20) -> list[dict]:
    rows = store.query("SELECT * FROM scan_snapshot ORDER BY ts DESC LIMIT ?", (int(limit),))
    return [_decode_snapshot(row) for row in rows]


def _decode_snapshot(row: dict | None) -> dict | None:
    if not row:
        return None
    snap = dict(row)
    snap["stats_json"] = loads(snap.get("stats_json"), {})
    snap["is_base"] = bool(snap.get("is_base"))
    return snap


def set_base_snapshot(store: Any, snapshot_id: str) -> bool:
    """登记基线快照（同计划互斥：先清空同计划旧基线）。"""
    snap = get_snapshot(store, snapshot_id)
    if not snap:
        return False
    if snap.get("plan_id"):
        store.execute(
            "UPDATE scan_snapshot SET is_base=0 WHERE plan_id=?", (snap["plan_id"],)
        )
    store.execute("UPDATE scan_snapshot SET is_base=1 WHERE snapshot_id=?", (snapshot_id,))
    return True


def add_snapshot_items(store: Any, snapshot_id: str, items: list[dict]) -> int:
    """批量写入快照冻结项（每快照一次，幂等 OR REPLACE）。"""
    if not items:
        return 0
    n = 0
    for item in items:
        store.execute(
            """INSERT OR REPLACE INTO scan_snapshot_item(snapshot_id, asset_id, finding_key,
                 kind, check_id, severity, status, cvss) VALUES(?,?,?,?,?,?,?,?)""",
            (
                str(snapshot_id), str(item.get("asset_id")), str(item.get("finding_key")),
                item.get("kind"), item.get("check_id"), item.get("severity"),
                item.get("status"), item.get("cvss"),
            ),
        )
        n += 1
    return n


def snapshot_items(store: Any, snapshot_id: str) -> list[dict]:
    return store.query(
        "SELECT * FROM scan_snapshot_item WHERE snapshot_id=?", (str(snapshot_id),)
    )


def snapshot_items_map(store: Any, snapshot_id: str) -> dict[tuple[str, str], dict]:
    return {
        (row["asset_id"], row["finding_key"]): row
        for row in snapshot_items(store, snapshot_id)
    }


def update_snapshot_stats(store: Any, snapshot_id: str, stats: dict) -> None:
    snap = get_snapshot(store, snapshot_id)
    if not snap:
        return
    merged = dict(snap.get("stats_json") or {})
    merged.update(stats or {})
    store.execute(
        "UPDATE scan_snapshot SET stats_json=?, finding_count=? WHERE snapshot_id=?",
        (dumps(merged), int(stats.get("findings", snap.get("finding_count") or 0)), snapshot_id),
    )


# ---------------------------------------------------------------------------
# diff 统计
# ---------------------------------------------------------------------------
def save_diff_stat(store: Any, cur: str, prev: str, stats: dict) -> None:
    store.execute(
        """INSERT OR REPLACE INTO scan_diff_stat(cur, prev, new, fixed, persisting,
             regressed, ts) VALUES(?,?,?,?,?,?,?)""",
        (
            str(cur), str(prev), int(stats.get("new", 0)), int(stats.get("fixed", 0)),
            int(stats.get("persisting", 0)), int(stats.get("regressed", 0)), today_utc(),
        ),
    )


def list_diff_stats(store: Any, limit: int = 12) -> list[dict]:
    return store.query(
        "SELECT * FROM scan_diff_stat ORDER BY ts DESC LIMIT ?", (int(limit),)
    )


# ---------------------------------------------------------------------------
# CVE 辅助（导入/匹配在 scan.cve 子包，这里只放跨模块通用查询）
# ---------------------------------------------------------------------------
def cve_count(store: Any) -> int:
    try:
        row = store.query_one("SELECT COUNT(DISTINCT cve_id) AS n FROM cve_cache")
        return int(row["n"]) if row else 0
    except Exception:  # noqa: BLE001 - 未导入时表可能不存在
        return 0


def cve_severity_counts(store: Any) -> dict:
    try:
        rows = store.query(
            "SELECT severity, COUNT(DISTINCT cve_id) AS n FROM cve_cache GROUP BY severity"
        )
        return {str(r.get("severity") or "未知"): int(r.get("n") or 0) for r in rows}
    except Exception:  # noqa: BLE001
        return {}


def scan_overview(store: Any) -> dict:
    """扫描概览计数（CLI status / Web overview 用）。"""
    init_schema(store)
    counts: dict[str, int] = {}
    for name, sql in (
        ("assets", "SELECT COUNT(*) AS n FROM asset WHERE enabled=1"),
        ("plans", "SELECT COUNT(*) AS n FROM scan_plan WHERE enabled=1"),
        ("tasks", "SELECT COUNT(*) AS n FROM scan_task"),
        ("snapshots", "SELECT COUNT(*) AS n FROM scan_snapshot"),
        ("findings", "SELECT COUNT(*) AS n FROM scan_finding"),
        ("open_findings", "SELECT COUNT(*) AS n FROM scan_finding "
                          "WHERE status IN ('new','observed','confirmed','reopened')"),
        ("cves", "SELECT COUNT(*) AS n FROM cve_cache"),
        ("oval_fixes", "SELECT COUNT(*) AS n FROM scan_oval_fix"),
        ("diff_rows", "SELECT COUNT(*) AS n FROM scan_diff_stat"),
    ):
        try:
            row = store.query_one(sql) or {}
            counts[name] = int(row.get("n") or 0)
        except Exception:  # noqa: BLE001 - 表缺失按 0 处理
            counts[name] = 0
    last = store.query_one(
        "SELECT * FROM scan_task ORDER BY started_at DESC LIMIT 1"
    )
    return {
        "counts": counts,
        "last_task": _decode_task(last),
        "last_snapshot": latest_snapshot(store),
    }
