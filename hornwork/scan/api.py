"""IF-24：扫描模块 Web 只读查询接口（``GET /api/scan/*`` 的数据层）。

设计约束：
- **只读**：确认 finding、转工单等写操作走控制面（CLI/daemon），这里绝不写业务表；
  唯一例外是 ``get_diff`` 可复用 :func:`hornwork.scan.diff.build`，但传
  ``write_stat=False``，GET 不落库；
- **容错**：表未建/库为空/字段缺失一律返回空结构，**不抛异常**——Web 端一次查询失败
  不能让控制台白屏；
- **统一形状**：所有 list 返回 ``{"items":[...],"total":n,"ts":...}``（total 是过滤后的
  总行数，items 受 limit 限制，前端可据此做分页）。

本模块只依赖 ``Store.execute/query/query_one``，不持有 sqlite 连接，导入期不读库。
"""

from __future__ import annotations

import json
from typing import Any

from ..log import get_logger
from ..schema import utc_now
from . import coverage as coverage_mod
from . import diff as diff_mod

log = get_logger("scan.api")

#: 允许的枚举值（非法过滤值不回退，直接返回空列表，避免"猜用户意图"）
KINDS: tuple[str, ...] = ("port", "component", "cve", "config", "tls", "web")
STATUSES: tuple[str, ...] = (
    "new", "observed", "confirmed", "false_positive", "fixed", "reopened",
)
SEVERITIES: tuple[str, ...] = ("严重", "高", "中", "低", "无")

#: finding 列表排序：严重级 → CVSS 降序 → 最近发现
_FINDING_ORDER = (
    " ORDER BY CASE severity"
    " WHEN '严重' THEN 0 WHEN '高' THEN 1 WHEN '中' THEN 2"
    " WHEN '低' THEN 3 WHEN '无' THEN 4 ELSE 5 END,"
    " COALESCE(cvss, -1) DESC, COALESCE(last_seen, '') DESC, finding_id"
)


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def _qs(value: Any) -> str:
    """查询参数转字符串（去空白）。"""
    return "" if value is None else str(value).strip()


def _limit(value: Any, default: int, maximum: int = 1000) -> int:
    """limit 归一：非法值回默认，范围 [1, maximum]。"""
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return default
    return max(1, min(int(maximum), number))


def _loads(raw: Any, default: Any = None) -> Any:
    """JSON 解码（失败返回 default）。"""
    if isinstance(raw, (dict, list)):
        return raw
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def _now() -> str:
    return utc_now()


def _list_result(items: list[dict], total: int | None = None) -> dict:
    """统一的列表返回结构。"""
    return {"items": items, "total": len(items) if total is None else int(total), "ts": _now()}


def _query(store: Any, sql: str, args: Any = ()) -> list[dict]:
    """只读查询（表未建/库未初始化时返回空列表）。"""
    try:
        return store.query(sql, args) or []
    except Exception as exc:  # noqa: BLE001 - 解释层必须容错
        log.warn("scan.api 查询失败", error=str(exc))
        return []


def _query_one(store: Any, sql: str, args: Any = ()) -> dict | None:
    """只读单行查询（异常时返回 None）。"""
    try:
        return store.query_one(sql, args)
    except Exception as exc:  # noqa: BLE001
        log.warn("scan.api 单行查询失败", error=str(exc))
        return None


def _count(store: Any, sql: str, args: Any = ()) -> int:
    """COUNT 查询（异常/空结果返回 0）。"""
    row = _query_one(store, sql, args)
    try:
        return int((row or {}).get("n") or 0)
    except (TypeError, ValueError):
        return 0


def _group_count(store: Any, sql: str, args: Any = ()) -> dict[str, int]:
    """``GROUP BY ... AS k, COUNT(*) AS n`` 查询 → ``{k: n}``。"""
    out: dict[str, int] = {}
    for row in _query(store, sql, args):
        key = str(row.get("k") or "unknown")
        try:
            out[key] = int(row.get("n") or 0)
        except (TypeError, ValueError):
            out[key] = 0
    return out


def _asset_map(store: Any, asset_ids: list[str]) -> dict[str, dict]:
    """批量取资产台账信息，用于给任务/finding 补 ip/hostname。"""
    ids = sorted({str(item) for item in asset_ids if item})
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    rows = _query(
        store,
        f"SELECT asset_id, ip, hostname, role, criticality FROM asset"
        f" WHERE asset_id IN ({placeholders})",
        ids,
    )
    return {str(row.get("asset_id")): row for row in rows}


def _enrich_asset(rows: list[dict], assets: dict[str, dict]) -> list[dict]:
    """给每行补 ``asset_ip`` / ``asset_hostname`` / ``role``（缺台账时留空）。"""
    for row in rows:
        asset = assets.get(str(row.get("asset_id") or "")) or {}
        row["asset_ip"] = asset.get("ip")
        row["asset_hostname"] = asset.get("hostname")
        if row.get("role") is None:
            row["role"] = asset.get("role")
    return rows


def _parse_task(row: dict) -> dict:
    """任务行：``checkpoint`` JSON 解码成 dict，原始串保留为 ``checkpoint_raw``。"""
    out = dict(row)
    raw = out.get("checkpoint")
    if isinstance(raw, str) and raw:
        out["checkpoint_raw"] = raw
        out["checkpoint"] = _loads(raw, {}) or {}
    elif not isinstance(raw, dict):
        out["checkpoint"] = {}
    return out


def _parse_finding(row: dict) -> dict:
    """finding 行：``evidence_json`` 解码成 ``evidence``（原始串保留）。"""
    out = dict(row)
    raw = out.get("evidence_json")
    if isinstance(raw, str) and raw:
        out["evidence"] = _loads(raw, {}) or {}
    elif not isinstance(raw, dict):
        out["evidence"] = {}
    return out


# ---------------------------------------------------------------------------
# 计划 / 任务
# ---------------------------------------------------------------------------
def list_plans(store: Any) -> dict:
    """``GET /api/scan/plans``：扫描计划清单（周期计划是数据，不是代码）。"""
    rows = _query(
        store,
        "SELECT plan_id, name, kind, profile, selector_json, engines_json, window_start,"
        " window_end, rate_limit, max_hosts, enabled, last_run, next_run, created_at"
        " FROM scan_plan ORDER BY enabled DESC, kind, plan_id",
    )
    items: list[dict] = []
    for row in rows:
        item = dict(row)
        item["enabled"] = bool(item.get("enabled", 1))
        item["selector"] = _loads(item.pop("selector_json", None), {}) or {}
        item["engines"] = _loads(item.pop("engines_json", None), None)
        items.append(item)
    return _list_result(items)


def list_tasks(store: Any, limit: int = 50, status: str | None = None) -> dict:
    """``GET /api/scan/tasks``：任务列表（可按状态过滤，按开始时间倒序）。"""
    count = _limit(limit, 50)
    where = ""
    args: list[Any] = []
    wanted = _qs(status)
    if wanted:
        where = " WHERE status=?"
        args.append(wanted)
    total = _count(store, f"SELECT COUNT(*) AS n FROM scan_task{where}", args)
    rows = _query(
        store,
        "SELECT task_id, run_id, plan_id, asset_id, slot, profile, status, stage, progress,"
        " checkpoint, snapshot_id, started_at, finished_at, cost_ms, error"
        f" FROM scan_task{where} ORDER BY COALESCE(started_at, '') DESC, task_id DESC LIMIT ?",
        args + [count],
    )
    items = [_parse_task(row) for row in rows]
    _enrich_asset(items, _asset_map(store, [row.get("asset_id") for row in items]))
    return _list_result(items, total)


def get_task(store: Any, task_id: Any) -> dict | None:
    """``GET /api/scan/tasks/<id>``：单任务详情（含解码后的 checkpoint）。"""
    row = _query_one(store, "SELECT * FROM scan_task WHERE task_id=?", (_qs(task_id),))
    if not row:
        return None
    item = _parse_task(row)
    _enrich_asset([item], _asset_map(store, [item.get("asset_id")]))
    return item


# ---------------------------------------------------------------------------
# finding / 资产
# ---------------------------------------------------------------------------
def list_findings(
    store: Any,
    asset_id: Any = None,
    severity: Any = None,
    status: Any = None,
    kind: Any = None,
    limit: int = 200,
) -> dict:
    """``GET /api/scan/findings``：当前 finding 列表（资产/严重级/状态/类型过滤）。

    ``scan_finding`` 是"当前状态"（每 ``(asset_id, finding_key)`` 一行）；
    历史快照请用 :func:`get_snapshot` / :func:`get_diff`。
    """
    count = _limit(limit, 200)
    where: list[str] = []
    args: list[Any] = []
    for column, value, allowed in (
        ("asset_id", asset_id, None),
        ("severity", severity, SEVERITIES),
        ("status", status, STATUSES),
        ("kind", kind, KINDS),
    ):
        text = _qs(value)
        if not text:
            continue
        if allowed is not None:
            text = text.lower() if column != "severity" else text
            if text not in allowed:
                # 非法枚举值：直接返回空集，不去猜用户意图
                return _list_result([], 0)
        where.append(f"{column}=?")
        args.append(text)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = _count(store, f"SELECT COUNT(*) AS n FROM scan_finding{clause}", args)
    rows = _query(
        store,
        "SELECT finding_id, task_id, asset_id, snapshot_id, kind, check_id, title, severity,"
        " cvss, cvss_source, confidence, status, finding_key, target, evidence_json,"
        " vuln_ref, first_seen, last_seen, updated_at"
        f" FROM scan_finding{clause}{_FINDING_ORDER} LIMIT ?",
        args + [count],
    )
    items = [_parse_finding(row) for row in rows]
    _enrich_asset(items, _asset_map(store, [row.get("asset_id") for row in items]))
    return _list_result(items, total)


def get_finding(store: Any, finding_id: Any) -> dict | None:
    """``GET /api/scan/findings/<id>``：单条 finding 详情。"""
    row = _query_one(
        store, "SELECT * FROM scan_finding WHERE finding_id=?", (_qs(finding_id),)
    )
    if not row:
        return None
    item = _parse_finding(row)
    _enrich_asset([item], _asset_map(store, [item.get("asset_id")]))
    return item


def list_assets(store: Any) -> dict:
    """``GET /api/scan/assets``：资产台账（启用的排前面）。"""
    rows = _query(
        store,
        "SELECT asset_id, ip, hostname, os_family, os_version, role, criticality,"
        " group_name, tags, cred_ref, is_self, enabled, first_seen, last_seen, facts_json"
        " FROM asset ORDER BY enabled DESC, criticality DESC, asset_id",
    )
    items: list[dict] = []
    for row in rows:
        item = dict(row)
        item["enabled"] = bool(item.get("enabled", 1))
        item["is_self"] = bool(item.get("is_self"))
        item["facts"] = _loads(item.pop("facts_json", None), {}) or {}
        tags = item.get("tags")
        if isinstance(tags, str) and tags.strip().startswith("["):
            item["tags"] = _loads(tags, tags)
        items.append(item)
    return _list_result(items)


# ---------------------------------------------------------------------------
# 快照 / 差异 / 覆盖率
# ---------------------------------------------------------------------------
def list_snapshots(store: Any, limit: int = 20) -> dict:
    """``GET /api/scan/snapshots``：快照列表（按时间倒序）。"""
    count = _limit(limit, 20)
    total = _count(store, "SELECT COUNT(*) AS n FROM scan_snapshot")
    rows = _query(
        store,
        "SELECT snapshot_id, plan_id, run_id, ts, kind, label, is_base,"
        " task_count, finding_count, stats_json"
        " FROM scan_snapshot ORDER BY ts DESC LIMIT ?",
        (count,),
    )
    items: list[dict] = []
    for row in rows:
        item = dict(row)
        item["is_base"] = bool(item.get("is_base"))
        item["stats"] = _loads(item.pop("stats_json", None), {}) or {}
        items.append(item)
    return _list_result(items, total)


def get_snapshot(store: Any, snapshot_id: Any) -> dict | None:
    """``GET /api/scan/snapshots/<id>``：快照详情 + 冻结项统计。"""
    snapshot_id = _qs(snapshot_id)
    row = _query_one(store, "SELECT * FROM scan_snapshot WHERE snapshot_id=?", (snapshot_id,))
    if not row:
        return None
    item = dict(row)
    item["is_base"] = bool(item.get("is_base"))
    item["stats"] = _loads(item.pop("stats_json", None), {}) or {}
    item["item_count"] = _count(
        store,
        "SELECT COUNT(*) AS n FROM scan_snapshot_item WHERE snapshot_id=?",
        (snapshot_id,),
    )
    item["by_kind"] = _group_count(
        store,
        "SELECT kind AS k, COUNT(*) AS n FROM scan_snapshot_item"
        " WHERE snapshot_id=? GROUP BY kind",
        (snapshot_id,),
    )
    item["by_severity"] = _group_count(
        store,
        "SELECT COALESCE(severity, '无') AS k, COUNT(*) AS n FROM scan_snapshot_item"
        " WHERE snapshot_id=? GROUP BY k",
        (snapshot_id,),
    )
    return item


def get_diff(store: Any, cur: Any, prev: Any) -> dict:
    """``GET /api/scan/diff?cur=&prev=``：两个快照的四态差异（只读，不写统计）。"""
    try:
        return diff_mod.build(store, _qs(cur), _qs(prev), write_stat=False)
    except Exception as exc:  # noqa: BLE001 - diff.build 已容错，这里再兜一层
        log.warn("scan.api diff 失败", error=str(exc))
        return {
            "cur": _qs(cur),
            "prev": _qs(prev),
            "ts": _now(),
            "items": [],
            "stats": {"new": 0, "fixed": 0, "persisting": 0, "regressed": 0, "total": 0},
            "by_severity": {},
            "error": str(exc),
        }


def get_coverage(store: Any, snapshot_id: Any, cfg: dict | None = None) -> dict:
    """``GET /api/scan/coverage?snapshot=``：加权覆盖率（只读）。"""
    try:
        result = coverage_mod.compute(store, _qs(snapshot_id), cfg)
    except Exception as exc:  # noqa: BLE001
        log.warn("scan.api coverage 失败", error=str(exc))
        result = {
            "snapshot_id": _qs(snapshot_id),
            "ts": _now(),
            "assets": 0,
            "coverage": 0.0,
            "by_domain": {},
            "matrix": [],
            "uncovered": [],
            "weights": dict(coverage_mod.DEFAULT_WEIGHTS),
            "error": str(exc),
        }
    return result


def trend(store: Any, limit: int = 12) -> dict:
    """``GET /api/scan/trend``：历史 diff 统计（new/fixed 曲线数据）。"""
    try:
        items = diff_mod.trend(store, limit) or []
    except Exception as exc:  # noqa: BLE001
        log.warn("scan.api trend 失败", error=str(exc))
        items = []
    return _list_result(items)


# ---------------------------------------------------------------------------
# CVE 库统计 / 总览
# ---------------------------------------------------------------------------
def cve_stats(store: Any) -> dict:
    """``GET /api/scan/cve``：CVE 库聚合（无表时返回全零结构，不抛）。"""
    result: dict[str, Any] = {
        "total": 0,
        "by_severity": {},
        "by_source": {},
        "by_year": {},
        "last_modified": None,
        "oval_fixes": 0,
        "component_map": 0,
        "ts": _now(),
    }
    row = _query_one(
        store, "SELECT COUNT(*) AS n, MAX(modified) AS last_modified FROM cve_cache"
    )
    if row:
        result["total"] = int(row.get("n") or 0)
        result["last_modified"] = row.get("last_modified")
    result["by_severity"] = _group_count(
        store,
        "SELECT COALESCE(severity, '无') AS k, COUNT(*) AS n FROM cve_cache GROUP BY k",
    )
    result["by_source"] = _group_count(
        store,
        "SELECT COALESCE(source, 'unknown') AS k, COUNT(*) AS n FROM cve_cache GROUP BY k",
    )
    result["by_year"] = _group_count(
        store,
        "SELECT substr(COALESCE(published, ''), 1, 4) AS k, COUNT(*) AS n"
        " FROM cve_cache GROUP BY k ORDER BY k",
    )
    result["oval_fixes"] = _count(store, "SELECT COUNT(*) AS n FROM scan_oval_fix")
    result["component_map"] = _count(store, "SELECT COUNT(*) AS n FROM cve_component_map")
    return result


def overview(store: Any) -> dict:
    """``GET /api/scan/overview``：台账/计划/任务/快照/finding 计数 + 最近任务/快照。

    额外给出 ``counts``（扁平计数，Web 概览直接复用）与 ``last_task`` / ``last_snapshot``。
    """
    counts = {
        "asset": _count(store, "SELECT COUNT(*) AS n FROM asset"),
        "plan": _count(store, "SELECT COUNT(*) AS n FROM scan_plan"),
        "task": _count(store, "SELECT COUNT(*) AS n FROM scan_task"),
        "snapshot": _count(store, "SELECT COUNT(*) AS n FROM scan_snapshot"),
        "finding": _count(store, "SELECT COUNT(*) AS n FROM scan_finding"),
        "cve": _count(store, "SELECT COUNT(*) AS n FROM cve_cache"),
    }
    task_status = _group_count(
        store, "SELECT status AS k, COUNT(*) AS n FROM scan_task GROUP BY status"
    )
    finding_status = _group_count(
        store, "SELECT status AS k, COUNT(*) AS n FROM scan_finding GROUP BY status"
    )
    finding_kind = _group_count(
        store, "SELECT kind AS k, COUNT(*) AS n FROM scan_finding GROUP BY kind"
    )
    recent_tasks = [_parse_task(row) for row in _query(
        store,
        "SELECT task_id, plan_id, asset_id, status, stage, progress, snapshot_id,"
        " started_at, finished_at, cost_ms, error FROM scan_task"
        " ORDER BY COALESCE(started_at, '') DESC, task_id DESC LIMIT 5",
    )]
    _enrich_asset(recent_tasks, _asset_map(store, [row.get("asset_id") for row in recent_tasks]))
    last_task_row = _query_one(
        store,
        "SELECT * FROM scan_task ORDER BY COALESCE(started_at, '') DESC, task_id DESC LIMIT 1",
    )
    last_task = _parse_task(last_task_row) if last_task_row else None

    last_snapshot = _query_one(
        store, "SELECT * FROM scan_snapshot ORDER BY ts DESC LIMIT 1"
    )
    if last_snapshot:
        last_snapshot = dict(last_snapshot)
        last_snapshot["is_base"] = bool(last_snapshot.get("is_base"))
        last_snapshot["stats"] = _loads(last_snapshot.pop("stats_json", None), {}) or {}

    return {
        "counts": counts,
        "assets": counts["asset"],
        "plans": counts["plan"],
        "tasks": {"total": counts["task"], "by_status": task_status},
        "snapshots": counts["snapshot"],
        "findings": {
            "total": counts["finding"],
            "by_status": finding_status,
            "by_kind": finding_kind,
        },
        "cve": {"total": counts["cve"]},
        "recent_tasks": recent_tasks,
        "last_task": last_task,
        "last_snapshot": last_snapshot,
        "ts": _now(),
    }
