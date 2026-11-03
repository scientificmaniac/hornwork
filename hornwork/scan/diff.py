"""IF-22：扫描快照差异（扫描模块"结果解释层"之一）。

"定期扫描"的价值必须靠差异证明：没有 diff，"每天扫"和"每周扫"在报告上无法区分。
本模块只读 ``scan_snapshot_item``（**冻结项**，不读会被后续扫描覆盖状态的
``scan_finding``），按下列四态判级：

===========  ==========================================================
``new``        上次快照没有、本次快照有；
``fixed``      上次快照有、本次快照没有；
``regressed``  两边都有，但本次 ``status='reopened'``，或上次已是 ``fixed``
               （修好后又出现 = 回归）；
``persisting`` 其余"两边都有"的情况。
===========  ==========================================================

对外接口：:func:`build` / :func:`trend` / :func:`window`。所有函数只用标准库，
导入期不碰数据库；库表缺失或参数非法时返回带 ``error`` 字段的空结构而不抛异常
（报告/Web 是"解释层"，不能让一次查询失败拖垮整份报告）。

``finding_key`` 的语义见设计：``sha256(asset_id|kind|check_id|target)[:32]``，
与来源引擎无关，只描述"什么东西坏了"，因此同一 key 在两次快照间可直接对齐。
"""

from __future__ import annotations

import json
from typing import Any

from ..log import get_logger
from ..schema import utc_now

log = get_logger("scan.diff")

#: 四态展示顺序（报告里"回归"最刺眼，排最前；"已修复"放最后）
DELTA_ORDER: dict[str, int] = {
    "regressed": 0,
    "new": 1,
    "persisting": 2,
    "fixed": 3,
}

#: 严重级排序（严重 > 高 > 中 > 低 > 无）
SEVERITY_ORDER: dict[str, int] = {"严重": 0, "高": 1, "中": 2, "低": 3, "无": 4}

#: 严重级全集（``by_severity`` 固定输出这五档，缺档补 0，方便报告直接遍历）
SEVERITIES: tuple[str, ...] = ("严重", "高", "中", "低", "无")

#: 四态中文标签（报告/CLI 共用）
DELTA_LABELS: dict[str, str] = {
    "new": "新增",
    "fixed": "已修复",
    "persisting": "仍存在",
    "regressed": "回归",
}

#: 问题类 finding 的 kind（事实类 port/component 不参与 diff 统计，见 §4.8）
ISSUE_KINDS: tuple[str, ...] = ("cve", "config", "tls", "web")


def _json_obj(raw: Any) -> dict:
    """把 JSON 字符串解析成 dict；解析失败/非 dict 一律返回空 dict。"""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _empty_stats() -> dict:
    """四态统计的全零骨架。"""
    return {"new": 0, "fixed": 0, "persisting": 0, "regressed": 0, "total": 0}


def _empty_by_severity() -> dict:
    """按严重级统计的全零骨架（五档全给，报告可直接遍历）。"""
    return {sev: _empty_stats() for sev in SEVERITIES}


def _items_of(store: Any, snapshot_id: str) -> dict[tuple[str, str], dict]:
    """读取某快照的全部冻结项，返回 ``{(asset_id, finding_key): item}``。

    只读 ``scan_snapshot_item``——``scan_finding`` 是"当前状态"，拿它对比历史快照
    会把"后来修好/后来变严重"的状态错误地套到旧快照上。
    """
    rows = store.query(
        "SELECT asset_id, finding_key, kind, check_id, severity, status, cvss"
        " FROM scan_snapshot_item WHERE snapshot_id=?",
        (snapshot_id,),
    )
    out: dict[tuple[str, str], dict] = {}
    for row in rows or []:
        asset_id = str(row.get("asset_id") or "")
        finding_key = str(row.get("finding_key") or "")
        if not asset_id or not finding_key:
            continue
        out[(asset_id, finding_key)] = {
            "asset_id": asset_id,
            "finding_key": finding_key,
            "kind": row.get("kind"),
            "check_id": row.get("check_id"),
            "severity": row.get("severity"),
            "status": row.get("status"),
            "cvss": row.get("cvss"),
        }
    return out


def _finding_meta(store: Any) -> dict[tuple[str, str], dict]:
    """读取 ``scan_finding`` 的展示字段（标题/目标/CVSS），用于补全 diff 行。

    读取失败（表不存在/库未初始化）返回空 dict，diff 仍用冻结项里的列兜底。
    """
    try:
        rows = store.query(
            "SELECT asset_id, finding_key, title, target, severity, cvss"
            " FROM scan_finding"
        )
    except Exception as exc:  # noqa: BLE001 - 解释层必须容错
        log.warn("diff 读取 scan_finding 失败", error=str(exc))
        return {}
    out: dict[tuple[str, str], dict] = {}
    for row in rows or []:
        key = (str(row.get("asset_id") or ""), str(row.get("finding_key") or ""))
        if key[1]:
            out[key] = row
    return out


def _classify(prev: dict | None, cur: dict | None) -> str:
    """四态判级。"""
    if prev is None:
        return "new"
    if cur is None:
        return "fixed"
    cur_status = str(cur.get("status") or "").strip().lower()
    prev_status = str(prev.get("status") or "").strip().lower()
    if cur_status == "reopened":
        return "regressed"
    if prev_status == "fixed":
        return "regressed"
    return "persisting"


def _sort_key(item: dict) -> tuple[int, int, float]:
    """排序键：回归→新增→仍存在→已修复；同级按严重级，再按 CVSS 降序。"""
    severity = str(item.get("severity") or "无")
    cvss = item.get("cvss")
    try:
        cvss_num = float(cvss) if cvss is not None else -1.0
    except (TypeError, ValueError):
        cvss_num = -1.0
    return (
        DELTA_ORDER.get(str(item.get("delta")), 9),
        SEVERITY_ORDER.get(severity, 5),
        -cvss_num,
    )


def _demo_item(
    key: tuple[str, str],
    delta: str,
    prev: dict | None,
    cur: dict | None,
    meta: dict,
) -> dict:
    """把一条差异拼成报告可直接渲染的 dict（冻结项优先，元数据补标题/目标）。"""
    base = cur or prev or {}
    title = meta.get("title")
    target = meta.get("target")
    severity = meta.get("severity") or base.get("severity")
    cvss = meta.get("cvss")
    if cvss is None:
        cvss = base.get("cvss")
    return {
        "finding_key": key[1],
        "asset_id": key[0],
        "kind": base.get("kind"),
        "check_id": base.get("check_id"),
        "severity": severity,
        "cvss": cvss,
        "title": title,
        "target": target,
        "prev_status": (prev or {}).get("status"),
        "cur_status": (cur or {}).get("status"),
        "delta": delta,
    }


def _write_stat(store: Any, cur_snapshot: str, prev_snapshot: str, stats: dict, ts: str) -> None:
    """把本次统计写入 ``scan_diff_stat``（主键 cur,prev，重复查看幂等覆盖）。"""
    try:
        store.execute(
            "INSERT OR REPLACE INTO scan_diff_stat("
            " cur, prev, new, fixed, persisting, regressed, ts)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                cur_snapshot,
                prev_snapshot,
                int(stats.get("new") or 0),
                int(stats.get("fixed") or 0),
                int(stats.get("persisting") or 0),
                int(stats.get("regressed") or 0),
                ts,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - 统计表写失败不应中断报告
        log.warn("diff 写 scan_diff_stat 失败", cur=cur_snapshot, prev=prev_snapshot, error=str(exc))


def build(store: Any, cur_snapshot: str, prev_snapshot: str, write_stat: bool = True) -> dict:
    """对比两个快照，返回四态差异与统计，并（默认）写入 ``scan_diff_stat``。

    返回结构::

        {"cur","prev","ts","items":[{finding_key,asset_id,kind,check_id,severity,cvss,
          title,target,prev_status,cur_status,delta}],
         "stats":{"new","fixed","persisting","regressed","total"},
         "by_severity":{"严重":{...五个计数},...}}

    ``prev_snapshot`` 为空或不存在时返回全零统计 + ``error`` 字段（不抛），
    便于报告在"首次扫描没有上一次"时仍能完整渲染。
    ``write_stat=False`` 供 Web 只读查询使用（GET 不落库）。
    """
    cur_snapshot = str(cur_snapshot or "").strip()
    prev_snapshot = str(prev_snapshot or "").strip()
    ts = utc_now()
    result: dict[str, Any] = {
        "cur": cur_snapshot,
        "prev": prev_snapshot,
        "ts": ts,
        "items": [],
        "stats": _empty_stats(),
        "by_severity": _empty_by_severity(),
    }
    if not prev_snapshot:
        result["error"] = "prev_snapshot 为空：没有可对比的上一次快照"
        return result
    if not cur_snapshot:
        result["error"] = "cur_snapshot 为空：缺少本次快照"
        return result

    # 快照存在性校验：两边都必须能在 scan_snapshot 里找到（表缺失按"不存在"处理）
    try:
        prev_row = store.query_one(
            "SELECT snapshot_id FROM scan_snapshot WHERE snapshot_id=?", (prev_snapshot,)
        )
        cur_row = store.query_one(
            "SELECT snapshot_id FROM scan_snapshot WHERE snapshot_id=?", (cur_snapshot,)
        )
    except Exception as exc:  # noqa: BLE001 - 多数是表未建（尚未跑过扫描）
        log.warn("diff 校验快照失败", cur=cur_snapshot, prev=prev_snapshot, error=str(exc))
        result["error"] = f"scan_snapshot 查询失败：{exc}"
        return result
    if prev_row is None:
        result["error"] = f"prev_snapshot 不存在：{prev_snapshot}"
        return result
    if cur_row is None:
        result["error"] = f"cur_snapshot 不存在：{cur_snapshot}"
        return result

    try:
        prev_items = _items_of(store, prev_snapshot)
        cur_items = _items_of(store, cur_snapshot)
    except Exception as exc:  # noqa: BLE001
        log.warn("diff 读取快照项失败", error=str(exc))
        result["error"] = f"scan_snapshot_item 查询失败：{exc}"
        return result

    meta = _finding_meta(store)
    rows: list[dict] = []
    for key in set(prev_items) | set(cur_items):
        prev_item = prev_items.get(key)
        cur_item = cur_items.get(key)
        delta = _classify(prev_item, cur_item)
        rows.append(_demo_item(key, delta, prev_item, cur_item, meta.get(key) or {}))
    rows.sort(key=_sort_key)

    stats = _empty_stats()
    by_severity = _empty_by_severity()
    for row in rows:
        delta = str(row.get("delta"))
        stats[delta] = stats.get(delta, 0) + 1
        stats["total"] += 1
        severity = str(row.get("severity") or "无")
        bucket = by_severity.setdefault(severity, _empty_stats())
        bucket[delta] = bucket.get(delta, 0) + 1
        bucket["total"] += 1

    result["items"] = rows
    result["stats"] = stats
    result["by_severity"] = by_severity
    if write_stat:
        _write_stat(store, cur_snapshot, prev_snapshot, stats, ts)
    log.info(
        "scan.diff.built",
        cur=cur_snapshot,
        prev=prev_snapshot,
        new=stats["new"],
        fixed=stats["fixed"],
        persisting=stats["persisting"],
        regressed=stats["regressed"],
    )
    return result


def trend(store: Any, limit: int = 12) -> list[dict]:
    """按 ``ts`` 倒序返回历史差异统计（报告"三次扫描演变"图的数据源）。

    表不存在/库为空返回 ``[]``，不抛异常；``limit`` 默认 12 条（够画 3~6 次曲线）。
    """
    try:
        count = max(1, min(200, int(limit or 12)))
    except (TypeError, ValueError):
        count = 12
    try:
        rows = store.query(
            "SELECT cur, prev, new, fixed, persisting, regressed, ts"
            " FROM scan_diff_stat ORDER BY ts DESC LIMIT ?",
            (count,),
        )
    except Exception as exc:  # noqa: BLE001
        log.warn("diff 读取趋势失败", error=str(exc))
        return []
    out: list[dict] = []
    for row in rows or []:
        out.append(
            {
                "cur": row.get("cur"),
                "prev": row.get("prev"),
                "new": int(row.get("new") or 0),
                "fixed": int(row.get("fixed") or 0),
                "persisting": int(row.get("persisting") or 0),
                "regressed": int(row.get("regressed") or 0),
                "ts": row.get("ts"),
            }
        )
    return out


def window(store: Any, from_snapshot: str, to_snapshot: str) -> dict:
    """``build`` 的 CLI/时间窗别名：从 ``from_snapshot`` 到 ``to_snapshot``。

    对应 ``hornworkctl scan diff --from S1 --to S2`` 语义，即 cur=to、prev=from。
    """
    return build(store, to_snapshot, from_snapshot)
