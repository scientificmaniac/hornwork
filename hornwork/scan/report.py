"""扫描报告渲染与导出。

一份报告要回答三个问题：**这次扫到了什么**（资产与服务清单 + CVE/问题明细）、
**和上次比变了什么**（四态 diff）、**还有哪些没扫到**（覆盖矩阵 + 未覆盖清单）。
另外单列"引擎贡献"表，让"复用引擎 + 自研编排"的边界在报告上可见。

约束：
- 单文件 HTML，内联 CSS，**无外部字体/JS/CDN**，离线双击即可打开，打印友好（``@media print``）；
- 所有动态文本经 :func:`html.escape` 转义；JSON 解析失败一律容错；
- 仅标准库；导入期不读库。

对外接口：:func:`render_html` / :func:`render_json` / :func:`export`。
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from ..config import cfg_get
from ..log import get_logger
from ..schema import utc_now
from . import coverage as coverage_mod
from . import diff as diff_mod

log = get_logger("scan.report")

#: 问题类 finding（事实类 port/component 只进"资产与服务清单"）
ISSUE_KINDS: tuple[str, ...] = ("cve", "config", "tls", "web")

#: 严重级展示顺序
SEVERITY_ORDER: tuple[str, ...] = ("严重", "高", "中", "低", "无")

#: 置信度中文标签（§4.7 四级）
CONFIDENCE_LABELS: dict[str, str] = {
    "exact": "精确匹配",
    "range": "区间命中",
    "cpe_only": "仅 CPE 命中",
    "tool": "工具/PoC",
}

#: 报告里的免责声明（仅用于授权资产与隔离靶场）
DISCLAIMER = (
    "本报告仅用于本地授权资产与隔离靶场（Vulhub）的安全评估教学，"
    "未经书面授权不得用于扫描任何第三方系统。"
)

#: 证据链取值候选键（不同引擎/版本的 evidence_json 字段名可能不同）
_EVIDENCE_KEYS: dict[str, tuple[str, ...]] = {
    "banner": ("banner", "raw_banner", "header", "server_header"),
    "service": ("service", "service_name", "svc", "name"),
    "product": ("product", "app", "software", "component"),
    "component": ("component", "comp_norm", "product", "app"),
    "version": (
        "version", "detected", "detected_version", "matched_version",
        "package_version", "found",
    ),
    "cpe": ("cpe23", "cpe", "cpe_uri"),
    "range": ("range", "interval", "version_range", "affected_range", "constraint"),
    "cvss": ("cvss", "cvss_score", "base_score"),
    "record": (
        "vuln_ref", "archive_id", "record_id", "vuln", "archive", "record",
    ),
    "fixed": ("fixed", "fixed_version", "patch_version"),
    "fix": ("fix", "advice", "remediation", "solution", "mitigation"),
}


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def _e(value: Any, default: str = "-") -> str:
    """转义成 HTML 文本：None/空 → 默认占位，列表用顿号连接，换行折成空格。"""
    if value is None:
        return html.escape(default, quote=True)
    if isinstance(value, (list, tuple)):
        text = "、".join(str(item).strip() for item in value if str(item).strip())
        return html.escape(text or default, quote=True)
    text = re.sub(r"\s+", " ", str(value).strip())
    return html.escape(text or default, quote=True)


def _plain(value: Any, default: str = "-") -> str:
    """转非 HTML 的纯文本（JSON 用）。"""
    if value is None:
        return default
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value if str(item).strip()]
        return "、".join(items) if items else default
    text = re.sub(r"\s+", " ", str(value).strip())
    return text or default


def _json_obj(raw: Any) -> dict:
    """JSON 字符串 → dict；失败/非 dict → 空 dict。"""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _num(value: Any, digits: int = 1, default: str = "-") -> str:
    """数值格式化（CVSS 保留 1 位）。"""
    if value is None or value == "":
        return default
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return default


def _pct(value: Any) -> str:
    """覆盖率 → 百分比字符串（保留 1 位小数）。"""
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "0.0%"


def _trunc(value: Any, limit: int = 200) -> str:
    """截断文本（证据原文可能很长）。"""
    text = _plain(value, "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _loads(value: Any, default: Any = None) -> Any:
    """通用 JSON 解码（失败返回 default）。"""
    if isinstance(value, (dict, list)):
        return value
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _sev_order(value: Any) -> int:
    """严重级排序权重。"""
    try:
        return SEVERITY_ORDER.index(str(value or "无"))
    except ValueError:
        return len(SEVERITY_ORDER)


def _cvss_value(value: Any) -> float:
    """CVSS 排序值（None → -1，保证降序时排最后）。"""
    try:
        return float(value) if value is not None else -1.0
    except (TypeError, ValueError):
        return -1.0


def _sev_badge(value: Any) -> str:
    """严重级彩色徽标（颜色只靠 CSS 类，无常量色值）。"""
    label = str(value or "无")
    cls = {
        "严重": "sev-critical",
        "高": "sev-high",
        "中": "sev-mid",
        "低": "sev-low",
        "无": "sev-none",
    }.get(label, "sev-none")
    return f'<span class="badge {cls}">{_e(label)}</span>'


def _evidence_of(row: dict) -> dict:
    """取 finding 行里的 evidence（dict）。"""
    return _json_obj(row.get("evidence_json") or row.get("evidence"))


def _pick(evidence: dict, name: str) -> Any:
    """按候选键从 evidence 取值。"""
    for key in _EVIDENCE_KEYS.get(name, ()):
        if evidence.get(key) not in (None, "", [], {}):
            return evidence.get(key)
    return None


def _range_text(value: Any) -> str:
    """把"版本区间"的各种表示统一成可读文本。"""
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return "、".join(value)
    if not isinstance(value, dict):
        return str(value)
    start_incl = value.get("start_incl") or value.get("version_start_incl") or value.get("min")
    start_excl = value.get("start_excl") or value.get("version_start_excl")
    end_incl = value.get("end_incl") or value.get("version_end_incl") or value.get("max")
    end_excl = value.get("end_excl") or value.get("version_end_excl")
    parts: list[str] = []
    if start_incl not in (None, ""):
        parts.append(f"≥{start_incl}")
    if start_excl not in (None, ""):
        parts.append(f">{start_excl}")
    if end_incl not in (None, ""):
        parts.append(f"≤{end_incl}")
    if end_excl not in (None, ""):
        parts.append(f"<{end_excl}")
    if parts:
        return "，".join(parts)
    for key in ("raw", "text", "version", "value"):
        if value.get(key) not in (None, ""):
            return str(value[key])
    return json.dumps(value, ensure_ascii=False)


def _fix_text(evidence: dict, vuln_fix: str = "") -> str:
    """修复建议：evidence 的 fix/fixed → 档案 fix → 待补充。"""
    fix = _pick(evidence, "fix")
    if isinstance(fix, dict):
        for key in ("patch_version", "fixed", "advice", "summary"):
            if fix.get(key) not in (None, ""):
                return str(fix[key])
    elif fix not in (None, ""):
        return str(fix)
    fixed = _pick(evidence, "fixed")
    if fixed not in (None, ""):
        return f"升级到 {fixed} 及以上"
    return vuln_fix or ""


def _chain_text(evidence: dict, row: dict) -> str:
    """构造"banner → 版本 → CPE → 区间 → CVSS → 档案"证据链文本。"""
    banner = _pick(evidence, "banner")
    version = _pick(evidence, "version")
    cpe = _pick(evidence, "cpe")
    range_text = _range_text(_pick(evidence, "range"))
    cvss = _pick(evidence, "cvss") or row.get("cvss")
    record = _pick(evidence, "record") or row.get("vuln_ref")
    parts: list[str] = []
    if banner:
        parts.append(f"banner={_trunc(banner, 60)}")
    if version:
        parts.append(f"版本={_plain(version)}")
    if cpe:
        parts.append(f"CPE={_trunc(cpe, 60)}")
    if range_text:
        parts.append(f"区间={_trunc(range_text, 60)}")
    if cvss not in (None, ""):
        parts.append(f"CVSS={_num(cvss)}")
    if record:
        parts.append(f"档案={_plain(record)}")
    if not parts:
        parts.append("证据待补充")
    return " → ".join(parts)


# ---------------------------------------------------------------------------
# 数据采集（全部容错）
# ---------------------------------------------------------------------------
def _snapshot_row(store: Any, snapshot_id: str) -> dict:
    """读取快照行；不存在/表缺失返回空 dict。"""
    try:
        row = store.query_one(
            "SELECT * FROM scan_snapshot WHERE snapshot_id=?", (snapshot_id,)
        )
    except Exception as exc:  # noqa: BLE001
        log.warn("report 读取 scan_snapshot 失败", snapshot=snapshot_id, error=str(exc))
        return {}
    return row or {}


def _plan_row(store: Any, plan_id: Any) -> dict:
    """读取计划行（用于页头"计划/形态"）。"""
    if not plan_id:
        return {}
    try:
        return store.query_one("SELECT * FROM scan_plan WHERE plan_id=?", (str(plan_id),)) or {}
    except Exception as exc:  # noqa: BLE001
        log.warn("report 读取 scan_plan 失败", plan=str(plan_id), error=str(exc))
        return {}


def _tasks_of(store: Any, snapshot: dict, snapshot_id: str) -> list[dict]:
    """取快照所属 run 的任务列表（含各资产 checkpoint）。"""
    rows: list[dict] = []
    run_id = str(snapshot.get("run_id") or "").strip()
    try:
        if run_id:
            rows.extend(store.query("SELECT * FROM scan_task WHERE run_id=?", (run_id,)) or [])
        rows.extend(
            store.query("SELECT * FROM scan_task WHERE snapshot_id=?", (snapshot_id,)) or []
        )
    except Exception as exc:  # noqa: BLE001
        log.warn("report 读取 scan_task 失败", snapshot=snapshot_id, error=str(exc))
    seen: set[str] = set()
    out: list[dict] = []
    for row in rows:
        task_id = str(row.get("task_id") or "")
        if task_id in seen:
            continue
        seen.add(task_id)
        out.append(row)
    return out


def _asset_map(store: Any, asset_ids: list[str]) -> dict[str, dict]:
    """批量取资产台账信息（ip/hostname/role）。"""
    if not asset_ids:
        return {}
    placeholders = ",".join("?" for _ in asset_ids)
    try:
        rows = store.query(
            f"SELECT asset_id, ip, hostname, role, os_family, criticality"
            f" FROM asset WHERE asset_id IN ({placeholders})",
            asset_ids,
        )
    except Exception as exc:  # noqa: BLE001
        log.warn("report 读取 asset 失败", error=str(exc))
        return {}
    return {str(row.get("asset_id")): row for row in rows or []}


def _snapshot_items(store: Any, snapshot_id: str) -> list[dict]:
    """读取快照冻结项（报告展示以快照时刻的严重级/状态为准）。"""
    try:
        return store.query(
            "SELECT asset_id, finding_key, kind, check_id, severity, status, cvss"
            " FROM scan_snapshot_item WHERE snapshot_id=?",
            (snapshot_id,),
        ) or []
    except Exception as exc:  # noqa: BLE001
        log.warn("report 读取 scan_snapshot_item 失败", snapshot=snapshot_id, error=str(exc))
        return []


def _findings_of(store: Any, snapshot_id: str, items: list[dict], tasks: list[dict]) -> list[dict]:
    """取本次快照的 finding 明细。

    优先"冻结项 keys ∩ scan_finding"（快照列决定严重级/状态，明细补标题/证据）；
    冻结项缺失时退回 ``scan_finding.snapshot_id``，再退回 run 内 task_id。
    """
    item_map: dict[tuple[str, str], dict] = {}
    for item in items:
        key = (str(item.get("asset_id") or ""), str(item.get("finding_key") or ""))
        if key[1]:
            item_map[key] = item
    rows: list[dict] = []
    if item_map:
        try:
            all_rows = store.query(
                "SELECT finding_id, task_id, asset_id, snapshot_id, kind, check_id, title,"
                " severity, cvss, cvss_source, confidence, status, finding_key, target,"
                " evidence_json, vuln_ref, first_seen, last_seen FROM scan_finding"
            ) or []
        except Exception as exc:  # noqa: BLE001
            log.warn("report 读取 scan_finding 失败", error=str(exc))
            all_rows = []
        for row in all_rows:
            key = (str(row.get("asset_id") or ""), str(row.get("finding_key") or ""))
            item = item_map.get(key)
            if item is None:
                continue
            merged = dict(row)
            # 冻结项优先：它是"当时的结论"，finding 表可能已被后续扫描更新
            merged["severity"] = item.get("severity") or row.get("severity")
            merged["status"] = item.get("status") or row.get("status")
            if item.get("cvss") is not None:
                merged["cvss"] = item.get("cvss")
            merged["kind"] = item.get("kind") or row.get("kind")
            merged["check_id"] = item.get("check_id") or row.get("check_id")
            rows.append(merged)
        return rows

    try:
        rows = store.query(
            "SELECT finding_id, task_id, asset_id, snapshot_id, kind, check_id, title,"
            " severity, cvss, cvss_source, confidence, status, finding_key, target,"
            " evidence_json, vuln_ref, first_seen, last_seen"
            " FROM scan_finding WHERE snapshot_id=?",
            (snapshot_id,),
        ) or []
    except Exception as exc:  # noqa: BLE001
        log.warn("report 按快照读取 scan_finding 失败", error=str(exc))
        rows = []
    if not rows and tasks:
        task_ids = [str(task.get("task_id")) for task in tasks if task.get("task_id")]
        if task_ids:
            placeholders = ",".join("?" for _ in task_ids)
            try:
                rows = store.query(
                    "SELECT finding_id, task_id, asset_id, snapshot_id, kind, check_id, title,"
                    " severity, cvss, cvss_source, confidence, status, finding_key, target,"
                    " evidence_json, vuln_ref, first_seen, last_seen"
                    f" FROM scan_finding WHERE task_id IN ({placeholders})",
                    task_ids,
                ) or []
            except Exception as exc:  # noqa: BLE001
                log.warn("report 按任务读取 scan_finding 失败", error=str(exc))
                rows = []
    return rows


def _prev_snapshot_id(store: Any, snapshot: dict, snapshot_id: str) -> str:
    """找同一计划、时间上紧邻的上一次快照（用于自动 diff）。"""
    plan_id = str(snapshot.get("plan_id") or "").strip()
    ts = snapshot.get("ts")
    if not ts:
        return ""
    try:
        if plan_id:
            row = store.query_one(
                "SELECT snapshot_id FROM scan_snapshot WHERE plan_id=? AND ts<?"
                " AND snapshot_id<>? ORDER BY ts DESC LIMIT 1",
                (plan_id, ts, snapshot_id),
            )
        else:
            row = store.query_one(
                "SELECT snapshot_id FROM scan_snapshot WHERE ts<? AND snapshot_id<>?"
                " ORDER BY ts DESC LIMIT 1",
                (ts, snapshot_id),
            )
    except Exception as exc:  # noqa: BLE001
        log.warn("report 查找上一快照失败", error=str(exc))
        return ""
    return str((row or {}).get("snapshot_id") or "")


def _vuln_fix(store: Any, vuln_ref: Any, cache: dict[str, str]) -> str:
    """从靶场模块档案取修复方案（表不存在/无记录时返回空串）。"""
    ref = str(vuln_ref or "").strip()
    if not ref:
        return ""
    if ref in cache:
        return cache[ref]
    text = ""
    try:
        row = store.query_one(
            "SELECT payload FROM vuln_record WHERE id=? OR cve=?", (ref, ref)
        )
        payload = _json_obj((row or {}).get("payload"))
        fix = payload.get("fix") if isinstance(payload.get("fix"), dict) else {}
        text = str(fix.get("patch_version") or "")
        if not text:
            for rule in payload.get("affected_versions") or []:
                if isinstance(rule, dict) and rule.get("fixed") not in (None, ""):
                    text = f"升级到 {rule['fixed']} 及以上"
                    break
    except Exception:  # noqa: BLE001 - 未建档/未同步时只是没有修复建议
        text = ""
    cache[ref] = text
    return text


def _engine_rows(snapshot: dict) -> list[dict]:
    """引擎贡献：``stats_json.engines`` → ``[{engine,status,findings,cost_ms,version}]``。

    兼容两种写法：runner 聚合后是 ``{引擎: {"done": n, "error": n, "findings": 总数}}``，
    单任务级是 ``{引擎: {"status": "...", "findings": n, "cost_ms": ms}}``。
    """
    stats = _json_obj(snapshot.get("stats_json"))
    engines = stats.get("engines")
    if not isinstance(engines, dict):
        return []
    known = ("done", "partial", "error", "timeout", "skipped", "dry_run", "not_run")
    rows: list[dict] = []
    for name, info in engines.items():
        detail = info if isinstance(info, dict) else {"status": info}
        status = detail.get("status")
        if status is None:
            parts: list[str] = []
            for key in known:
                try:
                    value = int(detail.get(key) or 0)
                except (TypeError, ValueError):
                    continue
                if value > 0:
                    parts.append(f"{key}×{value}")
            status = " / ".join(parts) or None
        rows.append(
            {
                "engine": str(name),
                "status": status,
                "findings": detail.get("findings"),
                "cost_ms": detail.get("cost_ms"),
                "version": detail.get("version"),
            }
        )
    rows.sort(key=lambda item: str(item.get("engine") or ""))
    return rows


def _collect(store: Any, cfg: dict, snapshot_id: str) -> dict:
    """采集报告所需的全部数据（一次查询，多次渲染）。"""
    snapshot = _snapshot_row(store, snapshot_id)
    plan = _plan_row(store, snapshot.get("plan_id"))
    tasks = _tasks_of(store, snapshot, snapshot_id)
    items = _snapshot_items(store, snapshot_id)
    findings = _findings_of(store, snapshot_id, items, tasks)

    task_asset_ids = [str(task.get("asset_id")) for task in tasks if task.get("asset_id")]
    item_asset_ids = [str(item.get("asset_id")) for item in items if item.get("asset_id")]
    find_asset_ids = [str(row.get("asset_id")) for row in findings if row.get("asset_id")]
    asset_ids: list[str] = []
    for value in task_asset_ids + item_asset_ids + find_asset_ids:
        if value and value not in asset_ids:
            asset_ids.append(value)
    assets = _asset_map(store, asset_ids)

    facts: list[dict] = []
    issues: list[dict] = []
    vuln_fix_cache: dict[str, str] = {}
    for row in findings:
        evidence = _evidence_of(row)
        asset = assets.get(str(row.get("asset_id") or "")) or {}
        base = {
            "asset_id": row.get("asset_id"),
            "ip": asset.get("ip"),
            "hostname": asset.get("hostname"),
            "kind": row.get("kind"),
            "check_id": row.get("check_id"),
            "title": row.get("title"),
            "severity": row.get("severity"),
            "status": row.get("status"),
            "target": row.get("target"),
        }
        if str(row.get("kind") or "") in ISSUE_KINDS:
            confidence = str(row.get("confidence") or "").strip().lower()
            detected = _pick(evidence, "version")
            hit = _range_text(_pick(evidence, "range"))
            fixed = _pick(evidence, "fixed")
            if not hit and fixed not in (None, ""):
                hit = f"修复版本 {fixed}"
            fix_text = _fix_text(evidence, _vuln_fix(store, row.get("vuln_ref"), vuln_fix_cache))
            issues.append(
                {
                    **base,
                    "component": row.get("target") or _pick(evidence, "component") or "-",
                    "detected": _plain(detected, "-"),
                    "hit": _plain(hit, "-"),
                    "rule": CONFIDENCE_LABELS.get(confidence, confidence or "-"),
                    "confidence": confidence or "-",
                    "cvss": row.get("cvss"),
                    "cvss_source": row.get("cvss_source") or "nvd",
                    "vuln_ref": row.get("vuln_ref") or "",
                    "fix": _plain(fix_text, "待补充"),
                    "chain": _chain_text(evidence, row),
                }
            )
        else:
            banner = _pick(evidence, "banner")
            if not banner:
                pieces = [
                    evidence.get("product"), evidence.get("version"),
                    evidence.get("extrainfo"),
                ]
                banner = " ".join(str(part).strip() for part in pieces if part)
            if not banner and evidence.get("state"):
                banner = f"state={evidence.get('state')}"
                if evidence.get("reason"):
                    banner += f"，reason={evidence.get('reason')}"
            facts.append(
                {
                    **base,
                    "service": _plain(_pick(evidence, "service") or _pick(evidence, "product"), "-"),
                    "version": _plain(_pick(evidence, "version"), "-"),
                    "banner": _plain(banner, "-"),
                }
            )

    facts.sort(key=lambda item: (str(item.get("asset_id") or ""), str(item.get("target") or "")))
    # 置信度优先排序：可确认（range/exact/tool）在前，"仅 CPE 命中"（低置信）沉底，
    # 报告读者先看到有证据的结论，再看到"待人工确认"。同置信度内按严重级与 CVSS 排。
    _conf_rank = {"range": 0, "exact": 1, "tool": 2, "cpe_only": 3}
    issues.sort(
        key=lambda item: (
            _conf_rank.get(str(item.get("confidence") or "").lower(), 4),
            _sev_order(item.get("severity")),
            -_cvss_value(item.get("cvss")),
            str(item.get("check_id") or ""),
        )
    )

    severity_dist = {sev: 0 for sev in SEVERITY_ORDER}
    for item in issues:
        key = str(item.get("severity") or "无")
        severity_dist[key] = severity_dist.get(key, 0) + 1

    cve_count = sum(1 for item in issues if str(item.get("check_id") or "").upper().startswith("CVE-"))
    stats = _json_obj(snapshot.get("stats_json"))
    engines = _engine_rows(snapshot)
    return {
        "snapshot": snapshot,
        "plan": plan,
        "tasks": tasks,
        "assets": assets,
        "asset_ids": asset_ids,
        "facts": facts,
        "issues": issues,
        "severity_dist": severity_dist,
        "cve_count": cve_count,
        "engines": engines,
        "stats": stats,
    }


def _report_context(
    store: Any,
    cfg: dict,
    snapshot_id: str,
    diff: dict | None,
    coverage: dict | None,
) -> dict:
    """在 :func:`_collect` 之上补齐 diff / coverage / 页头页脚信息。"""
    snapshot_id = str(snapshot_id or "").strip()
    data = _collect(store, cfg, snapshot_id)
    snapshot = data["snapshot"]

    if diff is not None and not isinstance(diff, dict):
        diff = None
    if diff is None and snapshot:
        prev_id = _prev_snapshot_id(store, snapshot, snapshot_id)
        if prev_id:
            try:
                # 生成报告属于"主动留痕"，默认把本次 diff 统计落 scan_diff_stat
                diff = diff_mod.build(store, snapshot_id, prev_id)
            except Exception as exc:  # noqa: BLE001 - diff 失败不阻断报告
                log.warn("report 自动 diff 失败", snapshot=snapshot_id, error=str(exc))
                diff = None
    if coverage is None:
        try:
            coverage = coverage_mod.compute(store, snapshot_id, cfg)
        except Exception as exc:  # noqa: BLE001
            log.warn("report 计算覆盖率失败", snapshot=snapshot_id, error=str(exc))
            coverage = None

    plan = data["plan"]
    stats = data["stats"]
    profile = str(stats.get("profile") or plan.get("profile") or "-")
    host_count = len({str(task.get("asset_id")) for task in data["tasks"] if task.get("asset_id")})
    if not host_count:
        host_count = len(data["asset_ids"])

    diff_stats = (diff or {}).get("stats") or {}
    ctx = {
        "snapshot_id": snapshot_id,
        "snapshot": snapshot,
        "plan": plan,
        "profile": profile,
        "host_count": host_count,
        "diff": diff,
        "coverage": coverage,
        "summary": {
            "assets": host_count,
            "issues": len(data["issues"]),
            "facts": len(data["facts"]),
            "cves": data["cve_count"],
            "severity_dist": data["severity_dist"],
            "coverage": float((coverage or {}).get("coverage") or 0.0),
            "new": int(diff_stats.get("new") or 0),
            "fixed": int(diff_stats.get("fixed") or 0),
            "persisting": int(diff_stats.get("persisting") or 0),
            "regressed": int(diff_stats.get("regressed") or 0),
            "prev": (diff or {}).get("prev"),
            "has_diff": bool(diff) and not (diff or {}).get("error"),
            "diff_error": (diff or {}).get("error"),
        },
        "generated_at": utc_now(),
        "rules_version": str(cfg_get(cfg, "scan.rules_version", "scan-rules-v1") or "scan-rules-v1"),
        "command": f"hornworkctl scan report --snapshot {snapshot_id} --format html",
    }
    ctx.update({
        key: data[key]
        for key in ("facts", "issues", "engines", "tasks", "assets", "asset_ids")
    })
    return ctx


# ---------------------------------------------------------------------------
# HTML 渲染
# ---------------------------------------------------------------------------
_CSS = """
:root{color-scheme:light}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI","Microsoft YaHei","PingFang SC",sans-serif;
  color:#1f2937;background:#f3f4f6;line-height:1.55;font-size:14px}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px 48px}
header.report-head{background:linear-gradient(135deg,#0f172a,#1e3a8a);color:#f8fafc;
  border-radius:10px;padding:26px 30px;margin-bottom:18px}
header.report-head h1{margin:0 0 4px;font-size:25px;letter-spacing:.5px}
header.report-head .sub{color:#c7d2fe;font-size:13px;margin-bottom:16px}
.meta{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px 22px;font-size:13px}
.meta div{color:#e2e8f0}
.meta b{color:#fff;font-weight:600}
.meta .k{color:#93c5fd;margin-right:6px}
section{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px 22px;
  margin-bottom:16px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
h2{font-size:17px;margin:0 0 14px;padding-bottom:9px;border-bottom:2px solid #e5e7eb;
  color:#0f172a;display:flex;align-items:center;gap:8px}
h2 .tag{font-size:12px;font-weight:400;color:#6b7280}
h3{font-size:14px;margin:18px 0 8px;color:#334155}
p.note{color:#6b7280;font-size:12.5px;margin:6px 0 12px}
.cards{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px}
.card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px}
.card .label{font-size:12px;color:#64748b;margin-bottom:4px}
.card .value{font-size:21px;font-weight:700;color:#0f172a;word-break:break-all}
.card .hint{font-size:11.5px;color:#94a3b8;margin-top:3px}
.card.hl{border-color:#bfdbfe;background:#eff6ff}
.card.warn{border-color:#fed7aa;background:#fff7ed}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin:6px 0 4px}
th,td{border:1px solid #e5e7eb;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f1f5f9;color:#334155;font-weight:600;white-space:nowrap}
tbody tr:nth-child(even){background:#fafafa}
td.mono,.mono{font-family:Consolas,"SFMono-Regular","Courier New",monospace;font-size:12px}
.nowrap{white-space:nowrap}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;
  font-weight:600;white-space:nowrap;border:1px solid transparent}
.sev-critical{background:#fee2e2;color:#991b1b;border-color:#fecaca}
.sev-high{background:#ffedd5;color:#9a3412;border-color:#fed7aa}
.sev-mid{background:#fef9c3;color:#854d0e;border-color:#fde68a}
.sev-low{background:#dbeafe;color:#1e40af;border-color:#bfdbfe}
.sev-none{background:#f1f5f9;color:#475569;border-color:#e2e8f0}
.cov{display:inline-block;min-width:52px;text-align:center;padding:1px 6px;border-radius:5px;
  font-size:11.5px;font-weight:600;font-family:Consolas,monospace}
.cov-full{background:#dcfce7;color:#166534}
.cov-half{background:#fef3c7;color:#92400e}
.cov-zero{background:#fee2e2;color:#991b1b}
.cov-na{background:#f8fafc;color:#cbd5e1;border:1px dashed #e2e8f0}
.table-wrap{overflow-x:auto}
.empty{color:#94a3b8;font-size:12.5px;padding:8px 2px}
.chain{font-size:11.5px;color:#475569;max-width:420px;word-break:break-all}
.diff-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.diff-block h3{margin-top:0}
.diff-block h3 .n{color:#64748b;font-weight:500;font-size:12.5px}
.legend{font-size:12px;color:#64748b;margin:4px 0 10px}
footer{color:#64748b;font-size:12px;padding:16px 4px 0;border-top:1px solid #e5e7eb;
  margin-top:8px;line-height:1.8}
footer b{color:#334155}
.cover-note{font-size:12.5px;color:#6b7280;margin-top:8px}
@media (max-width:900px){
  .cards{grid-template-columns:repeat(2,minmax(0,1fr))}
  .meta{grid-template-columns:1fr}
  .diff-grid{grid-template-columns:1fr}
}
@media print{
  body{background:#fff;font-size:11.5px}
  .wrap{max-width:none;padding:0}
  section{box-shadow:none;border:1px solid #d1d5db;break-inside:avoid;padding:14px 16px}
  header.report-head{background:#1e3a8a !important;-webkit-print-color-adjust:exact;
    print-color-adjust:exact}
  .table-wrap{overflow:visible}
  table{font-size:10.5px}
  h2{break-after:avoid}
  tr{break-inside:avoid}
  .cards{grid-template-columns:repeat(3,minmax(0,1fr))}
  @page{size:A4 landscape;margin:12mm}
}
"""


def _cell(text: str, cls: str = "") -> str:
    """``<td>`` 片段（text 必须是已转义 HTML）。"""
    return f'<td class="{cls}">{text}</td>' if cls else f"<td>{text}</td>"


def _table(headers: list[str], rows: list[str], cls: str = "") -> str:
    """通用表格：headers 为已转义文本，rows 为 ``<tr>`` 片段列表。"""
    head = "".join(f"<th>{html.escape(str(item), quote=True)}</th>" for item in headers)
    body = "".join(rows) if rows else (
        f'<tr><td class="empty" colspan="{len(headers)}">（无记录）</td></tr>'
    )
    cls_attr = f' class="{cls}"' if cls else ""
    return (
        f'<div class="table-wrap"><table{cls_attr}><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div>"
    )


def _cov_cell(value: float) -> str:
    """覆盖矩阵单元格：1.0 绿 / 0.5 黄 / 0 红。"""
    cls = "cov-full" if value >= 1.0 else ("cov-half" if value > 0 else "cov-zero")
    return f'<span class="cov {cls}">{_num(value, 1)}</span>'


def _cov_na() -> str:
    """不适用域：显示灰色"—"，避免把"不适用"误读成"未覆盖"。"""
    return '<span class="cov cov-na">—</span>'


def _render_header(ctx: dict) -> str:
    """页头：标题 + 快照/计划/运行时间/主机/引擎 profile。"""
    snapshot = ctx["snapshot"]
    plan = ctx["plan"]
    profile = ctx["profile"]
    labels = snapshot.get("label") or ""
    meta = [
        ("快照", ctx["snapshot_id"] + (f"（{labels}）" if labels else "")),
        ("快照时间", snapshot.get("ts")),
        ("计划", f"{_plain(plan.get('name') or plan.get('plan_id'))}（{_plain(plan.get('kind'))}）"),
        ("运行号", snapshot.get("run_id")),
        ("形态 / Profile", f"{_plain(snapshot.get('kind'))} / {_plain(profile)}"),
        ("主机数", f"{ctx['host_count']} 台"),
    ]
    if snapshot.get("is_base"):
        meta.append(("基线", "是（首次全量快照）"))
    items = "".join(
        f'<div><span class="k">{html.escape(name, quote=True)}</span><b>{_e(value)}</b></div>'
        for name, value in meta
    )
    return (
        '<header class="report-head">'
        + "<h1>Hornwork · 漏洞扫描报告</h1>"
        + '<div class="sub">引擎可换 · 编排自研 · 结果可解释：'
        + "本报告给出本次结论、与上次快照的差异、以及明确未覆盖的盲区。</div>"
        + f'<div class="meta">{items}</div>'
        + "</header>"
    )


def _render_summary(ctx: dict) -> str:
    """概览卡片：资产/问题/CVE/严重级/覆盖率/变化。"""
    summary = ctx["summary"]
    dist = summary["severity_dist"]
    dist_text = " ".join(
        f'{sev} {int(dist.get(sev) or 0)}' for sev in SEVERITY_ORDER if int(dist.get(sev) or 0)
    ) or "无问题项"
    diff_hint = "—"
    if summary["has_diff"] and not summary.get("prev"):
        diff_hint = "首次快照"
    elif summary["has_diff"]:
        diff_hint = f'新增 {summary["new"]} / 已修复 {summary["fixed"]}'
    elif summary["diff_error"]:
        diff_hint = "无上次快照可比"
    cards = [
        ("资产数", str(summary["assets"]), "本快照涉及主机", ""),
        ("finding 总数", str(summary["issues"]), f'事实项 {summary["facts"]} 条（端口/组件）', ""),
        ("CVE 数", str(summary["cves"]), "check_id 为 CVE 编号", "hl"),
        ("严重级分布", dist_text, "严重/高/中/低/无", "warn" if dist.get("严重") else ""),
        ("综合覆盖率", _pct(summary["coverage"]), "加权 D1~D6（见覆盖矩阵）", "hl"),
        ("与上次快照", diff_hint, "新增 / 修复 / 回归", "warn" if summary.get("regressed") else ""),
    ]
    html_cards = "".join(
        f'<div class="card {cls}"><div class="label">{html.escape(label, quote=True)}</div>'
        f'<div class="value">{_e(value)}</div>'
        f'<div class="hint">{_e(hint)}</div></div>'
        for label, value, hint, cls in cards
    )
    return (
        '<section id="summary"><h2>概览 <span class="tag">Overview</span></h2>'
        f'<div class="cards">{html_cards}</div></section>'
    )


def _render_assets(ctx: dict) -> str:
    """表 1：资产与服务清单（端口/组件事实 + banner 证据截断）。"""
    rows: list[str] = []
    for item in ctx["facts"]:
        asset = ctx["assets"].get(str(item.get("asset_id") or "")) or {}
        ip = item.get("ip") or asset.get("ip") or "-"
        endpoint = f"{ip}" if not item.get("target") else f"{item.get('target')}"
        rows.append(
            "<tr>"
            + _cell(_e(item.get("asset_id")), "mono nowrap")
            + _cell(_e(endpoint), "mono")
            + _cell(_e(item.get("kind")), "nowrap")
            + _cell(_e(item.get("service")))
            + _cell(_e(item.get("version")), "mono")
            + _cell(_e(_trunc(item.get("banner"), 200)), "chain")
            + "</tr>"
        )
    return (
        '<section id="assets"><h2>表 1 · 资产与服务清单 '
        '<span class="tag">本次识别到的端口 / 组件（事实）</span></h2>'
        + _table(
            ["资产", "IP:端口 / 目标", "类型", "服务", "版本", "证据（banner，截断 200 字）"],
            rows,
        )
        + "</section>"
    )


def _render_issues(ctx: dict) -> str:
    """表 2：CVE/问题明细（含置信度、CVSS 来源、档案引用、证据链、修复建议）。"""
    rows: list[str] = []
    for item in ctx["issues"]:
        cvss = _num(item.get("cvss"))
        source = _plain(item.get("cvss_source"), "nvd")
        rows.append(
            "<tr>"
            + _cell(_sev_badge(item.get("severity")), "nowrap")
            + _cell(_e(item.get("check_id")), "mono nowrap")
            + _cell(_e(item.get("asset_id")), "mono nowrap")
            + _cell(_e(item.get("component")))
            + _cell(_e(item.get("detected")), "mono")
            + _cell(_e(item.get("hit")))
            + _cell(_e(item.get("rule")), "nowrap")
            + _cell(f"{cvss}<br><small>{_e(source)}</small>", "nowrap")
            + _cell(_e(item.get("vuln_ref") or "待建档"), "mono")
            + _cell(_e(item.get("fix")))
            + _cell(_e(item.get("chain")), "chain")
            + "</tr>"
        )
    return (
        '<section id="issues"><h2>表 2 · CVE / 问题明细 '
        '<span class="tag">cve · config · tls · web；证据链 banner→版本→CPE→区间→CVSS→档案</span></h2>'
        + _table(
            [
                "严重级", "CVE / 检查项", "资产", "组件", "检出/命中版本", "命中规则",
                "置信度", "CVSS（来源）", "档案", "修复建议", "证据链",
            ],
            rows,
        )
        + "</section>"
    )


def _diff_rows(items: list[dict], ctx: dict) -> list[str]:
    """四态段落内的行。"""
    rows: list[str] = []
    for item in items:
        asset = ctx["assets"].get(str(item.get("asset_id") or "")) or {}
        rows.append(
            "<tr>"
            + _cell(_e(asset.get("ip") or item.get("asset_id")), "mono nowrap")
            + _cell(_sev_badge(item.get("severity")), "nowrap")
            + _cell(_e(item.get("check_id")), "mono nowrap")
            + _cell(_e(item.get("title") or item.get("target")))
            + _cell(_e(item.get("prev_status")), "nowrap")
            + _cell(_e(item.get("cur_status")), "nowrap")
            + "</tr>"
        )
    return rows


def _render_diff(ctx: dict) -> str:
    """表 3：与上次快照的差异（新增 / 已修复 / 仍存在 / 回归四段）。"""
    diff = ctx["diff"]
    if not diff or diff.get("error"):
        reason = (diff or {}).get("error") or "未提供上一次快照"
        return (
            '<section id="diff"><h2>表 3 · 与上次快照的差异</h2>'
            f'<p class="empty">{_e(reason)}，本次无可对比的变化。</p></section>'
        )
    # 首次扫描/基线快照：没有"上一次"，把所有 finding 直接说明为首次发现，
    # 不硬造一个四态表（否则 runner 传回的 summary-only diff 会出现"新增 n 条但表为空"）。
    if not diff.get("prev"):
        total = len(ctx.get("facts") or []) + len(ctx.get("issues") or [])
        return (
            '<section id="diff"><h2>表 3 · 与上次快照的差异 '
            f'<span class="tag">基线快照 {_e(diff.get("cur"))}</span></h2>'
            f'<p class="note">首次运行（基线快照）：本次共 {total} 条 finding，'
            "全部按首次发现处理，无上一次快照可对比。</p></section>"
        )
    buckets: dict[str, list[dict]] = {"regressed": [], "new": [], "persisting": [], "fixed": []}
    for item in diff.get("items") or []:
        delta = str(item.get("delta") or "")
        if delta in buckets:
            buckets[delta].append(item)
    blocks: list[str] = []
    for delta in ("regressed", "new", "persisting", "fixed"):
        items = buckets[delta]
        label = diff_mod.DELTA_LABELS.get(delta, delta)
        blocks.append(
            f'<div class="diff-block"><h3>{html.escape(label, quote=True)}'
            f' <span class="n">{len(items)} 条</span></h3>'
            + _table(
                ["资产", "严重级", "CVE / 检查项", "标题", "上次状态", "本次状态"],
                _diff_rows(items, ctx),
            )
            + "</div>"
        )
    stats = diff.get("stats") or {}
    return (
        '<section id="diff"><h2>表 3 · 与上次快照的差异 '
        f'<span class="tag">{_e(diff.get("prev"))} → {_e(diff.get("cur"))}</span></h2>'
        f'<div class="legend">新增 {int(stats.get("new") or 0)} ｜ 已修复 '
        f'{int(stats.get("fixed") or 0)} ｜ 仍存在 {int(stats.get("persisting") or 0)} ｜ 回归 '
        f'{int(stats.get("regressed") or 0)} ｜ 合计 {int(stats.get("total") or 0)}</div>'
        f'<div class="diff-grid">{"".join(blocks)}</div></section>'
    )


def _render_coverage(ctx: dict) -> str:
    """表 4：覆盖率矩阵 + 未覆盖清单。"""
    coverage = ctx["coverage"]
    if not coverage:
        return (
            '<section id="coverage"><h2>表 4 · 覆盖率</h2>'
            '<p class="empty">覆盖率数据不可用。</p></section>'
        )
    error = coverage.get("error")
    domains = list(coverage_mod.DOMAINS)
    by_domain = coverage.get("by_domain") or {}
    headers = ["资产", "IP", "角色"] + [
        f"{code} {coverage_mod.DOMAIN_NAMES.get(code, code)}（{_num((by_domain.get(code) or {}).get('weight'), 2)}）"
        for code in domains
    ] + ["加权得分"]
    rows: list[str] = []
    for item in coverage.get("matrix") or []:
        cell_domains = item.get("domains") or {}
        cells = "".join(
            _cell(
                _cov_cell(float(cell_domains[code]))
                if code in cell_domains else _cov_na()
            )
            for code in domains
        )
        rows.append(
            "<tr>"
            + _cell(_e(item.get("asset_id")), "mono nowrap")
            + _cell(_e(item.get("ip")), "mono")
            + _cell(_e(item.get("role")), "nowrap")
            + cells
            + _cell(_cov_cell(float(item.get("score") or 0.0)), "nowrap")
            + "</tr>"
        )
    summary_line = (
        f'综合覆盖率 <b>{_pct(coverage.get("coverage"))}</b>'
        f'（{len(coverage.get("matrix") or [])} 台资产 × 适用检查域加权）'
    )
    if error:
        summary_line += f' ｜ <span class="empty">{_e(error)}</span>'

    uncovered_rows: list[str] = []
    for item in coverage.get("uncovered") or []:
        uncovered_rows.append(
            "<tr>"
            + _cell(_e(item.get("asset_id")), "mono nowrap")
            + _cell(_e(item.get("ip")), "mono")
            + _cell(_e(item.get("domain")), "nowrap")
            + _cell(_e(item.get("name")))
            + _cell(_e(item.get("status")), "nowrap")
            + _cell(_e(item.get("reason")))
            + "</tr>"
        )
    return (
        '<section id="coverage"><h2>表 4 · 覆盖率矩阵与未覆盖清单 '
        '<span class="tag">1.0=done · 0.5=partial · 0=skipped/error/未执行 · —=该角色不适用</span></h2>'
        f'<p class="cover-note">{summary_line}</p>'
        + _table(headers, rows)
        + '<h3>未覆盖清单（逐条给原因，主动暴露盲区）</h3>'
        + _table(["资产", "IP", "域", "检查域", "状态", "原因"], uncovered_rows)
        + "</section>"
    )


def _render_engines(ctx: dict) -> str:
    """表 5：引擎贡献（stats_json.engines 有则展示，缺失则整节省略）。"""
    engines = ctx.get("engines") or []
    if not engines:
        return ""
    rows: list[str] = []
    for item in engines:
        cost = item.get("cost_ms")
        cost_text = f"{int(cost) / 1000:.1f} s" if isinstance(cost, (int, float)) else "-"
        findings = item.get("findings")
        rows.append(
            "<tr>"
            + _cell(_e(item.get("engine")), "mono nowrap")
            + _cell(_e(item.get("version")))
            + _cell(_e(item.get("status")), "nowrap")
            + _cell(_e(findings if findings is not None else "-"), "nowrap")
            + _cell(_e(cost_text), "nowrap")
            + "</tr>"
        )
    return (
        '<section id="engines"><h2>表 5 · 引擎贡献 '
        '<span class="tag">复用引擎、自研编排：每个引擎跑了没有 / 花了多久 / 出了多少结论</span></h2>'
        + _table(["引擎", "版本", "状态", "发现数", "耗时"], rows)
        + "</section>"
    )


def _render_footer(ctx: dict) -> str:
    """页脚：命令与规则版本、生成时间、免责声明。"""
    return (
        "<footer>"
        f"<div><b>生成命令</b>：<span class=\"mono\">{_e(ctx.get('command'))}</span></div>"
        f"<div><b>规则 / 匹配版本</b>：{_e(ctx.get('rules_version'))} ｜ "
        f"<b>Profile</b>：{_e(ctx.get('profile'))}</div>"
        f"<div><b>生成时间</b>：{_e(ctx.get('generated_at'))}（UTC）</div>"
        f"<div><b>免责声明</b>：{html.escape(DISCLAIMER, quote=True)}</div>"
        "</footer>"
    )


def render_html(
    store: Any,
    cfg: dict,
    snapshot_id: str,
    diff: dict | None = None,
    coverage: dict | None = None,
) -> str:
    """渲染自包含 HTML 报告（单文件、内联 CSS、离线可开、打印友好）。

    ``diff`` / ``coverage`` 为空时自动计算：diff 自动找同一计划的上一次快照，
    coverage 走 :func:`hornwork.scan.coverage.compute`。
    """
    ctx = _report_context(store, cfg, snapshot_id, diff, coverage)
    title = f"Hornwork · 漏洞扫描报告（{snapshot_id or '未知快照'}）"
    body = "".join(
        [
            _render_header(ctx),
            _render_summary(ctx),
            _render_assets(ctx),
            _render_issues(ctx),
            _render_diff(ctx),
            _render_coverage(ctx),
            _render_engines(ctx),
            _render_footer(ctx),
        ]
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title, quote=True)}</title>"
        f"<style>{_CSS}</style></head>"
        f'<body><div class="wrap">{body}</div></body></html>\n'
    )


def render_json(
    store: Any,
    cfg: dict,
    snapshot_id: str,
    diff: dict | None = None,
    coverage: dict | None = None,
) -> dict:
    """渲染与 HTML 同源的 JSON 报告（供 CLI/接口二次加工，字段全部可 JSON 序列化）。"""
    ctx = _report_context(store, cfg, snapshot_id, diff, coverage)
    snapshot = ctx["snapshot"]
    plan = ctx["plan"]

    facts = [
        {
            "asset_id": item.get("asset_id"),
            "ip": item.get("ip"),
            "kind": item.get("kind"),
            "target": item.get("target"),
            "service": item.get("service"),
            "version": item.get("version"),
            "banner": _trunc(item.get("banner"), 200),
        }
        for item in ctx["facts"]
    ]
    issues = [
        {
            "asset_id": item.get("asset_id"),
            "ip": item.get("ip"),
            "kind": item.get("kind"),
            "check_id": item.get("check_id"),
            "title": item.get("title"),
            "component": item.get("component"),
            "detected": item.get("detected"),
            "hit": item.get("hit"),
            "confidence": item.get("confidence"),
            "rule": item.get("rule"),
            "cvss": item.get("cvss"),
            "cvss_source": item.get("cvss_source"),
            "severity": item.get("severity"),
            "status": item.get("status"),
            "vuln_ref": item.get("vuln_ref"),
            "fix": item.get("fix"),
            "chain": item.get("chain"),
        }
        for item in ctx["issues"]
    ]
    engines = [
        {
            "engine": item.get("engine"),
            "version": item.get("version"),
            "status": item.get("status"),
            "findings": item.get("findings"),
            "cost_ms": item.get("cost_ms"),
        }
        for item in ctx.get("engines") or []
    ]
    report = {
        "report": "hornwork-scan",
        "module": "扫描模块 漏洞扫描",
        "snapshot": {
            "snapshot_id": ctx["snapshot_id"],
            "ts": snapshot.get("ts"),
            "kind": snapshot.get("kind"),
            "label": snapshot.get("label"),
            "is_base": bool(snapshot.get("is_base")),
            "plan_id": snapshot.get("plan_id"),
            "run_id": snapshot.get("run_id"),
            "plan_name": plan.get("name"),
            "plan_kind": plan.get("kind"),
            "profile": ctx["profile"],
        },
        "summary": dict(ctx["summary"]),
        "assets": facts,
        "issues": issues,
        "diff": ctx["diff"] or {},
        "coverage": ctx["coverage"] or {},
        "engines": engines,
        "generated_at": ctx["generated_at"],
        "rules_version": ctx["rules_version"],
        "command": ctx["command"],
        "disclaimer": DISCLAIMER,
    }
    return report


# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------
def _report_dir(cfg: dict) -> Path:
    """报告目录：``scan.report_dir``（契约默认 ``/opt/hornwork/reports/scan``）。"""
    value = str(cfg_get(cfg, "scan.report_dir", "") or "").strip()
    return Path(value).expanduser() if value else Path("/opt/hornwork/reports/scan")


def _safe_name(value: Any) -> str:
    """文件名安全化（快照号本身是安全字符，防止外部传入奇怪值）。"""
    return re.sub(r"[^0-9A-Za-z_.-]+", "_", str(value or "unknown")) or "unknown"


def _default_path(cfg: dict, snapshot_id: str, fmt: str) -> Path:
    """默认输出路径：``<report_dir>/scan-<snapshot_id>.<fmt>``（与 runner/CLI 约定一致）。"""
    return _report_dir(cfg) / f"scan-{_safe_name(snapshot_id)}.{fmt}"


def _resolve_target(cfg: dict, snapshot_id: str, fmt: str, out: str | None) -> Path:
    """解析输出路径：``out`` 为空用默认路径；``out`` 指向目录时自动补文件名。"""
    if not out:
        return _default_path(cfg, snapshot_id, fmt)
    target = Path(str(out)).expanduser()
    if target.is_dir() or str(out).endswith(("/", "\\")):
        return target / f"scan-{_safe_name(snapshot_id)}.{fmt}"
    return target


def export(
    store: Any,
    cfg: dict,
    snapshot_id: str,
    fmt: str = "html",
    out: str | None = None,
    diff: dict | None = None,
    coverage: dict | None = None,
) -> dict:
    """导出报告到文件，返回 ``{"ok","path","bytes","snapshot_id","format"}``。

    写文件失败返回 ``ok=False`` + ``error``（不抛异常）；未知格式回退 HTML。
    ``diff`` / ``coverage`` 由调用方（runner/CLI）传入时直接复用，避免重复计算。
    """
    normalized = str(fmt or "html").strip().lower()
    if normalized not in ("html", "json"):
        log.warn("scan.report.unknown_format", fmt=str(fmt), fallback="html")
        normalized = "html"
    result: dict[str, Any] = {
        "ok": False,
        "path": "",
        "bytes": 0,
        "snapshot_id": str(snapshot_id or ""),
        "format": normalized,
    }
    try:
        if normalized == "json":
            payload = render_json(store, cfg, snapshot_id, diff=diff, coverage=coverage)
            content = json.dumps(payload, ensure_ascii=False, indent=2, default=str, allow_nan=False)
        else:
            content = render_html(store, cfg, snapshot_id, diff=diff, coverage=coverage)
        target = _resolve_target(cfg, snapshot_id, normalized, out)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        size = len(content.encode("utf-8"))
        result.update({"ok": True, "path": str(target), "bytes": size})
        log.info(
            "scan.report.exported",
            snapshot=str(snapshot_id),
            fmt=normalized,
            path=str(target),
            bytes=size,
        )
    except Exception as exc:  # noqa: BLE001 - 磁盘/序列化问题不能把上层打崩
        log.warn("scan.report.export_failed", snapshot=str(snapshot_id), error=str(exc))
        result["error"] = str(exc)
    return result

