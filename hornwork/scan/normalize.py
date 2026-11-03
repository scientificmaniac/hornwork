"""结果归一：RawResult → scan_finding（事实/问题）+ 去重 + 生命周期 + checkpoint。

核心约定：
- ``kind='port'`` / ``kind='component'`` 是**事实**（端口开着、装了哪个版本），状态固定
  ``observed``，参与 CVE 匹配但不计入"有效漏洞"；
- ``kind ∈ {cve, config, tls, web}`` 是**问题**，进入 ``new/observed/confirmed/...`` 生命周期；
- 去重键 ``finding_key = sha256(asset_id|kind|check_id|target)[:32]``，与来源引擎无关；
  ``UNIQUE(asset_id, finding_key)`` 让重复扫描只更新 ``last_seen``，不新增行；
- 生命周期：``new`` → ``confirmed``（人工/PoC）→ ``fixed``（连续 2 次快照未现）→ ``reopened``；
  引擎超时/目标不可达**不得**误判为已修复。
"""

from __future__ import annotations

from typing import Any

from ..log import get_logger
from . import store as sstore

log = get_logger("scan.normalize")

#: 检查域 → 引擎映射
DOMAIN_ENGINES: dict[str, tuple[str, ...]] = {
    "D1": ("nmap",),
    "D2": ("pkgs",),
    "D3": ("nmap", "cve"),
    "D4": ("lynis",),
    "D5": ("testssl",),
    "D6": ("nuclei",),
}

#: 域名称（报告/覆盖率展示）
DOMAIN_NAMES = {
    "D1": "端口与服务",
    "D2": "系统补丁 CVE",
    "D3": "应用组件 CVE",
    "D4": "主机配置基线",
    "D5": "TLS 配置",
    "D6": "Web/应用 PoC",
}

#: 资产角色 → 适用域（coverage 的默认口径；可被 config scan.coverage.role_domains 覆盖）
ROLE_DOMAINS: dict[str, tuple[str, ...]] = {
    "self": ("D1", "D2", "D3", "D4", "D5", "D6"),
    "server": ("D1", "D2", "D3", "D4", "D5", "D6"),
    "linux": ("D1", "D2", "D3", "D4", "D5", "D6"),
    "web": ("D1", "D3", "D5", "D6"),
    "lab": ("D1", "D3", "D6"),
    "workstation": ("D1", "D3", "D5"),
    "windows": ("D1", "D3", "D5"),
    "network": ("D1",),
}

FACT_KINDS = ("port", "component")


def _severity_order(severity: str | None) -> int:
    return {"严重": 0, "高": 1, "中": 2, "低": 3, "无": 4}.get(str(severity or ""), 5)


def _status_for_fact(existing: dict | None) -> str:
    """事实类 finding 的状态：固定 observed（不参与"有效漏洞"统计）。"""
    if existing and existing.get("status") == "false_positive":
        return "false_positive"
    return "observed"


def _status_for_issue(existing: dict | None, confidence: str | None, vuln_ref: str | None) -> str:
    """问题类 finding 的生命周期初值。

    - 已存在：fixed → reopened；false_positive 保持（人工判定优先）；其它保持原状态；
    - 首次出现：``cpe_only`` → observed（低置信不告警）；``tool`` → confirmed（PoC 证据）；
      ``exact/range`` → new（自动入 finding）；
    """
    if existing:
        current = str(existing.get("status") or "new")
        if current == "fixed":
            return "reopened"
        return current
    if confidence == "cpe_only":
        return "observed"
    if confidence == "tool":
        return "confirmed"
    return "new"


def normalize_results(
    store: Any,
    *,
    asset: dict,
    task_id: str,
    snapshot_id: str | None = None,
) -> list[dict]:
    """占位：真实归一由 :func:`build_findings` 完成（保留给 runner 的统一入口）。"""
    raise NotImplementedError("use build_findings(...)")


def build_findings(
    store: Any,
    raw_results: list[dict],
    *,
    asset: dict,
    task_id: str,
    snapshot_id: str | None = None,
    engine_status: dict[str, dict] | None = None,
) -> dict:
    """把引擎输出归一为 finding 并写库。

    返回 ``{"findings":[...], "facts":[...], "problems":[...],
             "seen_keys":{...}, "counts":{...}, "host_summary":{...}}``；
    调用方随后用 :func:`finalize_missing` 处理"未复现"的既有 finding。
    """
    asset_id = str(asset.get("asset_id"))
    seen_keys: set[str] = set()
    findings: list[dict] = []
    facts: list[dict] = []
    problems: list[dict] = []
    host_summary: dict[str, Any] = {}
    errors: list[str] = []

    for raw in raw_results or []:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind") or "component")
        if kind == "host_summary":
            host_summary.update(raw.get("evidence") or {})
            continue
        if kind not in ("port", "component", "cve", "config", "tls", "web"):
            errors.append(f"未知 kind：{kind}")
            continue
        check_id = str(raw.get("check_id") or "").strip()
        if not check_id:
            errors.append("缺少 check_id")
            continue
        target = raw.get("target")
        key = sstore.finding_key(asset_id, kind, check_id, target)
        existing = sstore.get_finding_by_key(store, asset_id, key)
        if kind in FACT_KINDS:
            status = _status_for_fact(existing)
        else:
            status = _status_for_issue(existing, raw.get("confidence"), raw.get("vuln_ref"))
        record = {
            "finding_key": key,
            "task_id": task_id,
            "asset_id": asset_id,
            "snapshot_id": snapshot_id,
            "kind": kind,
            "check_id": check_id,
            "title": raw.get("title") or check_id,
            "severity": raw.get("severity"),
            "cvss": raw.get("cvss"),
            "cvss_source": raw.get("cvss_source"),
            "confidence": raw.get("confidence"),
            "status": status,
            "target": target,
            "evidence_json": raw.get("evidence") or {},
            "vuln_ref": raw.get("vuln_ref"),
        }
        saved = sstore.upsert_finding(store, record)
        saved["_raw"] = raw
        findings.append(saved)
        seen_keys.add(key)
        (facts if kind in FACT_KINDS else problems).append(saved)

    counts = {
        "findings": len(findings),
        "facts": len(facts),
        "problems": len(problems),
        "by_kind": _count_by(findings, "kind"),
        "by_severity": _count_by(problems, "severity"),
    }
    if errors:
        log.warn("scan.normalize.errors", asset_id=asset_id, errors=errors[:5])
    return {
        "findings": findings,
        "facts": facts,
        "problems": problems,
        "seen_keys": seen_keys,
        "counts": counts,
        "host_summary": host_summary,
        "errors": errors,
    }


def _count_by(rows: list[dict], field: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field) or "未知")
        out[value] = out.get(value, 0) + 1
    return out


def cve_to_findings(matched: list[dict], *, asset_id: str, task_id: str,
                    snapshot_id: str | None = None) -> list[dict]:
    """把 matcher 输出转成 ``kind='cve'`` 的 RawResult（交给 :func:`build_findings` 统一入库）。"""
    out: list[dict] = []
    for item in matched or []:
        evidence = dict(item.get("evidence") or {})
        evidence.update({
            "detected_version": item.get("detected_version"),
            "matched_version": item.get("matched_version") or item.get("detected_version"),
            "cpe23": item.get("cpe23"),
            "interval": evidence.get("interval"),
            "reason": evidence.get("reason"),
            "cvss_source": item.get("cvss_source"),
            "archive_id": item.get("vuln_ref"),
            "source": item.get("source") or "nvd",
        })
        out.append({
            "engine": "matcher",
            "kind": "cve",
            "check_id": str(item.get("cve_id")),
            "target": f"{asset_id}:{item.get('comp_norm')}",
            "title": item.get("title") or f"{item.get('cve_id')} {item.get('comp_norm')}",
            "severity": item.get("severity"),
            "cvss": item.get("cvss"),
            "cvss_source": item.get("cvss_source") or "nvd",
            "confidence": item.get("confidence"),
            "vuln_ref": item.get("vuln_ref"),
            "evidence": evidence,
            "comp_norm": item.get("comp_norm"),
            "version": item.get("detected_version"),
        })
    return out


def finalize_missing(
    store: Any,
    *,
    asset_id: str,
    seen_keys: set[str],
    snapshot_id: str | None = None,
    keep_statuses: tuple[str, ...] = ("new", "observed", "confirmed", "reopened"),
) -> dict:
    """处理本次未复现的既有 finding：miss_count+1，连续 2 次未现 → fixed。

    注意：引擎失败/超时（partial）时**不应**调用本函数，否则会把"没扫到"误判成"已修复"。
    """
    from .. import schema

    missing = sstore.missing_findings(store, asset_id, seen_keys)
    fixed: list[dict] = []
    still: list[dict] = []
    now = schema.utc_now()
    for finding in missing:
        current = str(finding.get("status") or "new")
        if current not in keep_statuses:
            continue
        miss = int(finding.get("miss_count") or 0) + 1
        if miss >= 2:
            evidence = dict(finding.get("evidence_json") or {})
            evidence["_lifecycle"] = {"fixed_at": now, "miss_count": miss,
                                      "snapshot_id": snapshot_id}
            store.execute(
                "UPDATE scan_finding SET status='fixed', miss_count=?, evidence_json=?,"
                " updated_at=? WHERE finding_id=?",
                (miss, sstore.dumps(evidence), now, finding["finding_id"]),
            )
            fixed.append({"finding_id": finding["finding_id"],
                          "check_id": finding.get("check_id"), "kind": finding.get("kind")})
        else:
            store.execute(
                "UPDATE scan_finding SET miss_count=?, updated_at=? WHERE finding_id=?",
                (miss, now, finding["finding_id"]),
            )
            still.append({"finding_id": finding["finding_id"], "miss_count": miss})
    return {"fixed": fixed, "missing": still, "checked": len(missing)}


def build_checkpoint(
    *,
    engine_status: dict[str, dict],
    problems: list[dict],
    task_id: str,
    asset_id: str,
    cve_cache_ready: bool = True,
) -> dict:
    """构造任务 checkpoint：引擎结果 + 检查域状态（覆盖率的数据源）。"""
    engines = dict(engine_status or {})
    domains: dict[str, dict] = {}
    for domain, engine_names in DOMAIN_ENGINES.items():
        states = [engines.get(name) or {"status": "not_run"} for name in engine_names]
        available = [s for s in states if s.get("status") not in ("not_run", "not_selected")]
        if not available:
            domains[domain] = {"status": "skipped", "engines": [],
                               "reason": "引擎未运行（计划未选择或不可用）"}
            continue
        if any(s.get("status") in ("error", "timeout") for s in available):
            status = "error"
            reason = "; ".join(
                f"{name}:{(engines.get(name) or {}).get('error') or 'error'}"
                for name in engine_names if (engines.get(name) or {}).get("status") in ("error", "timeout")
            )
        elif any(s.get("status") == "skipped" for s in available):
            status = "partial"
            reason = "部分引擎不可用/不适用"
        else:
            status = "done"
            reason = None
        if domain == "D3" and status == "done" and not cve_cache_ready:
            status, reason = "partial", "cve_cache_empty（未导入 CVE 数据，只能出事实不能出漏洞）"
        domains[domain] = {"status": status, "engines": [
            name for name in engine_names if (engines.get(name) or {}).get("status") not in (None, "not_selected")
        ], "reason": reason}
    return {
        "done_assets": [asset_id],
        "task_id": task_id,
        "engines": engines,
        "domains": domains,
        "counts": {
            "problems": len(problems),
            "by_severity": _count_by(problems, "severity"),
        },
    }


def finding_sort_key(finding: dict) -> tuple:
    """问题排序：严重级 → CVSS → 最近时间。"""
    return (
        _severity_order(finding.get("severity")),
        -float(finding.get("cvss") or 0.0),
        str(finding.get("last_seen") or ""),
    )


def build_snapshot_items(findings: list[dict]) -> list[dict]:
    """把本次任务的 finding 冻结为快照项（diff 的唯一数据源）。"""
    items: list[dict] = []
    for finding in findings:
        items.append({
            "asset_id": finding.get("asset_id"),
            "finding_key": finding.get("finding_key"),
            "kind": finding.get("kind"),
            "check_id": finding.get("check_id"),
            "severity": finding.get("severity"),
            "status": finding.get("status"),
            "cvss": finding.get("cvss"),
        })
    return items
