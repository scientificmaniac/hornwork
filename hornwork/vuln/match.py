"""IF-18：组件 + 版本 → 漏洞档案匹配（供扫描模块扫描进程内调用）。

入参 ``{"component","version","distro"?,"cpe"?,"trace_id"?}``；
出参 ``{"matched":[...], "unknown":[...], "elapsed_ms":int}``，元素字段见。

三个设计约束：
1. 只回答"是否落入受影响版本区间"，不回答"是否可利用"——把版本命中当漏洞存在是漏扫
   误报的主要来源，可利用性交给扫描模块 PoC / 靶场模块复现结论。
2. 组件名归一化 token 包含匹配，覆盖 ``grafana`` vs ``Grafana 8.2.6``、
   ``spring-cloud-gateway`` vs ``Spring Cloud Gateway 3.1.0``、``redis`` vs
   ``Redis（Debian/Ubuntu 打包版）``；匹配不到返回 ``unknown`` + reason，绝不抛异常。
3. 单条档案/版本失败都被隔离，unknown 里给 reason 码，扫描模块可统计放弃匹配的比例。
"""

from __future__ import annotations

import re
import time
from typing import Any

from ..log import get_logger
from . import cvss, version
from .store import list_records

log = get_logger("vuln.match")

#: 组件名 token 忽略的通用词（纯数字 token 另行过滤）
_STOPWORDS = frozenset({"v", "ver", "version", "release", "app", "the", "and", "of"})
_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)

#: unknown 条目的原因码
REASON_BAD_REQUEST = "bad_request"
REASON_COMPONENT_NOT_MATCHED = "component_not_matched"
REASON_VERSION_MISSING = "version_missing"
REASON_STORE_UNAVAILABLE = "store_unavailable"
REASON_RECORD_INVALID = "record_invalid"

#: 单次匹配最多载入的档案数（防误配超大库拖慢扫描）
_MAX_RECORDS = 10000


def normalize_tokens(text: Any) -> set[str]:
    """组件名/CPE 片段 → 小写 token 集合（去纯数字与通用词）。

    ``Grafana 8.2.6`` → ``{"grafana"}``；``Spring Cloud Gateway 3.1.0`` →
    ``{"spring","cloud","gateway"}``；``Redis（Debian/Ubuntu 打包版）`` →
    ``{"redis","debian","ubuntu","打包版"}``。
    """
    raw = _TOKEN_RE.findall(str(text or "").lower())
    return {token for token in raw if not token.isdigit() and token not in _STOPWORDS}


def component_matches(
    request_component: str, record_component: str, extra_tokens: set[str] | None = None
) -> bool:
    """请求组件名与档案组件名是否指同一组件（双向 token 包含 + 长公共 token 兜底）。"""
    wanted = normalize_tokens(request_component) | set(extra_tokens or set())
    recorded = normalize_tokens(record_component)
    if not wanted or not recorded:
        return False
    if wanted <= recorded or recorded <= wanted:
        return True
    return any(len(token) >= 4 for token in wanted & recorded)


def _cpe_fields(cpe: str | None) -> tuple[str, str]:
    """拆 CPE 2.3 串，返回 ``(product, version)``；非法返回空串。"""
    if not cpe:
        return "", ""
    parts = str(cpe).split(":")
    product = parts[4].replace("_", " ") if len(parts) > 4 else ""
    version = parts[5] if len(parts) > 5 else ""
    return ("" if product in ("*", "-") else product, "" if version in ("*", "-") else version)


def _base_entry(record: dict | None) -> dict:
    """IF-18 出参公共骨架（命中与未命中的字段一致，便于扫描模块统一处理）。"""
    record = record or {}
    fix = record.get("fix") if isinstance(record.get("fix"), dict) else {}
    severity = record.get("severity")
    if not (isinstance(severity, str) and severity.strip()):
        try:
            severity = cvss.severity(float(record.get("cvss_score") or 0.0))
        except (TypeError, ValueError):
            severity = "无"
    return {
        "vuln_id": record.get("id"),
        "cve": record.get("cve"),
        "matched": False,
        "matched_rule": None,
        "fixed_version": str(fix.get("patch_version") or "") or None,
        "cvss_score": float(record.get("cvss_score") or 0.0),
        "severity": severity,
        "confidence": "unknown",
        "reason": None,
    }


def _make_unknown(detail: str, reason: str, record: dict | None = None) -> dict:
    entry = _base_entry(record)
    entry.update({"confidence": "unknown", "reason": reason, "detail": detail})
    return entry


def _evaluate(record: dict, component: str, version_text: str, distro: str | None) -> dict:
    """单条档案的版本区间匹配，返回 IF-18 条目。"""
    if not version_text:
        return _make_unknown(
            f"请求未提供版本号，无法判定组件 {component!r} 是否受影响", REASON_VERSION_MISSING, record
        )
    rules = record.get("affected_versions")
    if not isinstance(rules, list) or not rules:
        return _make_unknown("档案缺少 affected_versions，无法判定", version.REASON_NO_RULES, record)
    resolved = [version.apply_distro(rule, distro) for rule in rules if isinstance(rule, dict)]
    result = version.match_ranges(version_text, resolved)
    entry = _base_entry(record)
    entry["confidence"] = result["confidence"]
    if result["matched"]:
        entry.update(
            {
                "matched": True,
                "matched_rule": result["matched_rule"],
                "fixed_version": version.fixed_of(result["matched_rule"]) or entry["fixed_version"],
            }
        )
        return entry
    entry.update(
        {
            "reason": result["reason"],
            "detail": f"版本 {version_text!r} 未落入受影响区间（reason={result['reason']}）",
        }
    )
    return entry


def match(store: Any, cfg: dict, request: dict) -> dict:
    """IF-18 主入口：版本 → 档案匹配（入参非法/无组件/存储不可用都返回 unknown，不抛异常）。"""
    started = time.perf_counter()
    req = request if isinstance(request, dict) else {}
    component = str(req.get("component") or "").strip()
    version_text = str(req.get("version") or "").strip()
    distro = str(req.get("distro") or "").strip() or None
    cpe = str(req.get("cpe") or "").strip() or None
    trace_id = req.get("trace_id")
    cpe_product, cpe_version = _cpe_fields(cpe)
    component = component or cpe_product
    version_text = version_text or cpe_version

    matched: list[dict] = []
    unknown: list[dict] = []
    if not component:
        unknown.append(_make_unknown("请求缺少 component（且无可用 cpe），无法匹配", REASON_BAD_REQUEST))
        return {"matched": matched, "unknown": unknown, "elapsed_ms": _elapsed_ms(started)}
    try:
        records = list_records(store, limit=_MAX_RECORDS)
    except Exception as exc:  # 存储不可用不得阻塞扫描模块扫描
        log.warn("vuln.match.store_unavailable", error=str(exc), trace_id=trace_id)
        unknown.append(_make_unknown(f"档案库不可用: {exc}", REASON_STORE_UNAVAILABLE))
        return {"matched": matched, "unknown": unknown, "elapsed_ms": _elapsed_ms(started)}

    component_hits = 0
    for record in records:
        try:
            if not component_matches(component, str(record.get("component") or "")):
                continue
            component_hits += 1
            entry = _evaluate(record, component, version_text, distro)
            (matched if entry["matched"] else unknown).append(entry)
        except Exception as exc:  # 单条档案异常隔离
            component_hits += 1
            unknown.append(_make_unknown(f"档案处理失败: {exc}", REASON_RECORD_INVALID, record))
            log.warn("vuln.match.record_invalid", vuln_id=record.get("id"), error=str(exc))
    if component_hits == 0:
        unknown.append(
            _make_unknown(
                f"档案库中没有与组件 {component!r} 对应的漏洞记录", REASON_COMPONENT_NOT_MATCHED
            )
        )

    matched.sort(key=lambda item: (-float(item.get("cvss_score") or 0.0), str(item.get("vuln_id"))))
    unknown.sort(key=lambda item: str(item.get("vuln_id") or "~"))
    elapsed = _elapsed_ms(started)
    log.info(
        "vuln.match.done", component=component, version=version_text, distro=distro,
        matched=len(matched), unknown=len(unknown), elapsed_ms=elapsed, trace_id=trace_id,
    )
    return {"matched": matched, "unknown": unknown, "elapsed_ms": elapsed}


def match_many(store: Any, cfg: dict, requests: list[dict]) -> list[dict]:
    """批量匹配（扫描检测模块次扫多个资产）：逐条隔离，不因一条失败中断。"""
    return [match(store, cfg, request) for request in requests or []]


def _elapsed_ms(started: float) -> int:
    return max(0, int(round((time.perf_counter() - started) * 1000)))
