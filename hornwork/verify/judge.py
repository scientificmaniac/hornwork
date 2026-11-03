"""用例判定：按时间窗从数据库里查告警，把观测结果与期望值比对出 TP/TN/FP/FN。

判定口径：
- expected="alert_present"：窗口内出现相关告警 → TP，否则 FN；
- expected="no_alert"     ：窗口内出现相关告警 → FP，否则 TN；
- 期望值非法 / 时间不可解析 / 查询异常 → inconclusive（不计入 TPR/FPR）。

"相关告警"的过滤口径：
1. 用例给出 rule_ids 时先按 rule_id 收窄——**任一 rule_id 命中即算相关**（`rule_id IN (...)`
   的 OR 语义，例如 TC-07 的 ["N-0103","N-0106"] 命中任一即 TP）；
2. technique 用 Python 侧双口径过滤（告警表 technique 字段 + rule.mitre / mitre.techniques），
   支持父子技术号互认（T1055 ↔ T1055.008）；
3. 规则 ID 可能随规则库版本调整，rule_ids 查不到时按 technique 兜底召回（只服务"应告警"用例，
   避免误报 FN；阴性用例不带 technique，不会被兜底影响）。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..log import get_logger

log = get_logger("verify.judge")

# 报告里只保留告警摘要，避免把完整 payload（可能含大段 evidence）塞进 JSON/Markdown 报告
_ALERT_LIMIT = 50


def _iso(dt: datetime) -> str:
    """datetime → 统一 UTC ISO 口径（毫秒 + Z）。"""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_ts(ts: Any) -> datetime:
    """把 ISO8601/ datetime 解析成带时区的 UTC datetime；失败抛 ValueError。"""
    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    text = str(ts or "").strip()
    if not text:
        raise ValueError("empty timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text.replace(" ", "T"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _mttd_sec(t0_dt: datetime, first_ts: Any) -> int | None:
    """首个命中告警相对 t0 的秒数（四舍五入取整，负数按 0 处理）。"""
    try:
        delta = (_parse_ts(first_ts) - t0_dt).total_seconds()
    except (TypeError, ValueError):
        return None
    return max(0, int(round(delta)))


def _techniques_of(alert: dict) -> list[str]:
    """收集一条告警里出现的全部 ATT&CK 技术编号（去重保序）。"""
    found: list[str] = []
    if alert.get("technique"):
        found.append(str(alert["technique"]))
    mitre = alert.get("mitre") or {}
    if isinstance(mitre, dict):
        for item in mitre.get("techniques") or []:
            found.append(str(item))
    rule = alert.get("rule") or {}
    for item in rule.get("mitre") or []:
        found.append(str(item))
    out: list[str] = []
    for item in found:
        if item and item not in out:
            out.append(item)
    return out


def _matches_technique(alert: dict, technique: str | None) -> bool:
    """技术号匹配：精确相等，或父子技术互认（T1055 ↔ T1055.008）。

    采集/规则侧可能只打父技术号（如 memscan 告警用 T1055），用例用子技术号（T1055.008），
    父子互认避免因此误判漏报。
    """
    if not technique:
        return True
    for item in _techniques_of(alert):
        if item == technique:
            return True
        if item.startswith(technique + ".") or technique.startswith(item + "."):
            return True
    return False


def _summarize(alert: dict) -> dict:
    """告警摘要（报告/接口展示用，字段稳定）。"""
    rule = alert.get("rule") or {}
    return {
        "alert_id": alert.get("alert_id"),
        "ts": alert.get("ts"),
        "rule_id": rule.get("id") or alert.get("rule_id"),
        "rule_name": rule.get("name"),
        "engine": rule.get("engine"),
        "level": alert.get("level"),
        "technique": alert.get("technique"),
    }


def _collect_alerts(
    store,
    t0: str,
    t1: str,
    rule_ids: list[str],
    technique: str | None,
) -> list[dict]:
    """在 [t0, t1] 内收集与用例相关的告警，按时间升序返回。

    先按规则线索收窄；技术号在 Python 侧过滤（支持父子技术互认），
    规则线索过期时再按技术口径兜底召回。
    """
    if rule_ids:
        alerts = store.alerts_in_window(t0, t1, rule_ids=rule_ids)
    else:
        alerts = store.alerts_in_window(t0, t1)
    if technique:
        alerts = [a for a in alerts if _matches_technique(a, technique)]
    if not alerts and technique and rule_ids:
        # 规则 ID 变更/规则库未加载时按技术口径兜底，保证"应告警"用例不因线索过期误判 FN
        fallback = store.alerts_in_window(t0, t1)
        seen = {str(a.get("alert_id")) for a in alerts}
        alerts.extend(
            a for a in fallback
            if str(a.get("alert_id")) not in seen and _matches_technique(a, technique)
        )
    alerts.sort(key=lambda a: str(a.get("ts") or ""))
    return alerts


def judge_case(store, case: dict, t0: str, window_sec: int) -> dict:
    """判定单个用例。

    返回（契约第 6 节）：
    {"case_id","expected","observed","verdict","mttd_sec","alerts"}
    其中 verdict ∈ TP/TN/FP/FN/inconclusive，observed ∈ alert_present/no_alert/unknown。
    """
    case = dict(case or {})
    case_id = str(case.get("case_id") or "unknown")
    expected = str(case.get("expected") or "")
    technique = str(case.get("technique") or "") or None
    rule_ids = [str(r) for r in (case.get("rule_ids") or []) if r]

    result: dict[str, Any] = {
        "case_id": case_id,
        "expected": expected,
        "observed": "unknown",
        "verdict": "inconclusive",
        "mttd_sec": None,
        "alerts": [],
    }
    if expected not in ("alert_present", "no_alert"):
        log.warn("用例期望值非法，标 inconclusive", case_id=case_id, expected=expected)
        return result

    try:
        window = int(window_sec if window_sec is not None else 60)
        start = _parse_ts(t0)
        end = start + timedelta(seconds=max(0, window))
        alerts = _collect_alerts(store, _iso(start), _iso(end), rule_ids, technique)
    except Exception as exc:  # noqa: BLE001 - 单例失败不能中断整套验证
        log.warn("告警查询失败，标 inconclusive", case_id=case_id, error=str(exc))
        return result

    result["observed"] = "alert_present" if alerts else "no_alert"
    if expected == "alert_present":
        result["verdict"] = "TP" if alerts else "FN"
    else:
        result["verdict"] = "FP" if alerts else "TN"
    if alerts:
        result["mttd_sec"] = _mttd_sec(start, alerts[0].get("ts"))
    result["alerts"] = [_summarize(a) for a in alerts[:_ALERT_LIMIT]]
    return result
