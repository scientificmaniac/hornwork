"""工单管理：``open → investigating → contained → closed`` 状态机。


- 严重级 P1/P2/P3 由告警 level 映射（>=12 P1、>=9 P2、其余 P3）；
- 关闭时写 ``closed_at``（MTTR 计算依据）；
- ``verdict ∈ {tp, fp, benign, unknown}``；
- 同一告警 dedup_key 复用：已存在未关闭工单时直接返回该工单（幂等）。
"""

from __future__ import annotations

import uuid
from typing import Any

from .. import schema
from ..log import get_logger

log = get_logger("respond.case")

#: 合法状态
STATES: tuple[str, ...] = ("open", "investigating", "contained", "closed")

#: 允许的状态迁移（允许原地重复与人工重开）
TRANSITIONS: dict[str, set[str]] = {
    "open": {"open", "investigating", "contained", "closed"},
    "investigating": {"investigating", "contained", "closed", "open"},
    "contained": {"contained", "closed", "investigating"},
    "closed": {"closed", "open"},
}

#: 合法结论
VERDICTS: tuple[str, ...] = ("tp", "fp", "benign", "unknown")


def severity_from_level(level: Any) -> str:
    """告警 level → 工单严重级 P1/P2/P3。"""
    try:
        lvl = int(level)
    except (TypeError, ValueError):
        lvl = 0
    if lvl >= 12:
        return "P1"
    if lvl >= 9:
        return "P2"
    return "P3"


class CaseManager:
    """工单门面：持久化委托 ``hornwork.store.Store`` 的 case_ 相关方法。"""

    def __init__(self, store: Any, cfg: dict | None = None):
        self.store = store
        self.cfg = cfg or {}

    # ------------------------------------------------------------------ 创建
    def create(
        self,
        title: str,
        severity: str = "P3",
        dedup_key: str | None = None,
        verdict: str | None = None,
    ) -> dict[str, Any]:
        """新建工单并返回工单行。"""
        sev = str(severity or "P3").upper()
        if sev not in ("P1", "P2", "P3"):
            sev = "P3"
        rec = {
            "case_id": f"CASE-{uuid.uuid4().hex[:12].upper()}",
            "title": str(title or "未命名工单")[:500],
            "severity": sev,
            "status": "open",
            "dedup_key": dedup_key,
            "created_at": schema.utc_now(),
            "verdict": verdict if verdict in VERDICTS else None,
        }
        self.store.insert_case(rec)
        row = self.get(rec["case_id"]) or rec
        log.info("工单已创建", case_id=rec["case_id"], severity=sev, title=rec["title"])
        return row

    def create_from_alert(self, alert: dict[str, Any], title: str | None = None) -> dict[str, Any]:
        """从告警生成工单；同 dedup_key 的未关闭工单直接复用。"""
        alert = alert or {}
        rule = alert.get("rule") or {}
        level = alert.get("level")
        if level is None:
            level = rule.get("level")
        rule_name = str(rule.get("name") or rule.get("id") or "unknown")
        host = str(
            (alert.get("host") or {}).get("host_id")
            or (alert.get("entity") or {}).get("host_id")
            or "unknown"
        )
        technique = alert.get("technique")
        dedup = alert.get("dedup_key")
        if dedup:
            existing = self._find_open_by_dedup(str(dedup))
            if existing is not None:
                log.info("工单已存在，复用", case_id=existing.get("case_id"), dedup_key=dedup)
                return existing
        if not title:
            tech_part = f" {technique}" if technique else ""
            title = f"[{rule_name}]{tech_part} 告警工单 @ {host} (level={level})"
        return self.create(
            title=str(title),
            severity=severity_from_level(level),
            dedup_key=str(dedup) if dedup else None,
            verdict="unknown",
        )

    def _find_open_by_dedup(self, dedup_key: str) -> dict[str, Any] | None:
        """查找未关闭的同 dedup_key 工单。"""
        rows = self.store.query(
            "SELECT * FROM case_ WHERE dedup_key=? AND status!='closed' ORDER BY created_at DESC LIMIT 1",
            (dedup_key,),
        )
        return dict(rows[0]) if rows else None

    # ------------------------------------------------------------------ 更新/查询
    def update(
        self,
        case_id: str,
        status: str | None = None,
        verdict: str | None = None,
    ) -> bool:
        """按状态机更新工单；非法迁移返回 False（不写入）。"""
        row = self.get(case_id)
        if row is None:
            log.warn("工单不存在", case_id=case_id)
            return False
        fields: dict[str, Any] = {}
        if verdict is not None:
            if str(verdict) not in VERDICTS:
                log.warn("非法结论", case_id=case_id, verdict=verdict)
                return False
            fields["verdict"] = str(verdict)
        if status is not None:
            new_status = str(status)
            if new_status not in STATES:
                log.warn("非法状态", case_id=case_id, status=status)
                return False
            cur_status = str(row.get("status") or "open")
            if new_status not in TRANSITIONS.get(cur_status, set()) and new_status != cur_status:
                log.warn("非法状态迁移", case_id=case_id, src=cur_status, dst=new_status)
                return False
            fields["status"] = new_status
            if new_status == "closed":
                fields["closed_at"] = schema.utc_now()
            elif cur_status == "closed":
                fields["closed_at"] = None  # 重开时清空关闭时间
        if not fields:
            return False
        ok = bool(self.store.update_case(case_id, **fields))
        if ok:
            log.info("工单已更新", case_id=case_id, **fields)
        return ok

    def get(self, case_id: str) -> dict[str, Any] | None:
        """按 id 取工单。"""
        row = self.store.get_case(case_id)
        return dict(row) if row else None

    def list(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """列出工单（可按状态过滤）。"""
        return [dict(row) for row in self.store.list_cases(status=status, limit=int(limit))]

    # ------------------------------------------------------------------ 便捷方法
    def close(self, case_id: str, verdict: str | None = None) -> bool:
        """关闭工单（写 closed_at）。"""
        return self.update(case_id, status="closed", verdict=verdict)

    def set_verdict(self, case_id: str, verdict: str) -> bool:
        """只更新结论，不改状态。"""
        return self.update(case_id, verdict=verdict)
