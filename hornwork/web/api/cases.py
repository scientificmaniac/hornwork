"""工单域 handler：列表与建单（含 CaseManager 回退）。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations

import uuid

from ... import schema
from ..errors import HttpError as _HttpError
from ..common import (
    log,
    iso_now as _iso_now,
    q_int as _q_int,
)


class CasesMixin:
    """工单域 handler：列表与建单（含 CaseManager 回退）。"""

    def _h_cases_get(self, query: dict[str, str]) -> None:
        items = self.app.store.list_cases(
            status=query.get("status") or None,
            limit=_q_int(query, "limit", 100, 1, 1000),
        )
        self._send_json(200, {"ts": _iso_now(), "items": items, "count": len(items)})
    def _h_cases_post(self) -> None:
        body = self._read_json()
        title = str(body.get("title") or "").strip()
        if not title:
            raise _HttpError(400, "缺少工单标题 title")
        severity = str(body.get("severity") or "P3").strip() or "P3"
        verdict = body.get("verdict")
        dedup_key = body.get("dedup_key")
        store = self.app.store
        case_id: str | None = None
        source = "store"
        error: str | None = None
        try:
            from ...respond.case import CaseManager

            created = CaseManager(store, self.app.cfg).create(title=title, severity=severity, dedup_key=dedup_key, verdict=verdict)
            if isinstance(created, dict):
                case_id = str(created.get("case_id") or "") or None
            elif created:
                case_id = str(created)
            source = "casemanager"
        except Exception as exc:  # noqa: BLE001 - 响应层未就绪时退回 store 直接写入
            error = str(exc)
            log.debug("CaseManager 不可用，退回 store 写入", error=error)
        if not case_id:
            case_id = "case-" + uuid.uuid4().hex[:12]
            try:
                store.insert_case(
                    {
                        "case_id": case_id,
                        "title": title,
                        "severity": severity,
                        "status": "open",
                        "dedup_key": dedup_key,
                        "created_at": schema.utc_now(),
                        "verdict": verdict,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - 写库失败明确报错
                raise _HttpError(500, "工单写入失败", retryable=True, detail=exc) from exc
        row = None
        try:
            row = store.get_case(case_id)
        except Exception as exc:  # noqa: BLE001 - 回读失败不影响创建结果
            log.warn("工单回读失败", case_id=case_id, error=str(exc))
        self._send_json(201, {"ok": True, "case_id": case_id, "case": row, "source": source, "fallback_error": error})
