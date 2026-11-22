"""验证结果查询 handler。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations


from ..common import (
    iso_now as _iso_now,
    q_int as _q_int,
)
from ...verify.metrics import compute_metrics


class ValidateMixin:
    """验证结果查询 handler。"""

    def _h_validate(self, query: dict[str, str]) -> None:
        store = self.app.store
        run_id = query.get("run_id") or store.latest_run_id()
        if not run_id:
            self._send_json(200, {"run_id": None, "rows": [], "metrics": None, "report_path": None, "md_path": None})
            return
        rows = store.validation_rows(run_id=run_id, limit=_q_int(query, "limit", 500, 1, 2000))
        metrics = compute_metrics(rows)
        report_path = md_path = None
        compact: list[dict] = []
        for row in rows:
            payload = row.get("payload") or {}
            if isinstance(payload, dict):
                report_path = report_path or payload.get("report_path")
                md_path = md_path or payload.get("md_path")
            compact.append(
                {
                    "case_id": row.get("case_id"),
                    "technique": row.get("technique"),
                    "expected": row.get("expected"),
                    "observed": row.get("observed"),
                    "verdict": row.get("verdict"),
                    "mttd_sec": row.get("mttd_sec"),
                    "name": (payload or {}).get("name") if isinstance(payload, dict) else None,
                    "error": (payload or {}).get("error") if isinstance(payload, dict) else None,
                }
            )
        self._send_json(
            200,
            {
                "ts": _iso_now(),
                "run_id": run_id,
                "rows": compact,
                "case_count": len(compact),
                "metrics": metrics,
                "report_path": report_path,
                "md_path": md_path,
            },
        )
