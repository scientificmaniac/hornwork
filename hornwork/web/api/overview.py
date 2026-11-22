"""概览与引擎贡献统计 handler。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations


from ..common import (
    iso_now as _iso_now,
    q_int as _q_int,
)
from ...verify.metrics import compute_metrics


class OverviewMixin:
    """概览与引擎贡献统计 handler。"""

    def _h_overview(self, query: dict[str, str]) -> None:
        store = self.app.store
        days = _q_int(query, "days", 7, 1, 90)
        counts = store.counts()
        latest = store.latest_run_id()
        validation = None
        if latest:
            rows = store.validation_rows(run_id=latest)
            validation = {
                "run_id": latest,
                "case_count": len(rows),
                "metrics": compute_metrics(rows),
            }
        self._send_json(
            200,
            {
                "ts": _iso_now(),
                "counts": counts,
                "engine_stats": store.engine_stats(days),
                "sigma": store.sigma_stats(),
                "recent_scans": store.recent_scans(limit=5),
                "validation": validation,
                "web": self.app.status(),
            },
        )
    def _h_engine_stats(self, query: dict[str, str]) -> None:
        store = self.app.store
        days = _q_int(query, "days", 7, 1, 90)
        self._send_json(
            200,
            {
                "ts": _iso_now(),
                "days": days,
                "engine_stats": store.engine_stats(days),
                "contribution": store.engine_contribution(days),
                "sigma": store.sigma_stats(),
                "recent_scans": store.recent_scans(limit=_q_int(query, "limit", 20, 1, 200)),
            },
        )
