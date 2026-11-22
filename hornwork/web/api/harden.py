"""加固模块状态 handler（文件状态读取）。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations

from pathlib import Path

from ..errors import HttpError as _HttpError
from ..common import (
    iso_now as _iso_now,
)


class HardenMixin:
    """加固模块状态 handler（文件状态读取）。"""

    def _h_harden_status(self, query: dict) -> None:
        """加固模块：基线项、计划、运行结果、报告清单（全部来自文件状态）。"""
        import yaml

        from ...harden import core as hcore

        try:
            state = hcore.state(self.app.cfg)
            items_doc = yaml.safe_load(Path(hcore.ITEMS_PATH).read_text(encoding="utf-8")) or {}
            items = items_doc.get("items") or []
            plans = []
            for path in sorted(state["plans"].glob("pln-*.json"))[-5:]:
                data = hcore.read_json(path) or {}
                nitems = sum(len(b.get("items") or []) for b in (data.get("batches") or []))
                if not nitems:
                    nitems = len(data.get("items") or data.get("allowed") or [])
                plans.append({"plan_id": data.get("plan_id"), "role": data.get("role"),
                              "asset": data.get("asset_id"), "items": nitems,
                              "created_at": data.get("created_at")})
            runs = []
            for path in sorted(state["runs"].glob("run-*.json"))[-6:]:
                data = hcore.read_json(path) or {}
                results = data.get("results") or []
                counts: dict[str, int] = {}
                for r in results:
                    key = str(r.get("status") or "unknown")
                    counts[key] = counts.get(key, 0) + 1
                runs.append({"run_id": data.get("run_id"), "plan_id": data.get("plan_id"),
                             "mode": data.get("mode"), "status": data.get("status"),
                             "started_at": data.get("started_at"), "counts": counts,
                             "items": len(results)})
            reports = []
            rdir = state["root"] / "reports"
            for path in sorted(rdir.glob("harden-report-*.md"))[-6:]:
                reports.append({"name": path.name, "size": path.stat().st_size})
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "读取加固状态失败", detail=str(exc)) from exc
        self._send_json(200, {
            "items": [{"id": i.get("id"), "category": i.get("category"),
                       "title": i.get("title"), "risk": i.get("risk"),
                       "scope_A": str((i.get("scope") or {}).get("A", "")).startswith("yes")}
                      for i in items],
            "plans": plans, "runs": runs, "reports": reports, "ts": _iso_now(),
        })
