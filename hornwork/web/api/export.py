"""导出 handler：jsonl / markdown。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations

from datetime import datetime, timezone

from ... import schema
from ..errors import HttpError as _HttpError
from ..common import (
    iso_now as _iso_now,
    q_int as _q_int,
)


class ExportMixin:
    """导出 handler：jsonl / markdown。"""

    def _h_export(self, query: dict[str, str]) -> None:
        fmt = str(query.get("format") or "jsonl").strip().lower()
        kind = str(query.get("kind") or "alerts").strip().lower()
        since = query.get("since") or "24h"
        limit = _q_int(query, "limit", 500, 1, 5000)
        store = self.app.store
        if kind == "alerts":
            items = store.query_alerts(since=since, limit=limit)
        elif kind == "events":
            items = store.query_events(since=since, limit=limit)
        elif kind == "validation":
            run_id = query.get("run_id") or store.latest_run_id()
            items = store.validation_rows(run_id=run_id, limit=limit) if run_id else []
        else:
            raise _HttpError(400, "kind 仅支持 alerts/events/validation")

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "jsonl":
            body = ("\n".join(schema.dumps(item) for item in items) + ("\n" if items else "")).encode("utf-8")
            self._send_bytes(
                200,
                body,
                "application/x-ndjson; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="hornwork-{kind}-{stamp}.jsonl"'},
            )
            return
        if fmt in ("md", "markdown"):
            body = self._render_export_markdown(kind, items, since).encode("utf-8")
            self._send_bytes(
                200,
                body,
                "text/markdown; charset=utf-8",
                {"Content-Disposition": f'attachment; filename="hornwork-{kind}-{stamp}.md"'},
            )
            return
        raise _HttpError(400, "format 仅支持 jsonl 或 md")
    def _render_export_markdown(self, kind: str, items: list[dict], since: str) -> str:
        """导出 Markdown：概览计数 + 明细表。"""
        counts = self.app.store.counts()
        lines = [
            f"# Hornwork 导出（{kind}）",
            "",
            f"- 生成时间：{_iso_now()}",
            f"- 时间范围：since={since}",
            f"- 条数：{len(items)}",
            "",
            "## 概览",
            "",
            "| 计数项 | 值 |",
            "|---|---|",
        ]
        for key in ("events_total", "events_24h", "alerts_total", "alerts_24h", "alerts_open", "cases_total", "iocs"):
            lines.append(f"| {key} | {counts.get(key, 0)} |")
        lines.append("")
        if kind == "alerts":
            lines.extend(["## 告警", "", "| 时间 | 规则 | 级别 | 技术 | 状态 |", "|---|---|---|---|---|"])
            for item in items:
                rule = item.get("rule") or {}
                lines.append(
                    f"| {item.get('ts')} | {rule.get('id') or item.get('rule_id')} | {item.get('level')} "
                    f"| {item.get('technique') or '-'} | {item.get('status') or '-'} |"
                )
        elif kind == "events":
            lines.extend(["## 事件", "", "| 时间 | 类型 | 来源层 | 来源组件 |", "|---|---|---|---|"])
            for item in items:
                lines.append(
                    f"| {item.get('ts')} | {item.get('event_type')} | {item.get('source_layer')} | {item.get('source_product')} |"
                )
        else:
            lines.extend(["## 验证结果", "", "| 用例 | 技术 | 期望 | 观测 | 判定 | MTTD(s) |", "|---|---|---|---|---|---|"])
            for item in items:
                lines.append(
                    f"| {item.get('case_id')} | {item.get('technique') or '-'} | {item.get('expected')} "
                    f"| {item.get('observed')} | {item.get('verdict')} | {item.get('mttd_sec') if item.get('mttd_sec') is not None else '-'} |"
                )
        lines.append("")
        return "\n".join(lines)
