"""事件与告警域 handler。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ... import __version__, schema
from ...config import cfg_get
from ..errors import HttpError as _HttpError, error_payload as _error_payload
from ..common import (
    log,
    iso_now as _iso_now,
    query_dict as _query_dict,
    q_int as _q_int,
    NET_RULE_RE as _NET_RULE_RE,
    YARA_RULE_RE as _YARA_RULE_RE,
)
from ...verify.metrics import compute_metrics


class EventsMixin:
    """事件与告警域 handler。"""

    def _h_events_recent(self, query: dict) -> None:
        store = self.app.store
        limit = _q_int(query, "limit", 20, 1, 200)
        try:
            rows = store.query(
                "SELECT ts, event_type AS type, source_layer, host_id, engine, payload"
                " FROM event ORDER BY rowid DESC LIMIT ?", (limit,))
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "读取事件失败", detail=str(exc)) from exc
        self._send_json(200, {"items": rows, "count": len(rows), "ts": _iso_now()})
    def _h_event_types(self, query: dict) -> None:
        store = self.app.store
        try:
            rows = store.query(
                "SELECT event_type AS type, COUNT(*) AS n FROM event GROUP BY event_type"
                " ORDER BY n DESC LIMIT 20")
        except Exception as exc:  # noqa: BLE001
            raise _HttpError(500, "统计事件类型失败", detail=str(exc)) from exc
        self._send_json(200, {"items": rows, "ts": _iso_now()})
    def _h_events(self, query: dict[str, str]) -> None:
        limit = _q_int(query, "limit", 100, 1, 1000)
        items = self.app.store.query_events(
            event_type=query.get("type") or query.get("event_type") or None,
            since=query.get("since") or None,
            limit=limit,
            source_layer=query.get("layer") or query.get("source_layer") or None,
        )
        self._send_json(200, {"ts": _iso_now(), "count": len(items), "items": items})
    def _h_alerts(self, query: dict[str, str]) -> None:
        store = self.app.store
        level_min = query.get("level_min")
        rule_id = query.get("rule_id")
        items = store.query_alerts(
            since=query.get("since") or None,
            level_min=int(level_min) if str(level_min or "").isdigit() else None,
            technique=query.get("technique") or None,
            rule_ids=[rule_id] if rule_id else None,
            limit=_q_int(query, "limit", 100, 1, 1000),
        )
        self._send_json(200, {"ts": _iso_now(), "count": len(items), "items": items})
