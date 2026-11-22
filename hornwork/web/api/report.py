"""扫描报告清单与报告文件服务 handler。

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


class ReportMixin:
    """扫描报告清单与报告文件服务 handler。"""

    def _h_scan_reports(self, query: dict) -> None:
        root = Path("/opt/hornwork/reports")
        items = []
        for path in sorted(root.glob("scan/*.html"), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
            st = path.stat()
            items.append({"name": path.name, "rel": f"scan/{path.name}", "size": st.st_size,
                          "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))})
        self._send_json(200, {"items": items, "ts": _iso_now()})
    def _h_report_file(self, query: dict) -> None:
        rel = str(query.get("file") or "").strip()
        root = Path("/opt/hornwork/reports").resolve()
        target = (root / rel).resolve()
        if not str(target).startswith(str(root)) or not target.is_file():
            raise _HttpError(404, "报告不存在", retryable=False)
        ctype = "text/html; charset=utf-8" if target.suffix == ".html" else "text/plain; charset=utf-8"
        self._send_bytes(200, target.read_bytes(), ctype)
