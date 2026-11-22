"""靶场环境与漏洞档案 handler。

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


class LabMixin:
    """靶场环境与漏洞档案 handler。"""

    def _h_lab_envs(self, query: dict) -> None:
        """GET /api/lab/envs：靶场环境清单 + 最近 lab_run（靶场编排层）。"""
        store = self.app.store
        limit = _q_int(query, "limit", 10, 1, 100)
        envs: list[dict] = []
        runs: list[dict] = []
        try:
            envs = store.query("SELECT * FROM lab_env ORDER BY env_id")
            runs = store.query(
                "SELECT * FROM lab_run ORDER BY started_at DESC LIMIT ?", (limit,)
            )
        except Exception:  # noqa: BLE001 - 未初始化（未用过 lab）时返回空列表
            envs, runs = [], []
        for env in envs:
            for key in ("host_ports", "image_refs"):
                value = env.get(key)
                if isinstance(value, str) and value:
                    try:
                        env[key] = json.loads(value)
                    except json.JSONDecodeError:
                        pass
        self._send_json(200, {"envs": envs, "runs": runs, "ts": _iso_now()})
    def _h_vuln_records(self, query: dict) -> None:
        """GET /api/vuln/records：漏洞档案列表（CWE/等级可过滤）。"""
        store = self.app.store
        limit = _q_int(query, "limit", 200, 1, 1000)
        sql = ("SELECT id, cve, title, component, cwe, cvss_vector, cvss_score, severity,"
               " kind, status, yaml_path, updated_at FROM vuln_record WHERE 1=1")
        args: list = []
        cwe = (query.get("cwe") or [""])[0]
        severity = (query.get("severity") or [""])[0]
        if cwe:
            sql += " AND cwe LIKE ?"
            args.append(f"%{cwe}%")
        if severity:
            sql += " AND severity = ?"
            args.append(severity)
        sql += " ORDER BY cvss_score DESC, id LIMIT ?"
        args.append(limit)
        try:
            rows = store.query(sql, args)
        except Exception:  # noqa: BLE001
            rows = []
        self._send_json(200, {"records": rows, "ts": _iso_now()})
