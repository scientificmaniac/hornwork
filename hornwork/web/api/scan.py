"""扫描模块只读 API 代理（8 条路由）。

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


class ScanMixin:
    """扫描模块只读 API 代理（8 条路由）。"""

    def _scan_api(self):
        """惰性导入扫描模块只读 API（未初始化扫描数据时返回空结构，不抛异常）。"""
        from ...scan import api as scan_api
        from ...scan import store as scan_store

        scan_store.init_schema(self.app.store)
        return scan_api
    def _h_scan_overview(self, query: dict) -> None:
        """GET /api/scan/overview：台账/计划/任务/快照/finding/CVE 计数与最近任务。"""
        try:
            payload = self._scan_api().overview(self.app.store)
        except Exception as exc:  # noqa: BLE001
            payload = {"error": str(exc), "counts": {}}
        self._send_json(200, payload)
    def _h_scan_plans(self, query: dict) -> None:
        """GET /api/scan/plans：扫描计划列表。"""
        try:
            payload = self._scan_api().list_plans(self.app.store)
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "total": 0, "error": str(exc)}
        self._send_json(200, payload)
    def _h_scan_tasks(self, query: dict) -> None:
        """GET /api/scan/tasks?limit=&status=&run=&plan=：扫描任务列表。"""
        limit = _q_int(query, "limit", 50, 1, 1000)
        status = (query.get("status") or [None])[0]
        run_id = (query.get("run") or [None])[0]
        plan_id = (query.get("plan") or [None])[0]
        try:
            from ...scan import store as scan_store

            scan_store.init_schema(self.app.store)
            rows = scan_store.list_tasks(
                self.app.store, run_id=run_id, plan_id=plan_id, status=status, limit=limit
            )
            payload = {"items": rows, "total": len(rows), "ts": _iso_now()}
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "total": 0, "error": str(exc)}
        self._send_json(200, payload)
    def _h_scan_findings(self, query: dict) -> None:
        """GET /api/scan/findings?severity=&status=&kind=&asset=&limit=：finding 列表。"""
        filters = {
            "asset_id": (query.get("asset") or [None])[0],
            "severity": (query.get("severity") or [None])[0],
            "status": (query.get("status") or [None])[0],
            "kind": (query.get("kind") or [None])[0],
            "limit": _q_int(query, "limit", 200, 1, 2000),
        }
        try:
            payload = self._scan_api().list_findings(self.app.store, **filters)
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "total": 0, "error": str(exc)}
        self._send_json(200, payload)
    def _h_scan_snapshots(self, query: dict) -> None:
        """GET /api/scan/snapshots?limit=：快照列表。"""
        try:
            payload = self._scan_api().list_snapshots(
                self.app.store, limit=_q_int(query, "limit", 20, 1, 200)
            )
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "total": 0, "error": str(exc)}
        self._send_json(200, payload)
    def _h_scan_diff(self, query: dict) -> None:
        """GET /api/scan/diff?from=<snap>&to=<snap>：四态差异（缺省取最近两次快照）。"""
        cur = (query.get("from") or [None])[0]
        prev = (query.get("to") or [None])[0]
        try:
            from ...scan import diff as scan_diff, store as scan_store

            scan_store.init_schema(self.app.store)
            if not cur:
                latest = scan_store.list_snapshots(self.app.store, limit=2)
                if latest:
                    cur = latest[0]["snapshot_id"]
                    prev = prev or (latest[1]["snapshot_id"] if len(latest) > 1 else None)
            payload = scan_diff.build(self.app.store, cur, prev) if cur and prev else {
                "items": [], "stats": {}, "error": "快照不足，无法对比"
            }
        except Exception as exc:  # noqa: BLE001
            payload = {"items": [], "stats": {}, "error": str(exc)}
        self._send_json(200, payload)
    def _h_scan_coverage(self, query: dict) -> None:
        """GET /api/scan/coverage?snapshot=：资产×检查域覆盖率与未覆盖清单。"""
        snapshot = (query.get("snapshot") or [None])[0]
        try:
            from ...scan import coverage as scan_coverage, store as scan_store

            scan_store.init_schema(self.app.store)
            if not snapshot:
                latest = scan_store.latest_snapshot(self.app.store)
                snapshot = latest["snapshot_id"] if latest else None
            payload = (scan_coverage.compute(self.app.store, snapshot, self.app.cfg)
                       if snapshot else {"coverage": 0.0, "uncovered": [], "matrix": []})
        except Exception as exc:  # noqa: BLE001
            payload = {"coverage": 0.0, "uncovered": [], "matrix": [], "error": str(exc)}
        self._send_json(200, payload)
    def _h_scan_cve(self, query: dict) -> None:
        """GET /api/scan/cve：CVE 缓存统计（条数/来源/严重级）。"""
        try:
            payload = self._scan_api().cve_stats(self.app.store)
        except Exception as exc:  # noqa: BLE001
            payload = {"total_cves": 0, "error": str(exc)}
        self._send_json(200, payload)
