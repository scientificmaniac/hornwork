"""五模块集成状态与平台登录面加固状态（重型诊断接口）。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
from typing import Any

from ..common import (
    iso_now as _iso_now,
)


class IntegrationMixin:
    """五模块集成状态与平台登录面加固状态（重型诊断接口）。"""

    def _h_integration_status(self, query: dict) -> None:
        """五模块集成状态：各模块关键指标与联动证据。"""
        store = self.app.store
        out: dict[str, Any] = {"ts": _iso_now(), "host": None, "modules": {}}

        def count(sql: str) -> int:
            try:
                rows = store.query(sql)
                return int(rows[0]["n"]) if rows else 0
            except Exception:  # noqa: BLE001
                return 0

        # 检测模块
        m1 = {
            "events": count("SELECT COUNT(*) AS n FROM event"),
            "alerts": count("SELECT COUNT(*) AS n FROM alert"),
            "cases": count("SELECT COUNT(*) AS n FROM case_"),
            "audit_rows": count("SELECT COUNT(*) AS n FROM action_audit"),
            "sigma_hits": count("SELECT COUNT(*) AS n FROM sigma_stat WHERE hits>0"),
        }
        try:
            out["host"] = socket.gethostname()
        except Exception:  # noqa: BLE001
            pass
        try:
            rows = store.query("SELECT host_id FROM meta WHERE key='host_id'") or []
            if rows and rows[0].get("host_id"):
                out["host"] = rows[0]["host_id"]
        except Exception:  # noqa: BLE001
            pass
        out["modules"]["detection"] = m1

        # 靶场模块
        out["modules"]["vuln"] = {
            "records": count("SELECT COUNT(*) AS n FROM vuln_record"),
            "verified": count("SELECT COUNT(*) AS n FROM vuln_record WHERE status='verified'"),
            "lab_envs": count("SELECT COUNT(*) AS n FROM lab_env"),
            "lab_runs": count("SELECT COUNT(*) AS n FROM lab_run"),
        }

        # 扫描模块
        m3 = {
            "assets": count("SELECT COUNT(*) AS n FROM asset"),
            "plans": count("SELECT COUNT(*) AS n FROM scan_plan"),
            "tasks": count("SELECT COUNT(*) AS n FROM scan_task"),
            "snapshots": count("SELECT COUNT(*) AS n FROM scan_snapshot"),
            "findings": count("SELECT COUNT(*) AS n FROM scan_finding"),
            "cve_rows": count("SELECT COUNT(*) AS n FROM cve_cache"),
        }
        try:
            rows = store.query("SELECT task_id, plan_id, status, started_at FROM scan_task"
                               " ORDER BY started_at DESC LIMIT 1") or []
            m3["latest_task"] = rows[0] if rows else None
        except Exception:  # noqa: BLE001
            m3["latest_task"] = None
        out["modules"]["scan"] = m3

        # 认证模块
        m4: dict[str, Any] = {
            "users": count("SELECT COUNT(*) AS n FROM auth_user"),
            "sessions": count("SELECT COUNT(*) AS n FROM auth_session WHERE revoked_at IS NULL"),
            "audit_rows": count("SELECT COUNT(*) AS n FROM auth_audit"),
        }
        try:
            from ...auth import audit as auth_audit

            m4["chain"] = auth_audit.verify_chain(self._auth_engine().store)
        except Exception as exc:  # noqa: BLE001
            m4["chain"] = {"ok": False, "error": str(exc)}
        out["modules"]["auth"] = m4

        # 加固模块：最新一次加固运行
        m5: dict[str, Any] = {}
        try:
            from ...harden import core as harden_core

            runs_dir = harden_core.state(self.app.cfg)["runs"]
            files = sorted(runs_dir.glob("run-*.json"))
            if files:
                data = harden_core.read_json(files[-1]) or {}
                results = data.get("results") or []
                by_status: dict[str, int] = {}
                for item in results:
                    key = str(item.get("status") or "unknown")
                    by_status[key] = by_status.get(key, 0) + 1
                m5 = {
                    "latest_run": data.get("run_id"),
                    "mode": data.get("mode"),
                    "items": len(results),
                    "by_status": by_status,
                    "platform_items": [
                        {"id": r.get("item_id"), "title": r.get("title"),
                         "status": r.get("status")}
                        for r in results
                        if str(r.get("item_id") or "").startswith("H-PL-")
                    ],
                }
            else:
                m5 = {"latest_run": None, "platform_items": []}
        except Exception as exc:  # noqa: BLE001
            m5 = {"error": str(exc), "platform_items": []}
        out["modules"]["harden"] = m5

        self._send_json(200, out)
    def _h_platform_security(self, query: dict) -> None:
        """平台登录面加固状态：HTTPS 反代、锁定策略、目录权限、服务沙箱。"""
        sec: dict[str, Any] = {"ts": _iso_now(), "https": {}, "lockout": {}, "paths": {},
                               "service": {}}
        # HTTPS 反代（加固模块渲染的 nginx 8443）
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", 8443), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname="a.hornwork.local") as tls:
                    sec["https"] = {"ok": True, "protocol": tls.version(),
                                    "cipher": (tls.cipher() or [None])[0]}
        except Exception as exc:  # noqa: BLE001
            sec["https"] = {"ok": False, "error": str(exc)}
        # 登录锁定策略（认证模块策略表，加固模块 H-PL-02 固化）
        try:
            from ...auth import db as auth_db

            eng = self._auth_engine()
            sec["lockout"] = auth_db.get_policy(eng.store, "lockout")
        except Exception as exc:  # noqa: BLE001
            sec["lockout"] = {"error": str(exc)}
        # 数据与密钥目录权限
        for p in ("/var/lib/hornwork", "/var/lib/hornwork/hornwork.db",
                  "/var/lib/hornwork/auth", "/etc/hornwork/harden"):
            try:
                st = os.stat(p)
                sec["paths"][p] = {"mode": oct(st.st_mode & 0o777),
                                   "uid": st.st_uid, "gid": st.st_gid,
                                   "exists": True}
            except OSError:
                sec["paths"][p] = {"exists": False}
        # 服务运行身份与加固单元
        try:
            user = subprocess.run(["systemctl", "show", "hornwork", "-p", "User", "--value"],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
            sandbox = subprocess.run(["systemctl", "show", "hornwork", "-p", "NoNewPrivileges",
                                      "-p", "ProtectSystem", "--value"],
                                     capture_output=True, text=True, timeout=5).stdout.strip().splitlines()
            sec["service"] = {"unit": "hornwork.service", "user": user or "root",
                              "sandbox": sandbox}
        except Exception as exc:  # noqa: BLE001
            sec["service"] = {"error": str(exc)}
        sec["bind"] = {"host": self.app.bind, "port": self.app.port,
                       "token_auth": bool(self.app.token),
                       "tls_ingress": bool(sec["https"].get("ok"))}
        self._send_json(200, sec)
