"""hornworkctl：Hornwork 命令行客户端。

- 优先通过 Unix socket 控制面（数据目录 `/run/hornwork/ctl.sock`）与 daemon 通信；
- daemon 未运行时，只读命令（status/events/alerts/audit verify/export）直接读 SQLite；
- `scan` 在 daemon 未运行时用同一套引擎做离线扫描，便于答辩现场演示。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__, schema
from .client import CtlClient, CtlError
from .config import cfg_get, load_config, rule_dir
from .store import Store, open_store

# 认证模块依赖 argon2-cffi / cryptography；缺失时不影响其他模块的 CLI。
try:  # pragma: no cover - 取决于运行环境
    from .auth.cli import add_parsers as _auth_add_parsers
except Exception:  # noqa: BLE001
    _auth_add_parsers = None


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _table(rows: list[dict], columns: list[tuple[str, str]], empty: str = "（无数据）") -> None:
    if not rows:
        print(empty)
        return
    widths = {key: len(title) for key, title in columns}
    rendered = []
    for row in rows:
        cells = {}
        for key, _title in columns:
            val = row.get(key)
            if val is None:
                text = ""
            elif isinstance(val, (dict, list)):
                text = json.dumps(val, ensure_ascii=False, default=str)
            else:
                text = str(val)
            cells[key] = text
            widths[key] = max(widths[key], min(len(text), 60))
        rendered.append(cells)
    header = "  ".join(title.ljust(widths[key]) for key, title in columns)
    print(header)
    print("  ".join("-" * widths[key] for key, _t in columns))
    for cells in rendered:
        print("  ".join(cells[key][: widths[key]].ljust(widths[key]) for key, _t in columns))


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return ""
    try:
        return schema.to_utc(ts)[:19].replace("T", " ") + "Z"
    except Exception:  # noqa: BLE001
        return str(ts)[:19]


class Cli:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.cfg = load_config(args.config)
        self.socket_path = args.socket or str(cfg_get(self.cfg, "ctl.socket", "/run/hornwork/ctl.sock"))
        self.client = CtlClient(self.socket_path, timeout=float(args.timeout))
        self._store: Store | None = None

    # ------------------------------------------------------------------ 基础设施
    def ctl(self, method: str, params: dict | None = None) -> Any:
        try:
            return self.client.call(method, params or {})
        except CtlError as exc:
            print(f"[错误] {exc.message}", file=sys.stderr)
            raise SystemExit(2)

    def store(self) -> Store:
        if self._store is None:
            self._store = open_store(self.cfg)
        return self._store

    def daemon_up(self) -> bool:
        return self.client.available()

    def emit(self, obj: Any, rows: list[dict], columns: list[tuple[str, str]]) -> None:
        if self.args.json:
            _print_json(obj)
        else:
            _table(rows, columns)

    # ------------------------------------------------------------------ 各命令
    def cmd_status(self) -> int:
        if not self.daemon_up():
            print(f"[!] daemon 未运行（socket 不存在：{self.socket_path}）")
            try:
                counts = self.store().counts()
                print("数据库只读统计：")
                for key, val in counts.items():
                    print(f"  {key:16s} {val}")
            except Exception as exc:  # noqa: BLE001
                print(f"[!] 无法读取数据库：{exc}")
            return 1
        st = self.ctl("status")
        if self.args.json:
            _print_json(st)
            return 0
        print(f"Hornwork {st.get('version')}  pid={st.get('pid')}  运行 {st.get('uptime_sec')}s")
        print(f"主机：{st.get('host', {}).get('host_id')}  ({st.get('host', {}).get('hostname')})")
        counts = st.get("counts") or {}
        print(
            "事件 {}（24h {}）  告警 {}（24h {}，未处理 {}）  工单 {}  IOC {}  DLQ {}".format(
                counts.get("events_total"), counts.get("events_24h"),
                counts.get("alerts_total"), counts.get("alerts_24h"),
                counts.get("alerts_open"), counts.get("cases_total"),
                counts.get("iocs"), counts.get("dlq"),
            )
        )
        print(f"引擎：{st.get('engines')}")
        sig = st.get("sigma") or {}
        print(
            "Sigma：loaded={} supported={} skipped={} errors={} hits={} include_status_test={}".format(
                sig.get("loaded"), sig.get("supported"), sig.get("skipped"),
                sig.get("errors"), sig.get("hits"), sig.get("include_status_test"),
            )
        )
        print("采集器：")
        for col in st.get("collectors") or []:
            print(f"  - {col.get('name')}: running={col.get('running')} stats={col.get('stats')}")
        bus = st.get("bus") or {}
        print(f"总线：metrics={bus.get('metrics')} pending={bus.get('pending')}")
        print(f"Web：{st.get('web')}")
        print(f"ctl：{st.get('ctl')}")
        return 0

    def cmd_events(self) -> int:
        a = self.args
        params = {"type": a.type, "since": a.since, "limit": a.limit}
        if self.daemon_up():
            data = self.ctl("events.query", params).get("events") or []
        else:
            data = self.store().query_events(
                event_type=a.type, since=a.since, limit=a.limit, source_layer=a.layer
            )
        rows = [
            {
                "ts": _fmt_ts(e.get("ts")),
                "type": e.get("event_type"),
                "host": (e.get("host") or {}).get("host_id"),
                "process": (e.get("process") or {}).get("image"),
                "cmdline": ((e.get("process") or {}).get("cmdline") or "")[:80],
                "file": (e.get("file") or {}).get("path"),
            }
            for e in data
        ]
        self.emit({"events": data}, rows, [
            ("ts", "时间"), ("type", "类型"), ("host", "主机"),
            ("process", "进程"), ("cmdline", "命令行"), ("file", "文件"),
        ])
        return 0

    def cmd_alerts(self) -> int:
        a = self.args
        params = {"since": a.since, "level": a.level, "technique": a.technique, "limit": a.limit}
        if self.daemon_up():
            data = self.ctl("alerts.query", params).get("alerts") or []
        else:
            data = self.store().query_alerts(
                since=a.since, level_min=a.level, technique=a.technique, limit=a.limit
            )
        rows = [
            {
                "ts": _fmt_ts(x.get("ts")),
                "level": x.get("level"),
                "rule": (x.get("rule") or {}).get("id"),
                "name": (x.get("rule") or {}).get("name"),
                "engine": (x.get("rule") or {}).get("engine"),
                "technique": x.get("technique"),
                "status": x.get("status"),
            }
            for x in data
        ]
        self.emit({"alerts": data}, rows, [
            ("ts", "时间"), ("level", "级别"), ("rule", "规则"), ("name", "名称"),
            ("engine", "引擎"), ("technique", "技术"), ("status", "状态"),
        ])
        return 0

    def cmd_scan(self) -> int:
        """``scan`` 命令组：``file`` 为检测模块文件扫描，其余为扫描模块扫描子系统。"""
        sub = getattr(self.args, "scan_cmd", None) or "file"
        if sub == "file":
            return self._cmd_scan_file()
        return self._cmd_scan_subsystem(sub)

    def _cmd_scan_file(self) -> int:
        a = self.args
        path = str(Path(a.path).resolve())
        if self.daemon_up():
            res = self.ctl("scan.file", {"path": path, "deep": a.deep})
        else:
            res = self._offline_scan(path, a.deep)
        if self.args.json:
            _print_json(res)
        else:
            print(f"文件：{res.get('path')}")
            print(f"sha256：{res.get('sha256')}  大小：{res.get('size')}  verdict：{res.get('verdict')}  score：{res.get('score')}")
            print(f"引擎：{res.get('engines_used')}  耗时：{res.get('cost_ms')}ms  cached={res.get('cached')}")
            for hit in res.get("hits") or []:
                print(f"  - [{hit.get('engine')}] {hit.get('rule_id')} {hit.get('name')} score={hit.get('score')}")
        return 0

    def _offline_scan(self, path: str, deep: bool) -> dict:
        from .engines.cascade import Cascade
        from .engines.clamd_client import ClamavEngine
        from .engines.sigdb import SigDbEngine
        from .engines.yara_bridge import YaraEngine

        store = self.store()
        cascade = Cascade(self.cfg, [SigDbEngine(self.cfg, store), YaraEngine(self.cfg), ClamavEngine(self.cfg)], store)
        ctx = {"path": path, "size": os.path.getsize(path), "deep": deep, "filetype": "unknown"}
        # 离线模式只做扫描，不向数据库写（非 root/非服务用户通常没有写权限）；
        # Cascade 内部的落库失败会被忽略，不影响扫描结果。
        res = cascade.scan(path, deep=deep, ctx=ctx)
        return res

    def cmd_mem(self) -> int:
        a = self.args
        if a.mem_cmd == "scan":
            if not self.daemon_up():
                print("[错误] mem scan 需要 daemon 运行", file=sys.stderr)
                return 2
            res = self.ctl("mem.scan", {"pid": a.pid, "snapshot": a.snapshot})
        else:
            if not self.daemon_up():
                print("[错误] mem verify 需要 daemon 运行", file=sys.stderr)
                return 2
            res = self.ctl("mem.verify", {"snapshot": a.snapshot_dir})
        _print_json(res)
        return 0

    def cmd_rules(self) -> int:
        if self.args.rules_cmd == "reload":
            if not self.daemon_up():
                print("[错误] rules reload 需要 daemon 运行", file=sys.stderr)
                return 2
            _print_json(self.ctl("rules.reload"))
            return 0
        if self.daemon_up():
            st = self.ctl("status")
            _print_json({"sigma": st.get("sigma"), "engines": st.get("engines")})
        else:
            yara_dir = rule_dir(self.cfg, "yara")
            net_dir = rule_dir(self.cfg, "net")
            host_dir = rule_dir(self.cfg, "host")
            sigma_dir = rule_dir(self.cfg, "sigma")
            print(f"YARA 规则：{len(list(yara_dir.glob('*.yar')))} 条（{yara_dir}）")
            print(f"网络规则：{len(list(net_dir.glob('*.rules')))} 个文件（{net_dir}）")
            print(f"主机规则：{len(list(host_dir.glob('*.json')))} 条（{host_dir}）")
            print(f"Sigma 规则：{len(list(sigma_dir.rglob('*.yml')))} 条（{sigma_dir}）")
        return 0

    def cmd_intel(self) -> int:
        a = self.args
        if a.intel_cmd == "import":
            if not self.daemon_up():
                print("[错误] intel import 需要 daemon 运行", file=sys.stderr)
                return 2
            _print_json(self.ctl("intel.import", {"path": str(Path(a.path).resolve())}))
        elif a.intel_cmd == "build":
            if not self.daemon_up():
                print("[错误] intel build 需要 daemon 运行", file=sys.stderr)
                return 2
            _print_json(self.ctl("intel.build", {"bundle": a.bundle}))
        else:
            if self.daemon_up():
                data = self.ctl("intel.list", {"type": a.type, "limit": a.limit}).get("iocs") or []
            else:
                data = self.store().ioc_list(kind=a.type, limit=a.limit)
            rows = [
                {"type": x.get("type"), "value": x.get("value"), "confidence": x.get("confidence"),
                 "status": x.get("status"), "source": x.get("source")}
                for x in data
            ]
            self.emit({"iocs": data}, rows, [
                ("type", "类型"), ("value", "值"), ("confidence", "置信度"),
                ("status", "状态"), ("source", "来源"),
            ])
        return 0

    def cmd_case(self) -> int:
        a = self.args
        if a.case_cmd == "create":
            if not self.daemon_up():
                print("[错误] case create 需要 daemon 运行", file=sys.stderr)
                return 2
            _print_json(self.ctl("case.create", {"alert_id": a.alert}))
            return 0
        if a.case_cmd == "show":
            if self.daemon_up():
                cases = self.ctl("case.list", {"limit": 1000}).get("cases") or []
            else:
                cases = self.store().list_cases(limit=1000)
            case = next((c for c in cases if c.get("case_id") == a.case_id), None)
            if case is None:
                print(f"[错误] 工单不存在：{a.case_id}", file=sys.stderr)
                return 2
            _print_json(case)
            return 0
        if self.daemon_up():
            data = self.ctl("case.list", {"status": a.status, "limit": a.limit}).get("cases") or []
        else:
            data = self.store().list_cases(status=a.status, limit=a.limit)
        rows = [
            {"case_id": c.get("case_id"), "title": (c.get("title") or "")[:50],
             "severity": c.get("severity"), "status": c.get("status"),
             "created_at": _fmt_ts(c.get("created_at")), "verdict": c.get("verdict")}
            for c in data
        ]
        self.emit({"cases": data}, rows, [
            ("case_id", "工单"), ("title", "标题"), ("severity", "级别"),
            ("status", "状态"), ("created_at", "创建时间"), ("verdict", "结论"),
        ])
        return 0

    def cmd_respond(self) -> int:
        a = self.args
        if not self.daemon_up():
            print("[错误] respond 需要 daemon 运行", file=sys.stderr)
            return 2
        params = {"case_id": a.case, "playbook": a.playbook, "mode": a.mode}
        _print_json(self.ctl("respond.run", params))
        return 0

    def cmd_verify(self) -> int:
        a = self.args
        # 设计说明：验证脚本里 TC-03/04/05/06/10 需要 root（写 /etc、useradd 等）。
        # daemon 以 hornwork 用户运行，若经控制面转给 daemon 执行，这些用例只能 SKIP。
        # 因此：root 执行 hornworkctl 时在本进程内直接跑验证器（脚本继承 root 权限），
        # 仅通过控制面借用 daemon 的 mem.scan；非 root 时才回退到 daemon 内执行。
        local = bool(getattr(os, "geteuid", lambda: 1)() == 0) and not getattr(a, "remote", False)
        if local or not self.daemon_up():
            from .verify.runner import VerifyRunner

            ctl_call = None
            if local:
                # 以 root 在本进程执行验证：mem.scan 也本地做——daemon 以 hornwork 用户
                # 运行，读 root 目标进程的 /proc/pid/mem 会被 Yama/权限拒绝；root 进程
                # 自己扫描既等价又不需要给服务提权。其余方法仍可走 daemon 控制面。
                from .collectors.memscan import MemoryScanner

                store = self.store()

                def _local_alert(alert: dict) -> None:
                    # 本地验证进程直接落库（daemon 的告警消费链路不经过这里）
                    try:
                        store.insert_alert(alert)
                    except Exception:  # noqa: BLE001
                        pass

                scanner = MemoryScanner(self.cfg, store, _local_alert, None)

                def _ctl_call(method: str, params: dict | None = None) -> dict:
                    params = params or {}
                    if method == "mem.scan":
                        return {
                            "ok": True,
                            "result": scanner.scan_pid(
                                int(params.get("pid") or 0),
                                snapshot=bool(params.get("snapshot", False)),
                            ),
                        }
                    if self.daemon_up():
                        return {"ok": True, "result": self.ctl(method, params)}
                    return {"ok": False, "error": "daemon_down"}

                ctl_call = _ctl_call
            elif self.daemon_up():
                def _ctl_call(method: str, params: dict | None = None) -> dict:
                    return {"ok": True, "result": self.ctl(method, params or {})}

                ctl_call = _ctl_call
            runner = VerifyRunner(self.store(), self.cfg, ctl_call=ctl_call)
            report = runner.run(suite=a.suite, execute=not a.no_execute)
        else:
            report = self.ctl("verify.run", {"suite": a.suite, "execute": not a.no_execute})
        if self.args.json:
            _print_json(report)
            return 0
        metrics = report.get("metrics") or {}
        print(f"验证报告：{report.get('report_path')}")
        _table(
            [
                {"case": c.get("case_id"), "name": c.get("name"), "technique": c.get("technique"),
                 "expected": c.get("expected"), "observed": c.get("observed"),
                 "verdict": c.get("verdict"), "mttd": c.get("mttd_sec")}
                for c in report.get("cases") or []
            ],
            [("case", "用例"), ("name", "名称"), ("technique", "技术"),
             ("expected", "期望"), ("observed", "观测"), ("verdict", "判定"), ("mttd", "MTTD(s)")],
        )
        print(
            "TP={} TN={} FP={} FN={} inconclusive={} TPR={} FPR={} MTTD={}s 覆盖率={}".format(
                metrics.get("TP"), metrics.get("TN"), metrics.get("FP"), metrics.get("FN"),
                metrics.get("inconclusive"), metrics.get("tpr"), metrics.get("fpr"),
                metrics.get("mttd_sec"), metrics.get("coverage"),
            )
        )
        return 0

    def cmd_audit(self) -> int:
        if self.daemon_up():
            res = self.ctl("audit.verify")
        else:
            from .respond.actions import verify_chain

            rows = self.store().audit_rows()
            ok, broken = verify_chain(rows)
            res = {"ok": ok, "rows": len(rows), "broken_seq": broken}
        _print_json(res)
        print("审计链完整" if res.get("ok") else f"审计链断链于 seq={res.get('broken_seq')}")
        return 0 if res.get("ok") else 1

    def cmd_forensics(self) -> int:
        a = self.args
        if not self.daemon_up():
            print("[错误] forensics 需要 daemon 运行", file=sys.stderr)
            return 2
        if a.forensics_cmd == "collect":
            _print_json(self.ctl("forensics.collect", {"compress": a.compress}))
        elif a.forensics_cmd == "analyze":
            _print_json(self.ctl("forensics.analyze", {"image": a.image}))
        else:
            _print_json(self.ctl("forensics.compare", {"malfind": a.malfind, "since": a.since}))
        return 0

    # ------------------------------------------------------------------ 靶场模块：靶场编排
    def _lab_ctl(self):
        """构造 LabCtl，并把 lab 动作接入检测模块的事件库与审计哈希链。"""
        from .lab.ctl import LabCtl
        from .respond.actions import ActionExecutor

        store = self.store()
        auditor = ActionExecutor(store, self.cfg)

        def event_sink(ev: dict) -> None:
            try:
                store.insert_event(schema.normalize_event(ev, self.cfg))
            except Exception as exc:  # noqa: BLE001 - 事件失败不影响靶场动作
                print(f"[warn] lab 事件落库失败：{exc}", file=sys.stderr)

        def audit_sink(action: str, target: str, ok: bool) -> None:
            try:
                auditor.audit_event(action=action, target=target, mode="enforce", ok=ok)
            except Exception as exc:  # noqa: BLE001
                print(f"[warn] lab 审计写入失败：{exc}", file=sys.stderr)

        return LabCtl(self.cfg, store, event_sink=event_sink, audit_sink=audit_sink)

    def cmd_lab(self) -> int:
        a = self.args
        try:
            ctl = self._lab_ctl()
        except Exception as exc:  # noqa: BLE001 - 模块缺失时给出可读错误
            print(f"[错误] 靶场模块 lab 组件不可用：{exc}", file=sys.stderr)
            return 2
        action = a.lab_cmd
        if action == "index":
            res = ctl.index(force=bool(getattr(a, "force", False)))
            if self.args.json:
                _print_json(res)
            else:
                print(f"索引完成：{res.get('count')} 个环境，耗时 {res.get('elapsed_ms')}ms")
                print(f"输出：{res.get('path')}")
                for err in res.get("errors") or []:
                    print(f"  [warn] {err}")
            return 0
        if action == "list":
            rows = ctl.list(type=getattr(a, "type", None), status=getattr(a, "status", None),
                            limit=int(getattr(a, "limit", 100)))
            if self.args.json:
                _print_json({"envs": rows})
                return 0
            _table(
                [
                    {
                        "env_id": r.get("env_id"),
                        "category": r.get("category"),
                        "cve": r.get("cve") or "-",
                        "state": r.get("state") or "-",
                        "ports": json.dumps(r.get("ports") or {}, ensure_ascii=False),
                        "expires_at": r.get("expires_at") or "-",
                    }
                    for r in rows
                ],
                [("env_id", "环境"), ("category", "分类"), ("cve", "CVE"),
                 ("state", "状态"), ("ports", "端口"), ("expires_at", "TTL 到期")],
            )
            return 0
        if action == "up":
            res = ctl.up(a.env_id, ttl_min=getattr(a, "ttl", None), force=bool(getattr(a, "force", False)))
            _print_json(res) if self.args.json else self._print_lab_result("up", res)
            return 0 if res.get("ok") else 1
        if action == "down":
            res = ctl.down(a.env_id, keep_volume=bool(getattr(a, "keep_volume", False)))
            _print_json(res) if self.args.json else self._print_lab_result("down", res)
            return 0 if res.get("ok") else 1
        if action == "status":
            res = ctl.status(getattr(a, "env_id", None))
            if self.args.json:
                _print_json(res)
            else:
                for item in res.get("envs") or [res]:
                    print(f"{item.get('env_id')}: {item.get('state')} ports={item.get('ports')}"
                          f" ttl_left={item.get('ttl_left_sec')}s containers={len(item.get('containers') or [])}")
                if res.get("env_id") is None:
                    print(f"运行中环境数：{res.get('running')} / {res.get('total')}")
                    print(f"索引：{res.get('index')}")
            return 0
        if action == "logs":
            res = ctl.logs(a.env_id, tail=int(getattr(a, "tail", 100)))
            text = res.get("logs") or ""
            _print_json(res) if self.args.json else print(text[-20000:])
            return 0 if res.get("ok") else 1
        if action == "isolate":
            res = ctl.isolate(a.env_id)
            _print_json(res) if self.args.json else self._print_lab_result("isolate", res)
            return 0 if res.get("ok") else 1
        print(f"[错误] 未知 lab 子命令：{action}", file=sys.stderr)
        return 2

    @staticmethod
    def _print_lab_result(action: str, res: dict) -> None:
        print(f"[{action}] ok={res.get('ok')} env={res.get('env_id')} 耗时={res.get('elapsed_ms')}ms")
        if res.get("ports"):
            print(f"  端口：{json.dumps(res.get('ports'), ensure_ascii=False)}")
        if res.get("error"):
            print(f"  错误：{res.get('error')}")
        if res.get("detail"):
            print(f"  详情：{str(res.get('detail'))[:1000]}")
        for line in (res.get("hints") or []):
            print(f"  提示：{line}")

    # ------------------------------------------------------------------ 靶场模块：漏洞档案
    def _vuln_module(self):
        from .vuln import model, report, store as vstore
        from .vuln import match as vmatch

        store = self.store()
        vstore.init_schema(store)
        return store, model, vstore, vmatch, report

    def cmd_vuln(self) -> int:
        a = self.args
        try:
            store, model, vstore, vmatch, vreport = self._vuln_module()
        except Exception as exc:  # noqa: BLE001
            print(f"[错误] 靶场模块 vuln 组件不可用：{exc}", file=sys.stderr)
            return 2
        action = a.vuln_cmd
        if action == "record":
            sub = a.record_cmd
            if sub == "add":
                rec = model.load_record(a.path)
                errs = model.validate_record(rec, int(cfg_get(self.cfg, "vuln.min_references", 2)))
                if errs:
                    print("[错误] 档案校验失败：", file=sys.stderr)
                    for err in errs:
                        print(f"  - {err}", file=sys.stderr)
                    return 1
                if getattr(a, "dry_run", False):
                    print(f"[dry-run] 校验通过：{rec.get('id')} {rec.get('cve')}")
                    return 0
                res = vstore.sync_records(store, [rec])
                print(f"入库完成：upserted={res.get('upserted')} rejected={res.get('rejected')}")
                for err in res.get("errors") or []:
                    print(f"  [warn] {err}")
                return 0
            if sub == "sync":
                res = vstore.seed_from_dir(store, self.cfg)
                print(f"同步完成：{res}")
                return 0
        if action == "list":
            rows = vstore.list_records(store, cwe=getattr(a, "cwe", None),
                                       severity=getattr(a, "severity", None),
                                       status=getattr(a, "status", None),
                                       limit=int(getattr(a, "limit", 200)))
            if self.args.json:
                _print_json({"records": rows})
                return 0
            _table(
                [
                    {"id": r.get("id"), "cve": r.get("cve"), "title": (r.get("title") or "")[:40],
                     "cwe": r.get("cwe"), "score": r.get("cvss_score"),
                     "severity": r.get("severity"), "status": r.get("status")}
                    for r in rows
                ],
                [("id", "编号"), ("cve", "CVE"), ("title", "标题"), ("cwe", "CWE"),
                 ("score", "CVSS"), ("severity", "等级"), ("status", "状态")],
            )
            return 0
        if action == "show":
            rec = vstore.get_record(store, a.vuln_id)
            if rec is None:
                print(f"[错误] 档案不存在：{a.vuln_id}", file=sys.stderr)
                return 2
            if self.args.json:
                _print_json(rec)
            else:
                print(vreport.render_card(rec))
            return 0
        if action == "match":
            request = {
                "component": a.component,
                "version": a.version,
                "distro": getattr(a, "distro", None),
                "cpe": getattr(a, "cpe", None),
            }
            res = vmatch.match(store, self.cfg, request)
            _print_json(res) if self.args.json else _print_json(res)
            return 0
        if action == "report":
            out = getattr(a, "out", None)
            if out:
                # 允许传目录：自动补一个带时间戳的文件名（IF-19 返回文件路径 + sha256）
                out_path = Path(out)
                if out_path.is_dir():
                    out = str(out_path / f"vuln-report-{time.strftime('%Y%m%d-%H%M%S')}.{a.format}")
            res = vreport.export_report(store, self.cfg, ids=getattr(a, "ids", None),
                                        fmt=a.format, out=out)
            _print_json(res)
            return 0
        print(f"[错误] 未知 vuln 子命令：{action}", file=sys.stderr)
        return 2

    # ------------------------------------------------------------------ 扫描模块：扫描子系统
    def _scan_mods(self):
        """导入扫描模块组件并确保建表（CLI 离线可用，不依赖 daemon）。"""
        from . import scan

        store = self.store()
        scan.store.init_schema(store)
        return scan, store

    def _scan_runner(self, scan, store):
        return scan.runner.ScanRunner(self.cfg, store)

    def cmd_asset(self) -> int:
        """``asset add/list/show/enable/disable``：台账是扫描的唯一目标来源。"""
        from .scan import assets as sassets, store as sstore

        store = self.store()
        sstore.init_schema(store)
        action = self.args.asset_cmd
        if action == "add":
            ports: list[int] = []
            for chunk in str(getattr(self.args, "ports", "") or "").replace(";", ",").split(","):
                chunk = chunk.strip()
                if chunk.isdigit():
                    ports.append(int(chunk))
            try:
                asset = sassets.add_asset(
                    store, self.cfg,
                    ip=self.args.ip,
                    asset_id=getattr(self.args, "asset_id", None),
                    hostname=self.args.hostname,
                    role=self.args.role,
                    criticality=self.args.criticality,
                    group=self.args.group,
                    tags=self.args.tags,
                    cred_ref=self.args.cred_ref,
                    is_self=bool(self.args.self_asset),
                    enabled=not bool(self.args.disabled),
                    declared_ports=ports,
                )
            except ValueError as exc:
                print(f"[错误] {exc}", file=sys.stderr)
                return 2
            _print_json(asset) if self.args.json else print(
                f"资产已登记：{asset.get('asset_id')} {asset.get('ip')} role={asset.get('role')}"
            )
            return 0
        if action == "show":
            asset = sstore.get_asset(store, self.args.asset_id) or sstore.get_asset_by_ip(store, self.args.asset_id)
            if not asset:
                print(f"[错误] 资产不存在：{self.args.asset_id}", file=sys.stderr)
                return 2
            _print_json(sassets.asset_view(asset))
            return 0
        if action in ("enable", "disable"):
            ok = sstore.set_asset_enabled(store, self.args.asset_id, action == "enable")
            _print_json({"ok": ok, "asset_id": self.args.asset_id, "enabled": action == "enable"})
            return 0 if ok else 1
        rows = [sassets.asset_view(a) for a in sstore.list_assets(store)]
        if self.args.json:
            _print_json({"assets": rows})
            return 0
        _table(rows, [
            ("asset_id", "资产"), ("ip", "IP"), ("hostname", "主机名"), ("role", "角色"),
            ("criticality", "重要度"), ("group_name", "分组"), ("declared_ports", "声明端口"),
            ("enabled", "启用"),
        ])
        return 0

    def _cmd_scan_subsystem(self, sub: str) -> int:
        """扫描模块 ``scan`` 子命令分发。"""
        a = self.args
        if sub == "plan":
            return self._cmd_scan_plan()
        if sub == "run":
            return self._cmd_scan_run()
        if sub == "status":
            return self._cmd_scan_status()
        if sub == "findings":
            return self._cmd_scan_findings()
        if sub == "finding":
            return self._cmd_scan_finding_set()
        if sub == "diff":
            return self._cmd_scan_diff()
        if sub == "coverage":
            return self._cmd_scan_coverage()
        if sub == "report":
            return self._cmd_scan_report()
        if sub == "snapshot":
            return self._cmd_scan_snapshot()
        if sub == "cve":
            return self._cmd_scan_cve()
        if sub == "retry":
            return self._cmd_scan_retry()
        if sub == "cancel":
            return self._cmd_scan_cancel()
        print(f"[错误] 未知 scan 子命令：{sub}", file=sys.stderr)
        return 2

    # ---- plan
    def _cmd_scan_plan(self) -> int:
        from .scan import assets as sassets, scheduler, store as sstore

        store = self.store()
        action = self.args.plan_cmd
        if action == "add":
            selector: dict[str, Any] = {}
            if self.args.asset:
                selector["asset_ids"] = list(self.args.asset)
            for key, attr in (("group", "group"), ("role", "role"), ("ip", "ip")):
                value = getattr(self.args, attr, None)
                if value:
                    selector[key] = value
            if self.args.tag:
                selector["tags"] = list(self.args.tag)
            if self.args.min_criticality is not None:
                selector["min_criticality"] = self.args.min_criticality
            engines = None
            if self.args.engines:
                engines = [x.strip() for x in self.args.engines.replace(" ", ",").split(",") if x.strip()]
            params: dict[str, Any] = {}
            if self.args.params:
                try:
                    params = json.loads(self.args.params)
                except json.JSONDecodeError as exc:
                    print(f"[错误] --params 不是合法 JSON：{exc}", file=sys.stderr)
                    return 2
            if self.args.cve:
                params["cve_id"] = self.args.cve
            plan = sstore.upsert_plan(store, {
                "plan_id": self.args.id,
                "name": self.args.name or self.args.id,
                "kind": self.args.kind,
                "profile": self.args.profile,
                "selector_json": selector,
                "engines_json": engines,
                "window_start": self.args.window_start,
                "window_end": self.args.window_end,
                "rate_limit": self.args.rate,
                "max_hosts": self.args.max_hosts,
                "enabled": not bool(self.args.disabled),
                "params_json": params,
            })
            plan["next_run"] = scheduler.next_run(plan)
            _print_json(plan) if self.args.json else print(
                f"计划已保存：{plan.get('plan_id')} kind={plan.get('kind')} "
                f"profile={plan.get('profile')} 下次={plan.get('next_run') or '事件触发'}"
            )
            return 0
        if action in ("enable", "disable"):
            ok = sstore.set_plan_enabled(store, self.args.plan_id, action == "enable")
            _print_json({"ok": ok, "plan_id": self.args.plan_id, "enabled": action == "enable"})
            return 0 if ok else 1
        if action == "rm":
            cur = store.execute("DELETE FROM scan_plan WHERE plan_id=?", (self.args.plan_id,))
            print(f"已删除计划 {self.args.plan_id}（{cur.rowcount} 行）")
            return 0
        plans = [scheduler.plan_summary(p, self.cfg) for p in sstore.list_plans(store)]
        if self.args.json:
            _print_json({"plans": plans})
            return 0
        _table(plans, [
            ("plan_id", "计划"), ("kind", "周期"), ("profile", "Profile"), ("ports", "端口"),
            ("engines", "引擎"), ("window", "窗口"), ("enabled", "启用"),
            ("last_run", "上次"), ("next_run", "下次"),
        ])
        return 0

    # ---- run
    def _cmd_scan_run(self) -> int:
        from .scan import assets as sassets, store as sstore

        scan, store = self._scan_mods()
        runner = self._scan_runner(scan, store)
        a = self.args
        if not a.plan and not a.profile:
            print("[错误] 需要 --plan <id> 或 --profile quick|weekly|full|targeted|verify-fix", file=sys.stderr)
            return 2
        selector: dict[str, Any] = {}
        if a.asset:
            selector["asset_ids"] = list(a.asset)
        if getattr(a, "ip", None):
            asset = sstore.get_asset_by_ip(store, a.ip)
            if not asset and a.ip in ("127.0.0.1", "localhost"):
                asset = sassets.ensure_self_asset(store, self.cfg, ip="127.0.0.1")
            if not asset:
                print(f"[错误] IP {a.ip} 不在台账中（先用 asset add 登记）", file=sys.stderr)
                return 2
            selector["asset_ids"] = [asset["asset_id"]]
        if getattr(a, "group", None):
            selector["group"] = a.group
        trigger = a.trigger or ("timer" if a.timer else "manual")
        try:
            if a.plan:
                res = runner.run_plan(
                    a.plan, trigger=trigger, slot=a.slot, label=a.label,
                    asset_ids=list(a.asset or []) or None,
                    check_ids=list(a.check or []) or None,
                    dry_run=bool(a.dry_run), force_window=bool(a.force_window),
                    write_report=not a.no_report, check_only=bool(a.check_only),
                )
            else:
                res = runner.run_adhoc(
                    profile_name=a.profile, selector=selector, trigger=trigger,
                    label=a.label, check_ids=list(a.check or []) or None,
                    dry_run=bool(a.dry_run), force_window=True,
                    write_report=not a.no_report,
                )
        except KeyboardInterrupt:
            print("[!] 扫描被中断（已写入的任务可通过 scan retry 续跑）", file=sys.stderr)
            return 130
        if self.args.json:
            _print_json(res)
        else:
            self._print_scan_summary(res)
        return 0 if res.get("ok") else 1

    def _print_scan_summary(self, res: dict) -> None:
        if res.get("duplicate"):
            print(f"[幂等] {res.get('reason')}")
            return
        if not res.get("ok"):
            print(f"[拒绝] {res.get('reason')}")
            for check in res.get("gates") or []:
                if not check.get("ok"):
                    print(f"  闸门 {check.get('check')}：{check.get('reason') or check.get('ok')}")
            return
        print(f"扫描完成：plan={res.get('plan_id')} run={res.get('run_id')} "
              f"snapshot={res.get('snapshot_id')} profile={res.get('profile')} "
              f"耗时={res.get('duration_ms')}ms")
        counts = res.get("counts") or {}
        print(f"发现：finding={counts.get('findings')} 问题={counts.get('problems')}"
              f"（可确认={counts.get('actionable')} 仅CPE={counts.get('cpe_only')}）"
              f" CVE={counts.get('cve')} 端口={counts.get('ports')} 组件={counts.get('components')}"
              f" 严重级={counts.get('by_severity')}")
        engine_status = res.get("engine_status") or {}
        if engine_status:
            print("引擎：" + "  ".join(
                f"{name}={list(v.keys())}" for name, v in engine_status.items()
            ))
        diff = res.get("diff") or {}
        if diff.get("stats"):
            stats = diff["stats"]
            print(f"与上次快照对比：新增={stats.get('new')} 已修复={stats.get('fixed')} "
                  f"仍存在={stats.get('persisting')} 回归={stats.get('regressed')}（prev={diff.get('prev')}）")
        coverage = res.get("coverage") or {}
        if coverage.get("coverage") is not None:
            print(f"综合覆盖率：{round(float(coverage.get('coverage') or 0) * 100, 1)}%"
                  f"（未覆盖项 {len(coverage.get('uncovered') or [])} 条）")
        report = res.get("report") or {}
        if report.get("path"):
            print(f"报告：{report.get('path')} ({report.get('bytes')} bytes)")
        tasks = res.get("tasks") or []
        if tasks:
            _table(
                [{"task": t.get("task_id"), "asset": t.get("asset_id"), "status": t.get("status"),
                  "cost_ms": t.get("cost_ms"), "error": (t.get("error") or "")[:60]}
                 for t in tasks],
                [("task", "任务"), ("asset", "资产"), ("status", "状态"),
                 ("cost_ms", "耗时ms"), ("error", "错误")],
            )

    # ---- status / findings
    def _cmd_scan_status(self) -> int:
        from .scan import store as sstore

        store = self.store()
        tasks = sstore.list_tasks(store, run_id=getattr(self.args, "run", None),
                                  plan_id=getattr(self.args, "plan", None),
                                  limit=int(getattr(self.args, "limit", 20)))
        snapshots = sstore.list_snapshots(store, limit=int(getattr(self.args, "limit", 20)))
        overview = sstore.scan_overview(store)
        if self.args.json:
            _print_json({"tasks": tasks, "snapshots": snapshots, "overview": overview})
            return 0
        print("计数：" + "  ".join(f"{k}={v}" for k, v in (overview.get("counts") or {}).items()))
        _table(tasks, [
            ("task_id", "任务"), ("plan_id", "计划"), ("asset_id", "资产"), ("slot", "槽位"),
            ("status", "状态"), ("started_at", "开始"), ("cost_ms", "耗时ms"),
        ], empty="（还没有扫描任务）")
        print()
        _table(snapshots, [
            ("snapshot_id", "快照"), ("plan_id", "计划"), ("ts", "时间"), ("kind", "类型"),
            ("is_base", "基线"), ("finding_count", "项数"),
        ], empty="（还没有快照）")
        return 0

    def _cmd_scan_findings(self) -> int:
        from .scan import store as sstore

        store = self.store()
        a = self.args
        rows = sstore.list_findings(
            store, asset_id=a.asset, severity=a.severity, status=a.status,
            kind=a.kind, check_id=a.check, limit=a.limit,
        )
        if a.json:
            _print_json({"findings": rows})
            return 0
        _table(
            [{
                "finding_id": f.get("finding_id"), "asset": f.get("asset_id"),
                "kind": f.get("kind"), "check": f.get("check_id"),
                "title": (f.get("title") or "")[:48], "severity": f.get("severity"),
                "cvss": f.get("cvss"), "confidence": f.get("confidence"),
                "status": f.get("status"), "vuln_ref": f.get("vuln_ref") or "",
            } for f in rows],
            [("finding_id", "Finding"), ("asset", "资产"), ("kind", "类型"), ("check", "检查项"),
             ("title", "标题"), ("severity", "等级"), ("cvss", "CVSS"),
             ("confidence", "置信度"), ("status", "状态"), ("vuln_ref", "档案")],
            empty="（没有 finding）",
        )
        return 0

    def _cmd_scan_finding_set(self) -> int:
        from .scan import store as sstore

        store = self.store()
        a = self.args
        ok = sstore.set_finding_status(store, a.id, a.status, reason=a.reason)
        if not ok:
            print(f"[错误] finding 不存在：{a.id}", file=sys.stderr)
            return 2
        finding = sstore.get_finding(store, a.id)
        _print_json(finding) if a.json else print(
            f"已更新 {a.id} → {a.status}" + (f"（原因：{a.reason}）" if a.reason else "")
        )
        return 0

    # ---- diff / coverage / report / snapshot
    def _cmd_scan_diff(self) -> int:
        from .scan import diff as sdiff, store as sstore

        store = self.store()
        a = self.args
        cur, prev = a.cur, a.prev
        if not cur:
            snaps = sstore.list_snapshots(store, limit=2)
            if len(snaps) < 1:
                print("[错误] 还没有快照，先跑一次 scan run", file=sys.stderr)
                return 2
            cur = snaps[0]["snapshot_id"]
            prev = snaps[1]["snapshot_id"] if len(snaps) > 1 else None
        if not prev:
            print("[错误] 只有一个快照，无法对比（再跑一次扫描生成新快照）", file=sys.stderr)
            return 2
        res = sdiff.build(store, cur, prev)
        if self.args.json:
            _print_json(res)
            return 0
        stats = res.get("stats") or {}
        print(f"快照对比：{cur} vs {prev}  新增={stats.get('new')} 已修复={stats.get('fixed')} "
              f"仍存在={stats.get('persisting')} 回归={stats.get('regressed')}")
        _table(
            [{"delta": i.get("delta"), "asset": i.get("asset_id"), "kind": i.get("kind"),
              "check": i.get("check_id"), "severity": i.get("severity"),
              "title": (i.get("title") or "")[:50]} for i in (res.get("items") or [])],
            [("delta", "变化"), ("asset", "资产"), ("kind", "类型"), ("check", "检查项"),
             ("severity", "等级"), ("title", "标题")],
            empty="（无差异）",
        )
        return 0

    def _cmd_scan_coverage(self) -> int:
        from .scan import coverage as cov, store as sstore

        store = self.store()
        snapshot = self.args.snapshot
        if not snapshot:
            latest = sstore.latest_snapshot(store)
            if not latest:
                print("[错误] 还没有快照，先跑一次 scan run", file=sys.stderr)
                return 2
            snapshot = latest["snapshot_id"]
        res = cov.compute(store, snapshot, self.cfg)
        if self.args.json:
            _print_json(res)
            return 0
        print(f"快照 {snapshot} 综合覆盖率：{round(float(res.get('coverage') or 0) * 100, 1)}%"
              f"（资产 {res.get('assets')}）")
        for domain, data in (res.get("by_domain") or {}).items():
            print(f"  {domain} {data.get('name')}: {round(float(data.get('avg') or 0) * 100, 1)}%"
                  f"  权重={data.get('weight')}  适用资产={data.get('applicable')}")
        _table(
            [{"asset": m.get("asset_id"), "role": m.get("role"),
              **{d: v for d, v in (m.get("domains") or {}).items()},
              "score": round(float(m.get("score") or 0), 3)}
             for m in (res.get("matrix") or [])],
            [("asset", "资产"), ("role", "角色"), ("D1", "D1"), ("D2", "D2"), ("D3", "D3"),
             ("D4", "D4"), ("D5", "D5"), ("D6", "D6"), ("score", "得分")],
        )
        if res.get("uncovered"):
            print("未覆盖清单：")
            for item in res["uncovered"][:40]:
                print(f"  - {item.get('asset_id')} {item.get('domain')}: {item.get('reason')}")
        return 0

    def _cmd_scan_report(self) -> int:
        from .scan import coverage as cov, diff as sdiff, report as sreport, store as sstore

        store = self.store()
        snapshot = self.args.snapshot
        if not snapshot:
            latest = sstore.latest_snapshot(store)
            if not latest:
                print("[错误] 还没有快照，先跑一次 scan run", file=sys.stderr)
                return 2
            snapshot = latest["snapshot_id"]
        prev = sstore.previous_snapshot(store, snapshot)
        diff_res = sdiff.build(store, snapshot, prev["snapshot_id"]) if prev else None
        coverage_res = cov.compute(store, snapshot, self.cfg)
        res = sreport.export(self.store(), self.cfg, snapshot, fmt=self.args.format,
                             out=self.args.out, diff=diff_res, coverage=coverage_res)
        _print_json(res) if self.args.json else print(
            f"报告{'已生成' if res.get('ok') else '生成失败'}：{res.get('path')} "
            f"({res.get('bytes')} bytes)"
        )
        return 0 if res.get("ok") else 1

    def _cmd_scan_snapshot(self) -> int:
        from .scan import store as sstore

        store = self.store()
        if self.args.snapshot_cmd == "base":
            ok = sstore.set_base_snapshot(store, self.args.id)
            _print_json({"ok": ok, "snapshot_id": self.args.id, "is_base": ok})
            return 0 if ok else 2
        snaps = sstore.list_snapshots(store, limit=self.args.limit)
        if self.args.json:
            _print_json({"snapshots": snaps})
            return 0
        _table(snaps, [
            ("snapshot_id", "快照"), ("plan_id", "计划"), ("ts", "时间"), ("kind", "类型"),
            ("is_base", "基线"), ("task_count", "任务"), ("finding_count", "项数"),
        ])
        return 0

    # ---- CVE 数据
    def _cmd_scan_cve(self) -> int:
        from .scan.cve import cmap, feed
        from .scan import store as sstore

        store = self.store()
        sstore.init_schema(store)
        a = self.args
        if a.cve_cmd == "import":
            source = a.source or "nvd"
            result: dict[str, Any] = {}
            if source == "nvd":
                paths = list(a.file or [])
                if a.dir:
                    result = feed.import_dir(store, a.dir)
                elif paths:
                    result = feed.import_nvd(store, paths)
                else:
                    print("[错误] 需要 --file <NVD JSON/JSON.GZ>（可重复）或 --dir <目录>", file=sys.stderr)
                    return 2
            elif source == "oval":
                if not a.file:
                    print("[错误] OVAL 导入需要 --file <oval.xml.bz2>", file=sys.stderr)
                    return 2
                result = feed.import_oval(store, a.file[0], release=a.release)
            else:
                print(f"[错误] 未知数据源：{source}", file=sys.stderr)
                return 2
            _print_json(result)
            return 0 if not result.get("errors") or result.get("imported_rows") else 1
        if a.cve_cmd == "stats":
            res = feed.stats(store)
            res["severity_dist"] = sstore.cve_severity_counts(store)
            _print_json(res)
            return 0
        if a.cve_cmd == "map":
            path = a.file[0] if a.file else str(cfg_get(self.cfg, "scan.rules.comp_map", "") or "")
            res = cmap.import_csv(store, path)
            _print_json(res)
            return 0 if not res.get("errors") else 1
        if a.cve_cmd == "exclude":
            path = a.file[0] if a.file else str(cfg_get(self.cfg, "scan.rules.cve_exclude", "") or "")
            res = self._import_cve_exclude(store, path)
            _print_json(res)
            return 0 if not res.get("errors") else 1
        print(f"[错误] 未知 cve 子命令：{a.cve_cmd}", file=sys.stderr)
        return 2

    @staticmethod
    def _import_cve_exclude(store, path: str) -> dict:
        """导入排除项 CSV：``cve_id,comp_norm,version,reason``。"""
        import csv

        result = {"path": path, "upserted": 0, "skipped": 0, "errors": []}
        if not path or not Path(path).is_file():
            result["errors"].append("排除项文件不存在")
            return result
        try:
            with open(path, "r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    cve = str((row or {}).get("cve_id") or "").strip()
                    comp = str((row or {}).get("comp_norm") or "").strip()
                    if not cve or not comp:
                        result["skipped"] += 1
                        continue
                    store.execute(
                        "INSERT OR REPLACE INTO scan_cve_exclude(cve_id, comp_norm, version, reason)"
                        " VALUES(?,?,?,?)",
                        (cve, comp, (row or {}).get("version") or None,
                         (row or {}).get("reason") or None),
                    )
                    result["upserted"] += 1
        except OSError as exc:
            result["errors"].append(str(exc))
        return result

    # ---- retry / cancel
    def _cmd_scan_retry(self) -> int:
        from .scan import task as stask

        store = self.store()
        rows = stask.retry(store, self.args.run)
        _print_json({"run_id": self.args.run, "requeued": len(rows),
                     "tasks": [r.get("task_id") for r in rows]})
        return 0

    def _cmd_scan_cancel(self) -> int:
        from .scan import task as stask

        store = self.store()
        n = stask.cancel(store, self.args.run, reason=self.args.reason or "人工取消")
        _print_json({"run_id": self.args.run, "aborted": n})
        return 0

    def cmd_export(self) -> int:
        a = self.args
        if self.daemon_up():
            _print_json(self.ctl("export", {"format": a.format, "out": a.out, "limit": a.limit}))
            return 0
        # 离线导出：只导出告警/事件 JSONL
        store = self.store()
        out_dir = Path(a.out or cfg_get(self.cfg, "general.raw_dir", "./raw"))
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"export-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
        alerts = store.query_alerts(limit=a.limit)
        events = store.query_events(limit=a.limit)
        with open(path, "w", encoding="utf-8") as fh:
            for item in alerts + events:
                fh.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
        print(f"已导出 {len(alerts)} 条告警、{len(events)} 条事件到 {path}")
        return 0

    def cmd_prune(self) -> int:
        if not self.daemon_up():
            _print_json(self.store().prune(days=self.args.days))
            return 0
        _print_json(self.ctl("prune", {"days": self.args.days}))
        return 0

    # ---- 认证模块：认证 ----
    def cmd_auth(self) -> int:
        from .auth.cli import run as auth_run

        return auth_run(self.args, self.cfg)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hornworkctl", description="Hornwork 控制台 CLI")
    parser.add_argument("-c", "--config", default=None, help="配置文件（默认 /opt/hornwork/config.toml 或 ./config.toml）")
    parser.add_argument("--socket", default=None, help="控制面 socket 路径")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    parser.add_argument("--timeout", default=600, type=float, help="控制面超时秒")
    parser.add_argument("--version", action="version", version=f"hornworkctl {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="运行状态")

    p_ev = sub.add_parser("events", help="查询事件")
    p_ev.add_argument("--type", default=None)
    p_ev.add_argument("--layer", default=None)
    p_ev.add_argument("--since", default="10m")
    p_ev.add_argument("--limit", type=int, default=20)

    p_al = sub.add_parser("alerts", help="查询告警")
    p_al.add_argument("--level", type=int, default=None)
    p_al.add_argument("--technique", default=None)
    p_al.add_argument("--since", default="24h")
    p_al.add_argument("--limit", type=int, default=20)

    # ---- 扫描模块：扫描（文件扫描保留为 scan file 子命令） ----
    p_scan = sub.add_parser("scan", help="扫描：文件扫描 / 定期漏洞扫描")
    scan_sub = p_scan.add_subparsers(dest="scan_cmd", required=True)

    p_sf = scan_sub.add_parser("file", help="检测模块：文件扫描（sigdb→yara→clamav）")
    p_sf.add_argument("path")
    p_sf.add_argument("--deep", action="store_true")

    p_sp = scan_sub.add_parser("plan", help="扫描计划（周期是数据）")
    plan_sub = p_sp.add_subparsers(dest="plan_cmd", required=True)
    pa = plan_sub.add_parser("add")
    pa.add_argument("--id", required=True, help="计划 ID，如 daily-quick")
    pa.add_argument("--name", default=None)
    pa.add_argument("--kind", default="manual",
                    choices=["daily", "weekly", "quarterly", "targeted", "manual", "verify-fix", "change"])
    pa.add_argument("--profile", default="weekly",
                    choices=["quick", "weekly", "full", "targeted", "verify-fix"])
    pa.add_argument("--asset", action="append", default=None, help="资产 ID（可重复）")
    pa.add_argument("--group", default=None)
    pa.add_argument("--role", default=None)
    pa.add_argument("--tag", action="append", default=None)
    pa.add_argument("--min-criticality", dest="min_criticality", type=int, default=None)
    pa.add_argument("--engines", default=None, help="逗号分隔：nmap,pkgs,lynis,testssl,nuclei")
    pa.add_argument("--window-start", dest="window_start", default=None)
    pa.add_argument("--window-end", dest="window_end", default=None)
    pa.add_argument("--rate", type=int, default=500)
    pa.add_argument("--max-hosts", dest="max_hosts", type=int, default=4)
    pa.add_argument("--params", default=None, help="JSON 参数，如 '{\"time\":\"02:30\"}'")
    pa.add_argument("--cve", default=None, help="targeted 计划的 CVE 编号")
    pa.add_argument("--disabled", action="store_true")
    plan_sub.add_parser("list")
    for _name in ("enable", "disable", "rm"):
        _p = plan_sub.add_parser(_name)
        _p.add_argument("--plan-id", dest="plan_id", required=True)

    p_sr = scan_sub.add_parser("run", help="执行扫描（timer 与手动同一入口）")
    p_sr.add_argument("--plan", default=None, help="计划 ID")
    p_sr.add_argument("--profile", default=None,
                      choices=["quick", "weekly", "full", "targeted", "verify-fix"],
                      help="临时扫描 profile（不落计划表）")
    p_sr.add_argument("--asset", action="append", default=None)
    p_sr.add_argument("--ip", default=None, help="按台账 IP 选目标（本机回环自动登记）")
    p_sr.add_argument("--group", default=None)
    p_sr.add_argument("--check", action="append", default=None, help="只跑指定 check_id（复扫）")
    p_sr.add_argument("--trigger", default=None, help="manual|timer|targeted|verify-fix|change")
    p_sr.add_argument("--slot", default=None)
    p_sr.add_argument("--label", default=None)
    p_sr.add_argument("--dry-run", dest="dry_run", action="store_true")
    p_sr.add_argument("--check-only", dest="check_only", action="store_true",
                      help="只做闸门与目标选择，不实际扫描")
    p_sr.add_argument("--force-window", dest="force_window", action="store_true")
    p_sr.add_argument("--no-report", dest="no_report", action="store_true")
    p_sr.add_argument("--timer", action="store_true", help="标记为 systemd timer 触发")

    p_sst = scan_sub.add_parser("status", help="任务/快照/计数")
    p_sst.add_argument("--run", default=None)
    p_sst.add_argument("--plan", default=None)
    p_sst.add_argument("--limit", type=int, default=20)

    p_sfind = scan_sub.add_parser("findings", help="查询 finding")
    p_sfind.add_argument("--asset", default=None)
    p_sfind.add_argument("--severity", default=None)
    p_sfind.add_argument("--status", default=None)
    p_sfind.add_argument("--kind", default=None)
    p_sfind.add_argument("--check", default=None)
    p_sfind.add_argument("--limit", type=int, default=100)

    p_sfset = scan_sub.add_parser("finding", help="人工处置 finding")
    sfset_sub = p_sfset.add_subparsers(dest="finding_cmd", required=True)
    sfset = sfset_sub.add_parser("set")
    sfset.add_argument("--id", required=True)
    sfset.add_argument("--status", required=True,
                       choices=["new", "observed", "confirmed", "false_positive", "fixed", "reopened"])
    sfset.add_argument("--reason", default=None)

    p_sd = scan_sub.add_parser("diff", help="快照差异（四态）")
    p_sd.add_argument("--from", dest="prev", default=None, help="较旧的基线快照 ID")
    p_sd.add_argument("--to", dest="cur", default=None, help="较新的当前快照 ID（缺省取最近两次）")

    p_sc = scan_sub.add_parser("coverage", help="覆盖率与未覆盖清单")
    p_sc.add_argument("--snapshot", default=None)

    p_srep = scan_sub.add_parser("report", help="生成 HTML/JSON 报告")
    p_srep.add_argument("--snapshot", default=None)
    p_srep.add_argument("--format", default="html", choices=["html", "json"])
    p_srep.add_argument("--out", default=None)

    p_ssnap = scan_sub.add_parser("snapshot", help="快照")
    snap_sub = p_ssnap.add_subparsers(dest="snapshot_cmd", required=True)
    ssl = snap_sub.add_parser("list")
    ssl.add_argument("--limit", type=int, default=20)
    ssb = snap_sub.add_parser("base")
    ssb.add_argument("--id", required=True)

    p_scve = scan_sub.add_parser("cve", help="CVE 数据：导入/映射/统计/排除")
    cve_sub = p_scve.add_subparsers(dest="cve_cmd", required=True)
    ci = cve_sub.add_parser("import")
    ci.add_argument("--source", default="nvd", choices=["nvd", "oval"])
    ci.add_argument("--file", action="append", default=None)
    ci.add_argument("--dir", default=None)
    ci.add_argument("--release", default=None, help="OVAL 发行版代号（noble/jammy）")
    cve_sub.add_parser("stats")
    cm = cve_sub.add_parser("map")
    cm.add_argument("--file", action="append", default=None)
    ce = cve_sub.add_parser("exclude")
    ce.add_argument("--file", action="append", default=None)

    p_sretry = scan_sub.add_parser("retry", help="重试失败/部分完成的任务")
    p_sretry.add_argument("--run", required=True)
    p_scancel = scan_sub.add_parser("cancel", help="取消一次运行")
    p_scancel.add_argument("--run", required=True)
    p_scancel.add_argument("--reason", default=None)

    # ---- 扫描模块：资产台账 ----
    p_asset = sub.add_parser("asset", help="扫描模块：资产台账")
    asset_sub = p_asset.add_subparsers(dest="asset_cmd", required=True)
    aa = asset_sub.add_parser("add")
    aa.add_argument("--id", dest="asset_id", default=None, help="显式资产 ID（如 ast-self/ast-lab）")
    aa.add_argument("--ip", required=True)
    aa.add_argument("--hostname", default=None)
    aa.add_argument("--role", default="server",
                    choices=["self", "server", "web", "db", "lab", "workstation", "network", "windows"])
    aa.add_argument("--criticality", type=int, default=3)
    aa.add_argument("--group", default=None)
    aa.add_argument("--tags", default=None, help="逗号分隔")
    aa.add_argument("--cred-ref", dest="cred_ref", default=None)
    aa.add_argument("--ports", default=None, help="声明端口，逗号分隔")
    aa.add_argument("--self", dest="self_asset", action="store_true")
    aa.add_argument("--disabled", action="store_true")
    asset_sub.add_parser("list")
    ashow = asset_sub.add_parser("show")
    ashow.add_argument("asset_id")
    for _name in ("enable", "disable"):
        _p = asset_sub.add_parser(_name)
        _p.add_argument("asset_id")

    p_mem = sub.add_parser("mem", help="内存扫描")
    mem_sub = p_mem.add_subparsers(dest="mem_cmd", required=True)
    ms = mem_sub.add_parser("scan")
    ms.add_argument("--pid", type=int, required=True)
    ms.add_argument("--snapshot", action="store_true")
    mv = mem_sub.add_parser("verify")
    mv.add_argument("--snapshot", dest="snapshot_dir", required=True)

    p_rules = sub.add_parser("rules", help="规则管理")
    rules_sub = p_rules.add_subparsers(dest="rules_cmd", required=True)
    rules_sub.add_parser("reload")
    rules_sub.add_parser("list")

    p_intel = sub.add_parser("intel", help="情报管理")
    intel_sub = p_intel.add_subparsers(dest="intel_cmd", required=True)
    ii = intel_sub.add_parser("import")
    ii.add_argument("path")
    ib = intel_sub.add_parser("build")
    ib.add_argument("--bundle", default="bundle-1")
    il = intel_sub.add_parser("list")
    il.add_argument("--type", default=None)
    il.add_argument("--limit", type=int, default=200)

    p_case = sub.add_parser("case", help="工单")
    case_sub = p_case.add_subparsers(dest="case_cmd", required=True)
    cl = case_sub.add_parser("list")
    cl.add_argument("--status", default=None)
    cl.add_argument("--limit", type=int, default=50)
    cs = case_sub.add_parser("show")
    cs.add_argument("case_id")
    cc = case_sub.add_parser("create")
    cc.add_argument("--alert", required=True)

    p_resp = sub.add_parser("respond", help="执行响应 playbook")
    p_resp.add_argument("--case", required=True)
    p_resp.add_argument("--playbook", default="PB-001")
    p_resp.add_argument("--mode", default="observe", choices=["observe", "dry-run", "enforce"])

    p_ver = sub.add_parser("verify", help="验证")
    ver_sub = p_ver.add_subparsers(dest="verify_cmd", required=True)
    vr = ver_sub.add_parser("run")
    vr.add_argument("--suite", default="baseline")
    vr.add_argument("--no-execute", action="store_true")
    vr.add_argument("--remote", action="store_true", help="强制交给 daemon 执行（默认 root 时本进程执行）")

    p_audit = sub.add_parser("audit", help="审计链")
    audit_sub = p_audit.add_subparsers(dest="audit_cmd", required=True)
    audit_sub.add_parser("verify")

    p_fo = sub.add_parser("forensics", help="整机内存取证")
    fo_sub = p_fo.add_subparsers(dest="forensics_cmd", required=True)
    fc = fo_sub.add_parser("collect")
    fc.add_argument("--compress", action="store_true")
    fa = fo_sub.add_parser("analyze")
    fa.add_argument("--image", required=True)
    fm = fo_sub.add_parser("compare")
    fm.add_argument("--malfind", default=None)
    fm.add_argument("--since", default=None)

    # ---- 靶场模块：Vulhub 靶场编排 ----
    p_lab = sub.add_parser("lab", help="靶场模块：Vulhub 靶场编排")
    lab_sub = p_lab.add_subparsers(dest="lab_cmd", required=True)
    li = lab_sub.add_parser("index", help="扫描 /opt/vulhub 生成索引")
    li.add_argument("--force", action="store_true", help="强制重建")
    ll = lab_sub.add_parser("list", help="列出环境")
    ll.add_argument("--type", default=None, help="按分类过滤（如 grafana）")
    ll.add_argument("--status", default=None, help="按状态过滤")
    ll.add_argument("--limit", type=int, default=100)
    lu = lab_sub.add_parser("up", help="启动环境（含守卫与健康检查）")
    lu.add_argument("env_id")
    lu.add_argument("--ttl", type=int, default=None, help="TTL 分钟（默认配置值）")
    lu.add_argument("--force", action="store_true", help="跳过快照提醒")
    ld = lab_sub.add_parser("down", help="停止环境并清理数据卷")
    ld.add_argument("env_id")
    ld.add_argument("--keep-volume", action="store_true")
    lst = lab_sub.add_parser("status", help="环境状态/端口探测")
    lst.add_argument("env_id", nargs="?", default=None)
    lg = lab_sub.add_parser("logs", help="查看容器日志")
    lg.add_argument("env_id")
    lg.add_argument("--tail", type=int, default=100)
    lis = lab_sub.add_parser("isolate", help="下线并隔离环境")
    lis.add_argument("env_id")

    # ---- 靶场模块：漏洞档案 ----
    p_vuln = sub.add_parser("vuln", help="靶场模块：漏洞档案库")
    vuln_sub = p_vuln.add_subparsers(dest="vuln_cmd", required=True)
    vrec = vuln_sub.add_parser("record", help="档案入库/同步")
    vrec_sub = vrec.add_subparsers(dest="record_cmd", required=True)
    vra = vrec_sub.add_parser("add")
    vra.add_argument("path")
    vra.add_argument("--dry-run", action="store_true")
    vrec_sub.add_parser("sync")
    vl = vuln_sub.add_parser("list", help="按类型/等级筛选")
    vl.add_argument("--cwe", default=None)
    vl.add_argument("--severity", default=None)
    vl.add_argument("--status", default=None)
    vl.add_argument("--limit", type=int, default=200)
    vs = vuln_sub.add_parser("show", help="漏洞卡")
    vs.add_argument("vuln_id")
    vm = vuln_sub.add_parser("match", help="版本→档案匹配（IF-18）")
    vm.add_argument("--component", required=True)
    vm.add_argument("--version", required=True)
    vm.add_argument("--distro", default=None)
    vm.add_argument("--cpe", default=None)
    vrep = vuln_sub.add_parser("report", help="导出整改单/漏洞卡报告（IF-19）")
    vrep.add_argument("--ids", nargs="*", default=None)
    vrep.add_argument("--format", default="md", choices=["md", "json", "csv"])
    vrep.add_argument("--out", default=None)

    # ---- 认证模块：三因子认证 ----
    if _auth_add_parsers is not None:
        _auth_add_parsers(sub)
    else:
        p_auth = sub.add_parser("auth", help="认证模块：三因子认证（依赖未安装）")
        p_auth.add_argument("auth_args", nargs=argparse.REMAINDER)

    p_exp = sub.add_parser("export", help="导出")
    p_exp.add_argument("--format", default="md", choices=["md", "jsonl"])
    p_exp.add_argument("--out", default=None)
    p_exp.add_argument("--limit", type=int, default=1000)

    p_prune = sub.add_parser("prune", help="清理历史数据")
    p_prune.add_argument("--days", type=int, default=30)
    return parser


SCAN_SUBCOMMANDS = {
    "file", "plan", "run", "status", "findings", "finding", "diff",
    "coverage", "report", "snapshot", "cve", "retry", "cancel",
}


def _normalize_argv(argv: list[str]) -> list[str]:
    """兼容旧用法 ``hornworkctl scan <file>``：自动补 ``file`` 子命令。

    扫描模块把 ``scan`` 变成命令组（``scan plan/run/diff/...``），但检测模块的脚本与文档
    仍可能写 ``hornworkctl scan /tmp/eicar.com``，这里做一次无痛兼容。
    """
    if not argv or argv[0] != "scan":
        return argv
    for index, token in enumerate(argv[1:], start=1):
        if token.startswith("-"):
            continue
        if token in SCAN_SUBCOMMANDS:
            return argv
        return argv[:index] + ["file"] + argv[index:]
    return argv


def main(argv: list[str] | None = None) -> int:
    raw = list(argv if argv is not None else sys.argv[1:])
    raw = _normalize_argv(raw)
    parser = build_parser()
    args = parser.parse_args(raw)
    if not args.config:
        for cand in ("/opt/hornwork/config.toml", "config.toml"):
            if Path(cand).is_file():
                args.config = cand
                break
    cli = Cli(args)
    handlers = {
        "status": cli.cmd_status,
        "events": cli.cmd_events,
        "alerts": cli.cmd_alerts,
        "scan": cli.cmd_scan,
        "asset": cli.cmd_asset,
        "mem": cli.cmd_mem,
        "rules": cli.cmd_rules,
        "intel": cli.cmd_intel,
        "case": cli.cmd_case,
        "respond": cli.cmd_respond,
        "verify": cli.cmd_verify,
        "audit": cli.cmd_audit,
        "forensics": cli.cmd_forensics,
        "lab": cli.cmd_lab,
        "vuln": cli.cmd_vuln,
        "auth": cli.cmd_auth,
        "export": cli.cmd_export,
        "prune": cli.cmd_prune,
    }
    try:
        return handlers[args.cmd]()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
