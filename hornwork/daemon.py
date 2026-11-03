"""Hornwork 守护进程：装配采集器/引擎/总线/存储/控制面/Web。

运行模型：
- asyncio 主循环：总线消费、定时任务（老化、prune、后门检查）、控制面/Web 线程；
- 采集器各自持有 daemon 线程（auditd/fim/netcap）或轮询协程（proc/auth）；
- 静态扫描用线程池（默认 4 线程），失败不影响总线。

用法：
    python -m hornwork.daemon --config /opt/hornwork/config.toml
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import os
import signal
import sys
import threading
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__, schema
from .bus import Bus
from .client import CtlClient
from .config import cfg_get, ensure_dirs, load_config, rule_dir
from .ctl import CtlError, CtlServer
from .engines.cascade import Cascade
from .engines.clamd_client import ClamavEngine
from .engines.hostrules import HostRuleEngine
from .engines.sigma_matcher import SigmaMatcher
from .engines.sigdb import SigDbEngine
from .engines.yara_bridge import YaraEngine
from .collectors.auditd import AuditdCollector
from .collectors.authlog import AuthLogCollector
from .collectors.fim import FimCollector
from .collectors.memscan import MemoryScanner
from .collectors.netcap import NetPipeline
from .collectors.persist import PersistenceChecker
from .collectors.proc import ProcCollector
from .intel import feeds, intel2rule
from .intel.iocstore import IocStore
from .log import get_logger, setup_logging, utc_now_iso
from .respond.actions import ActionExecutor, verify_chain
from .respond.approve import ModeGuard
from .respond.case import CaseManager
from .respond.playbook import DEFAULT_PLAYBOOKS, PlaybookRunner, load_playbook
from .store import open_store
from .verify.forensics import Forensics
from .verify.runner import VerifyRunner
from .web.server import WebServer


class HornworkDaemon:
    def __init__(self, cfg_path: str | None = None):
        self.cfg_path = cfg_path
        self.cfg = load_config(cfg_path)
        ensure_dirs(self.cfg)
        setup_logging(
            str(cfg_get(self.cfg, "general.log_level", "INFO")),
            str(cfg_get(self.cfg, "general.app_log", "/var/log/hornwork/app.jsonl")),
        )
        self.log = get_logger("daemon")
        schema.reset_host_cache()
        self.host = schema.host_info(self.cfg)
        self.store = open_store(self.cfg)
        self.bus = Bus(int(cfg_get(self.cfg, "bus.event_queue_max", 100000)), log=self.log)
        self.started_at = time.time()
        self.counters: Counter = Counter()
        self._stop_evt: asyncio.Event | None = None
        self._periodic_task: asyncio.Task | None = None
        self._scan_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=int(cfg_get(self.cfg, "scan.workers", 4)),
            thread_name_prefix="scan",
        )
        self._pending_scans: set[str] = set()
        self._scan_lock = __import__("threading").Lock()
        self._ready = False
        self._build_components()
        self.log.info(
            "daemon 初始化完成",
            host_id=self.host.get("host_id"),
            db=str(self.store.path),
            version=__version__,
        )

    # ------------------------------------------------------------------ 装配
    def _build_components(self) -> None:
        cfg, store = self.cfg, self.store

        self.sigdb = SigDbEngine(cfg, store)
        self.yara = YaraEngine(cfg)
        self.clamav = ClamavEngine(cfg)
        self.cascade = Cascade(cfg, [self.sigdb, self.yara, self.clamav], store)
        self.hostrules = HostRuleEngine(cfg, store)
        self.sigma = SigmaMatcher(cfg, store)
        self.detectors = [self.hostrules, self.sigma]
        self.ioc = IocStore(store, cfg)
        self._bootstrap_intel()

        self.collectors: list[Any] = []
        if cfg_get(cfg, "collect.auditd.enabled", True):
            self.collectors.append(
                AuditdCollector(cfg, self.emit_event, store=store, emit_alert=self.emit_alert)
            )
        if cfg_get(cfg, "collect.proc.enabled", True):
            self.collectors.append(
                ProcCollector(cfg, self.emit_event, store=store, emit_alert=self.emit_alert)
            )
        if cfg_get(cfg, "collect.fim.enabled", True):
            self.collectors.append(
                FimCollector(cfg, self.emit_event, store=store, emit_alert=self.emit_alert)
            )
        if cfg_get(cfg, "collect.auth.enabled", True):
            self.collectors.append(
                AuthLogCollector(cfg, self.emit_event, store=store, emit_alert=self.emit_alert)
            )

        self.persist = PersistenceChecker(cfg, store, self.emit_event, self.emit_alert)
        self.memory = MemoryScanner(cfg, store, self.emit_alert, self.emit_event)
        # 扫描模块联动（IF-23）：扫描窗口门，供网络规则在窗口内降级"自扫流量"。
        self.scan_gate: Any = None
        self._scan_gate_thread: threading.Thread | None = None
        if cfg_get(cfg, "scan.enabled", True):
            try:
                from .scan.window import ScanWindowGate

                self.scan_gate = ScanWindowGate(store, cfg)
                self.scan_gate.refresh(force=True)
            except Exception as exc:  # noqa: BLE001 - 扫描联动不可用不影响检测
                self.log.warn("扫描窗口门初始化失败", error=str(exc))
                self.scan_gate = None
        self.netcap: NetPipeline | None = None
        if cfg_get(cfg, "collect.net.enabled", True):
            self.netcap = NetPipeline(
                cfg, self.emit_event, self.emit_alert,
                ioc_provider=self.ioc_provider, store=store,
                scan_gate=self.scan_gate,
            )

        self.cases = CaseManager(store, cfg)
        self.actions = ActionExecutor(store, cfg)
        self.playbooks = PlaybookRunner(store, self.actions)
        self.guard = ModeGuard(cfg)
        self.verify = VerifyRunner(store, cfg, ctl_call=self._ctl_call_safe)
        self.forensics = Forensics(store, cfg)

        self.web: WebServer | None = None
        if cfg_get(cfg, "web.enabled", True):
            self.web = WebServer(cfg, store)

        self.ctl = CtlServer(
            cfg_get(cfg, "ctl.socket", "/run/hornwork/ctl.sock"),
            self._build_handlers(),
            mode=int(cfg_get(cfg, "ctl.mode", 0o660)),
            group=cfg_get(cfg, "ctl.group", "adm"),
        )

    def _bootstrap_intel(self) -> None:
        """首次启动时把 rules/ioc 下的示例情报导入数据库，方便直接演示。"""
        try:
            if self.store.ioc_list(limit=1):
                return
            feed_dir = rule_dir(self.cfg, "ioc")
            if not feed_dir.is_dir():
                return
            total = 0
            for path in sorted(feed_dir.glob("*")):
                if path.suffix.lower() not in (".jsonl", ".csv", ".json"):
                    continue
                try:
                    records = feeds.load_feed(path)
                    res = self.ioc.import_records(records)
                    total += int(res.get("imported", 0))
                except Exception as exc:  # noqa: BLE001
                    self.log.warn("情报导入失败", path=str(path), error=str(exc))
            if total:
                self.log.info("已导入示例情报", count=total)
        except Exception as exc:  # noqa: BLE001
            self.log.warn("情报初始化失败", error=str(exc))

    # ------------------------------------------------------------------ 回调
    def emit_event(self, event: dict) -> None:
        """采集器 → 归一化 → 总线。"""
        try:
            ev = schema.normalize_event(event, self.cfg)
        except ValueError as exc:
            self.counters["bad_events"] += 1
            try:
                self.store.dlq_add("events.raw", event, str(exc))
            except Exception:  # noqa: BLE001
                pass
            self.log.warn("事件校验失败", error=str(exc))
            return
        self.counters["events"] += 1
        self.bus.publish("events." + str(ev.get("source_layer", "host")), ev)

    def emit_alert(self, alert: dict) -> None:
        """检测器/采集器 → 告警总线（落库在消费端统一做）。"""
        errs = schema.validate_alert(alert)
        if errs:
            self.counters["bad_alerts"] += 1
            self.log.warn("告警校验失败", errors=errs, rule=(alert.get("rule") or {}).get("id"))
            return
        self.counters["alerts_emitted"] += 1
        self.bus.publish("alerts.raw", alert)

    def ioc_provider(self, kind: str) -> set[str]:
        """给网络规则提供 IOC 集合：kind 支持 domains/domain/ips/ip。"""
        try:
            k = str(kind or "").lower()
            if k.startswith("domain"):
                return set(self.store.ioc_values("domain")) | set(self.store.ioc_values("url"))
            if k.startswith("ip"):
                return set(self.store.ioc_values("ip"))
            return set(self.store.ioc_values(k))
        except Exception:  # noqa: BLE001
            return set()

    # ------------------------------------------------------------------ 总线消费
    async def on_event(self, event: dict) -> None:
        try:
            self.store.insert_event(event, engine=(event.get("raw") or {}).get("collector"))
        except Exception as exc:  # noqa: BLE001
            self.log.warn("事件落库失败", error=str(exc))
        for det in self.detectors:
            try:
                hits = det.on_event(event) or []
            except Exception as exc:  # noqa: BLE001
                self.counters["detector_errors"] += 1
                self.log.warn("检测器异常", detector=getattr(det, "name", "?"), error=str(exc))
                continue
            for hit in hits:
                try:
                    self.alert_from_hit(hit, event)
                except Exception as exc:  # noqa: BLE001
                    self.log.warn("告警构造失败", error=str(exc))
        if event.get("event_type") in ("file_create", "file_modify"):
            path = (event.get("file") or {}).get("path")
            if path:
                self.maybe_scan(path)

    async def on_alert(self, alert: dict) -> None:
        try:
            inserted = self.store.insert_alert(alert)
        except Exception as exc:  # noqa: BLE001
            self.log.error("告警落库失败", error=str(exc))
            return
        if inserted:
            self.counters["alerts_stored"] += 1
            level = int(alert.get("level", 0))
            try:
                if level >= 9:
                    self.auto_case(alert)
            except Exception as exc:  # noqa: BLE001
                self.log.warn("自动建单失败", error=str(exc))

    def alert_from_hit(self, hit: dict, event: dict | None = None) -> dict:
        from .engines.base import hit_to_alert_fields

        fields = hit_to_alert_fields(hit)
        alert = schema.new_alert(
            fields["rule"],
            event=event,
            evidence=fields.get("evidence") or [],
            confidence=int(fields.get("confidence", 60)),
        )
        self.emit_alert(alert)
        return alert

    def auto_case(self, alert: dict) -> str | None:
        key = alert.get("dedup_key")
        if key:
            row = self.store.query_one("SELECT case_id FROM case_ WHERE dedup_key=?", (key,))
            if row:
                return row["case_id"]
        # 同一规则 5 分钟内只自动建一个工单：扫描/心跳/批量进程类规则可能在几秒内
        # 产生几十条告警，逐个建单会把工单队列刷爆（演示与运维都不可读）。
        from datetime import datetime, timedelta, timezone

        rule = alert.get("rule") or {}
        rule_name = str(rule.get("name") or "")
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
        if rule_name:
            for row in self.store.query(
                "SELECT case_id, title FROM case_ WHERE created_at >= ?"
                " ORDER BY created_at DESC LIMIT 200",
                (cutoff,),
            ):
                if rule_name in str(row.get("title") or ""):
                    return row["case_id"]
        case = self.cases.create_from_alert(alert)
        self.log.info(
            "自动建单", case_id=case.get("case_id"), rule=rule.get("id")
        )
        return case.get("case_id")

    # ------------------------------------------------------------------ 静态扫描
    def maybe_scan(self, path: str) -> None:
        if not bool(cfg_get(self.cfg, "scan.watch_on_file_event", True)):
            return
        try:
            p = Path(path)
            if not p.is_file():
                return
            size = p.stat().st_size
        except OSError:
            return
        if size <= 0 or size > int(cfg_get(self.cfg, "engines.max_size_mb", 100)) * 1024 * 1024:
            return
        for skip in cfg_get(self.cfg, "scan.skip_dirs", []) or []:
            if str(p).startswith(str(skip)):
                return
        for white in cfg_get(self.cfg, "scan.whitelist_paths", []) or []:
            if str(p).startswith(str(white)):
                return
        with self._scan_lock:
            if str(p) in self._pending_scans:
                return
            self._pending_scans.add(str(p))
        try:
            fut = self._scan_pool.submit(self.scan_file, str(p), False)
            fut.add_done_callback(lambda _f, path=str(p): self._finish_scan(path, _f))
        except RuntimeError:
            with self._scan_lock:
                self._pending_scans.discard(str(p))

    def _finish_scan(self, path: str, future: concurrent.futures.Future) -> None:
        with self._scan_lock:
            self._pending_scans.discard(path)
        try:
            res = future.result()
        except Exception as exc:  # noqa: BLE001
            self.counters["scan_errors"] += 1
            self.log.warn("扫描失败", path=path, error=str(exc))
            return
        if not res or res.get("verdict") in ("clean", "error"):
            return
        score = int(res.get("score", 0))
        level = 10 if score >= 80 else 6
        hits = res.get("hits") or []
        top = max(hits, key=lambda h: int(h.get("score", 0)), default=None)
        mitre = ((top or {}).get("meta") or {}).get("mitre") or []
        if isinstance(mitre, str):
            mitre = [mitre]
        rule = schema.make_rule(
            "SCAN-" + (res.get("first_hit") or "static"),
            "静态扫描命中：" + (top.get("name") if top else "可疑文件"),
            "cascade",
            level=level,
            mitre=list(mitre),
        )
        alert = schema.new_alert(
            rule,
            entity={"host_id": self.host.get("host_id")},
            evidence=[{
                "path": res.get("path"),
                "sha256": res.get("sha256"),
                "score": score,
                "hits": [{"engine": h.get("engine"), "rule_id": h.get("rule_id"), "name": h.get("name")} for h in hits[:8]],
            }],
            confidence=score,
        )
        self.emit_alert(alert)

    def scan_file(self, path: str, deep: bool = False) -> dict:
        p = Path(path)
        if not p.is_file():
            raise CtlError("not_found", f"文件不存在：{path}")
        ctx = {
            "path": str(p),
            "size": p.stat().st_size,
            "deep": bool(deep),
            "filetype": _filetype(p),
        }
        result = self.cascade.scan(str(p), deep=bool(deep), ctx=ctx)
        # Cascade 已负责写 scan_result 与 hash_cache（见 engines/cascade.py），
        # daemon 不再重复落库，避免每文件双行。
        return result

    # ------------------------------------------------------------------ 控制面
    def _ctl_call_safe(self, method: str, params: dict | None = None) -> dict | None:
        """给验证器用：内部直接调 handler，避免自我 socket 往返。"""
        handler = self._build_handlers().get(method)
        if handler is None:
            return None
        try:
            return {"ok": True, "result": handler(params or {})}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def _build_handlers(self) -> dict[str, Any]:
        if not hasattr(self, "_handlers_cache"):
            self._handlers_cache = {
                "status": lambda p: self.status(),
                "events.query": self._h_events,
                "alerts.query": self._h_alerts,
                "scan.file": self._h_scan,
                "mem.scan": self._h_mem_scan,
                "mem.verify": self._h_mem_verify,
                "rules.reload": lambda p: self.reload_rules(),
                "intel.import": self._h_intel_import,
                "intel.build": self._h_intel_build,
                "intel.list": self._h_intel_list,
                "case.create": self._h_case_create,
                "case.list": self._h_case_list,
                "case.update": self._h_case_update,
                "respond.run": self._h_respond,
                "verify.run": self._h_verify,
                "audit.verify": lambda p: self.audit_verify(),
                "forensics.collect": self._h_forensics_collect,
                "forensics.analyze": self._h_forensics_analyze,
                "forensics.compare": self._h_forensics_compare,
                "export": self._h_export,
                "prune": self._h_prune,
                "engine.stats": lambda p: {
                    "engine_stats": self.store.engine_stats(int(p.get("days", 7))),
                    "contribution": self.store.engine_contribution(int(p.get("days", 7))),
                },
                "sigma.stats": lambda p: self.sigma.stats(),
                # 扫描模块联动：扫描器在发 scan_window 事件后立即通知 daemon 刷新窗口缓存，
                # 否则 10s 的周期刷新会让短扫描的前几秒"漏降级"（自扰告警）。
                "scan.window_refresh": self._h_scan_window_refresh,
            }
        return self._handlers_cache

    def _h_scan_window_refresh(self, params: dict) -> dict:
        """控制面：立即刷新扫描窗口缓存，返回当前窗口统计。"""
        if self.scan_gate is None:
            return {"ok": False, "error": "scan_gate 未启用", "stats": {}}
        stats = self.scan_gate.refresh(force=True)
        return {"ok": True, "stats": stats}

    def status(self) -> dict:
        collectors = []
        for col in self.collectors:
            try:
                collectors.append(col.status())
            except Exception as exc:  # noqa: BLE001
                collectors.append({"name": getattr(col, "name", "unknown"), "error": str(exc)})
        if self.netcap is not None:
            try:
                collectors.append(self.netcap.status())
            except Exception as exc:  # noqa: BLE001
                collectors.append({"name": "netcap", "error": str(exc)})
        engines = {}
        for eng in (self.sigdb, self.yara, self.clamav):
            try:
                engines[eng.name] = eng.available()
            except Exception:  # noqa: BLE001
                engines[eng.name] = False
        return {
            "version": __version__,
            "pid": os.getpid(),
            "host": self.host,
            "config": self.cfg_path,
            "started_at": schema.to_utc(self.started_at),
            "uptime_sec": int(time.time() - self.started_at),
            "collectors": collectors,
            "engines": engines,
            "sigma": self.sigma.stats(),
            "bus": self.bus.status(),
            "counts": self.store.counts(),
            "db_bytes": self.store.db_size_bytes(),
            "counters": dict(self.counters),
            "scan_pending": len(self._pending_scans),
            "scan_gate": self.scan_gate.stats() if self.scan_gate is not None else {"enabled": False},
            "ctl": self.ctl.status(),
            "web": self.web.status() if self.web else {"enabled": False},
            "memory": self.memory.status() if hasattr(self.memory, "status") else {},
            "verify": {"report_dir": str(cfg_get(self.cfg, "verify.report_dir", ""))},
        }

    # ------------------------------ 控制面具体 handler
    def _h_events(self, p: dict) -> dict:
        return {
            "events": self.store.query_events(
                event_type=p.get("type"),
                since=p.get("since"),
                limit=int(p.get("limit", 50)),
                source_layer=p.get("layer"),
            )
        }

    def _h_alerts(self, p: dict) -> dict:
        return {
            "alerts": self.store.query_alerts(
                since=p.get("since"),
                level_min=int(p["level"]) if p.get("level") is not None else None,
                technique=p.get("technique"),
                rule_ids=p.get("rule_ids"),
                limit=int(p.get("limit", 50)),
            )
        }

    def _h_scan(self, p: dict) -> dict:
        path = p.get("path")
        if not path:
            raise CtlError("bad_params", "缺少 path")
        return self.scan_file(str(path), bool(p.get("deep", False)))

    def _h_mem_scan(self, p: dict) -> dict:
        pid = int(p.get("pid") or 0)
        if pid <= 0:
            raise CtlError("bad_params", "缺少 pid")
        return self.memory.scan_pid(pid, snapshot=bool(p.get("snapshot", False)))

    def _h_mem_verify(self, p: dict) -> dict:
        d = p.get("snapshot")
        if not d:
            raise CtlError("bad_params", "缺少 snapshot 目录")
        return self.memory.verify(str(d))

    def reload_rules(self) -> dict:
        out: dict[str, Any] = {}
        for eng in (self.sigdb, self.yara):
            try:
                out[eng.name] = eng.reload()
            except Exception as exc:  # noqa: BLE001
                out[eng.name] = {"ok": False, "error": str(exc)}
        for det in (self.hostrules, self.sigma):
            try:
                out[det.name] = det.reload()
            except Exception as exc:  # noqa: BLE001
                out[det.name] = {"ok": False, "error": str(exc)}
        if self.netcap is not None and hasattr(self.netcap, "reload"):
            try:
                out["netrules"] = self.netcap.reload()
            except Exception as exc:  # noqa: BLE001
                out["netrules"] = {"ok": False, "error": str(exc)}
        self.log.info("规则热加载完成", engines=list(out.keys()))
        return out

    def _h_intel_import(self, p: dict) -> dict:
        path = p.get("path")
        if not path:
            raise CtlError("bad_params", "缺少 path")
        records = feeds.load_feed(str(path))
        return self.ioc.import_records(records)

    def _h_intel_build(self, p: dict) -> dict:
        bundle = str(p.get("bundle") or p.get("bundle_id") or "bundle-1")
        return intel2rule.build(self.store, self.cfg, bundle)

    def _h_intel_list(self, p: dict) -> dict:
        return {"iocs": self.store.ioc_list(kind=p.get("type"), limit=int(p.get("limit", 200)))}

    def _h_case_create(self, p: dict) -> dict:
        alert_id = p.get("alert_id")
        if not alert_id:
            raise CtlError("bad_params", "缺少 alert_id")
        rows = self.store.query_alerts(limit=1000)
        alert = next((a for a in rows if a.get("alert_id") == alert_id), None)
        if alert is None:
            raise CtlError("not_found", "告警不存在")
        case = self.cases.create_from_alert(alert, p.get("title"))
        return case

    def _h_case_list(self, p: dict) -> dict:
        return {"cases": self.cases.list(status=p.get("status"), limit=int(p.get("limit", 100)))}

    def _h_case_update(self, p: dict) -> dict:
        case_id = p.get("case_id")
        if not case_id:
            raise CtlError("bad_params", "缺少 case_id")
        ok = self.cases.update(case_id, status=p.get("status"), verdict=p.get("verdict"))
        return {"ok": ok, "case": self.cases.get(case_id)}

    def _h_respond(self, p: dict) -> dict:
        case_id = p.get("case_id") or ""
        mode = self.guard.resolve(p.get("mode") or None)
        pb = p.get("playbook") or "PB-001"
        ok, reason = self.guard.check(pb, mode)
        if not ok:
            raise CtlError("approval_required", reason)
        if pb in DEFAULT_PLAYBOOKS:
            playbook = DEFAULT_PLAYBOOKS[pb]
        else:
            playbook = load_playbook(pb)
        return self.playbooks.run(case_id, playbook, mode=mode)

    def _h_verify(self, p: dict) -> dict:
        return self.verify.run(
            suite=str(p.get("suite") or cfg_get(self.cfg, "verify.suite", "baseline")),
            execute=bool(p.get("execute", True)),
        )

    def audit_verify(self) -> dict:
        rows = self.store.audit_rows()
        ok, broken = verify_chain(rows)
        return {"ok": ok, "rows": len(rows), "broken_seq": broken}

    def _h_forensics_collect(self, p: dict) -> dict:
        return self.forensics.collect(compress=bool(p.get("compress", True)))

    def _h_forensics_analyze(self, p: dict) -> dict:
        image = p.get("image")
        if not image:
            raise CtlError("bad_params", "缺少 image")
        return self.forensics.analyze(str(image))

    def _h_forensics_compare(self, p: dict) -> dict:
        return self.forensics.compare(
            offline_malfind=p.get("malfind"),
            since=p.get("since"),
        )

    def _h_export(self, p: dict) -> dict:
        fmt = str(p.get("format") or "jsonl")
        out_dir = Path(str(p.get("out") or cfg_get(self.cfg, "general.raw_dir", "./raw")))
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        alerts = self.store.query_alerts(limit=int(p.get("limit", 1000)))
        events = self.store.query_events(limit=int(p.get("limit", 1000)))
        if fmt == "md":
            path = out_dir / f"report-{stamp}.md"
            lines = [
                "# Hornwork 导出报告",
                "",
                f"- 生成时间：{utc_now_iso()}",
                f"- 主机：{self.host.get('host_id')}",
                f"- 事件数：{len(events)}；告警数：{len(alerts)}",
                "",
                "## 告警",
                "",
                "| 时间 | 规则 | 级别 | 技术 |",
                "|---|---|---|---|",
            ]
            for a in alerts[:200]:
                rule = a.get("rule") or {}
                lines.append(
                    f"| {a.get('ts')} | {rule.get('id')} {rule.get('name')} | {a.get('level')} | {a.get('technique') or ''} |"
                )
            lines += ["", "## 事件", "", "| 时间 | 类型 | 主机 |", "|---|---|---|"]
            for e in events[:200]:
                lines.append(f"| {e.get('ts')} | {e.get('event_type')} | {(e.get('host') or {}).get('host_id')} |")
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        else:
            path = out_dir / f"export-{stamp}.jsonl"
            with open(path, "w", encoding="utf-8") as fh:
                for a in alerts:
                    fh.write(json.dumps(a, ensure_ascii=False, default=str) + "\n")
                for e in events:
                    fh.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")
        return {"path": str(path), "alerts": len(alerts), "events": len(events), "format": fmt}

    def _h_prune(self, p: dict) -> dict:
        return self.store.prune(days=int(p.get("days", 30)))

    # ------------------------------------------------------------------ 运行
    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        self._stop_evt = asyncio.Event()
        self.bus.bind_loop(loop)
        self.bus.set_dlq(lambda topic, item, err: self.store.dlq_add(topic, item, err))
        self.bus.attach("events.*", self.on_event, "store-detect")
        self.bus.attach("alerts.raw", self.on_alert, "alert-store")

        self._start_collectors()
        self._periodic_task = asyncio.create_task(self._periodic_loop(), name="periodic")
        if self.web is not None:
            try:
                self.web.start()
            except Exception as exc:  # noqa: BLE001
                self.log.error("Web 控制台启动失败", error=str(exc))
                self.web = None
        self.ctl.start()
        loop.run_in_executor(None, self._background_init)

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.request_stop)
            except (NotImplementedError, RuntimeError):
                pass

        self._ready = True
        self.log.info("Hornwork 已启动", pid=os.getpid())
        try:
            await self._stop_evt.wait()
        except asyncio.CancelledError:
            pass
        await self._shutdown()

    def _start_collectors(self) -> None:
        for col in self.collectors:
            name = getattr(col, "name", col.__class__.__name__)
            try:
                col.start()
                self.log.info("采集器已启动", collector=name)
            except Exception as exc:  # noqa: BLE001
                self.log.error("采集器启动失败", collector=name, error=str(exc))
        if self.netcap is not None:
            try:
                self.netcap.start()
                self.log.info("抓包流水线已启动")
            except Exception as exc:  # noqa: BLE001
                self.log.error("抓包流水线启动失败", error=str(exc))
        self._start_scan_gate()

    def _start_scan_gate(self) -> None:
        """后台刷新扫描窗口缓存（10 s 一次，避免网络规则热路径查库）。"""
        if self.scan_gate is None:
            return
        if self._scan_gate_thread is not None and self._scan_gate_thread.is_alive():
            return
        interval = max(5.0, float(cfg_get(self.cfg, "scan.gates.window_refresh_sec", 10) or 10))

        def _loop() -> None:
            while self._stop_evt is not None and not self._stop_evt.is_set():
                try:
                    self.scan_gate.refresh()
                except Exception as exc:  # noqa: BLE001
                    self.log.warn("扫描窗口刷新失败", error=str(exc))
                time.sleep(interval)

        thread = threading.Thread(target=_loop, name="scan-window-gate", daemon=True)
        thread.start()
        self._scan_gate_thread = thread
        self.log.info("扫描窗口门已启动", refresh_sec=interval)

    def _background_init(self) -> None:
        """启动后的重活（基线构建）放到线程，避免拖慢启动。"""
        try:
            if self.store.get_meta("init.persist_baseline") != "done":
                res = self.persist.build_baseline()
                self.store.set_meta("init.persist_baseline", "done")
                self.log.info("后门检查基线已建立", detail=str(res)[:300])
        except Exception as exc:  # noqa: BLE001
            self.log.warn("后门基线构建失败", error=str(exc))

    async def _periodic_loop(self) -> None:
        interval = max(10, int(cfg_get(self.cfg, "host.check_interval_sec", 60)))
        last_persist = 0.0
        last_aging = 0.0
        last_prune = 0.0
        while self._stop_evt is not None and not self._stop_evt.is_set():
            now = time.time()
            if now - last_persist >= interval:
                last_persist = now
                try:
                    await asyncio.get_running_loop().run_in_executor(None, self._run_persist_checks)
                except Exception as exc:  # noqa: BLE001
                    self.log.warn("后门检查失败", error=str(exc))
            if now - last_aging >= 3600:
                last_aging = now
                try:
                    self.ioc.aging()
                except Exception as exc:  # noqa: BLE001
                    self.log.warn("情报老化失败", error=str(exc))
            if now - last_prune >= 86400:
                last_prune = now
                try:
                    self.store.prune(30, 7)
                except Exception as exc:  # noqa: BLE001
                    self.log.warn("prune 失败", error=str(exc))
            try:
                self.store.set_meta("daemon.heartbeat", schema.utc_now())
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(10)

    def _run_persist_checks(self) -> None:
        results = self.persist.run_checks() or []
        self.counters["persist_checks"] += 1
        findings = sum(len(r.get("findings") or []) for r in results)
        if findings:
            self.counters["persist_findings"] += findings
            self.log.info("后门检查发现异常", findings=findings)

    def request_stop(self) -> None:
        if self._stop_evt is not None:
            self._stop_evt.set()

    async def _shutdown(self) -> None:
        self.log.info("开始关闭 Hornwork")
        for col in self.collectors:
            try:
                col.stop()
            except Exception as exc:  # noqa: BLE001
                self.log.warn("采集器停止失败", error=str(exc))
        if self.netcap is not None:
            try:
                self.netcap.stop()
            except Exception:  # noqa: BLE001
                pass
        if self._periodic_task is not None:
            self._periodic_task.cancel()
        try:
            await self.bus.drain(5.0)
        except Exception:  # noqa: BLE001
            pass
        try:
            await self.bus.stop()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.ctl.stop()
        except Exception:  # noqa: BLE001
            pass
        if self.web is not None:
            try:
                self.web.stop()
            except Exception:  # noqa: BLE001
                pass
        try:
            self._scan_pool.shutdown(wait=False, cancel_futures=True)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.store.close()
        except Exception:  # noqa: BLE001
            pass
        self.log.info("Hornwork 已退出")


def _filetype(path: Path) -> str:
    """按魔数粗判文件类型（只用于 YARA external / 引擎 supports）。"""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return "unknown"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(b"PK"):
        return "zip"
    if head.startswith(b"%PDF"):
        return "pdf"
    return "data"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hornwork.daemon", description="Hornwork 守护进程")
    parser.add_argument("-c", "--config", default=None, help="配置文件路径")
    parser.add_argument("--version", action="version", version=f"hornwork {__version__}")
    args = parser.parse_args(argv)
    cfg_path = args.config
    if not cfg_path:
        for cand in ("/opt/hornwork/config.toml", "config.toml"):
            if Path(cand).is_file():
                cfg_path = cand
                break
    daemon = HornworkDaemon(cfg_path)
    try:
        asyncio.run(daemon.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
