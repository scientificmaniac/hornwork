"""一次扫描运行的编排器（扫描模块的"中枢"）。

流程：

```
计划/槽位 → 台账选目标 → 闸门（白名单/时间窗/并发/磁盘）→ 建任务（幂等）
  → 发 scan_window(start) 事件（告诉检测模块"这段流量是自己人"）
  → 逐资产执行引擎（nmap 端口+服务 → pkgs/lynis/testssl/nuclei 可选）
  → 归一（事实/问题 + 去重 + 生命周期）
  → CVE 匹配（CPE + Debian 版本区间 + 置信度 + 靶场模块档案交叉验证）
  → 快照冻结 + diff + 覆盖率 + 报告
  → 发 scan_window(end) 事件 + 任务事件 + 审计链
```

设计取舍：
- **运行可离线**：整条链路只依赖 SQLite，不要求 daemon 在线；timer 与手动入口同一套代码
  （``hornworkctl scan run --plan <id>``）；
- **失败不误判**：任一引擎 error/timeout 时该资产**不做** "连续未现 → fixed" 判定，
  避免把"没扫到"当成"已修复"；
- **白名单永不豁免**：事件触发计划可以不受时间窗限制，但越界目标一律拒绝并写审计。
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .. import schema
from ..config import cfg_get
from ..log import get_logger
from . import assets as sassets
from . import normalize, scheduler, store as sstore, task as stask

log = get_logger("scan.runner")


def _now() -> str:
    return schema.utc_now()


def _compact_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")


def _snapshot_id_for(run_id: str) -> str:
    """快照 ID：可排序的时间戳 + 运行 ID 后缀，保证同一秒内多次运行不冲突。"""
    suffix = schema.dedup_key(str(run_id))[:4].upper()
    return f"S{_compact_ts()}-{suffix}"


class ScanRunner:
    """扫描编排器：构造一次 ``run``（计划或临时 profile），返回可 JSON 化的摘要。"""

    def __init__(
        self,
        cfg: dict,
        store: Any,
        *,
        adapters: list | None = None,
        event_sink: Callable[[dict], None] | None = None,
        audit_sink: Callable[..., Any] | None = None,
    ):
        self.cfg = cfg or {}
        self.store = store
        self._adapters = adapters
        self.event_sink = event_sink
        self.audit_sink = audit_sink
        self._mapped_components: set[str] | None = None
        sstore.init_schema(self.store)

    # ------------------------------------------------------------------ 对外入口
    def run_plan(
        self,
        plan_id: str,
        *,
        trigger: str = "manual",
        slot: str | None = None,
        label: str | None = None,
        asset_ids: list[str] | None = None,
        check_ids: list[str] | None = None,
        dry_run: bool = False,
        force_window: bool = False,
        write_report: bool = True,
        check_only: bool = False,
    ) -> dict:
        """执行一个 ``scan_plan``。返回摘要（``ok=False`` 时带 ``reason``）。"""
        started = time.time()
        plan = sstore.get_plan(self.store, plan_id)
        if plan is None:
            return {"ok": False, "reason": f"计划不存在：{plan_id}", "plan_id": plan_id}
        if not plan.get("enabled") and not check_only:
            return {"ok": False, "reason": f"计划已禁用：{plan_id}", "plan_id": plan_id}

        # ---- 选目标 ----
        assets = sstore.select_assets(self.store, plan.get("selector_json"))
        if asset_ids:
            wanted = {str(x) for x in asset_ids}
            assets = [a for a in assets if a.get("asset_id") in wanted]
        if not assets:
            return {"ok": False, "reason": "台账中没有匹配的目标资产（先 asset add）",
                    "plan_id": plan_id, "gates": []}

        # ---- 闸门 ----
        gates = scheduler.gate_check(
            self.cfg, plan, assets, trigger=trigger, force_window=force_window,
            store=self.store,
        )
        self._audit(
            "scan.gate", target=plan_id, ok=gates["ok"],
            detail={"reason": gates.get("reason"), "checks": gates.get("checks")},
        )
        if not gates["ok"]:
            return {
                "ok": False,
                "reason": gates.get("reason") or "闸门拒绝",
                "plan_id": plan_id,
                "gates": gates.get("checks") or [],
                "duration_ms": int((time.time() - started) * 1000),
            }

        assets = gates.get("assets") or assets
        profile = scheduler.profile_of(self.cfg, plan)
        slot = slot or scheduler.slot_of(plan)
        run_id = sstore.new_id("run")
        snapshot_id = _snapshot_id_for(run_id)

        if check_only:
            return {
                "ok": True, "plan_id": plan_id, "run_id": run_id, "slot": slot,
                "would_scan": [{"asset_id": a.get("asset_id"), "ip": a.get("ip")} for a in assets],
                "profile": profile.get("name"), "engines": profile.get("engines"),
                "ports": profile.get("ports"), "gates": gates.get("checks") or [],
                "duration_ms": int((time.time() - started) * 1000),
            }

        # ---- 建任务（幂等）----
        tasks = stask.create_tasks(
            self.store, plan, assets, run_id, slot, snapshot_id=snapshot_id,
        )
        fresh = [t for t in tasks if t.get("_created") or t.get("status") != "done"]
        if not fresh:
            return {
                "ok": True, "duplicate": True, "plan_id": plan_id, "run_id": run_id,
                "slot": slot, "snapshot_id": snapshot_id,
                "reason": f"槽位 {slot} 已有完成任务（幂等返回）",
                "tasks": tasks, "duration_ms": int((time.time() - started) * 1000),
            }

        # ---- 快照（先登记，扫描结束后回填统计）----
        sstore.create_snapshot(self.store, {
            "snapshot_id": snapshot_id, "plan_id": plan_id, "run_id": run_id,
            "ts": _now(), "kind": plan.get("kind"), "label": label or plan.get("name"),
            "task_count": len(tasks),
            "stats_json": {"profile": profile.get("name"), "assets": [a.get("asset_id") for a in assets],
                           "engines_planned": profile.get("engines") or []},
        })

        # ---- 扫描窗口 start ----
        self._emit_window("start", plan=plan, run_id=run_id, assets=assets, profile=profile)
        try:
            outcome = self._execute_tasks(
                plan, profile, tasks, run_id, snapshot_id,
                trigger=trigger, check_ids=check_ids, dry_run=dry_run,
            )
        finally:
            self._emit_window("end", plan=plan, run_id=run_id, assets=assets, profile=profile)

        # ---- 收尾：快照统计 / diff / 覆盖率 / 报告 ----
        summary = self._finalize(
            plan=plan, profile=profile, run_id=run_id, snapshot_id=snapshot_id,
            tasks=tasks, assets=assets, outcome=outcome, slot=slot,
            write_report=write_report, started=started, trigger=trigger,
        )
        return summary

    def run_adhoc(
        self,
        *,
        profile_name: str = "targeted",
        selector: dict | None = None,
        trigger: str = "manual",
        label: str | None = None,
        asset_ids: list[str] | None = None,
        check_ids: list[str] | None = None,
        dry_run: bool = False,
        force_window: bool = True,
        write_report: bool = True,
    ) -> dict:
        """不落计划表的一次性扫描（``scan run --profile quick --target ...``）。

        实现方式：用内存里的临时计划（``plan_id=adhoc-<ts>``）走同一套编排与闸门，
        避免"手动跑的和定时跑的不是一套代码"。
        """
        plan = {
            "plan_id": f"adhoc-{_compact_ts()}",
            "name": label or f"临时扫描（{profile_name}）",
            "kind": "manual",
            "profile": profile_name,
            "selector_json": selector or {},
            "engines_json": None,
            "rate_limit": int(cfg_get(self.cfg, "scan.gates.pps", 500) or 500),
            "max_hosts": int(cfg_get(self.cfg, "scan.gates.max_hosts", 4) or 4),
            "enabled": 1,
        }
        assets = sstore.select_assets(self.store, plan["selector_json"])
        if asset_ids:
            wanted = {str(x) for x in asset_ids}
            assets = [a for a in assets if a.get("asset_id") in wanted]
        if not assets:
            return {"ok": False, "reason": "没有匹配的目标资产", "plan_id": plan["plan_id"]}

        gates = scheduler.gate_check(
            self.cfg, plan, assets, trigger=trigger, force_window=force_window,
            store=self.store,
        )
        if not gates["ok"]:
            return {"ok": False, "reason": gates.get("reason"), "plan_id": plan["plan_id"],
                    "gates": gates.get("checks") or []}

        assets = gates.get("assets") or assets
        profile = scheduler.profile_of(self.cfg, plan)
        slot = scheduler.slot_of(plan)
        run_id = sstore.new_id("run")
        snapshot_id = _snapshot_id_for(run_id)
        tasks = stask.create_tasks(self.store, plan, assets, run_id, slot,
                                   snapshot_id=snapshot_id)
        sstore.create_snapshot(self.store, {
            "snapshot_id": snapshot_id, "plan_id": plan["plan_id"], "run_id": run_id,
            "ts": _now(), "kind": "manual", "label": label or plan["name"],
            "task_count": len(tasks),
            "stats_json": {"profile": profile.get("name"),
                           "assets": [a.get("asset_id") for a in assets],
                           "engines_planned": profile.get("engines") or []},
        })
        self._emit_window("start", plan=plan, run_id=run_id, assets=assets, profile=profile)
        try:
            outcome = self._execute_tasks(
                plan, profile, tasks, run_id, snapshot_id,
                trigger=trigger, check_ids=check_ids, dry_run=dry_run,
            )
        finally:
            self._emit_window("end", plan=plan, run_id=run_id, assets=assets, profile=profile)
        started = time.time() - outcome.get("duration_ms", 0) / 1000.0
        return self._finalize(
            plan=plan, profile=profile, run_id=run_id, snapshot_id=snapshot_id,
            tasks=tasks, assets=assets, outcome=outcome, slot=slot,
            write_report=write_report, started=started, trigger=trigger,
        )

    # ------------------------------------------------------------------ 执行
    def _execute_tasks(
        self, plan: dict, profile: dict, tasks: list[dict], run_id: str,
        snapshot_id: str, *, trigger: str, check_ids: list[str] | None,
        dry_run: bool = False,
    ) -> dict:
        started = time.time()
        engine_status: dict[str, dict] = {}
        all_items: list[dict] = []
        total_counts = {"findings": 0, "problems": 0, "cve": 0, "ports": 0, "components": 0}
        by_severity: dict[str, int] = {}
        task_results: list[dict] = []
        cve_cache_ready = self._cve_cache_ready()

        for task in tasks:
            if not task.get("_created") and task.get("status") == "done":
                task_results.append({**task, "skipped": "already_done"})
                continue
            claimed = stask.claim(self.store, task["task_id"]) or task
            asset = sstore.get_asset(self.store, claimed.get("asset_id")) or {}
            result = self._execute_one(
                plan=plan, profile=profile, asset=asset, task=claimed,
                snapshot_id=snapshot_id, check_ids=check_ids,
                cve_cache_ready=cve_cache_ready, dry_run=dry_run,
            )
            task_results.append(result["task"])
            for name, outcome in (result.get("engine_status") or {}).items():
                bucket = engine_status.setdefault(name, {})
                status = str(outcome.get("status") or "unknown")
                bucket[status] = int(bucket.get(status) or 0) + 1
                bucket.setdefault("findings", 0)
                bucket["findings"] = int(bucket["findings"]) + int(outcome.get("findings") or 0)
            all_items.extend(result.get("snapshot_items") or [])
            for key in ("findings", "problems", "actionable", "cpe_only",
                        "cve", "ports", "components"):
                total_counts[key] = int(total_counts.get(key, 0)) + int(
                    (result.get("counts") or {}).get(key, 0)
                )
            for severity, n in ((result.get("counts") or {}).get("by_severity") or {}).items():
                by_severity[severity] = by_severity.get(severity, 0) + int(n)

        return {
            "tasks": task_results,
            "engine_status": engine_status,
            "snapshot_items": all_items,
            "counts": {**total_counts, "by_severity": by_severity},
            "duration_ms": int((time.time() - started) * 1000),
            "run_id": run_id,
        }

    def _execute_one(
        self, *, plan: dict, profile: dict, asset: dict, task: dict,
        snapshot_id: str, check_ids: list[str] | None,
        cve_cache_ready: bool, dry_run: bool = False,
    ) -> dict:
        started = time.time()
        task_id = str(task.get("task_id"))
        asset_id = str(task.get("asset_id"))
        stages: list[str] = []
        raw_results: list[dict] = []
        engine_status: dict[str, dict] = {}
        errors: list[str] = []

        adapters = self._select_adapters(profile, asset, check_ids)
        ctx = self._build_context(asset, plan, profile, check_ids)

        for adapter, reason in adapters:
            name = str(getattr(adapter, "name", "unknown"))
            if reason:
                engine_status[name] = {"status": "skipped", "reason": reason, "findings": 0}
                continue
            engine_started = time.time()
            try:
                if dry_run:
                    outputs: list[dict] = []
                    status = "dry_run"
                else:
                    outputs = list(adapter.run(asset, ctx) or [])
                    status = "done"
            except Exception as exc:  # noqa: BLE001 - 单引擎隔离，不中断整次扫描
                outputs = []
                status = "error"
                errors.append(f"{name}: {exc}")
                log.warn("scan.engine.error", task_id=task_id, engine=name, error=str(exc))
            cost_ms = int((time.time() - engine_started) * 1000)
            raw_results.extend(outputs)
            engine_status[name] = {
                "status": status, "cost_ms": cost_ms,
                "findings": len([r for r in outputs if r.get("kind") != "host_summary"]),
                "error": errors[-1] if status == "error" else None,
            }
            stages.append(f"engine:{name}")

        # 包清单通常 1500~2500 个包，逐条入库会把报告淹没；默认只保留"有 CPE 映射的
        # 安全相关组件"（comp_map 约 66 个）作为 component 事实，其余仅用于整体统计。
        raw_results = self._filter_package_facts(raw_results)

        # ---- CVE 匹配（nmap/pkgs 产出的 component 事实）----
        matched: list[dict] = []
        match_stats: dict[str, Any] = {}
        facts = self._component_facts(raw_results, asset)
        matcher = None
        try:
            from .cve import matcher as matcher_mod

            matcher = matcher_mod
        except Exception as exc:  # noqa: BLE001 - CVE 组件缺失时降级为"只有事实没有漏洞"
            log.warn("scan.matcher.unavailable", error=str(exc))
            engine_status.setdefault("matcher", {
                "status": "skipped", "reason": "matcher_unavailable", "findings": 0,
            })
        if matcher is not None:
            try:
                if facts:
                    result = matcher.match_facts(
                        self.store, self.cfg, facts, archive_map=self._archive_map()
                    )
                    matched = result.get("matched") or []
                    match_stats = result.get("stats") or {}
                    if matched:
                        raw_results.extend(
                            normalize.cve_to_findings(
                                matched, asset_id=asset_id, task_id=task_id,
                                snapshot_id=snapshot_id,
                            )
                        )
                    engine_status.setdefault("matcher", {
                        "status": "done", "findings": len(matched), "cost_ms": 0,
                        "stats": match_stats,
                    })
                else:
                    engine_status.setdefault("matcher", {
                        "status": "skipped", "reason": "no component facts", "findings": 0,
                    })
            except Exception as exc:  # noqa: BLE001 - 匹配失败保留事实、问题缺省
                errors.append(f"matcher: {exc}")
                log.warn("scan.matcher.error", task_id=task_id, error=str(exc))
                engine_status.setdefault("matcher", {"status": "error", "error": str(exc),
                                                     "findings": 0})

        # ---- 归一 ----
        normalized = normalize.build_findings(
            self.store, raw_results, asset=asset, task_id=task_id,
            snapshot_id=snapshot_id, engine_status=engine_status,
        )
        problems = normalized["problems"]
        facts_all = normalized["facts"]

        # ---- 生命周期：未复现既有 finding（引擎失败时不做，避免误判已修复）----
        engine_failed = any(
            (s or {}).get("status") in ("error", "timeout") for s in engine_status.values()
        )
        lifecycle = {"checked": 0, "fixed": [], "missing": [], "skipped": engine_failed}
        if not engine_failed:
            lifecycle = normalize.finalize_missing(
                self.store, asset_id=asset_id,
                seen_keys=normalized["seen_keys"], snapshot_id=snapshot_id,
            )

        # ---- checkpoint / 资产事实 / 快照项 ----
        checkpoint = normalize.build_checkpoint(
            engine_status=engine_status, problems=problems, task_id=task_id,
            asset_id=asset_id, cve_cache_ready=cve_cache_ready,
        )
        checkpoint["match_stats"] = match_stats
        checkpoint["lifecycle"] = {
            "fixed": len(lifecycle.get("fixed") or []),
            "missing": len(lifecycle.get("missing") or []),
        }
        stask.save_checkpoint(self.store, task_id, checkpoint)

        self._update_asset_facts(asset_id, raw_results, checkpoint)

        # ---- 任务终态 ----
        status = self._task_status(engine_status)
        cost_ms = int((time.time() - started) * 1000)
        error = "; ".join(errors)[:2000] or None
        finished = stask.finish(
            self.store, task_id, status, error=error,
            snapshot_id=snapshot_id, cost_ms=cost_ms,
        )
        # 任务事件（供检测模块/仪表盘消费）
        self._emit_event("scan_task", {
            "task_id": task_id, "run_id": task.get("run_id"), "plan_id": plan.get("plan_id"),
            "asset_id": asset_id, "status": status, "cost_ms": cost_ms,
            "snapshot_id": snapshot_id,
            "engines": {k: v.get("status") for k, v in engine_status.items()},
        })

        snapshot_items = normalize.build_snapshot_items(normalized["findings"])
        actionable = [p for p in problems if p.get("confidence") in ("exact", "range", "tool")]
        cpe_only = [p for p in problems if p.get("confidence") == "cpe_only"]
        counts = {
            "findings": normalized["counts"]["findings"],
            "problems": len(problems),
            "actionable": len(actionable),
            "cpe_only": len(cpe_only),
            "cve": len([p for p in problems if p.get("kind") == "cve"]),
            "ports": len([f for f in facts_all if f.get("kind") == "port"]),
            "components": len([f for f in facts_all if f.get("kind") == "component"]),
            "by_severity": normalized["counts"]["by_severity"],
        }
        return {
            "task": finished or task,
            "engine_status": engine_status,
            "snapshot_items": snapshot_items,
            "counts": counts,
            "stages": stages,
            "lifecycle": lifecycle,
            "match_stats": match_stats,
            "duration_ms": int((time.time() - started) * 1000),
        }

    # ------------------------------------------------------------------ 收尾
    def _finalize(
        self, *, plan: dict, profile: dict, run_id: str, snapshot_id: str,
        tasks: list[dict], assets: list[dict], outcome: dict, slot: str,
        write_report: bool, started: float, trigger: str,
    ) -> dict:
        items = outcome.get("snapshot_items") or []
        sstore.add_snapshot_items(self.store, snapshot_id, items)
        current_tasks = [sstore.get_task(self.store, t.get("task_id")) or t for t in tasks]
        task_status = stask.summary(current_tasks)
        stats = {
            "engines": outcome.get("engine_status") or {},
            "counts": outcome.get("counts") or {},
            "tasks": task_status,
            "profile": profile.get("name"),
            "trigger": trigger,
            "assets": [a.get("asset_id") for a in assets],
            "findings": len(items),
        }
        sstore.update_snapshot_stats(self.store, snapshot_id, {
            "engines": outcome.get("engine_status") or {},
            "counts": outcome.get("counts") or {},
            "tasks": task_status,
            "findings": len(items),
        })
        # 首次全量 / 季度计划自动登记基线
        snap = sstore.get_snapshot(self.store, snapshot_id)
        prev = sstore.previous_snapshot(self.store, snapshot_id)
        if prev is None or plan.get("kind") == "quarterly":
            sstore.set_base_snapshot(self.store, snapshot_id)

        diff_result: dict = {}
        try:
            from . import diff as diff_mod

            if prev:
                diff_result = diff_mod.build(self.store, snapshot_id, prev["snapshot_id"])
            else:
                diff_result = {"cur": snapshot_id, "prev": None, "items": [],
                               "stats": {"new": len(items), "fixed": 0, "persisting": 0,
                                         "regressed": 0, "total": len(items)}}
        except Exception as exc:  # noqa: BLE001
            log.warn("scan.diff.error", snapshot_id=snapshot_id, error=str(exc))
            diff_result = {"cur": snapshot_id, "prev": None, "error": str(exc), "stats": {}}

        coverage_result: dict = {}
        try:
            from . import coverage as coverage_mod

            coverage_result = coverage_mod.compute(self.store, snapshot_id, self.cfg)
        except Exception as exc:  # noqa: BLE001
            log.warn("scan.coverage.error", snapshot_id=snapshot_id, error=str(exc))
            coverage_result = {"snapshot_id": snapshot_id, "coverage": 0.0,
                               "error": str(exc), "uncovered": []}

        report_result: dict = {}
        if write_report:
            report_result = self._write_report(snapshot_id, diff_result, coverage_result)

        # 计划 last_run/next_run
        try:
            if plan.get("plan_id") and sstore.get_plan(self.store, plan.get("plan_id")):
                sstore.touch_plan_run(
                    self.store, plan["plan_id"], _now(), scheduler.next_run(plan)
                )
        except Exception as exc:  # noqa: BLE001
            log.warn("scan.plan.touch_failed", plan_id=plan.get("plan_id"), error=str(exc))

        duration_ms = int((time.time() - started) * 1000)
        summary = {
            "ok": task_status.get("by_status", {}).get("failed", 0) == 0,
            "plan_id": plan.get("plan_id"),
            "run_id": run_id,
            "snapshot_id": snapshot_id,
            "slot": slot,
            "trigger": trigger,
            "profile": profile.get("name"),
            "tasks": [sstore.get_task(self.store, t.get("task_id")) or t for t in tasks],
            "task_summary": task_status,
            "assets": [{"asset_id": a.get("asset_id"), "ip": a.get("ip")} for a in assets],
            "counts": outcome.get("counts") or {},
            "engine_status": outcome.get("engine_status") or {},
            "snapshot": sstore.get_snapshot(self.store, snapshot_id),
            "diff": diff_result,
            "coverage": coverage_result,
            "report": report_result,
            "duration_ms": duration_ms,
            "stats": stats,
        }
        self._audit("scan.run", target=f"{plan.get('plan_id')}/{snapshot_id}",
                    ok=bool(summary["ok"]),
                    detail={"run_id": run_id, "counts": summary["counts"],
                            "duration_ms": duration_ms,
                            "diff": diff_result.get("stats")})
        return summary

    def _write_report(self, snapshot_id: str, diff_result: dict, coverage_result: dict) -> dict:
        try:
            from . import report as report_mod

            result = report_mod.export(
                self.store, self.cfg, snapshot_id, fmt="html",
                diff=diff_result, coverage=coverage_result,
            )
            log.info("scan.report.written", snapshot_id=snapshot_id,
                     path=result.get("path"), ok=result.get("ok"))
            return result
        except Exception as exc:  # noqa: BLE001 - 报告失败不影响扫描结果
            log.warn("scan.report.error", snapshot_id=snapshot_id, error=str(exc))
            return {"ok": False, "error": str(exc), "snapshot_id": snapshot_id}

    # ------------------------------------------------------------------ 引擎选择
    def _load_adapters(self) -> list:
        if self._adapters is not None:
            return list(self._adapters)
        try:
            from .engines import build_adapters

            self._adapters = list(build_adapters(self.cfg))
        except Exception as exc:  # noqa: BLE001 - 引擎包缺失时降级为"无引擎"
            log.warn("scan.adapters.unavailable", error=str(exc))
            self._adapters = []
        return list(self._adapters)

    def _select_adapters(
        self, profile: dict, asset: dict, check_ids: list[str] | None,
    ) -> list[tuple[Any, str | None]]:
        """返回 ``[(adapter, skip_reason_or_None)]``；不可用/不适用/未选择都显式标记。"""
        selected = [str(x) for x in (profile.get("engines") or [])]
        adapters = self._load_adapters()
        wanted = set(selected)
        if check_ids:
            wanted |= self._engines_for_checks(check_ids)
        out: list[tuple[Any, str | None]] = []
        for adapter in adapters:
            name = str(getattr(adapter, "name", "unknown"))
            if name not in wanted:
                out.append((adapter, "not_selected"))
                continue
            try:
                if not adapter.available():
                    out.append((adapter, "engine_unavailable"))
                    continue
                if not adapter.supports(asset, str(profile.get("name") or "weekly")):
                    out.append((adapter, "not_applicable"))
                    continue
            except Exception as exc:  # noqa: BLE001
                out.append((adapter, f"probe_error: {exc}"))
                continue
            out.append((adapter, None))
        return out

    @staticmethod
    def _engines_for_checks(check_ids: list[str]) -> set[str]:
        engines: set[str] = set()
        for check in check_ids or []:
            text = str(check).upper()
            if text.startswith(("PORT-", "SVC-", "HOST-")):
                engines.add("nmap")
            elif text.startswith("PKG-"):
                engines.add("pkgs")
            elif text.startswith("LYNIS-"):
                engines.add("lynis")
            elif text.startswith("TLS-"):
                engines.add("testssl")
            else:
                engines.add("nuclei")
        return engines

    def _build_context(self, asset: dict, plan: dict, profile: dict,
                       check_ids: list[str] | None):
        try:
            from .engines import ScanContext
        except Exception:  # noqa: BLE001 - 引擎包缺失时用鸭子类型占位
            class ScanContext:  # type: ignore[no-redef]
                def __init__(self, **kwargs):
                    self.__dict__.update(kwargs)

        ports = str(profile.get("ports") or "top:200")
        declared = sassets.declared_ports(asset)
        # 靶场资产（role=lab）的容器端口在 18000+，不在 nmap top-N 里；
        # 对这类资产把 top:N 自动降级为"台账声明端口"扫描，避免"扫了却没覆盖"。
        if declared and str(asset.get("role") or "") == "lab" and ports.lower().startswith("top"):
            ports = "declared"
        port_override = self._ports_from_checks(check_ids)
        if port_override:
            ports = ",".join(str(p) for p in port_override)
        extra = {
            "declared_ports": declared,
            "tls_ports": sassets.tls_ports(asset) or [443, 8443],
            "web_targets": sassets.web_targets(asset) if sassets.declared_ports(asset) else [],
            "check_ids": list(check_ids or []),
        }
        return ScanContext(
            asset=asset,
            plan=plan,
            profile=str(profile.get("name") or "weekly"),
            ports=ports,
            service_detect=bool(profile.get("service_detect", True)),
            timeout_sec=int(profile.get("timeout_sec") or cfg_get(self.cfg, "scan.engine_timeout_sec", 900)),
            rate_limit=int(profile.get("rate_limit") or cfg_get(self.cfg, "scan.gates.pps", 500)),
            extra=extra,
        )

    @staticmethod
    def _ports_from_checks(check_ids: list[str] | None) -> list[int]:
        ports: list[int] = []
        for check in check_ids or []:
            text = str(check)
            for prefix in ("PORT-", "SVC-", "TLS-"):
                if text.upper().startswith(prefix):
                    payload = text[len(prefix):].split("/")[0]
                    if payload.isdigit():
                        ports.append(int(payload))
                    break
        return sorted(set(ports))

    # ------------------------------------------------------------------ CVE 数据
    def _cve_cache_ready(self) -> bool:
        try:
            return sstore.cve_count(self.store) > 0
        except Exception:  # noqa: BLE001
            return False

    def _known_mapped_components(self) -> set[str]:
        """``cve_component_map`` 里的本地组件名集合（一次查询，进程内缓存）。"""
        if self._mapped_components is None:
            try:
                rows = self.store.query("SELECT DISTINCT comp_norm FROM cve_component_map")
                self._mapped_components = {str(r.get("comp_norm")) for r in rows if r.get("comp_norm")}
            except Exception as exc:  # noqa: BLE001 - 映射表缺失时不过滤
                log.warn("scan.cmap.query_failed", error=str(exc))
                self._mapped_components = set()
        return self._mapped_components

    def _filter_package_facts(self, raw_results: list[dict]) -> list[dict]:
        """按配置过滤包清单事实：``scan.pkgs.fact_filter = mapped|all``。

        - ``mapped``（默认）：只保留 comp_map 里有 CPE 映射的安全相关组件，避免
          1500+ 个包逐条入 finding（报告/diff 会失去可读性）；
        - ``all``：全量入库（做包清单完整性演示时用）。
        """
        mode = str(cfg_get(self.cfg, "scan.pkgs.fact_filter", "mapped") or "mapped").lower()
        if mode != "mapped":
            return list(raw_results)
        allow = self._known_mapped_components()
        if not allow:
            return list(raw_results)
        kept: list[dict] = []
        for raw in raw_results or []:
            if (raw.get("engine") == "pkgs" and raw.get("kind") == "component"
                    and raw.get("comp_norm") not in allow):
                continue
            kept.append(raw)
        return kept

    def _component_facts(self, raw_results: list[dict], asset: dict) -> list[dict]:
        facts: list[dict] = []
        asset_id = asset.get("asset_id")
        distro = (asset.get("facts_json") or {}).get("distro") or asset.get("os_version")
        for raw in raw_results or []:
            if raw.get("kind") != "component":
                continue
            evidence = raw.get("evidence") or {}
            source = str(evidence.get("source") or raw.get("engine") or "")
            if raw.get("engine") == "pkgs":
                source = "dpkg"
            facts.append({
                "asset_id": asset_id,
                "comp_norm": raw.get("comp_norm") or evidence.get("product") or "",
                "version": raw.get("version") or evidence.get("version") or "",
                "cpe": raw.get("cpe") or evidence.get("cpe") or "",
                "source": source,
                "distro": evidence.get("distro") or distro,
                "raw": {k: evidence.get(k) for k in ("product", "vendor", "package", "port")},
            })
        return [f for f in facts if f.get("comp_norm")]

    def _archive_map(self) -> dict:
        """IF-18：靶场模块档案 → {cve: record} 映射（档案不存在时返回空 dict）。"""
        try:
            from ..vuln import store as vstore

            rows = vstore.list_records(self.store, limit=2000)
            archive: dict[str, dict] = {}
            for record in rows:
                cve = str(record.get("cve") or "").strip()
                if cve:
                    archive[cve] = {
                        "id": record.get("id"),
                        "title": record.get("title"),
                        "cvss_score": record.get("cvss_score"),
                        "severity": record.get("severity"),
                        "fix": record.get("fix"),
                        "status": record.get("status"),
                    }
            return archive
        except Exception as exc:  # noqa: BLE001 - 档案未初始化时不影响匹配
            log.warn("scan.archive.unavailable", error=str(exc))
            return {}

    # ------------------------------------------------------------------ 事件/审计
    def _emit_event(self, event_type: str, raw: dict) -> None:
        payload = {
            "event_type": event_type,
            "source_layer": "scan",
            "source_product": "hornwork.scan",
            "raw": raw,
        }
        try:
            event = schema.new_event(
                event_type, "scan", "hornwork.scan", self.cfg,
                network={"src_ips": raw.get("src_ips") or [], "dst_ips": raw.get("dst_ips") or []},
                raw=raw,
            )
        except Exception:  # noqa: BLE001 - 事件字段不合法时退化为半成品
            event = payload
            event["ts"] = _now()
            event.setdefault("event_id", schema.dedup_key(event_type, _now()))
        try:
            self.store.insert_event(schema.normalize_event(event, self.cfg) if "event_id" not in event else event,
                                    engine="scan")
        except Exception as exc:  # noqa: BLE001
            log.warn("scan.event.persist_failed", event_type=event_type, error=str(exc))
        if self.event_sink is not None:
            try:
                self.event_sink(event)
            except Exception as exc:  # noqa: BLE001 - 总线失败不阻断扫描
                log.warn("scan.event.sink_failed", event_type=event_type, error=str(exc))

    def _emit_window(self, phase: str, *, plan: dict, run_id: str,
                     assets: list[dict], profile: dict) -> None:
        """发 ``scan_window`` 事件（IF-23）：检测模块据此在窗口内对自扫流量降级判定。"""
        src_ips = self._local_ips()
        dst_ips = [str(a.get("ip")) for a in assets]
        start = _now()
        self._emit_event("scan_window", {
            "phase": phase,
            "plan_id": plan.get("plan_id"),
            "run_id": run_id,
            "start": start,
            "end": start if phase == "end" else None,
            "src_ips": src_ips,
            "dst_ips": dst_ips,
            "profile": profile.get("name"),
            "port_spec": profile.get("ports"),
            "engines": profile.get("engines"),
            "window_sec": int(cfg_get(self.cfg, "scan.gates.window_grace_sec", 600) or 600),
        })
        # 立即通知 daemon 刷新窗口缓存（best effort）：否则 10s 周期刷新会让短扫描
        # 前几秒的探测流量仍被检测模块判成"扫描攻击"，自扰治理只在窗口后半段生效。
        self._notify_window_refresh()

    def _notify_window_refresh(self) -> None:
        try:
            from ..client import CtlClient

            socket_path = str(cfg_get(self.cfg, "ctl.socket", "/run/hornwork/ctl.sock"))
            client = CtlClient(socket_path, timeout=2.0)
            if client.available():
                client.call("scan.window_refresh", {})
        except Exception as exc:  # noqa: BLE001 - daemon 未运行/权限不足时忽略
            log.info("scan.window.notify_skipped", error=str(exc))

    def _local_ips(self) -> list[str]:
        """本机源地址集合（写进 scan_window，供检测模块判定"自扫流量"）。"""
        ips = ["127.0.0.1"]
        for extra in cfg_get(self.cfg, "scan.local_ips", []) or []:
            text = str(extra).strip()
            if text and text not in ips:
                ips.append(text)
        try:
            import socket

            for info in socket.getaddrinfo(socket.gethostname(), None):
                host = str(info[4][0]) if len(info) > 4 else ""
                if host and host not in ips:
                    ips.append(host)
        except OSError:
            pass
        return ips

    def _audit(self, action: str, target: str, ok: bool, detail: dict | None = None) -> None:
        if self.audit_sink is not None:
            try:
                self.audit_sink(action, target, ok, detail or {})
                return
            except Exception as exc:  # noqa: BLE001
                log.warn("scan.audit.sink_failed", action=action, error=str(exc))
        try:
            from ..respond.actions import ActionExecutor

            ActionExecutor(self.store, self.cfg).audit_event(
                action=action, target=target, mode="enforce", ok=ok,
            )
        except Exception as exc:  # noqa: BLE001
            log.warn("scan.audit.failed", action=action, error=str(exc))

    # ------------------------------------------------------------------ 辅助
    @staticmethod
    def _task_status(engine_status: dict[str, dict]) -> str:
        """任务终态：引擎不可用 → partial（覆盖率按 partial 计）；不适用/未选择不算失败。"""
        states = [str((v or {}).get("status") or "") for v in (engine_status or {}).values()]
        reasons = [str((v or {}).get("reason") or "") for v in (engine_status or {}).values()]
        ran = [s for s in states if s in ("done", "error", "timeout", "dry_run")]
        if not ran:
            return "partial" if states else "failed"
        if any(s in ("error", "timeout") for s in ran):
            return "partial"
        if "engine_unavailable" in reasons:
            return "partial"
        return "done"

    def _update_asset_facts(self, asset_id: str, raw_results: list[dict],
                            checkpoint: dict) -> None:
        services = []
        ports = []
        for raw in raw_results or []:
            if raw.get("kind") == "port":
                evidence = raw.get("evidence") or {}
                ports.append(evidence.get("port"))
            elif raw.get("kind") == "component":
                evidence = raw.get("evidence") or {}
                if evidence.get("port"):
                    services.append({
                        "port": evidence.get("port"),
                        "service": evidence.get("service"),
                        "product": evidence.get("product"),
                        "version": evidence.get("version"),
                    })
        facts = {
            "last_scan": _now(),
            "open_ports": sorted({int(p) for p in ports if p}),
            "services": services[:100],
            "domains": {k: v.get("status") for k, v in (checkpoint.get("domains") or {}).items()},
        }
        try:
            sstore.update_asset_facts(self.store, asset_id, facts)
        except Exception as exc:  # noqa: BLE001
            log.warn("scan.asset.facts_failed", asset_id=asset_id, error=str(exc))
