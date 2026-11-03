"""幂等执行引擎：check → (dry-run | backup → apply → verify) → 高危项定时回滚保险。

设计要点：
- 三段式不合并：apply 的返回码不作为成功依据，必须独立 verify；
- 单步失败就地还原该步备份，不污染其它项（失败隔离）；
- 每项执行前备份 targets，回滚粒度是 run（按 run 逆序撤销）；
- high 风险项未带 --yes-risk 只标 skipped_unconfirmed，不静默执行；
- 带 guard_seconds 的项由 systemd-run 定时器做“改坏了自动退回”的安全垫。
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

from . import core, items as items_mod, plan as plan_mod

TERMINAL_OK = {"verified", "already_ok"}
FAILED = {"failed", "verify_failed"}


def _result(item: items_mod.Item, run_id: str) -> dict[str, Any]:
    return {
        "item_id": item.id,
        "title": item.title,
        "risk": item.risk,
        "phase": "pending",
        "status": "pending",
        "check_rc": None,
        "apply_rc": None,
        "verify_rc": None,
        "duration_ms": 0,
        "before_state": "",
        "after_state": "",
        "diff": "",
        "backup": None,
        "guard": None,
        "error": "",
    }


def _preview(item: items_mod.Item, check_out: str) -> str:
    lines = [f"- 目标：{', '.join(item.targets) if item.targets else '（无文件目标，直接执行命令）'}"]
    lines.append(f"- 计划动作：{item.apply.splitlines()[0][:160]}")
    if check_out:
        lines.append(f"- 当前检查输出：{check_out[:300]}")
    if item.guard_seconds:
        lines.append(f"- 安全垫：执行后 {item.guard_seconds}s 内未确认则自动回滚")
    return "\n".join(lines)


def save_run(run: dict[str, Any], cfg: dict | None = None) -> Path:
    path = core.state(cfg)["runs"] / f"{core.check_id(run['run_id'])}.json"
    return core.write_json(path, run)


def load_run(run_id: str, cfg: dict | None = None) -> dict[str, Any]:
    path = core.state(cfg)["runs"] / f"{core.check_id(run_id)}.json"
    run = core.read_json(path)
    if not run:
        raise FileNotFoundError(f"运行记录不存在：{path}")
    return run


def arm_guard(run: dict[str, Any], item: items_mod.Item) -> dict[str, Any] | None:
    """高危项执行后启动定时回滚；确认后由 confirm() 停掉。"""
    if not item.guard_seconds:
        return None
    unit = f"hornwork-harden-guard-{item.id.lower()}"
    py = sys.executable
    command = (
        f"systemd-run --unit={unit} --on-active={item.guard_seconds} --collect "
        f"--setenv=PYTHONPATH=/opt/hornwork --working-directory=/opt/hornwork "
        f"{py} -m hornwork.harden rollback --run {run['run_id']} --item {item.id} --auto"
    )
    res = core.sh(f"systemctl stop {unit}.timer {unit}.service 2>/dev/null; {command}", timeout=60)
    return {
        "unit": unit,
        "seconds": item.guard_seconds,
        "deadline": core.parse_ts(core.utc_now()).timestamp() + item.guard_seconds,
        "armed": res["rc"] == 0,
        "output": (res["out"] or res["err"])[:500],
    }


def disarm_guard(run: dict[str, Any], item_id: str) -> dict[str, Any]:
    unit = f"hornwork-harden-guard-{item_id.lower()}"
    res = core.sh(f"systemctl stop {unit}.timer {unit}.service 2>/dev/null; systemctl reset-failed {unit} 2>/dev/null", timeout=30)
    return {"unit": unit, "stopped": res["rc"] == 0, "output": (res["out"] or res["err"])[:300]}


def apply_plan(
    plan: dict[str, Any],
    mode: str = "apply",
    batches: list[int] | None = None,
    yes_risk: bool = False,
    dry_run: bool = False,
    only: list[str] | None = None,
    cfg: dict | None = None,
    operator: str | None = None,
) -> dict[str, Any]:
    items = {item.id: item for item in items_mod.load_items()}
    paths = core.state(cfg)
    run: dict[str, Any] = {
        "run_id": core.new_id("run"),
        "plan_id": plan["plan_id"],
        "asset_id": plan.get("asset_id", "A"),
        "role": plan.get("role", "A"),
        "mode": "dry_run" if dry_run else mode,
        "operator": operator or core.sh("id -un").get("out", "unknown"),
        "started_at": core.utc_now(),
        "finished_at": None,
        "status": "running",
        "results": [],
    }
    selected = plan.get("items", [])
    if batches:
        selected = [entry for entry in selected if entry["batch"] in batches]
    if only:
        selected = [entry for entry in selected if entry["id"] in only]
    save_run(run, cfg)
    core.emit_event(cfg, "plan" if mode == "check" else "apply", {"run_id": run["run_id"], "plan_id": plan["plan_id"], "items": len(selected)})

    for entry in selected:
        item = items.get(entry["id"])
        if item is None:
            continue
        result = _result(item, run["run_id"])
        started = time.time()
        # ------------------------------------------------ 1) check（只读）
        check = core.sh(item.check, timeout=item.timeout)
        result["check_rc"] = check["rc"]
        result["before_state"] = (check["out"] or check["err"])[:2000]
        result["phase"] = "checked"
        if item.manual_reason:
            result["status"] = "manual"
            result["error"] = item.manual_reason
            result["duration_ms"] = int((time.time() - started) * 1000)
            run["results"].append(result)
            save_run(run, cfg)
            continue
        if check["rc"] == 0:
            result["status"] = "already_ok"
            result["phase"] = "verified"
            result["duration_ms"] = int((time.time() - started) * 1000)
            run["results"].append(result)
            save_run(run, cfg)
            core.emit_event(cfg, "verify", {"run_id": run["run_id"], "item": item.id, "status": "already_ok"})
            continue
        if mode == "check" or dry_run:
            result["status"] = "would_apply"
            result["diff"] = _preview(item, result["before_state"])
            result["duration_ms"] = int((time.time() - started) * 1000)
            run["results"].append(result)
            save_run(run, cfg)
            continue
        if item.risk == "high" and not yes_risk:
            result["status"] = "skipped_unconfirmed"
            result["error"] = "高危项未带 --yes-risk，保持待确认"
            result["duration_ms"] = int((time.time() - started) * 1000)
            run["results"].append(result)
            save_run(run, cfg)
            continue
        # ------------------------------------------------ 2) 备份 → apply
        backup = core.backup_paths(list(item.targets), run["run_id"], item.id, paths["backups"])
        result["backup"] = backup
        apply_res = core.sh(item.apply, timeout=item.timeout)
        result["apply_rc"] = apply_res["rc"]
        result["phase"] = "applied"
        if apply_res["rc"] != 0:
            restored = core.restore_backup(backup)
            result["status"] = "failed"
            result["error"] = (apply_res["out"] or apply_res["err"])[:2000]
            result["after_state"] = f"apply 失败，已就地还原：{restored}"
            result["duration_ms"] = int((time.time() - started) * 1000)
            run["results"].append(result)
            save_run(run, cfg)
            core.emit_event(cfg, "apply", {"run_id": run["run_id"], "item": item.id, "status": "failed"})
            continue
        # ------------------------------------------------ 3) verify（外部视角）
        verify = core.sh(item.verify, timeout=item.timeout)
        result["verify_rc"] = verify["rc"]
        result["after_state"] = (verify["out"] or verify["err"])[:2000]
        result["status"] = "verified" if verify["rc"] == 0 else "verify_failed"
        result["phase"] = "verified" if verify["rc"] == 0 else "verify_failed"
        result["duration_ms"] = int((time.time() - started) * 1000)
        if item.guard_seconds:
            result["guard"] = arm_guard(run, item)
        run["results"].append(result)
        save_run(run, cfg)
        core.emit_event(cfg, "verify", {"run_id": run["run_id"], "item": item.id, "status": result["status"]})

    for result in run["results"]:
        if result["status"] in FAILED:
            run["status"] = "partially_failed"
            break
    else:
        run["status"] = "succeeded"
    run["finished_at"] = core.utc_now()
    run["counts"] = counts(run)
    save_run(run, cfg)
    return run


def confirm(run: dict[str, Any], item_ids: list[str] | None = None, cfg: dict | None = None) -> dict[str, Any]:
    """确认高危项变更：停掉定时回滚保险。"""
    confirmed = []
    for result in run["results"]:
        if item_ids and result["item_id"] not in item_ids:
            continue
        if not result.get("guard"):
            continue
        info = disarm_guard(run, result["item_id"])
        result["guard"]["confirmed_at"] = core.utc_now()
        result["guard"]["stopped"] = info["stopped"]
        confirmed.append(result["item_id"])
    save_run(run, cfg)
    core.emit_event(cfg, "apply", {"run_id": run["run_id"], "confirmed": confirmed})
    return {"run_id": run["run_id"], "confirmed": confirmed}


def rollback_run(
    run: dict[str, Any],
    item_ids: list[str] | None = None,
    cfg: dict | None = None,
    actor: str = "manual",
) -> dict[str, Any]:
    """按 run 逆序回滚：L1 文件快照 → L2 反向动作 → 不可回滚项如实标记。"""
    items = {item.id: item for item in items_mod.load_items()}
    items_index = {result["item_id"]: result for result in run["results"]}
    targets = item_ids or [result["item_id"] for result in run["results"]]
    done: list[dict[str, Any]] = []
    for item_id in reversed(targets):
        result = items_index.get(item_id)
        if result is None or result["status"] == "already_ok":
            continue
        item = items.get(item_id)
        entry: dict[str, Any] = {"item_id": item_id, "actions": [], "check_after": None}
        backup = result.get("backup")
        if backup and backup.get("entries"):
            entry["actions"] = core.restore_backup(backup)
            # 还原文件后执行“生效钩子”（如 sysctl --system / systemctl reload ssh），
            # 否则配置回到旧值但运行中的服务仍是新值——这是最常见的假回滚。
            if item and item.reverse:
                hook = core.sh(item.reverse, timeout=item.timeout)
                entry["actions"].append(
                    {"path": "post_restore_hook", "restored": "ok" if hook["rc"] == 0 else "failed", "output": (hook["out"] or hook["err"])[:500]}
                )
        elif item and item.reverse:
            res = core.sh(item.reverse, timeout=item.timeout)
            entry["actions"] = [{"path": "reverse", "restored": "ok" if res["rc"] == 0 else "failed", "output": (res["out"] or res["err"])[:500]}]
        elif item and item.rollback_mode == "manual":
            entry["actions"] = [{"path": "manual", "restored": "manual_required"}]
        else:
            entry["actions"] = [{"path": "none", "restored": "no_backup"}]
        if item:
            after = core.sh(item.check, timeout=item.timeout)
            entry["check_after"] = "not_compliant(已回到加固前)" if after["rc"] != 0 else "still_compliant(未生效)"
        done.append(entry)
        result["rollback"] = entry
        result["status_after_rollback"] = entry["check_after"]
    run["rollback"] = {
        "actor": actor,
        "at": core.utc_now(),
        "items": done,
        "success": sum(1 for d in done if d["check_after"] and d["check_after"].startswith("not_compliant")),
        "attempted": len(done),
    }
    if run.get("status") != "rolled_back":
        run["status_after_rollback"] = run.get("status")
    save_run(run, cfg)
    core.emit_event(cfg, "rollback", {"run_id": run["run_id"], "items": [d["item_id"] for d in done], "actor": actor})
    return run


def counts(run: dict[str, Any]) -> dict[str, int]:
    result: dict[str, int] = {}
    for entry in run.get("results", []):
        result[entry["status"]] = result.get(entry["status"], 0) + 1
    result["total"] = len(run.get("results", []))
    return result


def completion_rate(run: dict[str, Any]) -> float:
    counts_map = counts(run)
    applicable = counts_map.get("total", 0) - counts_map.get("manual", 0)
    done = counts_map.get("verified", 0) + counts_map.get("already_ok", 0)
    return round(done / applicable, 4) if applicable else 0.0
