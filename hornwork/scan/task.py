"""扫描任务的状态机与断点续跑。

状态转移（只允许这些边）::

    queued ─claim─▶ running ─┬─▶ done     全部资产×引擎成功（或有明确"不适用"）
                            ├─▶ partial  部分引擎失败/超时，数据可用（覆盖率按 partial 计）
                            ├─▶ failed   闸门拒绝/全部失败
                            └─▶ aborted  人工取消/超窗口
    done/partial/failed ─retry(仅失败部分)─▶ queued

幂等靠 ``scan_task`` 的 ``UNIQUE(plan_id, asset_id, slot)``：重复触发时
:func:`create_tasks` 直接返回已有任务（``created=False``），不依赖内存标志。
断点粒度为"资产 × 引擎"：``checkpoint.engines`` 记录每个引擎的结果，续跑时跳过已完成部分。
"""

from __future__ import annotations

from typing import Any

from .. import schema
from ..log import get_logger
from . import store as sstore

log = get_logger("scan.task")

#: 可重试的终态
RETRYABLE = ("failed", "partial", "aborted")


def create_tasks(
    store: Any,
    plan: dict,
    assets: list[dict],
    run_id: str,
    slot: str,
    *,
    snapshot_id: str | None = None,
    status: str = "queued",
) -> list[dict]:
    """为一次运行创建任务（每资产一条；槽位冲突时返回已有任务）。"""
    out: list[dict] = []
    for asset in assets:
        task, created = sstore.create_task(
            store,
            {
                "run_id": run_id,
                "plan_id": plan.get("plan_id"),
                "asset_id": asset.get("asset_id"),
                "slot": slot,
                "profile": plan.get("profile") or "weekly",
                "status": status,
                "snapshot_id": snapshot_id,
                "started_at": None if status == "queued" else schema.utc_now(),
            },
        )
        task["_created"] = created
        out.append(task)
    return out


def claim(store: Any, task_id: str) -> dict | None:
    """queued → running，登记 started_at。"""
    task = sstore.get_task(store, task_id)
    if not task:
        return None
    if task.get("status") == "running":
        return task
    sstore.update_task(
        store, task_id, status="running", stage="claimed",
        started_at=task.get("started_at") or schema.utc_now(),
    )
    return sstore.get_task(store, task_id)


def save_checkpoint(store: Any, task_id: str, patch: dict) -> dict:
    """合并式写 checkpoint（``{"engines":...}`` / ``{"domains":...}`` / ``{"done_assets":...}``）。"""
    task = sstore.get_task(store, task_id)
    checkpoint = dict((task or {}).get("checkpoint") or {})
    for key, value in (patch or {}).items():
        if isinstance(value, dict) and isinstance(checkpoint.get(key), dict):
            checkpoint[key].update(value)
        else:
            checkpoint[key] = value
    sstore.update_task(store, task_id, checkpoint=checkpoint)
    return checkpoint


def finish(
    store: Any,
    task_id: str,
    status: str,
    *,
    error: str | None = None,
    snapshot_id: str | None = None,
    cost_ms: int | None = None,
) -> dict | None:
    """任务进入终态并写 finished_at/耗时。"""
    if status not in ("done", "partial", "failed", "aborted"):
        raise ValueError(f"非法终态：{status}")
    task = sstore.get_task(store, task_id)
    fields: dict[str, Any] = {
        "status": status,
        "finished_at": schema.utc_now(),
        "stage": "finished",
    }
    if error is not None:
        fields["error"] = str(error)[:4000]
    if snapshot_id:
        fields["snapshot_id"] = snapshot_id
    if cost_ms is not None:
        fields["cost_ms"] = int(cost_ms)
    sstore.update_task(store, task_id, **fields)
    finished = sstore.get_task(store, task_id)
    log.info(
        "scan.task.finished",
        task_id=task_id,
        status=status,
        plan_id=(task or {}).get("plan_id"),
        asset_id=(task or {}).get("asset_id"),
        cost_ms=cost_ms,
    )
    return finished


def retry(store: Any, run_id: str, statuses: tuple[str, ...] = RETRYABLE) -> list[dict]:
    """把失败/部分完成的任务重置为 queued（只重跑未完成部分由 checkpoint 决定）。"""
    rows = []
    for task in sstore.list_tasks(store, run_id=run_id, limit=1000):
        if task.get("status") not in statuses:
            continue
        sstore.update_task(
            store, task["task_id"], status="queued", stage="retry",
            error=None, finished_at=None,
        )
        rows.append(sstore.get_task(store, task["task_id"]) or task)
    log.info("scan.task.retry", run_id=run_id, count=len(rows))
    return rows


def recover_stale(store: Any, older_than_sec: int = 1800) -> int:
    """把超时仍在 running 的任务转回 queued（daemon/重启后的断点续跑入口）。

    只处理 ``started_at`` 早于阈值的任务，避免误伤正在跑的任务。
    """
    cutoff = schema.utc_now()
    # 用 SQLite 的 julianday 做时间差，避免引入第三方时间库
    try:
        cur = store.execute(
            "UPDATE scan_task SET status='queued', stage='recovered',"
            " error='stale running task recovered'"
            " WHERE status='running' AND started_at IS NOT NULL"
            "   AND (julianday(?) - julianday(started_at)) * 86400 > ?",
            (cutoff, int(older_than_sec)),
        )
        n = int(cur.rowcount or 0)
    except Exception as exc:  # noqa: BLE001 - 恢复失败不应中断主流程
        log.warn("scan.task.recover_failed", error=str(exc))
        return 0
    if n:
        log.info("scan.task.recovered", count=n)
    return n


def cancel(store: Any, run_id: str, reason: str = "人工取消") -> int:
    """取消一次运行中未完成的任务（aborted）。"""
    n = 0
    for task in sstore.list_tasks(store, run_id=run_id, limit=1000):
        if task.get("status") in ("queued", "running"):
            sstore.update_task(
                store, task["task_id"], status="aborted", stage="cancelled",
                error=str(reason)[:4000], finished_at=schema.utc_now(),
            )
            n += 1
    return n


def summary(tasks: list[dict]) -> dict:
    """任务集合汇总（CLI/报告用）。"""
    by_status: dict[str, int] = {}
    by_engine: dict[str, dict[str, int]] = {}
    cost_ms = 0
    for task in tasks or []:
        status = str(task.get("status") or "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        cost_ms += int(task.get("cost_ms") or 0)
        for name, outcome in ((task.get("checkpoint") or {}).get("engines") or {}).items():
            state = str((outcome or {}).get("status") or "unknown")
            bucket = by_engine.setdefault(name, {})
            bucket[state] = bucket.get(state, 0) + 1
    return {
        "tasks": len(tasks or []),
        "by_status": by_status,
        "by_engine": by_engine,
        "cost_ms": cost_ms,
    }
