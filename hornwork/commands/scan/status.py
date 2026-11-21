"""``hornworkctl scan status``：任务 / 快照 / 计数的总览。

这是现场最常敲的一条：先看「有没有任务、跑到什么状态、哪些快照可用」。
输出顺序固定为「计数行 → 任务表 → 空行 → 快照表」，两张表各带自己的空占位语。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_OK
from ...cli_common.runtime import CliRuntime

NAME = "status"
HELP = "任务/快照/计数"

TASK_COLUMNS = [
    ("task_id", "任务"), ("plan_id", "计划"), ("asset_id", "资产"), ("slot", "槽位"),
    ("status", "状态"), ("started_at", "开始"), ("cost_ms", "耗时ms"),
]

SNAPSHOT_COLUMNS = [
    ("snapshot_id", "快照"), ("plan_id", "计划"), ("ts", "时间"), ("kind", "类型"),
    ("is_base", "基线"), ("finding_count", "项数"),
]


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan status``。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("--run", default=None)
    parser.add_argument("--plan", default=None)
    parser.add_argument("--limit", type=int, default=20)


def run(ctx: CliRuntime) -> int:
    """打印计数 + 任务表 + 快照表。"""
    from ...scan import store as scan_store

    args = ctx.args
    store = ctx.store()
    tasks = scan_store.list_tasks(
        store,
        run_id=getattr(args, "run", None),
        plan_id=getattr(args, "plan", None),
        limit=int(getattr(args, "limit", 20)),
    )
    snapshots = scan_store.list_snapshots(store, limit=int(getattr(args, "limit", 20)))
    overview = scan_store.scan_overview(store)
    if ctx.json_output:
        ctx.print_json({"tasks": tasks, "snapshots": snapshots, "overview": overview})
        return EXIT_OK
    counts = overview.get("counts") or {}
    print("计数：" + "  ".join(f"{key}={val}" for key, val in counts.items()))
    ctx.print_table(tasks, TASK_COLUMNS, empty="（还没有扫描任务）")
    print()
    ctx.print_table(snapshots, SNAPSHOT_COLUMNS, empty="（还没有快照）")
    return EXIT_OK
