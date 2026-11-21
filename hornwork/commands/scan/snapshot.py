"""``hornworkctl scan snapshot``：快照列表与基线设置。

「基线快照」是差异对比的锚点（``is_base``），设置后后续扫描以它为参照计算
新增/已修复。因此 ``base`` 子命令是对外语义的一部分，不能退化成普通标记。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_OK, EXIT_USAGE
from ...cli_common.runtime import CliRuntime

NAME = "snapshot"
HELP = "快照"

COLUMNS = [
    ("snapshot_id", "快照"), ("plan_id", "计划"), ("ts", "时间"), ("kind", "类型"),
    ("is_base", "基线"), ("task_count", "任务"), ("finding_count", "项数"),
]


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan snapshot list|base``。"""
    parser = actions.add_parser(NAME, help=HELP)
    subs = parser.add_subparsers(dest="snapshot_cmd", required=True)

    lister = subs.add_parser("list")
    lister.add_argument("--limit", type=int, default=20)

    base = subs.add_parser("base")
    base.add_argument("--id", required=True)


def run(ctx: CliRuntime) -> int:
    """按 ``snapshot_cmd`` 分派。"""
    from ...scan import store as scan_store

    args = ctx.args
    store = ctx.store()
    if args.snapshot_cmd == "base":
        ok = scan_store.set_base_snapshot(store, args.id)
        ctx.print_json({"ok": ok, "snapshot_id": args.id, "is_base": ok})
        # 注意：基线设置失败返回 2（不是 1）—— 表示"这个快照不存在"，属用法问题。
        return EXIT_OK if ok else EXIT_USAGE
    snapshots = scan_store.list_snapshots(store, limit=args.limit)
    if ctx.json_output:
        ctx.print_json({"snapshots": snapshots})
        return EXIT_OK
    ctx.print_table(snapshots, COLUMNS)
    return EXIT_OK
