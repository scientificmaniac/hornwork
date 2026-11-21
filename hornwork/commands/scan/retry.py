"""``hornworkctl scan retry``：把失败/部分完成的任务重新入队。

「续跑」的前提是任务表里留有上次运行的记录，因此本命令只做一次批量状态回滚，
不做任何目标解析 —— 目标与 profile 都沿用原任务。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_OK
from ...cli_common.runtime import CliRuntime

NAME = "retry"
HELP = "重试失败/部分完成的任务"


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan retry``。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("--run", required=True)


def run(ctx: CliRuntime) -> int:
    """重排指定 run 下失败/部分完成的任务。"""
    from ...scan import task as scan_task

    run_id = ctx.args.run
    rows = scan_task.retry(ctx.store(), run_id)
    ctx.print_json({
        "run_id": run_id,
        "requeued": len(rows),
        "tasks": [row.get("task_id") for row in rows],
    })
    return EXIT_OK
