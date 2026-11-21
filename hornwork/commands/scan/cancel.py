"""``hornworkctl scan cancel``：中止一次运行中尚未结束的任务。

已完成的任务不受影响 —— 取消是"停止继续"，不是"回滚已产生的数据"。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_OK
from ...cli_common.runtime import CliRuntime

NAME = "cancel"
HELP = "取消一次运行"

DEFAULT_REASON = "人工取消"
"""未给 ``--reason`` 时写进任务的取消原因（与重构前逐字一致）。"""


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan cancel``。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("--run", required=True)
    parser.add_argument("--reason", default=None)


def run(ctx: CliRuntime) -> int:
    """中止指定 run 的未结束任务。"""
    from ...scan import task as scan_task

    args = ctx.args
    aborted = scan_task.cancel(ctx.store(), args.run, reason=args.reason or DEFAULT_REASON)
    ctx.print_json({"run_id": args.run, "aborted": aborted})
    return EXIT_OK
