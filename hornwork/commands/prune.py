"""``hornworkctl prune``：清理历史数据。

在线清理由 daemon 执行（它持有全部写入句柄，避免与采集线程抢锁）；离线时直接
调存储层的 ``prune``。两条路径都输出 JSON，便于脚本化归档任务。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK
from ..cli_common.runtime import CliRuntime

NAME = "prune"
HELP = "清理历史数据"


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``prune``（参数直接挂在自身）。"""
    parser = sub.add_parser(NAME, help=HELP)
    parser.add_argument("--days", type=int, default=30)


def run(ctx: CliRuntime) -> int:
    """按天数清理历史数据。"""
    days = ctx.args.days
    if not ctx.daemon_up():
        ctx.print_json(ctx.store().prune(days=days))
        return EXIT_OK
    ctx.print_json(ctx.ctl("prune", {"days": days}))
    return EXIT_OK
