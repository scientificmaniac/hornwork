"""``hornworkctl forensics``：整机内存取证（采集/分析/比对）。

三个动作都是长任务，必须由 daemon 执行：采集要独占 AVML、分析要调 Volatility、
比对要读大盘镜像。CLI 只负责触发与呈现。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK
from ..cli_common.runtime import CliRuntime
from ..cli_common.validation import require_daemon

NAME = "forensics"
HELP = "整机内存取证"


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``forensics collect|analyze|compare``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="forensics_cmd", required=True)

    collect = actions.add_parser("collect")
    collect.add_argument("--compress", action="store_true")

    analyze = actions.add_parser("analyze")
    analyze.add_argument("--image", required=True)

    compare = actions.add_parser("compare")
    compare.add_argument("--malfind", default=None)
    compare.add_argument("--since", default=None)


def run(ctx: CliRuntime) -> int:
    """把动作转成控制面方法并输出 JSON。"""
    require_daemon(ctx.daemon_up(), "forensics")
    args = ctx.args
    if args.forensics_cmd == "collect":
        ctx.print_json(ctx.ctl("forensics.collect", {"compress": args.compress}))
    elif args.forensics_cmd == "analyze":
        ctx.print_json(ctx.ctl("forensics.analyze", {"image": args.image}))
    else:
        ctx.print_json(ctx.ctl("forensics.compare", {"malfind": args.malfind, "since": args.since}))
    return EXIT_OK
