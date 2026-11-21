"""``hornworkctl mem``：内存扫描与快照复核。

两条子路径都**必须**依赖 daemon：读目标进程 ``/proc/<pid>/mem`` 需要与服务
同权限的上下文，CLI 侧不复制这段逻辑。因此缺 daemon 时直接给出可执行提示，
而不是静默降级。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK
from ..cli_common.runtime import CliRuntime
from ..cli_common.validation import require_daemon

NAME = "mem"
HELP = "内存扫描"


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``mem scan`` / ``mem verify``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="mem_cmd", required=True)

    scan = actions.add_parser("scan")
    scan.add_argument("--pid", type=int, required=True)
    scan.add_argument("--snapshot", action="store_true")

    verify = actions.add_parser("verify")
    verify.add_argument("--snapshot", dest="snapshot_dir", required=True)


def run(ctx: CliRuntime) -> int:
    """按二级子命令调用控制面；结果恒以 JSON 输出。"""
    args = ctx.args
    if args.mem_cmd == "scan":
        require_daemon(ctx.daemon_up(), "mem scan")
        result = ctx.ctl("mem.scan", {"pid": args.pid, "snapshot": args.snapshot})
    else:
        require_daemon(ctx.daemon_up(), "mem verify")
        result = ctx.ctl("mem.verify", {"snapshot": args.snapshot_dir})
    ctx.print_json(result)
    return EXIT_OK
