"""``hornworkctl respond``：对工单执行响应 playbook。

强制要求 daemon：响应动作涉及进程/文件/网络的真实操作与审批门，必须在服务
进程内带着审批上下文执行，CLI 只是发起端。``--mode`` 默认 ``observe``（只观测
不动作），这是刻意保留的安全默认值。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK, RESPOND_MODES
from ..cli_common.runtime import CliRuntime
from ..cli_common.validation import require_daemon

NAME = "respond"
HELP = "执行响应 playbook"


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``respond``（无二级子命令，参数直接挂在自身）。"""
    parser = sub.add_parser(NAME, help=HELP)
    parser.add_argument("--case", required=True)
    parser.add_argument("--playbook", default="PB-001")
    parser.add_argument("--mode", default="observe", choices=RESPOND_MODES)


def run(ctx: CliRuntime) -> int:
    """把参数透传给 ``respond.run`` 并输出 JSON 结果。"""
    require_daemon(ctx.daemon_up(), "respond")
    args = ctx.args
    ctx.print_json(ctx.ctl("respond.run", {
        "case_id": args.case,
        "playbook": args.playbook,
        "mode": args.mode,
    }))
    return EXIT_OK
