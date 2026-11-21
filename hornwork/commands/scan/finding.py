"""``hornworkctl scan finding``：人工处置单条 finding。

状态机（六态）由存储层校验，CLI 只负责把「目标 + 新状态 + 原因」传下去。
``--reason`` 会原样出现在输出与审计里，因此不在这里做任何加工。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_OK, FINDING_STATUSES
from ...cli_common.errors import NotFoundError
from ...cli_common.runtime import CliRuntime

NAME = "finding"
HELP = "人工处置 finding"


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan finding set``。"""
    parser = actions.add_parser(NAME, help=HELP)
    subs = parser.add_subparsers(dest="finding_cmd", required=True)
    setter = subs.add_parser("set")
    setter.add_argument("--id", required=True)
    setter.add_argument("--status", required=True, choices=FINDING_STATUSES)
    setter.add_argument("--reason", default=None)


def run(ctx: CliRuntime) -> int:
    """执行 ``scan finding set``：更新单条 finding 的生命周期状态。

    ``finding`` 目前只有一个二级子命令 ``set``，因此这里不做分派 —— 直接执行。
    若将来新增（如 ``finding rm``），再引入 ``args.finding_cmd`` 的分派表，
    届时才有必要加那一层。
    """
    from ...scan import store as scan_store

    args = ctx.args
    store = ctx.store()
    ok = scan_store.set_finding_status(store, args.id, args.status, reason=args.reason)
    if not ok:
        raise NotFoundError(f"finding 不存在：{args.id}")
    finding = scan_store.get_finding(store, args.id)
    if ctx.json_output:
        ctx.print_json(finding)
    else:
        suffix = f"（原因：{args.reason}）" if args.reason else ""
        print(f"已更新 {args.id} → {args.status}{suffix}")
    return EXIT_OK
