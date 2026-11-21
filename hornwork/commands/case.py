"""``hornworkctl case``：响应工单的创建、查看与列表。

工单状态推进由响应子系统负责，CLI 只做读写透传。``create`` 需要 daemon 是因为
它要触发工单关联的 playbook 审批流；``show`` 刻意不用 ``case.get`` 而是拉全量
列表再筛，这样离线（直读 SQLite）与在线两条路径可以复用一个筛选函数。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK
from ..cli_common.errors import NotFoundError
from ..cli_common.runtime import CliRuntime
from ..cli_common.timefmt import format_ts
from ..cli_common.validation import require_daemon

NAME = "case"
HELP = "工单"

COLUMNS = [
    ("case_id", "工单"), ("title", "标题"), ("severity", "级别"),
    ("status", "状态"), ("created_at", "创建时间"), ("verdict", "结论"),
]

# ``case show`` 需要一次性拉全量再定位单条；上限沿用重构前的 1000。
_FULL_LIST_LIMIT = 1000


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``case list|show|create``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="case_cmd", required=True)

    lister = actions.add_parser("list")
    lister.add_argument("--status", default=None)
    lister.add_argument("--limit", type=int, default=50)

    shower = actions.add_parser("show")
    shower.add_argument("case_id")

    creator = actions.add_parser("create")
    creator.add_argument("--alert", required=True)


def run(ctx: CliRuntime) -> int:
    """按二级子命令分派。"""
    args = ctx.args
    if args.case_cmd == "create":
        require_daemon(ctx.daemon_up(), "case create")
        ctx.print_json(ctx.ctl("case.create", {"alert_id": args.alert}))
        return EXIT_OK
    if args.case_cmd == "show":
        return _show(ctx, args.case_id)
    return _list(ctx, args)


def _all_cases(ctx: CliRuntime) -> list[dict]:
    """取全部工单（daemon 优先，离线直读）。"""
    if ctx.daemon_up():
        return ctx.ctl("case.list", {"limit": _FULL_LIST_LIMIT}).get("cases") or []
    return ctx.store().list_cases(limit=_FULL_LIST_LIMIT)


def _show(ctx: CliRuntime, case_id: str) -> int:
    """定位单条工单并输出完整 JSON。"""
    case = next((item for item in _all_cases(ctx) if item.get("case_id") == case_id), None)
    if case is None:
        raise NotFoundError(f"工单不存在：{case_id}")
    ctx.print_json(case)
    return EXIT_OK


def _list(ctx: CliRuntime, args: argparse.Namespace) -> int:
    """按状态筛选工单并输出表格。"""
    if ctx.daemon_up():
        cases = ctx.ctl("case.list", {"status": args.status, "limit": args.limit}).get("cases") or []
    else:
        cases = ctx.store().list_cases(status=args.status, limit=args.limit)
    rows = [
        {
            "case_id": item.get("case_id"),
            "title": (item.get("title") or "")[:50],
            "severity": item.get("severity"),
            "status": item.get("status"),
            "created_at": format_ts(item.get("created_at")),
            "verdict": item.get("verdict"),
        }
        for item in cases
    ]
    ctx.emit({"cases": cases}, rows, COLUMNS)
    return EXIT_OK
