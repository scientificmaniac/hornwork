"""``hornworkctl scan findings``：按资产/等级/状态/类型/检查项查询 finding。

只读查询。标题截断到 48 字符是为了让 10 列宽表在 100 列终端里不折行。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_OK
from ...cli_common.runtime import CliRuntime

NAME = "findings"
HELP = "查询 finding"

COLUMNS = [
    ("finding_id", "Finding"), ("asset", "资产"), ("kind", "类型"), ("check", "检查项"),
    ("title", "标题"), ("severity", "等级"), ("cvss", "CVSS"),
    ("confidence", "置信度"), ("status", "状态"), ("vuln_ref", "档案"),
]


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan findings`` 及其过滤参数。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("--asset", default=None)
    parser.add_argument("--severity", default=None)
    parser.add_argument("--status", default=None)
    parser.add_argument("--kind", default=None)
    parser.add_argument("--check", default=None)
    parser.add_argument("--limit", type=int, default=100)


def run(ctx: CliRuntime) -> int:
    """查询并输出 finding 列表。"""
    from ...scan import store as scan_store

    args = ctx.args
    rows = scan_store.list_findings(
        ctx.store(),
        asset_id=args.asset,
        severity=args.severity,
        status=args.status,
        kind=args.kind,
        check_id=args.check,
        limit=args.limit,
    )
    if ctx.json_output:
        ctx.print_json({"findings": rows})
        return EXIT_OK
    ctx.print_table(
        [
            {
                "finding_id": row.get("finding_id"),
                "asset": row.get("asset_id"),
                "kind": row.get("kind"),
                "check": row.get("check_id"),
                "title": (row.get("title") or "")[:48],
                "severity": row.get("severity"),
                "cvss": row.get("cvss"),
                "confidence": row.get("confidence"),
                "status": row.get("status"),
                "vuln_ref": row.get("vuln_ref") or "",
            }
            for row in rows
        ],
        COLUMNS,
        empty="（没有 finding）",
    )
    return EXIT_OK
