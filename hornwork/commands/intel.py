"""``hornworkctl intel``：IOC 情报的导入、打包与查询。

``import`` / ``build`` 需要 daemon（情报落库后要立即下发给引擎与规则生成器）；
``list`` 支持离线直读，便于现场直接查"这个 IP 有没有进库"。
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ..cli_common.constants import EXIT_OK
from ..cli_common.runtime import CliRuntime
from ..cli_common.validation import require_daemon

NAME = "intel"
HELP = "情报管理"

COLUMNS = [
    ("type", "类型"), ("value", "值"), ("confidence", "置信度"),
    ("status", "状态"), ("source", "来源"),
]


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``intel import|build|list``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="intel_cmd", required=True)

    importer = actions.add_parser("import")
    importer.add_argument("path")

    builder = actions.add_parser("build")
    builder.add_argument("--bundle", default="bundle-1")

    lister = actions.add_parser("list")
    lister.add_argument("--type", default=None)
    lister.add_argument("--limit", type=int, default=200)


def run(ctx: CliRuntime) -> int:
    """按二级子命令分派。"""
    args = ctx.args
    if args.intel_cmd == "import":
        require_daemon(ctx.daemon_up(), "intel import")
        ctx.print_json(ctx.ctl("intel.import", {"path": str(Path(args.path).resolve())}))
    elif args.intel_cmd == "build":
        require_daemon(ctx.daemon_up(), "intel build")
        ctx.print_json(ctx.ctl("intel.build", {"bundle": args.bundle}))
    else:
        _list(ctx, args)
    return EXIT_OK


def _list(ctx: CliRuntime, args: argparse.Namespace) -> None:
    """查询 IOC 列表：daemon 优先，离线时直读 SQLite。"""
    if ctx.daemon_up():
        iocs = ctx.ctl("intel.list", {"type": args.type, "limit": args.limit}).get("iocs") or []
    else:
        iocs = ctx.store().ioc_list(kind=args.type, limit=args.limit)
    rows = [
        {
            "type": item.get("type"),
            "value": item.get("value"),
            "confidence": item.get("confidence"),
            "status": item.get("status"),
            "source": item.get("source"),
        }
        for item in iocs
    ]
    ctx.emit({"iocs": iocs}, rows, COLUMNS)
