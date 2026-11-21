"""``hornworkctl events``：查询规范化事件。

数据来源二选一：daemon 在跑走控制面 ``events.query``，否则直读 SQLite。
两条路径必须返回同构的 dict 列表，否则表格列会对不齐。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK
from ..cli_common.runtime import CliRuntime
from ..cli_common.timefmt import format_ts

NAME = "events"
HELP = "查询事件"

COLUMNS = [
    ("ts", "时间"), ("type", "类型"), ("host", "主机"),
    ("process", "进程"), ("cmdline", "命令行"), ("file", "文件"),
]
"""表格列定义：与重构前逐字一致。"""


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``events`` 子命令及其过滤参数。"""
    parser = sub.add_parser(NAME, help=HELP)
    parser.add_argument("--type", default=None)
    parser.add_argument("--layer", default=None)
    parser.add_argument("--since", default="10m")
    parser.add_argument("--limit", type=int, default=20)


def run(ctx: CliRuntime) -> int:
    """按条件查询事件并输出。"""
    args = ctx.args
    if ctx.daemon_up():
        events = ctx.ctl(
            "events.query",
            {"type": args.type, "since": args.since, "limit": args.limit},
        ).get("events") or []
    else:
        events = ctx.store().query_events(
            event_type=args.type,
            since=args.since,
            limit=args.limit,
            source_layer=args.layer,
        )
    ctx.emit({"events": events}, _rows(events), COLUMNS)
    return EXIT_OK


def _rows(events: list[dict]) -> list[dict]:
    """把事件压平成表格行。

    命令行超长会撑爆终端，因此截断到 80 字符（重构前的行为）。
    """
    rows = []
    for event in events:
        process = event.get("process") or {}
        rows.append({
            "ts": format_ts(event.get("ts")),
            "type": event.get("event_type"),
            "host": (event.get("host") or {}).get("host_id"),
            "process": process.get("image"),
            "cmdline": (process.get("cmdline") or "")[:80],
            "file": (event.get("file") or {}).get("path"),
        })
    return rows
