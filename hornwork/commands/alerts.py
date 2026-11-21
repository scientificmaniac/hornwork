"""``hornworkctl alerts``：查询检测告警。

与 :mod:`hornwork.commands.events` 同构：daemon 优先、离线直读 SQLite 兜底。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK
from ..cli_common.runtime import CliRuntime
from ..cli_common.timefmt import format_ts

NAME = "alerts"
HELP = "查询告警"

COLUMNS = [
    ("ts", "时间"), ("level", "级别"), ("rule", "规则"), ("name", "名称"),
    ("engine", "引擎"), ("technique", "技术"), ("status", "状态"),
]
"""表格列定义：与重构前逐字一致。"""


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``alerts`` 子命令及其过滤参数。"""
    parser = sub.add_parser(NAME, help=HELP)
    parser.add_argument("--level", type=int, default=None)
    parser.add_argument("--technique", default=None)
    parser.add_argument("--since", default="24h")
    parser.add_argument("--limit", type=int, default=20)


def run(ctx: CliRuntime) -> int:
    """按条件查询告警并输出。"""
    args = ctx.args
    if ctx.daemon_up():
        alerts = ctx.ctl(
            "alerts.query",
            {
                "since": args.since,
                "level": args.level,
                "technique": args.technique,
                "limit": args.limit,
            },
        ).get("alerts") or []
    else:
        alerts = ctx.store().query_alerts(
            since=args.since,
            level_min=args.level,
            technique=args.technique,
            limit=args.limit,
        )
    ctx.emit({"alerts": alerts}, _rows(alerts), COLUMNS)
    return EXIT_OK


def _rows(alerts: list[dict]) -> list[dict]:
    """把告警压平成表格行（规则字段嵌套在 ``rule`` 下）。"""
    rows = []
    for alert in alerts:
        rule = alert.get("rule") or {}
        rows.append({
            "ts": format_ts(alert.get("ts")),
            "level": alert.get("level"),
            "rule": rule.get("id"),
            "name": rule.get("name"),
            "engine": rule.get("engine"),
            "technique": alert.get("technique"),
            "status": alert.get("status"),
        })
    return rows
