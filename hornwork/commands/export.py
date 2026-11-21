"""``hornworkctl export``：导出告警与事件。

在线导出由 daemon 完成（它能访问全部历史）；离线时只导出告警/事件 JSONL ——
这是重构前就有的降级范围，没有扩大也没有缩小。

``--format md`` 在离线路径下**仍写 JSONL**：历史行为如此（格式由下游报告模块
消费），本次重构不改语义，只在文档里标注。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK, EXPORT_FORMATS
from ..cli_common.io import resolve_out_dir, timestamped_name, write_jsonl
from ..cli_common.runtime import CliRuntime
from ..config import cfg_get

NAME = "export"
HELP = "导出"


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``export``（参数直接挂在自身）。"""
    parser = sub.add_parser(NAME, help=HELP)
    parser.add_argument("--format", default="md", choices=EXPORT_FORMATS)
    parser.add_argument("--out", default=None)
    parser.add_argument("--limit", type=int, default=1000)


def run(ctx: CliRuntime) -> int:
    """优先走 daemon；否则离线导出 JSONL。"""
    args = ctx.args
    if ctx.daemon_up():
        ctx.print_json(ctx.ctl("export", {"format": args.format, "out": args.out, "limit": args.limit}))
        return EXIT_OK
    return _export_offline(ctx)


def _export_offline(ctx: CliRuntime) -> int:
    """离线导出：告警在前、事件在后，逐行 JSON。"""
    args = ctx.args
    raw_dir = cfg_get(ctx.cfg, "general.raw_dir", "./raw")
    out_dir = resolve_out_dir(args.out, str(raw_dir))
    path = out_dir / timestamped_name("export", "jsonl")

    store = ctx.store()
    alerts = store.query_alerts(limit=args.limit)
    events = store.query_events(limit=args.limit)
    write_jsonl(path, [*alerts, *events])
    print(f"已导出 {len(alerts)} 条告警、{len(events)} 条事件到 {path}")
    return EXIT_OK
