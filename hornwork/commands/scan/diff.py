"""``hornworkctl scan diff``：快照四态差异（new / fixed / persisting / regressed）。

缺省行为是「取最近两次快照自动对比」，这样现场只需 ``scan diff`` 一条命令就能
看到变化；只有显式给出 ``--to/--from`` 时才按指定对比较。快照不足时给出可执行
提示而不是空表。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_OK
from ...cli_common.errors import CliError
from ...cli_common.runtime import CliRuntime

NAME = "diff"
HELP = "快照差异（四态）"

COLUMNS = [
    ("delta", "变化"), ("asset", "资产"), ("kind", "类型"), ("check", "检查项"),
    ("severity", "等级"), ("title", "标题"),
]


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan diff``。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("--from", dest="prev", default=None, help="较旧的基线快照 ID")
    parser.add_argument("--to", dest="cur", default=None, help="较新的当前快照 ID（缺省取最近两次）")


def run(ctx: CliRuntime) -> int:
    """解析快照对并输出差异。"""
    from ...scan import diff as scan_diff, store as scan_store

    args = ctx.args
    store = ctx.store()
    cur, prev = _resolve_pair(store, scan_store, args.cur, args.prev)
    result = scan_diff.build(store, cur, prev)
    if ctx.json_output:
        ctx.print_json(result)
        return EXIT_OK
    stats = result.get("stats") or {}
    print(
        f"快照对比：{cur} vs {prev}  新增={stats.get('new')} 已修复={stats.get('fixed')} "
        f"仍存在={stats.get('persisting')} 回归={stats.get('regressed')}"
    )
    ctx.print_table(
        [
            {
                "delta": item.get("delta"),
                "asset": item.get("asset_id"),
                "kind": item.get("kind"),
                "check": item.get("check_id"),
                "severity": item.get("severity"),
                "title": (item.get("title") or "")[:50],
            }
            for item in (result.get("items") or [])
        ],
        COLUMNS,
        empty="（无差异）",
    )
    return EXIT_OK


def _resolve_pair(store, scan_store, cur: str | None, prev: str | None) -> tuple[str, str]:
    """确定要比较的 (当前, 基线) 快照 ID。

    只给 ``--to`` 时，基线取该快照的前一个；两者都没给时取最近两次。
    """
    if not cur:
        snaps = scan_store.list_snapshots(store, limit=2)
        if len(snaps) < 1:
            raise CliError("还没有快照，先跑一次 scan run")
        cur = snaps[0]["snapshot_id"]
        prev = snaps[1]["snapshot_id"] if len(snaps) > 1 else None
    if not prev:
        raise CliError("只有一个快照，无法对比（再跑一次扫描生成新快照）")
    return cur, prev
