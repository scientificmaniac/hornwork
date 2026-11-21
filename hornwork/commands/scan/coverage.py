"""``hornworkctl scan coverage``：资产 × 检查域的加权覆盖率。

覆盖率由 ``scan.coverage`` 计算（权重与角色映射来自配置），CLI 只负责选定快照
与呈现矩阵。未覆盖清单只打印前 40 条 —— 这是重构前就有的上限，避免刷屏。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_OK
from ...cli_common.errors import CliError
from ...cli_common.runtime import CliRuntime

NAME = "coverage"
HELP = "覆盖率与未覆盖清单"

# 未覆盖清单的终端打印上限（完整清单在 --json 里）。
MAX_UNCOVERED_PRINTED = 40

COLUMNS = [
    ("asset", "资产"), ("role", "角色"), ("D1", "D1"), ("D2", "D2"), ("D3", "D3"),
    ("D4", "D4"), ("D5", "D5"), ("D6", "D6"), ("score", "得分"),
]
"""矩阵列：D1–D6 为检查域，score 为加权总分。"""


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan coverage``。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("--snapshot", default=None)


def run(ctx: CliRuntime) -> int:
    """计算并输出覆盖率。"""
    from ...scan import coverage as scan_coverage, store as scan_store

    store = ctx.store()
    snapshot = ctx.args.snapshot or _latest_snapshot(store, scan_store)
    result = scan_coverage.compute(store, snapshot, ctx.cfg)
    if ctx.json_output:
        ctx.print_json(result)
        return EXIT_OK
    _print_human(ctx, snapshot, result)
    return EXIT_OK


def _latest_snapshot(store, scan_store) -> str:
    """取最近一次快照 ID；没有快照时给出可执行提示。"""
    latest = scan_store.latest_snapshot(store)
    if not latest:
        raise CliError("还没有快照，先跑一次 scan run")
    return latest["snapshot_id"]


def _print_human(ctx: CliRuntime, snapshot: str, result: dict) -> None:
    """综合覆盖率、按域明细、资产矩阵与未覆盖清单。"""
    print(
        f"快照 {snapshot} 综合覆盖率：{round(float(result.get('coverage') or 0) * 100, 1)}%"
        f"（资产 {result.get('assets')}）"
    )
    for domain, data in (result.get("by_domain") or {}).items():
        print(
            f"  {domain} {data.get('name')}: {round(float(data.get('avg') or 0) * 100, 1)}%"
            f"  权重={data.get('weight')}  适用资产={data.get('applicable')}"
        )
    ctx.print_table(
        [
            {
                "asset": entry.get("asset_id"),
                "role": entry.get("role"),
                **{domain: value for domain, value in (entry.get("domains") or {}).items()},
                "score": round(float(entry.get("score") or 0), 3),
            }
            for entry in (result.get("matrix") or [])
        ],
        COLUMNS,
    )
    uncovered = result.get("uncovered") or []
    if uncovered:
        print("未覆盖清单：")
        for item in uncovered[:MAX_UNCOVERED_PRINTED]:
            print(f"  - {item.get('asset_id')} {item.get('domain')}: {item.get('reason')}")
