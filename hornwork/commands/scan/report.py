"""``hornworkctl scan report``：导出扫描报告（HTML/JSON）。

报告里需要「与上次快照的差异」和「覆盖率」两个附件章节，因此在导出前先算好
两者再交给报告模块。缺省快照为最近一次；没有快照时直接给出可执行提示。
"""

from __future__ import annotations

import argparse

from ...cli_common.constants import EXIT_FAIL, EXIT_OK, SCAN_REPORT_FORMATS
from ...cli_common.errors import CliError
from ...cli_common.runtime import CliRuntime

NAME = "report"
HELP = "生成 HTML/JSON 报告"


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan report``。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("--snapshot", default=None)
    parser.add_argument("--format", default="html", choices=SCAN_REPORT_FORMATS)
    parser.add_argument("--out", default=None)


def run(ctx: CliRuntime) -> int:
    """计算差异/覆盖率后导出报告，退出码反映生成是否成功。"""
    from ...scan import coverage as scan_coverage, diff as scan_diff, report as scan_report
    from ...scan import store as scan_store

    args = ctx.args
    store = ctx.store()
    snapshot = args.snapshot or _latest_snapshot(store, scan_store)
    previous = scan_store.previous_snapshot(store, snapshot)
    diff_result = scan_diff.build(store, snapshot, previous["snapshot_id"]) if previous else None
    coverage_result = scan_coverage.compute(store, snapshot, ctx.cfg)
    result = scan_report.export(
        store, ctx.cfg, snapshot,
        fmt=args.format, out=args.out, diff=diff_result, coverage=coverage_result,
    )
    if ctx.json_output:
        ctx.print_json(result)
    else:
        state = "已生成" if result.get("ok") else "生成失败"
        print(f"报告{state}：{result.get('path')} ({result.get('bytes')} bytes)")
    return EXIT_OK if result.get("ok") else EXIT_FAIL


def _latest_snapshot(store, scan_store) -> str:
    """取最近一次快照 ID；没有快照时给出可执行提示。"""
    latest = scan_store.latest_snapshot(store)
    if not latest:
        raise CliError("还没有快照，先跑一次 scan run")
    return latest["snapshot_id"]
