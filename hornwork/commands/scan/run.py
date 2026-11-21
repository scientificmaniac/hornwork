"""``hornworkctl scan run``：执行一次扫描（timer 与手动共用同一入口）。

## 两条入口的差别只在「目标从哪来」

- ``--plan <id>``：目标、profile、时间窗、限速全部来自计划表；
- ``--profile <name>``：临时扫描，选择器由命令行直接给出，不落计划表。

## 中断语义

``Ctrl-C`` 返回 130 而不是 1：已写入的任务可以用 ``scan retry`` 续跑，因此这是
「可恢复的中断」，需要与「运行失败」区分开。
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from ...cli_common.constants import EXIT_FAIL, EXIT_INTERRUPT, EXIT_OK, SCAN_PROFILES
from ...cli_common.errors import CliError
from ...cli_common.runtime import CliRuntime

NAME = "run"
HELP = "执行扫描（timer 与手动同一入口）"

TASK_COLUMNS = [
    ("task", "任务"), ("asset", "资产"), ("status", "状态"),
    ("cost_ms", "耗时ms"), ("error", "错误"),
]


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan run``。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("--plan", default=None, help="计划 ID")
    parser.add_argument("--profile", default=None, choices=SCAN_PROFILES,
                        help="临时扫描 profile（不落计划表）")
    parser.add_argument("--asset", action="append", default=None)
    parser.add_argument("--ip", default=None, help="按台账 IP 选目标（本机回环自动登记）")
    parser.add_argument("--group", default=None)
    parser.add_argument("--check", action="append", default=None, help="只跑指定 check_id（复扫）")
    parser.add_argument("--trigger", default=None, help="manual|timer|targeted|verify-fix|change")
    parser.add_argument("--slot", default=None)
    parser.add_argument("--label", default=None)
    parser.add_argument("--dry-run", dest="dry_run", action="store_true")
    parser.add_argument("--check-only", dest="check_only", action="store_true",
                        help="只做闸门与目标选择，不实际扫描")
    parser.add_argument("--force-window", dest="force_window", action="store_true")
    parser.add_argument("--no-report", dest="no_report", action="store_true")
    parser.add_argument("--timer", action="store_true", help="标记为 systemd timer 触发")


def run(ctx: CliRuntime) -> int:
    """选择 plan/adhoc 入口执行扫描并输出摘要。"""
    args = ctx.args
    # 顺序与重构前一致：先确保扫描表结构就绪，再做参数校验。
    # 这样"用法错误也已完成建表"的行为不会变（离线首跑依赖它）。
    runner = _new_runner(ctx)
    if not args.plan and not args.profile:
        raise CliError("需要 --plan <id> 或 --profile quick|weekly|full|targeted|verify-fix")

    selector = _build_selector(ctx)
    trigger = args.trigger or ("timer" if args.timer else "manual")
    try:
        result = _execute(runner, args, selector, trigger)
    except KeyboardInterrupt:
        print("[!] 扫描被中断（已写入的任务可通过 scan retry 续跑）", file=sys.stderr)
        return EXIT_INTERRUPT
    if ctx.json_output:
        ctx.print_json(result)
    else:
        _print_summary(ctx, result)
    return EXIT_OK if result.get("ok") else EXIT_FAIL


def _new_runner(ctx: CliRuntime) -> Any:
    """构造扫描编排器，并确保扫描子系统的表结构已就绪。"""
    from ...scan import store as scan_store
    from ...scan.runner import ScanRunner

    store = ctx.store()
    scan_store.init_schema(store)
    return ScanRunner(ctx.cfg, store)


def _build_selector(ctx: CliRuntime) -> dict[str, Any]:
    """解析目标选择器；``--ip`` 必须已在台账中（回环地址自动登记）。"""
    from ...scan import assets as scan_assets
    from ...scan import store as scan_store

    args = ctx.args
    store = ctx.store()
    selector: dict[str, Any] = {}
    if args.asset:
        selector["asset_ids"] = list(args.asset)
    if getattr(args, "ip", None):
        asset = scan_store.get_asset_by_ip(store, args.ip)
        if not asset and args.ip in ("127.0.0.1", "localhost"):
            asset = scan_assets.ensure_self_asset(store, ctx.cfg, ip="127.0.0.1")
        if not asset:
            raise CliError(f"IP {args.ip} 不在台账中（先用 asset add 登记）")
        selector["asset_ids"] = [asset["asset_id"]]
    if getattr(args, "group", None):
        selector["group"] = args.group
    return selector


def _execute(runner: Any, args: argparse.Namespace, selector: dict[str, Any], trigger: str) -> dict:
    """按 plan / adhoc 调用编排器，参数原样透传。"""
    if args.plan:
        return runner.run_plan(
            args.plan, trigger=trigger, slot=args.slot, label=args.label,
            asset_ids=list(args.asset or []) or None,
            check_ids=list(args.check or []) or None,
            dry_run=bool(args.dry_run), force_window=bool(args.force_window),
            write_report=not args.no_report, check_only=bool(args.check_only),
        )
    return runner.run_adhoc(
        profile_name=args.profile, selector=selector, trigger=trigger,
        label=args.label, check_ids=list(args.check or []) or None,
        dry_run=bool(args.dry_run), force_window=True,
        write_report=not args.no_report, check_only=bool(args.check_only),
    )


def _print_summary(ctx: CliRuntime, result: dict) -> None:
    """人类可读的扫描摘要：闸门结论 / 计数 / 引擎 / 差异 / 覆盖率 / 报告 / 任务表。"""
    if result.get("duplicate"):
        print(f"[幂等] {result.get('reason')}")
        return
    if not result.get("ok"):
        print(f"[拒绝] {result.get('reason')}")
        for gate in result.get("gates") or []:
            if not gate.get("ok"):
                print(f"  闸门 {gate.get('check')}：{gate.get('reason') or gate.get('ok')}")
        return
    print(
        f"扫描完成：plan={result.get('plan_id')} run={result.get('run_id')} "
        f"snapshot={result.get('snapshot_id')} profile={result.get('profile')} "
        f"耗时={result.get('duration_ms')}ms"
    )
    counts = result.get("counts") or {}
    print(
        f"发现：finding={counts.get('findings')} 问题={counts.get('problems')}"
        f"（可确认={counts.get('actionable')} 仅CPE={counts.get('cpe_only')}）"
        f" CVE={counts.get('cve')} 端口={counts.get('ports')} 组件={counts.get('components')}"
        f" 严重级={counts.get('by_severity')}"
    )
    _print_engine_status(result.get("engine_status") or {})
    _print_diff(result.get("diff") or {})
    _print_coverage(result.get("coverage") or {})
    _print_report_path(result.get("report") or {})
    _print_tasks(ctx, result.get("tasks") or [])


def _print_engine_status(engine_status: dict) -> None:
    """每个引擎的成功/失败键列表。"""
    if not engine_status:
        return
    print("引擎：" + "  ".join(
        f"{name}={list(value.keys())}" for name, value in engine_status.items()
    ))


def _print_diff(diff: dict) -> None:
    """与上次快照的四态对比。"""
    stats = diff.get("stats")
    if not stats:
        return
    print(
        f"与上次快照对比：新增={stats.get('new')} 已修复={stats.get('fixed')} "
        f"仍存在={stats.get('persisting')} 回归={stats.get('regressed')}（prev={diff.get('prev')}）"
    )


def _print_coverage(coverage: dict) -> None:
    """综合覆盖率与未覆盖条数。"""
    if coverage.get("coverage") is None:
        return
    print(
        f"综合覆盖率：{round(float(coverage.get('coverage') or 0) * 100, 1)}%"
        f"（未覆盖项 {len(coverage.get('uncovered') or [])} 条）"
    )


def _print_report_path(report: dict) -> None:
    """报告落盘路径与大小。"""
    if report.get("path"):
        print(f"报告：{report.get('path')} ({report.get('bytes')} bytes)")


def _print_tasks(ctx: CliRuntime, tasks: list[dict]) -> None:
    """逐任务状态表（只在有任务时打印）。"""
    if not tasks:
        return
    ctx.print_table(
        [
            {
                "task": task.get("task_id"),
                "asset": task.get("asset_id"),
                "status": task.get("status"),
                "cost_ms": task.get("cost_ms"),
                "error": (task.get("error") or "")[:60],
            }
            for task in tasks
        ],
        TASK_COLUMNS,
    )
