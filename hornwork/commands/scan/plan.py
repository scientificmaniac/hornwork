"""``hornworkctl scan plan``：扫描计划（周期是数据，不是代码）。

计划把「周期、profile、目标选择器、时间窗、限速」存成数据库里的一条记录，
调度器只负责解释它。因此 CLI 侧的全部工作就是**如实搬运**这些字段，任何默认值
都必须是 ``argparse`` 里的默认值，不能在这里二次加工。
"""

from __future__ import annotations

import argparse
from typing import Any

from ...cli_common.constants import EXIT_FAIL, EXIT_OK, SCAN_PLAN_KINDS, SCAN_PROFILES
from ...cli_common.runtime import CliRuntime
from ...cli_common.validation import parse_json_arg, split_csv

NAME = "plan"
HELP = "扫描计划（周期是数据）"

COLUMNS = [
    ("plan_id", "计划"), ("kind", "周期"), ("profile", "Profile"), ("ports", "端口"),
    ("engines", "引擎"), ("window", "窗口"), ("enabled", "启用"),
    ("last_run", "上次"), ("next_run", "下次"),
]


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan plan add|list|enable|disable|rm``。"""
    parser = actions.add_parser(NAME, help=HELP)
    subs = parser.add_subparsers(dest="plan_cmd", required=True)

    adder = subs.add_parser("add")
    adder.add_argument("--id", required=True, help="计划 ID，如 daily-quick")
    adder.add_argument("--name", default=None)
    adder.add_argument("--kind", default="manual", choices=SCAN_PLAN_KINDS)
    adder.add_argument("--profile", default="weekly", choices=SCAN_PROFILES)
    adder.add_argument("--asset", action="append", default=None, help="资产 ID（可重复）")
    adder.add_argument("--group", default=None)
    adder.add_argument("--role", default=None)
    adder.add_argument("--tag", action="append", default=None)
    adder.add_argument("--min-criticality", dest="min_criticality", type=int, default=None)
    adder.add_argument("--engines", default=None, help="逗号分隔：nmap,pkgs,lynis,testssl,nuclei")
    adder.add_argument("--window-start", dest="window_start", default=None)
    adder.add_argument("--window-end", dest="window_end", default=None)
    adder.add_argument("--rate", type=int, default=500)
    adder.add_argument("--max-hosts", dest="max_hosts", type=int, default=4)
    adder.add_argument("--params", default=None, help="JSON 参数，如 '{\"time\":\"02:30\"}'")
    adder.add_argument("--cve", default=None, help="targeted 计划的 CVE 编号")
    adder.add_argument("--disabled", action="store_true")

    subs.add_parser("list")
    for name in ("enable", "disable", "rm"):
        toggle = subs.add_parser(name)
        toggle.add_argument("--plan-id", dest="plan_id", required=True)


def run(ctx: CliRuntime) -> int:
    """按 ``plan_cmd`` 分派。"""
    action = ctx.args.plan_cmd
    if action == "add":
        return _add(ctx)
    if action in ("enable", "disable"):
        return _toggle(ctx, action == "enable")
    if action == "rm":
        return _remove(ctx)
    return _list(ctx)


def _build_selector(args: argparse.Namespace) -> dict[str, Any]:
    """把零散的目标过滤参数收敛成调度器认识的 selector 字典。

    只写入**用户显式提供**的键：空值不入 selector，否则会覆盖计划里的既有语义。
    """
    selector: dict[str, Any] = {}
    if args.asset:
        selector["asset_ids"] = list(args.asset)
    for key, attr in (("group", "group"), ("role", "role"), ("ip", "ip")):
        value = getattr(args, attr, None)
        if value:
            selector[key] = value
    if args.tag:
        selector["tags"] = list(args.tag)
    if args.min_criticality is not None:
        selector["min_criticality"] = args.min_criticality
    return selector


def _add(ctx: CliRuntime) -> int:
    """保存（或覆盖）一条扫描计划，并回显下次运行时间。"""
    from ...scan import scheduler, store as scan_store

    args = ctx.args
    params = parse_json_arg(args.params, "--params")
    if args.cve:
        params["cve_id"] = args.cve
    store = ctx.store()
    plan = scan_store.upsert_plan(store, {
        "plan_id": args.id,
        "name": args.name or args.id,
        "kind": args.kind,
        "profile": args.profile,
        "selector_json": _build_selector(args),
        "engines_json": split_csv(args.engines) or None,
        "window_start": args.window_start,
        "window_end": args.window_end,
        "rate_limit": args.rate,
        "max_hosts": args.max_hosts,
        "enabled": not bool(args.disabled),
        "params_json": params,
    })
    plan["next_run"] = scheduler.next_run(plan)
    if ctx.json_output:
        ctx.print_json(plan)
    else:
        print(
            f"计划已保存：{plan.get('plan_id')} kind={plan.get('kind')} "
            f"profile={plan.get('profile')} 下次={plan.get('next_run') or '事件触发'}"
        )
    return EXIT_OK


def _toggle(ctx: CliRuntime, enabled: bool) -> int:
    """启用/停用计划；状态未变更返回 1。"""
    from ...scan import store as scan_store

    plan_id = ctx.args.plan_id
    ok = scan_store.set_plan_enabled(ctx.store(), plan_id, enabled)
    ctx.print_json({"ok": ok, "plan_id": plan_id, "enabled": enabled})
    return EXIT_OK if ok else EXIT_FAIL


def _remove(ctx: CliRuntime) -> int:
    """删除计划并报告影响行数。"""
    plan_id = ctx.args.plan_id
    cursor = ctx.store().execute("DELETE FROM scan_plan WHERE plan_id=?", (plan_id,))
    print(f"已删除计划 {plan_id}（{cursor.rowcount} 行）")
    return EXIT_OK


def _list(ctx: CliRuntime) -> int:
    """列出全部计划（带下次运行时间与端口/引擎摘要）。"""
    from ...scan import scheduler, store as scan_store

    store = ctx.store()
    plans = [scheduler.plan_summary(plan, ctx.cfg) for plan in scan_store.list_plans(store)]
    if ctx.json_output:
        ctx.print_json({"plans": plans})
        return EXIT_OK
    ctx.print_table(plans, COLUMNS)
    return EXIT_OK
