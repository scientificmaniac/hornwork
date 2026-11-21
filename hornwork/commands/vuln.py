"""``hornworkctl vuln``：漏洞档案库（记录/查询/匹配/报告）。

四个关注点各自有明确边界：

- ``record add|sync``：档案入库前先做**严格校验**（引用数量、必填字段），校验
  不过直接返回 1 且不写库 —— 档案是后续匹配与整改的依据，不能带病入库；
- ``list`` / ``show``：查询与漏洞卡渲染；
- ``match``：版本 → 档案匹配（IF-18）；
- ``report``：整改单/漏洞卡导出（IF-19）。

``--out`` 传目录时自动补时间戳文件名，这是 IF-19 的返回契约（文件路径 + sha256）。
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from ..cli_common.constants import EXIT_FAIL, EXIT_OK, EXIT_USAGE, VULN_REPORT_FORMATS
from ..cli_common.errors import NotFoundError
from ..cli_common.io import resolve_report_target
from ..cli_common.runtime import CliRuntime
from ..config import cfg_get

NAME = "vuln"
HELP = "靶场模块：漏洞档案库"

COLUMNS = [
    ("id", "编号"), ("cve", "CVE"), ("title", "标题"), ("cwe", "CWE"),
    ("score", "CVSS"), ("severity", "等级"), ("status", "状态"),
]


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``vuln record|list|show|match|report``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="vuln_cmd", required=True)

    record = actions.add_parser("record", help="档案入库/同步")
    subs = record.add_subparsers(dest="record_cmd", required=True)
    add = subs.add_parser("add")
    add.add_argument("path")
    add.add_argument("--dry-run", action="store_true")
    subs.add_parser("sync")

    lister = actions.add_parser("list", help="按类型/等级筛选")
    lister.add_argument("--cwe", default=None)
    lister.add_argument("--severity", default=None)
    lister.add_argument("--status", default=None)
    lister.add_argument("--limit", type=int, default=200)

    show = actions.add_parser("show", help="漏洞卡")
    show.add_argument("vuln_id")

    match = actions.add_parser("match", help="版本→档案匹配（IF-18）")
    match.add_argument("--component", required=True)
    match.add_argument("--version", required=True)
    match.add_argument("--distro", default=None)
    match.add_argument("--cpe", default=None)

    report = actions.add_parser("report", help="导出整改单/漏洞卡报告（IF-19）")
    report.add_argument("--ids", nargs="*", default=None)
    report.add_argument("--format", default="md", choices=VULN_REPORT_FORMATS)
    report.add_argument("--out", default=None)


def run(ctx: CliRuntime) -> int:
    """加载漏洞档案子系统后按 ``vuln_cmd`` 分派。

    未知子命令由 ``add_subparsers(required=True)`` 在 argparse 层拦下，此处
    不再保留不可达的兜底分支。
    """
    try:
        modules = _load_modules(ctx)
    except Exception as exc:  # noqa: BLE001 - 组件缺失时给出可读错误
        print(f"[错误] 靶场模块 vuln 组件不可用：{exc}", file=sys.stderr)
        return EXIT_USAGE

    action = ctx.args.vuln_cmd
    if action == "record":
        return _record(ctx, *modules)
    if action == "list":
        return _list(ctx, *modules)
    if action == "show":
        return _show(ctx, *modules)
    if action == "match":
        return _match(ctx, *modules)
    return _report(ctx, *modules)


def _load_modules(ctx: CliRuntime) -> tuple[Any, ...]:
    """导入漏洞档案子系统并确保建表（CLI 离线可用）。"""
    from ..vuln import match as vuln_match
    from ..vuln import model, report
    from ..vuln import store as vuln_store

    store = ctx.store()
    vuln_store.init_schema(store)
    return store, model, vuln_store, vuln_match, report


def _record(ctx: CliRuntime, store, model, vuln_store, _vmatch, _report) -> int:
    """档案入库：先校验，再（可选 dry-run）落库。"""
    args = ctx.args
    if args.record_cmd == "add":
        record = model.load_record(args.path)
        errors = model.validate_record(record, int(cfg_get(ctx.cfg, "vuln.min_references", 2)))
        if errors:
            print("[错误] 档案校验失败：", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            return EXIT_FAIL
        if getattr(args, "dry_run", False):
            print(f"[dry-run] 校验通过：{record.get('id')} {record.get('cve')}")
            return EXIT_OK
        result = vuln_store.sync_records(store, [record])
        print(f"入库完成：upserted={result.get('upserted')} rejected={result.get('rejected')}")
        for err in result.get("errors") or []:
            print(f"  [warn] {err}")
        return EXIT_OK
    result = vuln_store.seed_from_dir(store, ctx.cfg)
    print(f"同步完成：{result}")
    return EXIT_OK


def _list(ctx: CliRuntime, store, _model, vuln_store, _vmatch, _report) -> int:
    """按 CWE/等级/状态筛选档案。"""
    args = ctx.args
    rows = vuln_store.list_records(
        store,
        cwe=getattr(args, "cwe", None),
        severity=getattr(args, "severity", None),
        status=getattr(args, "status", None),
        limit=int(getattr(args, "limit", 200)),
    )
    if ctx.json_output:
        ctx.print_json({"records": rows})
        return EXIT_OK
    ctx.print_table(
        [
            {
                "id": row.get("id"),
                "cve": row.get("cve"),
                "title": (row.get("title") or "")[:40],
                "cwe": row.get("cwe"),
                "score": row.get("cvss_score"),
                "severity": row.get("severity"),
                "status": row.get("status"),
            }
            for row in rows
        ],
        COLUMNS,
    )
    return EXIT_OK


def _show(ctx: CliRuntime, store, _model, vuln_store, _vmatch, report) -> int:
    """输出单个档案（JSON）或渲染成漏洞卡（人类可读）。"""
    record = vuln_store.get_record(store, ctx.args.vuln_id)
    if record is None:
        raise NotFoundError(f"档案不存在：{ctx.args.vuln_id}")
    if ctx.json_output:
        ctx.print_json(record)
    else:
        print(report.render_card(record))
    return EXIT_OK


def _match(ctx: CliRuntime, store, _model, _vstore, vuln_match, _report) -> int:
    """版本 → 档案匹配，结果恒为 JSON。"""
    args = ctx.args
    request = {
        "component": args.component,
        "version": args.version,
        "distro": getattr(args, "distro", None),
        "cpe": getattr(args, "cpe", None),
    }
    ctx.print_json(vuln_match.match(store, ctx.cfg, request))
    return EXIT_OK


def _report(ctx: CliRuntime, store, _model, _vstore, _vmatch, report) -> int:
    """导出整改单/漏洞卡（``--out`` 可为目录，自动补 ``vuln-report-<时间戳>.<fmt>``）。"""
    args = ctx.args
    out = resolve_report_target(getattr(args, "out", None), args.format, prefix="vuln-report")
    result = report.export_report(
        store, ctx.cfg, ids=getattr(args, "ids", None), fmt=args.format, out=out,
    )
    ctx.print_json(result)
    return EXIT_OK
