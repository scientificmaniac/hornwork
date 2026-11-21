"""``hornworkctl asset``：资产台账（扫描的唯一目标来源）。

台账是扫描子系统的「谁会被告知该扫什么」的唯一入口，因此本模块只做参数搬运与
呈现，**不做**任何目标推导 —— 目标选择逻辑集中在 ``scan.assets``，避免两处
各写一份"哪些资产该扫"。

离线可用：台账读写直接走 SQLite，不依赖 daemon（现场登记主机是常见操作）。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import ASSET_ROLES, EXIT_FAIL, EXIT_OK
from ..cli_common.errors import CliError, NotFoundError
from ..cli_common.runtime import CliRuntime
from ..cli_common.validation import parse_ports

NAME = "asset"
HELP = "扫描模块：资产台账"

COLUMNS = [
    ("asset_id", "资产"), ("ip", "IP"), ("hostname", "主机名"), ("role", "角色"),
    ("criticality", "重要度"), ("group_name", "分组"), ("declared_ports", "声明端口"),
    ("enabled", "启用"),
]


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``asset add|list|show|enable|disable``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="asset_cmd", required=True)

    adder = actions.add_parser("add")
    adder.add_argument("--id", dest="asset_id", default=None, help="显式资产 ID（如 ast-self/ast-lab）")
    adder.add_argument("--ip", required=True)
    adder.add_argument("--hostname", default=None)
    adder.add_argument("--role", default="server", choices=ASSET_ROLES)
    adder.add_argument("--criticality", type=int, default=3)
    adder.add_argument("--group", default=None)
    adder.add_argument("--tags", default=None, help="逗号分隔")
    adder.add_argument("--cred-ref", dest="cred_ref", default=None)
    adder.add_argument("--ports", default=None, help="声明端口，逗号分隔")
    adder.add_argument("--self", dest="self_asset", action="store_true")
    adder.add_argument("--disabled", action="store_true")

    actions.add_parser("list")

    shower = actions.add_parser("show")
    shower.add_argument("asset_id")

    for name in ("enable", "disable"):
        toggle = actions.add_parser(name)
        toggle.add_argument("asset_id")


def run(ctx: CliRuntime) -> int:
    """按二级子命令分派到具体实现。"""
    action = ctx.args.asset_cmd
    if action == "add":
        return _add(ctx)
    if action == "show":
        return _show(ctx)
    if action in ("enable", "disable"):
        return _toggle(ctx, action == "enable")
    return _list(ctx)


def _add(ctx: CliRuntime) -> int:
    """登记资产；重复 IP 或非法参数给出可读错误。"""
    from ..scan import assets as scan_assets, store as scan_store

    args = ctx.args
    store = ctx.store()
    scan_store.init_schema(store)
    try:
        asset = scan_assets.add_asset(
            store, ctx.cfg,
            ip=args.ip,
            asset_id=getattr(args, "asset_id", None),
            hostname=args.hostname,
            role=args.role,
            criticality=args.criticality,
            group=args.group,
            tags=args.tags,
            cred_ref=args.cred_ref,
            is_self=bool(args.self_asset),
            enabled=not bool(args.disabled),
            declared_ports=parse_ports(getattr(args, "ports", None)),
        )
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    if ctx.json_output:
        ctx.print_json(asset)
    else:
        print(f"资产已登记：{asset.get('asset_id')} {asset.get('ip')} role={asset.get('role')}")
    return EXIT_OK


def _show(ctx: CliRuntime) -> int:
    """按资产 ID 或 IP 查看单个资产。"""
    from ..scan import assets as scan_assets, store as scan_store

    store = ctx.store()
    scan_store.init_schema(store)
    key = ctx.args.asset_id
    asset = scan_store.get_asset(store, key) or scan_store.get_asset_by_ip(store, key)
    if not asset:
        raise NotFoundError(f"资产不存在：{key}")
    ctx.print_json(scan_assets.asset_view(asset))
    return EXIT_OK


def _toggle(ctx: CliRuntime, enabled: bool) -> int:
    """启用/停用资产；状态未变更时返回 1（与重构前一致）。"""
    from ..scan import store as scan_store

    store = ctx.store()
    scan_store.init_schema(store)
    asset_id = ctx.args.asset_id
    ok = scan_store.set_asset_enabled(store, asset_id, enabled)
    ctx.print_json({"ok": ok, "asset_id": asset_id, "enabled": enabled})
    return EXIT_OK if ok else EXIT_FAIL


def _list(ctx: CliRuntime) -> int:
    """列出全部资产。"""
    from ..scan import assets as scan_assets, store as scan_store

    store = ctx.store()
    scan_store.init_schema(store)
    rows = [scan_assets.asset_view(asset) for asset in scan_store.list_assets(store)]
    if ctx.json_output:
        ctx.print_json({"assets": rows})
        return EXIT_OK
    ctx.print_table(rows, COLUMNS)
    return EXIT_OK
