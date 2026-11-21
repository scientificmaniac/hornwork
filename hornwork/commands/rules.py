"""``hornworkctl rules``：规则热重载与规则清单。

``reload`` 必须由 daemon 执行（规则热加载在服务进程内）；``list`` 则优先复用
daemon 的实时统计，daemon 缺席时退化为「数文件」—— 后者不解析规则内容，只给出
条数，足以判断部署是否完整。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_OK
from ..cli_common.runtime import CliRuntime
from ..cli_common.validation import require_daemon
from ..config import rule_dir

NAME = "rules"
HELP = "规则管理"


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``rules reload`` / ``rules list``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="rules_cmd", required=True)
    actions.add_parser("reload")
    actions.add_parser("list")


def run(ctx: CliRuntime) -> int:
    """按二级子命令执行。"""
    if ctx.args.rules_cmd == "reload":
        require_daemon(ctx.daemon_up(), "rules reload")
        ctx.print_json(ctx.ctl("rules.reload"))
        return EXIT_OK
    if ctx.daemon_up():
        status = ctx.ctl("status")
        ctx.print_json({"sigma": status.get("sigma"), "engines": status.get("engines")})
    else:
        _print_offline_inventory(ctx)
    return EXIT_OK


def _print_offline_inventory(ctx: CliRuntime) -> None:
    """离线清点四类规则目录：只数文件，不解析内容。"""
    yara = rule_dir(ctx.cfg, "yara")
    net = rule_dir(ctx.cfg, "net")
    host = rule_dir(ctx.cfg, "host")
    sigma = rule_dir(ctx.cfg, "sigma")
    print(f"YARA 规则：{len(list(yara.glob('*.yar')))} 条（{yara}）")
    print(f"网络规则：{len(list(net.glob('*.rules')))} 个文件（{net}）")
    print(f"主机规则：{len(list(host.glob('*.json')))} 条（{host}）")
    print(f"Sigma 规则：{len(list(sigma.rglob('*.yml')))} 条（{sigma}）")
