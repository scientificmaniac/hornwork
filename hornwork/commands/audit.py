"""``hornworkctl audit``：审计哈希链完整性校验。

两条路径：

1. daemon 在线 → ``audit.verify``（服务内已持有链状态）；
2. 离线 → 直读 ``audit_rows()`` 后在本进程内重算链。

离线路径之所以必须存在：审计链校验是"出事之后"的操作，恰恰最可能发生在
daemon 已经停掉的时候。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_FAIL, EXIT_OK
from ..cli_common.runtime import CliRuntime

NAME = "audit"
HELP = "审计链"


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``audit verify``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="audit_cmd", required=True)
    actions.add_parser("verify")


def run(ctx: CliRuntime) -> int:
    """校验审计链，退出码直接反映结论（0 完整 / 1 断链）。"""
    if ctx.daemon_up():
        result = ctx.ctl("audit.verify")
    else:
        result = _verify_offline(ctx)
    ctx.print_json(result)
    if result.get("ok"):
        print("审计链完整")
        return EXIT_OK
    print(f"审计链断链于 seq={result.get('broken_seq')}")
    return EXIT_FAIL


def _verify_offline(ctx: CliRuntime) -> dict:
    """在本进程内重算哈希链（不依赖 daemon）。"""
    from ..respond.actions import verify_chain

    rows = ctx.store().audit_rows()
    ok, broken = verify_chain(rows)
    return {"ok": ok, "rows": len(rows), "broken_seq": broken}
