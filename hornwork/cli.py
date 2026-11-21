"""``hornworkctl``：Hornwork 命令行客户端（入口文件）。

## 职责边界（本文件只做这三件事）

1. **注册**：调用各子命令模块的 ``register(sub)`` 把 argparse 树挂起来；
2. **归一化**：兼容旧写法 ``hornworkctl scan <path>``（自动补 ``file``）；
3. **调度**：解析参数 → 构造 :class:`~hornwork.cli_common.runtime.CliRuntime`
   → 调 ``run(ctx)`` → 返回确定性退出码（含 Ctrl-C → 130）。

任何业务逻辑都不在这里。新增子命令**不需要改本文件**，只要在
``hornwork.commands`` 的注册表里登记一行。

## 数据来源策略

- 优先通过 Unix socket 控制面（默认 ``/run/hornwork/ctl.sock``）与 daemon 通信；
- daemon 未运行时，只读命令（status/events/alerts/audit/export 等）直接读 SQLite；
- ``scan file`` 在 daemon 未运行时用同一套引擎做离线扫描，便于现场演示。

## 向后兼容入口

``hornwork.cli:main`` 仍是 ``pyproject.toml`` 与 ``Makefile`` 引用的入口，
签名与返回值语义不变，因此 ``python -m hornwork.cli``、``hornworkctl``
与 ``make rules`` 三条既有路径都不需要改。
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .cli_common.config import apply_config_default
from .cli_common.constants import DEFAULT_TIMEOUT, EXIT_INTERRUPT, SCAN_SUBCOMMANDS
from .cli_common.errors import CliError
from .cli_common.runtime import CliRuntime
from .commands import COMMANDS


def build_parser() -> argparse.ArgumentParser:
    """构造完整的 ``hornworkctl`` 解析器。

    顶层参数的顺序、默认值与 help 文案都是对外契约的一部分 —— 它们会出现在
    ``--help`` 与 shell 补全里，因此保持与重构前逐字一致。

    子命令由 :data:`hornwork.commands.COMMANDS` 顺序驱动，顺序即 ``--help``
    中的展示顺序。
    """
    parser = argparse.ArgumentParser(prog="hornworkctl", description="Hornwork 控制台 CLI")
    parser.add_argument(
        "-c", "--config", default=None,
        help="配置文件（默认 /opt/hornwork/config.toml 或 ./config.toml）",
    )
    parser.add_argument("--socket", default=None, help="控制面 socket 路径")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    parser.add_argument("--timeout", default=DEFAULT_TIMEOUT, type=float, help="控制面超时秒")
    parser.add_argument("--version", action="version", version=f"hornworkctl {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for module in COMMANDS:
        module.register(sub)
    return parser


def _normalize_argv(argv: list[str]) -> list[str]:
    """兼容旧用法 ``hornworkctl scan <file>``：自动补 ``file`` 子命令。

    扫描子系统把 ``scan`` 变成了命令组（``scan plan/run/diff/...``），但既有脚本
    与文档仍可能写 ``hornworkctl scan /tmp/eicar.com``。这里做一次无痛兼容：
    首个非选项 token 不在子命令集合里时，就把它当成文件路径并插入 ``file``。
    """
    if not argv or argv[0] != "scan":
        return argv
    for index, token in enumerate(argv[1:], start=1):
        if token.startswith("-"):
            continue
        if token in SCAN_SUBCOMMANDS:
            return argv
        return argv[:index] + ["file"] + argv[index:]
    return argv


def main(argv: list[str] | None = None) -> int:
    """CLI 主入口：返回进程退出码（不直接 ``sys.exit``，便于单测调用）。

    Parameters
    ----------
    argv:
        不含程序名的参数列表；``None`` 时取 ``sys.argv[1:]``。

    Raises
    ------
    SystemExit
        ``argparse`` 的用法错误、``--help``、``--version``，以及控制面调用失败
        （``CtlError`` → 退出码 2）都会以 ``SystemExit`` 向上传播 —— 与重构前
        完全一致，脚本可继续依赖这些退出码。
    """
    raw = list(argv if argv is not None else sys.argv[1:])
    args = build_parser().parse_args(_normalize_argv(raw))
    apply_config_default(args)
    handlers = {module.NAME: module.run for module in COMMANDS}
    try:
        return handlers[args.cmd](CliRuntime(args))
    except CliError as exc:
        _report_cli_error(exc)
        return exc.exit_code
    except KeyboardInterrupt:
        return EXIT_INTERRUPT


def _report_cli_error(exc: CliError) -> None:
    """把 :class:`CliError` 渲染成 ``[错误] <msg>``（+ 可选提示）到 stderr。"""
    print(f"[错误] {exc.message}", file=sys.stderr)
    if exc.hint:
        print(f"  {exc.hint}", file=sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
