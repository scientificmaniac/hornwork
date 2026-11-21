#!/usr/bin/env python3
"""CLI 对外接口快照工具（重构前后兼容性比对用）。

用途：
- 递归遍历 ``hornwork.cli.build_parser()`` 的命令树，导出每个命令的
  ``--help`` 文本与参数元数据，形成可 diff 的文本快照；
- 重构前后各导出一次，``diff`` 为空即证明「子命令名 / 参数名 / 参数顺序 /
  默认值 / choices / help 文档」零变化。

用法：
    python -m tools.cli_surface dump > surface-before.txt
    # …… 重构 ……
    python -m tools.cli_surface dump > surface-after.txt
    diff -u surface-before.txt surface-after.txt

说明：脚本只读 argparse 结构，不执行任何子命令，也不需要 root。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import typing
from typing import Any

# 固定帮助宽度，避免终端 COLUMNS 不同导致 diff 噪声。
os.environ.setdefault("COLUMNS", "100")


def _type_name(action: argparse.Action) -> str:
    """把 action.type 归一成稳定字符串（lambda/partial 取 __name__）。"""
    func = action.type
    if func is None:
        return "-"
    return getattr(func, "__name__", repr(func))


def _action_row(action: argparse.Action) -> dict[str, Any]:
    default = action.default
    if isinstance(default, (str, int, float, bool, type(None), list, tuple)):
        shown_default: Any = default
    else:  # 不可序列化的默认值只记类型名，避免快照抖动
        shown_default = f"<{type(default).__name__}>"
    return {
        "option_strings": list(action.option_strings),
        "dest": action.dest,
        "action": type(action).__name__,
        "nargs": action.nargs,
        "type": _type_name(action),
        "choices": list(action.choices) if action.choices else None,
        "required": bool(action.required),
        "default": shown_default,
        "help": action.help,
        "metavar": action.metavar,
    }


def _subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction | None:
    """找到 parser 上挂载的子命令 action（argparse 未提供公开 API）。"""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


def walk(parser: argparse.ArgumentParser, path: tuple[str, ...] = ()) -> typing.Iterator[
    tuple[tuple[str, ...], argparse.ArgumentParser]
]:
    """深度优先遍历命令树，产出 (命令路径, 该层 parser)。"""
    yield path, parser
    sub = _subparsers(parser)
    if sub is None:
        return
    for name, child in sub.choices.items():
        yield from walk(child, (*path, name))


def dump() -> None:
    from hornwork.cli import build_parser

    root = build_parser()
    for path, parser in walk(root):
        cmd = " ".join(("hornworkctl", *path))
        print(f"===== {'CMD':<12}{cmd}")
        print("----- HELP")
        print(parser.format_help().rstrip())
        print("----- ACTIONS")
        for action in parser._actions:
            print(json.dumps(_action_row(action), ensure_ascii=False, sort_keys=False))
        print()


def main(argv: list[str] | None = None) -> int:
    args = (argv if argv is not None else sys.argv[1:]) or ["dump"]
    if args[0] != "dump":
        print(__doc__.strip(), file=sys.stderr)
        return 2
    dump()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
