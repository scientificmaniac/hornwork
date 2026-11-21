"""``hornworkctl scan``：扫描命令组的注册与分派。

## 为什么 ``scan`` 是一个子包

``scan`` 下有 13 个二级子命令。全部塞进一个文件会立刻长成第二个 1500 行，
因此按「一个二级子命令一个文件」再拆一层，与顶层命令的拆分粒度保持一致：

============  ==========================================
二级子命令    模块
============  ==========================================
``file``      :mod:`.file`
``plan``      :mod:`.plan`
``run``       :mod:`.run`
``status``    :mod:`.status`
``findings``  :mod:`.findings`
``finding``   :mod:`.finding`
``diff``      :mod:`.diff`
``coverage``  :mod:`.coverage`
``report``    :mod:`.report`
``snapshot``  :mod:`.snapshot`
``cve``       :mod:`.cve`
``retry``     :mod:`.retry`
``cancel``    :mod:`.cancel`
============  ==========================================

## 两个实现细节（都是踩过的坑）

1. **子模块导入使用 ``_xxx`` 别名**。本模块自身必须导出 ``run(ctx)``（命令契约），
   而其中恰好有一个子模块也叫 ``run``；若直接 ``from . import run``，后定义的
   ``def run`` 会把模块名覆盖成函数，``register()`` 遍历时就会拿到函数而非模块
   （``AttributeError: 'function' object has no attribute 'register'``）。
2. **分派表存模块对象而非模块名字符串**。这样静态分析能看到真实依赖，模块改名
   或删文件时**导入即报错**，而不是等用户敲命令才 KeyError。
"""

from __future__ import annotations

import argparse
from collections.abc import Callable

from ...cli_common.runtime import CliRuntime
from . import (
    cancel as _cancel,
    coverage as _coverage,
    cve as _cve,
    diff as _diff,
    file as _file,
    finding as _finding,
    findings as _findings,
    plan as _plan,
    report as _report,
    retry as _retry,
    run as _run,
    snapshot as _snapshot,
    status as _status,
)

NAME = "scan"
HELP = "扫描：文件扫描 / 定期漏洞扫描"

SubCommand = Callable[[CliRuntime], int]

_MODULES = (
    _file, _plan, _run, _status, _findings, _finding, _diff,
    _coverage, _report, _snapshot, _cve, _retry, _cancel,
)
"""全部二级子命令模块，顺序即 ``scan --help`` 中的展示顺序。"""

_HANDLERS: dict[str, SubCommand] = {module.NAME: module.run for module in _MODULES}
"""二级子命令 → 执行函数。键取自各模块的 ``NAME``，避免两处字符串重复。"""


def register(sub: argparse._SubParsersAction) -> None:
    """挂载 ``scan`` 及其全部二级子命令。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="scan_cmd", required=True)
    for module in _MODULES:
        module.register(actions)


def run(ctx: CliRuntime) -> int:
    """按 ``scan_cmd`` 分派到对应二级子命令模块。

    ``scan_cmd`` 缺失时默认 ``file`` —— 这是 ``scan <path>`` 旧写法的落点
    （由 :func:`hornwork.cli._normalize_argv` 归一化后通常已显式带上 ``file``）。

    这里不再保留"未知子命令 → 退出码 2"的防御分支：``add_subparsers(required=True)``
    已在 argparse 层拦住一切未知值并以退出码 2 结束，该分支永远不可达。
    """
    subcommand = getattr(ctx.args, "scan_cmd", None) or _file.NAME
    return _HANDLERS[subcommand](ctx)
