"""``CliRuntime``：所有子命令模块共享的运行上下文。

它把「解析好的参数 + 合并后的配置 + 控制面客户端 + 懒打开的 SQLite」打包成
一个对象，替代重构前 ``Cli`` 实例上散落的 ``self.args / self.cfg / self.client``
访问。子命令模块只拿到这一个入口，因此：

- 不需要各自重复 ``load_config`` / ``CtlClient(...)``；
- 依赖方向单一（命令模块 → ``cli_common``），命令模块之间互不引用；
- 单测可构造一个轻量替身，不必真的连 socket。
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from typing import Any

from ..cli_common.config import socket_path
from ..cli_common.output import Column, print_json, print_table
from ..client import CtlClient, CtlError
from ..config import load_config
from ..store import Store, open_store


class CliRuntime:
    """一次 CLI 调用的运行上下文。

    Parameters
    ----------
    args:
        已由 ``argparse`` 解析完成的命名空间。
    cfg:
        已与 ``DEFAULTS`` 合并的配置字典。``None`` 时按 ``args.config`` 现读。

    Attributes
    ----------
    socket_path:
        控制面 socket 实际路径（命令行 ``--socket`` 优先于配置）。
    store:
        惰性打开的 SQLite 句柄；仅在 daemon 未运行或需要直读库时才会真正建连。
    """

    def __init__(self, args: argparse.Namespace, cfg: dict | None = None):
        self.args = args
        self.cfg = cfg if cfg is not None else load_config(getattr(args, "config", None))
        # socket 路径的推导规则（--socket 优先）只在 config.socket_path 里定义一次
        self._socket_path = socket_path(args, self.cfg)
        self.client = CtlClient(self._socket_path, timeout=float(getattr(args, "timeout", 600)))
        self._store: Store | None = None

    # ------------------------------------------------------------------ 基础设施
    @property
    def socket_path(self) -> str:
        """控制面 socket 路径（``status`` 的离线提示需要原样展示它）。"""
        return self._socket_path

    @property
    def json_output(self) -> bool:
        """是否要求机读 JSON 输出（``--json``）。"""
        return bool(getattr(self.args, "json", False))

    def daemon_up(self) -> bool:
        """daemon 是否在监听控制面 socket。"""
        return self.client.available()

    def ctl(self, method: str, params: dict | None = None) -> Any:
        """调用控制面方法；``CtlError`` 转为 ``[错误] ...`` + 退出码 2。"""
        try:
            return self.client.call(method, params or {})
        except CtlError as exc:
            print(f"[错误] {exc.message}", file=sys.stderr)
            raise SystemExit(2) from exc

    def store(self) -> Store:
        """返回（必要时打开）SQLite 存储层；同一进程内只打开一次。"""
        if self._store is None:
            self._store = open_store(self.cfg)
        return self._store

    # ------------------------------------------------------------------ 输出
    def emit(self, obj: Any, rows: Sequence[dict], columns: Sequence[Column]) -> None:
        """按 ``--json`` 选择输出 JSON 全文或等宽表格。"""
        if self.json_output:
            print_json(obj)
        else:
            print_table(rows, columns)

    def print_json(self, obj: Any) -> None:
        """无条件打印 JSON（部分子命令即使非 ``--json`` 也输出 JSON）。"""
        print_json(obj)

    def print_table(
        self,
        rows: Sequence[dict],
        columns: Sequence[Column],
        empty: str | None = None,
    ) -> None:
        """无条件打印表格；``empty`` 为 ``None`` 时用公共默认占位语。"""
        if empty is None:
            print_table(rows, columns)
        else:
            print_table(rows, columns, empty=empty)
