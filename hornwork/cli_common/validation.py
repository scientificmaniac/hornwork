"""CLI 参数校验与解析辅助。

约束：这里的函数只做「字符串 → 基础类型」的转换与快速失败，不访问数据库、
不发网络请求、不读配置文件。业务校验留在各子命令模块内。
"""

from __future__ import annotations

import json
import sys
from typing import Any

from ..cli_common.errors import CliError


def parse_ports(raw: str | None) -> list[int]:
    """把 ``"80,443;8080"`` 解析成 ``[80, 443, 8080]``。

    兼容逗号与分号两种分隔符（历史用法两版都有）；非数字片段静默跳过。
    空串/``None`` 返回空列表。
    """
    ports: list[int] = []
    for chunk in str(raw or "").replace(";", ",").split(","):
        chunk = chunk.strip()
        if chunk.isdigit():
            ports.append(int(chunk))
    return ports


def split_csv(raw: str | None) -> list[str]:
    """把 ``"nmap, pkgs lynis"`` 切成 ``["nmap", "pkgs", "lynis"]``。

    ``--engines`` 的 help 写的是"逗号分隔"，但历史实现同时容忍空格；
    这里保留该宽容度，避免既有脚本失效。
    """
    if not raw:
        return []
    normalized = str(raw).replace(" ", ",")
    return [item.strip() for item in normalized.split(",") if item.strip()]


def parse_json_arg(raw: str | None, option: str) -> Any:
    """解析 ``--params '{"time":"02:30"}'`` 这类 JSON 选项。

    空值返回空 dict；**只有** JSON 语法错误才抛 :class:`CliError`，文案与重构前
    逐字一致（``<option> 不是合法 JSON：<exc>``，退出码 2）。

    非空但结构不是对象的 JSON（如 ``[1,2]``）**原样返回**，不在这里改写：

    - 重构前的实现就是这样——它把 ``[1,2]`` 原样塞进 ``params_json``，随后由
      业务层自己抛错；
    - 若在此静默改成 ``{}``，退出码会从 1 变成 0、traceback 消失、库里还会多写
      一条空 params 的记录 —— 三重行为变更，且会掩盖用户的配置错误。

    类型标注为 ``Any`` 是刻意的：函数契约是"解析 JSON"，不是"保证得到 dict"。
    """
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CliError(f"{option} 不是合法 JSON：{exc}") from exc


def require_daemon(available: bool, command: str) -> None:
    """daemon 缺失时抛 :class:`UnavailableError`。

    文案固定为 ``<command> 需要 daemon 运行``，与重构前各处手写的一致。
    退出码走 :data:`hornwork.cli_common.errors.UnavailableError` 的默认值 2。
    """
    from ..cli_common.errors import UnavailableError

    if not available:
        raise UnavailableError(f"{command} 需要 daemon 运行")


def warn(message: str) -> None:
    """打印一条 ``[warn]`` 提示到 stderr（不改变退出码）。"""
    print(f"[warn] {message}", file=sys.stderr)
