"""靶场编排：Vulhub 靶场编排层（labctl）。

本包负责"把 Vulhub 环境安全地起停、探测、记录"：
- ``index``   ：扫描 /opt/vulhub 生成 vulhub-index.json（唯一事实来源）；
- ``runner``  ：local / ssh 两种后端的命令执行器（IF-17）；
- ``ports``   ：compose 端口解析、端口占用探测与区间分配；
- ``compose`` ：生成端口重写后的覆盖副本，封装 up/down/ps/logs；
- ``guard``   ：资源闸门、快照标记、目标白名单；
- ``store``   ：`lab_env` / `lab_run` 两张表的读写；
- ``ctl``     ：对外的 `LabCtl` 编排状态机。

依赖只有标准库 + PyYAML；所有系统命令/子进程调用都在函数体内执行，
因此在 Windows 开发机上 ``import hornwork.lab`` 不会报错。
"""

from __future__ import annotations

from . import compose, guard, index, ports, runner, store
from .ctl import LabCtl
from .index import build_index, load_index, parse_compose
from .runner import CommandRunner, Result

__all__ = [
    "LabCtl",
    "CommandRunner",
    "Result",
    "build_index",
    "load_index",
    "parse_compose",
    "compose",
    "guard",
    "index",
    "ports",
    "runner",
    "store",
]
