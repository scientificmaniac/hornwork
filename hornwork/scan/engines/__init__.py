"""扫描引擎适配层（扫描模块 IF-20）：统一协议 + 五个适配器 + 工厂。

引擎分工：

===========  ======================  ==============================================
适配器       检查域                  外部依赖（独立进程，可一键禁用）
===========  ======================  ==============================================
``nmap``     D1 端口 / D3 组件       nmap（``-sV`` + XML）
``pkgs``     D2 系统补丁             dpkg-query（本机）或 ssh + dpkg-query（远端）
``lynis``    D4 主机基线             lynis（需 root）
``testssl``  D5 TLS 配置             testssl.sh
``nuclei``   D6 Web/应用 PoC         nuclei + nuclei-templates
===========  ======================  ==============================================

约定：
- 适配器只做"执行 + 解析"，**不访问数据库、不写业务文件**；归一/匹配/diff 在上层；
- ``build_adapters(cfg)`` 只实例化、不探测可用性（``available()`` 由 runner 调用，
  便于把"引擎不可用"记成 ``engine_skipped`` 而不是任务失败）；
- 导入期不执行外部命令（Windows 开发机可安全 import）。
"""

from __future__ import annotations

from .base import ScanAdapter, ScanContext, binary_available
from .lynis_adapter import LynisAdapter
from .nmap_adapter import NmapAdapter
from .nuclei_adapter import NucleiAdapter
from .pkgs import PkgsAdapter
from .testssl_adapter import TestsslAdapter

#: 引擎装配顺序（runner 的 checkpoint / 消融按此顺序稳定输出）
ADAPTER_ORDER: tuple[str, ...] = ("nmap", "pkgs", "lynis", "testssl", "nuclei")

#: 引擎类（按 ADAPTER_ORDER 排序）
ADAPTER_CLASSES: tuple[type, ...] = (
    NmapAdapter, PkgsAdapter, LynisAdapter, TestsslAdapter, NucleiAdapter,
)


def build_adapters(cfg: dict) -> list:
    """按固定顺序实例化全部适配器，**不探测可用性**。

    返回 ``[NmapAdapter(cfg), PkgsAdapter(cfg), LynisAdapter(cfg), TestsslAdapter(cfg),
    NucleiAdapter(cfg)]``；runner 再用 ``available()`` / ``supports()`` 过滤，
    以便区分"计划未选""引擎不可用""不适用该资产"三种跳过原因。
    """
    cfg = cfg or {}
    return [adapter_cls(cfg) for adapter_cls in ADAPTER_CLASSES]


def build_adapter_map(cfg: dict) -> dict:
    """``{name: adapter}``，便于 runner 按 ``scan_plan.engines_json`` 取指定引擎。"""
    return {adapter.name: adapter for adapter in build_adapters(cfg)}


__all__ = [
    "ADAPTER_CLASSES",
    "ADAPTER_ORDER",
    "LynisAdapter",
    "NmapAdapter",
    "NucleiAdapter",
    "PkgsAdapter",
    "ScanAdapter",
    "ScanContext",
    "TestsslAdapter",
    "binary_available",
    "build_adapter_map",
    "build_adapters",
]
