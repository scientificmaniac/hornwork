"""Hornwork 检测引擎层。

对外导出：
- 静态扫描：`SigDbEngine` / `YaraEngine` / `ClamavEngine` / `Cascade` / `ContributionTracker`；
- 主机事件：`HostRuleEngine`（JSON DSL）/ `SigmaMatcher`（Sigma 子集）；
- 网络：`FlowTable` / `Tracker` / `NetRuleSet`（网络规则 DSL）；
- 协议与命中工具：`BaseScanEngine` / `BaseEventEngine` / `make_hit` 等。

第三方依赖（yara-python、PyYAML）在各模块内 try/except 导入：Windows 开发机缺包时
模块仍可 import，相应引擎 `available()` 返回 False（Sigma 的 `reload()` 返回错误信息）。
"""

from __future__ import annotations

from typing import Any

from .base import (
    BaseEventEngine,
    BaseScanEngine,
    Hit,
    ScanContext,
    hit_to_alert_fields,
    make_hit,
    merge_hits,
    normalize_hit,
)
from .cascade import Cascade, guess_filetype
from .clamd_client import ClamavEngine, ping, scan_stream
from .contribution import ContributionTracker
from .hostrules import HostRuleEngine
from .netflow import FlowTable, packet_ts, parse_flags_set
from .netrules import NetRule, NetRuleSet, parse_rules
from .sigma_matcher import SigmaMatcher
from .sigdb import SigDbEngine
from .tracker import Tracker
from .yara_bridge import YaraEngine

__all__ = [
    "BaseEventEngine", "BaseScanEngine", "Hit", "ScanContext",
    "hit_to_alert_fields", "make_hit", "merge_hits", "normalize_hit",
    "SigDbEngine", "YaraEngine", "ClamavEngine", "Cascade",
    "ContributionTracker", "guess_filetype",
    "HostRuleEngine", "SigmaMatcher",
    "FlowTable", "Tracker", "NetRuleSet", "NetRule", "parse_rules",
    "packet_ts", "parse_flags_set", "ping", "scan_stream",
    "build_scan_engines",
]


def build_scan_engines(cfg: dict, store: Any = None) -> list:
    """按默认装配顺序构建静态扫描引擎列表（不含 hash 伪引擎）。

    顺序与 `engines.order` 一致；Cascade 内部还会再按配置排序。
    """
    return [SigDbEngine(cfg, store), YaraEngine(cfg), ClamavEngine(cfg)]
