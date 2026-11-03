"""情报层：feed 解析 → IOC 仓库 → 规则产物 / STIX 互通。

子模块：
- :mod:`hornwork.intel.feeds`    JSONL/CSV 解析与规范化过滤；
- :mod:`hornwork.intel.iocstore` IOC 生命周期与取值集合（供 netrules 注入）；
- :mod:`hornwork.intel.intel2rule` IOC → YARA/网络规则/主机规则产物；
- :mod:`hornwork.intel.stix`     STIX 2.1 子集导出/导入。

导入期不加载任何第三方库，可在 Windows 开发机安全 import。
"""

from __future__ import annotations

from . import feeds, intel2rule, iocstore, stix
from .feeds import load_feed, normalize_record, parse_csv, parse_jsonl
from .intel2rule import build, validate_files
from .iocstore import IocStore, ioc_id_for, normalize_kind
from .stix import export_bundle, parse_bundle, read_bundle, write_bundle

__all__ = [
    "feeds",
    "iocstore",
    "intel2rule",
    "stix",
    "load_feed",
    "parse_jsonl",
    "parse_csv",
    "normalize_record",
    "IocStore",
    "ioc_id_for",
    "normalize_kind",
    "build",
    "validate_files",
    "export_bundle",
    "parse_bundle",
    "write_bundle",
    "read_bundle",
]
