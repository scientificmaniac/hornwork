"""漏洞档案层（靶场编排层）：CVSS 计算、版本区间匹配、档案校验入库、整改单导出。

子模块：
- :mod:`hornwork.vuln.cvss`    CVSS 3.1 计算器（parse/build/roundup/calculate/explain），
  与 FIRST 官方计算器 8/8 对拍；
- :mod:`hornwork.vuln.version` Debian/semver 版本比较与 ``in_range`` / ``match_ranges``，
  50+ 组用例与 ``dpkg --compare-versions`` 对拍（Linux 上）；
- :mod:`hornwork.vuln.model`   21 字段档案模型、18 必填校验、YAML 读写；
- :mod:`hornwork.vuln.store`   ``vuln_record`` 表（复用 ``hornwork.db``）、整目录同步、查询；
- :mod:`hornwork.vuln.match`   IF-18：组件+版本 → 档案（供扫描模块进程内调用）；
- :mod:`hornwork.vuln.report`  IF-19：漏洞卡/整改单渲染与 md/json/csv 导出。

对外只暴露文档约定的函数签名；导入期不访问数据库、不做文件 I/O，Windows 上可安全 import。
"""

from __future__ import annotations

from . import cvss, match, model, report, store, version
from .cvss import build, calculate, explain, parse, roundup, severity
from .match import component_matches, match_many, normalize_tokens
from .model import (
    REQUIRED_FIELDS,
    SEVERITIES,
    load_record,
    load_records,
    save_record,
    severity_of,
    validate_record,
)
from .report import export_report, render_card, render_rectification
from .store import (
    get_record,
    init_schema,
    list_records,
    seed_from_dir,
    sync_records,
)
from .version import (
    compare,
    compare_debian,
    compare_semver,
    dpkg_available,
    in_range,
    match_ranges,
)

__all__ = [
    "cvss", "version", "model", "store", "match", "report",
    "parse", "build", "roundup", "calculate", "severity", "explain",
    "compare", "compare_debian", "compare_semver", "in_range", "match_ranges", "dpkg_available",
    "REQUIRED_FIELDS", "SEVERITIES", "load_record", "save_record", "validate_record",
    "severity_of", "load_records",
    "init_schema", "sync_records", "seed_from_dir", "list_records", "get_record",
    "match_many", "component_matches", "normalize_tokens",
    "render_card", "render_rectification", "export_report",
]
