"""``hornworkctl scan cve``：CVE 数据导入、CPE 映射、统计与排除项。

四个动作都只操作本地 SQLite（导入源是本地 NVD/OVAL 文件），因此**不依赖
daemon**：离线主机同样可以灌库，这一点对封闭环境的部署很关键。

``--file`` 的取值语义：
- ``import``：可重复，NVD 可一次给多个文件；OVAL 只取第一个；
- ``map`` / ``exclude``：可省略，省略时回落到配置里的默认路径。
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ...cli_common.constants import CVE_IMPORT_SOURCES, EXIT_FAIL, EXIT_OK
from ...cli_common.errors import CliError
from ...cli_common.io import read_csv_rows
from ...cli_common.runtime import CliRuntime
from ...config import cfg_get

NAME = "cve"
HELP = "CVE 数据：导入/映射/统计/排除"


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan cve import|stats|map|exclude``。"""
    parser = actions.add_parser(NAME, help=HELP)
    subs = parser.add_subparsers(dest="cve_cmd", required=True)

    importer = subs.add_parser("import")
    importer.add_argument("--source", default="nvd", choices=CVE_IMPORT_SOURCES)
    importer.add_argument("--file", action="append", default=None)
    importer.add_argument("--dir", default=None)
    importer.add_argument("--release", default=None, help="OVAL 发行版代号（noble/jammy）")

    subs.add_parser("stats")

    mapper = subs.add_parser("map")
    mapper.add_argument("--file", action="append", default=None)

    excluder = subs.add_parser("exclude")
    excluder.add_argument("--file", action="append", default=None)


def run(ctx: CliRuntime) -> int:
    """按 ``cve_cmd`` 分派。

    未知子命令由 ``add_subparsers(required=True)`` 在 argparse 层拦下，
    此处不再保留不可达的兜底分支。
    """
    action = ctx.args.cve_cmd
    if action == "import":
        return _import(ctx)
    if action == "stats":
        return _stats(ctx)
    if action == "map":
        return _map(ctx)
    return _exclude(ctx)


def _store(ctx: CliRuntime):
    """取得已完成建表的存储层（扫描子系统表结构由本模块保证就绪）。"""
    from ...scan import store as scan_store

    store = ctx.store()
    scan_store.init_schema(store)
    return store


def _import(ctx: CliRuntime) -> int:
    """导入 NVD / OVAL 数据。"""
    from ...scan.cve import feed

    args = ctx.args
    store = _store(ctx)
    source = args.source or "nvd"
    if source == "nvd":
        paths = list(args.file or [])
        if args.dir:
            result = feed.import_dir(store, args.dir)
        elif paths:
            result = feed.import_nvd(store, paths)
        else:
            raise CliError("需要 --file <NVD JSON/JSON.GZ>（可重复）或 --dir <目录>")
    elif source == "oval":
        if not args.file:
            raise CliError("OVAL 导入需要 --file <oval.xml.bz2>")
        result = feed.import_oval(store, args.file[0], release=args.release)
    else:
        raise CliError(f"未知数据源：{source}")
    ctx.print_json(result)
    # 有错误且没导入任何行才算失败；部分失败仍返回 0（重构前语义）。
    return EXIT_OK if not result.get("errors") or result.get("imported_rows") else EXIT_FAIL


def _stats(ctx: CliRuntime) -> int:
    """输出导入量统计与等级分布。"""
    from ...scan import store as scan_store
    from ...scan.cve import feed

    store = _store(ctx)
    result = feed.stats(store)
    result["severity_dist"] = scan_store.cve_severity_counts(store)
    ctx.print_json(result)
    return EXIT_OK


def _map(ctx: CliRuntime) -> int:
    """导入组件→CPE 映射表（省略 --file 时用配置默认路径）。"""
    from ...scan.cve import cmap

    args = ctx.args
    store = _store(ctx)
    path = args.file[0] if args.file else str(cfg_get(ctx.cfg, "scan.rules.comp_map", "") or "")
    result = cmap.import_csv(store, path)
    ctx.print_json(result)
    return EXIT_OK if not result.get("errors") else EXIT_FAIL


def _exclude(ctx: CliRuntime) -> int:
    """导入 CVE 排除项 CSV（省略 --file 时用配置默认路径）。"""
    args = ctx.args
    store = _store(ctx)
    path = args.file[0] if args.file else str(cfg_get(ctx.cfg, "scan.rules.cve_exclude", "") or "")
    result = import_cve_exclude(store, path)
    ctx.print_json(result)
    return EXIT_OK if not result.get("errors") else EXIT_FAIL


def import_cve_exclude(store: Any, path: str) -> dict:
    """导入排除项 CSV：``cve_id,comp_norm,version,reason``。

    缺少 ``cve_id`` 或 ``comp_norm`` 的行计入 ``skipped``（不是错误）：
    这类行通常来自人工维护表里的空行或注释行。
    """
    result: dict[str, Any] = {"path": path, "upserted": 0, "skipped": 0, "errors": []}
    if not path or not Path(path).is_file():
        result["errors"].append("排除项文件不存在")
        return result
    try:
        for row in read_csv_rows(path):
            cve = str(row.get("cve_id") or "").strip()
            comp = str(row.get("comp_norm") or "").strip()
            if not cve or not comp:
                result["skipped"] += 1
                continue
            store.execute(
                "INSERT OR REPLACE INTO scan_cve_exclude(cve_id, comp_norm, version, reason)"
                " VALUES(?,?,?,?)",
                (cve, comp, row.get("version") or None, row.get("reason") or None),
            )
            result["upserted"] += 1
    except OSError as exc:
        result["errors"].append(str(exc))
    return result
