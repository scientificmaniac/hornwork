"""CPE 2.3 解析与"本地组件名 ↔ CPE 前缀"映射（``cve_component_map`` 表）。

扫描模块的匹配链路是 ``comp_norm → CPE 前缀 → cve_cache 粗筛 → 版本精判``，本文件负责第一跳：

- :func:`parse_cpe23`：CPE 2.3/2.2 → ``{part, vendor, product, version, update, rest}``；
- :func:`to_cpe23_prefix`：完整 CPE 或 2.2 URI → 2.3 前缀 ``cpe:2.3:a:vendor:product:``，
  前缀是 SQL 粗筛的入参（``LIKE '前缀%'``），保证"产品边界"不被误扩；
- :func:`import_csv` / :func:`seed_from_dir`：导入 ``rules/scan/comp_map.csv``（人工维护的映射表，
  CPE vendor/product 必须准确，拿不准的写在 ``note`` 里标"待核实"，**不编造**）；
- :func:`resolve`：组件名 → CPE 前缀列表（一个组件可映射多个前缀，如 nginx 的
  ``nginx:nginx`` 与 ``f5:nginx``）。

导入期不读文件、不连库；文件与数据库访问都发生在函数调用内，Windows 上可安全 import。
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from ...config import cfg_get
from ...log import get_logger
from .version import split_unescaped

log = get_logger("scan.cve.cmap")

#: 生产环境默认映射表路径（配置项 ``scan.rules.comp_map`` 优先）
DEFAULT_COMP_MAP = "/opt/hornwork/rules/scan/comp_map.csv"

#: CPE 表头（CSV 契约）
CSV_HEADER: tuple[str, ...] = ("comp_norm", "cpe23", "source", "note")

#: 合法的 CPE part（应用/操作系统/硬件），其余视为非法前缀
_VALID_PARTS: frozenset[str] = frozenset({"a", "o", "h"})


# ---------------------------------------------------------------------------
# 组件名归一
# ---------------------------------------------------------------------------
def normalize_comp(comp_norm: Any) -> str:
    """组件名归一：小写、空格/下划线 → 连字符、压缩连续连字符。

    ``"OpenSSH"``/``"apache httpd"``/``"spring_cloud_gateway"`` →
    ``"openssh"``/``"apache-httpd"``/``"spring-cloud-gateway"``。
    """
    text = str(comp_norm if comp_norm is not None else "").strip().lower()
    if not text:
        return ""
    for char in (" ", "_", "/"):
        text = text.replace(char, "-")
    while "--" in text:
        text = text.replace("--", "-")
    return text.strip("-")


# ---------------------------------------------------------------------------
# CPE 解析
# ---------------------------------------------------------------------------
def _attributes(cpe: Any) -> list[str]:
    """CPE → 11 个属性字段（不足补空串）；非法返回 ``[]``。"""
    text = str(cpe if cpe is not None else "").strip()
    if text.startswith("cpe:2.3:"):
        fields = split_unescaped(text)[2:]
    elif text.startswith("cpe:/"):
        fields = split_unescaped(text[5:])
    else:
        return []
    fields = [field.strip() for field in fields]
    if len(fields) < 3:
        return []
    while len(fields) < 11:
        fields.append("")
    return fields


def parse_cpe23(cpe23: str) -> dict:
    """解析 CPE 2.3（兼容 2.2 URI）。

    返回 ``{"part","vendor","product","version","update","rest"}``：
    ``rest`` 是 edition/language/sw_edition/target_sw/target_hw/other 六个剩余属性的列表；
    ``version`` 的 ``*``/``-`` 归一为 ``""``（与 :func:`hornwork.scan.cve.version.extract_version`
    一致）。非法串返回全空字段的 dict，绝不抛异常。
    """
    fields = _attributes(cpe23)
    empty = {"part": "", "vendor": "", "product": "", "version": "", "update": "", "rest": []}
    if not fields:
        return empty
    version = fields[3]
    return {
        "part": fields[0],
        "vendor": fields[1],
        "product": fields[2],
        "version": "" if version in ("*", "-") else version,
        "update": fields[4],
        "rest": fields[5:11],
    }


def to_cpe23_prefix(cpe: str) -> str:
    """完整 CPE / 2.2 URI / 2.3 前缀 → ``cpe:2.3:<part>:<vendor>:<product>:``。

    >>> to_cpe23_prefix("cpe:/a:openbsd:openssh:10.2p1")
    'cpe:2.3:a:openbsd:openssh:'
    >>> to_cpe23_prefix("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*")
    'cpe:2.3:a:nginx:nginx:'
    """
    fields = _attributes(cpe)
    if len(fields) < 3:
        return ""
    part = fields[0].strip().lower()
    if part not in _VALID_PARTS:
        return ""
    return f"cpe:2.3:{part}:{fields[1].lower()}:{fields[2].lower()}:"


# ---------------------------------------------------------------------------
# CSV 导入
# ---------------------------------------------------------------------------
def read_csv_rows(
    path: Path, required: tuple[str, ...] = CSV_HEADER[:2]
) -> tuple[list[dict], list[dict]]:
    """读 CSV（UTF-8 BOM 容忍、``#`` 注释行与空行跳过），返回 ``(rows, errors)``。

    ``required`` 是需要校验的必填列（comp_map 用 ``comp_norm,cpe23``，
    cve_exclude 用 ``cve_id,comp_norm``）。错误项形如 ``{"line":n,"error":"..."}``。
    """
    errors: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return [], [{"line": 0, "error": f"读取失败: {exc}"}]
    lines = [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return [], [{"line": 0, "error": "文件为空（只有表头或注释）"}]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    header = [str(name).strip().lower() for name in (reader.fieldnames or [])]
    missing = [name for name in required if name not in header]
    if missing:
        return [], [{"line": 0, "error": f"表头缺少列: {','.join(missing)}；需要 {','.join(required)}"}]
    rows: list[dict] = []
    for lineno, raw in enumerate(reader, start=2):
        if not isinstance(raw, dict):
            continue
        # DictReader 的键是原始表头大小写，统一成小写再取值
        normalized = {
            str(key).strip().lower(): (value if value is not None else "")
            for key, value in raw.items()
            if key is not None
        }
        rows.append({"line": lineno, **normalized})
    return rows, errors


def import_csv(store: Any, path: str) -> dict:
    """导入 ``comp_map.csv``（``comp_norm,cpe23,source,note``），按主键 upsert。

    返回 ``{"upserted","skipped","errors"}``；单行错误只记录不中断，重复导入幂等
    （``INSERT OR REPLACE``）。
    """
    result: dict[str, Any] = {"upserted": 0, "skipped": 0, "errors": []}
    # 允许独立调用（CLI 先导映射表、未导 CVE 数据）：建表幂等，DDL 单一来源
    from ..store import init_schema

    init_schema(store)
    file_path = Path(str(path)).expanduser()
    if not file_path.is_file():
        result["errors"].append({"line": 0, "error": f"映射文件不存在: {file_path}"})
        return result
    rows, errors = read_csv_rows(file_path)
    result["errors"].extend(errors)
    if not rows:
        return result
    for row in rows:
        comp = normalize_comp(row.get("comp_norm"))
        raw_cpe = str(row.get("cpe23") or "").strip()
        prefix = to_cpe23_prefix(raw_cpe)
        if not comp or not prefix:
            result["skipped"] += 1
            reason = "comp_norm 为空" if not comp else f"CPE 无法解析为前缀: {raw_cpe!r}"
            result["errors"].append({"line": row.get("line"), "error": reason})
            continue
        try:
            store.execute(
                "INSERT OR REPLACE INTO cve_component_map(comp_norm, cpe23, source, note)"
                " VALUES(?,?,?,?)",
                (comp, prefix, str(row.get("source") or ""), str(row.get("note") or "")),
            )
            result["upserted"] += 1
        except Exception as exc:  # noqa: BLE001 - 单行失败不中断整批导入
            result["errors"].append({"line": row.get("line"), "error": f"入库失败: {exc}"})
    log.info(
        "comp_map.imported", path=str(file_path),
        upserted=result["upserted"], skipped=result["skipped"], errors=len(result["errors"]),
    )
    return result


# ---------------------------------------------------------------------------
# 查询与种子导入
# ---------------------------------------------------------------------------
def resolve(store: Any, comp_norm: str) -> list[str]:
    """组件名 → CPE 前缀列表（保持 CSV 中的顺序，去重；无映射返回空列表）。

    表不存在/数据库异常时返回空列表而不是抛异常——匹配器会把它记入
    ``unknown_components``，不影响整轮扫描。
    """
    comp = normalize_comp(comp_norm)
    if not comp:
        return []
    try:
        rows = store.query(
            "SELECT cpe23 FROM cve_component_map WHERE comp_norm=? ORDER BY cpe23", (comp,)
        )
    except Exception as exc:  # noqa: BLE001 - 建表前/旧库缺表均按"无映射"处理
        log.warn("comp_map.query_failed", comp=comp, error=str(exc))
        return []
    prefixes: list[str] = []
    for row in rows:
        prefix = to_cpe23_prefix(str(row.get("cpe23") or ""))
        if prefix and prefix not in prefixes:
            prefixes.append(prefix)
    return prefixes


def repo_rules_dir() -> Path:
    """仓库内置规则目录 ``<repo>/hornwork/rules/scan``（开发机回退用）。"""
    return Path(__file__).resolve().parents[3] / "rules" / "scan"


def _resolve_comp_map_path(cfg: dict | None) -> Path:
    """解析映射表路径：配置 ``scan.rules.comp_map`` 存在则用，否则回退仓库内置。"""
    configured = str(cfg_get(cfg or {}, "scan.rules.comp_map", "") or "").strip()
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path
    return repo_rules_dir() / "comp_map.csv"


def seed_from_dir(store: Any, cfg: dict | None) -> dict:
    """按配置导入映射表（默认 ``/opt/hornwork/rules/scan/comp_map.csv``，开发机回退仓库）。

    返回 ``import_csv`` 的结果并补充 ``path`` / ``fallback``：``fallback=True`` 表示
    配置路径不存在、用的是仓库内置表。
    """
    configured = str(cfg_get(cfg or {}, "scan.rules.comp_map", "") or "").strip()
    path = _resolve_comp_map_path(cfg)
    fallback = bool(configured) and Path(configured).expanduser() != path
    result = import_csv(store, str(path))
    result["path"] = str(path)
    result["fallback"] = fallback
    return result
