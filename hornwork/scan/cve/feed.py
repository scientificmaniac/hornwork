"""CVE 数据源导入：NVD JSON 2.0 流式解析 + Ubuntu OVAL 修复版本视图 + 缓存统计。

设计要点：

- **流式解析**：NVD 年文件解压后可达数百 MB，``json.load`` 峰值是文件大小的 2～4 倍。
  这里用 :class:`json.JSONDecoder` 的 ``raw_decode`` 逐条取出 ``vulnerabilities`` 数组元素，
  解完即丢，峰值内存与文件大小无关（设计目标 < 150 MB，测试用 ``tracemalloc`` 给量级断言）。
- **一拍平**：``cve_cache`` 一行 = 一个 (CVE, CPE, 版本区间) 影响关系；``vulnerable=0`` 的
  "运行平台"关系不入库。**空边界统一存空串而不是 NULL**——SQLite 的复合主键对 NULL 不去重，
  存 NULL 会让重复导入产生重复行，破坏幂等。
- **Ubuntu OVAL**：解析 ``dpkg`` 测试/对象/状态，得到"发行版 + 包 + CVE → 修复版本"，写入
  ``scan_oval_fix``，用于修复"发行版补丁回移导致 banner 版本误判"的误报。Canonical 真实文件的
  包名在 ``<variables>`` 段、由 ``<dpkginfo_object><name var_ref="..."/>`` 引用（variables 在
  objects 之后），因此 objects 先存原始引用、整份文件解析完再统一解析 var_ref；
  只有 object_ref、没有 state_ref 的测试（仅判包存在）计入 ``skipped`` 而非 ``errors``。
- ``init_schema`` 直接委托 Lead 维护的 :mod:`hornwork.scan.store`（DDL 单一来源）。

导入期不读文件、不连库；``import_nvd`` 返回 ``peak_kb``（tracemalloc 实测峰值），
``elapsed_ms`` 为整批耗时。Windows 上可安全 import / 单测。
"""

from __future__ import annotations

import bz2
import gzip
import json
import re
import time
import tracemalloc
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterator

from ... import schema
from ...log import get_logger
from .version import extract_version

log = get_logger("scan.cve.feed")

#: 流式读取块大小（256 KiB）：一个 CVE 对象通常远小于它，块边界最多触发几次重解码
BLOCK = 1 << 18
#: 每 N 行提交一次（批量 executemany，避免逐行 commit 拖慢百 MB 级导入）
FLUSH_EVERY = 500
#: 关键字段搜索阶段允许的最大缓冲（正常在文件头几百字节内就能找到 "vulnerabilities"）
_MAX_HEAD = 8 << 20
#: errors 列表上限（避免坏数据把返回值撑爆；超出只计数不逐条返回）
_MAX_ERRORS = 500
#: platform 收集上限（真实 Canonical OVAL 有数万条重复 platform，只用于发行版推断）
_MAX_PLATFORMS = 200

#: NVD 英文严重级 → 项目统一中文级别（与靶场模块档案 CHECK 约束一致）
SEVERITY_MAP: dict[str, str] = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "none": "无",
}

#: Ubuntu 版本号 → 发行版代号（只收录已确认的版本，未确认不编造）
UBUNTU_CODENAMES: dict[str, str] = {
    "16.04": "xenial",
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "23.10": "mantic",
    "24.04": "noble",
    "24.10": "oracular",
    "25.04": "plucky",
    "25.10": "questing",
}

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_VERSION_RE = re.compile(r"(\d{2}\.\d{2})")


# ---------------------------------------------------------------------------
# 建表（委托 Lead 的单一 DDL 源）
# ---------------------------------------------------------------------------
def init_schema(store: Any) -> None:
    """建扫描模块全部表（幂等）；DDL 唯一来源是 :mod:`hornwork.scan.store`。"""
    from ..store import init_schema as _scan_init_schema

    _scan_init_schema(store)


# ---------------------------------------------------------------------------
# NVD JSON 2.0 流式解析
# ---------------------------------------------------------------------------
def _open_text(path: str | Path):
    """按扩展名打开文本流：``.gz`` 用 gzip，其余当普通 UTF-8 JSON。"""
    text = str(path).lower()
    if text.endswith(".gz"):
        return gzip.open(str(path), "rt", encoding="utf-8")
    return open(str(path), "r", encoding="utf-8")


def _array_start(buf: str) -> int:
    """定位顶层 CVE 数组起点（返回 ``[`` 之后的下标）；未找到返回 ``-1``。"""
    for key in ('"vulnerabilities"', '"CVE_Items"'):
        index = buf.find(key)
        if index >= 0:
            bracket = buf.find("[", index + len(key))
            if bracket >= 0:
                return bracket + 1
    stripped = buf.lstrip()
    if stripped.startswith("["):  # 兜底：顶层就是数组的裁剪夹具
        return len(buf) - len(stripped) + 1
    return -1


def iter_cves(path: str | Path) -> Iterator[dict]:
    """增量产出 NVD JSON 2.0 的 ``vulnerabilities[]`` 元素（逐对象解码，不整包 ``json.load``）。

    典型结构 ``{"vulnerabilities":[{"cve":{...}}, ...]}``；元素被解码后立即 yield，
    解码缓冲区只保留"未消费的尾部 + 下一个块"，峰值与文件大小无关。
    解析失败（文件被截断/结构非法）抛 :class:`ValueError`，由调用方按文件隔离。
    """
    decoder = json.JSONDecoder()
    with _open_text(path) as handle:
        buf = ""
        pos = 0
        while True:  # 阶段一：找到 vulnerabilities 数组
            chunk = handle.read(BLOCK)
            if not chunk:
                raise ValueError(f"未找到 vulnerabilities 数组（文件可能为空或非 NVD 2.0）: {path}")
            buf += chunk
            start = _array_start(buf)
            if start >= 0:
                pos = start
                break
            if len(buf) > _MAX_HEAD:
                raise ValueError(f"文件头部过大仍未见 vulnerabilities 数组: {path}")

        while True:  # 阶段二：逐对象 raw_decode
            while pos < len(buf) and buf[pos] in " \t\r\n,":
                pos += 1
            if pos >= len(buf):
                chunk = handle.read(BLOCK)
                if not chunk:
                    return
                buf = buf[pos:] + chunk
                pos = 0
                continue
            if buf[pos] == "]":
                return
            try:
                obj, end = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError as exc:
                # 大概率是块边界把一个对象截断了：补一块数据后从对象起点重试
                chunk = handle.read(BLOCK)
                if not chunk:
                    raise ValueError(f"JSON 解码失败（文件截断或结构非法）: {exc}") from exc
                buf = buf[pos:] + chunk
                pos = 0
                continue
            yield obj
            pos = end
            if pos > 4 * BLOCK:  # 丢弃已消费前缀，控制内存
                buf = buf[pos:]
                pos = 0


# ---------------------------------------------------------------------------
# NVD → cve_cache 行提取
# ---------------------------------------------------------------------------
def severity_cn(raw: Any) -> str:
    """NVD 英文严重级 → 中文级别；未知/空返回 ``""``。"""
    return SEVERITY_MAP.get(str(raw or "").strip().lower(), "")


def cvss_severity(score: Any) -> str:
    """按 CVSS baseScore 推导中文级别（NVD v2 无 baseSeverity 时回退）。"""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return ""
    if value >= 9.0:
        return "严重"
    if value >= 7.0:
        return "高"
    if value >= 4.0:
        return "中"
    if value > 0.0:
        return "低"
    return "无"


def _extract_cvss(metrics: Any) -> tuple[float | None, str]:
    """按 v3.1 → v3.0 → v2 回退取 ``(baseScore, 英文 baseSeverity)``。"""
    if not isinstance(metrics, dict):
        return None, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key)
        if not isinstance(items, list) or not items:
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            data = item.get("cvssData")
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            if score is None:
                continue
            try:
                base = float(score)
            except (TypeError, ValueError):
                continue
            raw_severity = data.get("baseSeverity") or item.get("baseSeverity")
            return base, str(raw_severity or "")
    return None, ""


def _english_description(descriptions: Any) -> str:
    """取英文描述并截断 300 字（报告标题/证据展示用）。"""
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang") or "").lower().startswith("en"):
            return str(item.get("value") or "")[:300]
    return ""


def _iter_nodes(nodes: Any) -> Iterator[dict]:
    """递归遍历 ``configurations[].nodes[]``（含 ``children``），产出 ``cpeMatch`` 条目。"""
    if not isinstance(nodes, list):
        return
    for node in nodes:
        if not isinstance(node, dict):
            continue
        matches = node.get("cpeMatch") or node.get("cpe_match") or []
        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, dict):
                    yield match
        yield from _iter_nodes(node.get("children"))


def _iter_cpe_matches(configurations: Any) -> Iterator[dict]:
    """遍历 ``configurations[]``（每个配置是一组 nodes）。"""
    if not isinstance(configurations, list):
        return
    for config in configurations:
        if isinstance(config, dict):
            yield from _iter_nodes(config.get("nodes"))


def _extract_cve(item: Any, source: str) -> dict:
    """单个 ``{"cve": {...}}`` → ``{"cve_id","rows","skipped"}``；非法条目抛 ValueError。"""
    if not isinstance(item, dict):
        raise ValueError("条目不是对象")
    cve = item.get("cve")
    if not isinstance(cve, dict):
        raise ValueError("条目缺少 cve 对象（非 NVD 2.0 结构）")
    cve_id = str(cve.get("id") or "").strip().upper()
    if not _CVE_ID_RE.fullmatch(cve_id):
        raise ValueError(f"非法 CVE 编号: {cve_id!r}")

    published = str(cve.get("published") or "")
    modified = str(cve.get("lastModified") or "")
    cvss, raw_severity = _extract_cvss(cve.get("metrics"))
    severity = severity_cn(raw_severity) or cvss_severity(cvss)
    title = _english_description(cve.get("descriptions"))

    rows: list[dict] = []
    skipped = 0
    for match in _iter_cpe_matches(cve.get("configurations")):
        criteria = str(match.get("criteria") or "").strip()
        if not criteria:
            skipped += 1
            continue
        vulnerable = match.get("vulnerable")
        if vulnerable is not None and not bool(vulnerable):
            skipped += 1  # "运行平台"关系，不是受影响关系
            continue
        rows.append(
            {
                "cve_id": cve_id,
                "cpe23": criteria,
                "vulnerable": 1,
                "cpe_version": extract_version(criteria),
                # 空边界存空串，保证复合主键去重（NULL 在 SQLite UNIQUE 中互不相等）
                "version_start_incl": str(match.get("versionStartIncluding") or ""),
                "version_start_excl": str(match.get("versionStartExcluding") or ""),
                "version_end_incl": str(match.get("versionEndIncluding") or ""),
                "version_end_excl": str(match.get("versionEndExcluding") or ""),
                "cvss": cvss,
                "severity": severity,
                "published": published,
                "modified": modified,
                "source": source,
                "title": title,
            }
        )
    if not rows:
        return {"cve_id": cve_id, "rows": [], "skipped": skipped + 1}
    return {"cve_id": cve_id, "rows": rows, "skipped": skipped}


# ---------------------------------------------------------------------------
# SQLite 写入工具
# ---------------------------------------------------------------------------
def _table_columns(store: Any, table: str) -> list[str]:
    """读表列名（按 DDL 顺序），用于"按实际表结构自适应插入"。"""
    rows = store.query(f"PRAGMA table_info({table})")
    columns = [str(row.get("name")) for row in rows if row.get("name")]
    if not columns:
        raise RuntimeError(f"表 {table} 不存在，请先调用 init_schema(store)")
    return columns


def _executemany(store: Any, sql: str, rows: list[tuple]) -> None:
    """批量写入（内存库/真 Store 都走一次事务）；无 ``conn`` 的桩对象退化为逐行 execute。"""
    if not rows:
        return
    conn = getattr(store, "conn", None)
    lock = getattr(store, "_lock", None)
    if conn is not None and lock is not None:
        with lock:
            conn.executemany(sql, rows)
            conn.commit()
        return
    for row in rows:
        store.execute(sql, row)


def _flush_rows(
    store: Any, sql: str, rows: list[tuple], result: dict, cve_index: int = 0
) -> int:
    """批量提交；整批失败时逐行重试，坏行计入 ``errors`` 不中断导入。

    ``cve_index`` 指向行元组里 CVE 编号的位置（``cve_cache`` 是 0，``scan_oval_fix`` 是 2），
    只用于错误定位，不影响写入。
    """
    if not rows:
        return 0
    try:
        _executemany(store, sql, rows)
        return len(rows)
    except Exception as exc:  # noqa: BLE001 - 批量失败降级为逐行，定位坏行
        log.warn("批量写入失败，降级逐行重试", rows=len(rows), error=str(exc))
    written = 0
    for row in rows:
        try:
            store.execute(sql, row)
            written += 1
        except Exception as row_exc:  # noqa: BLE001 - 单行失败只记录
            label = row[cve_index] if cve_index < len(row) else None
            if len(result["errors"]) < _MAX_ERRORS:
                result["errors"].append(
                    {"file": result.get("_file", ""), "cve": label,
                     "error": str(row_exc)[:300]}
                )
            else:
                result["_errors_truncated"] = int(result.get("_errors_truncated", 0)) + 1
    return written


def _insert_sql(table: str, columns: list[str]) -> str:
    placeholders = ",".join("?" for _ in columns)
    return f"INSERT OR REPLACE INTO {table}({','.join(columns)}) VALUES({placeholders})"


# ---------------------------------------------------------------------------
# import_nvd / import_dir
# ---------------------------------------------------------------------------
def _as_file_list(paths: Any) -> list[Path]:
    """``paths`` 支持单个字符串或列表；过滤空值并展开 ``~``。"""
    if isinstance(paths, (str, Path)):
        raw = [paths]
    elif isinstance(paths, (list, tuple, set)):
        raw = list(paths)
    else:
        raw = []
    return [Path(str(item)).expanduser() for item in raw if str(item or "").strip()]


def _empty_nvd_result() -> dict:
    return {
        "files": 0, "imported_rows": 0, "cves": 0, "skipped": 0,
        "errors": [], "bytes": 0, "elapsed_ms": 0, "peak_kb": 0,
    }


def _import_nvd(store: Any, paths: Any, source: str) -> dict:
    """``import_nvd`` 的实现体（不含 tracemalloc 包裹）。"""
    init_schema(store)
    result = _empty_nvd_result()
    columns = _table_columns(store, "cve_cache")
    sql = _insert_sql("cve_cache", columns)
    seen_cves: set[str] = set()
    for path in _as_file_list(paths):
        if not path.is_file():
            result["errors"].append({"file": str(path), "error": "文件不存在"})
            log.warn("nvd.file.missing", path=str(path))
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            result["errors"].append({"file": str(path), "error": f"读取文件属性失败: {exc}"})
            continue
        result["files"] += 1
        result["bytes"] += int(size)
        result["_file"] = path.name
        rows_buf: list[tuple] = []
        try:
            for item in iter_cves(path):
                try:
                    parsed = _extract_cve(item, source)
                except (TypeError, ValueError) as exc:  # 单条坏数据隔离
                    if len(result["errors"]) < _MAX_ERRORS:
                        result["errors"].append(
                            {"file": path.name, "cve": None, "error": str(exc)[:300]}
                        )
                    continue
                result["skipped"] += int(parsed["skipped"])
                if not parsed["rows"]:
                    continue
                seen_cves.add(parsed["cve_id"])
                for row in parsed["rows"]:
                    rows_buf.append(tuple(row.get(column) for column in columns))
                if len(rows_buf) >= FLUSH_EVERY:
                    result["imported_rows"] += _flush_rows(store, sql, rows_buf, result)
                    rows_buf = []
        except (OSError, ValueError) as exc:  # 文件级失败：记录后继续下一个文件
            result["errors"].append({"file": path.name, "error": f"解析失败: {exc}"})
            log.warn("nvd.file.parse_failed", path=str(path), error=str(exc))
        result["imported_rows"] += _flush_rows(store, sql, rows_buf, result)
    result["cves"] = len(seen_cves)
    result.pop("_file", None)
    result.pop("_errors_truncated", None)
    log.info(
        "nvd.imported", source=source, files=result["files"],
        rows=result["imported_rows"], cves=result["cves"],
        skipped=result["skipped"], errors=len(result["errors"]),
    )
    return result


def import_nvd(store: Any, paths: list[str] | str, source: str = "nvd") -> dict:
    """流式导入一个或多个 NVD JSON 2.0 文件。

    返回 ``{"files","imported_rows","cves","skipped","errors","bytes","elapsed_ms","peak_kb"}``：
    ``imported_rows`` 是写入尝试行数（复合主键重复会被 REPLACE 覆盖，不代表最终行数），
    ``cves`` 是本次涉及的 CVE 数，``skipped`` 是被跳过的 CPE 关系数（非受影响/无 criteria），
    ``bytes`` 是文件大小合计，``peak_kb`` 为 tracemalloc 实测峰值（未开 tracing 则本次开启）。
    """
    started = time.perf_counter()
    tracing = tracemalloc.is_tracing()
    if not tracing:
        tracemalloc.start()
    peak = 0
    try:
        result = _import_nvd(store, paths, source)
    finally:
        try:
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            if not tracing:
                tracemalloc.stop()
    result["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    result["peak_kb"] = int(peak // 1024)
    return result


def import_dir(
    store: Any, directory: str, pattern: str = "nvdcve-2.0-*.json.gz", source: str = "nvd"
) -> dict:
    """导入目录下匹配 ``pattern`` 的全部文件（按文件名排序，保证可复现的导入顺序）。

    容错：默认匹配不到时会再尝试去掉 ``.gz`` 的 ``*.json`` 形态（部分镜像提供未压缩文件），
    仍未找到则返回 ``errors``；子目录也会被递归查找一次。
    """
    base = Path(str(directory)).expanduser()
    if not base.is_dir():
        result = _empty_nvd_result()
        result["errors"].append({"file": str(base), "error": "目录不存在"})
        result["dir"] = str(base)
        return result
    patterns = [pattern]
    if pattern.endswith(".json.gz"):
        patterns.append(pattern[: -len(".gz")])
    files: list[Path] = []
    used_pattern = pattern
    for candidate in patterns:
        files = sorted(base.glob(candidate))
        if not files:
            files = sorted(base.rglob(candidate))  # 允许按年分子目录
        if files:
            used_pattern = candidate
            break
    if not files:
        result = _empty_nvd_result()
        result["errors"].append(
            {"file": str(base), "error": f"未找到匹配文件: {' / '.join(patterns)}"}
        )
        result["dir"] = str(base)
        return result
    result = import_nvd(store, [str(file) for file in files], source)
    result["dir"] = str(base)
    result["pattern"] = used_pattern
    return result


# ---------------------------------------------------------------------------
# Ubuntu OVAL
# ---------------------------------------------------------------------------
def _local_name(tag: Any) -> str:
    """去掉 XML 命名空间，只留本地名（``{ns}definition`` → ``definition``）。"""
    return str(tag).rsplit("}", 1)[-1]


def _open_oval(path: Path):
    """.xml / .xml.gz / .xml.bz2 统一按二进制流交给 iterparse。"""
    text = str(path).lower()
    if text.endswith(".gz"):
        return gzip.open(str(path), "rb")
    if text.endswith(".bz2"):
        return bz2.open(str(path), "rb")
    return open(str(path), "rb")


def _collect_definition(elem: Any, defs: dict[str, dict]) -> None:
    """收集 ``<definition>``：CVE 列表、criterion 的 test_ref、extend 引用。

    不按 ``class`` 过滤：Ubuntu OVAL 的 ``patch``/``inventory`` 定义常被漏洞定义
    ``extend_definition`` 引用，丢掉它们会漏掉"包 → 修复版本"这条边。

    CVE 归属优先级：``<reference source="CVE">`` + ``<title>`` 优先（Canonical 每个漏洞定义都
    只带自己的 CVE，避免描述里顺手提到的其它 CVE 被误挂）；两者都没有时才回退扫 ``<description>``。
    """
    definition_id = str(elem.get("id") or "").strip()
    if not definition_id:
        return
    titles: list[str] = []
    descriptions: list[str] = []
    refs: list[str] = []
    test_refs: list[str] = []
    extends: list[str] = []
    for node in elem.iter():
        tag = _local_name(node.tag)
        if tag == "title":
            titles.append("".join(node.itertext()))
        elif tag == "description":
            descriptions.append("".join(node.itertext()))
        elif tag == "reference":
            refs.append(f"{node.get('ref_id') or ''} {node.get('ref_url') or ''}")
        elif tag == "criterion":
            test_ref = node.get("test_ref")
            if test_ref:
                test_refs.append(str(test_ref).strip())
        elif tag == "extend_definition":
            definition_ref = node.get("definition_ref")
            if definition_ref:
                extends.append(str(definition_ref).strip())
    blob = " ".join(refs + titles)
    cves = {match.group(0).upper() for match in _CVE_ID_RE.finditer(blob)}
    if not cves:
        cves = {match.group(0).upper() for match in _CVE_ID_RE.finditer(" ".join(descriptions))}
    defs[definition_id] = {"cves": sorted(cves), "tests": test_refs, "extends": extends}


def _collect_test(elem: Any, tests: dict[str, dict]) -> None:
    """收集 ``<dpkginfo_test>``：object_ref（包名）与 state_ref（固定版本）。"""
    test_id = str(elem.get("id") or "").strip()
    if not test_id:
        return
    objects: list[str] = []
    states: list[str] = []
    for node in elem.iter():
        tag = _local_name(node.tag)
        if tag == "object":
            ref = node.get("object_ref")
            if ref:
                objects.append(str(ref).strip())
        elif tag == "state":
            ref = node.get("state_ref")
            if ref:
                states.append(str(ref).strip())
    tests[test_id] = {"objects": objects, "states": states}


def _state_evr(elem: Any) -> str:
    """从 ``<dpkginfo_state>`` 取修复版本：优先 ``operation`` 含 less 的 ``<evr>``。"""
    candidates: list[tuple[bool, str]] = []
    for node in elem.iter():
        if _local_name(node.tag) != "evr":
            continue
        text = "".join(node.itertext()).strip()
        if not text:
            continue
        operation = str(node.get("operation") or "").lower()
        candidates.append(("less" in operation, text))
    for is_less, text in candidates:
        if is_less:
            return text
    return candidates[0][1] if candidates else ""


def _collect_object(elem: Any, objects_raw: dict[str, dict]) -> None:
    """收集 ``<dpkginfo_object>`` 的包名来源：**字面量文本** 或 **变量引用**（Canonical 形态）。

    Canonical OVAL 的真实对象长这样（包名不在对象里，在 ``<variables>`` 段）::

        <linux-def:dpkginfo_object id="oval:...:obj:200224390000000">
          <linux-def:name var_ref="oval:com.ubuntu.noble:var:200224390000000"
                           var_check="at least one"/>
        </linux-def:dpkginfo_object>

    因此这里只存"原始引用"，等整份文件解析完（``<variables>`` 段在 objects 之后）再解析。
    """
    object_id = str(elem.get("id") or "").strip()
    if not object_id:
        return
    names: list[str] = []
    var_refs: list[str] = []
    for node in elem.iter():
        if _local_name(node.tag) != "name":
            continue
        text = "".join(node.itertext()).strip()
        if text:
            names.append(text)
        var_ref = str(node.get("var_ref") or "").strip()
        if var_ref and var_ref not in var_refs:
            var_refs.append(var_ref)
    objects_raw[object_id] = {"names": names, "var_refs": var_refs}


def _collect_variable(elem: Any, variables: dict[str, list[str]]) -> None:
    """收集 ``<variable>``/``<constant_variable>`` 的 ``<value>`` 列表（去重、保序）。

    一个变量可能有多个值（OVAL 语义是"at least one"），这里全部保留——
    对"包 → 修复版本"这张表来说，每个值都是真实受影响的包名，丢弃会漏报。
    """
    variable_id = str(elem.get("id") or "").strip()
    if not variable_id:
        return
    values: list[str] = []
    for node in elem.iter():
        if _local_name(node.tag) != "value":
            continue
        text = "".join(node.itertext()).strip()
        if text and text not in values:
            values.append(text)
    if values:
        variables[variable_id] = values


def _resolve_objects(
    objects_raw: dict[str, dict], variables: dict[str, list[str]]
) -> tuple[dict[str, list[str]], int, list[str]]:
    """``var_ref`` 后处理：对象 id → 包名列表。

    返回 ``(resolved, 未解析 var_ref 数, 未解析样本[≤5])``：真实 Canonical 文件若仍有未解析引用，
    样本可直接从 ``import_oval`` 的 errors 摘要里看到，便于定位 variables 段形态。
    """
    objects: dict[str, list[str]] = {}
    unresolved = 0
    samples: list[str] = []
    for object_id, raw in objects_raw.items():
        names = list(raw.get("names") or [])
        for var_ref in raw.get("var_refs") or []:
            values = variables.get(var_ref)
            if not values:
                unresolved += 1
                if len(samples) < 5:
                    samples.append(var_ref)
                continue
            for value in values:
                if value not in names:
                    names.append(value)
        if names:
            objects[object_id] = names
    return objects, unresolved, samples


def _parse_oval(path: Path) -> dict:
    """流式解析 OVAL XML（iterparse + 消费后 clear，控制内存）。

    处理 Canonical 真实的命名空间形态（默认 ns + ``linux-def:`` 前缀）、
    ``<variables>`` 变量引用、``<extend_definition>`` 组合、``<platform>`` 大段噪声。
    """
    defs: dict[str, dict] = {}
    tests: dict[str, dict] = {}
    objects_raw: dict[str, dict] = {}
    states: dict[str, str] = {}
    variables: dict[str, list[str]] = {}
    platforms: list[str] = []
    errors: list[dict] = []
    #: 只在这些元素结束时收集并清理；其余元素保留给父元素处理（如 definition 里的 criteria）
    consumed = {
        "definition", "dpkginfo_test", "dpkginfo_object", "dpkginfo_state",
        "definitions", "tests", "objects", "states", "variables",
        "variable", "constant_variable", "platform",
    }
    try:
        with _open_oval(path) as handle:
            for _event, elem in ET.iterparse(handle, events=("end",)):
                tag = _local_name(elem.tag)
                if tag not in consumed:
                    continue
                try:
                    if tag == "definition":
                        _collect_definition(elem, defs)
                    elif tag == "dpkginfo_test":
                        _collect_test(elem, tests)
                    elif tag == "dpkginfo_object":
                        _collect_object(elem, objects_raw)
                    elif tag == "dpkginfo_state":
                        state_id = str(elem.get("id") or "").strip()
                        evr = _state_evr(elem)
                        if state_id and evr:
                            states[state_id] = evr
                    elif tag in ("variable", "constant_variable"):
                        _collect_variable(elem, variables)
                    elif tag == "platform":
                        # 真实文件有数万条重复 platform，只留前 _MAX_PLATFORMS 条供发行版推断
                        text = "".join(elem.itertext()).strip()
                        if text and len(platforms) < _MAX_PLATFORMS:
                            platforms.append(text)
                finally:
                    elem.clear()
    except (OSError, ET.ParseError) as exc:
        errors.append({"file": path.name, "error": f"OVAL 解析失败: {exc}"})
    objects, unresolved_count, unresolved_samples = _resolve_objects(objects_raw, variables)
    return {
        "defs": defs, "tests": tests, "objects": objects,
        "objects_raw": len(objects_raw), "states": states,
        "variables": len(variables), "platforms": platforms,
        "unresolved_var_refs": unresolved_count,
        "unresolved_samples": unresolved_samples, "errors": errors,
    }


def _tests_of(defs: dict[str, dict], definition_id: str) -> list[str]:
    """沿 ``extend_definition`` 递归收集 definition 关联的全部 test_ref（带环保护）。"""
    seen: set[str] = set()
    queue = [definition_id]
    output: list[str] = []
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        node = defs.get(current)
        if not node:
            continue
        output.extend(node["tests"])
        queue.extend(node["extends"])
    return output


def _oval_fix_rows(parsed: dict) -> tuple[list[tuple[str, str, str]], list[dict], int]:
    """definition × test × object × state → ``(cve, package, fixed_version)`` 去重列表。

    返回 ``(rows, errors, skipped)``：

    - ``rows``：可写入 ``scan_oval_fix`` 的三元组；
    - ``errors``：真异常（criterion 指向的测试缺失、对象 var_ref 解析不出包名等），上限 500 条；
    - ``skipped``：没有贡献修复版本的 CVE definition 数。真实 Canonical 文件里存在大量
      "只有 object_ref、没有 state_ref"的测试（只判包是否存在，没有修复版本），
      这类属于**正常跳过**，不算 error。
    """
    defs = parsed["defs"]
    tests = parsed["tests"]
    objects = parsed["objects"]
    states = parsed["states"]
    rows: list[tuple[str, str, str]] = []
    errors: list[dict] = []
    skipped = 0
    seen: set[tuple[str, str, str]] = set()
    for definition_id, definition in defs.items():
        cves = definition.get("cves") or []
        if not cves:
            # patch/inventory/平台定义：真实文件里大量存在，本就不产生 CVE 修复版本
            continue
        test_refs = _tests_of(defs, definition_id)
        pairs: list[tuple[str, str]] = []
        missing_tests = 0
        has_state = False
        for test_id in test_refs:
            test = tests.get(test_id)
            if not test:
                missing_tests += 1
                continue
            packages: list[str] = []
            for ref in test["objects"]:
                for value in objects.get(ref) or []:
                    if value not in packages:
                        packages.append(value)
            fixes = [states[ref] for ref in test["states"] if states.get(ref)]
            if fixes:
                has_state = True
            for package in packages:
                for fixed in fixes:
                    pairs.append((package, fixed))
        if pairs:
            for cve in cves:
                for package, fixed in pairs:
                    key = (cve, package, fixed)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append(key)
            continue

        skipped += 1
        if test_refs and not has_state:
            # 正常形态：只有包存在性测试（object_ref 无 state_ref），没有修复版本可比
            continue
        if len(errors) >= _MAX_ERRORS:
            continue
        if not test_refs:
            reason = "definition 没有可解析的 criterion test_ref / extend_definition"
        elif missing_tests == len(test_refs):
            reason = "criterion 指向的 dpkg 测试在 <tests> 段不存在"
        else:
            reason = "dpkginfo_object 未解析出包名（var_ref 找不到对应 <variable>）"
        errors.append({"definition": definition_id, "error": reason})
    unresolved = int(parsed.get("unresolved_var_refs") or 0)
    if unresolved:
        samples = parsed.get("unresolved_samples") or []
        hint = f"，样本：{', '.join(str(item) for item in samples)}" if samples else ""
        errors.append(
            {"error": f"{unresolved} 个 dpkginfo_object 的 var_ref 在 <variables> 段找不到，"
                      f"已忽略{hint}"}
        )
    return rows, errors, skipped


def _normalize_release(release: Any) -> str:
    """``24.04`` / ``ubuntu-24.04`` / ``Ubuntu 24.04 LTS`` → 发行版代号（未知形态原样返回）。"""
    text = str(release or "").strip().lower()
    if not text:
        return ""
    if text in UBUNTU_CODENAMES.values():
        return text
    match = _VERSION_RE.search(text)
    if match and match.group(1) in UBUNTU_CODENAMES:
        return UBUNTU_CODENAMES[match.group(1)]
    for codename in UBUNTU_CODENAMES.values():
        if codename in text:
            return codename
    return text


def _infer_release(path: Path, platforms: list[str]) -> str:
    """从文件名或 ``<platform>`` 文本推断发行版（noble/jammy/...）。"""
    name = path.name.lower()
    for codename in UBUNTU_CODENAMES.values():
        if codename in name:
            return codename
    for text in platforms:
        match = _VERSION_RE.search(text or "")
        if match and match.group(1) in UBUNTU_CODENAMES:
            return UBUNTU_CODENAMES[match.group(1)]
    return ""


def import_oval(store: Any, path: str, release: str | None = None) -> dict:
    """导入 Ubuntu OVAL XML（``.xml``/``.xml.gz``/``.xml.bz2``），写 ``scan_oval_fix``。

    返回 ``{"release","imported_fixes","cves","packages","errors","elapsed_ms"}``，
    另附诊断字段 ``skipped``(无修复版本的 CVE 定义数) / ``objects`` / ``tests`` / ``states`` /
    ``variables`` / ``unresolved_var_refs``，便于核对真实 Canonical 文件的解析覆盖率。

    真实文件形态：``<dpkginfo_object><name var_ref="..."/></dpkginfo_object>`` 的包名在
    ``<variables>`` 段（且 variables 在 objects 之后），解析完再统一解析引用；
    只有 object_ref、没有 state_ref 的测试属于"仅判包存在"，计入 ``skipped`` 而非 ``errors``。
    重复导入幂等（主键 ``(release,package,cve_id)`` + ``INSERT OR REPLACE``）。
    """
    started = time.perf_counter()
    result: dict[str, Any] = {
        "release": "", "imported_fixes": 0, "cves": 0, "packages": 0,
        "errors": [], "elapsed_ms": 0, "skipped": 0,
        "objects": 0, "objects_raw": 0, "tests": 0, "states": 0,
        "variables": 0, "unresolved_var_refs": 0,
    }
    init_schema(store)
    file_path = Path(str(path)).expanduser()
    if not file_path.is_file():
        result["errors"].append({"file": str(file_path), "error": "文件不存在"})
        result["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        return result

    parsed = _parse_oval(file_path)
    result["errors"].extend(parsed["errors"])
    result["objects"] = len(parsed["objects"])
    result["objects_raw"] = int(parsed.get("objects_raw") or 0)
    result["tests"] = len(parsed["tests"])
    result["states"] = len(parsed["states"])
    result["variables"] = int(parsed["variables"])
    result["unresolved_var_refs"] = int(parsed["unresolved_var_refs"])
    resolved_release = _normalize_release(release) or _infer_release(file_path, parsed["platforms"])
    if not resolved_release:
        result["errors"].append(
            {"file": file_path.name,
             "error": "无法推断 Ubuntu 发行版，请显式传 release（如 noble/jammy）"}
        )
        result["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        return result
    result["release"] = resolved_release

    rows, row_errors, skipped = _oval_fix_rows(parsed)
    result["errors"].extend(row_errors)
    result["skipped"] = skipped
    imported_at = schema.utc_now()
    sql = (
        "INSERT OR REPLACE INTO scan_oval_fix"
        "(release, package, cve_id, fixed_version, source, imported_at) VALUES(?,?,?,?,?,?)"
    )
    payload = [
        (resolved_release, package, cve, fixed, "ubuntu-oval", imported_at)
        for cve, package, fixed in rows
    ]
    for start in range(0, len(payload), FLUSH_EVERY):
        result["imported_fixes"] += _flush_rows(
            store, sql, payload[start:start + FLUSH_EVERY], result, cve_index=2
        )
    result["cves"] = len({row[0] for row in rows})
    result["packages"] = len({row[1] for row in rows})
    result.pop("_file", None)
    result["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    log.info(
        "oval.imported", path=str(file_path), release=resolved_release,
        fixes=result["imported_fixes"], cves=result["cves"], packages=result["packages"],
        objects=result["objects"], variables=result["variables"],
        skipped=result["skipped"], errors=len(result["errors"]),
    )
    return result


# ---------------------------------------------------------------------------
# 统计
# ---------------------------------------------------------------------------
def stats(store: Any) -> dict:
    """缓存统计（SQL 聚合）：CVE 数/关系行数/来源/严重级分布/时间范围/OVAL 修复视图。"""
    init_schema(store)
    total = store.query_one(
        "SELECT COUNT(*) AS rows, COUNT(DISTINCT cve_id) AS cves FROM cve_cache"
    ) or {}
    by_source = {
        str(row.get("source") or "unknown"): int(row.get("n") or 0)
        for row in store.query("SELECT source, COUNT(*) AS n FROM cve_cache GROUP BY source")
    }
    by_severity = {
        str(row.get("severity") or "未知"): int(row.get("n") or 0)
        for row in store.query(
            "SELECT severity, COUNT(DISTINCT cve_id) AS n FROM cve_cache GROUP BY severity"
        )
    }
    published = store.query_one(
        "SELECT MIN(published) AS earliest, MAX(published) AS latest"
        " FROM cve_cache WHERE published IS NOT NULL AND published!=''"
    ) or {}
    oval = store.query_one("SELECT COUNT(*) AS n FROM scan_oval_fix") or {}
    releases = [
        str(row.get("release"))
        for row in store.query("SELECT DISTINCT release FROM scan_oval_fix ORDER BY release")
    ]
    return {
        "cves": int(total.get("cves") or 0),
        "rows": int(total.get("rows") or 0),
        "by_source": by_source,
        "by_severity": by_severity,
        "earliest": published.get("earliest"),
        "latest": published.get("latest"),
        "oval_fixes": int(oval.get("n") or 0),
        "oval_releases": releases,
    }
