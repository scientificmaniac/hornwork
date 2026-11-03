"""CVE 匹配器：包级 OVAL → CPE 前缀粗筛 → Debian 区间精判（三层收敛 + 可解释证据）。

匹配哲学：

1. **只回答"版本是否落在影响区间"**，不回答"是否可利用"；可利用性交给 PoC/靶场模块复现。
2. **SQL 只做粗筛，版本精判在 Python**：SQLite 没有 dpkg 语义，``substr``/``LIKE`` 只负责把
   候选集从"全库"收敛到"该组件的百级关系行"，区间/相等判定全部走靶场模块的 Debian 比较器。
3. **置信度决定处置**：``range``/``exact`` 可入 finding，``cpe_only`` 只入 observed（由 runner
   决定），保证"误报 ≤10% 由设计保证"。
4. **档案优先**：``archive_map`` 命中的 CVE，CVSS/严重级/修复方案以靶场模块档案为准
   （``cvss_source='vuln'`` + ``vuln_ref``），NVD 只是兜底（``cvss_source='nvd'``）。

置信度语义：

- ``range``：检测版本落在明确区间内（CPE 的 versionStart/End，或 Ubuntu OVAL 的"包修复版本"，
  即 ``detected < fixed``）；
- ``exact``：CPE 的 version 字段与检测版本精确相等（允许"检测版本截断到 CPE 版本长度"的前缀
  等价，用于 nmap banner 带 ``p1``/``Ubuntu-`` 后缀的场景，reason 会写明）；
- ``cpe_only``：只匹配到 vendor:product，没有可比较的版本信息；**不告警**。

导入期不读文件、不连库；``match_facts`` 内部才访问数据库，Windows 上可单测。
"""

from __future__ import annotations

from typing import Any

from ...config import cfg_get
from ...log import get_logger
from . import cmap, feed, version
from .feed import UBUNTU_CODENAMES, severity_cn

log = get_logger("scan.cve.matcher")

#: 置信度优先级（同一 CVE 多行命中时保留更强的证据）
CONFIDENCE_RANK: dict[str, int] = {"range": 3, "exact": 2, "cpe_only": 1}
#: 严重级排序（报告/告警按此优先展示）
SEVERITY_RANK: dict[str, int] = {"严重": 0, "高": 1, "中": 2, "低": 3, "无": 4}
#: 视为"包级清单"的来源（走 OVAL 优先的匹配路径）
PACKAGE_SOURCES: frozenset[str] = frozenset(
    {"dpkg", "package", "pkg", "packages", "dpkg-query", "apt"}
)
#: 排除项 CSV 默认路径（配置项 ``scan.rules.cve_exclude`` 优先）
DEFAULT_EXCLUDE_CSV = "/opt/hornwork/rules/scan/cve_exclude.csv"

#: 本地组件名 → Ubuntu/Debian 二进制包名别名（人工核对；``comp-%`` 前缀查询已覆盖大部分，
#: 这里补"包名不带连字符"的形态，如 python → python3）
PACKAGE_ALIASES: dict[str, tuple[str, ...]] = {
    "openssh": ("openssh-server", "openssh-client"),
    "openssl": ("openssl", "libssl3", "libssl1.1"),
    "nginx": ("nginx", "nginx-core", "nginx-common"),
    "apache2": ("apache2", "apache2-bin"),
    "httpd": ("apache2", "apache2-bin"),
    "mysql": ("mysql-server", "mysql-server-8.0", "mysql-server-8.4"),
    "mariadb": ("mariadb-server", "mariadb-server-10.11"),
    "postgresql": ("postgresql", "postgresql-16"),
    "php": ("php", "php-common", "php8.3", "php8.1"),
    "python": ("python3", "python3.12", "python3.10"),
    "bind9": ("bind9", "bind9-libs"),
    "redis": ("redis-server",),
    "samba": ("samba", "samba-common"),
    "cups": ("cups", "cups-daemon"),
    "docker": ("docker.io", "docker-ce", "containerd"),
    "ntp": ("ntp", "ntpsec"),
}

#: 未知组件原因码
REASON_NO_COMPONENT = "no_component"
REASON_NO_CPE_MAPPING = "no_cpe_mapping"


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _like_escape(text: str) -> str:
    """LIKE 通配符转义（配合 ``ESCAPE '\\'`` 使用，前缀入参不拼进 SQL 字符串）。"""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def _interval_of(row: dict) -> dict:
    """``cve_cache`` 行 → 证据里的区间描述（四个边界 + CPE 精确版本）。"""
    interval = {key: str(row.get(key) or "") for key in version.BOUND_KEYS}
    interval["cpe_version"] = str(row.get("cpe_version") or "")
    return interval


def _interval_text(row: dict) -> str:
    """把区间渲染成人类可读文本：``[8.2.0, 8.2.7)``。"""
    start_incl = str(row.get("version_start_incl") or "")
    start_excl = str(row.get("version_start_excl") or "")
    end_incl = str(row.get("version_end_incl") or "")
    end_excl = str(row.get("version_end_excl") or "")
    begin = f"[{start_incl}" if start_incl else (f"({start_excl}" if start_excl else "(-∞")
    end = f"{end_incl}]" if end_incl else (f"{end_excl})" if end_excl else "+∞)")
    return f"{begin}, {end}"


def _prefix_equivalent(detected: str, cpe_version: str) -> bool:
    """检测版本"截断到 CPE 版本长度"后是否相等（nmap banner 带后缀时的前缀等价）。"""
    limit = len(cpe_version)
    if limit <= 0 or len(detected) < limit:
        return False
    return detected[:limit] == cpe_version


def _release_candidates(distro: str | None) -> list[str]:
    """发行版标识 → OVAL 的 release 候选（``ubuntu-24.04`` → ``["ubuntu-24.04","noble"]``）。"""
    text = str(distro or "").strip().lower()
    if not text:
        return []
    candidates = [text]
    for token in text.replace("_", "-").replace(" ", "-").split("-"):
        if token in UBUNTU_CODENAMES.values() and token not in candidates:
            candidates.append(token)
    for number, codename in UBUNTU_CODENAMES.items():
        if number in text and codename not in candidates:
            candidates.append(codename)
    return candidates


def _exclude_csv_path(cfg: dict) -> Any:
    """解析排除项 CSV 路径（配置优先，开发机回退仓库内置）。"""
    configured = str(cfg_get(cfg or {}, "scan.rules.cve_exclude", "") or "").strip()
    if configured:
        from pathlib import Path

        path = Path(configured).expanduser()
        if path.is_file():
            return path
    repo_path = cmap.repo_rules_dir() / "cve_exclude.csv"
    return repo_path if repo_path.is_file() else None


# ---------------------------------------------------------------------------
# 排除项
# ---------------------------------------------------------------------------
def import_exclude_csv(store: Any, path: str) -> dict:
    """导入 ``cve_exclude.csv``（``cve_id,comp_norm,version,reason``）到 ``scan_cve_exclude``。

    ``version`` 为空表示"该组件该 CVE 的所有版本都排除"（通配）；按主键 upsert，幂等。
    """
    result: dict[str, Any] = {"upserted": 0, "skipped": 0, "errors": []}
    from pathlib import Path

    from ..store import init_schema

    init_schema(store)  # 允许独立调用（CLI 先导排除项）
    file_path = Path(str(path)).expanduser()
    if not file_path.is_file():
        result["errors"].append({"line": 0, "error": f"排除项文件不存在: {file_path}"})
        return result
    rows, errors = cmap.read_csv_rows(file_path, required=("cve_id", "comp_norm"))
    result["errors"].extend(errors)
    for row in rows:
        cve_id = str(row.get("cve_id") or "").strip().upper()
        comp = cmap.normalize_comp(row.get("comp_norm"))
        if not cve_id or not comp:
            result["skipped"] += 1
            result["errors"].append(
                {"line": row.get("line"), "error": "cve_id/comp_norm 为空，已跳过"}
            )
            continue
        try:
            store.execute(
                "INSERT OR REPLACE INTO scan_cve_exclude(cve_id, comp_norm, version, reason)"
                " VALUES(?,?,?,?)",
                (
                    cve_id,
                    comp,
                    version.normalize_version(str(row.get("version") or "")),
                    str(row.get("reason") or ""),
                ),
            )
            result["upserted"] += 1
        except Exception as exc:  # noqa: BLE001 - 单行失败不中断
            result["errors"].append({"line": row.get("line"), "error": f"入库失败: {exc}"})
    log.info("cve_exclude.imported", path=str(file_path), upserted=result["upserted"])
    return result


def _load_exclusions(store: Any) -> tuple[set[tuple[str, str, str]], set[tuple[str, str]]]:
    """读 ``scan_cve_exclude`` → ``(按版本排除集合, 全版本排除集合)``，全部归一后比较。"""
    exact: set[tuple[str, str, str]] = set()
    wildcard: set[tuple[str, str]] = set()
    try:
        rows = store.query("SELECT cve_id, comp_norm, version FROM scan_cve_exclude")
    except Exception as exc:  # noqa: BLE001 - 未建表时视为没有排除项
        log.warn("cve_exclude.load_failed", error=str(exc))
        return exact, wildcard
    for row in rows:
        cve_id = str(row.get("cve_id") or "").strip().upper()
        comp = cmap.normalize_comp(row.get("comp_norm"))
        if not cve_id or not comp:
            continue
        normalized = version.normalize_version(str(row.get("version") or ""))
        if normalized:
            exact.add((cve_id, comp, normalized))
        else:
            wildcard.add((cve_id, comp))
    return exact, wildcard


def _ensure_exclusions(store: Any, cfg: dict) -> None:
    """表为空时尝试用配置/仓库里的 ``cve_exclude.csv`` 播种一次（失败静默，由调用方继续）。"""
    try:
        row = store.query_one("SELECT COUNT(*) AS n FROM scan_cve_exclude")
    except Exception:  # noqa: BLE001 - 未建表时交给 init_schema 处理
        return
    if row and int(row.get("n") or 0) > 0:
        return
    path = _exclude_csv_path(cfg)
    if path is not None:
        try:
            import_exclude_csv(store, str(path))
        except Exception as exc:  # noqa: BLE001 - 排除项是增强项，失败不影响匹配
            log.warn("cve_exclude.seed_failed", path=str(path), error=str(exc))


def _is_excluded(
    cve_id: str,
    comp_norm: str,
    detected_version: str,
    exact: set[tuple[str, str, str]],
    wildcard: set[tuple[str, str]],
) -> bool:
    """排除项精确命中判定（版本已归一；无版本的排除行视为全版本通配）。"""
    comp = cmap.normalize_comp(comp_norm)
    key = (str(cve_id).upper(), comp)
    if key in wildcard:
        return True
    normalized = version.normalize_version(detected_version)
    return (key[0], comp, normalized) in exact


# ---------------------------------------------------------------------------
# 候选集查询（带调用内缓存，一次 match_facts 内不重复查库）
# ---------------------------------------------------------------------------
def _prefixes_for(
    store: Any, fact: dict, comp_norm: str, resolve_cache: dict[str, list[str]]
) -> list[str]:
    """事实的 CPE 前缀集合：nmap 自带的 CPE 优先，再补 comp_map 人工映射。"""
    prefixes: list[str] = []
    cpe = str(fact.get("cpe") or "").strip()
    if cpe:
        prefix = cmap.to_cpe23_prefix(cpe)
        if prefix:
            prefixes.append(prefix)
    if comp_norm not in resolve_cache:
        resolve_cache[comp_norm] = cmap.resolve(store, comp_norm)
    for prefix in resolve_cache[comp_norm]:
        if prefix not in prefixes:
            prefixes.append(prefix)
    return prefixes


def _prefix_rows(store: Any, prefix: str, row_cache: dict[str, list[dict]]) -> list[dict]:
    """CPE 前缀粗筛（``LIKE '前缀%'``，前缀入参转义，不拼字符串）。"""
    if prefix in row_cache:
        return row_cache[prefix]
    try:
        rows = store.query(
            "SELECT * FROM cve_cache WHERE vulnerable=1 AND cpe23 LIKE ? ESCAPE '\\'",
            (_like_escape(prefix) + "%",),
        )
    except Exception as exc:  # noqa: BLE001 - 表缺失/查询失败按无候选处理
        log.warn("cve_cache.query_failed", prefix=prefix, error=str(exc))
        rows = []
    row_cache[prefix] = rows
    return rows


def _package_patterns(comp_norm: str) -> list[str]:
    """包级查询的包名候选：本名 + 别名 + ``comp-%`` 前缀（由 SQL LIKE 覆盖）。"""
    names = [comp_norm]
    for alias in PACKAGE_ALIASES.get(comp_norm, ()):
        if alias not in names:
            names.append(alias)
    return names


def _oval_rows(
    store: Any, releases: list[str], comp_norm: str, oval_cache: dict[tuple, list[dict]]
) -> list[dict]:
    """查 ``scan_oval_fix``：``release ∈ 候选`` 且（包名精确 / 别名 / ``comp-%`` 前缀）。"""
    if not releases:
        return []
    cache_key = (tuple(releases), comp_norm)
    if cache_key in oval_cache:
        return oval_cache[cache_key]
    packages = _package_patterns(comp_norm)
    placeholders = ",".join("?" for _ in packages)
    sql = (
        "SELECT * FROM scan_oval_fix WHERE release=? AND (package IN ("
        + placeholders
        + ") OR package LIKE ? ESCAPE '\\')"
    )
    args: list[Any] = [*packages, _like_escape(comp_norm) + "-%"]
    rows: list[dict] = []
    try:
        for release in releases:
            rows.extend(store.query(sql, [release, *args]))
    except Exception as exc:  # noqa: BLE001 - OVAL 表缺失/查询失败按无数据回退 CPE 路径
        log.warn("oval.query_failed", comp=comp_norm, error=str(exc))
        rows = []
    oval_cache[cache_key] = rows
    return rows


# ---------------------------------------------------------------------------
# 命中项构造
# ---------------------------------------------------------------------------
def _make_entry(
    *,
    fact: dict,
    comp_norm: str,
    detected_raw: str,
    cve_id: str,
    confidence: str,
    matched_rule: dict,
    cpe23: str,
    cpe_prefix: str,
    cvss: Any,
    severity: str,
    cvss_source: str,
    interval: dict,
    reason: str,
    candidate_rows: int,
    archive_map: dict,
    source_tag: str,
    matched_version: str,
) -> dict:
    """构造单条命中（含档案交叉验证：命中档案则 CVSS/severity/vuln_ref 以档案为准）。"""
    archive = archive_map.get(cve_id) if isinstance(archive_map, dict) else None
    archive = archive if isinstance(archive, dict) else None
    title = None
    if archive:
        archive_cvss = archive.get("cvss_score")
        if archive_cvss not in (None, ""):
            cvss = archive_cvss
        archive_severity = str(archive.get("severity") or "").strip()
        if archive_severity:
            severity = archive_severity
        cvss_source = "vuln"
        title = archive.get("title")
    entry_severity = str(severity or "").strip()
    if not entry_severity and cvss is not None:
        entry_severity = severity_cn_from_score(cvss)
    raw_evidence = fact.get("raw")
    return {
        "asset_id": str(fact.get("asset_id") or ""),
        "cve_id": cve_id,
        "comp_norm": comp_norm,
        "detected_version": detected_raw,
        "matched_version": matched_version,
        "matched_rule": matched_rule,
        "cpe23": cpe23,
        "confidence": confidence,
        "cvss": float(cvss) if isinstance(cvss, (int, float)) else cvss,
        "severity": entry_severity,
        "cvss_source": cvss_source,
        "evidence": {
            "interval": interval,
            "cpe_prefix": cpe_prefix,
            "reason": reason,
            "candidate_rows": int(candidate_rows),
            "source": source_tag,
            "distro": str(fact.get("distro") or ""),
            "raw": str(raw_evidence)[:300] if raw_evidence not in (None, "") else "",
            "scheme": version.scheme_of(comp_norm, detected_raw),
        },
        "vuln_ref": (archive or {}).get("id") if archive else None,
        "title": title,
        "source": source_tag,
    }


def severity_cn_from_score(score: Any) -> str:
    """按 CVSS 分值推导中文级别（档案/NVD 都没给英文级时的兜底）。"""
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


def _judge_cpe_row(
    row: dict, detected_norm: str, detected_raw: str
) -> tuple[str, str, str] | None:
    """CPE 行精判 → ``(confidence, reason, matched_version)``；不命中返回 ``None``。

    三档：有区间 → ``range``；无区间但 CPE 有精确版本 → ``exact``（或 cpe_only 兜底）；
    两者都没有 → ``cpe_only``。
    """
    cpe_version = str(row.get("cpe_version") or "").strip()
    has_bounds = any(str(row.get(key) or "") not in ("", "*", "-") for key in version.BOUND_KEYS)
    if has_bounds:
        if not detected_norm:
            return None  # 没有检测版本无法落区间：既不命中也不报 cpe_only（无版本证据）
        if version.in_range(detected_norm, row):
            return (
                "range",
                f"版本 {detected_raw} 落在 CPE 影响区间 {_interval_text(row)}（按 Debian 序比较）",
                cpe_version or detected_raw,
            )
        return None
    if cpe_version:
        if not detected_norm:
            return (
                "cpe_only",
                f"CPE 精确版本为 {cpe_version}，但检测版本为空，只能组件级命中",
                cpe_version,
            )
        if version.compare(detected_norm, cpe_version) == 0:
            return (
                "exact",
                f"检测版本 {detected_raw} 与 CPE 精确版本 {cpe_version} 相等",
                cpe_version,
            )
        if _prefix_equivalent(detected_norm, cpe_version):
            return (
                "exact",
                f"检测版本 {detected_raw} 归一后为 {detected_norm}，截断到 CPE 版本长度 "
                f"{len(cpe_version)} 后与 {cpe_version} 相等（前缀等价）",
                cpe_version,
            )
        # CPE 给了具体版本且与检测版本不相等：该条影响关系**不成立**，不能降级成
        # cpe_only（否则 openssl 3.5.5 会把 CVE-2009-0653(openssl 0.9.6) 之类全报成
        # "仅 CPE 命中"，既误导又淹没报告）。真正的 cpe_only 只用于"CPE 没给版本"。
        return None
    return (
        "cpe_only",
        "CPE 关系既无版本区间也无精确版本，只能组件级命中（vendor:product 匹配）",
        "",
    )


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
def match_facts(
    store: Any, cfg: dict | None, facts: list[dict], archive_map: dict | None = None
) -> dict:
    """把归一后的组件事实匹配到 CVE（三层收敛），返回 ``{"matched","stats","unknown"}``。

    ``facts`` 每条：``{"asset_id","comp_norm","version","cpe","source":"nmap"|"dpkg",
    "distro","raw"}``。``archive_map``：``{cve_id: {"id","cvss_score","severity","fix",
    "title"}}``（由 runner 从靶场模块档案库构造）；命中时 CVSS/severity/vuln_ref 以档案为准。

    返回的 ``matched`` 元素字段见 与实现说明：``range``/``exact`` 可入
    finding，``cpe_only`` 只入 observed；``evidence`` 给出区间、CPE 前缀、原因与候选行数，
    保证"为什么判它受影响"可复核。
    """
    feed.init_schema(store)  # 幂等建表（DDL 单一来源：hornwork.scan.store）
    cfg = cfg or {}
    archive_map = archive_map if isinstance(archive_map, dict) else {}
    max_cpe_only = int(cfg_get(cfg, "scan.cve.max_cpe_only", 100) or 100)

    _ensure_exclusions(store, cfg)
    excluded_exact, excluded_wild = _load_exclusions(store)

    matched: list[dict] = []
    unknown: list[dict] = []
    unknown_components: list[str] = []
    resolve_cache: dict[str, list[str]] = {}
    row_cache: dict[str, list[dict]] = {}
    oval_cache: dict[tuple, list[dict]] = {}
    stats: dict[str, Any] = {
        "components": 0, "candidates": 0, "matched": 0,
        "by_confidence": {}, "by_severity": {},
        "excluded": 0, "oval_used": 0, "unknown_components": [],
    }

    for fact in facts or []:
        if not isinstance(fact, dict):
            continue
        stats["components"] += 1
        asset_id = str(fact.get("asset_id") or "")
        comp_norm = cmap.normalize_comp(fact.get("comp_norm"))
        detected_raw = str(fact.get("version") or "").strip()
        detected_norm = version.normalize_version(detected_raw)
        source = str(fact.get("source") or "").strip().lower()
        distro = str(fact.get("distro") or "").strip()
        if not comp_norm:
            unknown.append(
                {"asset_id": asset_id, "comp_norm": "", "version": detected_raw,
                 "reason": REASON_NO_COMPONENT}
            )
            continue

        best: dict[str, dict] = {}
        excluded_seen: set[str] = set()
        candidate_rows = 0

        if source in PACKAGE_SOURCES:
            releases = _release_candidates(distro)
            oval_rows = _oval_rows(store, releases, comp_norm, oval_cache)
            if oval_rows:
                # ① 包级：OVAL 是发行版权威视图，命中即 confidence=range（detected < fixed）
                stats["oval_used"] += len(oval_rows)
                for row in oval_rows:
                    candidate_rows += 1
                    fixed = str(row.get("fixed_version") or "").strip()
                    if not fixed or not detected_norm:
                        continue
                    try:
                        below = version.compare(detected_norm, fixed) < 0
                    except (TypeError, ValueError):
                        continue
                    if not below:
                        continue
                    cve_id = str(row.get("cve_id") or "").strip().upper()
                    if not cve_id:
                        continue
                    if _is_excluded(
                        cve_id, comp_norm, detected_norm, excluded_exact, excluded_wild
                    ):
                        if cve_id not in excluded_seen:
                            excluded_seen.add(cve_id)
                            stats["excluded"] += 1
                        continue
                    release = str(row.get("release") or "")
                    package = str(row.get("package") or "")
                    entry = _make_entry(
                        fact=fact, comp_norm=comp_norm, detected_raw=detected_raw,
                        cve_id=cve_id, confidence="range",
                        matched_rule={
                            "type": "oval", "release": release, "package": package,
                            "fixed_version": fixed,
                        },
                        cpe23="", cpe_prefix="",
                        cvss=None, severity="", cvss_source="nvd",
                        interval={
                            **{key: "" for key in version.BOUND_KEYS},
                            "cpe_version": "", "fixed_version": fixed,
                            "release": release, "package": package,
                        },
                        reason=(
                            f"Ubuntu OVAL：{release} 的包 {package} 修复版本为 {fixed}，"
                            f"检测版本 {detected_raw} 低于修复版本（包级判定）"
                        ),
                        candidate_rows=0, archive_map=archive_map, source_tag="oval",
                        matched_version=fixed,
                    )
                    _keep_best(best, entry)
                # OVAL 有数据即权威：不再回退 CPE，避免"回移补丁"被 banner 版本误判
                _attach_row_cvss(store, best, archive_map)
                _finish_fact(best, matched, stats, candidate_rows, max_cpe_only)
                continue

        # ②/③ 服务级（或包级无 OVAL 数据时的回退）：CPE 前缀粗筛 + Python 精判
        prefixes = _prefixes_for(store, fact, comp_norm, resolve_cache)
        if not prefixes:
            unknown.append(
                {"asset_id": asset_id, "comp_norm": comp_norm, "version": detected_raw,
                 "reason": REASON_NO_CPE_MAPPING}
            )
            if comp_norm not in unknown_components:
                unknown_components.append(comp_norm)
            continue
        candidate_rows = 0
        for prefix in prefixes:
            rows = _prefix_rows(store, prefix, row_cache)
            candidate_rows += len(rows)
            for row in rows:
                cve_id = str(row.get("cve_id") or "").strip().upper()
                if not cve_id:
                    continue
                judged = _judge_cpe_row(row, detected_norm, detected_raw)
                if judged is None:
                    continue
                confidence, reason, matched_version = judged
                if _is_excluded(
                    cve_id, comp_norm, detected_norm, excluded_exact, excluded_wild
                ):
                    if cve_id not in excluded_seen:
                        excluded_seen.add(cve_id)
                        stats["excluded"] += 1
                    continue
                entry = _make_entry(
                    fact=fact, comp_norm=comp_norm, detected_raw=detected_raw,
                    cve_id=cve_id, confidence=confidence,
                    matched_rule={
                        "type": confidence,
                        **_interval_of(row),
                        "cpe23": str(row.get("cpe23") or ""),
                    },
                    cpe23=str(row.get("cpe23") or ""), cpe_prefix=prefix,
                    cvss=row.get("cvss"),
                    severity=str(row.get("severity") or "").strip(),
                    cvss_source="nvd",
                    interval=_interval_of(row), reason=reason,
                    candidate_rows=candidate_rows, archive_map=archive_map,
                    source_tag=str(row.get("source") or "nvd"),
                    matched_version=matched_version,
                )
                _keep_best(best, entry)
        _finish_fact(best, matched, stats, candidate_rows, max_cpe_only)

    stats["unknown_components"] = unknown_components
    matched.sort(
        key=lambda item: (
            SEVERITY_RANK.get(str(item.get("severity") or ""), 9),
            -(float(item.get("cvss") or 0.0)),
            item.get("cve_id") or "",
            item.get("asset_id") or "",
            item.get("comp_norm") or "",
        )
    )
    stats["matched"] = len(matched)
    log.info(
        "cve.match.done", facts=stats["components"], candidates=stats["candidates"],
        matched=stats["matched"], excluded=stats["excluded"], oval_used=stats["oval_used"],
        unknown=len(unknown),
    )
    return {"matched": matched, "stats": stats, "unknown": unknown}


def _keep_best(best: dict[str, dict], entry: dict) -> None:
    """同一 CVE 多行命中时保留置信度更高的那条（rank 相同保留先到的）。"""
    cve_id = entry["cve_id"]
    current = best.get(cve_id)
    if current is None or CONFIDENCE_RANK.get(entry["confidence"], 0) > CONFIDENCE_RANK.get(
        current["confidence"], 0
    ):
        best[cve_id] = entry


def _attach_row_cvss(store: Any, best: dict[str, dict], archive_map: dict) -> None:
    """OVAL 命中项没有 CVSS：从 ``cve_cache`` 取该 CVE 的最高分补全（档案优先）。"""
    for cve_id, entry in best.items():
        if entry.get("cvss") is not None or cve_id in archive_map:
            continue
        try:
            row = store.query_one(
                "SELECT cvss, severity FROM cve_cache WHERE cve_id=? AND cvss IS NOT NULL"
                " ORDER BY cvss DESC LIMIT 1",
                (cve_id,),
            )
        except Exception:  # noqa: BLE001 - 补全失败不影响命中
            row = None
        if not row:
            continue
        entry["cvss"] = row.get("cvss")
        severity = str(row.get("severity") or "").strip()
        if severity:
            entry["severity"] = severity_cn(severity) or severity
        elif entry.get("cvss") is not None:
            entry["severity"] = severity_cn_from_score(entry["cvss"])


def _finish_fact(
    best: dict[str, dict],
    matched: list[dict],
    stats: dict,
    candidate_rows: int,
    max_cpe_only: int,
) -> None:
    """收尾：按 CVE 收敛后的命中写入 matched，并统计 ``by_confidence``/``by_severity``。

    排除项已在逐行精判时过滤并计数，这里不重复判定；``cpe_only`` 按 ``scan.cve.max_cpe_only``
    限量（默认 100 条/事实），防止"只匹配到 product"的关系把 observed 撑爆。
    """
    stats["candidates"] += int(candidate_rows)
    emitted_cpe_only = 0
    for entry in best.values():
        if entry["confidence"] == "cpe_only":
            if emitted_cpe_only >= max_cpe_only:
                continue
            emitted_cpe_only += 1
        entry["evidence"]["candidate_rows"] = int(candidate_rows)
        matched.append(entry)
        confidence = str(entry.get("confidence") or "unknown")
        stats["by_confidence"][confidence] = stats["by_confidence"].get(confidence, 0) + 1
        severity = str(entry.get("severity") or "").strip()
        if severity:
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

