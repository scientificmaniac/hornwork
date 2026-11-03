"""扫描模块 CVE 版本比较包装（**复用**靶场模块 ``hornwork.vuln.version``，不重写第二套比较器）。

靶场模块已经用 50+ 组用例与 ``dpkg --compare-versions`` 对拍过 Debian 语义（epoch、``~`` 预发布、
数字段按数值、'' 与字母排序、revision 段），本模块只做"扫描模块语义"的薄包装：

- :func:`compare`：Debian/dpkg 序比较，``None``/空串视为 ``"0"``（与靶场模块 ``in_range`` 口径一致）；
- :func:`in_range`：把 ``cve_cache`` 一行解释为版本区间（左闭右开），无区间退化为 ``cpe_version``
  精确相等；``cpe_version`` 为 ``*``/``-``/空时不作为约束；
- :func:`extract_version`：从 CPE 2.3 取 version 字段（``*``/``-`` → ``""``），兼容 CPE 2.2 URI；
- :func:`normalize_version`：比较前做发行版后缀归一，``9.6p1 Ubuntu-3ubuntu13.5`` →
  ``9.6p1-3ubuntu13.5``、``1.24.0 (Ubuntu)`` → ``1.24.0``；
- :func:`scheme_of`：按版本串形态猜版本体系（``debian``/``semver``/``generic``），**只用于解释
  与展示**；实际比较统一走 Debian 序——CPE/NVD 的版本串是"发行版版本 + 上游版本"混合形态，
  Debian 序是覆盖两者的安全超集。

本文件在导入期不读文件、不连数据库，Windows 上可安全 import。
"""

from __future__ import annotations

import re

from ...log import get_logger
from ...vuln.version import compare_debian

log = get_logger("scan.cve.version")

#: 区间字段（``cve_cache`` 的四个版本边界列）
BOUND_KEYS: tuple[str, ...] = (
    "version_start_incl",
    "version_start_excl",
    "version_end_incl",
    "version_end_excl",
)

#: ``9.6p1 Ubuntu-3ubuntu13.5`` 这类 banner 的发行版后缀（带空格）
_DISTRO_SPACE_RE = re.compile(r"\s+(?:ubuntu|debian)[-\s]", re.IGNORECASE)
#: ``1.24.0 (Ubuntu)`` 这类括号后缀
_PAREN_DISTRO_RE = re.compile(r"\s*\((?:ubuntu|debian)[^)]*\)", re.IGNORECASE)
#: 结尾单独出现的 ``ubuntu``/``debian`` 单词（如 nmap 的 ``1.20.0 ubuntu``）
_TRAILING_DISTRO_RE = re.compile(r"\s+(?:ubuntu|debian)\S*$", re.IGNORECASE)
_EPOCH_RE = re.compile(r"^\d+:")
#: Debian revision 形态：``-1`` / ``-1.2`` / ``-1ubuntu2``（semver 预发布 ``-rc1`` 不算）
_DEB_REVISION_RE = re.compile(r"-[0-9]+(?:\.[0-9]+)*(?:[a-z][0-9a-z.+~]*)?$", re.IGNORECASE)
_SEMVER_RE = re.compile(r"^v?\d+(?:\.\d+){1,2}(?:[-+][0-9A-Za-z.\-+]+)?$")

#: 常见 dpkg 包名（``scheme_of`` 的兜底提示；只影响解释文案，不影响比较结果）
_DEB_COMPONENTS: frozenset[str] = frozenset(
    {
        "apache2", "bash", "bind9", "chrony", "coreutils", "cups", "docker.io",
        "libc6", "libssl1.1", "libssl3", "mysql-server", "nginx", "ntp",
        "openssh-client", "openssh-server", "php", "postgresql", "redis-server",
        "samba", "sudo", "systemd", "vsftpd",
    }
)


# ---------------------------------------------------------------------------
# 基础比较
# ---------------------------------------------------------------------------
def compare(a: str | None, b: str | None) -> int:
    """按 Debian/dpkg 序比较两个版本串，返回 ``-1``/``0``/``1``；空串/None 视为 ``"0"``。"""
    left = str(a if a is not None else "").strip() or "0"
    right = str(b if b is not None else "").strip() or "0"
    return compare_debian(left, right)


def normalize_version(version: str | None) -> str:
    """比较前归一：去发行版后缀（Ubuntu/Debian 带空格或括号的形态）。

    只处理"banner 里混入发行版说明"的场景，纯 dpkg 版本串原样返回——
    ``9.6p1-3ubuntu13.5`` 这类**发行版修订号本身参与比较**，不能删。
    """
    text = str(version or "").strip()
    if not text:
        return ""
    text = _PAREN_DISTRO_RE.sub("", text)
    text = _DISTRO_SPACE_RE.sub("-", text)
    text = _TRAILING_DISTRO_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# 区间判定
# ---------------------------------------------------------------------------
def _meaningful(value: object) -> bool:
    """区间边界是否有意义（None/""/``*``/``-`` 都算没有约束）。"""
    text = str(value if value is not None else "").strip()
    return bool(text) and text not in ("*", "-")


def in_range(v: str, row: dict) -> bool:
    """检测版本是否落入 ``cve_cache`` 的一行区间（左闭右开）。

    - 有任何边界 → 按 `version_start_incl/excl`、`version_end_incl/excl` 判定；
    - 无边界但有 ``cpe_version`` → 退化为精确相等（``*``/``-``/空不约束）；
    - 两者都没有 → 无法判定，返回 ``False``（由 matcher 按 ``cpe_only`` 处理）。
    """
    if not isinstance(row, dict):
        return False
    detected = str(v if v is not None else "").strip()
    if not detected:
        return False
    try:
        has_bounds = any(_meaningful(row.get(key)) for key in BOUND_KEYS)
        if has_bounds:
            start_incl = row.get("version_start_incl")
            start_excl = row.get("version_start_excl")
            end_incl = row.get("version_end_incl")
            end_excl = row.get("version_end_excl")
            if _meaningful(start_incl) and compare(detected, str(start_incl)) < 0:
                return False
            if _meaningful(start_excl) and compare(detected, str(start_excl)) <= 0:
                return False
            if _meaningful(end_incl) and compare(detected, str(end_incl)) > 0:
                return False
            if _meaningful(end_excl) and compare(detected, str(end_excl)) >= 0:
                return False
            return True
        cpe_version = row.get("cpe_version")
        if _meaningful(cpe_version):
            return compare(detected, str(cpe_version)) == 0
        return False
    except (TypeError, ValueError):  # 版本/边界不可解析一律视为不命中，绝不抛给扫描循环
        log.warn("区间判定失败，按不命中处理", version=detected, cpe=row.get("cpe23"))
        return False


# ---------------------------------------------------------------------------
# CPE 字段
# ---------------------------------------------------------------------------
def split_unescaped(text: str, sep: str = ":") -> list[str]:
    """按未转义的分隔符切分 CPE（NVD 会用 ``\\`` 转义字段内的 ``:``）。"""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in str(text or ""):
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == sep:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _cpe_attributes(cpe23: str) -> list[str]:
    """CPE 2.3/2.2 → ``[part, vendor, product, version, update, ...]``；非法返回 ``[]``。"""
    text = str(cpe23 or "").strip()
    if text.startswith("cpe:2.3:"):
        return split_unescaped(text)[2:]
    if text.startswith("cpe:/"):
        return split_unescaped(text[5:])
    return []


def extract_version(cpe23: str) -> str:
    """从 CPE 取 version 字段；``*``/``-``/缺失一律返回 ``""``。

    >>> extract_version("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
    '9.6p1'
    >>> extract_version("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*")
    ''
    """
    fields = _cpe_attributes(cpe23)
    if len(fields) < 4:
        return ""
    version = fields[3].strip()
    return "" if version in ("*", "-") else version


# ---------------------------------------------------------------------------
# 版本体系判定（只用于解释）
# ---------------------------------------------------------------------------
def scheme_of(comp_norm: str, version: str) -> str:
    """按组件名 + 版本串形态粗判版本体系：``debian``/``semver``/``generic``。

    仅用于 ``evidence.reason`` 与报告展示；比较统一走 Debian 序。
    """
    comp = str(comp_norm or "").strip().lower()
    text = str(version or "").strip()
    if not text:
        return "generic"
    lowered = text.lower()
    if _EPOCH_RE.match(text):
        return "debian"
    if "ubuntu" in lowered or "debian" in lowered or "~" in text:
        return "debian"
    if _DEB_REVISION_RE.search(text):
        return "debian"
    if comp in _DEB_COMPONENTS:
        return "debian"
    if _SEMVER_RE.match(text):
        return "semver"
    return "generic"
