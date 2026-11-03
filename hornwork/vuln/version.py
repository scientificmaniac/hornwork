"""版本比较与影响区间匹配。

- Debian 规则（``deb``；``generic`` 退化为它）：完整实现 dpkg 语义，含文档点名的五类坑——
  epoch、``~`` 预发布、upstream/revision 分段数字比较、``+``/字母与空串排序、无 revision
  视为空串。纯 Python 实现（不调子进程），Linux 上用 ``dpkg --compare-versions`` 对拍。
- semver：主.次.修订 + 预发布标识，忽略 build metadata。
- 区间语义：introduced 左闭、fixed 右开、exclude 排除；matched 只答"是否受影响"，
  不答"是否可利用"（可利用性归扫描模块 PoC / 靶场模块复现）。
"""

from __future__ import annotations

import re
import shutil
import sys
from typing import Any

from ..log import get_logger

log = get_logger("vuln.version")

#: IF-18 的 reason 码（未命中原因，扫描模块可做统计）
REASON_NO_RULES = "no_rules"
REASON_VERSION_UNPARSABLE = "version_unparsable"
REASON_BELOW_INTRODUCED = "below_introduced"
REASON_AT_OR_ABOVE_FIXED = "at_or_above_fixed"
REASON_EXCLUDED = "excluded"
REASON_NOT_IN_RANGE = "not_in_range"

_EPOCH_RE = re.compile(r"^(\d+):(.*)$", re.DOTALL)
_SEMVER_CORE_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _split_version(version: str) -> tuple[int, str, str]:
    """拆 ``[epoch:]upstream[-revision]``；revision 取最后一个连字符之后（同 dpkg）。"""
    text = str(version or "").strip()
    epoch = 0
    match = _EPOCH_RE.match(text)
    if match:
        try:
            epoch = int(match.group(1))
        except ValueError:
            epoch = 0
        text = match.group(2)
    if "-" in text:
        upstream, revision = text.rsplit("-", 1)
    else:
        upstream, revision = text, ""
    return epoch, upstream, revision


def _is_digit(ch: str) -> bool:
    """只把 ASCII 数字当数字（对齐 C 版 dpkg 在 C locale 下的 isdigit）。"""
    return "0" <= ch <= "9"


def _order(ch: str) -> int:
    """dpkg 排序值：``~`` 最低，空串其次，字母按 ASCII，其余 +256。"""
    if not ch or _is_digit(ch):
        return 0
    if ch.isascii() and ch.isalpha():
        return ord(ch)
    return -1 if ch == "~" else ord(ch) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg 版本片段比较：非数字段逐字符 + 数字段按数值。"""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not _is_digit(a[i])) or (j < lb and not _is_digit(b[j])):
            ac = _order(a[i]) if i < la else 0
            bc = _order(b[j]) if j < lb else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and _is_digit(a[i]) and _is_digit(b[j]):
            if first_diff == 0:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and _is_digit(a[i]):
            return 1
        if j < lb and _is_digit(b[j]):
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def compare_debian(a: str, b: str) -> int:
    """Debian 版本比较：返回 -1 / 0 / 1。"""
    epoch_a, upstream_a, revision_a = _split_version(a)
    epoch_b, upstream_b, revision_b = _split_version(b)
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    result = _verrevcmp(upstream_a, upstream_b)
    if result:
        return result
    return _verrevcmp(revision_a, revision_b)


def _semver_parts(version: str) -> tuple[tuple[int, int, int], str]:
    """拆 ``((major, minor, patch), prerelease)``；容忍 ``v`` 前缀与缺位补 0。"""
    text = str(version or "").strip()
    if len(text) > 1 and text[0] in ("v", "V") and _is_digit(text[1]):
        text = text[1:]
    text = text.split("+", 1)[0]           # build metadata 不参与优先级
    core, _, prerelease = text.partition("-")
    match = _SEMVER_CORE_RE.match(core)
    if not match:
        raise ValueError(f"不是合法的 semver 版本号: {version!r}")
    nums = [int(group) if group is not None else 0 for group in match.groups()]
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2]), prerelease


def _compare_prerelease(a: str, b: str) -> int:
    """无预发布 > 有；数字标识 < 字母标识；逐段比较、短者小。"""
    if a == b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    parts_a, parts_b = a.split("."), b.split(".")
    for left, right in zip(parts_a, parts_b):
        if left == right:
            continue
        left_num, right_num = left.isdigit(), right.isdigit()
        if left_num and right_num:
            return -1 if int(left) < int(right) else 1
        if left_num:
            return -1
        if right_num:
            return 1
        return -1 if left < right else 1
    if len(parts_a) == len(parts_b):
        return 0
    return -1 if len(parts_a) < len(parts_b) else 1


def compare_semver(a: str, b: str) -> int:
    """semver 优先级比较：主.次.修订 →（相等时）预发布标识。"""
    core_a, pre_a = _semver_parts(a)
    core_b, pre_b = _semver_parts(b)
    if core_a != core_b:
        return -1 if core_a < core_b else 1
    return _compare_prerelease(pre_a, pre_b)


def normalize_scheme(scheme: Any) -> str:
    """scheme 归一成 ``deb`` / ``semver``；未知值回退 Debian 规则并告警。"""
    name = str(scheme or "generic").strip().lower() or "generic"
    if name in ("semver", "sem"):
        return "semver"
    if name not in ("generic", "deb", "debian", "dpkg"):
        log.warn("未知版本体系，回退 Debian 规则", scheme=name)
    return "deb"


def compare(a: str, b: str, scheme: str = "generic") -> int:
    """按版本体系比较两个版本号，返回 -1 / 0 / 1。"""
    if normalize_scheme(scheme) == "semver":
        return compare_semver(a, b)
    return compare_debian(a, b)


def dpkg_available() -> bool:
    """当前环境是否可调 ``dpkg --compare-versions``（对拍用；Windows 恒 False）。"""
    return sys.platform.startswith("linux") and shutil.which("dpkg") is not None


def apply_distro(rule: dict, distro: str | None) -> dict:
    """把 ``rule.distro`` 里的发行版修正版本套用到 ``fixed``（仅 deb 规则）。"""
    if not isinstance(rule, dict):
        return rule
    mapping = rule.get("distro")
    if not isinstance(mapping, dict) or not distro:
        return rule
    wanted = str(distro).strip().lower()
    for key, value in mapping.items():
        name = str(key).strip().lower()
        if not name:
            continue
        if wanted == name or wanted.startswith(name + "-") or wanted.startswith(name + ":"):
            resolved = dict(rule)
            resolved.update({"fixed": str(value), "scheme": "deb", "distro_used": name})
            return resolved
    return rule


def _rule_scheme(rule: dict) -> str:
    return normalize_scheme(rule.get("scheme") or "generic")


def in_range(version: str, rule: dict) -> bool:
    """判断版本是否落入单条区间规则（左闭右开 + exclude + 精确版本白名单）。"""
    try:
        if not isinstance(rule, dict) or not str(version or "").strip():
            return False
        scheme = _rule_scheme(rule)
        fixed = rule.get("fixed")
        if fixed not in (None, "") and compare(version, str(fixed), scheme) >= 0:
            return False
        for excluded in rule.get("exclude") or []:
            if excluded not in (None, "") and compare(version, str(excluded), scheme) == 0:
                return False
        introduced = rule.get("introduced")
        if introduced not in (None, "") and compare(version, str(introduced), scheme) < 0:
            return False
        versions = rule.get("versions")
        if versions:
            return any(compare(version, str(item), scheme) == 0 for item in versions)
        return True
    except (TypeError, ValueError):
        # 版本号/规则不可解析一律视为不落入区间，由 match_ranges 给 reason
        return False


def _version_parsable(version: str, scheme: str) -> bool:
    """粗判版本号是否可解析（semver 至少含数字；Debian 几乎什么都能比）。"""
    text = str(version or "").strip()
    if not text:
        return False
    return bool(re.search(r"\d", text)) if scheme == "semver" else True


def _is_exact_rule(rule: dict) -> bool:
    """规则是否属于"精确版本命中"（confidence=exact）。"""
    if rule.get("exact") or rule.get("versions"):
        return True
    introduced, fixed = rule.get("introduced"), rule.get("fixed")
    if introduced in (None, "") or fixed in (None, ""):
        return False
    try:
        return compare(str(introduced), str(fixed), _rule_scheme(rule)) == 0
    except (TypeError, ValueError):
        return False


def _miss_reason(version: str, rule: dict, scheme: str) -> str:
    """单条规则的未命中原因码。"""
    try:
        fixed = rule.get("fixed")
        if fixed not in (None, "") and compare(version, str(fixed), scheme) >= 0:
            return REASON_AT_OR_ABOVE_FIXED
        for excluded in rule.get("exclude") or []:
            if excluded not in (None, "") and compare(version, str(excluded), scheme) == 0:
                return REASON_EXCLUDED
        introduced = rule.get("introduced")
        if introduced not in (None, "") and compare(version, str(introduced), scheme) < 0:
            return REASON_BELOW_INTRODUCED
        return REASON_NOT_IN_RANGE
    except (TypeError, ValueError):
        return REASON_VERSION_UNPARSABLE


def _aggregate_reason(reasons: list[str]) -> str:
    """多规则都未命中：全一致给具体码，混合给 not_in_range。"""
    if reasons and len(set(reasons)) == 1:
        return reasons[0]
    return REASON_NOT_IN_RANGE


def match_ranges(version: str, ranges: list[dict]) -> dict:
    """版本 × 区间列表匹配（IF-18 判定核心）。

    返回 ``{"matched","matched_rule","confidence","reason"}``：confidence 为
    ``exact``（精确版本规则）/ ``range``（区间）/ ``unknown``（未命中）；解析失败不抛异常，
    退化为 ``unknown`` + ``version_unparsable``。
    """
    rules = [rule for rule in (ranges or []) if isinstance(rule, dict)]
    if not rules:
        return {"matched": False, "matched_rule": None, "confidence": "unknown", "reason": REASON_NO_RULES}
    for rule in rules:
        if not _version_parsable(version, _rule_scheme(rule)):
            return {
                "matched": False, "matched_rule": None,
                "confidence": "unknown", "reason": REASON_VERSION_UNPARSABLE,
            }
        try:
            hit = in_range(version, rule)
        except (TypeError, ValueError):
            return {
                "matched": False, "matched_rule": None,
                "confidence": "unknown", "reason": REASON_VERSION_UNPARSABLE,
            }
        if hit:
            confidence = "exact" if _is_exact_rule(rule) else "range"
            return {"matched": True, "matched_rule": rule, "confidence": confidence, "reason": None}
    reasons = [_miss_reason(version, rule, _rule_scheme(rule)) for rule in rules]
    return {
        "matched": False, "matched_rule": None,
        "confidence": "unknown", "reason": _aggregate_reason(reasons),
    }


def fixed_of(rule: dict | None) -> str | None:
    """取区间规则的修复版本（IF-18 的 fixed_version）。"""
    if not isinstance(rule, dict):
        return None
    fixed = rule.get("fixed")
    return None if fixed in (None, "") else str(fixed)


def describe_range(rule: dict) -> str:
    """把区间规则渲染成人类可读文本（漏洞卡/整改单用）。"""
    if not isinstance(rule, dict):
        return ""
    prefix = "semver " if _rule_scheme(rule) == "semver" else ""
    versions = rule.get("versions")
    if versions:
        return prefix + "精确版本 " + " / ".join(str(item) for item in versions)
    introduced, fixed = rule.get("introduced"), rule.get("fixed")
    if introduced not in (None, "") and fixed not in (None, ""):
        text = f"{prefix}[{introduced}, {fixed})"
    elif introduced not in (None, ""):
        text = f"{prefix}[{introduced}, +∞)"
    elif fixed not in (None, ""):
        text = f"{prefix}(-∞, {fixed})"
    else:
        text = prefix + "任意版本"
    excluded = [str(item) for item in rule.get("exclude") or [] if item not in (None, "")]
    return text + ("，排除 " + " / ".join(excluded) if excluded else "")
