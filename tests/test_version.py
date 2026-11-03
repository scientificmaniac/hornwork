"""版本比较与区间匹配单元测试。

- 50+ 组版本比较用例，覆盖文档点名的五类 Debian 坑：epoch、``~`` 预发布、
  upstream/revision 分段数字比较、``+``/字母顺序、无 revision 视为空串；
- Linux 上再用 ``dpkg --compare-versions`` 逐条对拍（目标一致率 100%），非 Linux 自动 skip；
- 另测 ``in_range`` / ``match_ranges`` / ``apply_distro`` 的区间语义与 reason 码。
"""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork.vuln import version  # noqa: E402

#: Debian 规则比较用例（a, b, 期望：a<b=-1 / a==b=0 / a>b=1）
DEBIAN_CASES = [
    # 基础与数字段
    ("1.0", "1.0", 0),
    ("1.0", "1.00", 0),
    ("1.0", "1.1", -1),
    ("1.9", "1.10", -1),
    ("1.10", "1.9", 1),
    ("2.0", "10.0", -1),
    ("0.9.9", "1.0.0", -1),
    ("3.0.0", "2.99.99", 1),
    ("1.0.0", "1.0", 1),
    ("1.0", "1.0.0", -1),
    ("1.0.0", "1.0.0.0", -1),
    ("1.0.0.0", "1.0.0", 1),
    # 无 revision 视为空串（空串排在数字前）
    ("1.2.3", "1.2.3-1", -1),
    ("1.2.3-1", "1.2.3", 1),
    ("1.0-0", "1.0", 0),
    ("1.0-00", "1.0", 0),
    ("1.0-0.1", "1.0", 1),
    ("1.0-1", "1.0-2", -1),
    ("1.0-1.1", "1.0-1.2", -1),
    # revision 逐段：非数字段 + 数字段按数值
    ("1.2.3-1ubuntu2", "1.2.3-1ubuntu3", -1),
    ("1.2.3-1ubuntu2", "1.2.3-1ubuntu10", -1),
    ("5.0.7-2ubuntu0.1", "5.0.7-2ubuntu0.2", -1),
    ("1.0.0-1", "1.0.0-1ubuntu1", -1),
    ("1.0.0-1ubuntu1", "1.0.0-1", 1),
    ("1.0-1", "1.0-1+deb11u1", -1),
    ("6:6.0.16-1+deb11u1", "6:6.0.16-1+deb11u2", -1),
    ("6:6.0.16-1ubuntu0.1", "6:6.0.16-1", 1),
    # ~ 预发布：排序值低于空串
    ("1.0~rc1", "1.0", -1),
    ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~~", "1.0~", -1),
    ("1.0~~", "1.0~~a", -1),
    ("2.0~beta", "2.0~alpha", 1),
    ("1:1.0~rc1", "1:1.0", -1),
    ("1.0-1ubuntu1~20.04.1", "1.0-1ubuntu1", -1),
    # epoch 优先
    ("1:1.0", "2.0", 1),
    ("1:1.0", "1:1.0", 0),
    ("0:1.0", "1.0", 0),
    ("2:0.1", "1:9.9", 1),
    # +、字母与空串的排序
    ("1.2.3+dfsg-1", "1.2.3-1", 1),
    ("1.2.3-1", "1.2.3+dfsg-1", -1),
    ("1.0+dfsg1", "1.0+dfsg2", -1),
    ("1.0a", "1.0", 1),
    ("1.0", "1.0a", -1),
    ("1.0a", "1.0b", -1),
    ("1.0svn1", "1.0", 1),
    ("1.0.rc1", "1.0", 1),
    ("6:6.0.16-1+deb11u1", "6:6.0.16-1", 1),
    ("a", "b", -1),
    # 组合场景（贴近档案里的真实版本号）
    ("8.2.6", "8.2.7", -1),
    ("8.3.0", "8.3.1", -1),
    ("3.1.0", "3.1.1", -1),
    ("5.0.7", "6.0.16", -1),
    ("6.0.16", "6:6.0.16-1", -1),
]

#: semver 比较用例（a, b, 期望）
SEMVER_CASES = [
    ("8.2.6", "8.2.7", -1),
    ("8.0.0", "8.0.7", -1),
    ("8.3.0", "8.3.1", -1),
    ("3.1.0", "3.1.1", -1),
    ("3.0.7", "3.1.0", -1),
    ("8.0.0-beta1", "8.0.0", -1),
    ("8.0.0", "8.0.0-beta1", 1),
    ("1.2.3", "1.2.3", 0),
    ("v1.2.3", "1.2.3", 0),
    ("1.2.3+build.5", "1.2.3", 0),
    ("1.10.0", "1.9.0", 1),
    ("1.0.0-rc.1", "1.0.0-rc.2", -1),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-beta.11", "1.0.0-beta.2", 1),
    ("1.0.0-rc.1", "1.0.0-beta.11", 1),
    ("1.0", "1.0.0", 0),
    ("1.0.0", "1.0", 0),
]


class DebianCompareTest(unittest.TestCase):
    def test_cases(self):
        self.assertGreaterEqual(len(DEBIAN_CASES), 50)
        for a, b, expected in DEBIAN_CASES:
            with self.subTest(a=a, b=b):
                self.assertEqual(version.compare_debian(a, b), expected)
                # 反对称性
                self.assertEqual(version.compare_debian(b, a), -expected)
                # generic 退化为 Debian 规则
                self.assertEqual(version.compare(a, b, "generic"), expected)

    @unittest.skipUnless(version.dpkg_available(), "非 Linux 或缺少 dpkg，跳过对拍")
    def test_against_dpkg(self):
        """Linux 上用 dpkg --compare-versions 逐条对拍（目标一致率 100%）。"""
        checked = 0
        mismatches: list[str] = []
        for a, b, expected in DEBIAN_CASES:
            # dpkg 只接受以数字（或 epoch 数字）开头的版本串
            if not re.match(r"^(\d+:)?\d", a) or not re.match(r"^(\d+:)?\d", b):
                continue
            if expected == 0:
                args = [a, "eq", b]
            elif expected < 0:
                args = [a, "lt", b]
            else:
                args = [a, "gt", b]
            result = subprocess.run(
                ["dpkg", "--compare-versions"] + args,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            checked += 1
            if result.returncode != 0:
                mismatches.append(f"{a} vs {b} 期望 {expected}，dpkg 不成立（{args[1]}）")
        self.assertGreater(checked, 40, "对拍用例太少")
        self.assertEqual(mismatches, [], "与 dpkg 不一致: " + "; ".join(mismatches))


class SemverCompareTest(unittest.TestCase):
    def test_cases(self):
        for a, b, expected in SEMVER_CASES:
            with self.subTest(a=a, b=b):
                self.assertEqual(version.compare_semver(a, b), expected)
                self.assertEqual(version.compare(a, b, "semver"), expected)
                self.assertEqual(version.compare_semver(b, a), -expected)

    def test_invalid_semver(self):
        with self.assertRaises(ValueError):
            version.compare_semver("not-a-version", "1.0.0")

    def test_unknown_scheme_falls_back_to_debian(self):
        # 未知 scheme 回退 Debian 规则（不抛异常），与 generic 结果一致
        self.assertEqual(version.compare("1.9", "1.10", "no-such-scheme"), -1)

    def test_dpkg_available_returns_bool(self):
        self.assertIsInstance(version.dpkg_available(), bool)


class InRangeTest(unittest.TestCase):
    def test_semver_interval_left_closed_right_open(self):
        rule = {"scheme": "semver", "introduced": "8.2.0", "fixed": "8.2.7"}
        for candidate, expected in [
            ("8.2.0", True),
            ("8.2.6", True),
            ("8.2.7", False),
            ("8.1.9", False),
            ("8.3.0", False),
        ]:
            with self.subTest(candidate=candidate):
                self.assertIs(version.in_range(candidate, rule), expected)

    def test_multi_rule_grafana_style(self):
        ranges = [
            {"scheme": "semver", "introduced": "8.0.0", "fixed": "8.0.7"},
            {"scheme": "semver", "introduced": "8.1.0", "fixed": "8.1.8"},
            {"scheme": "semver", "introduced": "8.2.0", "fixed": "8.2.7"},
            {"scheme": "semver", "introduced": "8.3.0", "fixed": "8.3.1"},
        ]
        self.assertFalse(any(version.in_range("8.2.8", rule) for rule in ranges))
        self.assertTrue(any(version.in_range("8.3.0", rule) for rule in ranges))
        self.assertTrue(any(version.in_range("8.0.0", rule) for rule in ranges))
        self.assertTrue(any(version.in_range("8.1.7", rule) for rule in ranges))

    def test_exclude(self):
        rule = {"scheme": "semver", "introduced": "8.0.0", "fixed": "8.0.7", "exclude": ["8.0.3"]}
        self.assertFalse(version.in_range("8.0.3", rule))
        self.assertTrue(version.in_range("8.0.4", rule))

    def test_open_bounds(self):
        self.assertTrue(version.in_range("5.0.7", {"scheme": "semver", "fixed": "6.0.16"}))
        self.assertFalse(version.in_range("6.0.16", {"scheme": "semver", "fixed": "6.0.16"}))
        self.assertTrue(version.in_range("9.9.9", {"scheme": "semver", "introduced": "5.0.0"}))
        self.assertFalse(version.in_range("4.9.9", {"scheme": "semver", "introduced": "5.0.0"}))

    def test_exact_versions_rule(self):
        rule = {"scheme": "semver", "versions": ["1.2.3", "1.2.4"]}
        self.assertTrue(version.in_range("1.2.3", rule))
        self.assertFalse(version.in_range("1.2.5", rule))

    def test_debian_epoch(self):
        # 5:5.0.7-2ubuntu0.1 的 epoch=5 < 6:6.0.16-1+deb11u1 的 epoch=6，落在区间内
        rule = {"scheme": "deb", "introduced": "0", "fixed": "6:6.0.16-1+deb11u1"}
        self.assertTrue(version.in_range("5:5.0.7-2ubuntu0.1", rule))
        self.assertFalse(version.in_range("6:6.0.16-1+deb11u1", rule))

    def test_bad_inputs(self):
        self.assertFalse(version.in_range("", {"scheme": "semver", "fixed": "1.0.0"}))
        self.assertFalse(version.in_range("1.0", None))  # type: ignore[arg-type]


class MatchRangesTest(unittest.TestCase):
    def test_matched_returns_rule(self):
        ranges = [{"scheme": "semver", "introduced": "8.2.0", "fixed": "8.2.7"}]
        result = version.match_ranges("8.2.6", ranges)
        self.assertTrue(result["matched"])
        self.assertEqual(result["confidence"], "range")
        self.assertIsNone(result["reason"])
        self.assertEqual(result["matched_rule"], ranges[0])

    def test_unmatched_reason_codes(self):
        ranges = [
            {"scheme": "semver", "introduced": "8.2.0", "fixed": "8.2.7"},
            {"scheme": "semver", "introduced": "8.3.0", "fixed": "8.3.1"},
        ]
        above = version.match_ranges("9.0.0", ranges)
        self.assertFalse(above["matched"])
        self.assertEqual(above["confidence"], "unknown")
        self.assertIn(above["reason"], (version.REASON_AT_OR_ABOVE_FIXED, version.REASON_NOT_IN_RANGE))
        below = version.match_ranges("8.0.0", ranges)
        self.assertIn(below["reason"], (version.REASON_BELOW_INTRODUCED, version.REASON_NOT_IN_RANGE))

    def test_excluded_reason(self):
        ranges = [{"scheme": "semver", "introduced": "1.0.0", "fixed": "2.0.0", "exclude": ["1.5.0"]}]
        result = version.match_ranges("1.5.0", ranges)
        self.assertFalse(result["matched"])
        self.assertEqual(result["reason"], version.REASON_EXCLUDED)

    def test_no_rules(self):
        result = version.match_ranges("1.0.0", [])
        self.assertEqual(result["reason"], version.REASON_NO_RULES)
        self.assertFalse(result["matched"])

    def test_unparsable(self):
        ranges = [{"scheme": "semver", "introduced": "1.0.0", "fixed": "2.0.0"}]
        result = version.match_ranges("not-a-version", ranges)
        self.assertEqual(result["reason"], version.REASON_VERSION_UNPARSABLE)
        self.assertEqual(result["confidence"], "unknown")
        empty = version.match_ranges("", ranges)
        self.assertEqual(empty["reason"], version.REASON_VERSION_UNPARSABLE)

    def test_exact_confidence(self):
        ranges = [{"scheme": "semver", "versions": ["1.2.3"]}]
        result = version.match_ranges("1.2.3", ranges)
        self.assertTrue(result["matched"])
        self.assertEqual(result["confidence"], "exact")


class DistroRuleTest(unittest.TestCase):
    def test_apply_distro_switches_fixed(self):
        rule = {
            "scheme": "deb",
            "introduced": "0",
            "fixed": "6:6.0.16-1",
            "distro": {"ubuntu": "6:6.0.16-1ubuntu0.1"},
        }
        resolved = version.apply_distro(rule, "ubuntu-20.04")
        self.assertEqual(resolved["fixed"], "6:6.0.16-1ubuntu0.1")
        self.assertEqual(resolved["scheme"], "deb")
        # 发行版修正号更高 → 原本"已修复"的版本在 Ubuntu 上仍是受影响版本
        self.assertFalse(version.in_range("6:6.0.16-1", rule))
        self.assertTrue(version.in_range("6:6.0.16-1", resolved))

    def test_apply_distro_untouched(self):
        rule = {"scheme": "semver", "introduced": "1.0.0", "fixed": "2.0.0"}
        self.assertEqual(version.apply_distro(rule, "ubuntu-20.04"), rule)
        self.assertEqual(version.apply_distro(rule, None), rule)


if __name__ == "__main__":
    unittest.main()
