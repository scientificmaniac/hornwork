"""CVSS 3.1 计算器单元测试。

对拍口径：与 FIRST 官方计算器结果逐条一致（8/8），不引用任何具体 CVE 的分值。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork.vuln import cvss  # noqa: E402

PREFIX = "CVSS:3.1/"

#:  对拍表（向量省略前缀，期望值来自官方计算器）
OFFICIAL_VECTORS = [
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # 未授权 RCE 常规
    ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # Scope 改变 + 全高影响
    ("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),   # Scope 改变 + 低权限
    ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # 本地提权
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # 拒绝服务
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),   # 高复杂度信息泄露
    ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # 反射型 XSS 典型
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # 0 分特判
]


class OfficialVectorTest(unittest.TestCase):
    """8 个公开向量：带前缀 / 省略前缀 / dict 入参三条路径结果一致。"""

    def test_official_vectors(self):
        for vector, expected in OFFICIAL_VECTORS:
            with self.subTest(vector=vector):
                self.assertEqual(cvss.calculate(PREFIX + vector), expected)
                self.assertEqual(cvss.calculate(vector), expected)
                self.assertEqual(cvss.calculate(cvss.parse(vector)), expected)

    def test_all_eight_pass(self):
        """显式计数，报告里可以直接写"与官方计算器一致 8/8"。"""
        passed = sum(
            1
            for vector, expected in OFFICIAL_VECTORS
            if cvss.calculate(vector) == expected
        )
        self.assertEqual(passed, 8)

    def test_parse_build_roundtrip(self):
        for vector, _expected in OFFICIAL_VECTORS:
            with self.subTest(vector=vector):
                metrics = cvss.parse(vector)
                self.assertEqual(cvss.build(metrics), PREFIX + vector)
                self.assertEqual(cvss.build(cvss.parse(PREFIX + vector)), PREFIX + vector)

    def test_severity_matches_table(self):
        expected = {9.8: "严重", 10.0: "严重", 9.9: "严重", 7.8: "高", 7.5: "高", 5.9: "中", 6.1: "中", 0.0: "无"}
        for vector, score in OFFICIAL_VECTORS:
            with self.subTest(vector=vector):
                self.assertEqual(cvss.severity(score), expected[score])
                self.assertEqual(cvss.explain(vector)["severity"], expected[score])


class ParseTest(unittest.TestCase):
    def test_lowercase_and_order(self):
        metrics = cvss.parse("av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h")
        self.assertEqual(metrics["AV"], "N")
        self.assertEqual(cvss.build(metrics), PREFIX + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_parse_rejects_wrong_version(self):
        for bad in (
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    cvss.parse(bad)

    def test_parse_rejects_bad_shapes(self):
        cases = [
            "",                                             # 空串
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",              # 缺 A
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P",      # 多了时间分量
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:X",          # 非法取值
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:N",     # 分量重复
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A",            # 分量缺冒号
        ]
        for bad in cases:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    cvss.parse(bad)

    def test_build_rejects_missing_or_illegal(self):
        good = {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
            "C": "H", "I": "H", "A": "H",
        }
        missing = dict(good)
        missing.pop("S")
        with self.assertRaises(ValueError):
            cvss.build(missing)
        illegal = dict(good)
        illegal["PR"] = "X"
        with self.assertRaises(ValueError):
            cvss.build(illegal)

    def test_build_fixed_order(self):
        metrics = {
            "C": "H", "I": "H", "A": "H", "S": "U",
            "UI": "N", "PR": "N", "AC": "L", "AV": "N",
        }
        self.assertEqual(cvss.build(metrics), PREFIX + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class RoundupTest(unittest.TestCase):
    """roundup 是"整数运算避开浮点误差"的关键实现，边界必须逐位对。"""

    def test_table(self):
        cases = [
            (0.0, 0.0),
            (0.000001, 0.0),
            (5.0, 5.0),
            (5.000001, 5.0),    # 浮点噪声不应进位
            (5.00001, 5.1),     # 真正超过 5.0 才进位
            (5.25, 5.3),
            (9.76013, 9.8),
            (9.8, 9.8),
            (9.800001, 9.8),
            (9.80001, 9.9),
            (10.0, 10.0),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertAlmostEqual(cvss.roundup(value), expected, places=6)

    def test_negative_and_zero(self):
        self.assertEqual(cvss.roundup(-1.0), 0.0)
        self.assertEqual(cvss.roundup(0.0), 0.0)


class SeverityTest(unittest.TestCase):
    def test_boundaries(self):
        cases = [
            (0.0, "无"), (0.0, "无"), (0.1, "低"), (3.9, "低"),
            (4.0, "中"), (6.9, "中"), (7.0, "高"), (8.9, "高"),
            (9.0, "严重"), (10.0, "严重"),
        ]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(cvss.severity(score), expected)


class ExplainTest(unittest.TestCase):
    def test_fields(self):
        detail = cvss.explain("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        for key in (
            "vector", "metrics", "weights", "scope_changed",
            "iss", "impact", "exploitability", "base_score", "severity",
        ):
            self.assertIn(key, detail)
        self.assertTrue(detail["scope_changed"])
        self.assertEqual(detail["base_score"], 10.0)
        self.assertEqual(detail["severity"], "严重")
        # PR 权重随 Scope 变化（S:C 时 low 为 0.68）
        low_scope_changed = cvss.explain("AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
        low_scope_unchanged = cvss.explain("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(low_scope_changed["weights"]["PR"], 0.68)
        self.assertEqual(low_scope_unchanged["weights"]["PR"], 0.62)

    def test_zero_impact(self):
        detail = cvss.explain("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(detail["impact"], 0.0)
        self.assertEqual(detail["base_score"], 0.0)

    def test_invalid_vector_raises(self):
        with self.assertRaises(ValueError):
            cvss.explain("AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


if __name__ == "__main__":
    unittest.main()
