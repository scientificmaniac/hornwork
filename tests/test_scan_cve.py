"""扫描模块 CVE 引擎单元测试：NVD 流式导入、Ubuntu OVAL、CPE 映射、区间匹配、置信度分级。

覆盖点：

- **流式解析**：小型 NVD 2.0 夹具（区间 / 精确版本 / 多节点 configurations / ``children`` /
  ``vulnerable=false``）→ 断言导入行数、字段、幂等；``.json.gz`` 与 ``import_dir``；
  ``tracemalloc`` 峰值量级断言（< 200 MB）；
- **OVAL**：``dpkginfo_test/object/state``、``extend_definition`` 组合、发行版推断、
  显式 release、``.xml.gz``、幂等；
- **版本包装**：与靶场模块 ``compare_debian`` 逐条对拍（epoch/``~``/revision/``p`` 后缀），
  ``in_range`` 左闭右开、``extract_version``、``scheme_of``；
- **CPE / comp_map**：解析、前缀、CSV 导入、``resolve``、配置回退；
- **端到端匹配**：``range``/``exact``/``cpe_only`` 三档、排除项（含通配）、档案覆盖
  CVSS/severity/vuln_ref、OVAL 包级优先与"OVAL 有数据不回退 CPE"的权威性、unknown 统计、
  ``stats`` 聚合与结果排序；
- **集成**：Lead 的 :func:`hornwork.scan.store.init_schema` 建表后本包可直接导入匹配。

夹具里的 ``CVE-2099-99999`` / ``CVE-2099-88888`` / ``CVE-2099-77777`` / ``CVE-2099-66666``
是**明显虚构的测试编号（非真实漏洞）**；真实编号（CVE-2021-43798 / CVE-2023-38408 /
CVE-2021-23017）的区间取自项目内已核对的数据。

产物统一写 ``tests/_tmp/scan-cve-<uuid>/``（DSH 沙箱下系统临时目录不可写），tearDown 清理。
"""

from __future__ import annotations

import bz2
import gzip
import json
import shutil
import sys
import time
import tracemalloc
import unittest
import uuid
from pathlib import Path

_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork.scan.cve import cmap, feed, matcher, version  # noqa: E402
from hornwork.store import Store  # noqa: E402
from hornwork.vuln.version import compare_debian  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CVE_FIXTURE_DIR = Path(__file__).resolve().parent / "data" / "cve"
NVD_FIXTURE = CVE_FIXTURE_DIR / "nvd-mini.json"
OVAL_FIXTURE = CVE_FIXTURE_DIR / "oval-mini.xml"
OVAL_CANONICAL_FIXTURE = CVE_FIXTURE_DIR / "oval-canonical-mini.xml"
REPO_COMP_MAP = PROJECT_ROOT / "rules" / "scan" / "comp_map.csv"
REPO_EXCLUDE = PROJECT_ROOT / "rules" / "scan" / "cve_exclude.csv"


def _mktemp(prefix: str) -> Path:
    """在 ``tests/_tmp`` 下建临时目录（沙箱内系统临时目录不可写）。"""
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = _TMP_ROOT / f"{prefix}-{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _cfg(**overrides) -> dict:
    """最小配置：comp_map 指向仓库内置表，CPE 命中上限放宽到测试需要的量级。"""
    cfg = {
        "scan": {
            "rules": {"comp_map": str(REPO_COMP_MAP), "cve_exclude": str(REPO_EXCLUDE)},
            "cve": {"max_cpe_only": 100},
        }
    }
    for key, value in overrides.items():
        cfg["scan"][key] = value
    return cfg


class _StoreCase(unittest.TestCase):
    """测试基类：临时目录 + 真 Store（复用检测模块 ``hornwork.store.Store``）。"""

    def setUp(self):
        self.tmp = _mktemp("scan-cve")
        self.db = Store(self.tmp / "hornwork.db")

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# NVD 流式导入
# ---------------------------------------------------------------------------
class NvdImportTest(_StoreCase):
    """NVD JSON 2.0 流式导入：字段、跳过项、幂等、gzip、目录、峰值内存。"""

    def test_import_fields_and_skipped(self):
        result = feed.import_nvd(self.db, str(NVD_FIXTURE))
        self.assertEqual(result["files"], 1)
        self.assertEqual(result["cves"], 5)
        self.assertEqual(result["imported_rows"], 9)
        self.assertEqual(result["skipped"], 1)  # vulnerable=false 的 Ubuntu 平台关系
        self.assertEqual(result["errors"], [])
        self.assertGreater(result["bytes"], 0)
        self.assertGreaterEqual(result["elapsed_ms"], 0)
        self.assertLess(result["peak_kb"], 200 * 1024)  # < 200 MB

        grafana = self.db.query(
            "SELECT * FROM cve_cache WHERE cve_id=? ORDER BY version_start_incl",
            ("CVE-2021-43798",),
        )
        self.assertEqual(len(grafana), 4)
        row = next(item for item in grafana if item["version_start_incl"] == "8.2.0")
        self.assertEqual(row["version_end_excl"], "8.2.7")
        self.assertEqual(row["cpe23"], "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*")
        self.assertAlmostEqual(row["cvss"], 7.5)
        self.assertEqual(row["severity"], "高")
        self.assertEqual(row["vulnerable"], 1)
        self.assertEqual(row["source"], "nvd")
        # 无区间/无精确版本时边界存空串（复合主键去重的前提，不能是 NULL）
        self.assertEqual(row["cpe_version"], "")

        # children 递归：CVE-2023-38408 的 cpeMatch 在 nodes[].children[] 里
        openssh = self.db.query_one(
            "SELECT * FROM cve_cache WHERE cve_id=?", ("CVE-2023-38408",)
        )
        self.assertIsNotNone(openssh)
        self.assertEqual(openssh["version_end_excl"], "9.3p2")
        self.assertEqual(openssh["severity"], "严重")

        # 精确版本写入 cpe_version
        exact = self.db.query_one(
            "SELECT * FROM cve_cache WHERE cve_id=? AND cpe_version=?",
            ("CVE-2099-99999", "1.20.0"),
        )
        self.assertIsNotNone(exact)
        self.assertEqual(exact["version_start_incl"], "")

        # CVSS v2 回退：无 baseSeverity 时按分值推导中文级别
        v2_row = self.db.query_one(
            "SELECT * FROM cve_cache WHERE cve_id=?", ("CVE-2099-66666",)
        )
        self.assertAlmostEqual(v2_row["cvss"], 8.0)
        self.assertEqual(v2_row["severity"], "高")

        # vulnerable=false 的关系不入库
        platform = self.db.query_one(
            "SELECT COUNT(*) AS n FROM cve_cache WHERE cpe23 LIKE 'cpe:2.3:o:canonical:%'"
        )
        self.assertEqual(int(platform["n"]), 0)

    def test_reimport_idempotent(self):
        feed.import_nvd(self.db, str(NVD_FIXTURE))
        second = feed.import_nvd(self.db, str(NVD_FIXTURE))
        self.assertEqual(second["imported_rows"], 9)
        total = self.db.query_one("SELECT COUNT(*) AS n FROM cve_cache")
        self.assertEqual(int(total["n"]), 9)

    def test_gzip_support_and_peak_memory(self):
        gz_path = self.tmp / "nvdcve-2.0-2021.json.gz"
        with gzip.open(str(gz_path), "wt", encoding="utf-8") as handle:
            handle.write(NVD_FIXTURE.read_text(encoding="utf-8"))
        result = feed.import_nvd(self.db, [str(gz_path)])
        self.assertEqual(result["files"], 1)
        self.assertEqual(result["cves"], 5)
        total = self.db.query_one("SELECT COUNT(*) AS n FROM cve_cache")
        self.assertEqual(int(total["n"]), 9)

        # 独立测量：小夹具峰值远低于 200 MB（设计目标是"与文件大小无关"）
        tracemalloc.start()
        try:
            feed.import_nvd(self.db, str(NVD_FIXTURE))
        finally:
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        self.assertLess(peak, 200 * 1024 * 1024)

    def test_import_dir_and_stats(self):
        feed_dir = self.tmp / "feed"
        feed_dir.mkdir()
        for year in (2021, 2022):
            with gzip.open(
                str(feed_dir / f"nvdcve-2.0-{year}.json.gz"), "wt", encoding="utf-8"
            ) as handle:
                handle.write(NVD_FIXTURE.read_text(encoding="utf-8"))
        result = feed.import_dir(self.db, str(feed_dir))
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["cves"], 5)
        total = self.db.query_one("SELECT COUNT(*) AS n FROM cve_cache")
        self.assertEqual(int(total["n"]), 9)  # 两份相同内容按主键覆盖

        # 未压缩 .json 形态：默认 pattern 找不到时自动回退 *.json
        plain_dir = self.tmp / "feed-plain"
        plain_dir.mkdir()
        shutil.copyfile(NVD_FIXTURE, plain_dir / "nvdcve-2.0-2023.json")
        plain = feed.import_dir(self.db, str(plain_dir))
        self.assertEqual(plain["files"], 1)
        self.assertEqual(plain["pattern"], "nvdcve-2.0-*.json")
        self.assertEqual(int(self.db.query_one("SELECT COUNT(*) AS n FROM cve_cache")["n"]), 9)

        stats = feed.stats(self.db)
        self.assertEqual(stats["cves"], 5)
        self.assertEqual(stats["rows"], 9)
        self.assertEqual(stats["by_source"], {"nvd": 9})
        self.assertEqual(stats["by_severity"].get("严重"), 1)
        self.assertEqual(stats["by_severity"].get("高"), 2)
        self.assertIsNotNone(stats["earliest"])
        self.assertIsNotNone(stats["latest"])
        self.assertEqual(stats["oval_fixes"], 0)
        self.assertEqual(stats["oval_releases"], [])

    def test_streaming_across_block_boundary(self):
        """单个 CVE 对象大于读取块（256 KiB）时必须能跨块重解码，不能丢数据。"""

        def make_cve(index: int, description: str) -> dict:
            return {
                "cve": {
                    "id": f"CVE-2020-{9000 + index}",
                    "published": "2020-01-01T00:00:00.000",
                    "lastModified": "2020-01-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": description}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 6.0,
                                                              "baseSeverity": "MEDIUM"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [
                        {"vulnerable": True,
                         "criteria": "cpe:2.3:a:vendor:boundary:*:*:*:*:*:*:*:*",
                         "versionEndExcluding": "2.0"}
                    ]}]}],
                }
            }

        big = "A" * (feed.BLOCK + 4096)  # 故意跨块
        doc = {"vulnerabilities": [make_cve(1, "short"), make_cve(2, big), make_cve(3, "short")]}
        path = self.tmp / "boundary.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        result = feed.import_nvd(self.db, str(path))
        self.assertEqual(result["cves"], 3)
        self.assertEqual(result["imported_rows"], 3)
        self.assertEqual(result["errors"], [])
        total = self.db.query_one("SELECT COUNT(*) AS n FROM cve_cache")
        self.assertEqual(int(total["n"]), 3)

    def test_missing_file_and_bad_json(self):
        missing = feed.import_nvd(self.db, str(self.tmp / "nope.json"))
        self.assertEqual(missing["files"], 0)
        self.assertTrue(missing["errors"])

        bad = self.tmp / "bad.json"
        bad.write_text('{"vulnerabilities": [{"cve": {', encoding="utf-8")
        result = feed.import_nvd(self.db, str(bad))
        self.assertEqual(result["files"], 1)
        self.assertTrue(result["errors"])
        self.assertEqual(result["cves"], 0)


# ---------------------------------------------------------------------------
# Ubuntu OVAL
# ---------------------------------------------------------------------------
class OvalImportTest(_StoreCase):
    """Ubuntu OVAL：包 → 修复版本、extend_definition、发行版推断、gz 支持、幂等。"""

    def _count(self) -> int:
        return int(self.db.query_one("SELECT COUNT(*) AS n FROM scan_oval_fix")["n"])

    def test_import_infer_release_and_extend_definition(self):
        result = feed.import_oval(self.db, str(OVAL_FIXTURE))  # release 从 platform 推断
        self.assertEqual(result["release"], "noble")
        self.assertEqual(result["imported_fixes"], 2)
        self.assertEqual(result["cves"], 2)
        self.assertEqual(result["packages"], 2)
        self.assertEqual(result["errors"], [])

        openssl = self.db.query_one(
            "SELECT * FROM scan_oval_fix WHERE cve_id=?", ("CVE-2099-88888",)
        )
        self.assertEqual(openssl["package"], "openssl")
        self.assertEqual(openssl["fixed_version"], "3.0.13-1ubuntu1")
        self.assertEqual(openssl["release"], "noble")
        self.assertEqual(openssl["source"], "ubuntu-oval")
        self.assertTrue(openssl["imported_at"])

        # extend_definition：def:2 → def:3(patch) → dpkginfo_test
        openssh = self.db.query_one(
            "SELECT * FROM scan_oval_fix WHERE cve_id=?", ("CVE-2099-77777",)
        )
        self.assertIsNotNone(openssh)
        self.assertEqual(openssh["package"], "openssh-server")
        self.assertEqual(openssh["fixed_version"], "1:9.3p1-1ubuntu3")

    def test_explicit_release_gzip_and_idempotent(self):
        feed.import_oval(self.db, str(OVAL_FIXTURE))
        self.assertEqual(self._count(), 2)
        feed.import_oval(self.db, str(OVAL_FIXTURE))  # 幂等
        self.assertEqual(self._count(), 2)

        gz_path = self.tmp / "com.ubuntu.jammy.cve.oval.xml.gz"
        with gzip.open(str(gz_path), "wt", encoding="utf-8") as handle:
            handle.write(OVAL_FIXTURE.read_text(encoding="utf-8"))
        result = feed.import_oval(self.db, str(gz_path))
        self.assertEqual(result["release"], "jammy")  # 从文件名推断
        self.assertEqual(result["imported_fixes"], 2)
        self.assertEqual(self._count(), 4)

        # 显式 release 覆盖文件名推断
        explicit = feed.import_oval(self.db, str(gz_path), release="focal")
        self.assertEqual(explicit["release"], "focal")
        self.assertEqual(self._count(), 6)

        # Ubuntu 官方分发形态 .xml.bz2
        bz_path = self.tmp / "com.ubuntu.oracular.cve.oval.xml.bz2"
        bz_path.write_bytes(bz2.compress(OVAL_FIXTURE.read_bytes()))
        bz_result = feed.import_oval(self.db, str(bz_path))
        self.assertEqual(bz_result["release"], "oracular")
        self.assertEqual(bz_result["imported_fixes"], 2)
        self.assertEqual(self._count(), 8)
        stats = feed.stats(self.db)
        self.assertEqual(stats["oval_fixes"], 8)
        self.assertEqual(
            stats["oval_releases"], ["focal", "jammy", "noble", "oracular"]
        )

    def test_missing_file(self):
        result = feed.import_oval(self.db, str(self.tmp / "none.xml"), release="noble")
        self.assertEqual(result["imported_fixes"], 0)
        self.assertTrue(result["errors"])

    def test_canonical_style_variable_objects(self):
        """真实 Canonical OVAL 形态：包名在 ``<variables>`` 段、``name`` 用 ``var_ref`` 引用。

        回归点：真实 noble 文件里 ``dpkginfo_object/name`` 只有 ``var_ref`` 没有文本，
        旧实现会把 objects 解析成 0 个、``imported_fixes=0``；本用例锁死修复后的行为：
        对象/变量诊断数、var_ref 后处理、``extend_definition``、无 state 测试计入 skipped、
        悬空 var_ref 计入 errors 且不中断。
        """
        result = feed.import_oval(self.db, str(OVAL_CANONICAL_FIXTURE))  # release 从 platform 推断
        self.assertEqual(result["release"], "noble")
        self.assertEqual(result["objects"], 4)   # 4 个解析出包名的对象
        self.assertEqual(result["objects_raw"], 5)  # 5 个原始对象（其中 1 个 var_ref 悬空）
        self.assertEqual(result["tests"], 5)
        self.assertEqual(result["states"], 4)
        self.assertEqual(result["variables"], 2)
        self.assertEqual(result["unresolved_var_refs"], 1)
        self.assertEqual(result["imported_fixes"], 4)
        self.assertEqual(result["cves"], 3)
        self.assertEqual(result["packages"], 4)
        # 12346 只有"包存在"测试（无 state）→ skipped；12349 var_ref 悬空 → skipped + error
        self.assertEqual(result["skipped"], 2)
        self.assertTrue(result["errors"])
        error_definitions = [
            item.get("definition") for item in result["errors"] if item.get("definition")
        ]
        self.assertEqual(error_definitions, ["oval:com.ubuntu.noble:def:20990000005"])
        self.assertNotIn(
            "oval:com.ubuntu.noble:def:20990000002", error_definitions,
            "无 state 的'包存在'测试是正常形态，不应报 error",
        )

        rows = {
            (row["cve_id"], row["package"], row["fixed_version"])
            for row in self.db.query("SELECT * FROM scan_oval_fix")
        }
        # 变量引用解析出包名 + 修复版本
        self.assertIn(("CVE-2099-12345", "gcc-arm-none-eabi", "2.47-1ubuntu0.24.04.1"), rows)
        # extend_definition 链（patch 定义 + 字面量 name）
        self.assertIn(("CVE-2099-12347", "openssh-server", "1:9.3p1-1ubuntu3"), rows)
        # 变量多值（at least one）：每个值都是真实受影响的包名，全部保留
        self.assertIn(("CVE-2099-12348", "libpam0g", "5.0-1ubuntu1"), rows)
        self.assertIn(("CVE-2099-12348", "libpam-modules", "5.0-1ubuntu1"), rows)
        self.assertEqual(
            int(self.db.query(
                "SELECT COUNT(*) AS n FROM scan_oval_fix WHERE cve_id IN (?,?)",
                ("CVE-2099-12346", "CVE-2099-12349"),
            )[0]["n"]),
            0,
        )

        # 幂等：重复导入行数不变
        again = feed.import_oval(self.db, str(OVAL_CANONICAL_FIXTURE))
        self.assertEqual(again["imported_fixes"], 4)
        self.assertEqual(self._count(), 4)


# ---------------------------------------------------------------------------
# 版本比较包装 / 区间
# ---------------------------------------------------------------------------
class VersionWrapperTest(unittest.TestCase):
    """扫描模块 ``version`` 包装与靶场模块 ``compare_debian`` 结果必须完全一致。"""

    #: (a, b, 期望)；覆盖文档附录 A 的 epoch/~/revision/p 后缀五类坑
    CASES = [
        ("1.2.3", "1.2.10", -1),
        ("1.0~rc1", "1.0", -1),
        ("1:9.6p1-3", "9.6p1-4", 1),
        ("9.6p1-3ubuntu13.5", "9.6p1-3ubuntu13.4", 1),
        ("2.4.41-4ubuntu2.1", "2.4.41-4ubuntu2", 1),
        ("9.6p1", "9.6", 1),
        ("1.24.0", "1.24.0", 0),
        ("1.2.3", "1.2.3-1", -1),
        ("6:6.0.16-1+deb11u1", "6:6.0.16-1+deb11u2", -1),
        ("1.0", "1.00", 0),
        ("8.2.6", "8.2.7", -1),
        ("3.0.12", "3.0.13-1ubuntu1", -1),
        ("1:9.3p1-1ubuntu2", "1:9.3p1-1ubuntu3", -1),
        ("1.20.0", "1.20.1", -1),
    ]

    def test_compare_matches_module_two(self):
        for left, right, expected in self.CASES:
            with self.subTest(left=left, right=right):
                self.assertEqual(version.compare(left, right), expected)
                self.assertEqual(version.compare(left, right), compare_debian(left, right))
                self.assertEqual(version.compare(right, left), -expected)

    def test_empty_and_none_are_zero(self):
        self.assertEqual(version.compare(None, ""), 0)
        self.assertEqual(version.compare("", "0"), 0)
        self.assertEqual(version.compare("", "1.0"), compare_debian("0", "1.0"))
        self.assertEqual(version.compare(None, "1.0"), -1)

    def test_normalize_version(self):
        self.assertEqual(
            version.normalize_version("9.6p1 Ubuntu-3ubuntu13.5"), "9.6p1-3ubuntu13.5"
        )
        self.assertEqual(version.normalize_version("1.24.0 (Ubuntu)"), "1.24.0")
        self.assertEqual(version.normalize_version("1.20.0 ubuntu"), "1.20.0")
        self.assertEqual(version.normalize_version("8.2.6"), "8.2.6")
        self.assertEqual(version.normalize_version(None), "")

    def test_in_range_semantics(self):
        row = {"version_start_incl": "8.2.0", "version_end_excl": "8.2.7"}
        self.assertTrue(version.in_range("8.2.0", row))   # 左闭
        self.assertTrue(version.in_range("8.2.6", row))
        self.assertFalse(version.in_range("8.2.7", row))  # 右开
        self.assertFalse(version.in_range("8.1.9", row))
        self.assertFalse(version.in_range("", row))

        end_incl = {"version_start_incl": "0.6.18", "version_end_incl": "1.20.0"}
        self.assertTrue(version.in_range("1.20.0", end_incl))
        self.assertFalse(version.in_range("1.20.1", end_incl))

        start_excl = {"version_start_excl": "1.0", "version_end_excl": "2.0"}
        self.assertFalse(version.in_range("1.0", start_excl))
        self.assertTrue(version.in_range("1.0.1", start_excl))

        exact = {"cpe_version": "1.20.0"}
        self.assertTrue(version.in_range("1.20.0", exact))
        self.assertFalse(version.in_range("1.20.1", exact))
        self.assertFalse(version.in_range("1.20.0", {"cpe_version": "*"}))
        self.assertFalse(version.in_range("1.20.0", {}))

    def test_extract_version(self):
        self.assertEqual(
            version.extract_version("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"),
            "9.6p1",
        )
        self.assertEqual(
            version.extract_version("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"), ""
        )
        self.assertEqual(version.extract_version("cpe:2.3:a:openbsd:openssh:-:*:*:*"), "")
        self.assertEqual(
            version.extract_version("cpe:/a:openbsd:openssh:10.2p1"), "10.2p1"
        )
        self.assertEqual(version.extract_version(""), "")

    def test_scheme_of(self):
        self.assertEqual(version.scheme_of("grafana", "8.2.6"), "semver")
        self.assertEqual(version.scheme_of("openssl", "3.0.13-1ubuntu1"), "debian")
        self.assertEqual(version.scheme_of("openssh", "1:9.3p1-1ubuntu3"), "debian")
        self.assertEqual(version.scheme_of("libc6", "2.39"), "debian")  # dpkg 包名兜底
        self.assertEqual(version.scheme_of("thing", ""), "generic")
        self.assertEqual(version.scheme_of("thing", "1.0~beta"), "debian")


# ---------------------------------------------------------------------------
# CPE / comp_map
# ---------------------------------------------------------------------------
class CpeMapTest(_StoreCase):
    """CPE 解析、前缀化、映射表导入与查询、配置/仓库回退。"""

    def test_parse_cpe23(self):
        parsed = cmap.parse_cpe23("cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
        self.assertEqual(parsed["part"], "a")
        self.assertEqual(parsed["vendor"], "openbsd")
        self.assertEqual(parsed["product"], "openssh")
        self.assertEqual(parsed["version"], "9.6p1")
        self.assertEqual(parsed["update"], "*")
        self.assertEqual(len(parsed["rest"]), 6)

        wildcard = cmap.parse_cpe23("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*")
        self.assertEqual(wildcard["version"], "")
        self.assertEqual(cmap.parse_cpe23("not-a-cpe")["product"], "")

    def test_to_cpe23_prefix(self):
        self.assertEqual(
            cmap.to_cpe23_prefix("cpe:/a:openbsd:openssh:10.2p1"),
            "cpe:2.3:a:openbsd:openssh:",
        )
        self.assertEqual(
            cmap.to_cpe23_prefix("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"),
            "cpe:2.3:a:nginx:nginx:",
        )
        self.assertEqual(
            cmap.to_cpe23_prefix("cpe:2.3:a:nginx:nginx:"), "cpe:2.3:a:nginx:nginx:"
        )
        self.assertEqual(cmap.to_cpe23_prefix("openssh"), "")
        self.assertEqual(cmap.to_cpe23_prefix("cpe:2.3:x:vendor:product:"), "")

    def test_normalize_comp(self):
        self.assertEqual(cmap.normalize_comp("OpenSSH"), "openssh")
        self.assertEqual(cmap.normalize_comp("Apache httpd"), "apache-httpd")
        self.assertEqual(cmap.normalize_comp("spring_cloud_gateway"), "spring-cloud-gateway")
        self.assertEqual(cmap.normalize_comp(None), "")

    def test_import_repo_csv_and_resolve(self):
        result = cmap.import_csv(self.db, str(REPO_COMP_MAP))
        self.assertGreaterEqual(result["upserted"], 60)
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(result["errors"], [])
        self.assertEqual(
            cmap.resolve(self.db, "openssh"), ["cpe:2.3:a:openbsd:openssh:"]
        )
        nginx_prefixes = cmap.resolve(self.db, "nginx")
        self.assertIn("cpe:2.3:a:nginx:nginx:", nginx_prefixes)
        self.assertIn("cpe:2.3:a:f5:nginx:", nginx_prefixes)
        self.assertEqual(cmap.resolve(self.db, "no-such-component"), [])

        # 重复导入幂等
        again = cmap.import_csv(self.db, str(REPO_COMP_MAP))
        count = self.db.query_one("SELECT COUNT(*) AS n FROM cve_component_map")
        self.assertEqual(int(count["n"]), result["upserted"])
        self.assertEqual(again["upserted"], result["upserted"])

    def test_seed_from_dir_config_and_fallback(self):
        direct = cmap.seed_from_dir(self.db, _cfg())
        self.assertEqual(direct["path"], str(REPO_COMP_MAP))
        self.assertFalse(direct["fallback"])
        self.assertGreaterEqual(direct["upserted"], 60)

        # 配置指向不存在的路径 → 回退仓库内置表
        cfg = {"scan": {"rules": {"comp_map": str(self.tmp / "missing.csv")}}}
        fallback = cmap.seed_from_dir(self.db, cfg)
        self.assertTrue(fallback["fallback"])
        self.assertEqual(fallback["path"], str(REPO_COMP_MAP))
        self.assertGreaterEqual(fallback["upserted"], 60)

    def test_import_bad_rows(self):
        bad = self.tmp / "comp_map.csv"
        bad.write_text(
            "comp_norm,cpe23,source,note\n"
            'good,cpe:2.3:a:vendor:good:,manual,"ok"\n'
            "bad,not-a-cpe,manual,\n"
            ",cpe:2.3:a:vendor:x:,manual,\n",
            encoding="utf-8",
        )
        result = cmap.import_csv(self.db, str(bad))
        self.assertEqual(result["upserted"], 1)
        self.assertEqual(result["skipped"], 2)
        self.assertEqual(len(result["errors"]), 2)
        self.assertEqual(self.db.query("SELECT comp_norm FROM cve_component_map"), [
            {"comp_norm": "good"}
        ])


# ---------------------------------------------------------------------------
# 端到端匹配
# ---------------------------------------------------------------------------
class MatcherTest(_StoreCase):
    """三层收敛匹配：置信度、排除项、档案覆盖、OVAL 权威性、unknown 与统计。"""

    def setUp(self):
        super().setUp()
        self.cfg = _cfg()
        feed.import_nvd(self.db, str(NVD_FIXTURE))
        feed.import_oval(self.db, str(OVAL_FIXTURE))   # release=noble
        cmap.seed_from_dir(self.db, self.cfg)

    def _match(self, facts, archive_map=None):
        return matcher.match_facts(self.db, self.cfg, facts, archive_map)

    def test_range_hit_and_evidence(self):
        facts = [
            {
                "asset_id": "ast-1", "comp_norm": "grafana", "version": "8.2.6",
                "cpe": "cpe:/a:grafana:grafana:8.2.6", "source": "nmap",
                "distro": "", "raw": "HTTP/1.1 302 Found\r\nServer: Grafana",
            }
        ]
        result = self._match(facts)
        self.assertEqual(result["stats"]["components"], 1)
        self.assertEqual(len(result["matched"]), 1)
        entry = result["matched"][0]
        self.assertEqual(entry["cve_id"], "CVE-2021-43798")
        self.assertEqual(entry["asset_id"], "ast-1")
        self.assertEqual(entry["comp_norm"], "grafana")
        self.assertEqual(entry["detected_version"], "8.2.6")
        self.assertEqual(entry["confidence"], "range")
        self.assertAlmostEqual(entry["cvss"], 7.5)
        self.assertEqual(entry["severity"], "高")
        self.assertEqual(entry["cvss_source"], "nvd")
        self.assertIsNone(entry["vuln_ref"])
        self.assertEqual(entry["evidence"]["interval"]["version_end_excl"], "8.2.7")
        self.assertIn("8.2.7", entry["evidence"]["reason"])
        self.assertGreaterEqual(entry["evidence"]["candidate_rows"], 4)
        self.assertEqual(entry["evidence"]["cpe_prefix"], "cpe:2.3:a:grafana:grafana:")
        self.assertEqual(result["stats"]["by_confidence"], {"range": 1})
        self.assertEqual(result["stats"]["by_severity"], {"高": 1})
        self.assertEqual(result["unknown"], [])

    def test_archive_overrides_cvss_and_vuln_ref(self):
        facts = [
            {"asset_id": "ast-1", "comp_norm": "grafana", "version": "8.2.6",
             "cpe": "cpe:/a:grafana:grafana:8.2.6", "source": "nmap"}
        ]
        archive = {
            "CVE-2021-43798": {
                "id": "VULN-2026-0001", "cvss_score": 7.5, "severity": "高",
                "title": "Grafana 插件静态资源路由路径穿越导致任意文件读取",
                "fix": {"patch_version": "升级到 8.0.7 / 8.1.8 / 8.2.7 / 8.3.1"},
            }
        }
        entry = self._match(facts, archive)["matched"][0]
        self.assertEqual(entry["cvss_source"], "vuln")
        self.assertEqual(entry["vuln_ref"], "VULN-2026-0001")
        self.assertEqual(entry["title"], "Grafana 插件静态资源路由路径穿越导致任意文件读取")
        self.assertAlmostEqual(entry["cvss"], 7.5)
        self.assertEqual(entry["severity"], "高")

    def test_exact_and_prefix_equivalence(self):
        facts = [
            {"asset_id": "ast-1", "comp_norm": "nginx", "version": "1.20.0",
             "cpe": "cpe:/a:nginx:nginx:1.20.0", "source": "nmap"}
        ]
        matched = {item["cve_id"]: item for item in self._match(facts)["matched"]}
        self.assertEqual(set(matched), {"CVE-2021-23017", "CVE-2099-99999"})
        self.assertEqual(matched["CVE-2021-23017"]["confidence"], "range")
        exact = matched["CVE-2099-99999"]
        self.assertEqual(exact["confidence"], "exact")
        self.assertAlmostEqual(exact["cvss"], 5.0)
        self.assertEqual(exact["severity"], "中")
        self.assertIn("精确版本", exact["evidence"]["reason"])

        # nmap banner 带发行版修订：比较失败后用"截断到 CPE 版本长度"的前缀等价
        facts[0]["version"] = "1.20.0-1ubuntu1"
        matched = {item["cve_id"]: item for item in self._match(facts)["matched"]}
        self.assertNotIn("CVE-2021-23017", matched)  # 高于 1.20.0（end_incl）
        self.assertEqual(matched["CVE-2099-99999"]["confidence"], "exact")
        self.assertIn("前缀等价", matched["CVE-2099-99999"]["evidence"]["reason"])

    def test_container_cpe_is_not_component(self):
        """nmap 的容器/OS CPE（part=o）不应被当成应用组件去匹配。"""
        facts = [
            {"asset_id": "ast-1", "comp_norm": "linux_kernel", "version": "7.0.0",
             "cpe": "cpe:/o:linux:linux_kernel:7.0.0", "source": "nmap"}
        ]
        result = self._match(facts)
        self.assertEqual(result["matched"], [])

    def test_exact_version_mismatch_is_not_vulnerable(self):
        """CPE 给了具体版本且与检测版本不等 → 影响关系不成立，不得降级成 cpe_only。

        实机回归（2026-10-26 VM）：openssl 3.5.5 曾把 ``CVE-2009-0653``（CPE 精确版本
        0.9.6）报成"仅 CPE 命中"，类似误分类累计 100+ 条，淹没报告。真正需要 cpe_only 的
        只有"CPE 完全没有版本信息"的条目（vendor:product 级）。
        """
        # CVE-2099-88888 是测试夹具编号，非真实漏洞
        self.db.execute(
            "INSERT INTO cve_cache(cve_id, cpe23, vulnerable, cpe_version, cvss, severity, source)"
            " VALUES(?,?,?,?,?,?,?)",
            ("CVE-2099-88888", "cpe:2.3:a:openssl:openssl:0.9.6:*:*:*:*:*:*:*",
             1, "0.9.6", 5.0, "中", "nvd"),
        )
        facts = [
            {"asset_id": "ast-1", "comp_norm": "openssl", "version": "3.5.5",
             "cpe": "cpe:/a:openssl:openssl:3.5.5", "source": "nmap"}
        ]
        result = self._match(facts)
        ids = {item["cve_id"] for item in result["matched"]}
        self.assertNotIn("CVE-2099-88888", ids)

    def test_cpe_only_when_version_above_exact(self):
        facts = [
            {"asset_id": "ast-1", "comp_norm": "nginx", "version": "1.21.0",
             "cpe": "cpe:/a:nginx:nginx:1.21.0", "source": "nmap"}
        ]
        result = self._match(facts)
        self.assertEqual(len(result["matched"]), 1)
        entry = result["matched"][0]
        self.assertEqual(entry["cve_id"], "CVE-2099-99999")
        self.assertEqual(entry["confidence"], "cpe_only")
        self.assertEqual(result["stats"]["by_confidence"], {"cpe_only": 1})

    def test_exclusion_exact_and_wildcard(self):
        facts = [
            {"asset_id": "ast-1", "comp_norm": "grafana", "version": "8.2.6",
             "cpe": "cpe:/a:grafana:grafana:8.2.6", "source": "nmap"}
        ]
        self.db.execute(
            "INSERT OR REPLACE INTO scan_cve_exclude(cve_id, comp_norm, version, reason)"
            " VALUES(?,?,?,?)",
            ("CVE-2021-43798", "grafana", "8.2.6", "测试：定点排除"),
        )
        result = self._match(facts)
        self.assertEqual(result["matched"], [])
        self.assertEqual(result["stats"]["excluded"], 1)

        # 版本留空 → 该组件该 CVE 的所有版本都排除
        self.db.execute(
            "UPDATE scan_cve_exclude SET version='' WHERE cve_id=?", ("CVE-2021-43798",)
        )
        result = self._match(facts)
        self.assertEqual(result["matched"], [])
        self.assertEqual(result["stats"]["excluded"], 1)

    def test_exclude_csv_import(self):
        csv_path = self.tmp / "cve_exclude.csv"
        csv_path.write_text(
            "cve_id,comp_norm,version,reason\n"
            "# 注释行\n"
            "CVE-2099-99999,nginx,1.20.0,测试排除\n"
            "CVE-2021-23017,nginx,,测试通配排除\n",
            encoding="utf-8",
        )
        imported = matcher.import_exclude_csv(self.db, str(csv_path))
        self.assertEqual(imported["upserted"], 2)
        rows = self.db.query("SELECT * FROM scan_cve_exclude ORDER BY cve_id")
        self.assertEqual([row["cve_id"] for row in rows], ["CVE-2021-23017", "CVE-2099-99999"])
        facts = [
            {"asset_id": "ast-1", "comp_norm": "nginx", "version": "1.20.0",
             "cpe": "cpe:/a:nginx:nginx:1.20.0", "source": "nmap"}
        ]
        result = self._match(facts)
        self.assertEqual(result["matched"], [])
        self.assertEqual(result["stats"]["excluded"], 2)

    def test_oval_package_level_authority(self):
        # 发行版 OVAL：包版本低于修复版本 → range 命中（不需要 CPE）
        facts = [
            {"asset_id": "ast-2", "comp_norm": "openssl", "version": "3.0.12",
             "source": "dpkg", "distro": "ubuntu-24.04"}
        ]
        archive = {
            "CVE-2099-88888": {
                "id": "VULN-TEST-0001", "cvss_score": 8.1, "severity": "高",
                "title": "测试档案（OVAL 包级命中）",
            }
        }
        result = self._match(facts, archive)
        self.assertEqual(len(result["matched"]), 1)
        entry = result["matched"][0]
        self.assertEqual(entry["cve_id"], "CVE-2099-88888")
        self.assertEqual(entry["confidence"], "range")
        self.assertEqual(entry["source"], "oval")
        self.assertEqual(entry["matched_rule"]["type"], "oval")
        self.assertEqual(entry["matched_rule"]["package"], "openssl")
        self.assertEqual(entry["matched_rule"]["fixed_version"], "3.0.13-1ubuntu1")
        self.assertIn("Ubuntu OVAL", entry["evidence"]["reason"])
        self.assertEqual(entry["cvss_source"], "vuln")
        self.assertEqual(entry["vuln_ref"], "VULN-TEST-0001")
        self.assertAlmostEqual(entry["cvss"], 8.1)
        self.assertEqual(result["stats"]["oval_used"], 1)

        # OVAL 有该包数据即权威：已高于修复版本 → 不回退 CPE（CVE-2099-66666 的
        # CPE 区间 [.., 99.0) 本会命中，这里必须被"包级已修复"抑制）
        facts[0]["version"] = "3.0.13-1ubuntu1"
        result = self._match(facts)
        self.assertEqual(result["matched"], [])

        # extend_definition 链：openssh-server 包 → CVE-2099-77777
        facts = [
            {"asset_id": "ast-2", "comp_norm": "openssh-server",
             "version": "1:9.3p1-1ubuntu2", "source": "dpkg", "distro": "noble"}
        ]
        result = self._match(facts)
        self.assertEqual(len(result["matched"]), 1)
        self.assertEqual(result["matched"][0]["cve_id"], "CVE-2099-77777")

    def test_nmap_range_via_normalized_banner(self):
        facts = [
            {"asset_id": "ast-3", "comp_norm": "openssh",
             "version": "9.3p1 Ubuntu-3ubuntu13.5",
             "cpe": "cpe:/a:openbsd:openssh:9.3p1", "source": "nmap"}
        ]
        result = self._match(facts)
        self.assertEqual(len(result["matched"]), 1)
        entry = result["matched"][0]
        self.assertEqual(entry["cve_id"], "CVE-2023-38408")
        self.assertEqual(entry["confidence"], "range")
        self.assertIn("9.3p2", entry["evidence"]["reason"])

    def test_package_falls_back_to_cpe_without_oval(self):
        facts = [
            {"asset_id": "ast-4", "comp_norm": "nginx", "version": "1.20.0",
             "source": "dpkg", "distro": "noble"}
        ]
        result = self._match(facts)
        cves = {item["cve_id"] for item in result["matched"]}
        self.assertIn("CVE-2021-23017", cves)
        self.assertIn("CVE-2099-99999", cves)
        self.assertEqual(result["stats"]["oval_used"], 0)

    def test_unknown_and_stats(self):
        facts = [
            {"asset_id": "ast-5", "comp_norm": "totally-unknown-comp",
             "version": "1.0.0", "source": "nmap"},
            {"asset_id": "ast-5", "comp_norm": "", "version": "1.0.0", "source": "nmap"},
        ]
        result = self._match(facts)
        self.assertEqual(result["matched"], [])
        reasons = {item["reason"] for item in result["unknown"]}
        self.assertEqual(reasons, {matcher.REASON_NO_CPE_MAPPING, matcher.REASON_NO_COMPONENT})
        self.assertEqual(result["stats"]["unknown_components"], ["totally-unknown-comp"])
        self.assertEqual(result["stats"]["components"], 2)

    def test_severity_mapping_helpers(self):
        self.assertEqual(feed.severity_cn("critical"), "严重")
        self.assertEqual(feed.severity_cn("HIGH"), "高")
        self.assertEqual(feed.severity_cn("medium"), "中")
        self.assertEqual(feed.severity_cn("low"), "低")
        self.assertEqual(feed.severity_cn("none"), "无")
        self.assertEqual(feed.severity_cn("bogus"), "")
        self.assertEqual(feed.cvss_severity(9.8), "严重")
        self.assertEqual(feed.cvss_severity(7.0), "高")
        self.assertEqual(feed.cvss_severity(4.0), "中")
        self.assertEqual(feed.cvss_severity(0.1), "低")
        self.assertEqual(feed.cvss_severity(0), "无")

    def test_match_perf_and_candidate_budget(self):
        facts = [
            {"asset_id": f"ast-{index}", "comp_norm": "grafana", "version": "8.2.6",
             "cpe": "cpe:/a:grafana:grafana:8.2.6", "source": "nmap"}
            for index in range(50)
        ]
        started = time.perf_counter()
        result = self._match(facts)
        elapsed = time.perf_counter() - started
        self.assertEqual(len(result["matched"]), 50)
        self.assertLess(result["stats"]["candidates"], 5000)  # 单资产候选行目标 < 5000
        self.assertLess(elapsed, 10.0)  # 量级验证（不硬性 2 s，CI 机器可能很慢）


# ---------------------------------------------------------------------------
# 与 Lead 的 scan/store.py 集成
# ---------------------------------------------------------------------------
class ScanStoreCompatTest(_StoreCase):
    """Lead 的 DDL 建表后，本包的导入/匹配/统计必须全部可用（表结构对齐检查）。"""

    def test_init_schema_and_run(self):
        from hornwork.scan import store as scan_store

        scan_store.init_schema(self.db)
        feed.init_schema(self.db)  # 幂等；DDL 委托 scan.store
        tables = {
            row["name"]
            for row in self.db.query("SELECT name FROM sqlite_master WHERE type='table'")
        }
        for table in (
            "cve_cache", "cve_component_map", "scan_oval_fix", "scan_cve_exclude",
            "scan_finding", "asset", "scan_task",
        ):
            self.assertIn(table, tables)

        import_result = feed.import_nvd(self.db, str(NVD_FIXTURE))
        self.assertEqual(import_result["cves"], 5)
        self.assertEqual(scan_store.cve_count(self.db), 5)
        oval_result = feed.import_oval(self.db, str(OVAL_FIXTURE))
        self.assertEqual(oval_result["release"], "noble")

        cfg = _cfg()
        cmap.seed_from_dir(self.db, cfg)
        result = matcher.match_facts(
            self.db,
            cfg,
            [{"asset_id": "ast-1", "comp_norm": "grafana", "version": "8.2.6",
              "cpe": "cpe:/a:grafana:grafana:8.2.6", "source": "nmap"}],
        )
        self.assertEqual(len(result["matched"]), 1)

        # 与 Lead 的归一化层对接：匹配结果可直接转成 kind='cve' 的 RawResult
        from hornwork.scan import normalize

        raw_results = normalize.cve_to_findings(
            result["matched"], asset_id="ast-1", task_id="tsk-test"
        )
        self.assertEqual(len(raw_results), 1)
        self.assertEqual(raw_results[0]["kind"], "cve")
        self.assertEqual(raw_results[0]["check_id"], "CVE-2021-43798")
        self.assertEqual(raw_results[0]["confidence"], "range")


if __name__ == "__main__":
    unittest.main(verbosity=2)
