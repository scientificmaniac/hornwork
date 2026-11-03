"""漏洞档案层单元测试：档案校验、CVSS 一致性、IF-18 匹配、入库幂等、报告渲染。

产物统一写 ``tests/_tmp/vuln-<uuid>/``（DSH 沙箱下系统临时目录不可写），tearDown 清理。
"""

from __future__ import annotations

import copy
import hashlib
import shutil
import sys
import unittest
import uuid
from pathlib import Path

# 说明：测试产物放工作区 tests/_tmp，禁止用 tempfile（沙箱限制）
_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork.config import load_config  # noqa: E402
from hornwork.store import Store  # noqa: E402
from hornwork.vuln import cvss, match, model, report  # noqa: E402
from hornwork.vuln import store as vuln_store  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RECORDS_DIR = PROJECT_ROOT / "data" / "records"

#: 任务下发的权威事实（NVD API 2.0，2026-10-26 抓取），测试锁死防止被改写
EXPECTED_FACTS = {
    "VULN-2026-0001": {
        "cve": "CVE-2021-43798",
        "score": 7.5,
        "severity": "高",
        "cwe_prefix": "CWE-22",
        "lab_path": "grafana/CVE-2021-43798",
        "ports": [3000],
        "technique": "T1190",
    },
    "VULN-2026-0002": {
        "cve": "CVE-2022-22947",
        "score": 10.0,
        "severity": "严重",
        "cwe_prefix": "CWE-94",
        "lab_path": "spring/CVE-2022-22947",
        "ports": [8080, 5005],
        "technique": "T1190",
    },
    "VULN-2026-0003": {
        "cve": "CVE-2022-0543",
        "score": 10.0,
        "severity": "严重",
        "cwe_prefix": "CWE-862",
        "lab_path": "redis/CVE-2022-0543",
        "ports": [6379],
        "technique": "T1190",
    },
}


def _mktemp(prefix: str) -> Path:
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = _TMP_ROOT / f"{prefix}-{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_records() -> dict[str, dict]:
    return {record["id"]: record for record in model.load_records(str(RECORDS_DIR))}


def _load_one(vuln_id: str = "VULN-2026-0001") -> dict:
    return copy.deepcopy(_load_records()[vuln_id])


class RecordFileTest(unittest.TestCase):
    """3 份 YAML 的事实、结构与 CVSS 一致性。"""

    @classmethod
    def setUpClass(cls):
        cls.records = _load_records()

    def test_three_records_present(self):
        self.assertEqual(
            sorted(self.records),
            ["VULN-2026-0001", "VULN-2026-0002", "VULN-2026-0003"],
        )

    def test_validate_all_pass(self):
        for vuln_id, record in self.records.items():
            with self.subTest(vuln_id=vuln_id):
                self.assertEqual(model.validate_record(record), [])

    def test_required_fields_count_and_status(self):
        self.assertEqual(len(model.REQUIRED_FIELDS), 18)
        for vuln_id, record in self.records.items():
            with self.subTest(vuln_id=vuln_id):
                for field in model.REQUIRED_FIELDS:
                    self.assertIn(field, record)
                # 档案可从 draft 推进到 verified（复现后回填证据），两种状态都必须自洽
                self.assertIn(record["status"], ("draft", "verified"))
                if record["status"] == "verified":
                    self.assertTrue(record["evidence"], "verified 档案必须有证据")
                else:
                    self.assertEqual(record["evidence"], [])
                self.assertEqual(record["owner"], "靶场模块")
                self.assertTrue(str(record["created_at"]).startswith("2026-10-26T13:00:00"))

    def test_cvss_score_matches_calculator(self):
        for vuln_id, record in self.records.items():
            with self.subTest(vuln_id=vuln_id):
                computed = cvss.calculate(record["cvss_vector"])
                self.assertAlmostEqual(float(record["cvss_score"]), computed, places=9)
                self.assertEqual(record["severity"], model.severity_of(computed))

    def test_authoritative_facts_not_rewritten(self):
        for vuln_id, expected in EXPECTED_FACTS.items():
            record = self.records[vuln_id]
            with self.subTest(vuln_id=vuln_id):
                self.assertEqual(record["cve"], expected["cve"])
                self.assertAlmostEqual(float(record["cvss_score"]), expected["score"], places=9)
                self.assertEqual(record["severity"], expected["severity"])
                self.assertTrue(record["cwe"].startswith(expected["cwe_prefix"]))
                self.assertEqual(record["lab"]["path"], expected["lab_path"])
                self.assertEqual(record["lab"]["ports"], expected["ports"])
                self.assertEqual(record["lab"]["kind"], "server")
                self.assertEqual(record["attack_technique"], expected["technique"])
                self.assertGreaterEqual(len(record["references"]), 2)
                self.assertTrue(record["fix"]["patch_version"])

    def test_load_save_roundtrip(self):
        tmp = _mktemp("vuln-record")
        try:
            target = tmp / "record.yaml"
            original = _load_one("VULN-2026-0002")
            model.save_record(str(target), original)
            reloaded = model.load_record(str(target))
            for field in model.REQUIRED_FIELDS:
                self.assertEqual(reloaded.get(field), original.get(field))
            self.assertEqual(reloaded["affected_versions"], original["affected_versions"])
            self.assertEqual(reloaded["created_at"], original["created_at"])
            self.assertEqual(reloaded["cvss_score"], 10.0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_save_record_fills_timestamps(self):
        tmp = _mktemp("vuln-record-ts")
        try:
            record = _load_one("VULN-2026-0001")
            record.pop("created_at")
            record.pop("updated_at")
            target = tmp / "record.yaml"
            model.save_record(str(target), record)
            reloaded = model.load_record(str(target))
            self.assertTrue(reloaded["created_at"].endswith("Z"))
            self.assertTrue(reloaded["updated_at"].endswith("Z"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_load_records_skips_broken_yaml(self):
        tmp = _mktemp("vuln-broken")
        try:
            shutil.copy(RECORDS_DIR / "VULN-2026-0001.yaml", tmp / "ok.yaml")
            (tmp / "broken.yaml").write_text("id: [unclosed\n", encoding="utf-8")
            loaded = model.load_records(str(tmp))
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["id"], "VULN-2026-0001")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ValidateRejectTest(unittest.TestCase):
    """校验器必须拒绝缺字段/引用不足/分数与向量矛盾等不合格档案。"""

    def test_missing_required_field(self):
        record = _load_one()
        record.pop("title")
        errors = model.validate_record(record)
        self.assertTrue(any("title" in error for error in errors), errors)

    def test_empty_required_text(self):
        record = _load_one()
        record["component"] = "   "
        errors = model.validate_record(record)
        self.assertTrue(any("component" in error for error in errors), errors)

    def test_references_insufficient(self):
        record = _load_one()
        record["references"] = record["references"][:1]
        errors = model.validate_record(record)
        self.assertTrue(any("references" in error for error in errors), errors)

    def test_cvss_score_mismatch(self):
        record = _load_one("VULN-2026-0001")
        record["cvss_score"] = 9.8
        errors = model.validate_record(record)
        self.assertTrue(any("cvss_score" in error for error in errors), errors)

    def test_severity_mismatch(self):
        record = _load_one("VULN-2026-0001")
        record["severity"] = "严重"
        errors = model.validate_record(record)
        self.assertTrue(any("severity" in error for error in errors), errors)

    def test_bad_vector(self):
        record = _load_one()
        record["cvss_vector"] = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        errors = model.validate_record(record)
        self.assertTrue(any("cvss_vector" in error for error in errors), errors)

    def test_verified_requires_evidence(self):
        record = _load_one()
        record["status"] = "verified"
        record["evidence"] = []  # 复现回填后档案在磁盘上可能已有证据，这里显式清空再验证规则
        errors = model.validate_record(record)
        self.assertTrue(any("evidence" in error for error in errors), errors)

    def test_evidence_sha256_format(self):
        record = _load_one()
        record["evidence"] = [{"path": "x.txt", "sha256": "abc", "ts": "2026-10-26T13:00:00Z"}]
        errors = model.validate_record(record)
        self.assertTrue(any("sha256" in error for error in errors), errors)

    def test_bad_identity_and_lab(self):
        record = _load_one()
        record["id"] = "VULN-001"
        record["lab"] = {"kind": "docker", "path": "", "ports": []}
        record["attack_path"] = []
        errors = model.validate_record(record)
        joined = "; ".join(errors)
        self.assertIn("id", joined)
        self.assertIn("lab.kind", joined)
        self.assertIn("attack_path", joined)

    def test_missing_fields_listed(self):
        errors = model.validate_record({})
        for field in model.REQUIRED_FIELDS:
            self.assertTrue(any(field in error for error in errors), field)

    def test_non_dict(self):
        self.assertTrue(model.validate_record([]))  # type: ignore[arg-type]

    def test_min_references_parameter(self):
        record = _load_one()
        self.assertEqual(model.validate_record(record, min_references=3), [])


class StoreTest(unittest.TestCase):
    """vuln_record 建表、同步幂等、查询过滤。"""

    def setUp(self):
        self.tmp = _mktemp("vuln-store")
        self.db = Store(self.tmp / "hornwork.db")
        self.cfg = load_config(None)
        self.cfg["vuln"]["records_dir"] = str(RECORDS_DIR)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_seed_idempotent(self):
        first = vuln_store.seed_from_dir(self.db, self.cfg)
        self.assertEqual(first["upserted"], 3)
        self.assertEqual(first["rejected"], 0)
        second = vuln_store.seed_from_dir(self.db, self.cfg)
        self.assertEqual(second["upserted"], 3)
        self.assertEqual(second["rejected"], 0)
        self.assertEqual(vuln_store.count_records(self.db), 3)

    def test_sync_records_rejects_bad_keeps_good(self):
        good = _load_one("VULN-2026-0001")
        bad = _load_one("VULN-2026-0002")
        bad["references"] = []
        result = vuln_store.sync_records(self.db, [good, bad])
        self.assertEqual(result["upserted"], 1)
        self.assertEqual(result["rejected"], 1)
        self.assertTrue(result["errors"])
        self.assertIsNotNone(vuln_store.get_record(self.db, "VULN-2026-0001"))
        self.assertIsNone(vuln_store.get_record(self.db, "VULN-2026-0002"))

    def test_sync_from_memory_record(self):
        record = _load_one("VULN-2026-0003")
        result = vuln_store.sync_records(self.db, [record])
        self.assertEqual(result["upserted"], 1)
        stored = vuln_store.get_record(self.db, "VULN-2026-0003")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["cve"], "CVE-2022-0543")
        self.assertEqual(len(stored["affected_versions"]), 1)

    def test_list_filters_and_order(self):
        vuln_store.seed_from_dir(self.db, self.cfg)
        self.assertEqual(len(vuln_store.list_records(self.db)), 3)
        self.assertEqual(len(vuln_store.list_records(self.db, severity="严重")), 2)
        self.assertEqual(len(vuln_store.list_records(self.db, cwe="CWE-22")), 1)
        # 档案可能处于 draft 或 verified（测试主机复现后会推进状态），过滤结果须自洽
        draft = vuln_store.list_records(self.db, status="draft")
        verified = vuln_store.list_records(self.db, status="verified")
        self.assertEqual(len(draft) + len(verified), 3)
        self.assertTrue(all(r["status"] == "draft" for r in draft))
        self.assertTrue(all(r["status"] == "verified" for r in verified))
        scores = [record["cvss_score"] for record in vuln_store.list_records(self.db)]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(len(vuln_store.list_records(self.db, limit=1)), 1)

    def test_get_missing(self):
        self.assertIsNone(vuln_store.get_record(self.db, "VULN-1999-9999"))

    def test_seed_with_missing_dir(self):
        self.cfg["vuln"]["records_dir"] = str(self.tmp / "no-such-dir")
        result = vuln_store.seed_from_dir(self.db, self.cfg)
        # 配置目录不存在时回退仓库内置 data/records（保证开发机/演示可用）
        self.assertEqual(result["upserted"], 3)
        self.assertEqual(result["dir"], str(RECORDS_DIR))


class MatchTest(unittest.TestCase):
    """IF-18：组件+版本 → 档案，命中/未命中/未知组件/CPE 兜底。"""

    def setUp(self):
        self.tmp = _mktemp("vuln-match")
        self.db = Store(self.tmp / "hornwork.db")
        self.cfg = load_config(None)
        self.cfg["vuln"]["records_dir"] = str(RECORDS_DIR)
        vuln_store.seed_from_dir(self.db, self.cfg)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _match(self, component=None, version=None, **extra):
        request = {}
        if component is not None:
            request["component"] = component
        if version is not None:
            request["version"] = version
        request.update(extra)
        return match.match(self.db, self.cfg, request)

    def test_grafana_hit_and_miss(self):
        hit = self._match("grafana", "8.2.6")
        self.assertEqual([item["cve"] for item in hit["matched"]], ["CVE-2021-43798"])
        entry = hit["matched"][0]
        self.assertTrue(entry["matched"])
        self.assertEqual(entry["confidence"], "range")
        self.assertEqual(entry["fixed_version"], "8.2.7")
        self.assertEqual(entry["severity"], "高")
        self.assertAlmostEqual(entry["cvss_score"], 7.5)
        self.assertEqual(entry["matched_rule"]["introduced"], "8.2.0")
        miss = self._match("grafana", "8.2.7")
        self.assertEqual(miss["matched"], [])
        self.assertEqual([item["vuln_id"] for item in miss["unknown"]], ["VULN-2026-0001"])

    def test_grafana_full_component_name(self):
        result = self._match("Grafana 8.2.6", "8.2.6")
        self.assertEqual([item["vuln_id"] for item in result["matched"]], ["VULN-2026-0001"])

    def test_spring_hit_and_miss(self):
        hit = self._match("spring-cloud-gateway", "3.1.0")
        self.assertEqual([item["cve"] for item in hit["matched"]], ["CVE-2022-22947"])
        self.assertEqual(hit["matched"][0]["confidence"], "range")
        miss = self._match("Spring Cloud Gateway", "3.1.1")
        self.assertEqual(miss["matched"], [])
        self.assertEqual(miss["unknown"][0]["reason"], "at_or_above_fixed")

    def test_redis_hit_and_miss(self):
        hit = self._match("redis", "5.0.7", distro="ubuntu-20.04")
        self.assertEqual([item["cve"] for item in hit["matched"]], ["CVE-2022-0543"])
        self.assertEqual(hit["matched"][0]["severity"], "严重")
        miss = self._match("Redis（Debian/Ubuntu 打包版）", "6.0.16")
        self.assertEqual(miss["matched"], [])
        self.assertEqual([item["vuln_id"] for item in miss["unknown"]], ["VULN-2026-0003"])

    def test_unknown_component_goes_to_unknown(self):
        result = self._match("nginx", "1.24.0")
        self.assertEqual(result["matched"], [])
        self.assertEqual(len(result["unknown"]), 1)
        self.assertEqual(result["unknown"][0]["reason"], "component_not_matched")

    def test_bad_request_does_not_raise(self):
        result = match.match(self.db, self.cfg, {})
        self.assertEqual(result["matched"], [])
        self.assertEqual(result["unknown"][0]["reason"], "bad_request")
        self.assertIsInstance(result["elapsed_ms"], int)

    def test_cpe_only_request(self):
        result = match.match(
            self.db,
            self.cfg,
            {"cpe": "cpe:2.3:a:grafana:grafana:8.2.6:*:*:*:*:*:*:*"},
        )
        self.assertEqual([item["cve"] for item in result["matched"]], ["CVE-2021-43798"])

    def test_missing_version(self):
        result = self._match("grafana")
        self.assertEqual(result["matched"], [])
        self.assertEqual(result["unknown"][0]["reason"], "version_missing")

    def test_match_many_isolated(self):
        results = match.match_many(
            self.db,
            self.cfg,
            [{"component": "grafana", "version": "8.2.6"}, {}, {"component": "nginx", "version": "1.0"}],
        )
        self.assertEqual(len(results), 3)
        self.assertEqual(len(results[0]["matched"]), 1)
        self.assertEqual(results[1]["unknown"][0]["reason"], "bad_request")


class ReportTest(unittest.TestCase):
    """IF-19：漏洞卡/整改单渲染与导出（路径 + sha256 + 条数）。"""

    def setUp(self):
        self.tmp = _mktemp("vuln-report")
        self.db = Store(self.tmp / "hornwork.db")
        self.cfg = load_config(None)
        self.cfg["vuln"]["records_dir"] = str(RECORDS_DIR)
        vuln_store.seed_from_dir(self.db, self.cfg)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_render_card(self):
        record = vuln_store.get_record(self.db, "VULN-2026-0001")
        # 该用例验证"无证据时的回填提示"；测试主机上档案可能已 verified，这里显式清空
        record = dict(record or {})
        record["evidence"] = []
        record["status"] = "draft"
        card = report.render_card(record)
        self.assertTrue(card.strip())
        for expected in ("VULN-2026-0001", "CVE-2021-43798", "CWE-22", "高", "7.5", "curl"):
            self.assertIn(expected, card)
        # 证据为空时给出回填提示，而不是空章节
        self.assertIn("待回填", card)

    def test_render_card_with_evidence(self):
        record = _load_one("VULN-2026-0002")
        record["evidence"] = [
            {"path": "data/evidence/VULN-2026-0002/run-01/resp.txt", "sha256": "a" * 64, "ts": "2026-10-26T13:10:00Z"}
        ]
        card = report.render_card(record)
        self.assertIn("a" * 64, card)
        self.assertIn("run-01/resp.txt", card)

    def test_render_rectification(self):
        records = vuln_store.list_records(self.db)
        text = report.render_rectification(records)
        self.assertTrue(text.strip())
        for header in ("CVE", "组件", "类型", "等级", "修复", "验证方式"):
            self.assertIn(header, text)
        for record in records:
            self.assertIn(record["cve"], text)
        self.assertEqual(text.count("CVE-"), 3)
        self.assertIn("漏洞整改单", text)

    def test_render_rectification_empty(self):
        text = report.render_rectification([])
        self.assertIn("漏洞整改单", text)
        self.assertIn("无记录", text)

    def test_export_md_and_sha256(self):
        out = self.tmp / "report.md"
        result = report.export_report(self.db, self.cfg, fmt="md", out=str(out))
        self.assertEqual(result["count"], 3)
        self.assertEqual(Path(result["path"]), out)
        data = out.read_bytes()
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["sha256"], hashlib.sha256(out.read_bytes()).hexdigest())

    def test_export_json_and_csv(self):
        json_out = self.tmp / "report.json"
        result = report.export_report(
            self.db, self.cfg, ids=["VULN-2026-0001"], fmt="json", out=str(json_out)
        )
        self.assertEqual(result["count"], 1)
        self.assertIn("CVE-2021-43798", json_out.read_text(encoding="utf-8"))
        csv_out = self.tmp / "report.csv"
        csv_result = report.export_report(self.db, self.cfg, fmt="csv", out=str(csv_out))
        self.assertEqual(csv_result["count"], 3)
        self.assertIn("CVE-2022-22947", csv_out.read_text(encoding="utf-8"))

    def test_export_unknown_format_falls_back_to_md(self):
        out = self.tmp / "report.txt"
        result = report.export_report(self.db, self.cfg, fmt="docx", out=str(out))
        self.assertEqual(result["count"], 3)
        self.assertIn("漏洞整改单", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
