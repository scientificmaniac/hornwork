"""加固模块单元测试（不依赖 root；需要 root 的系统动作通过 items.yaml 由执行器负责）。

运行：/opt/hornwork-venv/bin/python -m unittest tests.test_harden -v
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from hornwork.harden import core, crypto, executor, items as items_mod, plan as plan_mod, report as report_mod


class HardenTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp(prefix="harden-test-")
        os.environ["HORNWORK_HARDEN_DIR"] = str(Path(cls.tmp) / "state")
        os.environ["HORNWORK_HARDEN_KEY_DIR"] = str(Path(cls.tmp) / "keys")
        os.environ["HORNWORK_HARDEN_TLS_DIR"] = str(Path(cls.tmp) / "tls")

    @classmethod
    def tearDownClass(cls) -> None:
        os.environ.pop("HORNWORK_HARDEN_DIR", None)
        os.environ.pop("HORNWORK_HARDEN_KEY_DIR", None)
        os.environ.pop("HORNWORK_HARDEN_TLS_DIR", None)
        shutil.rmtree(cls.tmp, ignore_errors=True)


class ItemsTest(HardenTestBase):
    def test_load_and_validate(self) -> None:
        items = items_mod.load_items()
        self.assertGreaterEqual(len(items), 18)
        ids = [item.id for item in items]
        self.assertEqual(len(ids), len(set(ids)))
        for item in items:
            self.assertTrue(item.id.startswith("H-"))
            self.assertIn(item.risk, {"low", "mid", "high"})
            self.assertTrue(item.check and item.apply and item.verify)
            self.assertTrue(item.refs, f"{item.id} 缺标准依据")
            self.assertIn("A", item.scope)

    def test_batch_and_ordering(self) -> None:
        items = {item.id: item for item in items_mod.load_items()}
        self.assertEqual(items["H-AL-02"].batch, 1)
        self.assertEqual(items["H-SV-04"].batch, 3)
        self.assertEqual(items["H-CR-01"].batch, 4)
        self.assertEqual(items["H-TL-01"].batch, 5)
        self.assertLess(items["H-SV-04"].order, items["H-SV-02"].order, "防火墙必须先于 SSH")

    def test_scope_reasons(self) -> None:
        items = {item.id: item for item in items_mod.load_items()}
        self.assertTrue(items["H-SV-02"].applicable("A"))
        self.assertFalse(items["H-SV-02"].applicable("B"))
        self.assertIn("复现", items["H-SV-02"].scope_reason("B"))


class PlanTest(HardenTestBase):
    def test_role_a_and_b_plan(self) -> None:
        items = items_mod.load_items()
        plan_a = plan_mod.build_plan(items, role="A", asset="A")
        plan_b = plan_mod.build_plan(items, role="B", asset="B")
        self.assertGreater(plan_a["counts"]["applicable"], plan_b["counts"]["applicable"])
        self.assertGreaterEqual(plan_a["counts"]["excluded"], 0)
        b_ids = {entry["id"] for entry in plan_b["excluded"]}
        self.assertIn("H-SV-02", b_ids)
        # 靶场主机排除项必须带理由
        for entry in plan_b["excluded"]:
            self.assertTrue(entry["reason"])
        # 计划是编译产物：执行器只认 items 里的项
        for entry in plan_a["items"]:
            self.assertIn(entry["id"], {item.id for item in items})

    def test_plan_integrity(self) -> None:
        plan = plan_mod.build_plan(role="A")
        ok, _msg = plan_mod.verify_plan_integrity(plan)
        self.assertTrue(ok)
        plan["items"][0]["title"] = "被篡改"
        ok, msg = plan_mod.verify_plan_integrity(plan)
        self.assertFalse(ok)
        self.assertIn("哈希不匹配", msg)

    def test_plan_persistence(self) -> None:
        plan = plan_mod.build_plan(role="A")
        path = plan_mod.save_plan(plan)
        self.assertTrue(path.is_file())
        loaded = plan_mod.load_plan(plan["plan_id"])
        self.assertEqual(loaded["plan_sha256"], plan["plan_sha256"])


class BackupTest(HardenTestBase):
    def test_backup_restore_roundtrip(self) -> None:
        root = core.state()["backups"]
        target = Path(self.tmp) / "conf.txt"
        target.write_text("original\n", encoding="utf-8")
        record = core.backup_paths([str(target)], "run-test-0001", "H-TEST-01", root)
        target.write_text("hacked\n", encoding="utf-8")
        restored = core.restore_backup(record)
        self.assertEqual(restored[0]["restored"], "sha256_ok")
        self.assertEqual(target.read_text(encoding="utf-8"), "original\n")

    def test_backup_new_file_removed_on_restore(self) -> None:
        root = core.state()["backups"]
        target = Path(self.tmp) / "new-file.txt"
        record = core.backup_paths([str(target)], "run-test-0002", "H-TEST-02", root)
        target.write_text("created by apply\n", encoding="utf-8")
        core.restore_backup(record)
        self.assertFalse(target.exists())


class PwhashTest(HardenTestBase):
    def setUp(self) -> None:
        path = crypto.demo_db_path()
        if path.exists():
            path.unlink()

    def test_legacy_verify(self) -> None:
        import hashlib

        crypto.seed_demo_users()
        status = crypto.pwhash_status()
        self.assertEqual(status["legacy_hashes_remaining"], 3)
        md5_digest = hashlib.md5(crypto.DEMO_PASSWORDS["alice"].encode()).hexdigest()
        self.assertTrue(crypto.legacy_verify(crypto.DEMO_PASSWORDS["alice"], md5_digest))
        self.assertFalse(crypto.legacy_verify("wrong", md5_digest))

    def test_migrate_to_argon2id(self) -> None:
        crypto.seed_demo_users()
        result = crypto.pwhash_migrate()
        self.assertEqual(result["status"]["legacy_hashes_remaining"], 0)
        self.assertEqual(result["status"]["argon2id_users"], 3)
        for entry in result["migrated"]:
            self.assertTrue(entry.get("verify_ok"), entry)
            self.assertTrue(entry["new_prefix"].startswith("$argon2id$"))
        # 条件 UPDATE 天然幂等：再迁移一次不会产生新变更
        again = crypto.pwhash_migrate()
        self.assertEqual(again["migrated"], [])

    def test_check_passes_after_migration(self) -> None:
        crypto.seed_demo_users()
        self.assertFalse(crypto.pwhash_check()[0])
        crypto.pwhash_migrate()
        self.assertTrue(crypto.pwhash_check()[0])


class CryptoTest(HardenTestBase):
    def setUp(self) -> None:
        if not shutil.which("openssl"):
            self.skipTest("本机无 openssl")

    def test_ed25519_sign_and_tamper(self) -> None:
        result = crypto.sign_ensure()
        self.assertTrue(result["signed"])
        self.assertTrue(crypto.sign_check()[0])
        tamper = crypto.tamper_test()
        self.assertTrue(tamper["before_tamper_verify"])
        self.assertFalse(tamper["after_tamper_verify"])

    def test_cert_info_parse(self) -> None:
        work = Path(self.tmp) / "cert"
        work.mkdir(exist_ok=True)
        key, crt = work / "k.pem", work / "c.pem"
        core.sh(
            f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout {key} "
            f"-days 30 -subj '/CN=test.local' -addext 'subjectAltName=DNS:test.local,IP:127.0.0.1' -out {crt}"
        )
        info = crypto.cert_info(crt)
        self.assertTrue(info["exists"])
        self.assertGreater(info["days_left"], 20)
        self.assertIn("test.local", info["subject"])
        self.assertIn("127.0.0.1", info["san"])


class ReportTest(HardenTestBase):
    def _fake_run(self) -> dict:
        return {
            "run_id": "run-fake-0001",
            "plan_id": "pln-fake-0001",
            "status": "succeeded",
            "operator": "root",
            "started_at": core.utc_now(),
            "finished_at": core.utc_now(),
            "results": [
                {"item_id": "H-AL-02", "title": "journald", "risk": "low", "status": "verified", "duration_ms": 12, "guard": None, "batch": 1},
                {"item_id": "H-SV-02", "title": "ssh", "risk": "high", "status": "already_ok", "duration_ms": 5, "guard": {"armed": True}, "batch": 3},
            ],
        }

    def test_report_markdown(self) -> None:
        plan = plan_mod.build_plan(role="A")
        run = self._fake_run()
        run["counts"] = executor.counts(run)
        run["completion_rate"] = executor.completion_rate(run)
        data = report_mod.build(plan, run)
        text = report_mod.to_markdown(data)
        self.assertIn("加固模块 加固运行报告", text)
        self.assertIn("加固项完成率", text)
        self.assertIn("H-SV-02", text)
        self.assertIn("靶场主机故意不加固", text)

    def test_completion_rate(self) -> None:
        run = self._fake_run()
        self.assertEqual(executor.completion_rate(run), 1.0)
        run["results"].append({"item_id": "H-X", "status": "failed"})
        self.assertLess(executor.completion_rate(run), 1.0)


if __name__ == "__main__":
    unittest.main()
