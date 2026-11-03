"""核心层单元测试：config / schema / store / bus（不依赖 Linux 与第三方库）。"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path

# 说明：DSH 沙箱下系统临时目录不可写，统一把测试产物放到工作区 tests/_tmp
_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"


def _mktemp(prefix: str) -> Path:
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = _TMP_ROOT / f"{prefix}-{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork import schema  # noqa: E402
from hornwork.bus import Bus, topic_match  # noqa: E402
from hornwork.config import DEFAULTS, cfg_get, deep_merge, load_config  # noqa: E402
from hornwork.store import Store, parse_since  # noqa: E402


class ConfigTest(unittest.TestCase):
    def test_defaults_and_get(self):
        cfg = load_config(None)
        self.assertEqual(cfg_get(cfg, "general.data_dir"), "/var/lib/hornwork")
        self.assertEqual(cfg_get(cfg, "engines.clamav.timeout_sec"), 30)
        self.assertIsNone(cfg_get(cfg, "no.such.key"))
        self.assertEqual(cfg_get(cfg, "no.such.key", 7), 7)
        self.assertTrue(cfg["general"]["hostname"])

    def test_deep_merge_does_not_mutate(self):
        base = {"a": {"b": 1, "c": 2}}
        merged = deep_merge(base, {"a": {"b": 9}})
        self.assertEqual(merged["a"]["b"], 9)
        self.assertEqual(merged["a"]["c"], 2)
        self.assertEqual(base["a"]["b"], 1)

    def test_load_file(self):
        tmp = _mktemp("config")
        try:
            path = tmp / "config.toml"
            path.write_text('[general]\nhost_id = "test-host"\ndata_dir = "/tmp/x"\n', encoding="utf-8")
            cfg = load_config(path)
            self.assertEqual(cfg["general"]["host_id"], "test-host")
            self.assertEqual(cfg["general"]["data_dir"], "/tmp/x")
            self.assertEqual(cfg["scan"]["workers"], DEFAULTS["scan"]["workers"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class SchemaTest(unittest.TestCase):
    def setUp(self):
        schema.reset_host_cache()

    def test_new_event_and_validate(self):
        ev = schema.new_event(
            "process_create", "host", "hornwork-auditd",
            process={"pid": 1, "image": "/bin/sh", "cmdline": "sh -c id"},
        )
        self.assertEqual(ev["schema_version"], "1.0")
        self.assertEqual(schema.validate_event(ev), [])
        self.assertRegex(ev["ts"], r"^\d{4}-\d{2}-\d{2}T.*Z$")
        self.assertTrue(ev["host"]["host_id"])

    def test_bad_event_type(self):
        with self.assertRaises(ValueError):
            schema.new_event("not_a_type", "host", "x")

    def test_validate_rejects_unknown_major(self):
        ev = schema.new_event("file_create", "host", "fim")
        ev["schema_version"] = "9.0"
        self.assertTrue(schema.validate_event(ev))

    def test_normalize_event(self):
        ev = schema.normalize_event({"event_type": "file_create", "file": {"path": "/tmp/a"}})
        self.assertEqual(schema.validate_event(ev), [])
        with self.assertRaises(ValueError):
            schema.normalize_event({"event_type": "bogus"})

    def test_dedup_key(self):
        a = schema.dedup_key("R1", "host1", "1.2.3.4", 80)
        b = schema.dedup_key("R1", "host1", "1.2.3.4", 80)
        c = schema.dedup_key("R1", "host1", "1.2.3.5", 80)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 32)

    def test_new_alert_structure(self):
        ev = schema.new_event(
            "process_create", "host", "hornwork-auditd",
            process={"pid": 10, "image": "/usr/bin/wget", "cmdline": "wget http://x"},
            network={"dst_ip": "203.0.113.9", "dst_port": 80, "proto": "tcp"},
        )
        rule = schema.make_rule("H-0001", "可疑下载", "hostrules", level=8, mitre=["T1105"])
        alert = schema.new_alert(rule, event=ev, evidence=[{"path": "/tmp/a"}])
        self.assertEqual(schema.validate_alert(alert), [])
        self.assertEqual(alert["entity"]["host_id"], ev["host"]["host_id"])
        self.assertEqual(alert["entity"]["dst_ip"], "203.0.113.9")
        self.assertEqual(alert["technique"], "T1105")
        self.assertEqual(alert["level"], 8)
        json.dumps(alert, ensure_ascii=False)

    def test_severity_label(self):
        self.assertEqual(schema.severity_label(13), "critical")
        self.assertEqual(schema.severity_label(9), "high")
        self.assertEqual(schema.severity_label(6), "medium")
        self.assertEqual(schema.severity_label(1), "info")


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = _mktemp("store")
        self.store = Store(self.tmp_dir / "t.db")
        schema.reset_host_cache()
        self.ev = schema.new_event(
            "process_create", "host", "test",
            process={"pid": 42, "image": "/usr/bin/curl", "cmdline": "curl x"},
        )

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_event_roundtrip_and_dedup(self):
        self.assertTrue(self.store.insert_event(self.ev))
        self.assertFalse(self.store.insert_event(self.ev))
        rows = self.store.query_events(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_type"], "process_create")
        self.assertEqual(self.store.count_events(), 1)

    def test_alert_dedup_same_minute(self):
        rule = schema.make_rule("R1", "r", "e", level=5)
        a1 = schema.new_alert(rule, event=self.ev)
        a2 = schema.new_alert(rule, event=self.ev)
        a2["dedup_key"] = a1["dedup_key"]
        a2["ts"] = a1["ts"]
        self.assertTrue(self.store.insert_alert(a1))
        self.assertFalse(self.store.insert_alert(a2))
        self.assertEqual(self.store.count_alerts(), 1)
        alerts = self.store.query_alerts(limit=10)
        self.assertEqual(alerts[0]["rule"]["id"], "R1")

    def test_alerts_in_window(self):
        import datetime

        rule = schema.make_rule("R2", "r2", "e", level=9, mitre=["T1046"])
        now = schema.utc_now()
        alert = schema.new_alert(rule, ts=now)
        self.store.insert_alert(alert)
        t0 = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=60)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
        rows = self.store.alerts_in_window(t0, rule_ids=["R2"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["technique"], "T1046")

    def test_scan_result_and_hash_cache(self):
        rec = {
            "ts": schema.utc_now(), "path": "/tmp/eicar.com", "sha256": "a" * 64,
            "size": 68, "verdict": "malicious", "score": 100,
            "hits": [{"engine": "sigdb", "rule_id": "eicar", "name": "EICAR", "score": 100}],
            "first_hit": "sigdb", "cost_ms": 12,
        }
        self.assertGreater(self.store.insert_scan_result(rec), 0)
        self.assertEqual(self.store.scan_by_sha("a" * 64)["verdict"], "malicious")
        self.store.set_hash_cache("a" * 64, "malicious")
        self.assertEqual(self.store.get_hash_cache("a" * 64), "malicious")
        self.assertEqual(self.store.recent_scans(limit=5)[0]["verdict"], "malicious")

    def test_case_and_metadata(self):
        self.store.insert_case({
            "case_id": "c1", "title": "t", "severity": "P2",
            "created_at": schema.utc_now(),
        })
        self.assertTrue(self.store.update_case("c1", status="closed", verdict="tp"))
        case = self.store.get_case("c1")
        self.assertEqual(case["status"], "closed")
        self.store.set_meta("k", "v")
        self.assertEqual(self.store.get_meta("k"), "v")
        self.assertEqual(self.store.get_meta("missing", "d"), "d")

    def test_ioc_and_validation(self):
        self.store.ioc_upsert({"type": "domain", "value": "ioc.example", "confidence": 80})
        self.assertIn("ioc.example", self.store.ioc_values("domain"))
        self.store.insert_validation({
            "run_id": "r1", "case_id": "c1", "technique": "T1105",
            "expected": "alert_present", "observed": "alert", "verdict": "TP",
            "mttd_sec": 3, "payload": {"x": 1},
        })
        rows = self.store.validation_rows("r1")
        self.assertEqual(rows[0]["verdict"], "TP")
        self.assertEqual(rows[0]["payload"], {"x": 1})
        self.assertEqual(self.store.latest_run_id(), "r1")

    def test_counts_and_prune(self):
        self.store.insert_event(self.ev)
        counts = self.store.counts()
        self.assertEqual(counts["events_total"], 1)
        self.store.prune(days=0, scan_days=0)
        self.assertEqual(self.store.counts()["events_total"], 0)

    def test_parse_since(self):
        self.assertTrue(parse_since("5m").endswith("Z"))
        self.assertTrue(parse_since(None).endswith("Z"))
        iso = "2026-10-26T10:00:00.000Z"
        self.assertEqual(parse_since(iso), iso)


class BusTest(unittest.TestCase):
    def test_topic_match(self):
        self.assertTrue(topic_match("events.*", "events.host"))
        self.assertTrue(topic_match("events.*", "events"))
        self.assertTrue(topic_match("alerts.raw", "alerts.raw"))
        self.assertFalse(topic_match("events.*", "alerts.raw"))
        self.assertTrue(topic_match("*", "anything"))

    def test_async_publish_consume(self):
        async def scenario():
            bus = Bus(maxsize=10)
            received: list = []
            bus.bind_loop(asyncio.get_running_loop())

            async def handler(item):
                received.append(item)

            bus.attach("events.*", handler, "test")
            bus.publish("events.host", {"n": 1})
            bus.publish("alerts.raw", {"n": 2})
            for _ in range(50):
                if received:
                    break
                await asyncio.sleep(0.01)
            await bus.stop()
            return received

        got = asyncio.run(scenario())
        self.assertEqual(got, [{"n": 1}])


if __name__ == "__main__":
    unittest.main(verbosity=2)
