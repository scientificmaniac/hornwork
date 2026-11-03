"""情报层 + 响应层单元测试（Windows/Linux 均可跑，无第三方依赖）。

约定：**不使用 tempfile**（DSH 沙箱下系统临时目录不可写），所有测试产物写到
``tests/_tmp/<uuid>/``，tearDown 里 ``shutil.rmtree`` 清理。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path

THIS = Path(__file__).resolve()
ROOT = THIS.parents[1]          # 仓库根（含 hornwork/ 包）
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hornwork import schema                                    # noqa: E402
from hornwork.config import load_config                        # noqa: E402
from hornwork.intel import feeds, stix                         # noqa: E402
from hornwork.intel.intel2rule import build as intel2rule_build  # noqa: E402
from hornwork.intel.iocstore import IocStore                   # noqa: E402
from hornwork.respond.actions import ActionExecutor, verify_chain  # noqa: E402
from hornwork.respond.approve import ModeGuard                 # noqa: E402
from hornwork.respond.case import CaseManager                  # noqa: E402
from hornwork.respond.playbook import (                        # noqa: E402
    DEFAULT_PLAYBOOKS,
    PlaybookRunner,
    load_playbook,
    validate_playbook,
)
from hornwork.store import Store                               # noqa: E402

TMP_ROOT = THIS.parent / "_tmp"
PUBLIC_IP = "45.33.32.156"


def setUpModule() -> None:  # noqa: N802 - unittest 约定
    """屏蔽预期内的 warning 输出（过滤脏数据的告警），让测试输出干净。"""
    logging.disable(logging.WARNING)


def tearDownModule() -> None:  # noqa: N802 - unittest 约定
    logging.disable(logging.NOTSET)


def make_cfg(tmp: Path) -> dict:
    """基于默认配置生成本地化 cfg（规则/数据/隔离目录全在临时目录内）。"""
    cfg = load_config(None)
    cfg["general"]["rule_dir"] = str(tmp / "rules")
    cfg["general"]["data_dir"] = str(tmp / "data")
    cfg["general"]["raw_dir"] = str(tmp / "raw")
    cfg["engines"]["yara_rule_dir"] = str(tmp / "rules" / "yara")
    cfg["engines"]["net_rule_dir"] = str(tmp / "rules" / "net")
    cfg["engines"]["host_rule_dir"] = str(tmp / "rules" / "host")
    cfg["intel"]["bundle_dir"] = str(tmp / "rules" / "intel")
    cfg["intel"]["feed_dir"] = str(tmp / "rules" / "ioc")
    cfg["respond"]["quarantine_dir"] = str(tmp / "quarantine")
    cfg["respond"]["playbook_dir"] = str(tmp / "rules" / "playbooks")
    return cfg


class TempCase(unittest.TestCase):
    """为每个测试创建一个独立临时目录 + 干净的工作区。"""

    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = TMP_ROOT / f"t-{uuid.uuid4().hex[:10]}"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.cfg = make_cfg(self.tmp)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # 工具
    def store(self) -> Store:
        return Store(self.tmp / "hornwork.db")

    def write(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path


# ---------------------------------------------------------------------------
# 情报层：feeds
# ---------------------------------------------------------------------------
class TestFeeds(TempCase):
    def test_parse_jsonl_filters_and_normalizes(self) -> None:
        path = self.write(
            "feed.jsonl",
            "\n".join(
                [
                    '{"type":"ip","value":"8.8.8.8","confidence":90,"source":"t1","tlp":"TLP:WHITE"}',
                    '{"type":"ip","value":"192.168.1.10","confidence":90}',
                    '{"type":"domain","value":"Evil.Example.COM","confidence":"70","tlp":"red"}',
                    '{"type":"domain","value":"localhost"}',
                    '{"type":"hash","value":"' + "A" * 64 + '","confidence":95}',
                    '{"type":"url","value":"hxxp://bad[.]example[.]net/x","tlp":"green"}',
                    '{"value":"8.8.4.4"}',
                    '{"type":"domain","value":""}',
                    '{"type":"domain","value":"' + "a" * 300 + '.com"}',
                    "这不是 JSON",
                ]
            )
            + "\n",
        )
        records = feeds.load_feed(path)
        values = {(rec["type"], rec["value"]) for rec in records}
        self.assertEqual(len(records), 5, msg=f"实际={values}")
        self.assertIn(("ip", "8.8.8.8"), values)
        self.assertIn(("domain", "evil.example.com"), values)
        self.assertIn(("hash", "a" * 64), values)
        self.assertIn(("url", "http://bad.example.net/x"), values)
        self.assertIn(("ip", "8.8.4.4"), values)
        # 内网/回环被过滤
        self.assertNotIn(("ip", "192.168.1.10"), values)
        # TLP 归一
        ip_rec = next(r for r in records if r["value"] == "8.8.8.8")
        self.assertEqual(ip_rec["tlp"], "white")
        self.assertEqual(ip_rec["confidence"], 90)

    def test_parse_csv_urlhaus_mapping(self) -> None:
        path = self.write(
            "urlhaus.csv",
            "id,dateadded,url,url_status,threat,reporter\n"
            "1,2026-01-01,http://malware.example.com/payload.bin,online,malware,abuse\n"
            "2,2026-01-01,http://127.0.0.1/local,online,malware,abuse\n",
        )
        records = feeds.load_feed(path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["type"], "url")
        self.assertEqual(records[0]["value"], "http://malware.example.com/payload.bin")
        self.assertEqual(records[0]["source"], "abuse")

    def test_parse_csv_feodotracker_and_explicit_mapping(self) -> None:
        path = self.write(
            "feodo.csv",
            "first_seen,ip_address,port,last_online,malware,status\n"
            f"2026-01-01 00:00:00,{PUBLIC_IP},443,2026-01-02,emotet,online\n"
            "2026-01-01 00:00:00,10.0.0.5,8080,2026-01-02,emotet,online\n",
        )
        # 自动映射：ip_address 列识别为 ip，内网被过滤
        auto = feeds.load_feed(path)
        self.assertEqual(len(auto), 1)
        self.assertEqual(auto[0]["type"], "ip")
        # 显式映射 + ip:port 去端口
        path2 = self.write(
            "custom.csv",
            "kind,indicator,risk\n"
            f"ip,{PUBLIC_IP}:443,88\n"
            "ip,10.1.1.1:22,90\n",
        )
        mapped = feeds.parse_csv(
            path2, mapping={"type": "kind", "value": "indicator", "confidence": "risk"}
        )
        self.assertEqual(len(mapped), 1)
        self.assertEqual(mapped[0]["value"], PUBLIC_IP)
        self.assertEqual(mapped[0]["confidence"], 88)

        # 无 type 列时也能识别 ip:port 组合
        auto_port = feeds.load_feed(
            self.write("port.csv", f"ip:port,malware\n{PUBLIC_IP}:443,emotet\n")
        )
        self.assertEqual(len(auto_port), 1)
        self.assertEqual(auto_port[0]["type"], "ip")
        self.assertEqual(auto_port[0]["value"], PUBLIC_IP)


# ---------------------------------------------------------------------------
# 情报层：IocStore
# ---------------------------------------------------------------------------
class TestIocStore(TempCase):
    def test_import_dedup_values_and_stats(self) -> None:
        store = self.store()
        try:
            iocs = IocStore(store, self.cfg)
            records = [
                {"type": "ip", "value": PUBLIC_IP, "confidence": 90, "source": "t", "tlp": "red"},
                {"type": "ip", "value": PUBLIC_IP, "confidence": 90, "source": "t"},
                {"type": "domain", "value": "bad.example.com", "confidence": 70, "tlp": "green"},
                {"type": "hash", "value": "b" * 64, "confidence": 95},
                {"type": "ip", "value": "192.168.0.1"},
            ]
            result = iocs.import_records(records)
            self.assertEqual(result["total"], 5)
            self.assertEqual(result["imported"], 3)
            self.assertEqual(result["skipped"], 2)
            # 幂等：二次导入全部跳过
            again = iocs.import_records(records)
            self.assertEqual(again["imported"], 0)
            self.assertEqual(again["skipped"], 5)
            # values / provider（含 netrules 会传的集合名 ioc_ips/ioc_domains）
            self.assertEqual(iocs.values("ip"), {PUBLIC_IP})
            self.assertEqual(iocs.values("domain"), {"bad.example.com"})
            self.assertEqual(iocs.values("ioc_domains"), {"bad.example.com"})
            self.assertEqual(iocs.values("ioc_ips"), {PUBLIC_IP})
            provider = iocs.provider("ip")
            self.assertEqual(provider(), {PUBLIC_IP})
            self.assertEqual(provider("domains"), {"bad.example.com"})
            self.assertEqual(provider("ioc_ips"), {PUBLIC_IP})
            # TTL：ip 默认 30 天（有 expires_at），hash 永久（None）
            rows = {row["type"]: row for row in store.ioc_list(limit=50)}
            self.assertTrue(rows["ip"]["expires_at"])
            self.assertIsNone(rows["hash"]["expires_at"])
            # 过期记录不再出现在 values
            expired_id = rows["domain"]["ioc_id"]
            store.ioc_set_status(expired_id, "expired")
            self.assertEqual(iocs.values("domain"), set())
            # stats
            stats = iocs.stats()
            self.assertEqual(stats["total"], 3)
            self.assertEqual(stats["by_type"]["ip"], 1)
            self.assertEqual(stats["by_status"]["expired"], 1)
        finally:
            store.close()

    def test_stix_roundtrip(self) -> None:
        store = self.store()
        try:
            iocs = IocStore(store, self.cfg)
            iocs.import_records(
                [
                    {"type": "ip", "value": PUBLIC_IP, "confidence": 90, "source": "feed-a", "tlp": "red"},
                    {"type": "domain", "value": "c2.example.org", "confidence": 80, "tlp": "green"},
                    {"type": "hash", "value": "c" * 64, "confidence": 95, "tlp": "amber"},
                    {"type": "url", "value": "http://malware.example.com/a.bin", "tlp": "white"},
                ]
            )
            path = self.tmp / "bundle.json"
            count = iocs.export_stix(str(path))
            self.assertEqual(count, 4)
            bundle = json.loads(path.read_text(encoding="utf-8"))
            types = [obj["type"] for obj in bundle["objects"]]
            self.assertEqual(bundle["type"], "bundle")
            self.assertIn("identity", types)
            self.assertEqual(types.count("marking-definition"), 4)
            self.assertEqual(types.count("indicator"), 4)

            back = stix.read_bundle(path)
            got = {(rec["type"], rec["value"]) for rec in back}
            expected = {
                ("ip", PUBLIC_IP),
                ("domain", "c2.example.org"),
                ("hash", "c" * 64),
                ("url", "http://malware.example.com/a.bin"),
            }
            self.assertEqual(got, expected)
            ip_rec = next(rec for rec in back if rec["type"] == "ip")
            self.assertEqual(ip_rec["confidence"], 90)
            self.assertEqual(ip_rec["tlp"], "red")
            self.assertEqual(ip_rec["source"], "feed-a")
        finally:
            store.close()

    def test_parse_pattern_tolerates_quotes_and_spacing(self) -> None:
        self.assertEqual(stix.parse_pattern("[domain-name:value = 'X.COM']"), ("domain", "x.com"))
        self.assertEqual(
            stix.parse_pattern('[ipv4-addr:value="1.2.3.4"]'), ("ip", "1.2.3.4")
        )
        self.assertEqual(
            stix.parse_pattern("[ file:hashes.'SHA-256' = '" + "d" * 64 + "' ]"),
            ("hash", "d" * 64),
        )
        self.assertEqual(stix.parse_pattern("[file:name='evil.exe']"), ("filename", "evil.exe"))
        self.assertIsNone(stix.parse_pattern("[windows-registry-key:key='x']"))


# ---------------------------------------------------------------------------
# 情报层：intel2rule
# ---------------------------------------------------------------------------
class TestIntel2Rule(TempCase):
    def _seed(self, store: Store) -> IocStore:
        iocs = IocStore(store, self.cfg)
        iocs.import_records(
            [
                {"type": "hash", "value": "a" * 64, "confidence": 95, "source": "feed"},
                {"type": "ip", "value": PUBLIC_IP, "confidence": 90},
                {"type": "domain", "value": "c2.example.org", "confidence": 80},
                {"type": "url", "value": "http://malware.example.com/a.bin", "confidence": 80},
                {"type": "filename", "value": "evil.bin", "confidence": 70},
            ]
        )
        return iocs

    def test_build_products(self) -> None:
        store = self.store()
        try:
            self._seed(store)
            # 预置他人规则文件，构建后必须仍然存在（不得覆盖）
            yara_dir = Path(self.cfg["engines"]["yara_rule_dir"])
            yara_dir.mkdir(parents=True, exist_ok=True)
            others = yara_dir / "selfmade.yar"
            others.write_text('rule selfmade { condition: true }\n', encoding="utf-8")

            result = intel2rule_build(store, self.cfg, "bundle-test")
            self.assertEqual(result["bundle_id"], "bundle-test")
            self.assertEqual(result["counts"]["hash"], 1)
            self.assertEqual(result["counts"]["ip"], 1)
            self.assertEqual(result["counts"]["domain"], 2)  # 显式 domain + URL 主机名
            self.assertEqual(result["counts"]["filename"], 1)
            self.assertTrue(result["validated"], msg=f"errors={result['errors']}")
            self.assertEqual(result["errors"], [])
            self.assertTrue(others.exists())

            names = {Path(p).name for p in result["files"]}
            self.assertIn("intel-bundle-test.yar", names)
            self.assertIn("intel-bundle-test.rules", names)
            self.assertIn("intel-bundle-test.json", names)
            self.assertIn("bundle.json", names)
            for file_path in result["files"]:
                self.assertTrue(Path(file_path).is_file(), msg=file_path)

            yar_text = (Path(self.cfg["engines"]["yara_rule_dir"]) / "intel-bundle-test.yar").read_text(
                encoding="utf-8"
            )
            self.assertIn('import "hash"', yar_text)
            self.assertIn("rule intel_hash_1", yar_text)
            self.assertIn('hash.sha256(0, filesize) == "' + "a" * 64 + '"', yar_text)
            self.assertIn('attack = "T1204.002"', yar_text)

            net_text = (Path(self.cfg["engines"]["net_rule_dir"]) / "intel-bundle-test.rules").read_text(
                encoding="utf-8"
            )
            self.assertIn("dst_domain_in: ioc_domains", net_text)
            self.assertIn("dst_ip_in: ioc_ips", net_text)
            self.assertIn("N-9010", net_text)
            self.assertIn("N-9020", net_text)

            host_rule = json.loads(
                (Path(self.cfg["engines"]["host_rule_dir"]) / "intel-bundle-test.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(host_rule["id"], "H-IOC-bundle-test")
            ops = {cond["op"] for cond in host_rule["condition"]["any"]}
            self.assertIn("suffix", ops)

            manifest = json.loads(
                (Path(self.cfg["intel"]["bundle_dir"]) / "bundle.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["bundle_id"], "bundle-test")
            self.assertEqual(manifest["mode"]["hash"], "enforce")
            self.assertEqual(manifest["mode"]["domain"], "observe")
            self.assertEqual(manifest["counts"]["hash"], 1)

            # 若 yara-python 可用，validate_files 必须真的试编译通过
            try:
                import yara  # noqa: F401
            except ImportError:
                pass
            else:
                from hornwork.intel.intel2rule import validate_files

                check = validate_files([Path(self.cfg["engines"]["yara_rule_dir"]) / "intel-bundle-test.yar"])
                self.assertTrue(check["ok"], msg=str(check))
                self.assertTrue(check["yara"]["checked"])
        finally:
            store.close()

    def test_build_with_only_hashes_skips_net_rule(self) -> None:
        store = self.store()
        try:
            IocStore(store, self.cfg).import_records(
                [{"type": "hash", "value": "e" * 64, "confidence": 90}]
            )
            result = intel2rule_build(store, self.cfg, "hashonly")
            names = {Path(p).name for p in result["files"]}
            self.assertIn("intel-hashonly.yar", names)
            self.assertNotIn("intel-hashonly.rules", names)
        finally:
            store.close()


# ---------------------------------------------------------------------------
# 响应层：CaseManager
# ---------------------------------------------------------------------------
class TestCaseManager(TempCase):
    def _alert(self, level: int, rule_id: str = "R-9001") -> dict:
        rule = schema.make_rule(rule_id, "可疑下载行为", "yara", level=level, mitre=["T1105"])
        return schema.new_alert(rule, level=level, confidence=80)

    def test_create_from_alert_severity_and_dedup(self) -> None:
        store = self.store()
        try:
            cases = CaseManager(store, self.cfg)
            alert = self._alert(12)
            case = cases.create_from_alert(alert)
            self.assertEqual(case["severity"], "P1")
            self.assertIn("可疑下载行为", case["title"])
            self.assertEqual(case["status"], "open")
            self.assertEqual(case["dedup_key"], alert["dedup_key"])
            self.assertIsNotNone(case["created_at"])
            # 同 dedup_key 复用（幂等）
            again = cases.create_from_alert(alert)
            self.assertEqual(again["case_id"], case["case_id"])
            # level 映射（不同规则 → 不同 dedup_key，各自建单）
            self.assertEqual(cases.create_from_alert(self._alert(9, "R-9002"))["severity"], "P2")
            self.assertEqual(cases.create_from_alert(self._alert(5, "R-9003"))["severity"], "P3")
            self.assertEqual(len(cases.list()), 3)
        finally:
            store.close()

    def test_state_machine_and_closed_at(self) -> None:
        store = self.store()
        try:
            cases = CaseManager(store, self.cfg)
            case = cases.create("手工工单", severity="P2")
            case_id = case["case_id"]
            self.assertTrue(cases.update(case_id, status="investigating"))
            self.assertTrue(cases.update(case_id, status="contained"))
            self.assertTrue(cases.update(case_id, status="closed", verdict="tp"))
            closed = cases.get(case_id)
            self.assertEqual(closed["status"], "closed")
            self.assertEqual(closed["verdict"], "tp")
            self.assertIsNotNone(closed["closed_at"])
            # 非法状态 / 非法结论
            self.assertFalse(cases.update(case_id, status="bogus"))
            self.assertFalse(cases.update(case_id, verdict="hacked"))
            # 重开清空 closed_at
            self.assertTrue(cases.update(case_id, status="open"))
            self.assertIsNone(cases.get(case_id)["closed_at"])
            # 不存在的工单
            self.assertFalse(cases.update("CASE-NOPE", status="closed"))
            self.assertIsNone(cases.get("CASE-NOPE"))
            self.assertEqual([row["status"] for row in cases.list(status="open")], ["open"])
        finally:
            store.close()


# ---------------------------------------------------------------------------
# 响应层：ActionExecutor + 审计链
# ---------------------------------------------------------------------------
class TestActionExecutor(TempCase):
    def test_observe_mode_and_audit_chain(self) -> None:
        store = self.store()
        try:
            executor = ActionExecutor(store, self.cfg)
            r1 = executor.execute("block_ip", {"ip": PUBLIC_IP, "direction": "outbound"}, mode="observe")
            self.assertTrue(r1["ok"])
            self.assertEqual(r1["mode"], "observe")
            self.assertEqual(r1["target"], PUBLIC_IP)
            self.assertEqual(r1["rollback"], {})
            self.assertTrue(r1["action_id"].startswith("ACT-"))

            r2 = executor.execute("quarantine_file", {"path": str(self.tmp / "sample.bin")}, mode="observe")
            self.assertTrue(r2["ok"])
            r3 = executor.execute("collect_forensics", {"case_id": "CASE-X"}, mode="observe")
            self.assertTrue(r3["ok"])
            r4 = executor.execute("nope_action", {}, mode="observe")
            self.assertFalse(r4["ok"])

            rows = store.audit_rows()
            self.assertEqual(len(rows), 4)
            self.assertEqual(rows[0]["prev_hash"], "")
            self.assertTrue(rows[0]["hash"])
            for prev, cur in zip(rows, rows[1:]):
                self.assertEqual(cur["prev_hash"], prev["hash"])
            self.assertEqual(verify_chain(rows), (True, None))

            # 篡改一行后必须断链，并指出该行 seq
            tampered = [dict(row) for row in rows]
            tampered[1]["result"] = "tampered"
            ok, seq = verify_chain(tampered)
            self.assertFalse(ok)
            self.assertEqual(seq, tampered[1]["seq"])
        finally:
            store.close()

    def test_dry_run_returns_commands_and_undo(self) -> None:
        store = self.store()
        try:
            executor = ActionExecutor(store, self.cfg)
            dry = executor.execute("block_ip", {"ip": PUBLIC_IP}, mode="dry_run")
            self.assertTrue(dry["ok"])
            self.assertEqual(dry["mode"], "dry-run")
            self.assertIn("iptables", dry["detail"])
            self.assertIn(f"hornwork:{dry['action_id']}", dry["detail"])
            self.assertEqual(dry["rollback"]["kind"], "block_ip")

            quar = executor.execute("quarantine_file", {"path": str(self.tmp / "x.bin")}, mode="dry-run")
            self.assertTrue(quar["ok"])
            self.assertEqual(quar["rollback"]["kind"], "quarantine_file")
            undo = executor.undo(quar["rollback"], mode="dry-run")
            self.assertTrue(undo["ok"])
            self.assertTrue(undo["action"].startswith("undo:"))

            iso = executor.execute("isolate_host", {}, mode="dry-run")
            self.assertTrue(iso["ok"])
            self.assertEqual(iso["rollback"]["kind"], "isolate_host")

            #  的 restore_file 回滚动作
            restore = executor.execute(
                "restore_file",
                {"src": str(self.tmp / "a.bin"), "dst": str(self.tmp / "quarantine" / "abc")},
                mode="dry-run",
            )
            self.assertTrue(restore["ok"], msg=restore["detail"])
            self.assertIn("mv", restore["detail"])

            self.assertEqual(verify_chain(store.audit_rows()), (True, None))
        finally:
            store.close()

    def test_quarantine_enforce_and_restore(self) -> None:
        store = self.store()
        try:
            sample = self.tmp / "sample.bin"
            sample.write_bytes(b"MZ fake sample for quarantine test")
            executor = ActionExecutor(store, self.cfg)
            result = executor.execute("quarantine_file", {"path": str(sample)}, mode="enforce")
            self.assertTrue(result["ok"], msg=result["detail"])
            self.assertFalse(sample.exists())
            dst = Path(result["rollback"]["dst"])
            self.assertTrue(dst.is_file())
            undo = executor.undo(result["rollback"], mode="enforce")
            self.assertTrue(undo["ok"], msg=undo["detail"])
            self.assertTrue(sample.is_file())
            self.assertEqual(verify_chain(store.audit_rows()), (True, None))
        finally:
            store.close()

    def test_mode_guard(self) -> None:
        saved = os.environ.pop("HORNWORK_APPROVED", None)
        try:
            guard = ModeGuard(self.cfg)
            self.assertEqual(guard.resolve(None), "observe")
            self.assertTrue(guard.allowed("observe"))
            self.assertTrue(guard.allowed("dry-run"))
            self.assertFalse(guard.allowed("enforce"))
            self.assertTrue(guard.require_approval("isolate_host", "enforce"))
            self.assertFalse(guard.require_approval("isolate_host", "observe"))
            ok, reason = guard.check("isolate_host", "enforce")
            self.assertFalse(ok)
            self.assertIn("HORNWORK_APPROVED", reason)
            os.environ["HORNWORK_APPROVED"] = "1"
            self.assertTrue(guard.allowed("enforce"))
            self.assertTrue(guard.check("isolate_host", "enforce")[0])
            with self.assertRaises(ValueError):
                guard.resolve("yolo")
        finally:
            if saved is None:
                os.environ.pop("HORNWORK_APPROVED", None)
            else:
                os.environ["HORNWORK_APPROVED"] = saved


# ---------------------------------------------------------------------------
# 响应层：playbook
# ---------------------------------------------------------------------------
class TestPlaybook(TempCase):
    def test_default_playbooks_valid(self) -> None:
        for pb_id, pb in DEFAULT_PLAYBOOKS.items():
            self.assertEqual(validate_playbook(pb), [], msg=pb_id)

    def test_load_and_validate(self) -> None:
        valid = {
            "id": "PB-T1",
            "name": "测试流程",
            "steps": [
                {"id": "s1", "action": "block_ip", "mode": "enforce", "params": {"ip": "${ip}"}},
                {"id": "s2", "action": "update_case", "params": {"status": "investigating"}},
            ],
            "rollback": [{"action": "unblock_ip", "when": "verdict == benign"}],
        }
        path = self.write("pb.json", json.dumps(valid, ensure_ascii=False))
        self.assertEqual(load_playbook(path)["id"], "PB-T1")

        bad = {"id": "PB-T2", "name": "坏的", "steps": [{"id": "s1", "action": "explode"}]}
        errors = validate_playbook(bad)
        self.assertTrue(any("不支持的动作" in err for err in errors))
        bad_path = self.write("bad.json", json.dumps(bad, ensure_ascii=False))
        with self.assertRaises(ValueError):
            load_playbook(bad_path)

    def test_runner_observe_and_context(self) -> None:
        store = self.store()
        try:
            cases = CaseManager(store, self.cfg)
            case = cases.create("playbook 测试工单", severity="P2")
            case_id = case["case_id"]
            executor = ActionExecutor(store, self.cfg)
            runner = PlaybookRunner(store, executor)
            pb = {
                "id": "PB-T3",
                "name": "演练",
                "steps": [
                    {"id": "s1", "action": "block_ip", "mode": "enforce", "params": {"ip": "${ip}"}},
                    {"id": "s2", "action": "update_case", "params": {"status": "investigating"}},
                ],
            }
            result = runner.run(case_id, pb, mode="observe", context={"ip": PUBLIC_IP})
            self.assertTrue(result["ok"], msg=result)
            self.assertEqual(result["playbook"], "PB-T3")
            self.assertEqual(len(result["steps"]), 2)
            # observe 模式向下封顶：enforce 步骤被降级
            self.assertEqual(result["steps"][0]["mode"], "observe")
            self.assertIn(PUBLIC_IP, result["steps"][0]["detail"])
            self.assertEqual(cases.get(case_id)["status"], "investigating")
            self.assertEqual(verify_chain(store.audit_rows()), (True, None))
        finally:
            store.close()

    def test_runner_auto_context_from_alert(self) -> None:
        """未显式传 context 时，从工单关联告警自动提取 ${ip}/${path}。"""
        store = self.store()
        try:
            rule = schema.make_rule("R-9100", "可疑外联", "netrules", level=10, mitre=["T1071"])
            event = schema.new_event(
                "net_connect", "net", "netcap", self.cfg,
                file={"path": "/tmp/dropper.bin", "sha256": "1" * 64},
                network={"src_ip": "10.0.0.5", "dst_ip": PUBLIC_IP, "dst_port": 443, "proto": "tcp"},
            )
            alert = schema.new_alert(rule, level=10, event=event)
            self.assertTrue(store.insert_alert(alert))
            case = CaseManager(store, self.cfg).create_from_alert(alert)
            runner = PlaybookRunner(store, ActionExecutor(store, self.cfg))
            pb = {
                "id": "PB-AUTO",
                "name": "自动上下文",
                "steps": [
                    {"id": "s1", "action": "block_ip", "mode": "enforce", "params": {"ip": "${ip}"}},
                    {"id": "s2", "action": "quarantine_file", "mode": "dry-run",
                     "params": {"path": "${path}"}},
                ],
            }
            result = runner.run(case["case_id"], pb, mode="dry-run")
            self.assertTrue(result["ok"], msg=result)
            self.assertIn(PUBLIC_IP, result["steps"][0]["detail"])
            self.assertIn("/tmp/dropper.bin", result["steps"][1]["detail"])
        finally:
            store.close()

    def test_runner_stops_on_failure(self) -> None:
        store = self.store()
        try:
            case = CaseManager(store, self.cfg).create("失败即停", severity="P3")
            executor = ActionExecutor(store, self.cfg)
            runner = PlaybookRunner(store, executor)
            pb = {
                "id": "PB-T4",
                "name": "缺参数",
                "steps": [
                    {"id": "s1", "action": "quarantine_file", "mode": "observe"},
                    {"id": "s2", "action": "update_case", "params": {"status": "closed"}},
                ],
            }
            result = runner.run(case["case_id"], pb, mode="observe")
            self.assertFalse(result["ok"])
            self.assertEqual(len(result["steps"]), 1)
            self.assertFalse(result["steps"][0]["ok"])
            self.assertEqual(result["steps"][0]["action"], "quarantine_file")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
