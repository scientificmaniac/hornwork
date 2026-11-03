"""检测引擎层单元测试（Windows 开发机必须全绿）。

运行：
    python -m unittest tests.test_engines -v

约定：
- **不使用 tempfile**（DSH 沙箱下系统临时目录不可写）：产物写到
  ``tests/_tmp/engines-<uuid>/``，tearDown 里 ``shutil.rmtree`` 清理；
- 依赖 yara-python 的用例 skipUnless 已安装；依赖 PyYAML 的加载用例 skipUnless 已安装；
  clamd/EICAR 相关用例 skipUnless Linux 且有 socket；
- 纯函数用例（条件求值/字段映射/DSL 解析/熵/hex/ELF 结构）不依赖任何第三方库。
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import struct
import sys
import unittest
import uuid
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
if str(ROOT) not in sys.path:  # 允许从任意目录运行
    sys.path.insert(0, str(ROOT))

from hornwork.config import DEFAULTS  # noqa: E402
from hornwork.engines.base import make_hit  # noqa: E402
from hornwork.engines.cascade import Cascade, guess_filetype  # noqa: E402
from hornwork.engines.clamd_client import (  # noqa: E402
    ClamavEngine,
    _PONG_RE,
    _parse_response,
    _read_response,
    ping as clamd_ping,
)
from hornwork.engines.contribution import ContributionTracker  # noqa: E402
from hornwork.engines.hostrules import (  # noqa: E402
    HostRuleEngine,
    collect_leaf_fields,
    eval_condition as host_eval_condition,
    eval_leaf,
    get_field,
)
from hornwork.engines.netflow import FlowTable, packet_ts, parse_flags_set  # noqa: E402
from hornwork.engines.netrules import NetRuleSet, parse_rules  # noqa: E402
from hornwork.engines.sigma_matcher import (  # noqa: E402
    FIELD_MAP,
    SigmaMatcher,
    check_condition,
    eval_condition as sigma_eval_condition,
    match_selection,
    match_value,
    tokenize_condition,
    validate_selection,
)
from hornwork.engines.sigdb import (  # noqa: E402
    SigDbEngine,
    elf_anomalies,
    hex_to_regex,
    parse_elf,
    parse_hash_line,
    parse_hex_line,
    parse_pe,
    parse_regex_line,
    pe_anomalies,
    shannon_entropy,
)
from hornwork.engines.tracker import Tracker  # noqa: E402
from hornwork.engines.yara_bridge import YaraEngine  # noqa: E402
from hornwork.store import Store  # noqa: E402

try:  # 开发机可能没有 PyYAML
    import yaml as _yaml  # noqa: F401
except Exception:  # pragma: no cover
    _yaml = None
try:  # 开发机可能没有 yara-python
    import yara as _yara  # noqa: F401
except Exception:  # pragma: no cover
    _yara = None

TMP_ROOT = TESTS_DIR / "_tmp"

#  的 8 条网络规则原文（测试内置，避免依赖 rules/ 目录当前内容）
NET_RULES_TEXT = """
# Hornwork 网络检测规则
rule N-0101 syn_scan {
  proto: tcp
  flags: syn
  not_flags: ack
  window: 5s
  group_by: src_ip, dst_ip
  count_distinct: dst_port >= 20
  severity: 8
  technique: T1046
  msg: "SYN 端口扫描"
}

rule N-0102 xmas_null_scan {
  proto: tcp
  flags_any_of: [fin, psh, urg]
  severity: 7
  technique: T1046
  msg: "XMAS/NULL 类异常 flag 扫描"
}

rule N-0103 ioc_outbound {
  proto: tcp
  dst_domain_in: ioc_domains
  severity: 10
  technique: T1071.001
  msg: "出站命中威胁情报域名"
}

rule N-0104 icmp_sweep {
  proto: icmp
  icmp_type: 8
  window: 5s
  group_by: src_ip
  count_distinct: dst_ip >= 10
  severity: 6
  technique: T1018
  msg: "ICMP 主机扫描"
}

rule N-0105 lateral_smb {
  proto: tcp
  dst_port_in: [445, 139]
  src_cidr: 192.168.1.0/24
  dst_cidr: 192.168.1.0/24
  window: 60s
  group_by: src_ip
  count_distinct: dst_ip >= 3
  severity: 9
  technique: T1021.002
  msg: "内网 SMB 横向连接"
}

rule N-0106 c2_heartbeat {
  proto: tcp
  window: 600s
  group_by: src_ip, dst_ip
  count: packets >= 10
  avg_interval_between: 30s, 90s
  severity: 6
  technique: T1071
  msg: "可疑心跳式外联（仅标记）"
}

rule N-0107 malformed_packet {
  proto: any
  malformed: true
  severity: 4
  msg: "协议畸形报文"
}

rule N-0108 large_upload {
  proto: tcp
  direction: outbound
  window: 60s
  group_by: src_ip, dst_ip
  sum_bytes: >= 52428800
  severity: 6
  technique: T1041
  msg: "单向外发流量异常（疑似外传）"
}
"""


# ---------------------------------------------------------------------------
# 测试基类与工具
# ---------------------------------------------------------------------------
class EngineTestBase(unittest.TestCase):
    """每个用例一个隔离目录，不使用系统临时目录。"""

    def setUp(self) -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = TMP_ROOT / f"engines-{uuid.uuid4().hex[:12]}"
        self.tmp.mkdir(parents=True, exist_ok=False)
        self._stores: list[Store] = []

    def tearDown(self) -> None:
        for store in self._stores:
            try:
                store.close()
            except Exception:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ 工具
    def write(self, rel: str, content: str | bytes) -> Path:
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def make_cfg(self, rule_root: Path | None = None) -> dict:
        cfg = copy.deepcopy(DEFAULTS)
        root = Path(rule_root or (self.tmp / "rules"))
        cfg["general"]["rule_dir"] = str(root)
        # 关键：规则子目录全部显式指向测试临时目录，避免在测试主机（/opt/hornwork/rules
        # 存在）上误读真实规则库，导致用例随部署环境变化而失败。
        cfg["engines"]["yara_rule_dir"] = str(root / "yara")
        cfg["engines"]["net_rule_dir"] = str(root / "net")
        cfg["engines"]["host_rule_dir"] = str(root / "host")
        cfg["engines"]["sigma_rule_dir"] = str(root / "sigma")
        cfg["engines"]["sigdb"]["hash_file"] = str(root / "sigdb" / "hashes.txt")
        cfg["engines"]["sigdb"]["hex_file"] = str(root / "sigdb" / "hex.txt")
        cfg["engines"]["sigdb"]["regex_file"] = str(root / "sigdb" / "regex.txt")
        # 测试主机上 clamd socket 真实存在，测试必须指向不存在的临时路径才是 hermetic 的
        cfg["engines"]["clamav"]["socket"] = str(self.tmp / "no-such-clamd.sock")
        cfg["net"]["home_net"] = "192.168.1.0/24"
        return cfg

    def open_store(self, name: str = "test.db") -> Store:
        store = Store(str(self.tmp / name))
        self._stores.append(store)
        return store


def make_packet(**overrides) -> dict:
    pkt = {
        "ts": 1000.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "8.8.8.8",
        "src_port": 40000,
        "dst_port": 443,
        "proto": "tcp",
        "flags": 0,
        "ip_len": 60,
        "icmp_type": None,
        "malformed": False,
    }
    pkt.update(overrides)
    return pkt


def make_event(event_type: str, **sections) -> dict:
    event = {
        "schema_version": "1.0",
        "event_id": f"ev-{uuid.uuid4().hex[:8]}",
        "ts": "2026-10-26T00:00:00.000Z",
        "source_layer": "host",
        "source_product": "unit-test",
        "event_type": event_type,
        "host": {"host_id": "h-test", "hostname": "h-test", "os": "ubuntu"},
    }
    for key, value in sections.items():
        event[key] = value
    return event


def make_elf_no_sections() -> bytes:
    """构造一个 64 字节、无节表/无程序头的 ELF64 头。"""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type = ET_EXEC
        0x3E,       # e_machine = x86_64
        1,          # e_version
        0x401000,   # e_entry
        0,          # e_phoff
        0,          # e_shoff（无节表）
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        0,          # e_phnum
        64,         # e_shentsize
        0,          # e_shnum
        0,          # e_shstrndx
    )
    return e_ident + header


def make_elf_entry_writable() -> bytes:
    """构造一个入口落在可写 LOAD 段的 ELF64（1 个程序头，无节表）。"""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type
        0x3E,       # e_machine
        1,          # e_version
        0x400900,   # e_entry：落在下面的可写 LOAD 段内
        64,         # e_phoff
        0,          # e_shoff
        0,          # e_flags
        64,         # e_ehsize
        56,         # e_phentsize
        1,          # e_phnum
        64,         # e_shentsize
        0,          # e_shnum
        0,          # e_shstrndx
    )
    # PT_LOAD(1) flags=RWX(7) vaddr=0x400000 memsz=0x2000
    phdr = struct.pack("<IIQQQQQQ", 1, 7, 0, 0x400000, 0x400000, 0x100, 0x2000, 0x1000)
    return e_ident + header + phdr


def make_pe_no_sections() -> bytes:
    """构造一个合法 MZ/PE 头但 0 个节表的 PE 文件。"""
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)          # e_lfanew
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x44, 0x8664, 0, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", data, 0x58, 0x20B)          # 可选头 magic (PE32+)
    struct.pack_into("<I", data, 0x58 + 16, 0x1000)   # AddressOfEntryPoint
    return bytes(data)


# ---------------------------------------------------------------------------
# FlowTable / Tracker
# ---------------------------------------------------------------------------
class FlowTableTest(unittest.TestCase):
    def test_bidirectional_key(self) -> None:
        table = FlowTable()
        forward = make_packet(src_ip="1.1.1.1", src_port=1234, dst_ip="2.2.2.2", dst_port=80)
        backward = make_packet(src_ip="2.2.2.2", src_port=80, dst_ip="1.1.1.1", dst_port=1234)
        self.assertEqual(table.key(forward), table.key(backward))

    def test_update_counts(self) -> None:
        table = FlowTable()
        pkt = make_packet(ts=100.0, flags=0x02, ip_len=100)  # SYN
        table.update(pkt)
        state = table.update(make_packet(ts=101.5, flags=0x10, ip_len=50))  # ACK
        self.assertEqual(state["packets"], 2)
        self.assertEqual(state["bytes"], 150)
        self.assertEqual(state["syn"], 1)
        self.assertEqual(state["ack"], 1)
        self.assertEqual(state["first_ts"], 100.0)
        self.assertEqual(state["last_ts"], 101.5)
        self.assertEqual(len(table), 1)

    def test_evict_and_age(self) -> None:
        table = FlowTable(max_flows=100)
        # 从 100 开始，避免 ts=0 被当作"缺失时间戳"回退到当前时间
        for index in range(10):
            table.update(make_packet(ts=100.0 + index, dst_port=1000 + index))
        self.assertEqual(len(table), 10)
        removed = table.evict(0.5)
        self.assertEqual(removed, 5)
        self.assertEqual(len(table), 5)
        self.assertEqual(table.age(now=1000.0), 5)
        self.assertEqual(len(table), 0)
        self.assertEqual(table.stats()["flows"], 0)

    def test_packet_ts_and_flags(self) -> None:
        from datetime import datetime, timezone
        self.assertEqual(packet_ts({"ts": 12}), 12.0)
        expected = datetime(2026, 10, 26, tzinfo=timezone.utc).timestamp()
        self.assertAlmostEqual(packet_ts({"ts": "2026-10-26T00:00:00.000Z"}), expected, places=3)
        self.assertEqual(parse_flags_set(0x02 | 0x10), {"syn", "ack"})
        self.assertEqual(parse_flags_set("syn,ack"), {"syn", "ack"})
        self.assertEqual(parse_flags_set(["FIN", "psh"]), {"fin", "psh"})
        self.assertEqual(parse_flags_set(None), set())


class TrackerTest(unittest.TestCase):
    def test_distinct_ports_and_dsts(self) -> None:
        tracker = Tracker(window=5.0, shards=5)
        base = 2000.0
        for index in range(3):
            tracker.add(base + index * 0.5, "10.0.0.1", "10.0.0.2", 80 + index)
        tracker.add(base + 1.5, "10.0.0.1", "10.0.0.3", 443)
        now = base + 2.0
        self.assertEqual(tracker.distinct_ports(now, "10.0.0.1", "10.0.0.2"), 3)
        self.assertEqual(tracker.distinct_dsts(now, "10.0.0.1", "dst_ip"), 2)
        self.assertEqual(tracker.distinct_dsts(now, "10.0.0.1", "dst_port"), 4)
        self.assertEqual(tracker.count_packets(now, "10.0.0.1", "10.0.0.2"), 3)

    def test_bytes_and_interval(self) -> None:
        tracker = Tracker(window=10.0, shards=5)
        for index in range(3):
            tracker.add_packet(3000.0 + index * 2.0, "a", "b", 1, nbytes=100)
        now = 3004.0
        self.assertEqual(tracker.sum_bytes(now, "a", "b"), 300)
        self.assertAlmostEqual(tracker.avg_interval(now, "a", "b") or 0.0, 2.0, places=3)
        self.assertEqual(tracker.last_packet_ts("a", "b"), 3004.0)
        self.assertIsNone(tracker.last_packet_ts("x", "y"))

    def test_window_expired(self) -> None:
        tracker = Tracker(window=5.0, shards=5)
        tracker.add(1000.0, "a", "b", 80)
        self.assertEqual(tracker.distinct_ports(1000.0, "a", "b"), 1)
        # 分片滑窗：远超窗口后再查应为 0
        self.assertEqual(tracker.distinct_ports(2000.0, "a", "b"), 0)
        self.assertEqual(tracker.count_packets(2000.0, "a", "b"), 0)


# ---------------------------------------------------------------------------
# 网络规则解析与求值
# ---------------------------------------------------------------------------
class NetRuleParseTest(unittest.TestCase):
    def test_parse_eight_rules(self) -> None:
        rules, errors = parse_rules(NET_RULES_TEXT, source="hornwork-net.rules")
        self.assertEqual(errors, [])
        self.assertEqual(len(rules), 8)
        self.assertEqual([rule.rule_id for rule in rules],
                         [f"N-010{i}" for i in range(1, 9)])

    def test_rule_fields(self) -> None:
        rules, _errors = parse_rules(NET_RULES_TEXT)
        by_id = {rule.rule_id: rule for rule in rules}
        scan = by_id["N-0101"]
        self.assertEqual(scan.proto, "tcp")
        self.assertEqual(scan.flags, frozenset({"syn"}))
        self.assertEqual(scan.not_flags, frozenset({"ack"}))
        self.assertEqual(scan.window, 5.0)
        self.assertEqual(scan.group_by, ("src_ip", "dst_ip"))
        self.assertEqual(scan.count_distinct["field"], "dst_port")
        self.assertEqual(scan.count_distinct["op"], ">=")
        self.assertEqual(scan.count_distinct["value"], 20.0)
        self.assertEqual(scan.severity, 8)
        self.assertEqual(scan.technique, "T1046")
        self.assertTrue(scan.has_behavior)

        heartbeat = by_id["N-0106"]
        self.assertEqual(heartbeat.count["field"], "packets")
        self.assertEqual(heartbeat.avg_interval_between, (30.0, 90.0))
        self.assertEqual(heartbeat.window, 600.0)

        upload = by_id["N-0108"]
        self.assertEqual(upload.direction, "outbound")
        self.assertEqual(upload.sum_bytes["value"], 52428800.0)
        self.assertFalse(by_id["N-0102"].has_behavior)
        self.assertEqual(by_id["N-0103"].dst_domain_in, ("ioc_domains",))
        self.assertEqual(by_id["N-0105"].dst_port_in, (445, 139))
        self.assertIsNotNone(by_id["N-0105"].src_cidr)

    def test_parse_error_reported_with_rule_isolation(self) -> None:
        text = "rule N-9999 broken { proto tcp }\n" + NET_RULES_TEXT
        rules, errors = parse_rules(text, source="broken.rules")
        self.assertEqual(len(rules), 8)          # 后面的合法规则仍要解析出来
        self.assertTrue(errors)                  # 非法规则记错误
        self.assertIn("broken.rules", errors[0])

    @unittest.skipUnless((ROOT / "rules" / "net").is_dir(), "缺少 rules/net 目录")
    def test_real_rule_file(self) -> None:
        files = sorted((ROOT / "rules" / "net").glob("*.rules"))
        self.assertTrue(files, "rules/net 下没有规则文件")
        rules, errors = parse_rules(files[0].read_text(encoding="utf-8"), source=files[0].name)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(rules), 8)


class NetRuleEvalTest(EngineTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.write("rules/net/hornwork-net.rules", NET_RULES_TEXT)
        self.cfg = self.make_cfg()
        self.ioc_domains = {"evil.example"}
        self.ruleset = NetRuleSet(self.cfg, ioc_provider=self._ioc_provider)

    def _ioc_provider(self, kind: str):
        if "domain" in str(kind):
            return self.ioc_domains
        return {"203.0.113.9"}

    def test_syn_scan_fires_after_20_ports(self) -> None:
        hits: list[dict] = []
        for index in range(20):
            pkt = make_packet(ts=1000.0 + index * 0.1, dst_port=1000 + index, flags=0x02)
            current = self.ruleset.evaluate(pkt)
            if index < 19:
                self.assertEqual(current, [], f"第 {index + 1} 个 SYN 包不应触发端口扫描")
            hits.extend(current)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["engine"], "netrules")
        self.assertEqual(hit["rule_id"], "N-0101")
        self.assertEqual(hit["score"], 80)
        self.assertEqual(hit["meta"]["severity"], 8)
        self.assertEqual(hit["meta"]["mitre"], ["T1046"])
        self.assertEqual(hit["meta"]["rule_name"], "syn_scan")
        self.assertIn("count_distinct", hit["evidence"])
        self.assertGreaterEqual(hit["evidence"]["count_distinct"]["count"], 20)

    def test_icmp_sweep_fires_on_10th_host(self) -> None:
        hits: list[dict] = []
        for index in range(10):
            pkt = make_packet(
                ts=2000.0 + index * 0.2, proto="icmp", icmp_type=8,
                dst_ip=f"10.0.0.{index + 1}", dst_port=None, src_port=None,
            )
            current = self.ruleset.evaluate(pkt)
            if index < 9:
                self.assertEqual(current, [])
            hits.extend(current)
        self.assertEqual([hit["rule_id"] for hit in hits], ["N-0104"])
        self.assertEqual(hits[0]["score"], 60)
        self.assertEqual(hits[0]["meta"]["technique"], "T1018")

    def test_single_packet_rule_and_dedup(self) -> None:
        xmas = make_packet(ts=3000.0, dst_port=22, flags=0x29)  # FIN|PSH|URG
        first = self.ruleset.evaluate(xmas)
        self.assertTrue(any(hit["rule_id"] == "N-0102" for hit in first))
        second = self.ruleset.evaluate(make_packet(ts=3001.0, dst_port=22, flags=0x29))
        self.assertFalse(any(hit["rule_id"] == "N-0102" for hit in second))

    def test_malformed_packet(self) -> None:
        hits = self.ruleset.evaluate(make_packet(ts=4000.0, malformed=True, dst_port=1))
        self.assertEqual([hit["rule_id"] for hit in hits], ["N-0107"])
        self.assertEqual(hits[0]["score"], 40)

    def test_ioc_domain_hit(self) -> None:
        pkt = make_packet(ts=5000.0, domain="evil.example")
        hits = self.ruleset.evaluate(pkt)
        self.assertEqual([hit["rule_id"] for hit in hits], ["N-0103"])
        self.assertEqual(hits[0]["score"], 100)

    def test_large_upload_sum_bytes(self) -> None:
        pkt = make_packet(ts=6000.0, ip_len=60_000_000, dst_port=8080)
        hits = self.ruleset.evaluate(pkt)
        self.assertEqual([hit["rule_id"] for hit in hits], ["N-0108"])
        self.assertEqual(hits[0]["score"], 60)
        self.assertIn("sum_bytes", hits[0]["evidence"])

    def test_stats_counters(self) -> None:
        self.ruleset.evaluate(make_packet(ts=7000.0))
        stats = self.ruleset.stats()
        self.assertEqual(stats["rules"], 8)
        self.assertEqual(stats["errors"], 0)
        self.assertGreaterEqual(stats["evaluations"], 1)
        self.assertGreaterEqual(stats["dedup_entries"], 0)


# ---------------------------------------------------------------------------
# 主机规则 JSON DSL
# ---------------------------------------------------------------------------
class HostRuleTest(EngineTestBase):
    RULES = {
        "H-9001-tmp-exec.json": {
            "id": "H-9001", "name": "tmp 目录执行", "level": 8,
            "mitre": ["T1105"], "event_types": ["process_create"],
            "condition": {"all": [
                {"field": "process.image", "op": "prefix", "value": "/tmp/"},
                {"field": "user.name", "op": "neq", "value": "root"},
            ]},
            "description": "临时目录执行且非 root",
        },
        "H-9002-cron.json": {
            "id": "H-9002", "name": "cron 文件写入", "level": 7,
            "mitre": ["T1053.003"], "event_types": ["file_create", "file_modify"],
            "condition": {"any": [
                {"field": "file.path", "op": "suffix", "value": ".sh"},
                {"field": "file.path", "op": "contains", "value": "/etc/cron"},
            ]},
        },
        "H-9003-not-download.json": {
            "id": "H-9003", "name": "非 root 下载", "level": 6,
            "mitre": [], "event_types": ["process_create"],
            "condition": {"all": [
                {"field": "process.cmdline", "op": "contains", "value": "curl"},
                {"not": [{"field": "user.name", "op": "eq", "value": "root"}]},
            ]},
        },
        "broken.json": [],
    }

    def setUp(self) -> None:
        super().setUp()
        for name, payload in self.RULES.items():
            if name == "broken.json":
                self.write(f"rules/host/{name}", "{not valid json")
            else:
                self.write(f"rules/host/{name}", json.dumps(payload, ensure_ascii=False))
        self.write("rules/host/H-9004-bad-op.json", json.dumps({
            "id": "H-9004", "name": "bad op", "level": 5,
            "condition": {"all": [{"field": "file.path", "op": "startswith", "value": "/"}]},
        }))
        self.cfg = self.make_cfg()
        self.engine = HostRuleEngine(self.cfg)

    def test_reload(self) -> None:
        result = self.engine.reload()
        self.assertEqual(result["rules"], 3)
        self.assertEqual(len(result["errors"]), 2)   # 坏 JSON + 不支持 op
        self.assertEqual(self.engine.stats()["rules"], 3)

    def test_process_event_hit(self) -> None:
        event = make_event(
            "process_create",
            process={"image": "/tmp/evil.sh", "cmdline": "/tmp/evil.sh --x"},
            user={"name": "ubuntu", "uid": 1000},
        )
        hits = self.engine.on_event(event)
        ids = [hit["rule_id"] for hit in hits]
        self.assertIn("H-9001", ids)
        hit = next(hit for hit in hits if hit["rule_id"] == "H-9001")
        self.assertEqual(hit["engine"], "hostrules")
        self.assertEqual(hit["score"], 80)              # level 8 * 10
        self.assertEqual(hit["meta"]["level"], 8)
        self.assertEqual(hit["meta"]["mitre"], ["T1105"])
        self.assertEqual(hit["meta"]["description"], "临时目录执行且非 root")
        self.assertEqual(hit["evidence"]["event_id"], event["event_id"])

    def test_event_type_filter_and_not(self) -> None:
        # file_create 事件不触发 process_create 规则
        file_event = make_event("file_create", file={"path": "/etc/cron.d/evil.sh"})
        ids = [hit["rule_id"] for hit in self.engine.on_event(file_event)]
        self.assertIn("H-9002", ids)
        self.assertNotIn("H-9001", ids)
        # root 用户执行 curl 不触发 H-9003（not 条件）
        root_event = make_event(
            "process_create",
            process={"image": "/usr/bin/curl", "cmdline": "curl http://x"},
            user={"name": "root"},
        )
        ids = [hit["rule_id"] for hit in self.engine.on_event(root_event)]
        self.assertNotIn("H-9003", ids)
        user_event = make_event(
            "process_create",
            process={"image": "/usr/bin/curl", "cmdline": "curl http://x"},
            user={"name": "ubuntu"},
        )
        ids = [hit["rule_id"] for hit in self.engine.on_event(user_event)]
        self.assertIn("H-9003", ids)

    def test_condition_tree_and_ops(self) -> None:
        event = make_event(
            "process_create",
            process={
                "image": "/usr/bin/bash", "cmdline": "bash -c 'id'",
                "pid": 4242, "parent_image": "/usr/bin/sshd",
            },
            user={"name": "ubuntu", "uid": 1000},
            file={"path": "/tmp/a.sh"},
            network={"dst_ip": "1.2.3.4", "dst_port": 4444},
        )
        self.assertEqual(get_field(event, "process.pid"), 4242)
        self.assertIsNone(get_field(event, "process.missing.deep"))
        self.assertTrue(host_eval_condition({"all": [
            {"field": "process.pid", "op": "gt", "value": 1000},
            {"field": "process.pid", "op": "lt", "value": 5000},
            {"field": "network.dst_port", "op": "in", "value": [443, 4444]},
            {"field": "process.image", "op": "regex", "value": "bash$"},
            {"field": "process.missing", "op": "exists", "value": False},
        ]}, event))
        self.assertTrue(host_eval_condition({"any": [
            {"field": "process.image", "op": "suffix", "value": ".sh"},
            {"field": "process.cmdline", "op": "contains", "value": "-c"},
        ]}, event))
        self.assertTrue(host_eval_condition({"not": [
            {"field": "user.name", "op": "eq", "value": "root"},
        ]}, event))
        self.assertFalse(host_eval_condition({"nin": [
            {"field": "process.pid", "op": "nin", "value": [4242]},
        ]}, event))
        self.assertFalse(eval_leaf({"field": "process.missing", "op": "eq", "value": 1}, event))
        # nin：pid 4242 在排除列表里 → False；换成 9999 则为 True
        self.assertFalse(eval_leaf(
            {"field": "process.pid", "op": "nin", "value": [4242]}, event))
        self.assertTrue(eval_leaf(
            {"field": "process.pid", "op": "nin", "value": [9999]}, event))
        self.assertEqual(collect_leaf_fields({"all": [{"field": "a"}, {"any": [{"field": "b"}]}]}),
                         ["a", "b"])


# ---------------------------------------------------------------------------
# Sigma 纯函数（不依赖 PyYAML）
# ---------------------------------------------------------------------------
class SigmaPureTest(unittest.TestCase):
    def test_field_map(self) -> None:
        expected = {
            "image": "process.image", "commandline": "process.cmdline",
            "parentimage": "process.parent_image", "user": "user.name",
            "targetfilename": "file.path", "destinationip": "network.dst_ip",
            "destinationport": "network.dst_port", "queryname": "network.domain",
        }
        for key, path in expected.items():
            self.assertEqual(FIELD_MAP[key], path)

    def test_match_value_modifiers(self) -> None:
        self.assertTrue(match_value("/bin/bash", "/bash", ["endswith"]))
        self.assertFalse(match_value("/bin/bash", "/zsh", ["endswith"]))
        self.assertTrue(match_value("bash -c curl", "curl", ["contains"]))
        self.assertTrue(match_value("/usr/bin/python3", "/usr/bin/", ["startswith"]))
        self.assertTrue(match_value("abc123", r"abc\d+", ["re"]))
        self.assertTrue(match_value("BASH", "bash"))                    # 大小写不敏感
        self.assertTrue(match_value("/tmp/evil.sh", "/tmp/*.sh"))       # 通配
        self.assertTrue(match_value(4444, "4444"))                      # 数字字符串
        self.assertTrue(match_value("x", ["a", "x"]))                   # 列表 = OR
        self.assertFalse(match_value("x", ["a", "b"]))
        # `all` 修饰符：列表内所有子串都要出现（AND）
        self.assertTrue(match_value("curl wget", ["curl", "wget"], ["contains", "all"]))
        self.assertFalse(match_value("curl", ["curl", "wget"], ["contains", "all"]))

    def test_match_selection(self) -> None:
        event = make_event(
            "process_create",
            process={"image": "/bin/bash", "cmdline": "bash -c 'curl http://x'",
                     "parent_image": "/usr/sbin/sshd"},
            user={"name": "ubuntu"},
            network={"dst_ip": "203.0.113.5", "dst_port": 4444},
            file={"path": "/tmp/x.sh"},
        )
        self.assertTrue(match_selection({"Image": "/bin/bash"}, event))
        self.assertTrue(match_selection({"Image|endswith": "/bash"}, event))
        self.assertTrue(match_selection({"CommandLine|contains": "curl"}, event))
        self.assertTrue(match_selection({"ParentImage|endswith": "/sshd"}, event))
        self.assertTrue(match_selection({"DestinationPort": 4444}, event))
        self.assertTrue(match_selection({"DestinationIp": "203.0.113.5"}, event))
        self.assertTrue(match_selection({"TargetFilename|endswith": ".sh"}, event))
        self.assertFalse(match_selection({"Image": "/bin/sh"}, event))
        # selection 列表 = OR
        self.assertTrue(match_selection([{"Image": "/bin/sh"}, {"Image": "/bin/bash"}], event))

    def test_eval_condition_boolean(self) -> None:
        selections = {
            "sel_img": {"Image|endswith": "/bash"},
            "sel_cmd": {"CommandLine|contains": ["curl", "wget"]},
            "filter_user": {"User": "root"},
        }
        event = make_event(
            "process_create",
            process={"image": "/bin/bash", "cmdline": "bash -c curl http://x"},
            user={"name": "ubuntu"},
        )
        self.assertTrue(sigma_eval_condition("sel_img and sel_cmd", selections, event))
        self.assertTrue(sigma_eval_condition("sel_img and not filter_user", selections, event))
        self.assertTrue(sigma_eval_condition("sel_img or filter_user", selections, event))
        self.assertFalse(sigma_eval_condition("sel_img and filter_user", selections, event))
        self.assertTrue(sigma_eval_condition("sel_img and (sel_cmd or filter_user)",
                                             selections, event))
        self.assertFalse(sigma_eval_condition("sel_img and (sel_cmd and filter_user)",
                                              selections, event))

    def test_eval_condition_quantifiers(self) -> None:
        selections = {
            "selection_a": {"Image|contains": "bash"},
            "selection_b": {"CommandLine|contains": "curl"},
            "selection_c": {"User": "root"},
        }
        event = make_event(
            "process_create",
            process={"image": "/bin/bash", "cmdline": "curl http://x"},
            user={"name": "ubuntu"},
        )
        self.assertTrue(sigma_eval_condition("1 of selection_*", selections, event))
        self.assertTrue(sigma_eval_condition("2 of selection_*", selections, event))
        self.assertFalse(sigma_eval_condition("3 of selection_*", selections, event))
        self.assertFalse(sigma_eval_condition("all of them", selections, event))
        # 全部 selection 都为真时 all of them 才成立
        root_event = make_event(
            "process_create",
            process={"image": "/bin/bash", "cmdline": "curl http://x"},
            user={"name": "root"},
        )
        self.assertTrue(sigma_eval_condition("all of them", selections, root_event))
        self.assertTrue(sigma_eval_condition("all of selection_*", selections, root_event))

    def test_unsupported_condition(self) -> None:
        self.assertFalse(sigma_eval_condition("sel | count() > 5", {"sel": {}}, {}))
        self.assertFalse(sigma_eval_condition("", {}, {}))
        self.assertFalse(sigma_eval_condition("unknown_selection", {"sel": {}}, {}))
        self.assertTrue(check_condition("selection", ["selection"]) is None)
        self.assertIsNotNone(check_condition("selection and", ["selection"]))
        self.assertIsNotNone(check_condition("sel1 or sel2", ["sel1"]))
        self.assertEqual(tokenize_condition("1 of sel_*"), ["1", "of", "sel_", "*"])

    def test_validate_selection(self) -> None:
        self.assertIsNone(validate_selection({"Image|endswith": "/bash"}))
        self.assertIsNone(validate_selection([{"Image": "a"}, {"CommandLine": "b"}]))
        self.assertIsNotNone(validate_selection({"DestinationHostname": "x"}))
        self.assertIsNotNone(validate_selection({"Image": "x", "CommandLine|base64offset": "y"}))


class SigmaLoadTest(EngineTestBase):
    STABLE = """title: Test Bash
id: test-bash-stable
status: stable
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/bash'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.004
"""

    TEST_STATUS = """title: Test Curl
id: test-curl-test
status: test
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/curl'
  condition: selection
level: medium
"""

    UNSUPPORTED = """title: Test Hostname
id: test-hostname
status: stable
logsource:
  category: network_connection
  product: linux
detection:
  selection:
    DestinationHostname: evil.example
  condition: selection
level: low
"""

    DEPRECATED = """title: Test Deprecated
id: test-deprecated
status: deprecated
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '.tmp'
  condition: selection
level: low
"""

    def setUp(self) -> None:
        super().setUp()
        self.write("rules/sigma/linux/proc/stable.yml", self.STABLE)
        self.write("rules/sigma/linux/proc/test_status.yml", self.TEST_STATUS)
        self.write("rules/sigma/linux/net/unsupported.yml", self.UNSUPPORTED)
        self.write("rules/sigma/linux/file/deprecated.yml", self.DEPRECATED)
        self.cfg = self.make_cfg()

    @unittest.skipUnless(_yaml is not None, "未安装 PyYAML")
    def test_reload_and_skip_reasons(self) -> None:
        matcher = SigmaMatcher(self.cfg)
        result = matcher.reload()
        self.assertEqual(set(result), {"ok", "loaded", "supported", "skipped", "error"})
        self.assertEqual(result["loaded"], 4)
        self.assertEqual(result["supported"], 1)
        self.assertEqual(result["skipped"], 3)
        stats = matcher.stats()
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["supported"], 1)
        self.assertEqual(stats["skipped"], 3)
        self.assertEqual(stats["errors"], 0)
        self.assertFalse(stats["include_status_test"])
        self.assertEqual(stats["skip_reasons"].get("status"), 1)
        self.assertEqual(stats["skip_reasons"].get("deprecated"), 1)
        self.assertEqual(stats["skip_reasons"].get("unsupported_field"), 1)
        self.assertEqual(stats["rules"], 1)

    @unittest.skipUnless(_yaml is not None, "未安装 PyYAML")
    def test_include_status_test_switch(self) -> None:
        cfg = copy.deepcopy(self.cfg)
        cfg["engines"]["sigma"]["include_status_test"] = True
        matcher = SigmaMatcher(cfg)
        self.assertEqual(len(matcher.rules()), 2)
        self.assertTrue(matcher.stats()["include_status_test"])
        event = make_event(
            "process_create",
            process={"image": "/bin/bash", "cmdline": "bash -i"},
            user={"name": "ubuntu"},
        )
        hits = matcher.on_event(event)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["engine"], "sigma")
        self.assertEqual(hits[0]["rule_id"], "test-bash-stable")
        self.assertEqual(hits[0]["score"], 90)
        self.assertEqual(hits[0]["meta"]["mitre"], ["T1059.004"])
        self.assertIn("selection", hits[0]["evidence"]["matched_selections"])

    @unittest.skipUnless(_yaml is not None, "未安装 PyYAML")
    def test_store_sigma_stats(self) -> None:
        store = self.open_store()
        matcher = SigmaMatcher(self.cfg, store)
        matcher.reload()
        self.assertEqual(store.sigma_stats()["total"], 4)
        self.assertEqual(store.sigma_stats()["supported"], 1)
        event = make_event("process_create", process={"image": "/usr/bin/bash"})
        self.assertEqual(len(matcher.on_event(event)), 1)
        self.assertEqual(int(store.sigma_stats()["hits"]), 1)

    @unittest.skipUnless(_yaml is not None, "未安装 PyYAML")
    def test_yaml_error_recorded(self) -> None:
        self.write("rules/sigma/linux/bad.yml", "title: [unclosed\n")
        matcher = SigmaMatcher(self.cfg)
        stats = matcher.stats()
        self.assertGreaterEqual(stats["errors"], 1)
        self.assertIn("error", stats["skip_reasons"])

    @unittest.skipUnless(_yaml is not None, "未安装 PyYAML")
    def test_real_sigma_rules(self) -> None:
        rules_dir = ROOT / "rules" / "sigma"
        if not rules_dir.is_dir():
            self.skipTest("缺少 rules/sigma 目录")
        cfg = self.make_cfg(rule_root=ROOT / "rules")
        cfg["engines"]["sigma"]["include_status_test"] = True
        matcher = SigmaMatcher(cfg)
        stats = matcher.stats()
        self.assertGreater(stats["total"], 30)
        self.assertGreaterEqual(stats["supported"], 30)
        self.assertEqual(stats["errors"], 0)


# ---------------------------------------------------------------------------
# SigDb：签名解析 / 熵 / ELF-PE 结构 / 引擎扫描
# ---------------------------------------------------------------------------
class SigDbParseTest(unittest.TestCase):
    def test_entropy(self) -> None:
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(shannon_entropy(b"\x00" * 4096), 0.0)
        self.assertAlmostEqual(shannon_entropy(bytes(range(256)) * 16), 8.0, places=3)
        self.assertGreater(shannon_entropy(bytes(range(256)) * 16), 7.2)

    def test_hex_to_regex(self) -> None:
        pattern = hex_to_regex("4D5A??00")
        self.assertIsNotNone(pattern)
        assert pattern is not None
        self.assertIsNotNone(pattern.search(b"xxMZ\x90\x00yy"))
        self.assertIsNotNone(pattern.search(b"MZ\x00\x00"))
        self.assertIsNone(pattern.search(b"MZ\x90\x01"))
        # 半字节通配
        nibble = hex_to_regex("4?")
        self.assertIsNotNone(nibble)
        self.assertIsNotNone(nibble.search(b"\x4f"))  # type: ignore[union-attr]
        self.assertIsNone(nibble.search(b"\x5f"))     # type: ignore[union-attr]
        self.assertIsNone(hex_to_regex("4D5Z"))       # 非法 hex
        self.assertIsNone(hex_to_regex("4D5"))        # 奇数长度

    def test_parse_rule_lines(self) -> None:
        self.assertEqual(parse_hash_line("a" * 64 + "  eicar.com"), ("a" * 64, "eicar.com"))
        self.assertEqual(parse_hash_line("# comment"), None)
        self.assertEqual(parse_hash_line("not-a-hash"), None)
        hex_rule = parse_hex_line("4D5A??00 | mz_header | 80")
        self.assertIsNotNone(hex_rule)
        assert hex_rule is not None
        self.assertEqual(hex_rule["name"], "mz_header")
        self.assertEqual(hex_rule["score"], 80)
        regex_rule = parse_regex_line("EVIL_MARKER | marker | 60")
        self.assertEqual(regex_rule["name"], "marker")
        self.assertEqual(regex_rule["score"], 60)
        # 正则 pattern 里含 | 也不能被切坏
        regex_rule2 = parse_regex_line("foo|bar | alt | 60")
        self.assertEqual(regex_rule2["pattern"], "foo|bar")

    def test_elf_structural(self) -> None:
        info = parse_elf(make_elf_no_sections())
        self.assertIsNotNone(info)
        codes = [code for code, _detail in elf_anomalies(info)]
        self.assertIn("no_section_table", codes)

        info2 = parse_elf(make_elf_entry_writable())
        self.assertIsNotNone(info2)
        codes2 = [code for code, _detail in elf_anomalies(info2)]
        self.assertIn("entry_in_writable_segment", codes2)
        self.assertIn("no_section_table", codes2)

        self.assertIsNone(parse_elf(b"not an elf"))

    def test_pe_structural(self) -> None:
        info = parse_pe(make_pe_no_sections())
        self.assertIsNotNone(info)
        self.assertEqual(info["nsections"], 0)  # type: ignore[index]
        codes = [code for code, _detail in pe_anomalies(info)]
        self.assertIn("no_section_table", codes)
        self.assertIsNone(parse_pe(b"not a pe"))


class SigDbEngineTest(EngineTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.sample = self.write(
            "samples/sample.bin",
            b"PREFIX" + b"\x4d\x5a\x90\x00" + b"SUFFIX EVIL_MARKER",
        )
        self.hash = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        self.write("rules/sigdb/hashes.txt",
                   f"# sha256 演示\n{self.hash}  eicar-like-test\n")
        self.write("rules/sigdb/hex.txt", "4D5A??00 | mz_header | 80\n")
        self.write("rules/sigdb/regex.txt", "EVIL_MARKER | evil_marker | 60\n")
        self.cfg = self.make_cfg()
        self.engine = SigDbEngine(self.cfg)

    def test_reload_counts(self) -> None:
        result = self.engine.reload()
        self.assertEqual(result["hashes"], 1)
        self.assertEqual(result["hex"], 1)
        self.assertEqual(result["regex"], 1)
        self.assertEqual(result["errors"], [])
        self.assertTrue(self.engine.available())
        self.assertTrue(self.engine.supports({"size": 1024}))
        self.assertFalse(self.engine.supports({"size": 10 * 1024 * 1024 * 1024}))

    def test_scan_hash_hex_regex(self) -> None:
        hits = self.engine.scan(str(self.sample), {"size": self.sample.stat().st_size})
        by_engine = {hit["rule_id"]: hit for hit in hits}
        self.assertTrue(any(rule_id.startswith("hash:") for rule_id in by_engine))
        hash_hit = next(hit for hit in hits if hit["rule_id"].startswith("hash:"))
        self.assertEqual(hash_hit["score"], 100)
        self.assertEqual(hash_hit["evidence"]["sha256"], self.hash)
        self.assertEqual(hash_hit["evidence"]["matched"], "eicar-like-test")

        hex_hit = by_engine.get("hex:mz_header")
        self.assertIsNotNone(hex_hit)
        assert hex_hit is not None
        self.assertEqual(hex_hit["score"], 80)
        self.assertEqual(hex_hit["evidence"]["offset"], 6)
        self.assertEqual(hex_hit["evidence"]["matched"], "4D5A??00")

        regex_hit = by_engine.get("regex:evil_marker")
        self.assertIsNotNone(regex_hit)
        assert regex_hit is not None
        self.assertEqual(regex_hit["score"], 60)
        for hit in hits:
            self.assertEqual(hit["engine"], "sigdb")
            self.assertEqual(set(hit), {"engine", "rule_id", "name", "score", "meta", "evidence"})

    def test_entropy_hit(self) -> None:
        random_file = self.write("samples/random.bin", os.urandom(8192))
        hits = self.engine.scan(str(random_file), {"size": 8192})
        self.assertTrue(any(hit["rule_id"] == "entropy:high" for hit in hits))
        entropy_hit = next(hit for hit in hits if hit["rule_id"] == "entropy:high")
        self.assertEqual(entropy_hit["score"], 40)
        self.assertGreaterEqual(entropy_hit["evidence"]["entropy"], 7.2)

    def test_structural_hit(self) -> None:
        elf_file = self.write("samples/elf.bin", make_elf_no_sections())
        hits = self.engine.scan(str(elf_file), {"size": elf_file.stat().st_size})
        self.assertTrue(any(hit["rule_id"] == "struct:no_section_table" for hit in hits))
        struct_hit = next(hit for hit in hits if hit["rule_id"].startswith("struct:"))
        self.assertEqual(struct_hit["score"], 70)
        self.assertEqual(struct_hit["evidence"]["kind"], "elf")

    def test_missing_rule_files(self) -> None:
        cfg = self.make_cfg(rule_root=self.tmp / "empty-rules")
        engine = SigDbEngine(cfg)
        result = engine.reload()
        self.assertEqual(result["hashes"], 0)
        self.assertEqual(result["errors"], [])

    @unittest.skipUnless((ROOT / "rules" / "sigdb").is_dir(), "缺少 rules/sigdb 目录")
    def test_real_sigdb_rules(self) -> None:
        cfg = self.make_cfg(rule_root=ROOT / "rules")
        engine = SigDbEngine(cfg)
        result = engine.reload()
        self.assertEqual(result["errors"], [])
        self.assertGreaterEqual(result["hashes"], 1)
        self.assertGreaterEqual(result["hex"], 1)
        self.assertGreaterEqual(result["regex"], 1)


# ---------------------------------------------------------------------------
# Cascade / Contribution（全部使用假引擎，不依赖 yara/clamd）
# ---------------------------------------------------------------------------
class FakeEngine:
    """级联测试用假引擎。"""

    version = "test"

    def __init__(self, name: str, score: int = 0, cost: str = "fast",
                 available: bool = True, fail: bool = False, delay: float = 0.0):
        self.name = name
        self.score = score
        self.cost = cost
        self._available = available
        self.fail = fail
        self.delay = delay
        self.calls = 0

    def available(self) -> bool:
        return self._available

    def supports(self, ctx: dict) -> bool:
        return True

    def scan(self, path: str, ctx: dict) -> list[dict]:
        self.calls += 1
        if self.delay:
            import time as _time
            _time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("boom")
        if self.score <= 0:
            return []
        return [make_hit(self.name, f"{self.name}-rule", f"{self.name} hit", self.score,
                         {"mitre": ["T1000"]}, {"path": path})]


class CascadeTest(EngineTestBase):
    def _file(self, content: bytes = b"cascade test payload") -> Path:
        return self.write("sample.bin", content)

    def test_order_hits_first_hit(self) -> None:
        sample = self._file()
        sigdb = FakeEngine("sigdb", score=60)
        yara_engine = FakeEngine("yara", score=70)
        clamav = FakeEngine("clamav", score=95, cost="slow")
        cascade = Cascade(self.make_cfg(), [clamav, yara_engine, sigdb])
        result = cascade.scan(str(sample), deep=True)
        self.assertEqual(result["engines_used"], ["sigdb", "yara", "clamav"])
        self.assertEqual(result["first_hit"], "clamav")
        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["score"], 95)
        self.assertFalse(result["cached"])
        self.assertEqual(len(result["hits"]), 3)
        for hit in result["hits"]:
            self.assertEqual(set(hit), {"engine", "rule_id", "name", "score", "meta", "evidence"})
            self.assertTrue(hit["evidence"]["path"])

    def test_tie_first_hit_is_earliest(self) -> None:
        sample = self._file()
        cascade = Cascade(self.make_cfg(), [
            FakeEngine("yara", score=80), FakeEngine("sigdb", score=80),
        ])
        result = cascade.scan(str(sample))
        self.assertEqual(result["engines_used"], ["sigdb", "yara"])
        self.assertEqual(result["first_hit"], "sigdb")

    def test_deep_skips_slow_engine(self) -> None:
        sample = self._file()
        slow = FakeEngine("clamav", score=95, cost="slow")
        cascade = Cascade(self.make_cfg(), [slow])
        shallow = cascade.scan(str(sample), deep=False)
        self.assertEqual(shallow["engines_used"], [])
        self.assertEqual(slow.calls, 0)
        deep = cascade.scan(str(sample), deep=True)
        self.assertEqual(deep["engines_used"], ["clamav"])
        self.assertEqual(slow.calls, 1)

    def test_stop_score_breaks(self) -> None:
        sample = self._file()
        first = FakeEngine("sigdb", score=95)
        second = FakeEngine("yara", score=90)
        cascade = Cascade(self.make_cfg(), [first, second])
        result = cascade.scan(str(sample))
        self.assertEqual(result["engines_used"], ["sigdb"])
        self.assertEqual(second.calls, 0)

    def test_suspicious_threshold(self) -> None:
        sample = self._file()
        cascade = Cascade(self.make_cfg(), [FakeEngine("sigdb", score=60)])
        result = cascade.scan(str(sample))
        self.assertEqual(result["verdict"], "suspicious")
        self.assertEqual(result["first_hit"], "sigdb")

    def test_error_isolation_and_engine_stats(self) -> None:
        sample = self._file()
        store = self.open_store()
        broken = FakeEngine("sigdb", fail=True)
        good = FakeEngine("yara", score=60)
        cascade = Cascade(self.make_cfg(), [broken, good], store)
        result = cascade.scan(str(sample))
        self.assertEqual(result["engines_used"], ["yara"])
        self.assertEqual(result["verdict"], "suspicious")
        self.assertIn("sigdb", result["error"] or "")
        stats = {row["engine"]: row for row in store.engine_stats(days=1)}
        self.assertEqual(stats["sigdb"]["errors"], 1)
        self.assertEqual(stats["yara"]["files"], 1)
        self.assertEqual(stats["yara"]["hits"], 1)

    def test_hash_cache_short_circuit(self) -> None:
        sample = self._file()
        store = self.open_store()
        from hornwork.schema import sha256_file
        sha = sha256_file(str(sample))
        store.set_hash_cache(sha, "malicious")
        engine = FakeEngine("sigdb", score=95)
        cascade = Cascade(self.make_cfg(), [engine], store)
        result = cascade.scan(str(sample))
        self.assertTrue(result["cached"])
        self.assertEqual(result["engines_used"], ["hash"])
        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(engine.calls, 0)
        self.assertEqual(len(store.recent_scans(limit=10)), 1)

    def test_size_limit_only_hash(self) -> None:
        cfg = self.make_cfg()
        cfg["engines"]["max_size_mb"] = 1
        sample = self._file(b"\x00" * (1536 * 1024))
        engine = FakeEngine("sigdb", score=95)
        cascade = Cascade(cfg, [engine])
        result = cascade.scan(str(sample))
        self.assertTrue(result["partial"])
        self.assertEqual(result["engines_used"], ["hash"])
        self.assertEqual(result["verdict"], "clean")
        self.assertEqual(engine.calls, 0)
        self.assertIn("max_size", result["error"] or "")

    def test_budget_exhausted_partial(self) -> None:
        sample = self._file()
        # 第一个引擎耗时超过预算 → 后续引擎不再启动并标记 partial
        slow = FakeEngine("sigdb", score=0, delay=0.15)
        never = FakeEngine("yara", score=95)
        cascade = Cascade(self.make_cfg(), [slow, never])
        result = cascade.scan(str(sample), budget_ms=50)
        self.assertTrue(result["partial"])
        self.assertEqual(result["engines_used"], ["sigdb"])
        self.assertEqual(result["verdict"], "clean")
        self.assertIn("预算", result["error"] or "")
        self.assertEqual(never.calls, 0)

    def test_clean_scan_writes_row(self) -> None:
        sample = self._file()
        store = self.open_store()
        cascade = Cascade(self.make_cfg(), [FakeEngine("sigdb", score=0)], store)
        result = cascade.scan(str(sample))
        self.assertEqual(result["verdict"], "clean")
        self.assertEqual(result["score"], 0)
        rows = store.recent_scans(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "clean")
        self.assertEqual(rows[0]["path"], str(sample))

    def test_scan_writes_hash_cache_for_next_scan(self) -> None:
        sample = self._file(b"cache me")
        store = self.open_store()
        engine = FakeEngine("sigdb", score=75)
        cascade = Cascade(self.make_cfg(), [engine], store)
        first = cascade.scan(str(sample))
        self.assertFalse(first["cached"])
        self.assertEqual(first["verdict"], "suspicious")
        self.assertEqual(engine.calls, 1)
        self.assertEqual(store.get_hash_cache(first["sha256"]), "suspicious")
        second = cascade.scan(str(sample))
        self.assertTrue(second["cached"])
        self.assertEqual(second["engines_used"], ["hash"])
        self.assertEqual(second["verdict"], "suspicious")
        self.assertEqual(engine.calls, 1)  # 未再调用引擎

    def test_missing_file(self) -> None:
        cascade = Cascade(self.make_cfg(), [])
        result = cascade.scan(str(self.tmp / "nope.bin"))
        self.assertEqual(result["verdict"], "error")
        self.assertIn("不可读", result["error"] or "")

    def test_guess_filetype(self) -> None:
        self.assertEqual(guess_filetype(str(self.write("a.elf", make_elf_no_sections()))), "elf")
        self.assertEqual(guess_filetype(str(self.write("b.bin", b"MZ payload"))), "pe")


class ContributionTest(EngineTestBase):
    def test_record_and_queries(self) -> None:
        store = self.open_store()
        tracker = ContributionTracker(store)
        result = {
            "sha256": "a" * 64,
            "verdict": "malicious",
            "engines_used": ["sigdb", "yara"],
            "hits": [
                make_hit("sigdb", "r1", "n1", 90, {}, {}),
                make_hit("yara", "r2", "n2", 60, {}, {}),
            ],
            "engine_costs": {"sigdb": 3, "yara": 7},
            "stat_written": False,
        }
        tracker.record(result)
        self.assertEqual(store.get_hash_cache("a" * 64), "malicious")
        stats = {row["engine"]: row for row in store.engine_stats(days=1)}
        self.assertEqual(stats["sigdb"]["files"], 1)
        self.assertEqual(stats["sigdb"]["hits"], 1)
        self.assertEqual(stats["sigdb"]["malicious"], 1)
        self.assertEqual(stats["yara"]["malicious"], 0)
        table = tracker.engine_table(days=7)
        self.assertTrue(any(row["engine"] == "sigdb" for row in table))
        self.assertIsInstance(tracker.top(days=7), list)

        # stat_written=True：不重复累计引擎统计，但仍更新哈希缓存
        tracker.record({
            "sha256": "a" * 64, "verdict": "clean", "engines_used": ["sigdb"],
            "hits": [], "stat_written": True,
        })
        self.assertEqual(store.get_hash_cache("a" * 64), "clean")
        stats2 = {row["engine"]: row for row in store.engine_stats(days=1)}
        self.assertEqual(stats2["sigdb"]["files"], 1)

    def test_none_store_is_safe(self) -> None:
        tracker = ContributionTracker(None)
        tracker.record({"sha256": "b" * 64, "verdict": "clean"})
        self.assertEqual(tracker.top(), [])
        self.assertEqual(tracker.engine_table(), [])


# ---------------------------------------------------------------------------
# YARA / ClamAV（有依赖时跑真实链路，否则跳过）
# ---------------------------------------------------------------------------
class YaraEngineTest(EngineTestBase):
    YAR = """rule HornworkUnitTest {
  meta:
    description = "unit test marker"
    attack = "T1000"
    severity = 90
    source = "unit-test"
  strings:
    $marker = "HORNWORK_YARA_MARKER"
  condition:
    $marker
}
"""

    @unittest.skipUnless(_yara is not None, "未安装 yara-python")
    def test_compile_scan_and_reload(self) -> None:
        self.write("rules/yara/unit.yar", self.YAR)
        cfg = self.make_cfg()
        engine = YaraEngine(cfg)
        self.assertTrue(engine.available())
        result = engine.reload()
        self.assertTrue(result["ok"])
        self.assertEqual(result["rules"], 1)
        self.assertIsNone(result["error"])

        sample = self.write("samples/marker.bin", b"xx HORNWORK_YARA_MARKER yy")
        hits = engine.scan(str(sample), {"size": sample.stat().st_size})
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["engine"], "yara")
        self.assertEqual(hit["rule_id"], "HornworkUnitTest")
        self.assertEqual(hit["score"], 90)
        self.assertEqual(hit["meta"]["yara_meta"]["attack"], "T1000")
        self.assertEqual(hit["evidence"]["offset"], 3)
        self.assertEqual(hit["evidence"]["matched"], "$marker")

    @unittest.skipUnless(_yara is not None, "未安装 yara-python")
    def test_compile_error_keeps_old_rules(self) -> None:
        self.write("rules/yara/good.yar", self.YAR)
        cfg = self.make_cfg()
        engine = YaraEngine(cfg)
        self.assertEqual(engine.rule_count, 1)
        self.write("rules/yara/bad.yar", "rule Broken { condition: $undefined }")
        result = engine.reload()
        self.assertFalse(result["ok"])
        self.assertIsNotNone(result["error"])
        self.assertTrue(engine.available())      # 旧规则仍在
        sample = self.write("samples/marker.bin", b"HORNWORK_YARA_MARKER")
        self.assertEqual(len(engine.scan(str(sample), {"size": sample.stat().st_size})), 1)

    @unittest.skipUnless(_yara is None, "仅在未安装 yara-python 时验证降级行为")
    def test_unavailable_without_yara(self) -> None:
        engine = YaraEngine(self.make_cfg())
        self.assertFalse(engine.available())
        result = engine.reload()
        self.assertFalse(result["ok"])
        self.assertIn("yara", (result["error"] or "").lower())
        self.assertEqual(engine.scan("whatever", {}), [])

    @unittest.skipUnless(_yara is not None, "未安装 yara-python")
    @unittest.skipUnless((ROOT / "rules" / "yara").is_dir(), "缺少 rules/yara 目录")
    def test_real_yara_rules_compile(self) -> None:
        cfg = self.make_cfg(rule_root=ROOT / "rules")
        engine = YaraEngine(cfg)
        result = engine.reload()
        self.assertTrue(result["ok"], result["error"])
        self.assertGreaterEqual(result["rules"], 10)
        self.assertTrue(engine.available())


class ClamdClientTest(EngineTestBase):
    def test_parse_response(self) -> None:
        # 干净：真实 clamd 返回 "stream: OK"（可能带尾部空格 / \0 / 换行）
        for payload in ("stream: OK", "stream: OK ", "stream: OK\n",
                        "stream: OK\x00", "stream: OK \x00", "OK", "ok",
                        b"stream: OK\n"):
            self.assertEqual(_parse_response(payload, "/tmp/x"), [], payload)

        # 命中：签名名取 FOUND 之前、最后一个 ':' 之后的部分
        for payload, expected in (
            ("stream: Eicar-Test-Signature FOUND", "Eicar-Test-Signature"),
            ("stream: Eicar-Test-Signature FOUND\n", "Eicar-Test-Signature"),
            ("stream: Eicar-Test-Signature FOUND\x00", "Eicar-Test-Signature"),
            ("/tmp/eicar.com: Eicar-Test-Signature FOUND", "Eicar-Test-Signature"),
            ("Eicar-Test-Signature FOUND", "Eicar-Test-Signature"),
            (b"stream: Win.Test.EICAR_HDB-1 FOUND\n", "Win.Test.EICAR_HDB-1"),
        ):
            hits = _parse_response(payload, "/tmp/x")
            self.assertEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["engine"], "clamav")
            self.assertEqual(hits[0]["score"], 100)
            self.assertEqual(hits[0]["meta"]["signature"], expected)
            self.assertEqual(hits[0]["rule_id"], f"clamav:{expected}")

        # 异常响应/空响应必须抛 RuntimeError，由级联隔离并触发熔断
        for payload in ("INSTREAM size limit exceeded. ERROR",
                        "ERROR", "", "   ", None):
            with self.assertRaises(RuntimeError):
                _parse_response(payload, "/tmp/x")

    def test_read_response_strips_nul_for_ping(self) -> None:
        class _FakeSock:
            def __init__(self, payload: bytes):
                self.payload = payload

            def recv(self, size: int) -> bytes:
                data, self.payload = self.payload[:size], self.payload[size:]
                return data

        self.assertEqual(_read_response(_FakeSock(b"PONG\x00")), "PONG")  # type: ignore[arg-type]
        self.assertTrue(_PONG_RE.search(_read_response(_FakeSock(b"PONG\x00"))))  # type: ignore[arg-type]
        self.assertEqual(_read_response(_FakeSock(b"stream: OK \x00")), "stream: OK")  # type: ignore[arg-type]

    def test_supports_only_deep_and_size(self) -> None:
        cfg = self.make_cfg()
        engine = ClamavEngine(cfg)
        self.assertFalse(engine.supports({"deep": False, "size": 1024}))
        self.assertTrue(engine.supports({"deep": True, "size": 1024}))
        self.assertFalse(engine.supports({"deep": True, "size": 10 ** 12}))
        # socket 不存在时 available() 必须快速返回 False（并进入熔断）
        self.assertFalse(engine.available())
        self.assertFalse(engine.available())
        self.assertIsNotNone(engine.last_error)

    @unittest.skipUnless(sys.platform.startswith("linux"), "clamd 需要 Linux")
    def test_ping_unix_socket(self) -> None:
        cfg = self.make_cfg()
        engine = ClamavEngine(cfg)
        # 无 clamd 的环境直接验证 ping 返回 False 而不是抛异常
        self.assertFalse(clamd_ping(str(self.tmp / "no-such.sock"), timeout=0.2))
        self.assertFalse(engine.ping())


if __name__ == "__main__":
    unittest.main(verbosity=2)
