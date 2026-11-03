"""采集层单元测试：netdecode / auditd / proc / fim / authlog / memscan / netcap。

设计原则：
- 只测纯函数与不依赖 root/内核的能力，Windows 上必须全绿；
- Linux 专属用例（真实 /proc、inotify）用 `skipUnless(sys.platform.startswith("linux"))`；
- 不写系统临时目录（DSH 沙箱不可写），产物统一放 `tests/_tmp/<uuid>` 并在 tearDown 清理；
- 不访问网络、不启动真实抓包 socket。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import struct
import sys
import time
import unittest
import uuid
from pathlib import Path

# 说明：DSH 沙箱下系统临时目录不可写，统一把测试产物放到工作区 tests/_tmp
_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from hornwork.collectors import (  # noqa: E402
    AuditdCollector,
    AuthLogCollector,
    BruteForceTracker,
    FimCollector,
    MemoryScanner,
    NetPipeline,
    PersistenceChecker,
    ProcCollector,
)
from hornwork.collectors import netdecode  # noqa: E402
from hornwork.collectors.memscan import parse_maps_text  # noqa: E402
from hornwork.collectors.netcap import (  # noqa: E402
    _SimpleFlow,
    _SimpleTracker,
    resolve_ifaces,
)
from hornwork.collectors.proc import (  # noqa: E402
    diff_procs,
    read_connections,
    snapshot_procs,
)
from hornwork.store import Store  # noqa: E402

IS_LINUX = sys.platform.startswith("linux")

try:  # 网络规则引擎由 engines-dev 维护，缺失时跳过集成用例
    from hornwork.engines.netrules import NetRuleSet  # noqa: F401

    HAVE_NETRULES = True
except Exception:  # noqa: BLE001
    HAVE_NETRULES = False


def _mktemp(prefix: str) -> Path:
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = _TMP_ROOT / f"{prefix}-{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# 报文构造工具
# ---------------------------------------------------------------------------
_MAC_A = b"\x02\x00\x00\x00\x00\x01"
_MAC_B = b"\x02\x00\x00\x00\x00\x02"


def _eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return _MAC_A + _MAC_B + struct.pack("!H", ethertype) + payload


def _ipv4(payload: bytes, proto: int = 6, src: str = "10.0.0.1",
          dst: str = "10.0.0.2", total_len: int | None = None,
          frag: int = 0, ttl: int = 64) -> bytes:
    length = 20 + len(payload) if total_len is None else total_len
    return struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, length, 0x1234, frag, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + payload


def _tcp(sport: int, dport: int, flags: int = 0x02, payload: bytes = b"",
         data_offset: int = 5) -> bytes:
    return struct.pack(
        "!HHIIBBHHH", sport, dport, 1, 0, data_offset << 4, flags, 65535, 0, 0
    ) + payload


def _udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp(type_: int = 8, code: int = 0, payload: bytes = b"") -> bytes:
    return struct.pack("!BBHHH", type_, code, 0, 1, 2) + payload


def _ipv6(payload: bytes, next_header: int = 6, src: str = "2001:db8::1",
          dst: str = "2001:db8::2") -> bytes:
    header = struct.pack("!IHBB", 6 << 28, len(payload), next_header, 64)
    return (
        header
        + socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
        + payload
    )


def _dns_message(name: str, qtype: int = 1, msg_id: int = 0x1234,
                 flags: int = 0x0100) -> bytes:
    """手工拼一个单问题 DNS 报文（flags 默认 RD=1，即查询）。"""
    qname = b""
    for label in [part for part in name.strip(".").split(".") if part]:
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"
    return (
        struct.pack("!HHHHHH", msg_id, flags, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", qtype, 1)
    )


def _dns_udp_frame(name: str, sport: int = 40000, dport: int = 53,
                   qtype: int = 1, flags: int = 0x0100) -> bytes:
    return _eth(_ipv4(_udp(sport, dport, _dns_message(name, qtype, flags=flags)), proto=17))


def _dns_tcp_frame(name: str, sport: int = 40000, dport: int = 53) -> bytes:
    message = _dns_message(name)
    payload = struct.pack("!H", len(message)) + message
    tcp = _tcp(sport, dport, flags=0x18, payload=payload)
    return _eth(_ipv4(tcp))


# ---------------------------------------------------------------------------
# netdecode
# ---------------------------------------------------------------------------
class NetDecodeTest(unittest.TestCase):
    def test_tcp_syn(self):
        frame = _eth(_ipv4(_tcp(12345, 80, flags=netdecode.FLAG_SYN)))
        pkt = netdecode.decode(frame)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt["src_ip"], "10.0.0.1")
        self.assertEqual(pkt["dst_ip"], "10.0.0.2")
        self.assertEqual(pkt["proto"], "tcp")
        self.assertEqual(pkt["proto_num"], 6)
        self.assertEqual(pkt["src_port"], 12345)
        self.assertEqual(pkt["dst_port"], 80)
        self.assertEqual(pkt["flags"], netdecode.FLAG_SYN)
        self.assertEqual(pkt["ethertype"], 0x0800)
        self.assertFalse(pkt["malformed"])
        self.assertEqual(pkt["raw_len"], len(frame))
        self.assertEqual(pkt["ip_len"], 40)
        self.assertGreater(pkt["ts"], 0)
        self.assertRegex(pkt["ts_iso"], r"^\d{4}-\d{2}-\d{2}T.*Z$")

    def test_tcp_payload_and_flags(self):
        frame = _eth(_ipv4(_tcp(443, 5555, flags=0x18, payload=b"hello")))
        pkt = netdecode.decode(frame)
        self.assertEqual(pkt["payload_len"], 5)
        self.assertEqual(netdecode.parse_flags(pkt["flags"]), {"psh", "ack"})

    def test_udp(self):
        frame = _eth(_ipv4(_udp(5353, 53, b"abc"), proto=17))
        pkt = netdecode.decode(frame)
        self.assertEqual(pkt["proto"], "udp")
        self.assertEqual(pkt["src_port"], 5353)
        self.assertEqual(pkt["dst_port"], 53)
        self.assertEqual(pkt["payload_len"], 3)
        self.assertFalse(pkt["malformed"])

    def test_icmp(self):
        frame = _eth(_ipv4(_icmp(8, 0), proto=1))
        pkt = netdecode.decode(frame)
        self.assertEqual(pkt["proto"], "icmp")
        self.assertEqual(pkt["icmp_type"], 8)
        self.assertEqual(pkt["icmp_code"], 0)
        self.assertEqual(pkt["src_port"], None)

    def test_ipv6_tcp(self):
        frame = _eth(_ipv6(_tcp(40000, 22, flags=0x02)), ethertype=0x86DD)
        pkt = netdecode.decode(frame)
        self.assertEqual(pkt["ethertype"], 0x86DD)
        self.assertEqual(pkt["src_ip"], "2001:db8::1")
        self.assertEqual(pkt["dst_ip"], "2001:db8::2")
        self.assertEqual(pkt["proto"], "tcp")
        self.assertEqual(pkt["dst_port"], 22)
        self.assertEqual(pkt["ttl"], 64)

    def test_short_frame_is_malformed(self):
        pkt = netdecode.decode(b"\x00" * 10)
        self.assertIsNotNone(pkt)
        self.assertTrue(pkt["malformed"])
        self.assertEqual(pkt["raw_len"], 10)

    def test_empty_frame_returns_none(self):
        self.assertIsNone(netdecode.decode(b""))
        self.assertIsNone(netdecode.decode(None))

    def test_truncated_ipv4(self):
        frame = _eth(_ipv4(_tcp(1, 2), total_len=200))
        pkt = netdecode.decode(frame)
        self.assertTrue(pkt["malformed"])
        # 仍能解出五元组
        self.assertEqual(pkt["dst_port"], 2)

    def test_syn_fin_contradiction(self):
        frame = _eth(_ipv4(_tcp(1, 2, flags=netdecode.FLAG_SYN | netdecode.FLAG_FIN)))
        self.assertTrue(netdecode.decode(frame)["malformed"])

    def test_bad_tcp_data_offset(self):
        frame = _eth(_ipv4(_tcp(1, 2, data_offset=2)))
        self.assertTrue(netdecode.decode(frame)["malformed"])

    def test_parse_flags(self):
        self.assertEqual(netdecode.parse_flags(0), set())
        self.assertEqual(netdecode.parse_flags(0x12), {"syn", "ack"})
        self.assertEqual(
            netdecode.parse_flags(0xFF), {"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}
        )
        self.assertEqual(netdecode.FLAG_SYN, 0x02)
        self.assertEqual(netdecode.FLAG_ACK, 0x10)

    def test_arp_not_malformed(self):
        frame = _eth(b"\x00" * 28, ethertype=0x0806)
        pkt = netdecode.decode(frame)
        self.assertEqual(pkt["proto"], "arp")
        self.assertFalse(pkt["malformed"])

    def test_bytearray_input(self):
        frame = bytearray(_eth(_ipv4(_tcp(1, 2))))
        self.assertEqual(netdecode.decode(frame)["proto"], "tcp")

    # ---- DNS 查询名 --------------------------------------
    def test_dns_query_udp(self):
        frame = _dns_udp_frame("IOC.Example.")
        pkt = netdecode.decode(frame)
        self.assertEqual(pkt["domain"], "ioc.example")       # 小写、去末尾点
        self.assertEqual(pkt["dns_qtype"], 1)                # A 记录
        self.assertFalse(pkt["dns_is_response"])
        self.assertFalse(pkt["malformed"])
        self.assertEqual(pkt["dst_port"], 53)

    def test_dns_query_tcp_skips_length_prefix(self):
        pkt = netdecode.decode(_dns_tcp_frame("c2.bad-domain.test"))
        self.assertEqual(pkt["domain"], "c2.bad-domain.test")
        self.assertEqual(pkt["dns_qtype"], 1)
        self.assertFalse(pkt["dns_is_response"])
        self.assertFalse(pkt["malformed"])

    def test_dns_response_flag(self):
        # flags=0x8180：QR=1 → 响应
        pkt = netdecode.decode(_dns_udp_frame("ioc.example", flags=0x8180))
        self.assertTrue(pkt["dns_is_response"])
        self.assertEqual(pkt["domain"], "ioc.example")

    def test_dns_only_on_port_53(self):
        pkt = netdecode.decode(_dns_udp_frame("ioc.example", dport=5353))
        self.assertNotIn("domain", pkt)
        self.assertFalse(pkt["malformed"])
        # 源端口 53 的响应方向同样解析
        pkt = netdecode.decode(_dns_udp_frame("ioc.example", sport=53, dport=40000,
                                              flags=0x8180))
        self.assertEqual(pkt["domain"], "ioc.example")

    def test_dns_malformed_does_not_set_malformed(self):
        # 1) 载荷不足 12 字节
        short = _eth(_ipv4(_udp(40000, 53, b"\x01\x02"), proto=17))
        pkt = netdecode.decode(short)
        self.assertNotIn("domain", pkt)
        self.assertFalse(pkt["malformed"])

        # 2) 压缩指针自环（12 字节头 + 指向自身的指针）
        loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c"
        frame = _eth(_ipv4(_udp(40000, 53, loop), proto=17))
        pkt = netdecode.decode(frame)
        self.assertNotIn("domain", pkt)
        self.assertFalse(pkt["malformed"])

        # 3) 标签长度越界
        bad_label = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x3f" + b"ab"
        frame = _eth(_ipv4(_udp(40000, 53, bad_label), proto=17))
        pkt = netdecode.decode(frame)
        self.assertNotIn("domain", pkt)
        self.assertFalse(pkt["malformed"])

    def test_dns_compression_pointer_basic(self):
        # 问题名本身用压缩指针指向 offset=18 的真实域名（RFC1035 指针的常见用法）
        name = b"\x03ioc\x07example\x00"
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        message = header + b"\xc0\x12" + struct.pack("!HH", 1, 1) + name
        pkt = netdecode.decode(_eth(_ipv4(_udp(40000, 53, message), proto=17)))
        self.assertEqual(pkt["domain"], "ioc.example")
        self.assertEqual(pkt["dns_qtype"], 1)
        self.assertFalse(pkt["malformed"])


# ---------------------------------------------------------------------------
# auditd
# ---------------------------------------------------------------------------
_SYSCALL_LINE = (
    'type=SYSCALL msg=audit(1698312345.678:1001): arch=c000003e syscall=59 success=yes '
    'exit=0 pid=1234 ppid=1 uid=0 exe="/usr/bin/cat" key="hornwork_exec"'
)


class AuditdTest(unittest.TestCase):
    def test_parse_line(self):
        rec = AuditdCollector.parse_line(_SYSCALL_LINE)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["type"], "SYSCALL")
        self.assertEqual(rec["id"], 1001)
        self.assertEqual(rec["fields"]["syscall"], "59")
        self.assertEqual(rec["fields"]["exe"], "/usr/bin/cat")
        self.assertEqual(rec["fields"]["key"], "hornwork_exec")
        self.assertRegex(rec["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_parse_non_audit_line(self):
        self.assertIsNone(AuditdCollector.parse_line(""))
        self.assertIsNone(AuditdCollector.parse_line("Oct 26 20:00:00 host sshd[1]: hello"))
        self.assertIsNone(AuditdCollector.parse_line("----"))

    def test_assemble_execve_hex_args(self):
        hex_arg = "/etc/passwd".encode().hex()
        lines = [
            _SYSCALL_LINE,
            "type=EXECVE msg=audit(1698312345.678:1001): argc=2 a0=\"cat\" " + f"a1={hex_arg}",
            'type=CWD msg=audit(1698312345.678:1001): cwd="/root"',
        ]
        records = [AuditdCollector.parse_line(line) for line in lines]
        asm = AuditdCollector.assemble([r for r in records if r])
        self.assertIsNotNone(asm)
        self.assertEqual(asm["event_type"], "process_create")
        self.assertEqual(asm["process"]["pid"], 1234)
        self.assertEqual(asm["process"]["cmdline"], "cat /etc/passwd")
        self.assertEqual(asm["process"]["image"], "/usr/bin/cat")
        self.assertEqual(asm["raw"]["audit_id"], 1001)
        self.assertEqual(asm["rule"]["raw"]["key"], "hornwork_exec")

    def test_assemble_identity_key(self):
        lines = [
            'type=SYSCALL msg=audit(1698312400.100:2002): syscall=257 pid=999 uid=0 '
            'success=yes key="hornwork_identity"',
            'type=PATH msg=audit(1698312400.100:2002): item=0 name="/etc/shadow" '
            "inode=123 nametype=NORMAL mode=0100640",
        ]
        asm = AuditdCollector.assemble([AuditdCollector.parse_line(x) for x in lines])
        self.assertEqual(asm["event_type"], "file_modify")
        self.assertEqual(asm["file"]["path"], "/etc/shadow")
        self.assertEqual(asm["user"]["uid"], 0)

    def test_assemble_persist_key(self):
        lines = [
            'type=SYSCALL msg=audit(1698312500.500:3003): syscall=257 pid=7 uid=0 key="hornwork_persist"',
            'type=PATH msg=audit(1698312500.500:3003): item=0 name="/etc/cron.d/x" inode=9 nametype=CREATE',
        ]
        asm = AuditdCollector.assemble([AuditdCollector.parse_line(x) for x in lines])
        self.assertEqual(asm["event_type"], "persist_item")
        self.assertEqual(asm["file"]["path"], "/etc/cron.d/x")

    def test_assemble_relative_path_uses_cwd(self):
        lines = [
            'type=SYSCALL msg=audit(1698312600.1:4004): syscall=257 pid=8 uid=0 key="hornwork_identity"',
            'type=CWD msg=audit(1698312600.1:4004): cwd="/etc"',
            'type=PATH msg=audit(1698312600.1:4004): item=0 name="passwd" inode=3 nametype=NORMAL',
        ]
        asm = AuditdCollector.assemble([AuditdCollector.parse_line(x) for x in lines])
        self.assertEqual(asm["file"]["path"], "/etc/passwd")

    def test_assemble_proctitle_fallback(self):
        proctitle = "vim\x00/etc/passwd".encode().hex()
        lines = [
            'type=SYSCALL msg=audit(1698312700.1:5005): syscall=59 pid=11 uid=0 exe="/usr/bin/vim"',
            f"type=PROCTITLE msg=audit(1698312700.1:5005): proctitle={proctitle}",
        ]
        asm = AuditdCollector.assemble([AuditdCollector.parse_line(x) for x in lines])
        self.assertEqual(asm["event_type"], "process_create")
        self.assertEqual(asm["process"]["cmdline"], "vim /etc/passwd")

    def test_assemble_unmappable_returns_none(self):
        line = 'type=CWD msg=audit(1698312800.1:6006): cwd="/root"'
        self.assertIsNone(AuditdCollector.assemble([AuditdCollector.parse_line(line)]))
        self.assertIsNone(AuditdCollector.assemble([]))

    def test_tail_emits_assembled_event(self):
        """文件 tail + 2s 拼装窗口 + emit 的端到端链路（跨平台，无需 root）。"""
        tmp = _mktemp("auditd")
        log_path = tmp / "audit.log"
        log_path.write_text("", encoding="utf-8")
        events: list[dict] = []
        cfg = {
            "general": {"host_id": "test-host"},
            "collect": {
                "auditd": {
                    "log_path": str(log_path),
                    "assemble_window_ms": 50,
                    "poll_interval_ms": 20,
                }
            },
        }
        collector = AuditdCollector(cfg, events.append)
        collector.start()
        try:
            time.sleep(0.15)
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(_SYSCALL_LINE + "\n")
                handle.write(
                    'type=EXECVE msg=audit(1698312345.678:1001): argc=2 a0="cat" '
                    + f"a1={'/etc/passwd'.encode().hex()}\n"
                )
                handle.flush()
            deadline = time.time() + 3.0
            while time.time() < deadline and not events:
                time.sleep(0.05)
        finally:
            collector.stop()
        self.assertTrue(events, "auditd tail 未产出事件")
        self.assertEqual(events[0]["event_type"], "process_create")
        self.assertEqual(events[0]["process"]["cmdline"], "cat /etc/passwd")
        self.assertEqual(collector.status()["stats"]["events"], 1)
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# proc
# ---------------------------------------------------------------------------
class ProcTest(unittest.TestCase):
    @staticmethod
    def _proc(pid: int, starttime: int) -> dict:
        return {
            "pid": pid, "ppid": 1, "uid": 0, "threads": 1,
            "image": "/usr/bin/x", "cmdline": "x", "starttime": starttime, "state": "S",
        }

    def test_diff_created_exited_changed(self):
        prev = {1: self._proc(1, 100), 2: self._proc(2, 200)}
        cur = {2: self._proc(2, 200), 3: self._proc(3, 300)}
        created, exited, changed = diff_procs(prev, cur)
        self.assertEqual([p["pid"] for p in created], [3])
        self.assertEqual([p["pid"] for p in exited], [1])
        self.assertEqual(changed, [])

    def test_pid_reuse_is_changed(self):
        prev = {2: self._proc(2, 200)}
        cur = {2: self._proc(2, 999)}
        created, exited, changed = diff_procs(prev, cur)
        self.assertEqual(created, [])
        self.assertEqual(exited, [])
        self.assertEqual([p["pid"] for p in changed], [2])

    def test_snapshot_returns_dict(self):
        snap = snapshot_procs()
        self.assertIsInstance(snap, dict)
        if IS_LINUX:
            self.assertIn(os.getpid(), snap)
            self.assertEqual(snap[os.getpid()]["pid"], os.getpid())
        else:
            self.assertEqual(snap, {})

    def test_read_connections_returns_list(self):
        conns = read_connections()
        self.assertIsInstance(conns, list)
        for conn in conns[:5]:
            self.assertIn("proto", conn)
            self.assertIn("local_ip", conn)
            self.assertIn("inode", conn)
            self.assertIsInstance(conn["inode"], int)

    def test_collector_status_contract(self):
        collector = ProcCollector({}, lambda event: None)
        status = collector.status()
        self.assertEqual(status["name"], "proc")
        self.assertIn("running", status)
        self.assertIn("stats", status)
        self.assertIsInstance(status["errors"], int)


# ---------------------------------------------------------------------------
# fim
# ---------------------------------------------------------------------------
class FimTest(unittest.TestCase):
    def setUp(self):
        self.tmp = _mktemp("fim")
        self.data = self.tmp / "data"
        self.data.mkdir()
        (self.data / "a.conf").write_text("alpha", encoding="utf-8")
        (self.data / "b.conf").write_text("beta", encoding="utf-8")
        self.store = Store(self.tmp / "t.db")

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _collector(self) -> FimCollector:
        cfg = {
            "collect": {"fim": {"dirs": [str(self.data)], "baseline": False, "debounce_ms": 10}},
            "general": {"raw_dir": str(self.tmp / "raw"), "host_id": "test-host"},
        }
        return FimCollector(cfg, lambda event: None, store=self.store)

    def test_baseline_not_rebuilt_when_exists(self):
        collector = self._collector()
        self.assertEqual(collector.build_baseline(), 2)
        (self.data / "d.conf").write_text("delta", encoding="utf-8")
        collector._ensure_baseline()  # 已有基线 → 不重建
        self.assertEqual(len(self.store.baseline_all()), 2)
        self.assertEqual(collector.status()["stats"]["baseline_files"], 2)

    def test_build_baseline_and_diff(self):
        collector = self._collector()
        count = collector.build_baseline()
        self.assertEqual(count, 2)
        self.assertEqual(len(self.store.baseline_all()), 2)

        # 新增文件 → reason=new
        (self.data / "c.conf").write_text("gamma", encoding="utf-8")
        time.sleep(0.02)
        changes = collector.diff_baseline()
        self.assertTrue(any(c["reason"] == "new" and c["path"].endswith("c.conf") for c in changes))

        # 内容变化 → reason=sha256
        time.sleep(0.02)
        (self.data / "a.conf").write_text("alpha-changed", encoding="utf-8")
        changes = collector.diff_baseline()
        self.assertTrue(any(c["path"].endswith("a.conf") for c in changes))

    def test_debounce_merges_events(self):
        emitted: list[dict] = []
        cfg = {"collect": {"fim": {"dirs": [str(self.data)], "debounce_ms": 50}}}
        collector = FimCollector(cfg, emitted.append)
        collector._enqueue("file_modify", "/tmp/x", False)
        collector._enqueue("file_create", "/tmp/x", False)
        self.assertEqual(collector._pending["/tmp/x"]["kind"], "file_create")
        # 轮询到去抖窗口结束，避免依赖系统时钟精度导致的间歇性失败
        deadline = time.time() + 2.0
        while time.time() < deadline and not emitted:
            time.sleep(0.01)
            collector._flush_pending()
        self.assertEqual(
            len(emitted), 1, f"未投递事件（errors={collector.status()['errors']}）"
        )
        self.assertEqual(emitted[0]["event_type"], "file_create")

    @unittest.skipIf(IS_LINUX, "Linux 上会真正启动 inotify，避免污染测试进程")
    def test_start_without_inotify_does_not_raise(self):
        collector = self._collector()
        collector.start()  # 非 Linux：记 WARN 后返回
        self.assertFalse(collector.status()["running"])
        collector.stop()


# ---------------------------------------------------------------------------
# authlog
# ---------------------------------------------------------------------------
class AuthLogTest(unittest.TestCase):
    def test_parse_failed(self):
        from hornwork.collectors.authlog import parse_line

        line = (
            "Oct 26 20:10:57 lab-vm sshd[1234]: Failed password for invalid user admin "
            "from 192.168.56.50 port 55123 ssh2"
        )
        info = parse_line(line)
        self.assertEqual(info["kind"], "failed")
        self.assertEqual(info["user"], "admin")
        self.assertEqual(info["src_ip"], "192.168.56.50")
        self.assertRegex(info["ts"], r"^\d{4}-\d{2}-\d{2}T.*Z$")

    def test_parse_accepted(self):
        from hornwork.collectors.authlog import parse_line

        line = "Oct 26 20:11:00 lab-vm sshd[1]: Accepted publickey for root from 10.0.0.5 port 22 ssh2"
        info = parse_line(line)
        self.assertEqual(info["kind"], "accepted")
        self.assertEqual(info["user"], "root")
        self.assertEqual(info["src_ip"], "10.0.0.5")

    def test_parse_account(self):
        from hornwork.collectors.authlog import parse_line

        line = "Oct 26 20:12:00 lab-vm useradd[900]: new user: name=evil, UID=0, GID=0, home=/home/evil"
        info = parse_line(line)
        self.assertEqual(info["kind"], "account")
        self.assertEqual(info["user"], "evil")

    def test_parse_irrelevant(self):
        from hornwork.collectors.authlog import parse_line

        self.assertIsNone(parse_line("Oct 26 20:13:00 lab-vm CRON[1]: (root) CMD (ls)"))
        self.assertIsNone(parse_line(""))

    def test_bruteforce_trigger(self):
        tracker = BruteForceTracker(threshold=5, window=300)
        for index in range(5):
            self.assertIsNone(tracker.add("192.168.56.50", 1000.0 + index, False))
        info = tracker.add("192.168.56.50", 1100.0, True)
        self.assertIsNotNone(info)
        self.assertEqual(info["failures"], 5)
        self.assertEqual(info["src_ip"], "192.168.56.50")
        # 触发后计数复位
        self.assertIsNone(tracker.add("192.168.56.50", 1200.0, True))

    def test_bruteforce_no_trigger(self):
        tracker = BruteForceTracker(threshold=5, window=300)
        for index in range(4):
            tracker.add("10.0.0.9", 2000.0 + index, False)
        self.assertIsNone(tracker.add("10.0.0.9", 2100.0, True))

    def test_bruteforce_window_expired(self):
        tracker = BruteForceTracker(threshold=2, window=10)
        tracker.add("10.0.0.7", 100.0, False)
        tracker.add("10.0.0.7", 105.0, False)
        # 成功时间超出窗口，旧失败被裁掉
        self.assertIsNone(tracker.add("10.0.0.7", 200.0, True))

    def test_collector_status_contract(self):
        collector = AuthLogCollector({}, lambda event: None)
        status = collector.status()
        self.assertEqual(status["name"], "authlog")
        self.assertIsInstance(status["errors"], int)


# ---------------------------------------------------------------------------
# memscan
# ---------------------------------------------------------------------------
_MAPS_SAMPLE = """\
55d4a0f000-55d4a0f000 r-xp 00000000 08:01 11 /usr/bin/cat
55d4a0f000-55d4a10000 r-xp 00000000 08:01 11 /usr/bin/cat
55d4a10000-55d4a11000 rw-p 00000000 08:01 11 /usr/bin/cat
7f0000000000-7f0000001000 rwxp 00000000 00:00 0
7f0000001000-7f0000002000 r-xp 00000000 00:00 0 [vdso]
7f0000002000-7f0000003000 r-xp 00000000 00:00 0 /memfd:inject (deleted)
"""


class MemScanTest(unittest.TestCase):
    def test_parse_maps_text(self):
        regions = parse_maps_text(_MAPS_SAMPLE)
        self.assertEqual(len(regions), 5)
        # 前两行同权限同路径同 inode → 合并
        self.assertEqual(regions[0]["start"], 0x55D4A0F000)
        self.assertEqual(regions[0]["end"], 0x55D4A10000)
        self.assertEqual(regions[0]["pathname"], "/usr/bin/cat")
        self.assertEqual(regions[0]["perms"], "r-xp")
        # 匿名可执行段
        self.assertEqual(regions[2]["pathname"], None)
        self.assertEqual(regions[2]["perms"], "rwxp")
        # 特殊段
        self.assertEqual(regions[3]["pathname"], "[vdso]")
        self.assertEqual(regions[4]["pathname"], "/memfd:inject (deleted)")

    def test_parse_maps_text_skips_malformed(self):
        text = "\n".join([
            "not-a-map-line",
            "zz-100 r-xp 0 0 0 /x",
            "1000-2000 r-xp 00000000 00:00 5 /ok",
        ])
        regions = parse_maps_text(text)
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0]["pathname"], "/ok")
        self.assertEqual(regions[0]["inode"], 5)

    def test_scan_pid_returns_error_on_non_linux(self):
        scanner = MemoryScanner({})
        result = scanner.scan_pid(1)
        self.assertIn("pid", result)
        self.assertIn("regions", result)
        self.assertIn("hits", result)
        if not IS_LINUX:
            self.assertIn("error", result)
            self.assertEqual(result["hits"], [])

    @unittest.skipUnless(IS_LINUX, "需要真实 /proc")
    def test_parse_maps_of_self(self):
        from hornwork.collectors.memscan import parse_maps

        regions = parse_maps(os.getpid())
        self.assertTrue(regions)
        self.assertTrue(all(r["end"] > r["start"] for r in regions))
        self.assertTrue(any(r["pathname"] for r in regions))

    @unittest.skipUnless(IS_LINUX, "需要真实 /proc")
    def test_scan_self_smoke(self):
        scanner = MemoryScanner({})
        result = scanner.scan_pid(os.getpid())
        self.assertEqual(result["pid"], os.getpid())
        self.assertNotIn("error", result)

    def test_verify_snapshot(self):
        tmp = _mktemp("memsnap")
        try:
            regions_dir = tmp / "regions"
            regions_dir.mkdir()
            data = b"payload-bytes"
            (regions_dir / "1000-2000.bin").write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            hit = {
                "pid": 42, "start": 0x1000, "end": 0x2000, "perms": "rwxp",
                "pathname": None, "kind": "anon_rwx", "sha256": digest, "bytes": len(data),
            }
            (tmp / "maps.txt").write_text("1000-2000 rwxp 00000000 00:00 0\n", encoding="utf-8")
            (tmp / "hits.json").write_text(json.dumps([hit]), encoding="utf-8")

            scanner = MemoryScanner({})
            report = scanner.verify(str(tmp))
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["hits"], 1)
            self.assertEqual(report["regions"], 1)

            # 篡改 region 文件 → 复核失败
            (regions_dir / "1000-2000.bin").write_bytes(b"tampered")
            report = scanner.verify(str(tmp))
            self.assertFalse(report["ok"])
            self.assertTrue(report["mismatch"])

            self.assertFalse(scanner.verify(str(tmp / "missing"))["ok"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_snapshot_dir_layout(self):
        tmp = _mktemp("memraw")
        try:
            scanner = MemoryScanner(
                {"general": {"raw_dir": str(tmp), "host_id": "test-host"}}
            )
            snapshot_dir = scanner._new_snapshot_dir(1234)
            self.assertTrue(os.path.isdir(snapshot_dir))
            self.assertTrue(os.path.isdir(os.path.join(snapshot_dir, "regions")))
            self.assertIn("mem", snapshot_dir)
            self.assertIn("1234", snapshot_dir)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_snapshot_files_roundtrip_verify(self):
        """snapshot 落盘格式（hits.json 为 {"hits":[...]}）必须能被 verify() 复核。"""
        tmp = _mktemp("memround")
        try:
            scanner = MemoryScanner({})
            snapshot_dir = str(tmp / "snap")
            os.makedirs(os.path.join(snapshot_dir, "regions"))
            data = b"\x7fELF-fake-payload"
            hit = {
                "pid": 42, "start": 0x400000, "end": 0x401000, "perms": "rwxp",
                "pathname": None, "kind": "anon_rwx", "elf": True, "pe": False,
                "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            }
            scanner._write_region(snapshot_dir, hit, data)
            scanner._write_snapshot_files(
                snapshot_dir, "400000-401000 rwxp 00000000 00:00 0\n", [hit],
                {"pid": 42, "verdict": "observed", "score": 40},
            )
            report = scanner.verify(snapshot_dir)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["hits"], 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# persist
# ---------------------------------------------------------------------------
class PersistTest(unittest.TestCase):
    @unittest.skipIf(
        IS_LINUX, "Linux 上 run_checks 会读取真实 /proc 与 /etc，保持单测无副作用"
    )
    def test_run_checks_structure(self):
        checker = PersistenceChecker({}, None, lambda event: None, lambda alert: None)
        results = checker.run_checks()
        self.assertEqual(len(results), 7)
        names = [item["check"] for item in results]
        self.assertEqual(
            names,
            ["hidden_process", "fileless", "ld_preload", "kernel_module",
             "persist_item", "account_anomaly", "suid_new"],
        )
        for item in results:
            self.assertIn("findings", item)
            self.assertIn("errors", item)
            self.assertIsInstance(item["findings"], list)
            self.assertIsInstance(item["errors"], list)
        # 非 Linux：至少隐藏进程/无文件/内核模块应给出降级说明
        errors = {item["check"]: item["errors"] for item in results}
        self.assertTrue(errors["hidden_process"])
        self.assertTrue(errors["fileless"])
        self.assertTrue(errors["kernel_module"])

    def test_status_contract(self):
        checker = PersistenceChecker({}, None, lambda event: None)
        status = checker.status()
        self.assertEqual(status["name"], "persist")
        self.assertIsInstance(status["stats"], dict)
        self.assertIsInstance(status["errors"], int)


# ---------------------------------------------------------------------------
# netcap
# ---------------------------------------------------------------------------
class NetPipelineTest(unittest.TestCase):
    def _pipeline(self, **cfg_overrides) -> NetPipeline:
        cfg = {
            "general": {"rule_dir": str(_REPO_ROOT / "rules"), "host_id": "test-host"},
            "engines": {"net_rule_dir": str(_REPO_ROOT / "rules" / "net")},
            "net": {"home_net": "10.1.1.0/24", "dedup_sec": 60},
            "collect": {"net": {"iface": "any", "emit_flow_event": True}},
            "bus": {"frame_queue_max": 1024},
        }
        cfg.update(cfg_overrides)
        return NetPipeline(cfg, lambda event: None, lambda alert: None)

    def test_status_contract_and_counters(self):
        pipeline = self._pipeline()
        status = pipeline.status()
        self.assertEqual(status["name"], "netcap")
        self.assertFalse(status["running"])
        stats = status["stats"]
        for key in ("received", "decoded", "dropped", "malformed", "flow_table_size"):
            self.assertIn(key, stats)
        self.assertIn("tracker", stats)

    def test_reload_shape(self):
        pipeline = self._pipeline()
        result = pipeline.reload()
        self.assertIn("ok", result)
        self.assertIn("rules", result)
        self.assertIn("errors", result)
        self.assertIsInstance(result["rules"], int)
        self.assertIsInstance(result["errors"], list)

    def test_decode_pipeline_and_flow_events(self):
        events: list[dict] = []
        pipeline = NetPipeline(
            self._pipeline().cfg, events.append, lambda alert: None
        )
        frame = _eth(_ipv4(_tcp(40000, 8080, flags=0x02, payload=b"x" * 16)))
        pipeline.process_frame(frame)
        stats = pipeline.status()["stats"]
        self.assertEqual(stats["decoded"], 1)
        self.assertEqual(stats["flow_table_size"], 1)
        self.assertEqual(stats["flow_events"], 1)
        self.assertEqual(events[0]["event_type"], "net_connect")
        self.assertEqual(events[0]["network"]["dst_port"], 8080)

    def test_malformed_frame_counted(self):
        pipeline = self._pipeline()
        pipeline.process_frame(b"\x00" * 8)
        self.assertGreaterEqual(pipeline.status()["stats"]["decoded"], 1)
        self.assertGreaterEqual(pipeline.status()["stats"]["malformed"], 1)

    def test_dns_query_event_and_dedupe(self):
        events: list[dict] = []
        pipeline = NetPipeline(self._pipeline().cfg, events.append, lambda alert: None)
        frame = _dns_udp_frame("IOC.Example")
        pipeline.process_frame(frame)
        pipeline.process_frame(frame)  # 5 s 内同 (src_ip, domain) 只发一次
        dns_events = [e for e in events if e.get("event_type") == "dns_query"]
        self.assertEqual(len(dns_events), 1)
        event = dns_events[0]
        self.assertEqual(event["source_layer"], "net")
        self.assertEqual(event["network"]["domain"], "ioc.example")
        self.assertEqual(event["network"]["dst_port"], 53)
        self.assertEqual(event["network"]["direction"], "outbound")
        self.assertEqual(event["raw"]["dns_qtype"], 1)
        stats = pipeline.status()["stats"]
        self.assertEqual(stats["dns_events"], 1)
        self.assertEqual(stats["dns_deduped"], 1)

    def test_dns_response_does_not_emit_query_event(self):
        events: list[dict] = []
        pipeline = NetPipeline(self._pipeline().cfg, events.append, lambda alert: None)
        pipeline.process_frame(_dns_udp_frame("ioc.example", sport=53, dport=40000,
                                              flags=0x8180))
        self.assertFalse([e for e in events if e.get("event_type") == "dns_query"])
        self.assertEqual(pipeline.status()["stats"]["dns_events"], 0)

    @unittest.skipUnless(HAVE_NETRULES, "NetRuleSet 不可用")
    def test_dns_domain_hits_ioc_netrule(self):
        """DNS 查询名进入 NetRuleSet.evaluate，可按 IOC 域名命中（N-0103 同类规则）。"""
        tmp = _mktemp("netrules")
        try:
            (tmp / "dns-ioc.rules").write_text(
                "rule T-9001 dns_ioc_outbound {\n"
                "  proto: any\n"
                "  dst_domain_in: ioc_domains\n"
                "  severity: 10\n"
                "  technique: T1071.001\n"
                '  msg: "出站命中威胁情报域名"\n'
                "}\n",
                encoding="utf-8",
            )
            cfg = {
                "general": {"rule_dir": str(tmp), "host_id": "test-host"},
                "engines": {"net_rule_dir": str(tmp)},
                "net": {"home_net": "10.0.0.0/24", "dedup_sec": 60},
                "collect": {"net": {"iface": "any", "emit_flow_event": False}},
            }
            alerts: list[dict] = []
            pipeline = NetPipeline(
                cfg,
                lambda event: None,
                alerts.append,
                ioc_provider=lambda kind: {"ioc.example"} if "domain" in str(kind) else set(),
            )
            self.assertEqual(pipeline.reload()["rules"], 1)
            pipeline.process_frame(_dns_udp_frame("ioc.example"))
            self.assertTrue(
                any(alert["rule"]["id"] == "T-9001" for alert in alerts),
                [a["rule"]["id"] for a in alerts],
            )
            # 响应包带同一 QNAME 也不得再次命中（只在出站查询方向告警）
            after_query = len(alerts)
            pipeline.process_frame(
                _dns_udp_frame("ioc.example", sport=53, dport=40000, flags=0x8180)
            )
            self.assertEqual(len(alerts), after_query, "DNS 响应方向不应再次触发 IOC 域名规则")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @unittest.skipUnless(HAVE_NETRULES, "NetRuleSet 不可用")
    @unittest.skipUnless(
        (_REPO_ROOT / "rules" / "net").is_dir(), "rules/net 规则目录不存在"
    )
    def test_syn_scan_triggers_netrule(self):
        alerts: list[dict] = []
        pipeline = NetPipeline(self._pipeline().cfg, lambda event: None, alerts.append)
        pipeline.reload()
        for offset in range(25):
            port = 1000 + offset
            pipeline.process_frame(_eth(_ipv4(_tcp(40000 + offset, port, flags=0x02))))
        self.assertTrue(any(alert["rule"]["id"] == "N-0101" for alert in alerts), alerts)
        self.assertTrue(all(alert["level"] >= 1 for alert in alerts))

    def test_resolve_ifaces(self):
        self.assertEqual(resolve_ifaces("eth9"), ["eth9"])
        names = resolve_ifaces("any")
        self.assertTrue(names)
        self.assertIsInstance(names, list)

    def test_simple_flow_fallback(self):
        flow = _SimpleFlow(max_flows=100, timeout=1)
        pkt = {"proto": "tcp", "src_ip": "1.1.1.1", "src_port": 1,
               "dst_ip": "2.2.2.2", "dst_port": 2, "ts": 1000.0}
        state = flow.update(pkt)
        self.assertEqual(state["packets"], 1)
        flow.update(pkt)
        self.assertEqual(flow.update(pkt)["packets"], 3)
        self.assertEqual(len(flow), 1)
        self.assertGreaterEqual(flow.age(now=2000.0), 1)

    def test_simple_tracker_fallback(self):
        tracker = _SimpleTracker(window=5.0)
        tracker.add(100.0, "1.1.1.1", "2.2.2.2", 80)
        tracker.add(100.5, "1.1.1.1", "2.2.2.2", 81)
        tracker.add(100.6, "1.1.1.1", "3.3.3.3", 443)
        self.assertEqual(tracker.distinct_ports(101.0, "1.1.1.1", "2.2.2.2"), 2)
        self.assertEqual(tracker.distinct_dsts(101.0, "1.1.1.1", "dst_ip"), 2)
        self.assertEqual(tracker.last_packet_ts("1.1.1.1", "3.3.3.3"), 100.6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
