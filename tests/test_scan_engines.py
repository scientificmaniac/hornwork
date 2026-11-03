"""扫描模块扫描引擎适配器单元测试（Windows 开发机可跑，不装任何外部工具）。

覆盖：
- nmap 解析：真实夹具 ``tests/data/scan/nmap-localhost-top100.xml``（nmap 7.98 输出）；
- nmap 命令链路：``unittest.mock.patch("subprocess.run")`` 替身，校验 ``-sV``/端口规格/限速；
- 端口规格翻译：``top:N`` / 逗号 / 区间 / 空 / ``declared``；
- 失败路径：超时、畸形 XML、空输出、二进制缺失、非零退出码 —— 均不抛异常；
- lynis report / testssl JSON / nuclei JSONL 的字段映射（样本里的模板 id 用明显虚构的
  ``test-*``，不编造真实 CVE）；
- 适配器协议属性、``build_adapters`` 工厂与 ``ScanContext`` 语义。

测试产物统一写工作区 ``tests/_tmp/scan-<uuid>/`` 并在用例结束清理（DSH 沙箱下系统
临时目录不保证可写；适配器本身通过 ``ctx.extra["tmp_dir"]`` 也支持该目录）。
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
import unittest
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork.scan.engines import (  # noqa: E402
    ADAPTER_ORDER,
    LynisAdapter,
    NmapAdapter,
    NucleiAdapter,
    PkgsAdapter,
    ScanAdapter,
    ScanContext,
    TestsslAdapter,
    build_adapter_map,
    build_adapters,
)
from hornwork.scan.engines import base as engine_base  # noqa: E402
from hornwork.scan.engines.lynis_adapter import parse_report as parse_lynis_report  # noqa: E402
from hornwork.scan.engines.nmap_adapter import (  # noqa: E402
    build_port_args,
    normalize_component,
    parse_cpe,
    parse_nmap_xml,
)
from hornwork.scan.engines.nuclei_adapter import parse_nuclei_jsonl  # noqa: E402
from hornwork.scan.engines.pkgs import parse_dpkg_output, parse_os_release  # noqa: E402
from hornwork.scan.engines.testssl_adapter import parse_testssl_json  # noqa: E402

DATA_DIR = Path(__file__).resolve().parent / "data" / "scan"
NMAP_XML_PATH = DATA_DIR / "nmap-localhost-top100.xml"

#: lynis report 样本（真实语法、内容虚构）
LYNIS_REPORT = """\
lynis_version=3.1.1
hardening_index=64
warning[]=SSH-7408|Consider hardening SSH configuration|Details: AllowTcpForwarding (set YES to NO)
suggestion[]=BOOT-5122|Set a password on GRUB boot loader|Details: grub password not set
suggestion[]=KRNL-6000|One or more sysctl values differ from the scan profile|Details: kernel.sysrq
"""

#: testssl JSON 样本（id 用 test-* 虚构；CVE 用 2099 明显虚构）
TESTSSL_JSON = json.dumps([
    {"id": "test-protocol-tls10", "severity": "HIGH", "finding": "TLS 1.0 is offered",
     "port": "443", "protocol": "tcp"},
    {"id": "test-weak-cipher", "severity": "MEDIUM", "finding": "weak cipher negotiated",
     "port": "443", "cve": "CVE-2099-0001", "protocol": "tcp"},
    {"id": "test-ok-cert", "severity": "OK", "finding": "certificate valid", "port": "443"},
    {"no_id": "header-only entry"},
])

#: nuclei JSONL 样本（模板 id 用 test-* 虚构；CVE 用 2099 明显虚构）
NUCLEI_JSONL = "\n".join([
    json.dumps({
        "template-id": "test-exposed-debug",
        "info": {"name": "Test Exposed Debug Endpoint", "severity": "high",
                 "classification": {"cve-id": ["CVE-2099-0002"], "cwe-id": ["cwe-200"]}},
        "matched-at": "http://127.0.0.1:8000/debug",
        "request": "GET /debug HTTP/1.1\r\nHost: 127.0.0.1:8000",
        "response": "HTTP/1.1 200 OK\r\n\r\ndebug panel",
    }),
    json.dumps({
        "template-id": "test-info-banner",
        "info": {"name": "Test Info Banner", "severity": "info"},
        "matched-at": "http://127.0.0.1:8000/",
    }),
    "this is not json and must be skipped",
])


def _expected_binary_available(*names: str) -> bool:
    """与平台无关的"二进制是否存在"期望值（Windows 恒 False）。"""
    if os.name == "nt":
        return False
    return any(shutil.which(name) for name in names)


class _TmpCase(unittest.TestCase):
    """公共底座：工作区内的临时目录 + 默认 ScanContext 工厂。"""

    def setUp(self) -> None:
        self.tmp = _TMP_ROOT / f"scan-{uuid.uuid4().hex[:8]}"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ctx(self, asset: dict | None = None, extra: dict | None = None, **kwargs) -> ScanContext:
        merged = {"tmp_dir": str(self.tmp)}
        if extra:
            merged.update(extra)
        return ScanContext(asset or {"asset_id": "a-self", "ip": "127.0.0.1", "is_self": 1},
                           extra=merged, **kwargs)

    @staticmethod
    def fake_proc(stdout: str = "", rc: int = 0, stderr: str = "") -> SimpleNamespace:
        return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# 1. nmap：真实 XML 夹具解析
# ---------------------------------------------------------------------------
class TestNmapFixture(unittest.TestCase):
    """用 nmap 7.98 的真实输出夹具验证解析器（不执行任何子进程）。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.xml = NMAP_XML_PATH.read_text(encoding="utf-8")
        cls.rows = parse_nmap_xml(
            cls.xml, ip="127.0.0.1", cmd=["nmap", "-sV", "127.0.0.1"], elapsed_ms=6270,
        )
        cls.ports = [row for row in cls.rows if row["kind"] == "port"]
        cls.comps = [row for row in cls.rows if row["kind"] == "component"]
        cls.summaries = [row for row in cls.rows if row["kind"] == "host_summary"]

    def test_fixture_exists(self) -> None:
        self.assertTrue(NMAP_XML_PATH.is_file(), "真实 nmap XML 夹具缺失")

    def test_open_ports(self) -> None:
        self.assertEqual([row["check_id"] for row in self.ports],
                         ["PORT-22/tcp", "PORT-80/tcp", "PORT-631/tcp", "PORT-8000/tcp"])
        self.assertEqual([row["target"] for row in self.ports],
                         ["127.0.0.1:22/tcp", "127.0.0.1:80/tcp",
                          "127.0.0.1:631/tcp", "127.0.0.1:8000/tcp"])
        self.assertEqual(self.ports[0]["title"], "22/tcp open ssh")
        for row in self.ports:
            self.assertIsNone(row["severity"])
            self.assertEqual(row["engine"], "nmap")
            self.assertEqual(row["evidence"]["state"], "open")
            self.assertTrue(row["evidence"]["reason"])

    def test_service_fields(self) -> None:
        by_port = {row["check_id"]: row for row in self.comps}
        self.assertEqual(len(by_port), 4)

        ssh = by_port["SVC-22/tcp"]
        self.assertEqual(ssh["comp_norm"], "openssh")
        self.assertEqual(ssh["version"], "10.2p1 Ubuntu 2ubuntu3.8")
        self.assertEqual(ssh["cpe"], "cpe:/a:openbsd:openssh:10.2p1")
        self.assertEqual(ssh["title"], "OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 (22/tcp)")
        self.assertEqual(ssh["facts"]["vendor"], "openbsd")
        self.assertEqual(ssh["facts"]["product"], "openssh")

        nginx = by_port["SVC-80/tcp"]
        self.assertEqual(nginx["comp_norm"], "nginx")
        self.assertEqual(nginx["version"], "1.18.0")
        self.assertEqual(nginx["cpe"], "cpe:/a:igor_sysoev:nginx:1.18.0")

        cups = by_port["SVC-631/tcp"]
        self.assertEqual(cups["comp_norm"], "cups")
        self.assertEqual(cups["version"], "2.4")

        gunicorn = by_port["SVC-8000/tcp"]
        self.assertEqual(gunicorn["comp_norm"], "gunicorn")
        self.assertNotIn("version", gunicorn)  # 无版本时不写空键
        self.assertEqual(gunicorn["title"], "Gunicorn (8000/tcp)")

    def test_component_evidence(self) -> None:
        ssh = next(row for row in self.comps if row["check_id"] == "SVC-22/tcp")
        evidence = ssh["evidence"]
        for key in ("service", "product", "version", "extrainfo", "cpe",
                    "tunnel", "confidence", "method"):
            self.assertIn(key, evidence)
        self.assertEqual(evidence["service"], "ssh")
        self.assertEqual(evidence["product"], "OpenSSH")
        self.assertEqual(evidence["method"], "probed")
        self.assertEqual(evidence["confidence"], 10)
        self.assertIn("Ubuntu Linux", evidence["extrainfo"])
        # runner 的资产事实（asset.facts_json.services）按 evidence.port 汇总
        self.assertEqual(evidence["port"], 22)
        self.assertEqual(evidence["proto"], "tcp")

    def test_host_summary(self) -> None:
        self.assertEqual(len(self.summaries), 1)
        summary = self.summaries[0]
        self.assertEqual(summary["check_id"], "HOST-127.0.0.1")
        self.assertEqual(summary["target"], "127.0.0.1")
        evidence = summary["evidence"]
        self.assertTrue(evidence["up"])
        self.assertGreaterEqual(evidence["scanned"], 100)
        self.assertEqual(evidence["open"], 4)
        self.assertEqual(evidence["closed"], 96)
        self.assertEqual(evidence["filtered"], 0)
        self.assertIsInstance(evidence["elapsed_ms"], int)
        self.assertEqual(evidence["nmap_version"], "7.98")
        self.assertEqual(evidence["cmd"], ["nmap", "-sV", "127.0.0.1"])

    def test_results_are_json_serializable(self) -> None:
        payload = json.dumps(self.rows, ensure_ascii=False)
        self.assertTrue(payload)
        for row in self.rows:
            for key in ("engine", "kind", "check_id", "target", "title",
                        "severity", "evidence"):
                self.assertIn(key, row)
            self.assertIsInstance(row["evidence"], dict)

    def test_multiple_hosts(self) -> None:
        two_hosts = """<?xml version="1.0"?>
<nmaprun version="7.98"><host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/>
<service name="http" product="Apache httpd" version="2.4.58"><cpe>cpe:/a:apache:http_server:2.4.58</cpe></service>
</port></ports></host></nmaprun>"""
        rows = parse_nmap_xml(two_hosts, ip="10.0.0.2")
        kinds = [row["kind"] for row in rows]
        self.assertEqual(kinds, ["port", "component", "host_summary"])
        self.assertEqual(rows[2]["check_id"], "HOST-10.0.0.2")
        self.assertEqual(rows[1]["comp_norm"], "http_server")


class TestNmapCpeHelpers(unittest.TestCase):
    def test_parse_cpe_uri(self) -> None:
        parsed = parse_cpe("cpe:/a:openbsd:openssh:10.2p1")
        self.assertEqual(parsed["part"], "a")
        self.assertEqual(parsed["vendor"], "openbsd")
        self.assertEqual(parsed["product"], "openssh")
        self.assertEqual(parsed["version"], "10.2p1")

    def test_parse_cpe_23(self) -> None:
        parsed = parse_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")
        self.assertEqual(parsed["product"], "nginx")
        self.assertEqual(parsed["version"], "1.18.0")

    def test_parse_cpe_invalid(self) -> None:
        for value in ("", None, "not-a-cpe", "cpe:", "cpe:2.3:a:only"):
            self.assertEqual(parse_cpe(value), {})

    def test_normalize_component(self) -> None:
        self.assertEqual(normalize_component("OpenSSH", ["cpe:/a:openbsd:openssh:10.2p1"]), "openssh")
        # OS CPE 不能被当成组件
        self.assertEqual(normalize_component("Some Server", ["cpe:/o:linux:linux_kernel"]), "some-server")
        self.assertEqual(normalize_component("My_Product", []), "my-product")
        self.assertEqual(normalize_component("", []), "")


# ---------------------------------------------------------------------------
# 2. nmap：端口规格翻译
# ---------------------------------------------------------------------------
class TestNmapPortSpec(unittest.TestCase):
    def test_specs(self) -> None:
        cases = [
            ("top:200", ["--top-ports", "200"]),
            ("top:1000", ["--top-ports", "1000"]),
            ("top", ["--top-ports", "200"]),
            ("", ["--top-ports", "200"]),
            (None, ["--top-ports", "200"]),
            ("1-65535", ["-p", "1-65535"]),
            ("22,80,18000", ["-p", "22,80,18000"]),
            (" 22,80 ", ["-p", "22,80"]),
        ]
        for spec, expected in cases:
            with self.subTest(spec=spec):
                self.assertEqual(build_port_args(spec), expected)

    def test_declared_ports(self) -> None:
        self.assertEqual(build_port_args("declared", [22, 80, 631]), ["-p", "22,80,631"])
        self.assertEqual(build_port_args("declared", ["443"]), ["-p", "443"])
        # 声明为空 / 非法 → 回退 top200
        self.assertEqual(build_port_args("declared", []), ["--top-ports", "200"])
        self.assertEqual(build_port_args("declared", None), ["--top-ports", "200"])
        self.assertEqual(build_port_args("declared", ["abc", 70000]), ["--top-ports", "200"])


# ---------------------------------------------------------------------------
# 3. nmap：命令拼装与执行链路（mock subprocess.run）
# ---------------------------------------------------------------------------
class TestNmapRunMocked(_TmpCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.xml = NMAP_XML_PATH.read_text(encoding="utf-8")

    def test_full_chain(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc(self.xml)) as run_mock, \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            rows = NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx())
        self.assertTrue(rows)
        self.assertEqual(rows[0]["kind"], "port")
        args, kwargs = run_mock.call_args
        cmd = args[0]
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[0], "nmap")
        self.assertEqual(cmd[1:3], ["-oX", "-"])
        self.assertIn("-sV", cmd)
        self.assertNotIn("-sS", cmd)  # 显式不写 SYN 扫描
        self.assertEqual(cmd[cmd.index("--version-intensity") + 1], "7")
        self.assertEqual(cmd[cmd.index("--max-retries") + 1], "2")
        self.assertEqual(cmd[cmd.index("--host-timeout") + 1], "900s")
        self.assertEqual(cmd[-1], "127.0.0.1")
        self.assertEqual(cmd[cmd.index("--top-ports") + 1], "200")
        self.assertEqual(cmd[cmd.index("--max-rate") + 1], "500")
        # 子进程调用参数固定
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertFalse(kwargs["check"])
        self.assertFalse(kwargs["shell"])
        self.assertGreater(kwargs["timeout"], 0)

    def test_service_detect_off(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc(self.xml)) as run_mock, \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx(service_detect=False))
        cmd = run_mock.call_args[0][0]
        self.assertNotIn("-sV", cmd)
        self.assertNotIn("--version-intensity", cmd)

    def test_custom_ports_and_no_rate_limit(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc(self.xml)) as run_mock, \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            NmapAdapter({}).run({"ip": "127.0.0.1"},
                               self.ctx(ports="1-65535", rate_limit=0, timeout_sec=60))
        cmd = run_mock.call_args[0][0]
        self.assertEqual(cmd[cmd.index("-p") + 1], "1-65535")
        self.assertNotIn("--max-rate", cmd)
        self.assertEqual(cmd[cmd.index("--host-timeout") + 1], "60s")

    def test_declared_ports_in_args(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc(self.xml)) as run_mock, \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            NmapAdapter({}).run({"ip": "127.0.0.1"},
                               self.ctx(ports="declared", extra={"declared_ports": [22, 80]}))
        cmd = run_mock.call_args[0][0]
        self.assertEqual(cmd[cmd.index("-p") + 1], "22,80")

    def test_config_bin_and_intensity(self) -> None:
        cfg = {"scan": {"nmap": {"bin": "/usr/bin/nmap", "version_intensity": 5,
                                 "max_retries": 1}}}
        with mock.patch("subprocess.run", return_value=self.fake_proc(self.xml)) as run_mock, \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            NmapAdapter(cfg).run({"ip": "127.0.0.1"}, self.ctx())
        cmd = run_mock.call_args[0][0]
        self.assertEqual(cmd[0], "/usr/bin/nmap")
        self.assertEqual(cmd[cmd.index("--version-intensity") + 1], "5")
        self.assertEqual(cmd[cmd.index("--max-retries") + 1], "1")

    def test_nonzero_rc_still_parses(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc(self.xml, rc=1)), \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            rows = NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx())
        self.assertEqual(len([row for row in rows if row["kind"] == "port"]), 4)


# ---------------------------------------------------------------------------
# 4. nmap：失败路径（绝不抛异常）
# ---------------------------------------------------------------------------
class TestNmapFailures(_TmpCase):
    def test_timeout_returns_empty(self) -> None:
        timeout_exc = __import__("subprocess").TimeoutExpired("nmap", 30)
        with mock.patch("subprocess.run", side_effect=timeout_exc), \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            self.assertEqual(NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])

    def test_timeout_with_partial_output(self) -> None:
        timeout_exc = __import__("subprocess").TimeoutExpired(
            "nmap", 30, output="<nmaprun><host>", stderr=""
        )
        with mock.patch("subprocess.run", side_effect=timeout_exc), \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            # 截断 XML 解析失败 → 返回 []，不抛
            self.assertEqual(NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])

    def test_malformed_xml(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc("<nmaprun><host>")), \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            self.assertEqual(NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])
        self.assertEqual(parse_nmap_xml("<nmaprun><host>", ip="127.0.0.1"), [])
        self.assertEqual(parse_nmap_xml("", ip="127.0.0.1"), [])
        self.assertEqual(parse_nmap_xml("<?xml version='1.0'?><nmaprun></nmaprun>"), [])

    def test_empty_output(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc("", rc=0)), \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            self.assertEqual(NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])

    def test_missing_binary(self) -> None:
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("nmap")), \
                mock.patch.object(NmapAdapter, "available", return_value=True):
            self.assertEqual(NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])

    def test_unavailable_engine_skips_subprocess(self) -> None:
        with mock.patch("subprocess.run") as run_mock, \
                mock.patch.object(NmapAdapter, "available", return_value=False):
            self.assertEqual(NmapAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])
        run_mock.assert_not_called()

    def test_available_on_platform(self) -> None:
        expected = _expected_binary_available("nmap")
        self.assertEqual(NmapAdapter({}).available(), expected)

    def test_supports(self) -> None:
        adapter = NmapAdapter({})
        for profile in ("quick", "weekly", "full", "targeted", "verify-fix"):
            self.assertTrue(adapter.supports({"ip": "127.0.0.1"}, profile))
        self.assertFalse(adapter.supports({}, "weekly"))


# ---------------------------------------------------------------------------
# 5. pkgs：包清单
# ---------------------------------------------------------------------------
class TestPkgs(_TmpCase):
    def test_parse_dpkg_output(self) -> None:
        text = "bash 5.2.21-2ubuntu4\nopenssh-server 1:9.6p1-3ubuntu13.5\n\nbroken\n"
        rows = parse_dpkg_output(text, distro="noble", backend="local")
        self.assertEqual([row["check_id"] for row in rows],
                         ["PKG-bash", "PKG-openssh-server", "PKG-broken"])
        first = rows[0]
        self.assertEqual(first["kind"], "component")
        self.assertEqual(first["target"], "package:bash")
        self.assertEqual(first["comp_norm"], "bash")
        self.assertEqual(first["version"], "5.2.21-2ubuntu4")
        self.assertEqual(first["title"], "bash 5.2.21-2ubuntu4")
        self.assertEqual(first["evidence"]["backend"], "local")
        self.assertEqual(first["evidence"]["distro"], "noble")
        self.assertIsNone(first["severity"])
        self.assertNotIn("version", rows[2])  # 无版本的孤立行不写空 version
        json.dumps(rows, ensure_ascii=False)

    def test_parse_os_release(self) -> None:
        self.assertEqual(parse_os_release('NAME="Ubuntu"\nVERSION_CODENAME=noble\n'), "noble")
        self.assertEqual(parse_os_release('VERSION_CODENAME="jammy"\n'), "jammy")
        self.assertIsNone(parse_os_release("NAME=Ubuntu\n"))
        self.assertIsNone(parse_os_release(""))

    def test_available_on_platform(self) -> None:
        self.assertEqual(PkgsAdapter({}).available(), _expected_binary_available("dpkg-query"))

    def test_supports_local_backend(self) -> None:
        adapter = PkgsAdapter({})
        self.assertTrue(adapter.supports({"ip": "127.0.0.1", "is_self": 1}, "weekly"))
        # 集成调整：只有显式 is_self 才算本机，避免单机双角色里 ast-lab（同为 127.0.0.1）
        # 重复跑一遍 dpkg（包级 finding 与耗时都会翻倍）。
        self.assertFalse(adapter.supports({"ip": "127.0.0.1"}, "weekly"))
        self.assertFalse(adapter.supports({"ip": "192.168.56.20"}, "weekly"))
        self.assertFalse(adapter.supports({}, "weekly"))

    def test_supports_ssh_backend(self) -> None:
        adapter = PkgsAdapter({"scan": {"pkgs": {"backend": "ssh"}}})
        self.assertTrue(adapter.supports({"ip": "192.168.56.20", "cred_ref": "b-scan"}, "weekly"))
        self.assertFalse(adapter.supports({"ip": "192.168.56.20"}, "weekly"))

    def test_run_local(self) -> None:
        with mock.patch("subprocess.run",
                        return_value=self.fake_proc("bash 5.2.21-2ubuntu4\ncurl 8.5.0-2\n")) as run_mock, \
                mock.patch.object(PkgsAdapter, "available", return_value=True):
            rows = PkgsAdapter({}).run({"ip": "127.0.0.1", "is_self": 1}, self.ctx())
        self.assertEqual(len(rows), 2)
        cmd = run_mock.call_args[0][0]
        self.assertEqual(cmd[:2], ["dpkg-query", "-W"])
        self.assertIn("${Package} ${Version}", cmd[2])
        self.assertEqual(rows[0]["evidence"]["backend"], "local")
        self.assertIn("distro", rows[0]["evidence"])

    def test_run_ssh_command(self) -> None:
        cfg = {"scan": {"pkgs": {"backend": "ssh", "ssh_key": "~/.ssh/id_ed25519_scan"}}}
        asset = {"ip": "192.168.56.20", "cred_ref": "b-scan", "ssh_user": "b-scan"}
        with mock.patch("subprocess.run",
                        return_value=self.fake_proc("bash 5.2.21-2ubuntu4\n")) as run_mock, \
                mock.patch.object(PkgsAdapter, "available", return_value=True):
            rows = PkgsAdapter(cfg).run(asset, self.ctx(asset=asset))
        self.assertEqual(len(rows), 1)
        cmd = run_mock.call_args[0][0]
        self.assertEqual(cmd[0], "ssh")
        self.assertEqual(cmd[cmd.index("-o") + 1], "BatchMode=yes")
        self.assertIn("ConnectTimeout=5", cmd)
        self.assertEqual(cmd[cmd.index("-i") + 1].replace("\\", "/").split("/")[-1],
                         "id_ed25519_scan")
        self.assertIn("b-scan@192.168.56.20", cmd)
        self.assertIn("dpkg-query", cmd[-1])

    def test_run_failure_returns_empty(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc("", rc=1)), \
                mock.patch.object(PkgsAdapter, "available", return_value=True):
            self.assertEqual(PkgsAdapter({}).run({"ip": "127.0.0.1", "is_self": 1}, self.ctx()), [])

    def test_run_not_supported_skips_subprocess(self) -> None:
        with mock.patch("subprocess.run") as run_mock, \
                mock.patch.object(PkgsAdapter, "available", return_value=True):
            self.assertEqual(PkgsAdapter({}).run({"ip": "192.168.56.20"}, self.ctx()), [])
        run_mock.assert_not_called()


# ---------------------------------------------------------------------------
# 6. lynis：report 解析
# ---------------------------------------------------------------------------
class TestLynis(_TmpCase):
    def test_parse_report(self) -> None:
        rows = parse_lynis_report(LYNIS_REPORT, target="host:127.0.0.1")
        self.assertEqual([row["check_id"] for row in rows],
                         ["LYNIS-SSH-7408", "LYNIS-BOOT-5122", "LYNIS-KRNL-6000"])
        self.assertEqual([row["severity"] for row in rows], ["中", "低", "低"])
        for row in rows:
            self.assertEqual(row["engine"], "lynis")
            self.assertEqual(row["kind"], "config")
            self.assertEqual(row["target"], "host:127.0.0.1")
            self.assertEqual(row["evidence"]["hardening_index"], 64)
            self.assertTrue(row["evidence"]["message"])
            self.assertTrue(row["evidence"]["raw"])
        self.assertEqual(rows[0]["title"], "Consider hardening SSH configuration")
        self.assertIn("AllowTcpForwarding", rows[0]["evidence"]["details"])
        json.dumps(rows, ensure_ascii=False)

    def test_parse_report_empty(self) -> None:
        self.assertEqual(parse_lynis_report("", target="host:1.2.3.4"), [])
        self.assertEqual(parse_lynis_report("lynis_version=3.1.1\n", target="host:1.2.3.4"), [])

    def test_custom_severity(self) -> None:
        rows = parse_lynis_report(LYNIS_REPORT, target="host:127.0.0.1",
                                 warning_severity="高", suggestion_severity="中")
        self.assertEqual([row["severity"] for row in rows], ["高", "中", "中"])

    def test_available_on_platform(self) -> None:
        self.assertEqual(LynisAdapter({}).available(), _expected_binary_available("lynis"))

    def test_supports(self) -> None:
        adapter = LynisAdapter({})
        self.assertTrue(adapter.supports({"ip": "127.0.0.1", "is_self": 1}, "weekly"))
        # 集成调整：需显式 is_self（同上，避免 ast-lab 重复跑 lynis）。
        self.assertFalse(adapter.supports({"ip": "127.0.0.1"}, "full"))
        self.assertTrue(adapter.supports({"ip": "127.0.0.1", "is_self": 1}, "verify-fix"))
        self.assertFalse(adapter.supports({"ip": "127.0.0.1", "is_self": 1}, "quick"))
        self.assertFalse(adapter.supports({"ip": "192.168.56.20"}, "weekly"))

    def test_run_reads_and_cleans_report(self) -> None:
        def fake_run(cmd, **kwargs):
            report_path = Path(cmd[cmd.index("--report-file") + 1])
            report_path.write_text(LYNIS_REPORT, encoding="utf-8")
            return self.fake_proc("", rc=0)

        with mock.patch("subprocess.run", side_effect=fake_run) as run_mock, \
                mock.patch.object(LynisAdapter, "available", return_value=True):
            rows = LynisAdapter({}).run({"ip": "127.0.0.1", "is_self": 1}, self.ctx())
        self.assertEqual(len(rows), 3)
        cmd = run_mock.call_args[0][0]
        self.assertEqual(cmd[1:3], ["audit", "system"])
        for flag in ("--quick", "--no-colors", "--quiet", "--report-file"):
            self.assertIn(flag, cmd)
        self.assertEqual(list(self.tmp.iterdir()), [], "lynis 临时 report 未删除")

    def test_run_nonzero_still_parses(self) -> None:
        def fake_run(cmd, **kwargs):
            Path(cmd[cmd.index("--report-file") + 1]).write_text(LYNIS_REPORT, encoding="utf-8")
            return self.fake_proc("", rc=2)

        with mock.patch("subprocess.run", side_effect=fake_run), \
                mock.patch.object(LynisAdapter, "available", return_value=True):
            self.assertEqual(len(LynisAdapter({}).run({"ip": "127.0.0.1", "is_self": 1}, self.ctx())), 3)

    def test_run_missing_report_returns_empty(self) -> None:
        with mock.patch("subprocess.run", return_value=self.fake_proc("", rc=0)), \
                mock.patch.object(LynisAdapter, "available", return_value=True):
            self.assertEqual(LynisAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_run_unavailable(self) -> None:
        with mock.patch("subprocess.run") as run_mock, \
                mock.patch.object(LynisAdapter, "available", return_value=False):
            self.assertEqual(LynisAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])
        run_mock.assert_not_called()


# ---------------------------------------------------------------------------
# 7. testssl：JSON 解析与端口选择
# ---------------------------------------------------------------------------
class TestTestssl(_TmpCase):
    def test_parse_json(self) -> None:
        rows = parse_testssl_json(TESTSSL_JSON, ip="127.0.0.1", default_port=443)
        # OK/INFO/DEBUG 项（检查通过/纯信息）被跳过，只留问题项
        self.assertEqual([row["check_id"] for row in rows],
                         ["TLS-test-protocol-tls10", "TLS-test-weak-cipher"])
        self.assertEqual([row["severity"] for row in rows], ["高", "中"])
        self.assertEqual([row["target"] for row in rows],
                         ["127.0.0.1:443", "127.0.0.1:443"])
        self.assertEqual(rows[1]["evidence"]["cve"], "CVE-2099-0001")
        self.assertEqual(rows[0]["evidence"]["protocol"], "tcp")
        self.assertEqual(rows[0]["evidence"]["port"], 443)
        for row in rows:
            self.assertEqual(row["engine"], "testssl")
            self.assertEqual(row["kind"], "tls")
        json.dumps(rows, ensure_ascii=False)

    def test_parse_bad_json(self) -> None:
        self.assertEqual(parse_testssl_json("", ip="127.0.0.1"), [])
        self.assertEqual(parse_testssl_json("{not json", ip="127.0.0.1"), [])
        self.assertEqual(parse_testssl_json('{"no": "id"}', ip="127.0.0.1"), [])

    def test_ports_for(self) -> None:
        adapter = TestsslAdapter({})
        asset = {"ip": "127.0.0.1"}
        self.assertEqual(adapter.ports_for(asset, self.ctx(extra={"tls_ports": [8443]})), [8443])
        self.assertEqual(adapter.ports_for(asset, self.ctx()), [443, 8443])
        declared = {"ip": "127.0.0.1", "facts_json": json.dumps([
            {"port": 443, "tags": ["tls"]}, {"port": 8080, "tags": ["http"]},
        ])}
        self.assertEqual(adapter.ports_for(declared, self.ctx()), [443])
        self.assertEqual(adapter.ports_for({"ip": "127.0.0.1", "facts_json": "not json"},
                                           self.ctx()), [443, 8443])

    def test_available_on_platform(self) -> None:
        expected = _expected_binary_available("testssl", "testssl.sh")
        self.assertEqual(TestsslAdapter({}).available(), expected)

    def test_run_and_cleanup(self) -> None:
        def fake_run(cmd, **kwargs):
            json_path = Path(cmd[cmd.index("--jsonfile") + 1])
            json_path.write_text(TESTSSL_JSON, encoding="utf-8")
            return self.fake_proc("", rc=0)

        asset = {"ip": "127.0.0.1"}
        with mock.patch("subprocess.run", side_effect=fake_run) as run_mock, \
                mock.patch.object(TestsslAdapter, "available", return_value=True):
            rows = TestsslAdapter({}).run(asset, self.ctx(extra={"tls_ports": [8443]}))
        self.assertEqual(len(rows), 2)
        cmd = run_mock.call_args[0][0]
        for flag in ("--quiet", "--jsonfile", "--severity", "--vulnerable", "--protocols"):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index("--severity") + 1], "HIGH")
        self.assertEqual(cmd[cmd.index("--protocols") + 1], "127.0.0.1:8443")
        self.assertEqual(list(self.tmp.iterdir()), [], "testssl 临时 JSON 未删除")

    def test_run_timeout_returns_empty(self) -> None:
        timeout_exc = __import__("subprocess").TimeoutExpired("testssl", 30)
        with mock.patch("subprocess.run", side_effect=timeout_exc), \
                mock.patch.object(TestsslAdapter, "available", return_value=True):
            self.assertEqual(TestsslAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])
        self.assertEqual(list(self.tmp.iterdir()), [])


# ---------------------------------------------------------------------------
# 8. nuclei：JSONL 解析与执行
# ---------------------------------------------------------------------------
class TestNuclei(_TmpCase):
    def test_parse_jsonl(self) -> None:
        rows = parse_nuclei_jsonl(NUCLEI_JSONL, default_url="http://127.0.0.1:8000/")
        self.assertEqual([row["check_id"] for row in rows],
                         ["test-exposed-debug", "test-info-banner"])
        self.assertEqual([row["severity"] for row in rows], ["高", "无"])
        first = rows[0]
        self.assertEqual(first["kind"], "web")
        self.assertEqual(first["target"], "http://127.0.0.1:8000/debug")
        self.assertEqual(first["title"], "Test Exposed Debug Endpoint")
        self.assertEqual(first["evidence"]["cve"], ["CVE-2099-0002"])
        self.assertEqual(first["evidence"]["cwe"], ["cwe-200"])
        self.assertEqual(first["evidence"]["template_id"], "test-exposed-debug")
        self.assertIn("GET /debug", first["evidence"]["request"])
        self.assertEqual(first["confidence"], "tool")
        self.assertEqual(rows[1]["target"], "http://127.0.0.1:8000/")
        json.dumps(rows, ensure_ascii=False)

    def test_truncate_evidence(self) -> None:
        long_line = json.dumps({
            "template-id": "test-long-evidence",
            "info": {"name": "Long", "severity": "medium"},
            "matched-at": "http://127.0.0.1/",
            "request": "A" * 5000,
            "response": "B" * 5000,
        })
        rows = parse_nuclei_jsonl(long_line)
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["evidence"]["request"]), 2000)
        self.assertEqual(len(rows[0]["evidence"]["response"]), 2000)

    def test_parse_empty(self) -> None:
        self.assertEqual(parse_nuclei_jsonl(""), [])
        self.assertEqual(parse_nuclei_jsonl("{\"no\": \"template\"}\n"), [])

    def test_available_requires_binary_and_templates(self) -> None:
        cfg = {"scan": {"nuclei": {"templates": str(self.tmp)}}}
        with mock.patch("hornwork.scan.engines.nuclei_adapter.binary_available",
                        return_value=True):
            self.assertTrue(NucleiAdapter(cfg).available())
        with mock.patch("hornwork.scan.engines.nuclei_adapter.binary_available",
                        return_value=False):
            self.assertFalse(NucleiAdapter(cfg).available())
        cfg_missing = {"scan": {"nuclei": {"templates": str(self.tmp / "missing")}}}
        with mock.patch("hornwork.scan.engines.nuclei_adapter.binary_available",
                        return_value=True):
            self.assertFalse(NucleiAdapter(cfg_missing).available())

    def test_run_and_args(self) -> None:
        with mock.patch("subprocess.run",
                        return_value=self.fake_proc(NUCLEI_JSONL)) as run_mock, \
                mock.patch.object(NucleiAdapter, "available", return_value=True):
            rows = NucleiAdapter({}).run(
                {"ip": "127.0.0.1"},
                self.ctx(extra={"web_targets": ["http://127.0.0.1:8000/"]}),
            )
        self.assertEqual(len(rows), 2)
        cmd = run_mock.call_args[0][0]
        self.assertEqual(cmd[cmd.index("-u") + 1], "http://127.0.0.1:8000/")
        for flag in ("-jsonl", "-silent", "-rate-limit", "-timeout", "-etags", "-severity"):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index("-rate-limit") + 1], "500")
        self.assertEqual(cmd[cmd.index("-timeout") + 1], "10")
        self.assertEqual(cmd[cmd.index("-etags") + 1], "fuzz,dos,bruteforce")
        self.assertEqual(cmd[cmd.index("-severity") + 1], "critical,high,medium")

    def test_run_no_targets(self) -> None:
        with mock.patch("subprocess.run") as run_mock, \
                mock.patch.object(NucleiAdapter, "available", return_value=True):
            self.assertEqual(NucleiAdapter({}).run({"ip": "127.0.0.1"}, self.ctx()), [])
        run_mock.assert_not_called()

    def test_run_failure_isolated_per_url(self) -> None:
        timeout_exc = __import__("subprocess").TimeoutExpired("nuclei", 30)
        calls = {"n": 0}

        def fake_run(cmd, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise timeout_exc
            return self.fake_proc(NUCLEI_JSONL)

        with mock.patch("subprocess.run", side_effect=fake_run), \
                mock.patch.object(NucleiAdapter, "available", return_value=True):
            rows = NucleiAdapter({}).run(
                {"ip": "127.0.0.1"},
                self.ctx(extra={"web_targets": ["http://a/", "http://b/"]}),
            )
        self.assertEqual(len(rows), 2)  # 第一个 URL 超时不影响第二个

    def test_run_unavailable(self) -> None:
        with mock.patch("subprocess.run") as run_mock, \
                mock.patch.object(NucleiAdapter, "available", return_value=False):
            self.assertEqual(NucleiAdapter({}).run({"ip": "127.0.0.1"},
                                                   self.ctx(extra={"web_targets": ["http://a/"]})), [])
        run_mock.assert_not_called()


# ---------------------------------------------------------------------------
# 9. base：上下文、工具函数、适配器契约
# ---------------------------------------------------------------------------
class TestBase(_TmpCase):
    def test_scan_context_defaults(self) -> None:
        ctx = ScanContext({"ip": "127.0.0.1"})
        self.assertEqual(ctx.profile, "weekly")
        self.assertEqual(ctx.ports, "top:200")
        self.assertTrue(ctx.service_detect)
        self.assertEqual(ctx.timeout_sec, 900)
        self.assertEqual(ctx.rate_limit, 500)
        self.assertIsNone(ctx.deadline)
        self.assertEqual(ctx.extra, {})
        self.assertEqual(ctx.plan, {})

    def test_scan_context_positional_order(self) -> None:
        # 契约参数顺序：asset, plan, profile, ports, service_detect, timeout_sec, ...
        ctx = ScanContext({"ip": "1.2.3.4"}, {"plan_id": "p1"}, "full", "1-65535",
                          False, 60, 100, None, {"x": 1})
        self.assertEqual(ctx.plan["plan_id"], "p1")
        self.assertEqual(ctx.profile, "full")
        self.assertEqual(ctx.ports, "1-65535")
        self.assertFalse(ctx.service_detect)
        self.assertEqual(ctx.timeout_sec, 60)
        self.assertEqual(ctx.rate_limit, 100)
        self.assertEqual(ctx.extra, {"x": 1})

    def test_remaining_sec(self) -> None:
        ctx = ScanContext({"ip": "127.0.0.1"}, deadline=time.monotonic() + 60)
        remain = ctx.remaining_sec(None)
        self.assertIsNotNone(remain)
        self.assertGreater(remain, 50)
        self.assertLessEqual(remain, 61)
        ctx2 = ScanContext({"ip": "127.0.0.1"}, deadline=datetime.now() + timedelta(seconds=30))
        self.assertGreater(ctx2.remaining_sec(None), 20)
        self.assertIsNone(ScanContext({"ip": "127.0.0.1"}).remaining_sec(None))
        self.assertEqual(ScanContext({"ip": "127.0.0.1"}, deadline="not-a-date").remaining_sec(7), 7)

    def test_make_raw(self) -> None:
        row = engine_base.make_raw(
            "demo", "component", "SVC-1/tcp", "1.2.3.4:1/tcp",
            title="x", evidence={"a": 1}, comp_norm="demo", cpe=None, extra_field="v",
        )
        self.assertEqual(row["engine"], "demo")
        self.assertIsNone(row["severity"])
        self.assertNotIn("cpe", row)            # None 字段不写入
        self.assertEqual(row["extra_field"], "v")
        json.dumps(row, ensure_ascii=False)

    def test_binary_available(self) -> None:
        self.assertFalse(engine_base.binary_available({}, "scan.nmap.bin", ""))
        self.assertFalse(engine_base.binary_available(
            {}, "scan.nmap.bin", str(self.tmp / "no-such-binary")))
        self.assertEqual(
            engine_base.binary_available({}, "scan.nmap.bin", "nmap"),
            _expected_binary_available("nmap"),
        )

    def test_is_local_ip_and_asset_is_self(self) -> None:
        self.assertTrue(engine_base.is_local_ip("127.0.0.1"))
        self.assertTrue(engine_base.is_local_ip("::1"))
        self.assertTrue(engine_base.is_local_ip("localhost"))
        self.assertFalse(engine_base.is_local_ip("8.8.8.8"))
        self.assertFalse(engine_base.is_local_ip(""))
        self.assertFalse(engine_base.is_local_ip("not-an-ip"))
        self.assertTrue(engine_base.asset_is_self({"ip": "192.168.56.20", "is_self": 1}))
        self.assertTrue(engine_base.asset_is_self({"ip": "192.168.56.20", "is_self": "true"}))
        self.assertTrue(engine_base.asset_is_self({"ip": "127.0.0.1"}))
        self.assertFalse(engine_base.asset_is_self({"ip": "192.168.56.20"}))
        self.assertFalse(engine_base.asset_is_self({}))
        self.assertFalse(engine_base.asset_is_self(None))

    def test_port_list(self) -> None:
        self.assertEqual(engine_base.port_list("443,8443"), [443, 8443])
        self.assertEqual(engine_base.port_list([443, "8443"]), [443, 8443])
        self.assertEqual(engine_base.port_list(443), [443])
        self.assertEqual(engine_base.port_list("bad,0,70000"), [])
        self.assertEqual(engine_base.port_list(None), [])

    def test_build_adapters(self) -> None:
        adapters = build_adapters({})
        self.assertEqual([adapter.name for adapter in adapters], list(ADAPTER_ORDER))
        self.assertEqual(len(adapters), 5)
        for adapter in adapters:
            self.assertIsInstance(adapter, ScanAdapter)
            self.assertIn(adapter.cost, ("fast", "medium", "slow"))
            self.assertTrue(adapter.requires)
            self.assertTrue(adapter.version)
        mapping = build_adapter_map({})
        self.assertEqual(set(mapping), set(ADAPTER_ORDER))
        self.assertIsInstance(mapping["nmap"], NmapAdapter)

    def test_adapter_contract_attributes(self) -> None:
        expected = {
            NmapAdapter: ("nmap", ["tcp"]),
            PkgsAdapter: ("pkgs", ["dpkg"]),
            LynisAdapter: ("lynis", ["root"]),
            TestsslAdapter: ("testssl", ["testssl"]),
            NucleiAdapter: ("nuclei", ["nuclei"]),
        }
        for cls, (name, requires) in expected.items():
            with self.subTest(adapter=name):
                adapter = cls({})
                self.assertEqual(adapter.name, name)
                self.assertEqual(adapter.requires, requires)
                self.assertIsInstance(adapter.supports({"ip": "127.0.0.1"}, "weekly"), bool)


if __name__ == "__main__":
    unittest.main(verbosity=2)
