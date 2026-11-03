"""靶场编排（靶场编排层）单元测试。

不依赖 Docker / SSH / 虚拟机：命令执行用 FakeRunner 替身，端口探测被 mock；
测试产物统一写 ``tests/_tmp/lab-<uuid>/``，每个用例结束清理（不使用 tempfile）。
"""

from __future__ import annotations

import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml

# 说明：DSH 沙箱下系统临时目录不可写，统一把测试产物放到工作区 tests/_tmp
_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork import schema  # noqa: E402
from hornwork.config import load_config  # noqa: E402
from hornwork.lab import LabCtl, build_index, load_index, parse_compose  # noqa: E402
from hornwork.lab import compose as complib  # noqa: E402
from hornwork.lab import guard  # noqa: E402
from hornwork.lab import ports as portlib  # noqa: E402
from hornwork.lab import store as labstore  # noqa: E402
from hornwork.lab.runner import CommandRunner, Result  # noqa: E402
from hornwork.store import Store  # noqa: E402

ENV_GRAFANA = "grafana/CVE-2021-43798"
ENV_APP = "app/CVE-2020-1111"

GRAFANA_COMPOSE = """\
services:
  grafana:
    image: vulhub/grafana:8.2.6
    ports:
      - "3000:3000"
"""

APP_COMPOSE = """\
services:
  web:
    build: .
    ports:
      - "8080:80"
    expose:
      - "80"
  db:
    image: mysql:5.7
    ports:
      - "3306:3306"
"""

GRAFANA_README = """\
# Grafana 目录穿越（CVE-2021-43798）

[![build](https://img.example/badge.svg)](https://example.com)

Grafana 8.2.6 存在目录穿越漏洞，未授权访问者可读取插件目录下的任意文件。
复现时请只在本机靶场执行。
"""


def _mk_tmp() -> Path:
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = _TMP_ROOT / f"lab-{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _make_fake_vulhub(root: Path) -> None:
    """构造两个假 Vulhub 环境：单服务 image 版 + 多服务 build 版。"""
    grafana = root / "grafana" / "CVE-2021-43798"
    grafana.mkdir(parents=True, exist_ok=True)
    (grafana / "docker-compose.yml").write_text(GRAFANA_COMPOSE, encoding="utf-8")
    (grafana / "README.md").write_text(GRAFANA_README, encoding="utf-8")

    app = root / "app" / "CVE-2020-1111"
    app.mkdir(parents=True, exist_ok=True)
    (app / "docker-compose.yml").write_text(APP_COMPOSE, encoding="utf-8")


def _cfg_for(tmp: Path, vulhub: Path) -> dict:
    cfg = load_config(None)
    cfg["lab"].update(
        {
            "backend": "local",
            "vulhub_root": str(vulhub),
            "overrides_dir": str(tmp / "overrides"),
            "state_file": str(tmp / "state.json"),
            "index_path": str(tmp / "data" / "vulhub-index.json"),
            "host_bind": "127.0.0.1",
            "max_envs": 2,
            "min_mem_mb": 800,
            "min_disk_gb": 0,
            "default_ttl_min": 90,
            "pull_timeout_sec": 30,
            "up_timeout_sec": 30,
            "down_timeout_sec": 30,
            "healthy_timeout_sec": 2,
            "health_poll_sec": 0.1,
            "port_range": [18000, 18999],
            "target_whitelist": ["127.0.0.1"],
            "snapshot_marker": str(tmp / "S0-B.ok"),
        }
    )
    return cfg


class FakeRunner:
    """记录调用并返回可控 Result 的命令执行替身。"""

    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or {}
        self.calls: list[dict] = []
        self.fail_patterns: dict[str, Result] = {}
        self.ps_payload: list[dict] = [{"Name": "demo-1", "Service": "web", "State": "running"}]

    @staticmethod
    def project_name(compose_path: str) -> str:
        return "hornwork-test"

    def _dispatch(self, key: str) -> Result:
        for pattern, result in self.fail_patterns.items():
            if pattern in key:
                return result
        return Result(True, 0, "", "", 3, [])

    def run(self, args, timeout: int = 120, retries: int = 0) -> Result:
        cmd = [str(a) for a in args]
        self.calls.append({"kind": "run", "cmd": cmd, "timeout": timeout, "retries": retries})
        return self._dispatch(" ".join(cmd))

    def compose(self, compose_path: str, *args: str, timeout: int = 120) -> Result:
        cmd = [str(a) for a in args]
        self.calls.append(
            {"kind": "compose", "path": str(compose_path), "args": cmd, "timeout": timeout}
        )
        key = " ".join(cmd)
        if key.strip() == "ps --format json":
            payload = "\n".join(json.dumps(item) for item in self.ps_payload)
            return Result(True, 0, payload, "", 3, cmd)
        return self._dispatch(key)

    # 便于断言
    def compose_calls(self) -> list[list[str]]:
        return [call["args"] for call in self.calls if call["kind"] == "compose"]


class _TmpCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = _mk_tmp()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# 端口解析
# ---------------------------------------------------------------------------
class PortsTest(_TmpCase):
    def test_parse_port_spec(self):
        self.assertEqual(portlib.parse_port_spec("3000:3000"), (None, 3000, 3000))
        self.assertEqual(portlib.parse_port_spec("127.0.0.1:8000:80"), ("127.0.0.1", 8000, 80))
        self.assertEqual(portlib.parse_port_spec(8080), (None, 8080, 8080))
        self.assertEqual(portlib.parse_port_spec("8080"), (None, 8080, 8080))
        self.assertEqual(portlib.parse_port_spec("8000:80/udp"), (None, 8000, 80))
        self.assertEqual(
            portlib.parse_port_spec({"target": 80, "published": 8080, "host_ip": "127.0.0.1"}),
            ("127.0.0.1", 8080, 80),
        )
        for bad in ("abc", "3000:abc", "8000-8005:8000-8005", "", None, True, -1, "0:80"):
            self.assertIsNone(portlib.parse_port_spec(bad), msg=repr(bad))

    def test_compose_ports(self):
        compose = {
            "services": {
                "web": {"ports": ["3000:3000", 8080, "127.0.0.1:9000:90"]},
                "db": {"ports": [{"target": 3306, "published": "13306", "protocol": "tcp"}]},
            }
        }
        self.assertEqual(
            portlib.compose_ports(compose),
            [
                {"container": 3000, "host": 3000, "bind": None, "protocol": "tcp"},
                {"container": 8080, "host": 8080, "bind": None, "protocol": "tcp"},
                {"container": 90, "host": 9000, "bind": "127.0.0.1", "protocol": "tcp"},
                {"container": 3306, "host": 13306, "bind": None, "protocol": "tcp"},
            ],
        )
        self.assertEqual(portlib.compose_ports({}), [])
        self.assertIsInstance(portlib.listening_ports(), set)

    def test_pick_and_allocate(self):
        self.assertEqual(portlib.pick_port({18000, 18001}, 18000, 18003), 18002)
        self.assertIsNone(portlib.pick_port(set(range(18000, 18003)), 18000, 18002))
        mapping, err = portlib.allocate_ports([80, 3306], set(), 18000, 18010)
        self.assertIsNone(err)
        self.assertEqual(mapping, {80: 18000, 3306: 18001})
        mapping2, err2 = portlib.allocate_ports([80, 81], set(), 18000, 18000)
        self.assertEqual(mapping2, {80: 18000})
        self.assertIn("耗尽", err2 or "")


# ---------------------------------------------------------------------------
# 索引 / compose 解析
# ---------------------------------------------------------------------------
class IndexTest(_TmpCase):
    def setUp(self) -> None:
        super().setUp()
        self.vulhub = self.tmp / "vulhub"
        _make_fake_vulhub(self.vulhub)

    def test_parse_compose_single_service(self):
        path = self.vulhub / "grafana" / "CVE-2021-43798" / "docker-compose.yml"
        entry = parse_compose(str(path), str(self.vulhub))
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["env_id"], ENV_GRAFANA)
        self.assertEqual(entry["category"], "grafana")
        self.assertEqual(entry["dir"], "CVE-2021-43798")
        self.assertEqual(entry["cve"], "CVE-2021-43798")
        self.assertEqual(entry["compose_path"], str(path))
        self.assertEqual(entry["images"], ["vulhub/grafana:8.2.6"])
        self.assertEqual(entry["services"][0]["name"], "grafana")
        self.assertEqual(entry["services"][0]["image"], "vulhub/grafana:8.2.6")
        self.assertFalse(entry["services"][0]["build"])
        self.assertEqual(
            entry["services"][0]["ports"], [{"container": 3000, "host": 3000, "bind": None}]
        )
        self.assertIn("目录穿越", entry["summary"])
        self.assertLessEqual(len(entry["summary"]), 200)
        self.assertTrue(str(entry["readme_path"]).endswith("README.md"))

    def test_parse_compose_multi_service_build(self):
        path = self.vulhub / "app" / "CVE-2020-1111" / "docker-compose.yml"
        entry = parse_compose(str(path), str(self.vulhub))
        assert entry is not None
        self.assertEqual(entry["env_id"], ENV_APP)
        services = {svc["name"]: svc for svc in entry["services"]}
        self.assertEqual(set(services), {"web", "db"})
        self.assertTrue(services["web"]["build"])
        self.assertFalse(services["db"]["build"])
        self.assertEqual(services["web"]["ports"], [{"container": 80, "host": 8080, "bind": None}])
        self.assertEqual(entry["images"], ["mysql:5.7"])
        self.assertIsNone(entry["readme_path"])
        self.assertEqual(entry["summary"], "")

    def test_parse_compose_invalid(self):
        bad = self.tmp / "bad.yml"
        bad.write_text("services: {}\n", encoding="utf-8")
        self.assertIsNone(parse_compose(str(bad), str(self.vulhub)))
        not_yaml = self.tmp / "broken.yml"
        not_yaml.write_text("services: [unclosed\n", encoding="utf-8")
        self.assertIsNone(parse_compose(str(not_yaml), str(self.vulhub)))
        self.assertIsNone(parse_compose(str(self.tmp / "missing.yml"), str(self.vulhub)))

    def test_build_and_load_index(self):
        out = self.tmp / "data" / "vulhub-index.json"
        res = build_index(str(self.vulhub), str(out))
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 2)
        self.assertEqual(res["errors"], [])
        self.assertEqual(res["path"], str(out))
        self.assertGreaterEqual(res["elapsed_ms"], 0)
        self.assertTrue(out.is_file())
        entries = load_index(str(out))
        self.assertEqual([e["env_id"] for e in entries], sorted([ENV_APP, ENV_GRAFANA]))
        self.assertEqual(load_index(str(self.tmp / "nope.json")), [])
        self.assertEqual(load_index(str(out))[0]["category"], "app")

        missing = build_index(str(self.tmp / "no-such-root"), str(out))
        self.assertFalse(missing["ok"])
        self.assertEqual(missing["count"], 0)
        self.assertTrue(missing["errors"])

    def test_non_cve_env_is_indexed(self):
        """无 CVE 的环境也要收录（cve=None），--type 仍能按 category 过滤。"""
        root = self.tmp / "vulhub2"
        env_dir = root / "wordpress" / "phpmyadmin-4.8"
        env_dir.mkdir(parents=True)
        (env_dir / "docker-compose.yml").write_text(
            "services:\n  web:\n    image: vulhub/phpmyadmin:4.8\n    ports:\n      - '8080:80'\n",
            encoding="utf-8",
        )
        entry = parse_compose(str(env_dir / "docker-compose.yml"), str(root))
        assert entry is not None
        self.assertIsNone(entry["cve"])
        self.assertEqual(entry["env_id"], "wordpress/phpmyadmin-4.8")
        self.assertEqual(entry["category"], "wordpress")
        out = self.tmp / "vulhub2-index.json"
        res = build_index(str(root), str(out))
        self.assertTrue(res["ok"])
        self.assertEqual(res["count"], 1)
        self.assertEqual(load_index(str(out))[0]["cve"], None)

    def test_render_patched_compose(self):
        path = self.vulhub / "grafana" / "CVE-2021-43798" / "docker-compose.yml"
        entry = parse_compose(str(path), str(self.vulhub))
        assert entry is not None
        before = path.read_bytes()
        out = self.tmp / "overrides" / "grafana.yml"
        result_path = complib.render_patched_compose(
            entry, str(out), "0.0.0.0", {3000: 18001}
        )
        self.assertEqual(result_path, str(out))
        self.assertEqual(path.read_bytes(), before, "原 compose 不允许被修改")
        doc = yaml.safe_load(out.read_text(encoding="utf-8"))
        ports = doc["services"]["grafana"]["ports"]
        self.assertEqual(ports, ["127.0.0.1:18001:3000"])
        self.assertFalse(any(str(p).startswith("0.0.0.0") for p in ports))
        self.assertEqual(doc["x-hornwork-lab"]["port_map"], {"3000": 18001})
        self.assertEqual(doc["x-hornwork-lab"]["source_compose"], str(path))

    def test_render_multi_service_absolutizes_build(self):
        path = self.vulhub / "app" / "CVE-2020-1111" / "docker-compose.yml"
        entry = parse_compose(str(path), str(self.vulhub))
        assert entry is not None
        out = self.tmp / "overrides" / "app.yml"
        complib.render_patched_compose(entry, str(out), "127.0.0.1", {80: 18010, 3306: 18011})
        doc = yaml.safe_load(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["services"]["web"]["ports"], ["127.0.0.1:18010:80"])
        self.assertEqual(doc["services"]["db"]["ports"], ["127.0.0.1:18011:3306"])
        self.assertEqual(doc["services"]["web"]["build"], str(path.parent.resolve()))


# ---------------------------------------------------------------------------
# 守卫
# ---------------------------------------------------------------------------
class GuardTest(_TmpCase):
    def setUp(self) -> None:
        super().setUp()
        self.cfg = _cfg_for(self.tmp, self.tmp / "vulhub")

    def test_check_resources(self):
        with mock.patch("hornwork.lab.guard.free_mem_mb", return_value=4096), \
                mock.patch("hornwork.lab.guard.free_disk_gb", return_value=100.0):
            self.assertEqual(guard.check_resources(self.cfg, 0), [])
        with mock.patch("hornwork.lab.guard.free_mem_mb", return_value=100), \
                mock.patch("hornwork.lab.guard.free_disk_gb", return_value=100.0):
            reasons = guard.check_resources(self.cfg, 0)
        self.assertTrue(any("内存" in r for r in reasons))
        tight_disk_cfg = {**self.cfg, "lab": {**self.cfg["lab"], "min_disk_gb": 5}}
        with mock.patch("hornwork.lab.guard.free_mem_mb", return_value=4096), \
                mock.patch("hornwork.lab.guard.free_disk_gb", return_value=0.1):
            reasons = guard.check_resources(tight_disk_cfg, 0)
        self.assertTrue(any("磁盘" in r for r in reasons))
        reasons = guard.check_resources(self.cfg, int(self.cfg["lab"]["max_envs"]))
        self.assertTrue(any("并发" in r or "max_envs" in r for r in reasons))

    def test_snapshot_guard(self):
        marker = Path(self.cfg["lab"]["snapshot_marker"])
        reasons = guard.snapshot_guard(self.cfg, force=False)
        self.assertTrue(any("S0-B" in r or str(marker) in r for r in reasons))
        self.assertEqual(guard.snapshot_guard(self.cfg, force=True), [])
        marker.write_text("snapshot ok", encoding="utf-8")
        self.assertEqual(guard.snapshot_guard(self.cfg, force=False), [])

    def test_check_targets(self):
        cfg = {**self.cfg, "lab": {**self.cfg["lab"],
                                   "target_whitelist": ["127.0.0.1", "192.168.56.20"]}}
        for good in ("127.0.0.1", "127.0.0.1:8080", "http://127.0.0.1:8787/x",
                     "http://192.168.56.20:8080/path?q=1", "192.168.56.20"):
            self.assertTrue(guard.check_targets(cfg, good), msg=good)
        for bad in ("10.0.0.1", "http://evil.example/", "", "http://127.0.0.1.evil.com/"):
            self.assertFalse(guard.check_targets(cfg, bad), msg=bad)


# ---------------------------------------------------------------------------
# 命令执行器
# ---------------------------------------------------------------------------
class RunnerTest(_TmpCase):
    def setUp(self) -> None:
        super().setUp()
        self.cfg = _cfg_for(self.tmp, self.tmp / "vulhub")

    def test_local_run(self):
        runner = CommandRunner(self.cfg)
        res = runner.run([sys.executable, "-c", "print('lab-ok')"], timeout=30)
        self.assertTrue(res.ok, res.stderr)
        self.assertEqual(res.rc, 0)
        self.assertIn("lab-ok", res.stdout)
        self.assertGreaterEqual(res.elapsed_ms, 0)
        self.assertEqual(res.cmd[0], sys.executable)

    def test_missing_command(self):
        runner = CommandRunner(self.cfg)
        res = runner.run(["definitely-not-a-real-command-hornwork"], timeout=5)
        self.assertFalse(res.ok)
        self.assertEqual(res.rc, 127)

    def test_ssh_wrap_and_path_mapping(self):
        cfg = {**self.cfg, "lab": {**self.cfg["lab"], "backend": "ssh",
                                   "overrides_dir": "/opt/lab/overrides"}}
        cfg["lab"]["ssh"] = {
            "host": "192.168.56.20", "user": "lab", "key": "~/.ssh/id_ed25519_lab",
            "connect_timeout": 5, "remote_vulhub_root": "/srv/vulhub",
            "remote_overrides_dir": "/srv/lab/overrides",
        }
        runner = CommandRunner(cfg)
        fake = SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with mock.patch("hornwork.lab.runner.subprocess.run", return_value=fake) as patched:
            res = runner.run(
                ["docker", "compose", "-f", "/opt/lab/overrides/x.yml", "ps"], timeout=30
            )
        self.assertTrue(res.ok)
        argv = patched.call_args.args[0]
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("lab@192.168.56.20", argv)
        self.assertIn("/srv/lab/overrides/x.yml", argv[-1])

    def test_project_name(self):
        name = CommandRunner.project_name("/opt/lab/overrides/grafana_CVE-2021-43798.yml")
        self.assertTrue(name.startswith("hornwork-"))
        self.assertNotIn(" ", name)
        self.assertLessEqual(len(name), 63)

    def test_push_file(self):
        local_runner = CommandRunner(self.cfg)
        self.assertTrue(local_runner.push_file("/opt/lab/overrides/x.yml").ok)

        cfg = {**self.cfg, "lab": {**self.cfg["lab"], "backend": "ssh",
                                   "overrides_dir": "/opt/lab/overrides"}}
        cfg["lab"]["ssh"] = {
            "host": "192.168.56.20", "user": "lab", "key": "~/.ssh/id_ed25519_lab",
            "connect_timeout": 5, "remote_overrides_dir": "/srv/lab/overrides",
        }
        runner = CommandRunner(cfg)
        fake = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch("hornwork.lab.runner.subprocess.run", return_value=fake) as patched:
            res = runner.push_file("/opt/lab/overrides/x.yml")
        self.assertTrue(res.ok)
        argv = patched.call_args.args[0]
        self.assertEqual(argv[0], "scp")
        self.assertEqual(argv[-1], "lab@192.168.56.20:/srv/lab/overrides/x.yml")


# ---------------------------------------------------------------------------
# 存储层
# ---------------------------------------------------------------------------
class StoreLayerTest(_TmpCase):
    def test_schema_env_and_runs(self):
        store = Store(self.tmp / "hornwork.db")
        try:
            labstore.init_schema(store)
            labstore.init_schema(store)  # 幂等

            vulhub = self.tmp / "vulhub"
            _make_fake_vulhub(vulhub)
            entry = parse_compose(
                str(vulhub / "grafana" / "CVE-2021-43798" / "docker-compose.yml"), str(vulhub)
            )
            assert entry is not None
            labstore.upsert_env(store, entry)
            env = labstore.get_env(store, ENV_GRAFANA)
            assert env is not None
            self.assertEqual(env["category"], "grafana")
            self.assertEqual(env["cve"], "CVE-2021-43798")
            self.assertEqual(env["ports"], {3000: 3000})
            self.assertFalse(env["running"])

            labstore.set_env_state(store, ENV_GRAFANA, "starting", host_ports={3000: 18000})
            labstore.set_env_running(
                store, ENV_GRAFANA, True, {3000: 18000}, "2099-01-01T00:00:00.000Z"
            )
            env = labstore.get_env(store, ENV_GRAFANA)
            assert env is not None
            self.assertTrue(env["running"])
            self.assertEqual(env["ports"], {3000: 18000})
            self.assertEqual(labstore.count_running(store), 1)
            self.assertEqual(len(labstore.expired_envs(store, "2000-01-01T00:00:00.000Z")), 0)
            self.assertEqual(len(labstore.expired_envs(store, "2100-01-01T00:00:00.000Z")), 1)

            labstore.add_run(
                store,
                {
                    "run_id": "lab-test-1", "env_id": ENV_GRAFANA, "action": "up",
                    "started_at": schema.utc_now(), "ended_at": schema.utc_now(),
                    "elapsed_ms": 12, "result": "ok", "detail": "ok",
                    "ports_bound": {3000: 18000}, "cleanup_ok": 1,
                },
            )
            runs = labstore.recent_runs(store, 10)
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["result"], "ok")
            self.assertEqual(labstore.runs_for_env(store, ENV_GRAFANA)[0]["run_id"], "lab-test-1")
            summary = labstore.run_summary(store)
            self.assertEqual(summary["total"], 1)
            self.assertEqual(summary["by_result"], {"ok": 1})
        finally:
            store.close()


# ---------------------------------------------------------------------------
# LabCtl 状态机（FakeRunner + 内存 SQLite）
# ---------------------------------------------------------------------------
class LabCtlTest(_TmpCase):
    def setUp(self) -> None:
        super().setUp()
        self.vulhub = self.tmp / "vulhub"
        _make_fake_vulhub(self.vulhub)
        self.cfg = _cfg_for(self.tmp, self.vulhub)
        # 快照标记默认存在（模拟"已回滚 S0-B"）；守卫用例可改到缺失路径
        Path(self.cfg["lab"]["snapshot_marker"]).write_text("snapshot ok", encoding="utf-8")
        self.store = Store(self.tmp / "hornwork.db")
        # port_free 语义：True=端口空闲，False=端口已监听。健康检查要求 False。
        self.port_free_state = {"value": False}
        self.port_patches = (
            mock.patch("hornwork.lab.ports.listening_ports", return_value=set()),
            mock.patch(
                "hornwork.lab.ports.port_free",
                side_effect=lambda *args, **kwargs: self.port_free_state["value"],
            ),
        )

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:  # noqa: BLE001
            pass
        super().tearDown()

    def _make_ctl(self, fake: FakeRunner | None = None):
        events: list[dict] = []
        audits: list[dict] = []

        def _audit(**kwargs):
            audits.append(kwargs)

        ctl = LabCtl(self.cfg, self.store, event_sink=events.append, audit_sink=_audit)
        ctl.runner = fake or FakeRunner(self.cfg)
        index_res = ctl.index()
        self.assertTrue(index_res["ok"], index_res)
        return ctl, ctl.runner, events, audits

    def _runs(self, action: str | None = None) -> list[dict]:
        rows = self.store.query("SELECT * FROM lab_run ORDER BY started_at")
        if action:
            rows = [row for row in rows if row.get("action") == action]
        return rows

    def test_index_list(self):
        ctl, _fake, _events, _audits = self._make_ctl()
        self.assertEqual(len(ctl.list()), 2)
        self.assertEqual([item["env_id"] for item in ctl.list(type="grafana")], [ENV_GRAFANA])
        self.assertEqual([item["env_id"] for item in ctl.list(type="CVE-2020-1111")], [ENV_APP])
        self.assertEqual(len(ctl.list(status="down")), 2)
        self.assertEqual(ctl.list(status="running"), [])
        force = ctl.index(force=True)
        self.assertTrue(force["ok"])
        self.assertEqual(force["count"], 2)
        self.assertEqual(force["errors"], [])

    def test_up_success(self):
        with self.port_patches[0], self.port_patches[1]:
            ctl, fake, events, audits = self._make_ctl()
            res = ctl.up(ENV_GRAFANA, ttl_min=30)

            self.assertTrue(res["ok"], res)
            self.assertEqual(res["env_id"], ENV_GRAFANA)
            self.assertEqual(res["ports"], {3000: 18000})
            self.assertEqual(len(res["containers"]), 1)
            self.assertGreaterEqual(res["elapsed_ms"], 0)
            self.assertTrue(res["run_id"].startswith("lab-"))
            self.assertIsNotNone(res["expires_at"])

            # compose 调用：pull → up -d → ps
            args_list = fake.compose_calls()
            self.assertIn(["pull"], args_list)
            self.assertIn(["up", "-d", "--remove-orphans"], args_list)
            self.assertIn(["ps", "--format", "json"], args_list)

            # 覆盖副本存在且只绑回环
            override = Path(res["override"])
            self.assertTrue(override.is_file())
            doc = yaml.safe_load(override.read_text(encoding="utf-8"))
            self.assertEqual(doc["services"]["grafana"]["ports"], ["127.0.0.1:18000:3000"])

            # 事件/审计
            self.assertEqual(events[-1]["event_type"], "lab_action")
            self.assertEqual(schema.validate_event(events[-1]), [])
            self.assertEqual(events[-1]["raw"]["action"], "up")
            self.assertEqual(events[-1]["raw"]["result"], "ok")
            self.assertEqual(events[-1]["raw"]["ports"], {"3000": 18000})
            self.assertEqual(audits[-1]["action"], "lab.up")
            self.assertEqual(audits[-1]["target"], ENV_GRAFANA)
            self.assertTrue(audits[-1]["ok"])

            # 落库：运行态 + lab_run
            env = labstore.get_env(self.store, ENV_GRAFANA)
            assert env is not None
            self.assertTrue(env["running"])
            self.assertEqual(env["ports"], {3000: 18000})
            self.assertEqual(env["state"], "healthy")
            ups = self._runs("up")
            self.assertEqual(len(ups), 1)
            self.assertEqual(ups[0]["result"], "ok")
            self.assertEqual(ups[0]["cleanup_ok"], 1)
            self.assertIn("18000", ups[0]["ports_bound"])

            # 状态文件
            state = json.loads(Path(self.cfg["lab"]["state_file"]).read_text(encoding="utf-8"))
            self.assertEqual(state["envs"][ENV_GRAFANA]["state"], "healthy")
            self.assertEqual(state["envs"][ENV_GRAFANA]["ports"], {"3000": 18000})

            # status 单环境 / 全部
            one = ctl.status(ENV_GRAFANA)
            self.assertTrue(one["ok"])
            self.assertEqual(one["state"], "healthy")
            self.assertEqual(one["ports"], {3000: 18000})
            self.assertGreater(one["ttl_left_sec"], 0)
            all_status = ctl.status(None)
            self.assertEqual(all_status["running"], 1)
            self.assertEqual(all_status["total"], 2)
            stats = ctl.stats()
            self.assertEqual(stats["running"], 1)
            self.assertEqual(stats["runs"]["by_result"], {"ok": 1})

            # 已在运行时再次 up 被守卫拒绝
            again = ctl.up(ENV_GRAFANA)
            self.assertFalse(again["ok"])
            self.assertEqual(again["error"], "already_running")

            # down（先模拟端口已释放，cleanup_ok 才为 true）
            self.port_free_state["value"] = True
            down = ctl.down(ENV_GRAFANA)
            self.assertTrue(down["ok"], down)
            self.assertEqual(down["freed_ports"], [18000])
            self.assertTrue(down["cleanup_ok"])
            env = labstore.get_env(self.store, ENV_GRAFANA)
            assert env is not None
            self.assertFalse(env["running"])
            self.assertEqual(env["state"], "down")
            down_runs = self._runs("down")
            self.assertEqual(down_runs[-1]["result"], "ok")
            self.assertEqual(down_runs[-1]["cleanup_ok"], 1)
            self.assertEqual(audits[-1]["action"], "lab.down")
            self.assertTrue(audits[-1]["ok"])
            self.assertEqual(ctl.status(ENV_GRAFANA)["state"], "down")
            self.assertEqual(ctl.list(status="running"), [])
            logs = ctl.logs(ENV_GRAFANA, tail=10)
            self.assertTrue(logs["ok"])
            self.assertEqual(logs["tail"], 10)

    def test_up_failure_cleans_up(self):
        fake = FakeRunner(self.cfg)
        fake.fail_patterns["up -d"] = Result(False, 1, "", "compose up boom", 7, [])
        with self.port_patches[0], self.port_patches[1]:
            ctl, fake, events, audits = self._make_ctl(fake)
            res = ctl.up(ENV_APP)

        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "up_failed")
        self.assertIn("日志尾部", res["detail"])
        self.assertEqual(events[-1]["raw"]["result"], "error")
        self.assertFalse(audits[-1]["ok"])
        # 失败后必须执行 down -v 清理
        down_calls = [args for args in fake.compose_calls() if args and args[0] == "down"]
        self.assertTrue(down_calls, "失败路径必须调用 compose down")
        self.assertIn("-v", down_calls[0])
        env = labstore.get_env(self.store, ENV_APP)
        assert env is not None
        self.assertFalse(env["running"])
        self.assertEqual(env["state"], "error")
        runs = self._runs("up")
        self.assertEqual(runs[-1]["result"], "error")
        self.assertIn("boom", runs[-1]["detail"])

    def test_up_guards(self):
        with self.port_patches[0], self.port_patches[1]:
            ctl, fake, _events, _audits = self._make_ctl()

            missing = ctl.up("no/such-env")
            self.assertFalse(missing["ok"])
            self.assertEqual(missing["error"], "env_not_found")

            # 快照标记缺失 → 拒绝；force 可跳过
            marker = self.tmp / "missing-S0-B.ok"
            self.cfg["lab"]["snapshot_marker"] = str(marker)
            snap = ctl.up(ENV_GRAFANA)
            self.assertFalse(snap["ok"])
            self.assertEqual(snap["error"], "snapshot_missing")
            self.assertFalse(any(call["kind"] == "compose" for call in fake.calls))

            marker.write_text("ok", encoding="utf-8")
            with mock.patch("hornwork.lab.guard.free_mem_mb", return_value=10):
                denied = ctl.up(ENV_GRAFANA)
            self.assertFalse(denied["ok"])
            self.assertEqual(denied["error"], "resource_denied")
            self.assertFalse(any(call["kind"] == "compose" for call in fake.calls))

            # 资源正常时可启动（force 与快照无关，这里标记已补齐，验证正常路径）
            self.cfg["lab"]["max_envs"] = 5
            started = ctl.up(ENV_GRAFANA)
            self.assertTrue(started["ok"], started)

    def test_cleanup_expired(self):
        with self.port_patches[0], self.port_patches[1]:
            ctl, fake, events, audits = self._make_ctl()
            up = ctl.up(ENV_GRAFANA, ttl_min=1)
            self.assertTrue(up["ok"])
            fake.calls.clear()

            past = "2000-01-01T00:00:00.000Z"
            state_path = Path(self.cfg["lab"]["state_file"])
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["envs"][ENV_GRAFANA]["expires_at"] = past
            state_path.write_text(json.dumps(state), encoding="utf-8")
            self.store.execute(
                "UPDATE lab_env SET expires_at=? WHERE env_id=?", (past, ENV_GRAFANA)
            )

            # TTL 到点后清理（模拟端口已释放，cleanup_ok 才为 true）
            self.port_free_state["value"] = True
            res = ctl.cleanup_expired()
            self.assertTrue(res["ok"])
            self.assertEqual(res["count"], 1)
            self.assertEqual(res["checked"], 1)
            self.assertEqual(res["cleaned"][0]["env_id"], ENV_GRAFANA)
            self.assertTrue(res["cleaned"][0]["ok"])
            env = labstore.get_env(self.store, ENV_GRAFANA)
            assert env is not None
            self.assertFalse(env["running"])
            cleanup_runs = self._runs("cleanup")
            self.assertEqual(cleanup_runs[-1]["result"], "auto_cleanup")
            self.assertEqual(audits[-1]["action"], "lab.cleanup")
            self.assertIn(events[-1]["raw"]["result"], ("ok", "auto_cleanup"))
            self.assertTrue(any(args and args[0] == "down" for args in fake.compose_calls()))

    def test_down_unknown_env(self):
        with self.port_patches[0], self.port_patches[1]:
            ctl, _fake, _events, _audits = self._make_ctl()
            res = ctl.down("no/such-env")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "env_not_found")


if __name__ == "__main__":
    unittest.main(verbosity=2)
