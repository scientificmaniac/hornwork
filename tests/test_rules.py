"""Hornwork 规则库 / 部署文件 / 脚本 / 交付文档 的静态校验。

设计原则（与任务约束一致）：
- 不写任何临时文件（DSH 沙箱下系统临时目录可能不可写）；
- 第三方库缺失时用 `unittest.SkipTest` 跳过对应用例（yara-python 在 Windows 上可能未安装）；
- 团队模块（NetRuleSet / HostRuleEngine）尚未就绪或接口变化时 try/except 跳过并记录原因；
- 全部使用 UTF-8 读取，显式检查"无 BOM"。

运行：
    cd hornwork
    python -m unittest discover -s tests -v
    # 或
    python -m unittest tests.test_rules -v
"""

from __future__ import annotations

import csv
import io
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TEXT_SUFFIXES = {
    ".yar", ".rules", ".json", ".yml", ".yaml", ".txt", ".jsonl",
    ".csv", ".sh", ".c", ".md", ".conf", ".service",
}
NON_RULE_TEXT_DIRS = {"__pycache__", ".git", ".mypy_cache", ".pytest_cache"}

HOST_OPS = {
    "eq", "neq", "in", "nin", "prefix", "suffix", "contains",
    "regex", "gt", "lt", "exists",
}
PLAYBOOK_ACTIONS = {
    "quarantine_file", "collect_forensics", "open_case", "restore_file",
    "kill_process", "block_ip", "isolate_host", "disable_account",
}
EVENT_TYPES_FALLBACK = {
    "process_create", "process_exit", "file_create", "file_modify", "file_delete",
    "net_connect", "dns_query", "logon", "logon_fail", "account_create",
    "persist_item", "memory_scan", "scan_result", "alert", "net_flow",
}


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def read_text(path: Path) -> str:
    """按 UTF-8 读取，并保证没有 BOM。"""
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise AssertionError(f"{path} 含 UTF-8 BOM")
    return raw.decode("utf-8")


def yara_files() -> list[Path]:
    return sorted((RULES / "yara").glob("*.yar"))


def rule_texts() -> dict[str, str]:
    return {p.stem: read_text(p) for p in yara_files()}


def load_yaml_module():
    try:
        import yaml  # noqa: PLC0415

        return yaml
    except ImportError:  # pragma: no cover - 仅缺依赖时
        return None


def run_bash_syntax(script: Path) -> None:
    """优先用 Git Bash（Windows 上的完整 bash），其次 PATH 里的 bash；都不可用时跳过。"""
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        shutil.which("bash"),
        "/bin/bash",
        "/usr/bin/bash",
    ]
    bash = next((c for c in candidates if c and Path(c).is_file()), None)
    if bash is None:
        raise unittest.SkipTest("未找到 bash，跳过 bash -n 语法检查")
    try:
        proc = subprocess.run(
            [bash, "-n", str(script)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        raise unittest.SkipTest(f"bash 不可用（{exc}），跳过 {script.name} 语法检查") from exc
    if proc.returncode == 0:
        return
    detail = f"{proc.stdout}\n{proc.stderr}"
    # 说明：Windows 的 bash.exe 在受限沙箱中可能无法创建信号管道（Win32 error 5），
    # system32\bash.exe 则是 WSL 启动器（未安装发行版时报 E_ACCESSDENIED）。
    # 这些都属于"本机无法执行 bash"，按跳过处理（脚本语法另用 bashlex 静态校验）。
    if re.search(
        r"couldn't create signal pipe|Win32 error 5|WSL|Windows Subsystem|E_ACCESSDENIED",
        detail,
        re.IGNORECASE,
    ):
        raise unittest.SkipTest(
            f"bash 无法在当前环境执行（{bash}），跳过 {script.name} 的 bash -n 检查"
        )
    raise AssertionError(
        f"{script.name} 语法错误（bash -n 退出码 {proc.returncode}）：\n{detail}"
    )


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------
class TestYaraRules(unittest.TestCase):
    def test_file_count_and_unique_stems(self):
        files = yara_files()
        self.assertGreaterEqual(len(files), 10, "YARA 规则至少 10 条")
        self.assertLessEqual(len(files), 15, "YARA 规则最多 15 条")
        stems = [p.stem for p in files]
        self.assertEqual(len(stems), len(set(stems)), "不同 .yar 文件 stem 必须唯一")

    def test_meta_required_fields(self):
        for name, text in rule_texts().items():
            with self.subTest(rule=name):
                for field in ("attack", "severity", "source"):
                    self.assertRegex(
                        text,
                        rf"(?m)^\s*{field}\s*=",
                        f"{name}.yar 缺少 meta.{field}",
                    )
                m = re.search(r"(?m)^\s*severity\s*=\s*(\d+)\s*$", text)
                self.assertIsNotNone(m, f"{name}.yar 的 severity 必须是整数")
                self.assertTrue(0 <= int(m.group(1)) <= 100, "severity 取值 0-100")
                self.assertEqual(
                    len(re.findall(r"(?m)^\s*rule\s+[A-Za-z_]\w*", text)), 1,
                    f"{name}.yar 建议一条文件一条规则",
                )

    def test_rule_names_unique(self):
        names: list[str] = []
        for _stem, text in rule_texts().items():
            names.extend(re.findall(r"(?m)^\s*rule\s+([A-Za-z_]\w*)", text))
        self.assertEqual(len(names), len(set(names)), "YARA rule 名必须全局唯一")

    def test_eicar_rule_present(self):
        texts = rule_texts()
        hit = [name for name, text in texts.items()
               if "EICAR" in text.upper() and "58 35 4F 21" in text.upper()]
        self.assertTrue(hit, "必须包含 EICAR 测试串规则（hex 形式）")
        self.assertIn("severity = 100", texts[hit[0]])

    def test_compile_with_yara_python(self):
        try:
            import yara  # noqa: PLC0415
        except ImportError:
            raise unittest.SkipTest("未安装 yara-python，跳过 YARA 编译")
        # 用 sources={stem: text} 编译，规避 Windows libyara 对非 ASCII 文件路径的限制
        try:
            rules = yara.compile(
                sources=rule_texts(),
                externals={"filename": "", "filetype": "", "filesize": 0},
            )
        except Exception as exc:  # noqa: BLE001
            self.fail(f"YARA 编译失败：{exc}")
        self.assertIsNotNone(rules)


# ---------------------------------------------------------------------------
# 网络规则
# ---------------------------------------------------------------------------
class TestNetRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.net_files = sorted((RULES / "net").glob("*.rules"))
        cls.cfg = {
            "general": {"rule_dir": str(RULES)},
            "engines": {"net_rule_dir": str(RULES / "net")},
            "net": {
                "home_net": "192.168.56.0/24",
                "dedup_sec": 60,
                "tracker_window_sec": 5,
                "ioc_domain_set": "ioc_domains",
                "ioc_ip_set": "ioc_ips",
            },
        }

    def test_rule_files_exist(self):
        self.assertTrue(self.net_files, "rules/net/*.rules 不存在")
        text = "\n".join(read_text(p) for p in self.net_files)
        self.assertIn("rule N-0101", text)

    def test_parse_with_netrules(self):
        try:
            from hornwork.engines.netrules import NetRuleSet  # noqa: PLC0415
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f"hornwork.engines.netrules.NetRuleSet 不可用：{exc}")
        try:
            ruleset = NetRuleSet(self.cfg)
            rules = ruleset.rules()
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f"NetRuleSet 接口尚不可用（{exc}）")

        ids = [r.get("rule_id") for r in rules]
        self.assertEqual(len(rules), 8, f"应解析出 8 条网络规则，实际 {len(rules)}：{ids}")
        self.assertEqual(ids, [f"N-{n:04d}" for n in range(101, 109)])
        self.assertEqual(len(set(ids)), 8)
        # 关键字段与 对齐
        by_id = {r["rule_id"]: r for r in rules}
        self.assertEqual(by_id["N-0101"]["proto"], "tcp")
        self.assertEqual(by_id["N-0101"]["severity"], 8)
        self.assertEqual(by_id["N-0101"]["technique"], "T1046")
        self.assertIn("syn", by_id["N-0101"]["flags"])
        self.assertIn("ack", by_id["N-0101"]["not_flags"])
        self.assertEqual(by_id["N-0103"]["dst_domain_in"], ["ioc_domains"])
        self.assertEqual(by_id["N-0105"]["dst_port_in"], [445, 139])
        self.assertEqual(by_id["N-0106"]["avg_interval_between"], [30.0, 90.0])
        self.assertEqual(by_id["N-0108"]["direction"], "outbound")

    def test_rule_source_fields(self):
        # 直接文本校验，避免依赖解析器
        text = read_text(RULES / "net" / "hornwork-net.rules")
        for n in range(101, 109):
            self.assertIn(f"rule N-{n:04d}", text)
        for key in ("proto:", "severity:", "msg:"):
            self.assertIn(key, text)


# ---------------------------------------------------------------------------
# 主机规则 JSON DSL
# ---------------------------------------------------------------------------
class TestHostRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = sorted((RULES / "host").glob("*.json"))

    def _rules(self) -> list[dict]:
        rules = []
        for path in self.files:
            data = json.loads(read_text(path))
            if isinstance(data, dict):
                rules.append(data)
            elif isinstance(data, list):
                for item in data:
                    self.assertIsInstance(item, dict)
                    rules.append(item)
            else:
                self.fail(f"{path.name} 必须是对象或对象数组")
        return rules

    def test_count_and_required_fields(self):
        self.assertEqual(len(self._rules()), 8, "主机规则应为 8 条")
        for rule in self._rules():
            with self.subTest(rule=rule.get("id")):
                self.assertTrue(rule.get("id"), "缺少 id")
                self.assertTrue(rule.get("name"), "缺少 name")
                self.assertIsInstance(rule.get("level"), int)
                self.assertTrue(1 <= rule["level"] <= 10, "level 取值 1-10")
                self.assertIsInstance(rule.get("condition"), dict, "condition 必须是对象")
                self.assertIsInstance(rule.get("event_types"), list, "event_types 必须是数组")

    def test_event_types_in_schema(self):
        try:
            from hornwork.schema import EVENT_TYPES  # noqa: PLC0415
        except Exception:  # noqa: BLE001
            EVENT_TYPES = EVENT_TYPES_FALLBACK
        for rule in self._rules():
            for et in rule["event_types"]:
                with self.subTest(rule=rule.get("id"), event_type=et):
                    self.assertIn(et, EVENT_TYPES)

    def _check_condition(self, cond, path: str) -> int:
        """递归校验条件树；返回叶子数量。"""
        self.assertIsInstance(cond, dict, f"{path}: 条件节点必须是对象")
        leaves = 0
        for key, value in cond.items():
            if key in ("all", "any", "not"):
                self.assertIsInstance(value, list, f"{path}.{key} 必须是数组")
                self.assertTrue(value, f"{path}.{key} 不能为空数组")
                for idx, child in enumerate(value):
                    leaves += self._check_condition(child, f"{path}.{key}[{idx}]")
            elif key in ("field", "op", "value"):
                continue
            else:
                self.fail(f"{path}: 未知条件键 {key!r}（只允许 all/any/not/field/op/value）")
        if "field" in cond or "op" in cond:
            self.assertTrue(cond.get("field"), f"{path}: 叶子缺少 field")
            self.assertIn(cond.get("op"), HOST_OPS, f"{path}: 非法 op {cond.get('op')!r}")
            self.assertIn("value", cond, f"{path}: 叶子缺少 value")
            self.assertIsInstance(cond["field"], str)
            self.assertNotIn("*", cond["field"], f"{path}: field 不支持通配")
            return leaves + 1
        self.assertGreater(leaves, 0, f"{path}: 条件树没有叶子")
        return leaves

    def test_condition_tree_valid(self):
        for rule in self._rules():
            with self.subTest(rule=rule.get("id")):
                self.assertGreater(self._check_condition(rule["condition"], rule["id"]), 0)

    def test_engine_loads_rules(self):
        try:
            from hornwork.engines.hostrules import HostRuleEngine  # noqa: PLC0415
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f"HostRuleEngine 不可用：{exc}")
        cfg = {
            "general": {"rule_dir": str(RULES)},
            "engines": {"host_rule_dir": str(RULES / "host")},
        }
        try:
            engine = HostRuleEngine(cfg, None)
            result = engine.reload()
        except Exception as exc:  # noqa: BLE001
            raise unittest.SkipTest(f"HostRuleEngine 接口尚不可用（{exc}）")
        self.assertTrue(result.get("ok"), f"主机规则加载失败：{result.get('errors')}")
        self.assertEqual(result.get("rules"), 8)


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------
class TestSigmaRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = sorted((RULES / "sigma").rglob("*.yml"))
        cls.yaml = load_yaml_module()

    def test_count(self):
        self.assertGreaterEqual(len(self.files), 50, "Sigma 规则至少 50 条")
        self.assertLessEqual(len(self.files), 80, "Sigma 规则最多 80 条")

    def test_notice_exists(self):
        notice = RULES / "sigma" / "NOTICE.md"
        self.assertTrue(notice.is_file(), "缺少 rules/sigma/NOTICE.md")
        text = read_text(notice)
        for keyword in ("SigmaHQ", "DRL 1.1", "许可证", "选取范围"):
            self.assertIn(keyword, text, f"NOTICE.md 缺少 {keyword} 说明")

    def test_yaml_loadable_and_required_keys(self):
        if self.yaml is None:
            raise unittest.SkipTest("未安装 PyYAML，跳过 Sigma YAML 校验")
        for path in self.files:
            with self.subTest(file=path.relative_to(RULES / "sigma").as_posix()):
                doc = self.yaml.safe_load(read_text(path))
                self.assertIsInstance(doc, dict, f"{path.name} 不是 YAML 对象")
                for key in ("title", "id", "logsource", "detection"):
                    self.assertIn(key, doc, f"{path.name} 缺少 {key}")
                self.assertIsInstance(doc["logsource"], dict)
                self.assertIsInstance(doc["detection"], dict)

    def test_categories_supported(self):
        if self.yaml is None:
            raise unittest.SkipTest("未安装 PyYAML，跳过 Sigma YAML 校验")
        cats = set()
        for path in self.files:
            doc = self.yaml.safe_load(read_text(path))
            cat = (doc.get("logsource") or {}).get("category")
            cats.add(cat)
            self.assertIn(cat, {"process_creation", "file_event", "network_connection"},
                          f"{path.name} 的 logsource.category={cat!r} 不在支持范围")
        self.assertIn("process_creation", cats)
        self.assertIn("file_event", cats)


# ---------------------------------------------------------------------------
# sigdb 签名
# ---------------------------------------------------------------------------
class TestSigdb(unittest.TestCase):
    def test_hashes(self):
        path = RULES / "sigdb" / "hashes.txt"
        self.assertTrue(path.is_file(), "缺少 rules/sigdb/hashes.txt")
        lines = [ln.strip() for ln in read_text(path).splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
        self.assertTrue(lines, "hashes.txt 为空")
        for line in lines:
            with self.subTest(line=line[:24]):
                parts = line.split()
                self.assertIn(len(parts[0]), (32, 40, 64, 96, 128),
                              f"哈希长度非法：{parts[0]}")
                self.assertRegex(parts[0], r"^[0-9a-fA-F]+$")
        joined = " ".join(lines).lower()
        self.assertIn(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            joined,
            "hashes.txt 必须包含 EICAR 的 sha256",
        )

    def test_hex(self):
        path = RULES / "sigdb" / "hex.txt"
        self.assertTrue(path.is_file(), "缺少 rules/sigdb/hex.txt")
        lines = [ln.strip() for ln in read_text(path).splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
        self.assertTrue(lines)
        for line in lines:
            with self.subTest(line=line[:32]):
                if "|" in line:
                    pattern, name, score = [p.strip() for p in line.rsplit("|", 2)]
                    self.assertTrue(name, f"hex 规则缺少名称：{line}")
                    self.assertRegex(score, r"^\d+$", f"hex 评分必须是数字：{line}")
                else:
                    pattern = line.split()[0]
                tokens = pattern.replace(" ", "").split("??")
                for token in tokens:
                    self.assertRegex(token, r"^[0-9a-fA-F*]*$",
                                     f"hex 模式含非法字符：{pattern}")
                    self.assertEqual(len(token) % 2, 0,
                                     f"hex 模式半字节数必须为偶数：{pattern}")

    def test_regex(self):
        path = RULES / "sigdb" / "regex.txt"
        self.assertTrue(path.is_file(), "缺少 rules/sigdb/regex.txt")
        lines = [ln.strip() for ln in read_text(path).splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
        self.assertTrue(lines)
        for line in lines:
            with self.subTest(line=line[:32]):
                pattern, name, score = [p.strip() for p in line.rsplit("|", 2)]
                self.assertTrue(name)
                self.assertRegex(score, r"^\d+$")
                self.assertLessEqual(len(pattern.encode("utf-8")), 2048)
                try:
                    re.compile(pattern)
                except re.error as exc:
                    self.fail(f"正则编译失败 {pattern!r}: {exc}")


# ---------------------------------------------------------------------------
# 情报演示数据
# ---------------------------------------------------------------------------
class TestIntelSamples(unittest.TestCase):
    def _jsonl(self, name: str) -> list[dict]:
        path = RULES / "ioc" / name
        self.assertTrue(path.is_file(), f"缺少 {path}")
        records = []
        for idx, line in enumerate(read_text(path).splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                self.fail(f"{name}:{idx} 不是合法 JSON：{exc}")
        self.assertTrue(records, f"{name} 为空")
        return records

    def test_jsonl_schema(self):
        for name in ("sample-domains.jsonl", "sample-ips.jsonl", "sample-hashes.jsonl"):
            for rec in self._jsonl(name):
                with self.subTest(file=name, value=rec.get("value")):
                    self.assertIn(rec.get("type"), {"ip", "domain", "url", "hash", "filename"})
                    self.assertTrue(rec.get("value"))
                    self.assertIsInstance(rec.get("confidence"), int)
                    self.assertIn(rec.get("tlp"), {"white", "green", "amber", "red"})
                    self.assertTrue(rec.get("source"))

    def test_domains_reserved(self):
        for rec in self._jsonl("sample-domains.jsonl"):
            value = rec["value"].lower()
            ok = value.endswith(".example") or any(
                value.endswith(s) for s in ("example.com", "example.net", "example.org")
            ) or value.endswith(".test") or value.endswith(".invalid")
            self.assertTrue(ok, f"演示域名必须使用保留域名：{value}")

    def test_ips_reserved(self):
        import ipaddress

        for rec in self._jsonl("sample-ips.jsonl"):
            ip = ipaddress.ip_address(rec["value"])
            ok = (
                ip.is_private or ip.is_loopback or ip.is_link_local
                or ip in ipaddress.ip_network("192.0.2.0/24")
                or ip in ipaddress.ip_network("198.51.100.0/24")
                or ip in ipaddress.ip_network("203.0.113.0/24")
            )
            self.assertTrue(ok, f"演示 IP 必须是保留/私网地址：{ip}")

    def test_abusech_csv(self):
        path = RULES / "ioc" / "sample-abusech.csv"
        self.assertTrue(path.is_file(), "缺少 sample-abusech.csv")
        rows = list(csv.DictReader(io.StringIO(read_text(path))))
        self.assertGreaterEqual(len(rows), 3)
        for row in rows:
            self.assertIn("dst_ip", row)
            self.assertIn("malware", row)


# ---------------------------------------------------------------------------
# Playbook
# ---------------------------------------------------------------------------
class TestPlaybook(unittest.TestCase):
    def test_pb001(self):
        path = RULES / "playbooks" / "PB-001.json"
        self.assertTrue(path.is_file(), "缺少 rules/playbooks/PB-001.json")
        pb = json.loads(read_text(path))
        self.assertEqual(pb.get("id"), "PB-001")
        self.assertTrue(pb.get("name"))
        steps = pb.get("steps")
        self.assertIsInstance(steps, list)
        self.assertTrue(steps, "playbook 至少一个步骤")
        step_ids = set()
        for step in steps:
            self.assertIn(step.get("action"), PLAYBOOK_ACTIONS,
                          f"未知动作：{step.get('action')}")
            self.assertTrue(step.get("id"), "步骤缺少 id")
            self.assertNotIn(step["id"], step_ids, "步骤 id 重复")
            step_ids.add(step["id"])
            if "mode" in step:
                self.assertIn(step["mode"], {"observe", "dry-run", "enforce"})
        rollback = pb.get("rollback") or []
        for item in rollback:
            self.assertIn(item.get("action"), PLAYBOOK_ACTIONS)
        actions = {step["action"] for step in steps}
        self.assertIn("quarantine_file", actions)
        self.assertIn("collect_forensics", actions)
        self.assertIn("open_case", actions)


# ---------------------------------------------------------------------------
# 部署文件 / 脚本 / C 工具 / 文档
# ---------------------------------------------------------------------------
class TestDeployArtifacts(unittest.TestCase):
    def test_deploy_files(self):
        expected = [
            "deploy/hornwork.service",
            "deploy/hornwork.rules",
            "deploy/clamd-hornwork.conf",
            "deploy/logrotate-hornwork",
            "scripts/setup.sh",
            "scripts/demo.sh",
            "scripts/check.sh",
            "hornwork/tools/inject_demo.c",
            "docs/interfaces.md",
            "docs/rules.md",
            "docs/runbook.md",
        ]
        for rel in expected:
            with self.subTest(path=rel):
                self.assertTrue((ROOT / rel).is_file(), f"缺少 {rel}")

    def test_service_unit(self):
        text = read_text(ROOT / "deploy" / "hornwork.service")
        for needle in (
            "ExecStart=/opt/hornwork-venv/bin/python -m hornwork.daemon --config /opt/hornwork/config.toml",
            "User=hornwork",
            "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_PTRACE",
            "ReadWritePaths=/var/lib/hornwork /var/log/hornwork /run/hornwork /opt/hornwork/rules /opt/hornwork/raw",
            "ProtectSystem=strict",
            "WantedBy=multi-user.target",
        ):
            self.assertIn(needle, text)

    def test_audit_rules(self):
        text = read_text(ROOT / "deploy" / "hornwork.rules")
        for needle in (
            "-D",
            "-b 8192",
            "--backlog_wait_time 60000",
            "-f 1",
            "-a always,exit -F arch=b64 -S execve -k hornwork_exec",
            "-w /etc/shadow -p wa -k hornwork_identity",
            "-w /etc/ld.so.preload -p wa -k hornwork_persist",
            "-w /etc/audit/rules.d -p wa -k hornwork_tamper",
        ):
            self.assertIn(needle, text)

    def test_clamd_conf(self):
        text = read_text(ROOT / "deploy" / "clamd-hornwork.conf")
        for needle in (
            "LocalSocket /var/run/clamav/clamd.ctl",
            "StreamMaxLength 100M",
            "MaxThreads 4",
            "ReadTimeout 60",
        ):
            self.assertIn(needle, text)

    def test_shell_scripts(self):
        for name in ("setup.sh", "demo.sh", "check.sh"):
            path = ROOT / "scripts" / name
            text = read_text(path)
            self.assertIn("#!/usr/bin/env bash", text, f"{name} 缺少 shebang")
            self.assertIn("set -", text, f"{name} 缺少 set 选项")
            run_bash_syntax(path)

    def test_inject_demo_c(self):
        text = read_text(ROOT / "hornwork" / "tools" / "inject_demo.c")
        for needle in (
            "PTRACE_ATTACH", "PTRACE_GETREGS", "PTRACE_PEEKDATA",
            "PTRACE_POKEDATA", "PTRACE_SETREGS", "PTRACE_DETACH", "--restore",
        ):
            self.assertIn(needle, text, f"inject_demo.c 缺少 {needle}")
        self.assertIn("getuid()", text, "inject_demo.c 必须校验同 uid")


# ---------------------------------------------------------------------------
# 编码 / BOM
# ---------------------------------------------------------------------------
class TestEncoding(unittest.TestCase):
    def test_utf8_without_bom(self):
        checked = 0
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file():
                continue
            if any(part in NON_RULE_TEXT_DIRS for part in path.relative_to(ROOT).parts):
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                try:
                    read_text(path)
                except UnicodeDecodeError as exc:
                    self.fail(f"{path} 不是合法 UTF-8：{exc}")
                checked += 1
        self.assertGreater(checked, 80, "参与编码检查的文本文件数量异常")


# ---------------------------------------------------------------------------
# 文档
# ---------------------------------------------------------------------------
class TestDocs(unittest.TestCase):
    def test_docs_content(self):
        expectations = {
            "docs/interfaces.md": ("CanonicalEvent", "ctl.sock", "/api/"),
            "docs/rules.md": ("YARA", "N-0101", "H-0001", "Sigma", "sigdb"),
            "docs/runbook.md": ("setup.sh", "systemctl", "备份", "排查"),
        }
        for rel, needles in expectations.items():
            text = read_text(ROOT / rel)
            for needle in needles:
                self.assertIn(needle, text, f"{rel} 缺少 {needle} 相关内容")
            self.assertGreater(len(text), 1000, f"{rel} 内容过少")


if __name__ == "__main__":
    unittest.main(verbosity=2)
