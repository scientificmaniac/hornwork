"""验证层与 Web 控制台的单元测试（Windows 开发机必须全绿）。

覆盖：
- judge_case：TP/FN/FP/TN、MTTD、技术口径兜底、非法期望；
- compute_metrics：TPR/FPR/MTTD/覆盖率、空集合；
- VerifyRunner：execute=False 只做 DB 判定（monkeypatch 时钟 + 临时 validation）；
- forensics：parse_malfind / parse_pslist / compare 互证 CSV / 缺失二进制降级；
- WebServer：/healthz、/api/overview、/api/events、/api/rules 写标记、/metrics、401 鉴权。

注意：测试产物统一写在工作区 tests/_tmp/（DSH 沙箱不允许写系统临时目录），
每个用例用 uuid 目录隔离，tearDown 里 shutil.rmtree 清理。
"""

from __future__ import annotations

import json
import os
import shutil
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

from hornwork import schema
from hornwork.config import load_config
from hornwork.store import Store
from hornwork.verify import (
    Forensics,
    VerifyRunner,
    compute_metrics,
    judge_case,
    parse_malfind,
    parse_pslist,
)
from hornwork.verify import runner as runner_mod
from hornwork.web import WebServer

TESTS_DIR = Path(__file__).resolve().parent
TMP_ROOT = TESTS_DIR / "_tmp"

# 固定时钟：判定窗口内的确定性数据（避免依赖真实时间）
T0 = "2026-10-26T12:00:00.000Z"
T0_PLUS_5 = "2026-10-26T12:00:05.000Z"

MALFIND_SAMPLE = """Volatility 3 Framework 2.28.2
Progress:  100.00\t\tPDB scanning finished
PID\tProcess\tStart VPN\tEnd VPN\tTag\tProtection\tHexdump\tDisasm
4321\tbash\t0x7f0012300000\t0x7f0012301000\tVadS\tPAGE_EXECUTE_READWRITE\t4d 5a 90 00\t0x7f0012300000:\tmov eax, 0x1
\t0x7f0012300004:\tnop
4322\tsshd\t0x7f0099900000\t0x7f0099902000\tHeap\tPAGE_EXECUTE_READ\t90 90 90 90\t0x7f0099900000:\tnop
"""

PSLIST_SAMPLE = """Volatility 3 Framework 2.28.2
Progress:  100.00\t\tStacking attempts finished
OFFSET (V)\tPID\tTID\tPPID\tCOMM\tUID\tGID
0x880123400000\t1\t1\t0\tsystemd\t0\t0
0x880123401000\t4321\t4321\t1\tbash\t1000\t1000
"""


def _make_tmp(name: str) -> Path:
    """在 tests/_tmp 下创建 uuid 隔离目录（不使用系统临时目录）。"""
    path = TMP_ROOT / f"{name}-{uuid.uuid4().hex[:10]}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def _make_cfg(tmp: Path) -> dict:
    """构造与生产配置同构、但全部落到临时目录的 cfg。"""
    cfg = load_config(None)
    cfg["general"]["data_dir"] = str(tmp / "data")
    cfg["general"]["host_id"] = "testhost"
    cfg["general"]["hostname"] = "testhost"
    cfg["verify"]["report_dir"] = str(tmp / "reports")
    cfg["verify"]["simulate_dir"] = ""      # 空 → 用包内置 simulate/
    cfg["verify"]["window_sec"] = 60
    cfg["verify"]["settle_sec"] = 0
    cfg["forensics"]["work_dir"] = str(tmp / "forensics")
    cfg["forensics"]["avml_bin"] = str(tmp / "no-such-avml")
    cfg["forensics"]["vol_bin"] = str(tmp / "no-such-vol")
    cfg["web"]["enabled"] = True
    cfg["web"]["bind"] = "127.0.0.1"
    cfg["web"]["port"] = 0                   # 随机空闲端口
    cfg["web"]["token"] = ""
    return cfg


def _insert_alert(store: Store, rule_id: str, technique: str | None, ts: str, level: int = 8) -> dict:
    """造一条告警（规则/技术可控）。"""
    mitre = [technique] if technique else []
    rule = schema.make_rule(rule_id, f"测试规则 {rule_id}", "hostrules", level=level, mitre=mitre)
    alert = schema.new_alert(rule, ts=ts, entity={"host_id": "testhost"}, evidence=[{"note": "unit-test"}])
    store.insert_alert(alert)
    return alert


class JudgeTestCase(unittest.TestCase):
    """judge_case 判定矩阵。"""

    def setUp(self) -> None:
        self.tmp = _make_tmp("judge")
        self.cfg = _make_cfg(self.tmp)
        self.store = Store(self.tmp / "data" / "hornwork.db")
        self.alert = _insert_alert(self.store, "H-TEST-1", "T1059.004", T0_PLUS_5, level=9)

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _case(self, **kwargs) -> dict:
        case = {
            "case_id": "TC-X",
            "name": "单测用例",
            "technique": "T1059.004",
            "expected": "alert_present",
            "rule_ids": ["H-TEST-1"],
            "script": "x.sh",
        }
        case.update(kwargs)
        return case

    def test_tp_and_mttd(self) -> None:
        result = judge_case(self.store, self._case(), T0, 60)
        self.assertEqual(result["verdict"], "TP")
        self.assertEqual(result["observed"], "alert_present")
        self.assertEqual(result["mttd_sec"], 5)
        self.assertEqual(result["alerts"][0]["alert_id"], self.alert["alert_id"])

    def test_fn_when_no_matching_alert(self) -> None:
        result = judge_case(self.store, self._case(rule_ids=["H-NOT-EXIST"], technique="T1105"), T0, 60)
        self.assertEqual(result["verdict"], "FN")
        self.assertEqual(result["observed"], "no_alert")
        self.assertIsNone(result["mttd_sec"])

    def test_rule_ids_any_match(self) -> None:
        # rule_ids 是"任一命中"语义：TC-07 只有 N-0106 告警、没有 N-0103 也应判 TP
        _insert_alert(self.store, "N-0106", "T1071", T0_PLUS_5, level=6)
        result = judge_case(
            self.store,
            {
                "case_id": "TC-07",
                "name": "C2 心跳外联",
                "technique": "T1071.001",
                "expected": "alert_present",
                "rule_ids": ["N-0103", "N-0106"],
                "script": "T1071.001.sh",
            },
            T0,
            60,
        )
        self.assertEqual(result["verdict"], "TP")
        self.assertEqual(result["alerts"][0]["rule_id"], "N-0106")

    def test_technique_fallback_when_rule_hint_stale(self) -> None:
        # 规则线索过期（rule_id 不存在），但同技术告警存在 → 兜底算 TP
        result = judge_case(self.store, self._case(rule_ids=["H-OLD-ID"]), T0, 60)
        self.assertEqual(result["verdict"], "TP")

    def test_parent_child_technique_match(self) -> None:
        # memscan 告警打父技术号 T1055，用例 TC-09 用子技术号 T1055.008 → 父子互认算 TP
        _insert_alert(self.store, "M-0101", "T1055", T0_PLUS_5, level=10)
        result = judge_case(
            self.store,
            self._case(rule_ids=["M-0101"], technique="T1055.008", case_id="TC-09"),
            T0,
            60,
        )
        self.assertEqual(result["verdict"], "TP")
        self.assertEqual(result["alerts"][0]["rule_id"], "M-0101")

    def test_fp_for_negative_case(self) -> None:
        result = judge_case(self.store, self._case(expected="no_alert", technique=None, rule_ids=[]), T0, 60)
        self.assertEqual(result["verdict"], "FP")

    def test_tn_when_window_has_no_alert(self) -> None:
        result = judge_case(self.store, self._case(expected="no_alert", technique=None, rule_ids=[]), "2026-10-25T00:00:00.000Z", 60)
        self.assertEqual(result["verdict"], "TN")
        self.assertEqual(result["observed"], "no_alert")

    def test_invalid_expected_is_inconclusive(self) -> None:
        result = judge_case(self.store, self._case(expected="maybe"), T0, 60)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["observed"], "unknown")

    def test_bad_timestamp_is_inconclusive(self) -> None:
        result = judge_case(self.store, self._case(), "not-a-time", 60)
        self.assertEqual(result["verdict"], "inconclusive")


class MetricsTestCase(unittest.TestCase):
    """指标计算。"""

    def test_full_metrics(self) -> None:
        rows = [
            {"verdict": "TP", "technique": "T1", "mttd_sec": 3},
            {"verdict": "TP", "technique": "T1", "mttd_sec": 5},
            {"verdict": "FN", "technique": "T2", "mttd_sec": None},
            {"verdict": "FP", "technique": "T3", "mttd_sec": 1},
            {"verdict": "TN", "technique": None},
            {"verdict": "inconclusive", "technique": "T4"},
        ]
        metrics = compute_metrics(rows)
        self.assertEqual((metrics["TP"], metrics["TN"], metrics["FP"], metrics["FN"]), (2, 1, 1, 1))
        self.assertEqual(metrics["inconclusive"], 1)
        self.assertAlmostEqual(metrics["tpr"], 2 / 3, places=4)
        self.assertAlmostEqual(metrics["fpr"], 1 / 2, places=4)
        self.assertEqual(metrics["mttd_sec"], 4.0)
        self.assertAlmostEqual(metrics["coverage"], 0.25, places=4)   # 仅 T1 有 TP
        self.assertEqual(metrics["techniques"], ["T1", "T2", "T3", "T4"])

    def test_empty_rows(self) -> None:
        metrics = compute_metrics([])
        self.assertEqual(metrics["TP"] + metrics["FN"] + metrics["FP"] + metrics["TN"], 0)
        self.assertIsNone(metrics["tpr"])
        self.assertIsNone(metrics["fpr"])
        self.assertIsNone(metrics["mttd_sec"])
        self.assertIsNone(metrics["coverage"])
        self.assertEqual(metrics["techniques"], [])

    def test_unknown_verdict_counts_as_inconclusive(self) -> None:
        metrics = compute_metrics([{"verdict": "weird"}, {"verdict": None}])
        self.assertEqual(metrics["inconclusive"], 2)


class VerifyRunnerTestCase(unittest.TestCase):
    """执行器：execute=False 只做 DB 判定。"""

    def setUp(self) -> None:
        self.tmp = _make_tmp("runner")
        self.cfg = _make_cfg(self.tmp)
        self.store = Store(self.tmp / "data" / "hornwork.db")
        _insert_alert(self.store, "H-TC01", "T1059.004", T0_PLUS_5, level=9)

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_suites_has_baseline_cases(self) -> None:
        runner = VerifyRunner(self.store, self.cfg)
        suites = runner.suites()
        self.assertIn("baseline", suites)
        self.assertEqual(suites["baseline"]["case_count"], 11)
        self.assertEqual(len(suites["baseline"]["techniques"]), 10)
        # TC-07 的规则线索：N-0103（DNS 情报域名）/ N-0106（心跳）任一命中即 TP
        tc07 = next(case for case in suites["baseline"]["cases"] if case["case_id"] == "TC-07")
        self.assertEqual(tc07["rule_ids"], ["N-0103", "N-0106"])
        # TC-09 双次内存扫描配置：第一次基线、1s 后第二次 snapshot 触发 A+B
        tc09 = next(case for case in suites["baseline"]["cases"] if case["case_id"] == "TC-09")
        self.assertTrue(tc09["post_ctl"]["double_scan"])
        self.assertTrue(tc09["post_ctl"]["snapshot"])
        self.assertEqual(tc09["post_ctl"]["interval_sec"], 1)

    def test_tc09_script_builds_rwx_target(self) -> None:
        # TC-09 必须自建匿名 RWX 目标程序 + 本地监听 + pid 文件 + KEEP 语义，否则 memscan 永远 observed
        script = Path(__file__).resolve().parents[1] / "hornwork" / "verify" / "simulate" / "T1055.008.sh"
        text = script.read_text(encoding="utf-8")
        for token in ("PROT_READ | PROT_WRITE | PROT_EXEC", "MAP_ANONYMOUS", "mmap(",
                      "SOCK_STREAM", "hornwork-tc09.pid", "HORNWORK_TC09_KEEP",
                      "--pid", "--dry-run", "TARGET_BIN", "LISTENER_PID", '"$TC $TECH start"'):
            self.assertIn(token, text)

    def test_tc07_script_sends_dns_queries(self) -> None:
        # 脚本必须真的发 DNS 查询（N-0103 依赖抓包解析 QNAME），且保留心跳部分
        script = Path(__file__).resolve().parents[1] / "hornwork" / "verify" / "simulate" / "T1071.001.sh"
        text = script.read_text(encoding="utf-8")
        for token in ("TC-07: dns_query sent", "ioc.example", "c2.example.com",
                      "HORNWORK_PYTHON", "SOCK_DGRAM", "create_connection", '"$TC $TECH start"'):
            self.assertIn(token, text)

    def test_run_without_execute(self) -> None:
        ctl_calls: list[tuple] = []

        def ctl_call(method, params):
            ctl_calls.append((method, params))
            return {"ok": True, "result": {"running": True, "collectors": 6}}

        runner = VerifyRunner(self.store, self.cfg, ctl_call=ctl_call)
        with mock.patch.object(runner_mod, "_now", lambda: T0):
            report = runner.run(execute=False)

        self.assertEqual(set(report), {"run_id", "cases", "metrics", "report_path", "md_path"})
        self.assertEqual(len(report["cases"]), 11)
        metrics = report["metrics"]
        self.assertEqual(metrics["TP"], 1)          # TC-01 命中
        self.assertEqual(metrics["FN"], 9)          # 其余 9 个攻击用例无告警
        self.assertEqual(metrics["FP"], 1)          # TC-N1 阴性用例撞上告警
        self.assertEqual(metrics["TN"], 0)
        self.assertEqual(metrics["inconclusive"], 0)
        self.assertAlmostEqual(metrics["tpr"], 0.1, places=4)
        self.assertAlmostEqual(metrics["coverage"], 0.1, places=4)

        self.assertTrue(Path(report["report_path"]).is_file())
        self.assertTrue(Path(report["md_path"]).is_file())
        payload = json.loads(Path(report["report_path"]).read_text(encoding="utf-8"))
        self.assertEqual(payload["run_id"], report["run_id"])
        self.assertEqual(payload["daemon"], {"running": True, "collectors": 6})
        self.assertIn("Hornwork 验证报告", Path(report["md_path"]).read_text(encoding="utf-8"))
        self.assertEqual(ctl_calls[0][0], "status")

        rows = self.store.validation_rows(run_id=report["run_id"])
        self.assertEqual(len(rows), 11)
        self.assertEqual(self.store.latest_run_id(), report["run_id"])
        tc01 = next(row for row in rows if row["case_id"] == "TC-01")
        self.assertEqual(tc01["verdict"], "TP")
        self.assertEqual(tc01["mttd_sec"], 5)
        self.assertEqual(tc01["payload"]["report_path"], report["report_path"])

    def test_post_ctl_mem_scan_hook(self) -> None:
        # TC-09：脚本成功后 runner 读 pid 文件 → ctl mem.scan → 清理目标进程/pid 文件
        calls: list[tuple] = []

        def ctl_call(method, params):
            calls.append((method, params))
            return {"ok": True, "result": {"pid": params["pid"], "verdict": "malicious", "score": 95, "hits": [{"kind": "rwx"}]}}

        runner = VerifyRunner(self.store, self.cfg, ctl_call=ctl_call)
        pid_file = self.tmp / "hornwork-tc09.pid"
        pid_file.write_text("424242\n", encoding="utf-8")
        item: dict = {"case_id": "TC-09"}
        with mock.patch.dict(os.environ, {"HORNWORK_TMP": str(self.tmp)}):
            runner._run_post_ctl({"method": "mem.scan", "pid_file": "hornwork-tc09.pid"}, item)
        state = item["post_ctl"]
        self.assertTrue(state["ok"])
        self.assertEqual(state["pid"], 424242)
        self.assertEqual(state["result"]["verdict"], "malicious")
        self.assertEqual(state["result"]["hit_count"], 1)
        self.assertEqual(calls, [("mem.scan", {"pid": 424242})])
        self.assertFalse(pid_file.exists())      # 扫描后清理 pid 文件

    def test_post_ctl_double_scan(self) -> None:
        # TC-09：第一次 mem.scan 建行为基线，sleep 1s 后第二次带 snapshot → 结果取第二次
        calls: list[tuple] = []

        def ctl_call(method, params):
            calls.append((method, dict(params)))
            if params.get("snapshot"):
                return {"ok": True, "result": {"pid": params["pid"], "verdict": "injected", "score": 80,
                                               "hits": [{"kind": "anon_rwx"}]}}
            return {"ok": True, "result": {"pid": params["pid"], "verdict": "observed", "score": 60,
                                           "hits": [{"kind": "anon_rwx"}]}}

        runner = VerifyRunner(self.store, self.cfg, ctl_call=ctl_call)
        pid_file = self.tmp / "hornwork-tc09.pid"
        pid_file.write_text("424242\n", encoding="utf-8")
        item: dict = {"case_id": "TC-09"}
        spec = {"method": "mem.scan", "pid_file": "hornwork-tc09.pid",
                "double_scan": True, "snapshot": True, "interval_sec": 1}
        with mock.patch.dict(os.environ, {"HORNWORK_TMP": str(self.tmp)}), \
                mock.patch.object(runner_mod.time, "sleep") as sleep_mock:
            runner._run_post_ctl(spec, item)

        state = item["post_ctl"]
        self.assertTrue(state["ok"])
        self.assertEqual([call[0] for call in calls], ["mem.scan", "mem.scan"])
        self.assertEqual(calls[0][1], {"pid": 424242})                       # 基线：不带 snapshot
        self.assertEqual(calls[1][1], {"pid": 424242, "snapshot": True})     # 第二次：带 snapshot
        self.assertEqual(state["baseline"]["verdict"], "observed")
        self.assertEqual(state["result"]["verdict"], "injected")             # 结果取自第二次
        self.assertEqual(state["interval_sec"], 1.0)
        sleep_mock.assert_called_once_with(1.0)
        self.assertFalse(pid_file.exists())

    def test_post_ctl_skipped_without_ctl(self) -> None:
        runner = VerifyRunner(self.store, self.cfg)   # ctl_call=None（离线 CLI 场景）
        item: dict = {"case_id": "TC-09"}
        runner._run_post_ctl({"method": "mem.scan", "pid_file": "hornwork-tc09.pid"}, item)
        self.assertTrue(item["post_ctl"]["skipped"])
        self.assertFalse(item["post_ctl"]["ok"])

    def test_child_env_keeps_target_only_with_ctl(self) -> None:
        spec = {"post_ctl": {"method": "mem.scan", "pid_file": "hornwork-tc09.pid"}}
        with_ctl = VerifyRunner(self.store, self.cfg, ctl_call=lambda m, p: {"ok": True, "result": {}})
        self.assertEqual(with_ctl._child_env(spec).get("HORNWORK_TC09_KEEP"), "1")
        without_ctl = VerifyRunner(self.store, self.cfg)
        self.assertNotIn("HORNWORK_TC09_KEEP", without_ctl._child_env(spec))

    def test_run_without_execute_with_missing_sim_dir(self) -> None:
        # 无脚本目录时 execute=False 仍只做 DB 判定：不触发 bash、不抛异常
        cfg = _make_cfg(self.tmp)
        cfg["verify"]["simulate_dir"] = str(self.tmp / "missing-simulate-dir")
        runner = VerifyRunner(self.store, cfg)
        with mock.patch.object(runner_mod, "_now", lambda: T0):
            report = runner.run(execute=False)
        self.assertEqual(len(report["cases"]), 11)
        self.assertTrue(all(case["executed"] is False for case in report["cases"]))
        self.assertEqual(report["metrics"]["TP"], 1)

    def test_unknown_suite_raises(self) -> None:
        runner = VerifyRunner(self.store, self.cfg)
        with self.assertRaises(ValueError):
            runner.run(suite="not-exist", execute=False)

    def test_execute_with_missing_scripts_is_inconclusive(self) -> None:
        # execute=True 但脚本目录为空：每例都应标 inconclusive（Windows 无法跑 bash 的安全路径）
        cfg = _make_cfg(self.tmp)
        cfg["verify"]["simulate_dir"] = str(self.tmp / "no-scripts")
        (self.tmp / "no-scripts").mkdir()
        runner = VerifyRunner(self.store, cfg)
        with mock.patch.object(runner_mod, "_now", lambda: T0):
            report = runner.run(execute=True)
        verdicts = [case["verdict"] for case in report["cases"]]
        self.assertEqual(verdicts, ["inconclusive"] * 11)
        self.assertEqual(report["metrics"]["inconclusive"], 11)
        self.assertIsNone(report["metrics"]["tpr"])
        self.assertIsNone(report["metrics"]["fpr"])


class ForensicsTestCase(unittest.TestCase):
    """取证文本解析、互证 CSV 与降级行为。"""

    def setUp(self) -> None:
        self.tmp = _make_tmp("forensics")
        self.cfg = _make_cfg(self.tmp)
        self.store = Store(self.tmp / "data" / "hornwork.db")
        self.work = Path(self.cfg["forensics"]["work_dir"])
        self.work.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_parse_malfind(self) -> None:
        rows = parse_malfind(MALFIND_SAMPLE)
        self.assertEqual(len(rows), 2)
        first = rows[0]
        self.assertEqual(first["pid"], 4321)
        self.assertEqual(first["process"], "bash")
        self.assertEqual(first["start"], 0x7F0012300000)
        self.assertEqual(first["end"], 0x7F0012301000)
        self.assertEqual(first["perms"], "rwx")
        self.assertEqual(first["tag"], "VadS")
        self.assertEqual(rows[1]["perms"], "r-x")

    def test_parse_pslist(self) -> None:
        rows = parse_pslist(PSLIST_SAMPLE)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["pid"], 1)
        self.assertEqual(rows[0]["comm"], "systemd")
        self.assertEqual(rows[1]["ppid"], 1)
        self.assertEqual(rows[1]["uid"], 1000)

    def test_compare_writes_csv(self) -> None:
        malfind = self.work / "sample.out"
        malfind.mkdir()
        malfind_path = malfind / "malfind.txt"
        malfind_path.write_text(MALFIND_SAMPLE, encoding="utf-8")
        self.store.insert_mem_hits(
            schema.utc_now(),
            [
                {"pid": 4321, "start": 0x7F0012300000, "end": 0x7F0012301000, "perms": "rwx"},
                {"pid": 9999, "start": 0x7F00DEAD0000, "end": 0x7F00DEAD1000, "perms": "rwx"},
            ],
        )
        result = Forensics(self.store, self.cfg).compare(offline_malfind=str(malfind_path))
        self.assertTrue(result["ok"], result.get("error"))
        # malfind 有 4321/4322 两段，在线 mem_hits 有 4321/9999 两段：
        # 4321 双方一致；4322 仅离线；9999 仅在线
        self.assertEqual(result["stats"]["both"], 1)
        self.assertEqual(result["stats"]["only_online"], 1)
        self.assertEqual(result["stats"]["only_offline"], 1)
        self.assertEqual(result["stats"]["match"], 1)
        self.assertEqual(result["stats"]["mismatch"], 2)
        csv_text = Path(result["csv_path"]).read_text(encoding="utf-8")
        self.assertIn("pid,start,end,perms,online,offline,match", csv_text)

    def test_compare_without_malfind(self) -> None:
        result = Forensics(self.store, self.cfg).compare(offline_malfind=str(self.tmp / "none.txt"))
        self.assertFalse(result["ok"])
        self.assertIsNone(result["csv_path"])

    def test_collect_without_avml(self) -> None:
        result = Forensics(self.store, self.cfg).collect()
        self.assertFalse(result["ok"])
        self.assertIn("avml", result["error"])

    def test_analyze_without_image(self) -> None:
        result = Forensics(self.store, self.cfg).analyze(str(self.tmp / "no-image.lime"))
        self.assertFalse(result["ok"])
        self.assertTrue(result["errors"])


class WebServerTestCase(unittest.TestCase):
    """Web 控制台：启动 → 请求 → 停止。"""

    def setUp(self) -> None:
        self.tmp = _make_tmp("web")
        self.cfg = _make_cfg(self.tmp)
        self.store = Store(self.tmp / "data" / "hornwork.db")
        _insert_alert(self.store, "N-0101", "T1046", schema.utc_now(), level=8)
        _insert_alert(self.store, "N-0103", "T1071.001", schema.utc_now(), level=10)
        self.server = WebServer(self.cfg, self.store)

    def tearDown(self) -> None:
        try:
            self.server.stop()
        finally:
            self.store.close()
            shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------ 辅助
    def _get(self, path: str, token: str | None = None, timeout: float = 5.0):
        request = urllib.request.Request(self._base() + path)
        if token:
            request.add_header("Authorization", "Bearer " + token)
        return urllib.request.urlopen(request, timeout=timeout)

    def _post(self, path: str, body: dict, token: str | None = None):
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self._base() + path, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        if token:
            request.add_header("Authorization", "Bearer " + token)
        return urllib.request.urlopen(request, timeout=5.0)

    def _base(self) -> str:
        status = self.server.status()
        return f"http://{status['bind']}:{status['port']}"

    # ------------------------------------------------------------ 用例
    def test_healthz_and_overview_without_token(self) -> None:
        self.server.start()
        status = self.server.status()
        self.assertTrue(status["running"])
        self.assertFalse(status["auth"])
        self.assertEqual(status["bind"], "127.0.0.1")
        for key in ("enabled", "bind", "port", "auth", "running"):
            self.assertIn(key, status)

        with self._get("/healthz") as resp:
            self.assertEqual(resp.status, 200)
            health = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(health["ok"])
        self.assertFalse(health["auth"])

        with self._get("/api/overview") as resp:
            self.assertEqual(resp.status, 200)
            overview = json.loads(resp.read().decode("utf-8"))
        self.assertIn("counts", overview)
        self.assertEqual(overview["counts"]["alerts_total"], 2)
        self.assertEqual(overview["counts"]["events_total"], 0)

        with self._get("/api/events?limit=5") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("items", json.loads(resp.read().decode("utf-8")))

        with self._get("/api/alerts?since=24h") as resp:
            self.assertEqual(resp.status, 200)
            alerts = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(alerts["count"], 2)

        with self._get("/metrics") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("hornwork_events_total", resp.read().decode("utf-8"))

        with self._get("/") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("Hornwork", resp.read().decode("utf-8"))

    def test_rules_reload_marker(self) -> None:
        self.server.start()
        with self._post("/api/rules", {"action": "reload"}) as resp:
            self.assertEqual(resp.status, 201)
            self.assertTrue(json.loads(resp.read().decode("utf-8"))["ok"])
        with self._get("/api/rules") as resp:
            data = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(data["reload"]["count"], 1)
        self.assertIsNotNone(data["reload"]["requested_at"])

    def test_token_required_when_configured(self) -> None:
        self.cfg["web"]["token"] = "unit-test-token"
        self.server.stop()
        self.server = WebServer(self.cfg, self.store)
        self.server.start()
        self.assertTrue(self.server.status()["auth"])

        # 无 token → 401 C7 结构
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/api/overview")
        self.assertEqual(ctx.exception.code, 401)
        payload = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(payload["code"], 401)
        self.assertIn("message", payload)
        self.assertIn("retryable", payload)

        # 带正确 token → 200；健康检查仍免鉴权
        with self._get("/api/overview", token="unit-test-token") as resp:
            self.assertEqual(resp.status, 200)
        with self._get("/healthz") as resp:
            self.assertEqual(resp.status, 200)

    def test_other_api_routes(self) -> None:
        self.server.start()
        # 引擎贡献统计
        with self._get("/api/engine-stats?days=7") as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
        self.assertIn("engine_stats", data)
        self.assertIn("sigma", data)

        # 情报列表（空库也要返回 200）
        with self._get("/api/intel?limit=10") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("items", json.loads(resp.read().decode("utf-8")))

        # 工单：POST 建单 → GET 可见
        with self._post("/api/cases", {"title": "单测工单", "severity": "P3"}) as resp:
            self.assertEqual(resp.status, 201)
            created = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(created["case_id"])
        with self._get("/api/cases") as resp:
            cases = json.loads(resp.read().decode("utf-8"))
        self.assertGreaterEqual(cases["count"], 1)

        # 导出：jsonl 与 markdown
        with self._get("/api/export?format=jsonl&kind=alerts&since=24h") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("ndjson", resp.headers.get("Content-Type", ""))
            lines = [line for line in resp.read().decode("utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertIn("alert_id", json.loads(line))
        with self._get("/api/export?format=md&kind=alerts&since=24h") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("Hornwork 导出", resp.read().decode("utf-8"))

        # 验证结果：插入一条落库记录后可查询（无记录时也要 200）
        self.store.insert_validation(
            {
                "run_id": "run-unittest",
                "case_id": "TC-01",
                "technique": "T1059.004",
                "expected": "alert_present",
                "observed": "alert_present",
                "verdict": "TP",
                "mttd_sec": 2,
                "payload": {"name": "单测", "report_path": "/tmp/report.json", "md_path": "/tmp/report.md"},
            }
        )
        with self._get("/api/validate?run_id=run-unittest") as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(data["run_id"], "run-unittest")
        self.assertEqual(data["metrics"]["TP"], 1)
        self.assertEqual(data["report_path"], "/tmp/report.json")

    def test_intel_import_records(self) -> None:
        # 情报层由 intel-respond 负责：未就绪时接口按契约返回 503，测试跳过
        try:
            import hornwork.intel.iocstore  # noqa: F401
        except Exception:  # noqa: BLE001
            self.skipTest("情报层未就绪")
        self.server.start()
        body = {
            "records": [
                {"type": "domain", "value": "tc07.example.com", "confidence": 80, "source": "unit-test", "tlp": "amber"},
                {"type": "ip", "value": "203.0.113.9", "confidence": 70, "source": "unit-test", "tlp": "amber"},
            ]
        }
        with self._post("/api/intel", body) as resp:
            self.assertEqual(resp.status, 201)
            data = json.loads(resp.read().decode("utf-8"))
        self.assertTrue(data.get("ok"))
        self.assertGreaterEqual(int(data.get("imported", 0)), 1)
        with self._get("/api/intel?limit=10") as resp:
            listed = json.loads(resp.read().decode("utf-8"))
        self.assertGreaterEqual(listed["count"], 1)

    def test_stop_releases_port(self) -> None:
        self.server.start()
        self.assertTrue(self.server.status()["running"])
        self.server.stop()
        self.assertFalse(self.server.status()["running"])


def tearDownModule() -> None:
    """测试全部结束后清理空的 tests/_tmp 目录。"""
    try:
        if TMP_ROOT.is_dir() and not any(TMP_ROOT.iterdir()):
            TMP_ROOT.rmdir()
    except OSError:
        pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
