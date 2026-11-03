"""扫描模块"结果解释层"单元测试：diff / coverage / report / api。

不依赖网络、虚拟机、nmap 或任何外部引擎：只用临时 SQLite 库手工造数，
验证四态分类、加权覆盖率的手算数值、HTML 报告的关键内容与转义、以及只读 API
的过滤/分页/空库容错。

运行：``cd hornwork && python -m unittest tests.test_scan_report -v``
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork.config import load_config  # noqa: E402
from hornwork.scan import api, coverage, diff, report  # noqa: E402
from hornwork.scan.store import init_schema  # noqa: E402
from hornwork.store import Store  # noqa: E402

TS1 = "2026-10-19T03:00:00.000Z"
TS2 = "2026-10-26T02:45:00.000Z"
PLAN = "weekly-linux"
RUN = "run-20261026"
#: 默认快照号（造 finding 时引用；表格/报告相关用例使用）
TS2_SNAPSHOT = "S20261026T024500"


# ---------------------------------------------------------------------------
# 造数工具（直接写表，模拟 Lead 的 runner/normalize 产物）
# ---------------------------------------------------------------------------
def _cfg(tmp: Path) -> dict:
    """测试配置：报告目录指向临时目录（避免写 /opt/hornwork）。"""
    cfg = load_config(None)
    scan = cfg.setdefault("scan", {})
    scan["report_dir"] = str(Path(tmp) / "reports")
    return cfg


def add_asset(
    store: Store,
    asset_id: str,
    ip: str,
    role: str = "lab",
    *,
    enabled: int = 1,
    hostname: str | None = None,
) -> None:
    store.execute(
        "INSERT INTO asset(asset_id, ip, hostname, role, criticality, enabled, is_self,"
        " first_seen, last_seen, facts_json) VALUES(?,?,?,?,3,?,0,?,?,'{}')",
        (asset_id, ip, hostname, role, int(enabled), TS1, TS2),
    )


def add_plan(store: Store, plan_id: str = PLAN, kind: str = "weekly") -> None:
    store.execute(
        "INSERT INTO scan_plan(plan_id, name, kind, profile, selector_json, engines_json,"
        " enabled, created_at) VALUES(?,?,?,?,?,?,1,?)",
        (plan_id, "每周常规扫描", kind, "weekly", json.dumps({"group": "lab"}),
         json.dumps(["nmap", "lynis"]), TS1),
    )


def add_snapshot(
    store: Store,
    snapshot_id: str,
    ts: str,
    *,
    plan_id: str = PLAN,
    run_id: str = RUN,
    kind: str = "weekly",
    is_base: int = 0,
    stats: dict | None = None,
) -> None:
    store.execute(
        "INSERT INTO scan_snapshot(snapshot_id, plan_id, run_id, ts, kind, label, is_base,"
        " task_count, finding_count, stats_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            snapshot_id, plan_id, run_id, ts, kind, f"{kind}快照", int(is_base),
            0, 0, json.dumps(stats or {}, ensure_ascii=False),
        ),
    )


def add_task(
    store: Store,
    task_id: str,
    asset_id: str,
    snapshot_id: str,
    checkpoint: dict,
    *,
    status: str = "done",
    run_id: str = RUN,
    plan_id: str = PLAN,
    started_at: str = TS2,
) -> None:
    store.execute(
        "INSERT INTO scan_task(task_id, run_id, plan_id, asset_id, slot, profile, status,"
        " stage, progress, checkpoint, snapshot_id, started_at, finished_at, cost_ms)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            task_id, run_id, plan_id, asset_id, task_id, "weekly", status, "done", 100,
            json.dumps(checkpoint, ensure_ascii=False), snapshot_id, started_at, TS2, 6300,
        ),
    )


def add_finding(
    store: Store,
    finding_id: str,
    asset_id: str,
    finding_key: str,
    kind: str,
    check_id: str,
    *,
    title: str | None = None,
    severity: str | None = None,
    cvss: float | None = None,
    cvss_source: str = "nvd",
    confidence: str | None = None,
    status: str = "new",
    target: str | None = None,
    evidence: dict | None = None,
    vuln_ref: str | None = None,
    snapshot_id: str = TS2_SNAPSHOT,
    task_id: str | None = None,
) -> None:
    store.execute(
        "INSERT INTO scan_finding(finding_id, task_id, asset_id, snapshot_id, kind, check_id,"
        " title, severity, cvss, cvss_source, confidence, status, finding_key, target,"
        " evidence_json, vuln_ref, miss_count, first_seen, last_seen, updated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)",
        (
            finding_id, task_id, asset_id, snapshot_id, kind, check_id, title or check_id,
            severity, cvss, cvss_source, confidence, status, finding_key, target,
            json.dumps(evidence or {}, ensure_ascii=False), vuln_ref, TS1, TS2, TS2,
        ),
    )


def add_item(
    store: Store,
    snapshot_id: str,
    asset_id: str,
    finding_key: str,
    kind: str,
    check_id: str,
    *,
    severity: str | None = None,
    status: str = "observed",
    cvss: float | None = None,
) -> None:
    store.execute(
        "INSERT INTO scan_snapshot_item(snapshot_id, asset_id, finding_key, kind, check_id,"
        " severity, status, cvss) VALUES(?,?,?,?,?,?,?,?)",
        (snapshot_id, asset_id, finding_key, kind, check_id, severity, status, cvss),
    )


class _DbCase(unittest.TestCase):
    """每个用例一个临时库；tearDown 关闭连接后清理临时目录。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hornwork-scan-report-"))
        self.store = Store(self.tmp / "hornwork.db")
        init_schema(self.store)
        self.cfg = _cfg(self.tmp)

    def tearDown(self) -> None:
        try:
            self.store.close()
        except Exception:  # noqa: BLE001 - 已关闭/文件被占用都不影响断言
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# 一、diff：四态分类 / 统计 / 排序 / 趋势 / 容错
# ---------------------------------------------------------------------------
class TestDiff(_DbCase):
    def _fixture(self) -> None:
        add_asset(self.store, "ast-0001", "192.168.56.20", "lab")
        add_asset(self.store, "ast-0002", "192.168.56.21", "web")
        add_plan(self.store)
        add_snapshot(self.store, "S1", TS1, run_id="run-0")
        add_snapshot(self.store, "S2", TS2)
        # S1（上一次）：端口/组件事实 + CVE（仍存在）+ 已修复 + 将回归
        add_item(self.store, "S1", "ast-0001", "key-port", "port", "PORT-22/tcp")
        add_item(self.store, "S1", "ast-0001", "key-comp", "component", "SVC-22/tcp")
        add_item(self.store, "S1", "ast-0002", "key-cve", "cve", "CVE-2023-1234",
                 severity="严重", status="confirmed", cvss=9.8)
        add_item(self.store, "S1", "ast-0002", "key-fixed", "cve", "CVE-2022-0001",
                 severity="中", status="confirmed", cvss=5.3)
        add_item(self.store, "S1", "ast-0002", "key-reg", "cve", "CVE-2022-0002",
                 severity="高", status="fixed", cvss=7.5)
        # S2（本次）：仍存在 3 条 + 回归 1 条 + 新增 2 条
        add_item(self.store, "S2", "ast-0001", "key-port", "port", "PORT-22/tcp")
        add_item(self.store, "S2", "ast-0001", "key-comp", "component", "SVC-22/tcp")
        add_item(self.store, "S2", "ast-0002", "key-cve", "cve", "CVE-2023-1234",
                 severity="严重", status="confirmed", cvss=9.8)
        add_item(self.store, "S2", "ast-0002", "key-reg", "cve", "CVE-2022-0002",
                 severity="高", status="confirmed", cvss=7.5)
        add_item(self.store, "S2", "ast-0002", "key-new", "cve", "CVE-2024-9999",
                 severity="中", status="new", cvss=5.5)
        add_item(self.store, "S2", "ast-0002", "key-cfg", "config", "LYNIS-001",
                 severity="低", status="new", cvss=3.1)
        # 当前状态表：供 diff 补 title/target
        add_finding(self.store, "fnd-cve", "ast-0002", "key-cve", "cve", "CVE-2023-1234",
                    title="OpenSSH 命令注入", severity="严重", cvss=9.8,
                    confidence="range", status="confirmed", target="ast-0002:openssh",
                    snapshot_id="S2")
        add_finding(self.store, "fnd-new", "ast-0002", "key-new", "cve", "CVE-2024-9999",
                    title="新披露漏洞", severity="中", cvss=5.5, status="new",
                    snapshot_id="S2")
        # 让两条新增的排序可断言：key-cfg 低 3.1 < key-new 中 5.5

    def test_four_states_and_stats(self) -> None:
        self._fixture()
        result = diff.build(self.store, "S2", "S1")
        self.assertNotIn("error", result)
        self.assertEqual(result["cur"], "S2")
        self.assertEqual(result["prev"], "S1")
        self.assertEqual(
            result["stats"],
            {"new": 2, "fixed": 1, "persisting": 3, "regressed": 1, "total": 7},
        )
        deltas = {(item["asset_id"], item["finding_key"]): item["delta"] for item in result["items"]}
        self.assertEqual(deltas[("ast-0001", "key-port")], "persisting")
        self.assertEqual(deltas[("ast-0001", "key-comp")], "persisting")
        self.assertEqual(deltas[("ast-0002", "key-cve")], "persisting")
        self.assertEqual(deltas[("ast-0002", "key-fixed")], "fixed")
        self.assertEqual(deltas[("ast-0002", "key-reg")], "regressed")
        self.assertEqual(deltas[("ast-0002", "key-new")], "new")
        self.assertEqual(deltas[("ast-0002", "key-cfg")], "new")
        # 冻结项状态：fixed 项来自 S1，new 项来自 S2
        items = {(item["finding_key"]): item for item in result["items"]}
        self.assertEqual(items["key-fixed"]["prev_status"], "confirmed")
        self.assertIsNone(items["key-fixed"]["cur_status"])
        self.assertIsNone(items["key-new"]["prev_status"])
        self.assertEqual(items["key-new"]["cur_status"], "new")
        # 元数据关联：从 scan_finding 取 title/target
        self.assertEqual(items["key-cve"]["title"], "OpenSSH 命令注入")
        self.assertEqual(items["key-cve"]["target"], "ast-0002:openssh")

    def test_sort_order_regressed_first_then_severity(self) -> None:
        self._fixture()
        result = diff.build(self.store, "S2", "S1")
        order = [item["delta"] for item in result["items"]]
        self.assertEqual(order[0], "regressed")
        self.assertEqual(order[-1], "fixed")
        # 同一 delta 内按严重级再 CVSS 降序：新增项中 "中"(5.5) 应排在 "低"(3.1) 之前
        new_items = [item for item in result["items"] if item["delta"] == "new"]
        self.assertEqual([item["finding_key"] for item in new_items], ["key-new", "key-cfg"])

    def test_regressed_by_reopened_status(self) -> None:
        add_asset(self.store, "ast-0001", "192.168.56.20")
        add_plan(self.store)
        add_snapshot(self.store, "S1", TS1)
        add_snapshot(self.store, "S2", TS2)
        add_item(self.store, "S1", "ast-0001", "key-reopened", "cve", "CVE-2021-1111",
                 severity="高", status="confirmed", cvss=7.0)
        add_item(self.store, "S2", "ast-0001", "key-reopened", "cve", "CVE-2021-1111",
                 severity="高", status="reopened", cvss=7.0)
        result = diff.build(self.store, "S2", "S1")
        self.assertEqual(result["items"][0]["delta"], "regressed")
        self.assertEqual(result["stats"]["regressed"], 1)
        self.assertEqual(result["stats"]["persisting"], 0)

    def test_by_severity_buckets(self) -> None:
        self._fixture()
        result = diff.build(self.store, "S2", "S1")
        by_sev = result["by_severity"]
        for severity in ("严重", "高", "中", "低", "无"):
            self.assertIn(severity, by_sev)
            for key in ("new", "fixed", "persisting", "regressed", "total"):
                self.assertIn(key, by_sev[severity])
        self.assertEqual(by_sev["严重"]["persisting"], 1)
        self.assertEqual(by_sev["高"]["regressed"], 1)
        self.assertEqual(by_sev["中"]["new"], 1)

    def test_missing_prev_returns_error_not_raise(self) -> None:
        add_asset(self.store, "ast-0001", "192.168.56.20")
        add_snapshot(self.store, "S2", TS2)
        empty = diff.build(self.store, "S2", "")
        self.assertEqual(empty["stats"], {"new": 0, "fixed": 0, "persisting": 0,
                                         "regressed": 0, "total": 0})
        self.assertIn("error", empty)
        missing = diff.build(self.store, "S2", "S-not-exist")
        self.assertEqual(missing["stats"]["total"], 0)
        self.assertIn("不存在", missing["error"])
        missing_cur = diff.build(self.store, "S-not-exist", "S2")
        self.assertIn("error", missing_cur)

    def test_error_when_schema_missing(self) -> None:
        bare = Store(self.tmp / "bare.db")
        try:
            result = diff.build(bare, "S2", "S1")
            self.assertIn("error", result)
            self.assertEqual(result["stats"]["total"], 0)
        finally:
            bare.close()

    def test_write_stat_flag_and_trend(self) -> None:
        self._fixture()
        diff.build(self.store, "S2", "S1", write_stat=False)
        self.assertEqual(
            self.store.query_one("SELECT COUNT(*) AS n FROM scan_diff_stat")["n"], 0
        )
        diff.build(self.store, "S2", "S1")
        row = self.store.query_one("SELECT * FROM scan_diff_stat WHERE cur='S2' AND prev='S1'")
        self.assertIsNotNone(row)
        self.assertEqual(int(row["new"]), 2)
        self.assertEqual(int(row["regressed"]), 1)
        # 既有一条更早的趋势记录，确保按 ts 倒序
        self.store.execute(
            "INSERT OR REPLACE INTO scan_diff_stat(cur, prev, new, fixed, persisting,"
            " regressed, ts) VALUES('S1','S0',3,0,0,0,'2020-01-01T00:00:00.000Z')"
        )
        rows = diff.trend(self.store, limit=12)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["cur"], "S2")
        self.assertEqual(rows[-1]["cur"], "S1")
        self.assertEqual(
            set(rows[0]),
            {"cur", "prev", "new", "fixed", "persisting", "regressed", "ts"},
        )
        # 表不存在时返回空列表
        bare = Store(self.tmp / "bare2.db")
        try:
            self.assertEqual(diff.trend(bare), [])
        finally:
            bare.close()

    def test_window_alias(self) -> None:
        self._fixture()
        from_window = diff.window(self.store, from_snapshot="S1", to_snapshot="S2")
        direct = diff.build(self.store, "S2", "S1", write_stat=False)
        self.assertEqual(from_window["stats"], direct["stats"])


# ---------------------------------------------------------------------------
# 二、coverage：加权数值 / 角色适用域 / 未覆盖清单 / 容错
# ---------------------------------------------------------------------------
def _checkpoint(d1: str, d3: str, d6: str, *, d3_reason: str | None = None,
                d6_reason: str | None = None) -> dict:
    """构造 lab 资产（D1/D3/D6 适用）的 checkpoint。"""
    return {
        "done_assets": ["ast-0001"],
        "engines": {"nmap": "done"},
        "domains": {
            "D1": {"status": d1, "engines": ["nmap"], "reason": None},
            "D3": {"status": d3, "engines": ["nmap", "cve"], "reason": d3_reason},
            "D6": {"status": d6, "engines": ["nuclei"], "reason": d6_reason},
        },
    }


class TestCoverage(_DbCase):
    def test_weighted_value_one_asset(self) -> None:
        """lab：D1 done / D3 partial / D6 skipped → 0.25/0.45 = 0.5556。"""
        add_asset(self.store, "ast-0001", "192.168.56.20", "lab")
        add_plan(self.store)
        add_snapshot(self.store, "S1", TS2)
        add_task(self.store, "tsk-1", "ast-0001", "S1",
                 _checkpoint("done", "partial", "skipped",
                             d6_reason="engine_skipped:nuclei"))
        result = coverage.compute(self.store, "S1", self.cfg)
        self.assertNotIn("error", result)
        self.assertAlmostEqual(result["coverage"], round(0.25 / 0.45, 4), places=4)
        self.assertEqual(result["assets"], 1)
        row = result["matrix"][0]
        self.assertEqual(row["domains"], {"D1": 1.0, "D3": 0.5, "D6": 0.0})
        self.assertAlmostEqual(row["score"], round(0.25 / 0.45, 4), places=4)
        self.assertEqual(row["notes"]["D6"], "engine_skipped:nuclei")
        self.assertEqual(row["notes"]["D3"], "部分执行（结果可用但不完整）")
        # D2/D4/D5 对 lab 不适用 → applicable 0
        self.assertEqual(result["by_domain"]["D2"]["applicable"], 0)
        self.assertEqual(result["by_domain"]["D1"]["done"], 1)
        uncovered = {(item["asset_id"], item["domain"]) for item in result["uncovered"]}
        self.assertEqual(uncovered, {("ast-0001", "D3"), ("ast-0001", "D6")})
        self.assertEqual(result["weights"]["D2"], 0.30)

    def test_missing_task_counts_zero_and_lists_uncovered(self) -> None:
        add_asset(self.store, "ast-0001", "192.168.56.20", "lab")
        add_asset(self.store, "ast-0002", "192.168.56.21", "lab")
        add_plan(self.store)
        add_snapshot(self.store, "S1", TS2)
        add_task(self.store, "tsk-1", "ast-0001", "S1",
                 _checkpoint("done", "partial", "skipped"))
        result = coverage.compute(self.store, "S1", self.cfg)
        self.assertEqual(result["assets"], 2)
        self.assertAlmostEqual(result["coverage"], round(0.25 / 0.90, 4), places=4)
        reasons = [
            item["reason"] for item in result["uncovered"]
            if item["asset_id"] == "ast-0002"
        ]
        self.assertEqual(len(reasons), 3)
        self.assertTrue(all(reason == "本次运行未包含该资产" for reason in reasons))
        ast2 = [row for row in result["matrix"] if row["asset_id"] == "ast-0002"][0]
        self.assertEqual(ast2["domains"], {"D1": 0.0, "D3": 0.0, "D6": 0.0})
        self.assertEqual(ast2["score"], 0.0)

    def test_role_applicable_domains(self) -> None:
        """web：适用 D1/D3/D5/D6；D2 即使 done 也不进分母。"""
        add_asset(self.store, "ast-0009", "192.168.56.30", "web")
        add_plan(self.store)
        add_snapshot(self.store, "S1", TS2)
        add_task(self.store, "tsk-9", "ast-0009", "S1", {
            "domains": {
                "D1": {"status": "done", "engines": ["nmap"], "reason": None},
                "D2": {"status": "done", "engines": ["pkgs"], "reason": None},
                "D3": {"status": "skipped", "engines": [], "reason": "no cred"},
                "D5": {"status": "done", "engines": ["testssl"], "reason": None},
                "D6": {"status": "skipped", "engines": [], "reason": "no template"},
            }
        })
        result = coverage.compute(self.store, "S1", self.cfg)
        # 分子 .15+.10=.25，分母 .15+.20+.10+.10=.55
        self.assertAlmostEqual(result["coverage"], round(0.25 / 0.55, 4), places=4)
        self.assertEqual(result["matrix"][0]["domains"], {"D1": 1.0, "D3": 0.0,
                                                          "D5": 1.0, "D6": 0.0})

    def test_cfg_overrides_weights_and_role_domains(self) -> None:
        add_asset(self.store, "ast-0001", "192.168.56.20", "lab")
        add_plan(self.store)
        add_snapshot(self.store, "S1", TS2)
        add_task(self.store, "tsk-1", "ast-0001", "S1",
                 _checkpoint("done", "partial", "skipped"))
        cfg = load_config(None)
        cfg.setdefault("scan", {})["coverage"] = {
            "weights": {"D1": 1.0, "D2": 0.0, "D3": 0.0, "D4": 0.0, "D5": 0.0, "D6": 0.0},
            "role_domains": {"lab": ["D1"]},
        }
        result = coverage.compute(self.store, "S1", cfg)
        self.assertAlmostEqual(result["coverage"], 1.0, places=4)
        self.assertEqual(result["uncovered"], [])
        self.assertEqual(result["weights"]["D1"], 1.0)

    def test_missing_snapshot_returns_zero_with_error(self) -> None:
        add_asset(self.store, "ast-0001", "192.168.56.20", "lab")
        result = coverage.compute(self.store, "S-not-exist", self.cfg)
        self.assertEqual(result["coverage"], 0.0)
        self.assertIn("error", result)
        self.assertEqual(len(result["uncovered"]), 3)
        self.assertTrue(all(item["reason"] == "快照不存在，无法判定覆盖"
                            for item in result["uncovered"]))

    def test_disabled_asset_not_counted(self) -> None:
        add_asset(self.store, "ast-0001", "192.168.56.20", "lab", enabled=0)
        result = coverage.compute(self.store, "S1", self.cfg)
        self.assertEqual(result["assets"], 0)
        self.assertEqual(result["coverage"], 0.0)
        self.assertEqual(result["uncovered"], [])

    def test_schema_missing(self) -> None:
        bare = Store(self.tmp / "bare.db")
        try:
            result = coverage.compute(bare, "S1")
            self.assertEqual(result["coverage"], 0.0)
            self.assertIn("error", result)
        finally:
            bare.close()


# ---------------------------------------------------------------------------
# 三、report：HTML 关键内容 / 转义 / 无外部依赖 / 导出
# ---------------------------------------------------------------------------
REPORT_RUN = "run-report"


class TestReport(_DbCase):
    def _fixture(self) -> None:
        """2 资产、2 快照、2 task、4 问题 + 2 事实；覆盖率手算 = 0.8。"""
        add_asset(self.store, "ast-0001", "192.168.56.20", "lab", hostname="b-lab")
        add_asset(self.store, "ast-0002", "192.168.56.21", "web", hostname="b-web")
        add_plan(self.store)
        add_snapshot(
            self.store, "S1", TS1, run_id="run-report-0",
            stats={"engines": {"nmap": {"done": 1, "findings": 2}}, "profile": "weekly"},
        )
        stats = {
            "engines": {"nmap": {"done": 2, "findings": 2}, "lynis": {"error": 1, "findings": 1}},
            "assets": ["ast-0001", "ast-0002"],
            "profile": "weekly",
            "findings": 7,
        }
        add_snapshot(self.store, TS2_SNAPSHOT, TS2, stats=stats)

        # 覆盖率：ast-0001(lab) = .25/.45，ast-0002(web) = .55/.55 → 合计 .8
        add_task(self.store, "tsk-1", "ast-0001", TS2_SNAPSHOT,
                 _checkpoint("done", "partial", "skipped",
                             d3_reason="部分引擎不可用/不适用",
                             d6_reason="engine_skipped:nuclei"),
                 run_id=REPORT_RUN)
        add_task(self.store, "tsk-2", "ast-0002", TS2_SNAPSHOT, {
            "done_assets": ["ast-0002"],
            "engines": {"nmap": "done", "testssl": "done"},
            "domains": {
                "D1": {"status": "done", "engines": ["nmap"], "reason": None},
                "D3": {"status": "done", "engines": ["nmap", "cve"], "reason": None},
                "D5": {"status": "done", "engines": ["testssl"], "reason": None},
                "D6": {"status": "done", "engines": ["nuclei"], "reason": None},
            },
        }, run_id=REPORT_RUN)

        # 事实：端口 + 组件（banner 里放 <script> 验证转义）
        add_finding(
            self.store, "fnd-port", "ast-0001", "key-port", "port", "PORT-22/tcp",
            title="22/tcp open ssh", status="observed", target="192.168.56.20:22/tcp",
            evidence={"port": 22, "proto": "tcp", "state": "open",
                      "reason": "syn-ack", "service": "ssh"},
        )
        add_finding(
            self.store, "fnd-comp", "ast-0001", "key-comp", "component", "SVC-22/tcp",
            title="OpenSSH 9.6p1 (22/tcp)", status="observed",
            target="192.168.56.20:22/tcp",
            evidence={"service": "ssh", "product": "OpenSSH", "version": "9.6p1",
                      "cpe": "cpe:/a:openbsd:openssh:9.6p1",
                      "extrainfo": "<script>alert(1)</script>"},
        )
        # 问题：CVE（区间命中 + 档案 + 修复）、CVE（回归）、CVE（新增）、配置
        add_finding(
            self.store, "fnd-cve", "ast-0002", "key-cve", "cve", "CVE-2023-1234",
            title="<b>OpenSSH 注入</b>", severity="严重", cvss=9.8,
            cvss_source="nvd", confidence="range", status="confirmed",
            target="ast-0002:openssh",
            evidence={
                "banner": "SSH-2.0-OpenSSH_9.0",
                "detected_version": "9.0", "matched_version": "9.0",
                "cpe23": "cpe:2.3:a:openbsd:openssh:9.0",
                "interval": {"start_excl": "8.0", "end_incl": "9.3"},
                "archive_id": "VULN-0001", "source": "nvd",
            },
            vuln_ref="VULN-0001",
        )
        add_finding(
            self.store, "fnd-reg", "ast-0002", "key-reg", "cve", "CVE-2022-0002",
            title="回归漏洞", severity="高", cvss=7.5, confidence="exact",
            status="confirmed", target="ast-0002:openssl",
            evidence={"detected_version": "3.0.1",
                      "cpe23": "cpe:2.3:a:openssl:openssl:3.0.1"},
        )
        add_finding(
            self.store, "fnd-new", "ast-0002", "key-new", "cve", "CVE-2024-9999",
            title="新披露漏洞", severity="中", cvss=5.5, confidence="cpe_only",
            status="new", target="ast-0002:nginx",
        )
        add_finding(
            self.store, "fnd-cfg", "ast-0002", "key-cfg", "config", "LYNIS-001",
            title="SSH 允许密码登录", severity="低", cvss=3.1, confidence="tool",
            status="new", target="192.168.56.21:ssh",
            evidence={"fix": "禁用 PasswordAuthentication"},
        )

        # 冻结项：S1 与 S2（新增/修复/回归/仍存在）
        for snapshot_id in ("S1", TS2_SNAPSHOT):
            add_item(self.store, snapshot_id, "ast-0001", "key-port", "port", "PORT-22/tcp")
            add_item(self.store, snapshot_id, "ast-0001", "key-comp", "component", "SVC-22/tcp")
            add_item(self.store, snapshot_id, "ast-0002", "key-cve", "cve", "CVE-2023-1234",
                     severity="严重", status="confirmed", cvss=9.8)
        # 回归：上一次已是 fixed，本次又出现
        add_item(self.store, "S1", "ast-0002", "key-reg", "cve", "CVE-2022-0002",
                 severity="高", status="fixed", cvss=7.5)
        add_item(self.store, TS2_SNAPSHOT, "ast-0002", "key-reg", "cve", "CVE-2022-0002",
                 severity="高", status="confirmed", cvss=7.5)
        add_item(self.store, "S1", "ast-0002", "key-fixed", "cve", "CVE-2021-0001",
                 severity="中", status="confirmed", cvss=6.0)
        add_item(self.store, TS2_SNAPSHOT, "ast-0002", "key-new", "cve", "CVE-2024-9999",
                 severity="中", status="new", cvss=5.5)
        add_item(self.store, TS2_SNAPSHOT, "ast-0002", "key-cfg", "config", "LYNIS-001",
                 severity="低", status="new", cvss=3.1)

    def test_render_html_key_content(self) -> None:
        self._fixture()
        html = report.render_html(self.store, self.cfg, TS2_SNAPSHOT)
        self.assertIsInstance(html, str)
        for needle in (
            "Hornwork", "漏洞扫描报告", TS2_SNAPSHOT, "每周常规扫描",
            "CVE-2023-1234", "区间命中", "仅 CPE 命中", "工具/PoC",
            "VULN-0001", "证据链", "banner=SSH-2.0-OpenSSH_9.0",
            "80.0%", "新增", "已修复", "仍存在", "回归",
            "端口与服务", "未覆盖清单", "nmap", "免责声明",
            "禁用 PasswordAuthentication",
        ):
            self.assertIn(needle, html)
        # 问题表按严重级排序：严重在 高 之前
        self.assertLess(html.index("CVE-2023-1234"), html.index("CVE-2022-0002"))

    def test_render_html_escapes_dynamic_text(self) -> None:
        self._fixture()
        html = report.render_html(self.store, self.cfg, TS2_SNAPSHOT)
        self.assertIn("&lt;b&gt;OpenSSH 注入&lt;/b&gt;", html)
        self.assertNotIn("<b>OpenSSH", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script", html.lower())

    def test_render_html_offline_single_file(self) -> None:
        self._fixture()
        html = report.render_html(self.store, self.cfg, TS2_SNAPSHOT)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("<style>", html)
        self.assertNotIn("@import", html)
        for token in ('src="http', 'href="http', "http://", "https://", "cdn."):
            self.assertNotIn(token, html)
        self.assertIn("@media print", html)

    def test_render_json(self) -> None:
        self._fixture()
        payload = report.render_json(self.store, self.cfg, TS2_SNAPSHOT)
        self.assertEqual(payload["report"], "hornwork-scan")
        self.assertEqual(payload["snapshot"]["snapshot_id"], TS2_SNAPSHOT)
        self.assertEqual(len(payload["issues"]), 4)
        self.assertEqual(len(payload["assets"]), 2)
        self.assertEqual(payload["summary"]["cves"], 3)
        self.assertAlmostEqual(payload["summary"]["coverage"], 0.8, places=4)
        self.assertEqual(payload["diff"]["stats"]["new"], 2)
        self.assertEqual(payload["diff"]["stats"]["fixed"], 1)
        chain = [item for item in payload["issues"] if item["check_id"] == "CVE-2023-1234"][0]
        self.assertIn("档案=VULN-0001", chain["chain"])
        self.assertIn("区间=", chain["chain"])
        # 必须能被 json.dumps（Web/CLI 直接返回）
        json.dumps(payload, ensure_ascii=False, allow_nan=False)

    def test_render_diff_without_previous_snapshot(self) -> None:
        """首扫时 runner 传入 summary-only diff（prev=None）：不硬造四态表。"""
        self._fixture()
        runner_diff = {
            "cur": TS2_SNAPSHOT, "prev": None, "items": [],
            "stats": {"new": 0, "fixed": 0, "persisting": 0, "regressed": 0, "total": 0},
        }
        html = report.render_html(self.store, self.cfg, TS2_SNAPSHOT, diff=runner_diff)
        self.assertIn("首次运行（基线快照）", html)
        self.assertIn("首次快照", html)
        self.assertNotIn("新增 0 ｜ 已修复 0", html)
        payload = report.render_json(self.store, self.cfg, TS2_SNAPSHOT, diff=runner_diff)
        self.assertIsNone(payload["summary"]["prev"])
        self.assertTrue(payload["summary"]["has_diff"])

    def test_export_html_json_and_kwargs(self) -> None:
        self._fixture()
        diff_result = diff.build(self.store, TS2_SNAPSHOT, "S1", write_stat=False)
        coverage_result = coverage.compute(self.store, TS2_SNAPSHOT, self.cfg)

        html_path = self.tmp / "out" / "report.html"
        result = report.export(
            self.store, self.cfg, TS2_SNAPSHOT, fmt="html", out=str(html_path),
            diff=diff_result, coverage=coverage_result,
        )
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(set(result) >= {"ok", "path", "bytes", "snapshot_id", "format"}, True)
        self.assertEqual(result["format"], "html")
        self.assertEqual(result["snapshot_id"], TS2_SNAPSHOT)
        self.assertTrue(Path(result["path"]).is_file())
        content = Path(result["path"]).read_text(encoding="utf-8")
        self.assertIn("漏洞扫描报告", content)
        self.assertIn("CVE-2023-1234", content)
        self.assertEqual(result["bytes"], len(content.encode("utf-8")))

        json_path = self.tmp / "out" / "report.json"
        result_json = report.export(
            self.store, self.cfg, TS2_SNAPSHOT, fmt="json", out=str(json_path),
            diff=diff_result, coverage=coverage_result,
        )
        self.assertTrue(result_json["ok"], result_json.get("error"))
        payload = json.loads(Path(result_json["path"]).read_text(encoding="utf-8"))
        self.assertEqual(payload["snapshot"]["snapshot_id"], TS2_SNAPSHOT)

    def test_export_default_path_and_directory(self) -> None:
        self._fixture()
        default = report.export(self.store, self.cfg, TS2_SNAPSHOT)
        self.assertTrue(default["ok"], default.get("error"))
        self.assertEqual(Path(default["path"]).name, f"scan-{TS2_SNAPSHOT}.html")
        self.assertEqual(Path(default["path"]).parent, self.tmp / "reports")
        # out 指向已存在目录 → 自动补默认文件名
        out_dir = self.tmp / "pick"; out_dir.mkdir()
        inside = report.export(self.store, self.cfg, TS2_SNAPSHOT, out=str(out_dir))
        self.assertTrue(inside["ok"], inside.get("error"))
        self.assertEqual(Path(inside["path"]).name, f"scan-{TS2_SNAPSHOT}.html")

    def test_export_failure_returns_not_raise(self) -> None:
        self._fixture()
        blocker = self.tmp / "blocker"
        blocker.write_text("x", encoding="utf-8")
        result = report.export(
            self.store, self.cfg, TS2_SNAPSHOT, out=str(blocker / "report.html")
        )
        self.assertFalse(result["ok"])
        self.assertIn("error", result)

    def test_render_missing_snapshot_is_tolerated(self) -> None:
        html = report.render_html(self.store, self.cfg, "S-not-exist")
        self.assertIn("漏洞扫描报告", html)
        self.assertIn("S-not-exist", html)
        payload = report.render_json(self.store, self.cfg, "S-not-exist")
        self.assertEqual(payload["issues"], [])

    def test_render_with_schema_missing(self) -> None:
        bare = Store(self.tmp / "bare.db")
        try:
            html = report.render_html(bare, self.cfg, "S1")
            self.assertIn("漏洞扫描报告", html)
            payload = report.render_json(bare, self.cfg, "S1")
            self.assertEqual(payload["issues"], [])
        finally:
            bare.close()


# ---------------------------------------------------------------------------
# 四、api：过滤 / 分页 / 空库容错 / 概览
# ---------------------------------------------------------------------------
class TestApiEmpty(_DbCase):
    def test_empty_schema(self) -> None:
        plans = api.list_plans(self.store)
        self.assertEqual(plans["items"], [])
        self.assertEqual(plans["total"], 0)
        self.assertIn("ts", plans)
        self.assertEqual(api.list_tasks(self.store)["total"], 0)
        self.assertEqual(api.list_findings(self.store)["items"], [])
        self.assertEqual(api.list_snapshots(self.store)["items"], [])
        self.assertEqual(api.list_assets(self.store)["total"], 0)
        self.assertIsNone(api.get_task(self.store, "nope"))
        self.assertIsNone(api.get_finding(self.store, "nope"))
        self.assertIsNone(api.get_snapshot(self.store, "nope"))
        overview = api.overview(self.store)
        self.assertEqual(overview["counts"]["asset"], 0)
        self.assertEqual(overview["counts"]["finding"], 0)
        self.assertIsNone(overview["last_task"])
        self.assertIsNone(overview["last_snapshot"])
        stats = api.cve_stats(self.store)
        self.assertEqual(stats["total"], 0)
        self.assertEqual(stats["by_severity"], {})
        self.assertIsInstance(stats["ts"], str)
        self.assertEqual(api.trend(self.store)["items"], [])
        diff_result = api.get_diff(self.store, "S2", "S1")
        self.assertIn("error", diff_result)
        self.assertEqual(diff_result["stats"]["total"], 0)
        coverage_result = api.get_coverage(self.store, "S1", self.cfg)
        self.assertEqual(coverage_result["coverage"], 0.0)

    def test_tables_missing(self) -> None:
        bare = Store(self.tmp / "bare.db")
        try:
            self.assertEqual(api.list_plans(bare)["total"], 0)
            self.assertEqual(api.list_tasks(bare)["items"], [])
            self.assertEqual(api.list_findings(bare)["total"], 0)
            self.assertEqual(api.list_snapshots(bare)["total"], 0)
            self.assertEqual(api.list_assets(bare)["total"], 0)
            self.assertEqual(api.cve_stats(bare)["total"], 0)
            overview = api.overview(bare)
            self.assertEqual(overview["counts"]["snapshot"], 0)
            self.assertIsNone(api.get_snapshot(bare, "S1"))
        finally:
            bare.close()


class TestApiPopulated(_DbCase):
    def setUp(self) -> None:
        super().setUp()
        add_asset(self.store, "ast-0001", "192.168.56.20", "lab")
        add_asset(self.store, "ast-0002", "192.168.56.21", "web")
        add_plan(self.store)
        add_snapshot(self.store, "S1", TS1, run_id="run-0",
                     stats={"engines": {"nmap": {"done": 1, "findings": 2}}})
        add_snapshot(self.store, TS2_SNAPSHOT, TS2,
                     stats={"engines": {"nmap": {"done": 2, "findings": 2}}})
        add_task(self.store, "tsk-1", "ast-0001", TS2_SNAPSHOT,
                 {"done_assets": ["ast-0001"],
                  "domains": {"D1": {"status": "done", "engines": ["nmap"], "reason": None}}},
                 status="done")
        add_task(self.store, "tsk-2", "ast-0002", TS2_SNAPSHOT,
                 {"done_assets": ["ast-0002"],
                  "domains": {"D1": {"status": "partial", "engines": ["nmap"],
                                     "reason": "部分引擎不可用/不适用"}}},
                 status="partial")
        add_finding(self.store, "fnd-1", "ast-0001", "key-1", "cve", "CVE-2023-0001",
                    title="严重漏洞", severity="严重", cvss=9.8, confidence="range",
                    status="confirmed", target="ast-0001:openssh",
                    evidence={"detected_version": "9.0"}, vuln_ref="VULN-0001")
        add_finding(self.store, "fnd-2", "ast-0002", "key-2", "cve", "CVE-2023-0002",
                    title="中危漏洞", severity="中", cvss=5.5, confidence="exact",
                    status="new", target="ast-0002:nginx")
        add_finding(self.store, "fnd-3", "ast-0002", "key-3", "config", "LYNIS-001",
                    title="配置问题", severity="低", cvss=2.0, confidence="tool",
                    status="new", target="ast-0002:ssh")
        add_finding(self.store, "fnd-4", "ast-0001", "key-4", "port", "PORT-22/tcp",
                    title="22/tcp open", severity=None, status="observed",
                    target="192.168.56.20:22/tcp",
                    evidence={"port": 22, "state": "open"})
        add_item(self.store, TS2_SNAPSHOT, "ast-0001", "key-1", "cve", "CVE-2023-0001",
                 severity="严重", status="confirmed", cvss=9.8)
        add_item(self.store, TS2_SNAPSHOT, "ast-0002", "key-2", "cve", "CVE-2023-0002",
                 severity="中", status="new", cvss=5.5)
        # 上一次快照只有 key-1（本次仍存在）→ diff 得到 new=1 / persisting=1
        add_item(self.store, "S1", "ast-0001", "key-1", "cve", "CVE-2023-0001",
                 severity="严重", status="confirmed", cvss=9.8)
        self.store.execute(
            "INSERT OR REPLACE INTO scan_diff_stat(cur, prev, new, fixed, persisting,"
            " regressed, ts) VALUES(?,?,1,0,1,0,?)",
            (TS2_SNAPSHOT, "S1", TS2),
        )
        self.store.execute(
            "INSERT INTO cve_cache(cve_id, cpe23, vulnerable, cvss, severity, published,"
            " modified, source) VALUES('CVE-2023-0001','cpe:2.3:a:openbsd:openssh:*',1,"
            "9.8,'严重','2023-01-01T00:00:00.000','2023-02-01T00:00:00.000','nvd')"
        )
        self.store.execute(
            "INSERT INTO cve_cache(cve_id, cpe23, vulnerable, cvss, severity, published,"
            " modified, source) VALUES('CVE-2023-0002','cpe:2.3:a:nginx:nginx:*',1,"
            "5.5,'中','2023-03-01T00:00:00.000','2023-04-01T00:00:00.000','ubuntu')"
        )

    def test_list_tasks_filter_and_pagination(self) -> None:
        all_tasks = api.list_tasks(self.store)
        self.assertEqual(all_tasks["total"], 2)
        self.assertEqual(len(all_tasks["items"]), 2)
        done = api.list_tasks(self.store, status="done")
        self.assertEqual(done["total"], 1)
        self.assertEqual(done["items"][0]["task_id"], "tsk-1")
        limited = api.list_tasks(self.store, limit=1)
        self.assertEqual(limited["total"], 2)
        self.assertEqual(len(limited["items"]), 1)
        self.assertIsInstance(all_tasks["items"][0]["checkpoint"], dict)
        self.assertIn("domains", all_tasks["items"][0]["checkpoint"])

    def test_get_task(self) -> None:
        task = api.get_task(self.store, "tsk-1")
        self.assertIsNotNone(task)
        self.assertEqual(task["asset_id"], "ast-0001")
        self.assertEqual(task["asset_ip"], "192.168.56.20")
        self.assertEqual(task["checkpoint"]["domains"]["D1"]["status"], "done")
        self.assertIsNone(api.get_task(self.store, "tsk-none"))

    def test_list_findings_filters(self) -> None:
        all_findings = api.list_findings(self.store)
        self.assertEqual(all_findings["total"], 4)
        self.assertEqual(all_findings["items"][0]["severity"], "严重")
        severe = api.list_findings(self.store, severity="严重")
        self.assertEqual(severe["total"], 1)
        self.assertEqual(severe["items"][0]["check_id"], "CVE-2023-0001")
        by_asset = api.list_findings(self.store, asset_id="ast-0002")
        self.assertEqual(by_asset["total"], 2)
        cve = api.list_findings(self.store, kind="cve")
        self.assertEqual(cve["total"], 2)
        # 大小写不敏感（kind/status 枚举统一小写）
        self.assertEqual(api.list_findings(self.store, kind="CVE")["total"], 2)
        confirmed = api.list_findings(self.store, status="confirmed")
        self.assertEqual(confirmed["total"], 1)
        limited = api.list_findings(self.store, limit=2)
        self.assertEqual(limited["total"], 4)
        self.assertEqual(len(limited["items"]), 2)
        invalid = api.list_findings(self.store, severity="critical")
        self.assertEqual(invalid["total"], 0)
        self.assertEqual(invalid["items"], [])
        parsed = api.list_findings(self.store, kind="port")["items"][0]
        self.assertIsInstance(parsed["evidence"], dict)
        self.assertEqual(parsed["evidence"]["state"], "open")

    def test_get_finding_and_snapshot(self) -> None:
        finding = api.get_finding(self.store, "fnd-1")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["vuln_ref"], "VULN-0001")
        self.assertEqual(finding["evidence"]["detected_version"], "9.0")
        self.assertIsNone(api.get_finding(self.store, "nope"))
        snapshot = api.get_snapshot(self.store, TS2_SNAPSHOT)
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot["item_count"], 2)
        self.assertEqual(snapshot["by_kind"]["cve"], 2)
        self.assertIsInstance(snapshot["stats"], dict)
        self.assertIsNone(api.get_snapshot(self.store, "S-none"))

    def test_list_snapshots_and_assets(self) -> None:
        snapshots = api.list_snapshots(self.store, limit=1)
        self.assertEqual(snapshots["total"], 2)
        self.assertEqual(len(snapshots["items"]), 1)
        self.assertEqual(snapshots["items"][0]["snapshot_id"], TS2_SNAPSHOT)
        assets = api.list_assets(self.store)
        self.assertEqual(assets["total"], 2)
        self.assertEqual(assets["items"][0]["role"], "lab")
        self.assertIsInstance(assets["items"][0]["facts"], dict)

    def test_list_plans(self) -> None:
        plans = api.list_plans(self.store)
        self.assertEqual(plans["total"], 1)
        plan = plans["items"][0]
        self.assertEqual(plan["plan_id"], PLAN)
        self.assertIsInstance(plan["selector"], dict)
        self.assertEqual(plan["selector"]["group"], "lab")
        self.assertTrue(plan["enabled"])

    def test_diff_coverage_trend(self) -> None:
        diff_result = api.get_diff(self.store, TS2_SNAPSHOT, "S1")
        self.assertNotIn("error", diff_result)
        self.assertEqual(diff_result["stats"]["new"], 1)
        self.assertEqual(diff_result["stats"]["persisting"], 1)
        # 只读：不应写入 scan_diff_stat（已有 1 行来自夹具）
        self.assertEqual(
            self.store.query_one("SELECT COUNT(*) AS n FROM scan_diff_stat")["n"], 1
        )
        coverage_result = api.get_coverage(self.store, TS2_SNAPSHOT, self.cfg)
        self.assertEqual(coverage_result["snapshot_id"], TS2_SNAPSHOT)
        self.assertIsInstance(coverage_result["coverage"], float)
        trend = api.trend(self.store)
        self.assertEqual(trend["total"], 1)
        self.assertEqual(trend["items"][0]["cur"], TS2_SNAPSHOT)

    def test_cve_stats(self) -> None:
        stats = api.cve_stats(self.store)
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["by_severity"]["严重"], 1)
        self.assertEqual(stats["by_source"]["nvd"], 1)
        self.assertEqual(stats["by_year"]["2023"], 2)
        self.assertEqual(stats["oval_fixes"], 0)
        self.assertEqual(stats["component_map"], 0)

    def test_overview(self) -> None:
        overview = api.overview(self.store)
        self.assertEqual(overview["counts"]["asset"], 2)
        self.assertEqual(overview["counts"]["plan"], 1)
        self.assertEqual(overview["counts"]["task"], 2)
        self.assertEqual(overview["counts"]["snapshot"], 2)
        self.assertEqual(overview["counts"]["finding"], 4)
        self.assertEqual(overview["counts"]["cve"], 2)
        self.assertEqual(overview["tasks"]["total"], 2)
        self.assertEqual(overview["tasks"]["by_status"]["done"], 1)
        self.assertEqual(overview["findings"]["by_kind"]["cve"], 2)
        self.assertIsNotNone(overview["last_task"])
        self.assertIsNotNone(overview["last_snapshot"])
        self.assertEqual(overview["last_snapshot"]["snapshot_id"], TS2_SNAPSHOT)
        self.assertLessEqual(len(overview["recent_tasks"]), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
