"""扫描模块扫描流程测试（Lead 负责）：台账/计划/闸门/任务/归一/生命周期/窗口联动。

本测试**不依赖 nmap、不联网**：用假适配器注入 RawResult，验证"编排 + 归一 + 快照 +
diff + 覆盖率 + 报告 + Web API"整条链路在 Windows 开发机上可回归。
真实 nmap 解析由 ``test_scan_engines`` 覆盖，真实 NVD 匹配由 ``test_scan_cve`` 覆盖。
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from hornwork import schema
from hornwork.config import deep_merge, load_config
from hornwork.scan import (
    assets,
    coverage,
    diff,
    normalize,
    report,
    runner,
    scheduler,
    store as sscan,
    task as stask,
    window,
)
from hornwork.store import Store


def _cfg(tmpdir: str) -> dict:
    cfg = load_config(None)
    return deep_merge(cfg, {
        "general": {"data_dir": tmpdir, "host_id": "test-host"},
        "scan": {
            "report_dir": str(pathlib.Path(tmpdir) / "reports"),
            "gates": {"window_start": "", "window_end": "", "min_disk_gb": 0},
            "settings": {},
        },
    })


class FakeNmap:
    """假 nmap 适配器：按脚本返回 RawResult，用于验证编排而不真的扫描。"""

    name = "nmap"
    version = "fake-1.0"
    cost = "medium"
    requires = ["tcp"]

    def __init__(self, builder):
        self.builder = builder
        self.calls = 0

    def available(self) -> bool:
        return True

    def supports(self, asset, profile) -> bool:
        return True

    def run(self, asset, ctx):
        self.calls += 1
        return [dict(item) for item in self.builder(asset, ctx)]


def _open_port(port=22, proto="tcp", service="ssh"):
    return {
        "engine": "nmap", "kind": "port",
        "check_id": f"PORT-{port}/{proto}",
        "target": f"127.0.0.1:{port}/{proto}",
        "title": f"{port}/{proto} open {service}",
        "evidence": {"port": port, "proto": proto, "state": "open", "reason": "syn-ack",
                     "service": service},
    }


def _component(name="OpenSSH", version="10.2p1", cpe="cpe:/a:openbsd:openssh:10.2p1", port=22):
    return {
        "engine": "nmap", "kind": "component",
        "check_id": f"SVC-{port}/tcp", "target": f"127.0.0.1:{port}/tcp",
        "title": f"{name} {version} ({port}/tcp)",
        "comp_norm": name.lower(), "version": version, "cpe": cpe,
        "evidence": {"service": "ssh", "product": name, "version": version, "cpe": cpe,
                     "port": port, "source": "nmap"},
    }


def _summary():
    return {
        "engine": "nmap", "kind": "host_summary", "check_id": "HOST-127.0.0.1",
        "target": "127.0.0.1",
        "evidence": {"up": True, "scanned": 200, "open": 1, "closed": 199, "filtered": 0},
    }


def _config_finding(check_id="LYNIS-TEST-1"):
    return {
        "engine": "nmap", "kind": "config", "check_id": check_id,
        "target": "host:127.0.0.1",
        "title": "测试基线项：SSH 允许 root 登录",
        "severity": "中", "confidence": "exact",
        "evidence": {"message": "PermitRootLogin yes", "raw": "warning[]=TEST|..."},
    }


class ScanFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="scan-flow-")
        self.cfg = _cfg(self.tmp)
        self.store = Store(pathlib.Path(self.tmp) / "hornwork.db")
        sscan.init_schema(self.store)
        self.asset = assets.add_asset(
            self.store, self.cfg, ip="127.0.0.1", hostname="test-host",
            role="self", criticality=5, group="self", is_self=True,
            declared_ports=[22, 80],
        )
        self.plan = sscan.upsert_plan(self.store, {
            "plan_id": "p-manual",
            "name": "测试手动计划",
            "kind": "manual",
            "profile": "quick",
            "selector_json": {"group": "self"},
            "enabled": 1,
        })
        self.outputs = [_open_port(), _component(), _summary(), _config_finding()]
        self.adapter = FakeNmap(lambda asset, ctx: self.outputs)

    def tearDown(self) -> None:
        self.store.close()

    # ------------------------------------------------------------------ 台账/计划
    def test_asset_and_plan(self):
        rows = sscan.list_assets(self.store)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "127.0.0.1")
        self.assertEqual(assets.declared_ports(rows[0]), [22, 80])
        self.assertTrue(rows[0]["is_self"])
        plan = sscan.get_plan(self.store, "p-manual")
        self.assertEqual(plan["profile"], "quick")
        self.assertEqual(plan["selector_json"], {"group": "self"})
        # 计划幂等更新
        sscan.upsert_plan(self.store, {"plan_id": "p-manual", "kind": "manual",
                                      "profile": "weekly", "selector_json": {}})
        self.assertEqual(sscan.get_plan(self.store, "p-manual")["profile"], "weekly")
        self.assertEqual(len(sscan.list_plans(self.store)), 1)

    def test_select_assets_selector(self):
        assets.add_asset(self.store, self.cfg, ip="192.168.1.50", role="lab", group="lab",
                         tags="web,lab")
        self.assertEqual(len(sscan.select_assets(self.store, {"group": "lab"})), 1)
        self.assertEqual(len(sscan.select_assets(self.store, {"tags": "web"})), 1)
        self.assertEqual(len(sscan.select_assets(self.store, {"role": "self"})), 1)
        self.assertEqual(len(sscan.select_assets(self.store, {})), 2)
        # 禁用资产不进目标集
        sscan.set_asset_enabled(self.store, self.asset["asset_id"], False)
        self.assertEqual(len(sscan.select_assets(self.store, {"group": "self"})), 0)

    # ------------------------------------------------------------------ 闸门/槽位
    def test_allow_cidrs(self):
        self.assertTrue(scheduler.check_allow_cidrs(self.cfg, "127.0.0.1")[0])
        ok, reason = scheduler.check_allow_cidrs(self.cfg, "8.8.8.8")
        self.assertFalse(ok)
        self.assertIn("allow_cidrs", reason)

    def test_slots_and_windows(self):
        self.assertEqual(scheduler.slot_of({"kind": "daily"}), schema.utc_now()[:10].replace("-", ""))
        self.assertTrue(scheduler.slot_of({
            "kind": "targeted", "params_json": {"cve_id": "CVE-2021-43798"}
        }).startswith("cve-"))
        self.assertFalse(scheduler.in_window(None, "02:00", "03:00") and
                         scheduler.in_window(None, "03:00", "02:00"))
        self.assertIsNotNone(scheduler.next_run({"kind": "daily"}))
        self.assertIsNotNone(scheduler.next_run({"kind": "weekly"}))
        self.assertIsNotNone(scheduler.next_run({"kind": "quarterly"}))

    # ------------------------------------------------------------------ 跑通扫描
    def test_run_plan_end_to_end(self):
        r = runner.ScanRunner(self.cfg, self.store, adapters=[self.adapter])
        res = r.run_plan("p-manual", slot="t1", trigger="manual")
        self.assertTrue(res["ok"], res.get("reason"))
        self.assertTrue(res["snapshot_id"])
        counts = res["counts"]
        self.assertEqual(counts["findings"], 3)          # 1 port + 1 component + 1 config
        self.assertEqual(counts["problems"], 1)          # config 是"问题"
        tasks = sscan.list_tasks(self.store, run_id=res["run_id"])
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["status"], "done")
        # 事实/问题状态
        findings = sscan.list_findings(self.store)
        by_kind = {f["kind"]: f for f in findings}
        self.assertEqual(by_kind["port"]["status"], "observed")
        self.assertEqual(by_kind["component"]["status"], "observed")
        self.assertEqual(by_kind["config"]["status"], "new")
        # 快照冻结项
        items = sscan.snapshot_items(self.store, res["snapshot_id"])
        self.assertEqual(len(items), 3)
        # 资产事实回填
        asset = sscan.get_asset(self.store, self.asset["asset_id"])
        self.assertIn(22, asset["facts_json"]["open_ports"])
        # scan_window 事件（IF-23）
        events = self.store.query_events(event_type="scan_window", limit=10)
        self.assertEqual(len(events), 2)
        phases = {((e.get("raw") or {}).get("phase")) for e in events}
        self.assertEqual(phases, {"start", "end"})
        # 任务事件
        task_events = self.store.query_events(event_type="scan_task", limit=10)
        self.assertEqual(len(task_events), 1)

    def test_run_idempotent_daily_slot(self):
        sscan.upsert_plan(self.store, {"plan_id": "p-daily", "kind": "daily",
                                      "profile": "quick", "selector_json": {"group": "self"}})
        r = runner.ScanRunner(self.cfg, self.store, adapters=[self.adapter])
        first = r.run_plan("p-daily", trigger="manual")
        self.assertTrue(first["ok"])
        second = r.run_plan("p-daily", trigger="manual")
        self.assertTrue(second.get("duplicate"))
        self.assertEqual(len(sscan.list_tasks(self.store)), 1)

    def test_gate_rejects_out_of_scope_target(self):
        assets.add_asset(self.store, self.cfg, ip="8.8.8.8", group="outside", role="lab")
        sscan.upsert_plan(self.store, {"plan_id": "p-bad", "kind": "manual", "profile": "quick",
                                      "selector_json": {"group": "outside"}})
        r = runner.ScanRunner(self.cfg, self.store, adapters=[self.adapter])
        res = r.run_plan("p-bad", trigger="manual")
        self.assertFalse(res["ok"])
        self.assertIn("allow_cidrs", res.get("reason") or "")
        self.assertEqual(len(sscan.list_tasks(self.store)), 0)
        audit = self.store.query("SELECT * FROM action_audit WHERE action='scan.gate'")
        self.assertGreaterEqual(len(audit), 1)

    def test_lifecycle_fixed_after_two_misses(self):
        r = runner.ScanRunner(self.cfg, self.store, adapters=[self.adapter])
        first = r.run_plan("p-manual", slot="L1")
        config_finding = [f for f in sscan.list_findings(self.store) if f["kind"] == "config"][0]
        self.assertEqual(config_finding["status"], "new")
        # 第二次：配置项消失（其余仍在）
        self.outputs = [_open_port(), _component(), _summary()]
        second = r.run_plan("p-manual", slot="L2")
        self.assertTrue(second["ok"])
        after2 = sscan.get_finding(self.store, config_finding["finding_id"])
        self.assertEqual(after2["status"], "new")      # 第一次未现，还不算 fixed
        self.assertEqual(after2["miss_count"], 1)
        # 第三次仍未出现 → fixed
        third = r.run_plan("p-manual", slot="L3")
        self.assertTrue(third["ok"])
        after3 = sscan.get_finding(self.store, config_finding["finding_id"])
        self.assertEqual(after3["status"], "fixed")
        # 第四次重新出现 → reopened
        self.outputs = [_open_port(), _component(), _summary(), _config_finding()]
        fourth = r.run_plan("p-manual", slot="L4")
        self.assertTrue(fourth["ok"])
        reopened = sscan.get_finding(self.store, config_finding["finding_id"])
        self.assertEqual(reopened["status"], "reopened")

    def test_diff_between_snapshots(self):
        r = runner.ScanRunner(self.cfg, self.store, adapters=[self.adapter])
        s1 = r.run_plan("p-manual", slot="D1")["snapshot_id"]
        # 新开一个端口 + 去掉配置项
        self.outputs = [_open_port(), _open_port(80, "tcp", "http"), _component(), _summary()]
        s2 = r.run_plan("p-manual", slot="D2")["snapshot_id"]
        result = diff.build(self.store, s2, s1)
        self.assertEqual(result["stats"]["new"], 1)        # 新增 80 端口事实
        self.assertEqual(result["stats"]["fixed"], 1)      # 配置项消失（1 次未现不算 fixed，只是不在快照）
        # 快照项层面：s1 有 config 项，s2 没有 → fixed
        self.assertEqual(result["cur"], s2)
        self.assertGreaterEqual(result["stats"]["persisting"], 2)
        row = self.store.query_one(
            "SELECT * FROM scan_diff_stat WHERE cur=? AND prev=?", (s2, s1)
        )
        self.assertIsNotNone(row)

    def test_coverage_weighted(self):
        r = runner.ScanRunner(self.cfg, self.store, adapters=[self.adapter])
        res = r.run_plan("p-manual", slot="C1")
        cov = coverage.compute(self.store, res["snapshot_id"], self.cfg)
        self.assertEqual(cov["assets"], 1)
        # D1 由 nmap 覆盖=1.0；D2/D4/D5/D6 未运行=0；D3 因 matcher 缺失为 partial
        domains = cov["matrix"][0]["domains"]
        self.assertEqual(domains["D1"], 1.0)
        self.assertEqual(domains["D2"], 0.0)
        self.assertGreater(cov["coverage"], 0.0)
        self.assertLess(cov["coverage"], 1.0)
        self.assertTrue(any("D2" == item["domain"] for item in cov["uncovered"]))

    def test_report_export(self):
        r = runner.ScanRunner(self.cfg, self.store, adapters=[self.adapter])
        res = r.run_plan("p-manual", slot="R1", write_report=True)
        path = res["report"].get("path")
        self.assertTrue(path and pathlib.Path(path).is_file(), res["report"])
        html = pathlib.Path(path).read_text(encoding="utf-8")
        self.assertIn("漏洞扫描", html)
        self.assertIn("127.0.0.1", html)
        self.assertNotIn("<script", html.lower())

    # ------------------------------------------------------------------ 引擎消融/续跑
    def test_engine_ablation(self):
        class Unavailable:
            name = "nuclei"
            version = "x"
            cost = "slow"
            requires = ["nuclei"]

            def available(self) -> bool:
                return False

            def supports(self, asset, profile):
                return True

            def run(self, asset, ctx):
                raise AssertionError("不可用引擎不应被调用")

        sscan.upsert_plan(self.store, {"plan_id": "p-weekly", "kind": "manual",
                                      "profile": "weekly", "selector_json": {"group": "self"}})
        r = runner.ScanRunner(
            self.cfg, self.store,
            adapters=[self.adapter, Unavailable()],
        )
        res = r.run_plan("p-weekly", slot="A1")
        self.assertTrue(res["ok"])
        statuses = res["engine_status"]
        self.assertEqual(statuses["nuclei"]["skipped"], 1)
        # weekly 计划里 nmap 与 nuclei 都被选中，nuclei 不可用 → 任务 partial
        task = sscan.list_tasks(self.store, run_id=res["run_id"])[0]
        self.assertEqual(task["status"], "partial")

    def test_retry_requeues_failed(self):
        task, _ = sscan.create_task(self.store, {
            "plan_id": "p-manual", "asset_id": self.asset["asset_id"],
            "slot": "retry-1", "run_id": "run-x", "status": "failed",
        })
        rows = stask.retry(self.store, "run-x")
        self.assertEqual(len(rows), 1)
        self.assertEqual(sscan.get_task(self.store, task["task_id"])["status"], "queued")

    # ------------------------------------------------------------------ 扫描窗口门
    def test_scan_window_gate(self):
        gate = window.ScanWindowGate(self.store, self.cfg)
        # 手工造一条"进行中"的窗口事件（phase=start，无 end）
        ev = schema.new_event(
            "scan_window", "scan", "hornwork.scan", self.cfg,
            network={"src_ips": ["127.0.0.1"], "dst_ips": ["127.0.0.1"]},
            raw={"phase": "start", "run_id": "run-test", "plan_id": "p-manual",
                 "start": schema.utc_now(), "src_ips": ["127.0.0.1"],
                 "dst_ips": ["127.0.0.1"], "window_sec": 600},
        )
        self.store.insert_event(schema.normalize_event(ev, self.cfg))
        gate.refresh(force=True)
        self.assertTrue(gate.is_scan_traffic("127.0.0.1", "127.0.0.1"))
        self.assertTrue(gate.suppress("N-0101", "127.0.0.1", "127.0.0.1"))
        self.assertFalse(gate.suppress("N-0103", "127.0.0.1", "127.0.0.1"))  # IOC 规则不降级
        self.assertFalse(gate.is_scan_traffic("10.0.0.9", "127.0.0.1"))     # 非本机源
        # 结束事件后失效
        end = schema.new_event(
            "scan_window", "scan", "hornwork.scan", self.cfg,
            raw={"phase": "end", "run_id": "run-test", "plan_id": "p-manual",
                 "start": schema.utc_now(), "end": schema.utc_now(),
                 "src_ips": ["127.0.0.1"], "dst_ips": ["127.0.0.1"], "window_sec": 600},
        )
        self.store.insert_event(schema.normalize_event(end, self.cfg))
        gate.refresh(force=True)
        self.assertFalse(gate.is_scan_traffic("127.0.0.1", "127.0.0.1"))

    # ------------------------------------------------------------------ 归一细节
    def test_normalize_finding_key_stable(self):
        key1 = sscan.finding_key("ast-1", "cve", "CVE-2021-43798", "ast-1:grafana")
        key2 = sscan.finding_key("ast-1", "cve", "CVE-2021-43798", "ast-1:grafana")
        self.assertEqual(key1, key2)
        self.assertNotEqual(key1, sscan.finding_key("ast-1", "cve", "CVE-2021-43798", "ast-2:grafana"))
        raw = normalize.cve_to_findings(
            [{"cve_id": "CVE-2021-43798", "comp_norm": "grafana", "detected_version": "8.2.6",
              "confidence": "range", "severity": "高", "cvss": 7.5, "cvss_source": "nvd",
              "evidence": {"interval": {"end_excl": "8.2.7"}}}],
            asset_id="ast-1", task_id="t1",
        )
        self.assertEqual(raw[0]["kind"], "cve")
        self.assertEqual(raw[0]["check_id"], "CVE-2021-43798")
        self.assertEqual(raw[0]["confidence"], "range")


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
