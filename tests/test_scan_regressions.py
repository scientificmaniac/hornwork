"""扫描子系统两个既有缺陷的回归测试。

这两个缺陷在 CLI 重构前就存在，重构过程中被发现，随后按用户要求**单独修复**。
本模块锁定修复结果，防止回退：

1. ``scan run --profile ... --check-only`` 的 ``--check-only`` 曾被静默丢弃 ——
   ``run_adhoc`` 没有该参数，导致本应"只做闸门与目标选择"的调用**真的执行扫描**。
2. 全新数据目录上，扫描子系统的只读入口会因表未创建而抛
   ``sqlite3.OperationalError: no such table``（退出码 1 + traceback）。

两个用例都在临时目录里自建库，不触碰系统数据目录，可跨平台运行。
"""

from __future__ import annotations

import inspect
import sqlite3
import tempfile
import unittest
from pathlib import Path

from hornwork.scan import store as scan_store
from hornwork.scan.runner import ScanRunner
from hornwork.store import Store


class RunAdhocCheckOnlyTest(unittest.TestCase):
    """缺陷 1：``run_adhoc`` 必须支持且真正尊重 ``check_only``。"""

    def test_run_adhoc_accepts_check_only(self):
        signature = inspect.signature(ScanRunner.run_adhoc)
        self.assertIn("check_only", signature.parameters)
        self.assertFalse(signature.parameters["check_only"].default)

    def test_check_only_creates_no_tasks_and_no_snapshot(self):
        """``check_only=True`` 时不得建任务、不得建快照。"""
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "probe.db")
            try:
                scan_store.init_schema(store)
                # 登记一个本机资产，让目标选择与闸门能通过
                scan_store.upsert_asset(store, {
                    "asset_id": "ast-self", "ip": "127.0.0.1", "role": "self",
                    "criticality": 3, "is_self": 1, "enabled": 1,
                })
                runner = ScanRunner({}, store)
                result = runner.run_adhoc(
                    profile_name="quick",
                    selector={},
                    force_window=True,
                    check_only=True,
                )
                # 关键断言：返回 would_scan 计划，而不是真的扫描
                self.assertTrue(result.get("ok"), result)
                self.assertIn("would_scan", result)
                self.assertNotIn("tasks", result)
                self.assertEqual(scan_store.list_tasks(store, limit=50), [])
                self.assertEqual(scan_store.list_snapshots(store, limit=10), [])
            finally:
                store.close()


class EmptyDatabaseReadTest(unittest.TestCase):
    """缺陷 2：全新库上扫描只读入口不得因缺表崩溃。"""

    def test_reads_work_on_brand_new_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            # 只建核心表（复用 Store 的构造），**不**调用 scan_store.init_schema
            store = Store(Path(tmp) / "fresh.db")
            try:
                # 以下调用在修复前都会抛 no such table
                self.assertEqual(scan_store.list_plans(store), [])
                self.assertEqual(scan_store.list_tasks(store), [])
                self.assertEqual(scan_store.list_findings(store), [])
                self.assertEqual(scan_store.list_snapshots(store), [])
                self.assertEqual(scan_store.list_assets(store), [])
                self.assertIsNone(scan_store.get_asset(store, "ast-none"))
                self.assertIsNone(scan_store.get_plan(store, "no-such-plan"))
                self.assertIsNone(scan_store.latest_snapshot(store))
                self.assertIsInstance(scan_store.scan_overview(store), dict)
                self.assertEqual(scan_store.cve_count(store), 0)
            finally:
                store.close()

    def test_ensure_schema_is_idempotent(self):
        """``ensure_schema`` 可重复调用，且第二次不重复执行 DDL。"""
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "idem.db")
            try:
                scan_store.ensure_schema(store)
                self.assertTrue(getattr(store, "_scan_schema_ensured", False))
                scan_store.ensure_schema(store)  # 不应抛异常
                self.assertTrue(getattr(store, "_scan_schema_ensured", False))
            finally:
                store.close()

    def test_missing_table_no_longer_leaks_sqlite_error(self):
        """修复前的失败形态是 sqlite3.OperationalError，这里显式断言它不再出现。"""
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "guard.db")
            try:
                try:
                    scan_store.list_plans(store)
                except sqlite3.OperationalError as exc:  # pragma: no cover - 修复后不应触发
                    self.fail(f"仍抛 OperationalError：{exc}")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
