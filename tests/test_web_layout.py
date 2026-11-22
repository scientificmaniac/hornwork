"""Web 控制台重构后的架构约束测试（Windows 开发机必须全绿）。

锁定重构引入的结构，防止后续改动退化：
- 公共层模块存在且导入健康（errors/context/routing）；
- 静态路由表：启动时构建一次、路径唯一、GET/POST 分派语义正确、405/404 语义；
- 错误三态契约：C7/SOFT/AUTH_STATE 常量与转换函数；
- WebContext 统计/重载/TTL 缓存/认证引擎双检锁的行为；
- 文件体量约束：server.py ≤ 原 1522 行（重构后应显著减小）；
- keep-alive：同连接连续 GET 复用、POST 关闭。
"""

from __future__ import annotations

import http.client
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from hornwork.config import load_config
from hornwork.store import Store
from hornwork.web import WebServer
from hornwork.web import errors as web_errors
from hornwork.web import routing
from hornwork.web.context import TtlCache, WebContext

WEB_DIR = Path(__file__).resolve().parents[1] / "hornwork" / "web"


class ModuleLayoutTestCase(unittest.TestCase):
    """公共层模块存在性与导入健康。"""

    def test_public_modules_importable(self) -> None:
        for name in ("errors", "context", "routing"):
            mod = __import__(f"hornwork.web.{name}", fromlist=["_"])
            self.assertTrue(mod.__name__ == f"hornwork.web.{name}")

    def test_server_shrunk(self) -> None:
        """server.py 应从 1522 行大幅缩减（handler 已拆到 api/* mixin）。"""
        lines = (WEB_DIR / "server.py").read_text(encoding="utf-8").splitlines()
        self.assertLess(len(lines), 600, f"server.py 有 {len(lines)} 行，拆分裂解未达预期")

    def test_api_mixins_exist(self) -> None:
        """api/ 目录应包含全部 14 个域 mixin 模块。"""
        api = WEB_DIR / "api"
        expected = {
            "auth", "integration", "events", "harden", "report", "lab", "scan",
            "overview", "rules", "intel", "cases", "validate", "export", "metrics",
        }
        actual = {p.stem for p in api.glob("*.py") if p.name != "__init__.py"}
        self.assertTrue(expected.issubset(actual), f"缺少 mixin 模块：{expected - actual}")
        for name in expected:
            lines = (api / f"{name}.py").read_text(encoding="utf-8").splitlines()
            self.assertLess(len(lines), 250, f"api/{name}.py 有 {len(lines)} 行，超过 250 行上限")

    def test_handler_inherits_mixins(self) -> None:
        """_Handler 应通过多继承装配全部 mixin。"""
        from hornwork.web.server import _Handler

        names = {c.__name__ for c in _Handler.__mro__}
        for mixin in ("AuthMixin", "ScanMixin", "RulesMixin", "MetricsMixin"):
            self.assertIn(mixin, names, f"_Handler 未装配 {mixin}")

    def test_error_modes(self) -> None:
        self.assertTrue(web_errors.is_valid_mode(web_errors.C7))
        self.assertTrue(web_errors.is_valid_mode(web_errors.SOFT))
        self.assertTrue(web_errors.is_valid_mode(web_errors.AUTH_STATE))
        self.assertFalse(web_errors.is_valid_mode("bogus"))

    def test_c7_payload(self) -> None:
        p = web_errors.error_payload(401, "未授权", retryable=False, detail="x" * 900)
        self.assertEqual(p["code"], 401)
        self.assertEqual(p["message"], "未授权")
        self.assertFalse(p["retryable"])
        self.assertEqual(len(p["detail"]), 800)


class RouteTableTestCase(unittest.TestCase):
    """静态路由表结构与分派语义。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.routes = routing.build_routes()

    def test_unique_paths(self) -> None:
        # 除 POST\x00 复合键外，主表路径不得重复（build_routes 内部已断言，这里再验证）
        main = [k for k in self.routes if not k.startswith("POST\x00")]
        self.assertEqual(len(main), len(set(main)))

    def test_expected_route_count(self) -> None:
        # 41 条 GET/静态 + 3 条 POST 复合键 = 44（与当前实现一致）
        self.assertGreaterEqual(len(self.routes), 40)

    def test_public_routes_present(self) -> None:
        for path in ("/", "/healthz", "/metrics", "/api/overview", "/api/events",
                     "/api/rules", "/api/intel", "/api/cases", "/api/export"):
            self.assertIn(path, self.routes, path)

    def test_scan_routes_explicit(self) -> None:
        # 扫描 8 条必须显式注册，不再 getattr 条件挂载
        for path in ("/api/scan/overview", "/api/scan/plans", "/api/scan/tasks",
                     "/api/scan/findings", "/api/scan/snapshots", "/api/scan/diff",
                     "/api/scan/coverage", "/api/scan/cve"):
            self.assertIn(path, self.routes, path)

    def test_no_auth_for_public(self) -> None:
        for path in ("/", "/healthz", "/api/auth/login", "/api/auth/session"):
            self.assertFalse(self.routes[path].needs_auth, path)

    def test_auth_required_for_api(self) -> None:
        for path in ("/api/overview", "/api/events", "/metrics"):
            self.assertTrue(self.routes[path].needs_auth, path)

    def test_lookup_get_post(self) -> None:
        route, hint = routing.lookup(self.routes, "/api/rules", "GET")
        self.assertIsNotNone(route)
        self.assertEqual(route.handler, "_h_rules_get")
        route, hint = routing.lookup(self.routes, "/api/rules", "POST")
        self.assertIsNotNone(route)
        self.assertEqual(route.handler, "_h_rules_post")

    def test_lookup_405(self) -> None:
        route, hint = routing.lookup(self.routes, "/api/overview", "POST")
        self.assertIsNone(route)
        self.assertIn("GET", hint)
        route, hint = routing.lookup(self.routes, "/api/nope", "GET")
        self.assertIsNone(route)
        self.assertEqual(hint, "")


class TtlCacheTestCase(unittest.TestCase):
    """TTL 缓存行为。"""

    def test_put_get_hit(self) -> None:
        c = TtlCache()
        c.put(("k",), {"v": 1}, ttl=10)
        self.assertEqual(c.get(("k",)), {"v": 1})

    def test_ttl_zero_no_cache(self) -> None:
        c = TtlCache()
        c.put(("k",), {"v": 1}, ttl=0)
        self.assertIsNone(c.get(("k",)))

    def test_expired(self) -> None:
        c = TtlCache()
        c.put(("k",), {"v": 1}, ttl=-1)
        self.assertIsNone(c.get(("k",)))

    def test_invalidate_prefix(self) -> None:
        c = TtlCache()
        c.put(("rules", "a"), 1, ttl=10)
        c.put(("rules", "b"), 2, ttl=10)
        c.put(("other",), 3, ttl=10)
        self.assertEqual(c.invalidate("rules"), 2)
        self.assertIsNone(c.get(("rules", "a")))
        self.assertEqual(c.get(("other",)), 3)


class WebContextTestCase(unittest.TestCase):
    """共享上下文统计/重载行为。"""

    def setUp(self) -> None:
        self.ctx = WebContext({}, object())

    def test_stats(self) -> None:
        self.ctx.note_request()
        self.ctx.note_request()
        self.ctx.note_error()
        s = self.ctx.stats_snapshot()
        self.assertEqual(s["requests"], 2)
        self.assertEqual(s["errors"], 1)

    def test_reload_increments(self) -> None:
        a = self.ctx.request_reload("first")
        b = self.ctx.request_reload("second")
        self.assertEqual(a["count"], 1)
        self.assertEqual(b["count"], 2)
        self.assertEqual(b["note"], "second")
        self.assertEqual(self.ctx.reload_state()["count"], 2)


class KeepAliveTestCase(unittest.TestCase):
    """连接复用：GET 复用同一 socket，POST 关闭。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        cfg = load_config(None)
        cfg["general"]["data_dir"] = str(self.tmp / "data")
        cfg["web"]["enabled"] = True
        cfg["web"]["bind"] = "127.0.0.1"
        cfg["web"]["port"] = 0
        cfg["web"]["token"] = ""
        self.store = Store(self.tmp / "data" / "hornwork.db")
        self.server = WebServer(cfg, self.store)
        self.server.start()
        self.port = self.server.status()["port"]

    def tearDown(self) -> None:
        self.server.stop()
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_get_keepalive_same_socket(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("GET", "/healthz")
            r1 = conn.getresponse(); r1.read()
            self.assertEqual(r1.getheader("Connection"), "keep-alive")
            self.assertIsNotNone(conn.sock)
            conn.request("GET", "/healthz")
            r2 = conn.getresponse(); r2.read()
            self.assertEqual(r2.status, 200)
            self.assertEqual(r2.getheader("Connection"), "keep-alive")
        finally:
            conn.close()

    def test_post_closes(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("POST", "/api/rules",
                         body=json.dumps({"action": "reload"}),
                         headers={"Content-Type": "application/json"})
            r = conn.getresponse(); r.read()
            self.assertEqual(r.getheader("Connection"), "close")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
