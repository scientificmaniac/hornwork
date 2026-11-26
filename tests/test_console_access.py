"""Web 控制台访问审计与多用户模型 —— 等价性测试（E1–E16）。

等价性 = 同一安全语义经不同路径/不同实现，必须产生可比对的一致结果。
每个联动点（状态机 / 会话 / 审计链 / 多用户）都有对偶断言。

注意：测试产物统一写 tests/_tmp（DSH 沙箱约束）；Windows 全绿是硬门槛。
"""

from __future__ import annotations

import json
import math
import shutil
import sys
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

TMP_ROOT = Path(__file__).resolve().parent / "_tmp"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hornwork.auth import audit, biometric, crypto, db, policy, risk, session, totp  # noqa: E402
from hornwork.auth.engine import AuthEngine  # noqa: E402
from hornwork.config import load_config  # noqa: E402
from hornwork.web import WebServer  # noqa: E402


def _mktemp(prefix: str) -> Path:
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = TMP_ROOT / f"{prefix}-{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _vec(seed: float = 0.0) -> list[float]:
    raw = [math.sin(i * 0.11 + seed) + 0.3 * math.cos(i * 0.037 + seed) for i in range(512)]
    return biometric.l2_normalize(raw)


class ConsoleAccessBase(unittest.TestCase):
    """三角色固定夹具：viewer / operator / admin，全部注册 TOTP + 人脸。"""

    PASSWORD = "Str0ng-Passw0rd-2026"

    def setUp(self) -> None:
        self.tmp = _mktemp("console")
        self.cfg = load_config(None)
        self.cfg["general"]["data_dir"] = str(self.tmp)
        self.cfg["auth"]["db_path"] = str(self.tmp / "hornwork.db")
        self.cfg["auth"]["key_path"] = str(self.tmp / "auth.key")
        self.cfg["auth"]["pepper_path"] = str(self.tmp / "auth.pepper")
        self.keys = crypto.KeyRing.from_config(self.cfg, create=True)
        self.store = db.open_auth_store(self.cfg)
        self.eng = AuthEngine(self.cfg, self.store, self.keys)
        db.set_policy(self.store, "argon2.params",
                      {"m": 8192, "t": 1, "p": 1, "hash_len": 32, "salt_len": 16})
        self.eng.reload_policy()
        self.users: dict[str, dict] = {}
        self.secrets: dict[str, bytes] = {}
        self._make_users()

    def tearDown(self) -> None:
        try:
            self.store.close()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_users(self) -> None:
        # 首个账号自动 admin；后续显式创建并设角色
        for name, role in (("alice", "admin"), ("bob", "operator"), ("carol", "viewer")):
            is_admin = (role == "admin")
            self.eng.create_user(name, self.PASSWORD, admin=is_admin)
            info = self.eng.enroll_totp(name)
            secret = totp.from_b32(info["secret_b32"])
            self.assertTrue(self.eng.confirm_totp(name, totp.totp(secret))[0])
            self.eng.enroll_biometric(name, _vec(0.3))
            self.secrets[name] = secret
            if not is_admin:
                self.eng.set_role(name, role)
            self.users[name] = self.eng.get_user(name)

    def _login(self, name: str, *, loa3: bool = False, ua: str | None = None,
               ip: str | None = None) -> dict:
        kwargs = {"ua": ua, "ip": ip}
        if loa3:
            # 强制 LOA3：用 IOC IP 命中触发风险评分升到 3
            self.store.execute(
                "INSERT OR REPLACE INTO ioc(ioc_id,type,value,confidence,whitelisted,status)"
                " VALUES('eq-ioc','ip','203.0.113.77',80,0,'active')")
            kwargs["ip"] = "203.0.113.77"
            return self.eng.login(name, self.PASSWORD,
                                  totp_code=totp.totp(self.secrets[name]),
                                  embedding=_vec(0.3), **kwargs)
        return self.eng.login_password_only(name, self.PASSWORD, **kwargs)


class EngineEquivalenceTest(ConsoleAccessBase):
    """E1–E3：状态机等价性。"""

    def test_e2_login_paths_produce_equivalent_loa(self) -> None:
        # 平台路径（无 TOTP）与三因子路径在相同输入下 LOA 语义一致
        r1 = self.eng.login_password_only("bob", self.PASSWORD, ip="10.0.0.5")
        r2 = self.eng.login("bob", self.PASSWORD, ip="10.0.0.5",
                            totp_code=totp.totp(self.secrets["bob"]))
        self.assertEqual(r1["status"], "ok", r1)
        self.assertEqual(r2["status"], "ok", r2)
        self.assertEqual(r1["loa"], 2)
        self.assertEqual(r2["loa"], 2)
        a1 = audit.tail(self.store, "bob", 1)[0]
        self.assertEqual(a1["event"], "logon")
        self.assertEqual(a1["loa"], 2)

    def test_e3_step_up_changes_decision_consistently(self) -> None:
        # 稳定的 LOA2 会话：避开 02:00-06:00 UTC 的 unusual_time 窗口
        now = time.time()
        from datetime import datetime, timezone
        if datetime.fromtimestamp(now, timezone.utc).hour in (2, 3, 4, 5):
            now = datetime.fromtimestamp(now, timezone.utc).replace(
                hour=6, minute=1, second=0, microsecond=0).timestamp()
        res = self.eng.login_password_only("bob", self.PASSWORD, now=now)
        token = res["token"]
        before = self.eng.require_action(token, "write")
        self.assertEqual(before["decision"], "stepup_required")
        self.assertEqual(before["reason"], "loa_too_low")
        # 直接读会话行算 policy.step_up_required，必须也是 step-up
        row = self.eng.session_row(token)
        self.assertEqual(policy.step_up_required(row, "write"), True)
        # step-up 后决策翻转
        up = self.eng.step_up(token, totp.totp(self.secrets["bob"], at=now + 30),
                              embedding=_vec(0.3), now=now + 30)
        self.assertEqual(up["status"], "ok", up)
        after = self.eng.require_action(token, "write")
        self.assertEqual(after["decision"], "allow")
        self.assertEqual(policy.step_up_required(self.eng.session_row(token), "write"), False)


class SessionEquivalenceTest(ConsoleAccessBase):
    """E4–E6：会话等价性。"""

    def test_e4_ua_binding_symmetric(self) -> None:
        ua = "Mozilla/5.0 (TestAgent)"
        issued = session.issue(self.store, self.keys, int(self.users["carol"]["id"]), 2,
                               ua=ua, policy={})
        row = self.store.query_one("SELECT ua_hash FROM auth_session WHERE session_id=?",
                                   (issued["session_id"],))
        self.assertTrue(row["ua_hash"])
        # 正确 UA：底层 verify 通过
        session.verify(self.store, self.keys, issued["token"], ua=ua)
        # 错误 UA：底层 verify 抛 ua_mismatch；引擎 authorize 也 deny
        with self.assertRaises(session.SessionError) as ctx:
            session.verify(self.store, self.keys, issued["token"], ua="EvilBot")
        self.assertEqual(ctx.exception.reason, "ua_mismatch")
        decision = self.eng.authorize(issued["token"], "read",
                                      role="viewer", ua="EvilBot")
        self.assertEqual(decision["decision"], "deny")
        self.assertEqual(decision["reason"], "ua_mismatch")

    def test_e5_revoked_session_three_layers_agree(self) -> None:
        token = self._login("carol")["token"]
        self.assertTrue(self.eng.logout(token))
        with self.assertRaises(session.SessionError) as ctx:
            session.verify(self.store, self.keys, token)
        self.assertEqual(ctx.exception.reason, "revoked")
        d = self.eng.require_action(token, "read")
        self.assertEqual(d["decision"], "deny")
        self.assertEqual(d["reason"], "revoked")
        d2 = self.eng.authorize(token, "read", role="viewer")
        self.assertEqual(d2["reason"], "revoked")

    def test_e6_ip_drift_risk_recompute(self) -> None:
        # 会话 IP 10.0.0.5，请求 IP 命中 IOC → 风险分应一致
        token = self._login("bob", ip="10.0.0.5")["token"]
        self.store.execute(
            "INSERT OR REPLACE INTO ioc(ioc_id,type,value,confidence,whitelisted,status)"
            " VALUES('drift-ioc','ip','203.0.113.99',80,0,'active')")
        direct = risk.score(self.store, self.eng.get_user("bob"), ip="203.0.113.99")
        decision = self.eng.authorize(token, "write", role="operator",
                                      request_ip="203.0.113.99")
        self.assertIsNotNone(decision["risk"])
        self.assertEqual(decision["risk"]["score"], direct["score"])
        self.assertEqual(decision["decision"], "stepup_required")
        self.assertEqual(decision["reason"], "session_ip_drift")


class AuditEquivalenceTest(ConsoleAccessBase):
    """E7–E10：审计链等价性。"""

    def test_e7_chain_ok_and_tamper_detected(self) -> None:
        for i in range(20):
            audit.append(self.store, event="console_access", result="ok",
                         username="probe", factor="read", detail=f"i={i}")
        ok = audit.verify_chain(self.store)
        self.assertTrue(ok["ok"], ok)
        # fixture 建号/登录已产生若干身份审计，这里只断言新增的 20 条都在链上
        n = self.store.query_one(
            "SELECT COUNT(*) AS n FROM auth_audit WHERE event='console_access'")["n"]
        self.assertEqual(n, 20)
        self.assertGreaterEqual(ok["checked"], 20)
        row = self.store.query_one("SELECT id FROM auth_audit WHERE event='console_access' LIMIT 1")
        self.store.execute("UPDATE auth_audit SET detail='tampered' WHERE id=?", (row["id"],))
        self.assertFalse(audit.verify_chain(self.store)["ok"])

    def test_e8_audit_fields_match_decision(self) -> None:
        token = self._login("carol")["token"]
        dec = self.eng.authorize(token, "read", role="viewer")
        audit.append(self.store, event="console_access", result=dec["decision"],
                     username="carol", user_id=int(self.users["carol"]["id"]),
                     factor=dec["action"], loa=dec["loa"],
                     detail=json.dumps({"decision": dec["decision"], "reason": dec["reason"]}))
        row = audit.tail(self.store, "carol", 1)[0]
        self.assertEqual(row["event"], "console_access")
        self.assertEqual(row["factor"], "read")
        self.assertEqual(json.loads(row["detail"])["decision"], dec["decision"])

    def test_e15_access_audit_does_not_pollute_last_logon(self) -> None:
        # console_access 不得被 risk.last_logon() 当成登录
        self._login("bob", ip="10.0.0.5")
        before = risk.last_logon(self.store, int(self.users["bob"]["id"]))
        self.assertIsNotNone(before)
        for i in range(10):
            audit.append(self.store, event="console_access", result="ok",
                         username="bob", user_id=int(self.users["bob"]["id"]),
                         ip="203.0.113.66", detail=f"access-{i}")
        after = risk.last_logon(self.store, int(self.users["bob"]["id"]))
        self.assertEqual(after["id"], before["id"],
                         "console_access 污染了 last_logon，会破坏 ip_change 风险信号")


class MultiUserEquivalenceTest(ConsoleAccessBase):
    """E11–E13：多用户等价性。"""

    def test_e11_role_matrix_three_layers(self) -> None:
        matrix = [("viewer", "read", True), ("viewer", "write", False),
                  ("operator", "write", True), ("operator", "admin", False),
                  ("admin", "admin", True)]
        for role, action, expected in matrix:
            self.assertEqual(policy.role_allows(role, action), expected, (role, action))
            user = {"alice": self.users["alice"], "bob": self.users["bob"],
                    "carol": self.users["carol"]}[
                        {"admin": "alice", "operator": "bob", "viewer": "carol"}[role]]
            token = self._login(user["username"])["token"]
            dec = self.eng.require_action(token, action)
            if expected:
                self.assertNotEqual(dec["reason"], "role_denied", (role, action, dec))
            else:
                self.assertEqual(dec["reason"], "role_denied", (role, action, dec))

    def test_e12_two_sessions_logout_and_password_change(self) -> None:
        a = self._login("bob")["token"]
        b = self._login("bob")["token"]
        self.assertTrue(self.eng.logout(a))
        self.assertEqual(self.eng.require_action(a, "read")["decision"], "deny")
        self.assertEqual(self.eng.require_action(b, "read")["decision"], "allow")
        self.eng.set_password("bob", "N3w-Str0ng-Passw0rd!", old_password=self.PASSWORD)
        self.assertEqual(self.eng.require_action(b, "read")["decision"], "deny")


class WebMiddlewareTest(ConsoleAccessBase):
    """E1/E13/E16：Web 层端到端授权（403 vs 401 映射 + console_access 落库）。"""

    def setUp(self) -> None:
        super().setUp()
        self.cfg["web"]["enabled"] = True
        self.cfg["web"]["bind"] = "127.0.0.1"
        self.cfg["web"]["port"] = 0
        self.cfg["web"]["token"] = ""
        # 注入测试夹具的引擎：确保 Web 层与登录签发用同一把 keyring，
        # 消除"Web 自行从 cfg 构造引擎"带来的密钥来源歧义。
        self.server = WebServer(self.cfg, self.store, auth_engine=self.eng)
        self.server.start()

    def tearDown(self) -> None:
        try:
            self.server.stop()
        finally:
            super().tearDown()

    def _base(self) -> str:
        st = self.server.status()
        return f"http://{st['bind']}:{st['port']}"

    def _get(self, path: str, token: str | None = None,
             ua: str | None = "Python-urllib") -> tuple[int, dict]:
        req = urllib.request.Request(self._base() + path)
        # 每个请求显式关闭连接：避免 urllib 复用上一测试的 keep-alive 连接
        # （端口随机回收时可能命中已销毁实例的旧 socket，造成跨测试串扰）
        req.add_header("Connection", "close")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        if ua:
            req.add_header("User-Agent", ua)
        # 每次新建 opener：urllib 的全局 opener 会缓存 keep-alive 连接，
        # 随机端口回收后可能复用上一测试的旧 socket（跨实例 token → bad_mac）。
        opener = urllib.request.build_opener(urllib.request.HTTPHandler)
        try:
            with opener.open(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8")
            try:
                return exc.code, json.loads(body)
            except ValueError:
                return exc.code, {"raw": body}

    def test_e13_admin_route_role_gate(self) -> None:
        # viewer 会话访问管理接口 → 403（不是 401）
        viewer_token = self._login("carol")["token"]
        status, body = self._get("/api/auth/users", token=viewer_token)
        self.assertEqual(status, 403, body)
        detail = json.loads(body["detail"]) if isinstance(body.get("detail"), str) else body
        self.assertEqual(detail.get("reason"), "role_denied")
        # admin 路由需要 LOA3 + 强认证窗口：用三因子登录签发 LOA3 会话
        admin_login = self._login("alice", loa3=True)
        self.assertEqual(admin_login["loa"], 3, admin_login)
        admin_token = admin_login["token"]
        status, body = self._get("/api/auth/users", token=admin_token)
        self.assertEqual(status, 200, body)

    def test_e1_engine_decision_matches_http(self) -> None:
        token = self._login("carol")["token"]
        # 引擎判定
        eng_dec = self.eng.authorize(token, "read")
        self.assertEqual(eng_dec["decision"], "allow")
        # HTTP 判定：同一 token 同一 UA 必须放行（登录时 UA 是默认 Python-urllib）
        status, body = self._get("/api/overview", token=token)
        self.assertEqual(status, 200, body)
        # 审计行与决策一致
        row = audit.tail(self.store, "carol", 1)[0]
        self.assertEqual(row["event"], "console_access")
        self.assertEqual(row["factor"], "read")
        self.assertEqual(json.loads(row["detail"])["decision"], "allow")

    def test_e16_token_failure_is_401(self) -> None:
        status, body = self._get("/api/overview", token="s1.fake.token")
        self.assertEqual(status, 401, body)

    def test_e4_ua_mismatch_over_http_is_401(self) -> None:
        token = self._login("carol", ua="LegitAgent")["token"]
        status, body = self._get("/api/overview", token=token, ua="EvilAgent")
        self.assertEqual(status, 401, body)
        status, body = self._get("/api/overview", token=token, ua="LegitAgent")
        self.assertEqual(status, 200, body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
