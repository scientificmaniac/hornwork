"""认证模块单元测试：口令 / TOTP / 会话 / 人脸模板保护 / 风险 / 限流 / 审计链 / 状态机。

运行：`/opt/hornwork-venv/bin/python -m unittest tests.test_auth -v`
（测试产物放 tests/_tmp，不写系统临时目录）
"""

from __future__ import annotations

import json
import math
import shutil
import struct
import sys
import time
import unittest
import uuid
from pathlib import Path

_TMP_ROOT = Path(__file__).resolve().parent / "_tmp"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.exceptions import InvalidTag  # noqa: E402

from hornwork.auth import audit, biometric, crypto, db, password, risk, session, totp  # noqa: E402
from hornwork.auth.engine import AuthEngine  # noqa: E402
from hornwork.config import load_config  # noqa: E402


def _mktemp(prefix: str) -> Path:
    _TMP_ROOT.mkdir(parents=True, exist_ok=True)
    path = _TMP_ROOT / f"{prefix}-{uuid.uuid4().hex[:8]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _vec(seed: float = 0.0) -> list[float]:
    raw = [math.sin(i * 0.11 + seed) + 0.3 * math.cos(i * 0.037 + seed) for i in range(512)]
    return biometric.l2_normalize(raw)


class AuthTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = _mktemp("auth")
        self.cfg = load_config(None)
        self.cfg["general"]["data_dir"] = str(self.tmp)
        self.cfg["auth"]["db_path"] = str(self.tmp / "hornwork.db")
        self.cfg["auth"]["key_path"] = str(self.tmp / "auth.key")
        self.cfg["auth"]["pepper_path"] = str(self.tmp / "auth.pepper")
        self.keys = crypto.KeyRing.from_config(self.cfg, create=True)
        self.store = db.open_auth_store(self.cfg)
        self.eng = AuthEngine(self.cfg, self.store, self.keys)
        # 测试用低参数 Argon2id（生产默认 64 MB/t=3），避免单测跑几十秒
        db.set_policy(self.store, "argon2.params",
                      {"m": 8192, "t": 1, "p": 1, "hash_len": 32, "salt_len": 16})
        self.eng.reload_policy()

    def tearDown(self) -> None:
        try:
            self.store.close()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    # 便捷夹具
    def make_user(self, username: str = "alice", user_password: str = "Str0ng-Passw0rd-2026",
                  with_totp: bool = True, with_bio: bool = False,
                  embedding: list[float] | None = None):
        self.eng.create_user(username, user_password)
        secret = None
        if with_totp:
            info = self.eng.enroll_totp(username)
            secret = totp.from_b32(info["secret_b32"])
            ok, reason = self.eng.confirm_totp(username, totp.totp(secret))
            self.assertTrue(ok, reason)
        if with_bio:
            self.eng.enroll_biometric(username, embedding or _vec())
        return self.eng.get_user(username), secret


class PasswordTest(AuthTestBase):
    def test_phc_roundtrip_and_pepper(self):
        params = password.ar2params({"m": 8192, "t": 1, "p": 1})
        phc, algo = password.hash_password("correct horse battery", self.keys.pepper, params,
                                           salt=b"0123456789abcdef")
        self.assertEqual(algo, "argon2id")
        self.assertTrue(phc.startswith("$argon2id$v=19$m=8192,t=1,p=1$"))
        parsed = password.parse_phc(phc)
        self.assertEqual(parsed["salt"], b"0123456789abcdef")
        self.assertTrue(password.verify_argon2("correct horse battery", phc, self.keys.pepper))
        self.assertFalse(password.verify_argon2("wrong", phc, self.keys.pepper))
        # pepper 不同 → 同一口令/盐也得不到同一哈希
        other = crypto.KeyRing(self.keys.master, b"\x01" * 32)
        self.assertFalse(password.verify_argon2("correct horse battery", phc, other.pepper))

    def test_strength_policy(self):
        pol = {"min_len": 12, "admin_min_len": 16, "max_len": 128}
        self.assertFalse(password.check_strength("short", "alice", pol)[0])
        self.assertFalse(password.check_strength("alice-is-my-password", "alice", pol)[0])
        self.assertFalse(password.check_strength("password123", "bob", pol)[0])
        self.assertFalse(password.check_strength("123456789012", "bob", pol)[0])
        self.assertTrue(password.check_strength("Tr0ub4dor&3x", "bob", pol)[0])
        self.assertFalse(password.check_strength("Admin-Passw0rd!", "root", pol, admin=True)[0])
        self.assertTrue(password.check_strength("Admin-Passw0rd!2026", "root", pol,
                                                admin=True)[0])

    def test_legacy_md5_login_migrates(self):
        import hashlib

        self.make_user("legacy", with_totp=False)
        user = self.eng.get_user("legacy")
        md5_hex = hashlib.md5("OldStylePassw0rd!".encode()).hexdigest()
        self.store.execute("UPDATE auth_user SET password_hash=?, password_algo='md5'"
                           " WHERE id=?", (f"md5${md5_hex}", int(user["id"])))
        self.assertEqual(password.detect_algo(f"md5${md5_hex}"), "md5")
        # 没有 TOTP → 口令通过后提示先注册第二因子，但迁移已发生
        res = self.eng.start_login("legacy", "OldStylePassw0rd!")
        self.assertEqual(res["status"], "enroll_required")
        user = self.eng.get_user("legacy")
        self.assertEqual(user["password_algo"], "argon2id")
        self.assertTrue(str(user["password_hash"]).startswith("$argon2id$"))
        self.assertTrue(audit.tail(self.store, "legacy", 10))
        events = [r["event"] for r in audit.tail(self.store, "legacy", 20)]
        self.assertIn("rehash", events)


class TotpTest(AuthTestBase):
    # RFC 4226 附录 D：密钥 = ASCII "12345678901234567890"
    HOTP_VECTORS = ["755224", "287082", "359152", "969429", "338314",
                    "254676", "287922", "162583", "399871", "520489"]
    # RFC 6238 附录 B（SHA1，8 位）
    TOTP_VECTORS = [(59, "94287082"), (1111111109, "07081804"),
                    (1111111111, "14050471"), (1234567890, "89005924"),
                    (2000000000, "69279037"), (20000000000, "65353130")]

    def test_rfc4226_vectors(self):
        secret = b"12345678901234567890"
        for counter, expect in enumerate(self.HOTP_VECTORS):
            self.assertEqual(totp.hotp(secret, counter), expect, f"counter={counter}")

    def test_rfc6238_vectors(self):
        secret = b"12345678901234567890"
        for at, expect in self.TOTP_VECTORS:
            self.assertEqual(totp.hotp(secret, totp.counter_at(at), digits=8), expect)

    def test_window_replay_and_encrypted_secret(self):
        user, _ = self.make_user("zoe", with_totp=False)
        uid = int(user["id"])
        info = totp.enroll(self.store, self.keys, uid, "zoe")
        secret = totp.from_b32(info["secret_b32"])
        self.assertTrue(totp.confirm(self.store, self.keys, uid, totp.totp(secret))[0])
        base = time.time()
        code = totp.totp(secret, at=base)
        ok, reason, counter = totp.verify_user(self.store, self.keys, uid, code,
                                               at=base)
        self.assertTrue(ok, reason)
        # 同一码第二次 = 重放
        ok2, reason2, _ = totp.verify_user(self.store, self.keys, uid, code, at=base)
        self.assertFalse(ok2)
        self.assertIn("已使用", reason2)
        # 下一时间步的码可继续用（counter 单调）
        ok3, _, counter3 = totp.verify_user(self.store, self.keys, uid,
                                            totp.totp(secret, at=base + 30), at=base + 30)
        self.assertTrue(ok3)
        self.assertGreater(counter3, counter)
        # 库里不是明文：密钥密文 != 明文，DB 文件搜不到 Base32/原始字节
        row = self.store.query_one("SELECT secret_enc, nonce FROM auth_credential")
        self.assertNotEqual(bytes(row["secret_enc"]), secret)
        blob = Path(self.store.path).read_bytes()
        self.assertNotIn(totp.to_b32(secret).encode(), blob)
        self.assertNotIn(secret, blob)
        # AAD 绑 user_id：换用户解不开
        with self.assertRaises(InvalidTag):
            totp._open_secret(self.keys, 999, dict(row, key_id=1))


class SessionTest(AuthTestBase):
    def test_issue_verify_tamper_revoke(self):
        user, _secret = self.make_user("bob", with_totp=False)
        now = time.time()
        issued = session.issue(self.store, self.keys, int(user["id"]), 2,
                               ip="10.0.0.9", policy={}, now=now)
        row = session.verify(self.store, self.keys, issued["token"], now=now + 5)
        self.assertEqual(int(row["user_id"]), int(user["id"]))
        # 篡改
        bad = issued["token"][:-4] + ("AAAA" if not issued["token"].endswith("AAAA") else "BBBB")
        with self.assertRaises(session.SessionError):
            session.verify(self.store, self.keys, bad, now=now + 5)
        # 登出即失效
        self.assertTrue(session.revoke_token(self.store, self.keys, issued["token"], "logout"))
        with self.assertRaises(session.SessionError):
            session.verify(self.store, self.keys, issued["token"], now=now + 6)

    def test_idle_and_absolute_expiry(self):
        user, _ = self.make_user("carol", with_totp=False)
        now = time.time()
        issued = session.issue(self.store, self.keys, int(user["id"]), 2,
                               policy={"loa2": {"idle": 10, "absolute": 60}}, now=now)
        with self.assertRaises(session.SessionError):
            session.verify(self.store, self.keys, issued["token"], now=now + 11)
        issued = session.issue(self.store, self.keys, int(user["id"]), 2,
                               policy={"loa2": {"idle": 10, "absolute": 60}}, now=now)
        with self.assertRaises(session.SessionError):
            session.verify(self.store, self.keys, issued["token"], now=now + 61)

    def test_device_token(self):
        user, _ = self.make_user("dave", with_totp=False)
        res = session.trust_device(self.store, self.keys, int(user["id"]), "laptop")
        dev = session.verify_device(self.keys, res["device_token"])
        self.assertEqual(dev, (res["device_id"], int(user["id"])))
        self.assertTrue(session.device_is_trusted(self.store, int(user["id"]),
                                                  res["device_id"]))
        self.assertIsNone(session.verify_device(self.keys, "d1.broken"))


class BiometricTest(AuthTestBase):
    def test_transform_preserves_inner_product_and_is_revocable(self):
        seed = crypto.KeyRing.from_config(self.cfg).derive(b"auth|bio|seed|42", 32)
        a, b = _vec(0.0), _vec(0.1)
        ta, tb = biometric.transform(a, seed), biometric.transform(b, seed)
        self.assertAlmostEqual(biometric.cosine(a, b), biometric.cosine(ta, tb), places=6)
        # 逆变换可还原（证明正交、也说明"变换本身可逆，机密性靠 AEAD"）
        back = biometric.inverse_transform(ta, seed)
        for x, y in zip(back[:8], a[:8]):
            self.assertAlmostEqual(x, y, places=6)
        # 换种子 = 撤销（旧模板与新变换不可比）
        seed2 = crypto.KeyRing.from_config(self.cfg).derive(b"auth|bio|seed|99", 32)
        self.assertNotAlmostEqual(biometric.cosine(ta, biometric.transform(a, seed2)),
                                  1.0, places=3)

    def test_enroll_verify_delete(self):
        user, _ = self.make_user("erin", with_totp=False)
        uid = int(user["id"])
        res = self.eng.enroll_biometric("erin", _vec(0.2), quality=0.9)
        self.assertGreater(res["ciphertext_bytes"], 512 * 4)
        row = self.store.query_one("SELECT * FROM bio_template WHERE user_id=?", (uid,))
        plain = struct.pack(f"<{row['dim']}f", *biometric.l2_normalize(_vec(0.2)))
        self.assertNotIn(plain, bytes(row["tmpl_enc"]))
        self.assertNotIn(plain[:64], Path(self.store.path).read_bytes())
        # 同人加噪 → 通过；异人 → 拒绝
        ok, sim, reason = biometric.verify(self.store, self.keys, uid,
                                           biometric.noise_variant(_vec(0.2)),
                                           {"threshold": 0.35})
        self.assertTrue(ok, f"{sim} {reason}")
        ok2, sim2, _ = biometric.verify(self.store, self.keys, uid, _vec(5.0),
                                        {"threshold": 0.35})
        self.assertFalse(ok2, f"{sim2}")
        # AAD 不符（换 model_ver）→ 解不开
        with self.assertRaises(InvalidTag):
            biometric.decrypt_template(self.keys, uid, row, model_ver="other-model")
        self.assertEqual(self.eng.delete_biometric("erin"), 1)
        self.assertFalse(biometric.has_template(self.store, uid))

    def test_quality_gate(self):
        self.make_user("frank", with_totp=False)
        with self.assertRaises(ValueError):
            self.eng.enroll_biometric("frank", _vec(), quality=0.1)


class RiskAndRateLimitTest(AuthTestBase):
    def test_ioc_and_known_device(self):
        user, _ = self.make_user("gina", with_totp=False)
        self.store.execute(
            "INSERT OR REPLACE INTO ioc(ioc_id, type, value, confidence, whitelisted, status)"
            " VALUES('ioc-test','ip','203.0.113.7',80,0,'active')")
        res = risk.score(self.store, user, ip="203.0.113.7", device_id=None)
        self.assertIn("IP命中IOC+30", res["why"])
        self.assertGreaterEqual(res["score"], 30)
        self.assertEqual(res["required_loa"], 3)
        dev = session.trust_device(self.store, self.keys, int(user["id"]), "known")
        res2 = risk.score(self.store, user, ip="10.1.2.3", device_id=dev["device_id"])
        self.assertIn("已知设备-20", res2["why"])
        self.assertLess(res2["score"], 30)
        self.assertEqual(res2["required_loa"], 2)

    def test_lockout_after_failures(self):
        user, _ = self.make_user("henry", with_totp=False)
        for _ in range(5):
            res = self.eng.start_login("henry", "wrong-password-123")
            self.assertEqual(res["status"], "fail")
        user = self.eng.get_user("henry")
        self.assertIsNotNone(user["locked_until"])
        # 锁定期间即使口令正确也拒绝（只回统一错误码）
        res = self.eng.start_login("henry", "Str0ng-Passw0rd-2026")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["error"], "invalid_credentials")
        self.assertTrue(self.eng.unlock_user("henry"))
        self.assertIsNone(self.eng.get_user("henry")["locked_until"])

    def test_unknown_user_generic_error_and_audit(self):
        res = self.eng.start_login("nobody", "whatever-password", ip="10.9.9.9")
        self.assertEqual(res["error"], "invalid_credentials")
        row = self.store.query_one(
            "SELECT * FROM auth_audit WHERE username='nobody' ORDER BY id DESC LIMIT 1")
        self.assertEqual(row["detail"], "unknown_user")

    def test_ip_rate_limit(self):
        self.make_user("iris", with_totp=False)
        statuses = []
        for _ in range(23):
            statuses.append(self.eng.start_login("iris", "x", ip="198.51.100.9")["status"])
        self.assertIn("rate_limited", statuses)


class EngineLoginTest(AuthTestBase):
    PASSWORD = "Str0ng-Passw0rd-2026"

    def _force_loa3(self):
        db.set_policy(self.store, "risk.weights", {
            "new_device": 30, "ip_change": 15, "ioc_ip": 30, "fail_each": 10,
            "fail_cap": 30, "unusual_time": 10, "totp_fail": 15,
            "known_device": -20, "session_ip_drift": 25})
        self.eng.reload_policy()

    def test_two_factor_login_and_event(self):
        user, secret = self.make_user("judy")
        res = self.eng.login("judy", self.PASSWORD, ip="10.0.0.5",
                             totp_code=totp.totp(secret))
        self.assertEqual(res["status"], "ok", res)
        self.assertEqual(res["loa"], 2)
        self.assertEqual(res["factors"], ["pw", "totp"])
        info = self.eng.session_info(res["token"])
        self.assertEqual(int(info["session"]["loa"]), 2)
        # 检测模块 事件表能看到 logon（同一条事件模型，不新增总线）
        evs = self.store.query_events(event_type="logon", limit=10)
        self.assertTrue(evs)
        ev = evs[0]
        self.assertEqual(ev["source_product"], "hornwork-auth")
        self.assertEqual(ev["source_layer"], "host")
        self.assertEqual(ev["raw"]["auth"]["loa"], 2)
        self.assertIn("totp", ev["raw"]["auth"]["factors"])
        self.assertEqual(ev["user"]["name"], "judy")
        # 审计链完整
        self.assertTrue(audit.verify_chain(self.store)["ok"])

    def test_three_factor_login_requires_bio(self):
        self._force_loa3()
        user, secret = self.make_user("kate", with_bio=True, embedding=_vec(0.7))
        res = self.eng.login("kate", self.PASSWORD, ip="10.0.0.6",
                             totp_code=totp.totp(secret), embedding=_vec(0.7))
        self.assertEqual(res["status"], "ok", res)
        self.assertEqual(res["loa"], 3)
        self.assertEqual(res["factors"], ["pw", "totp", "bio"])
        self.assertFalse(res["degraded"])
        self.assertGreater(res["similarity"], 0.35)
        row = audit.tail(self.store, "kate", 1)[0]
        self.assertEqual(row["event"], "logon")
        self.assertEqual(row["loa"], 3)

    def test_biometric_failure_blocks_loa3(self):
        self._force_loa3()
        _user, secret = self.make_user("leo", with_bio=True, embedding=_vec(0.9))
        res = self.eng.login("leo", self.PASSWORD, ip="10.0.0.7",
                             totp_code=totp.totp(secret), embedding=_vec(3.3))
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["reason"], "below_threshold")

    def test_degraded_when_bio_not_enrolled(self):
        self._force_loa3()
        _user, secret = self.make_user("mia", with_bio=False)
        res = self.eng.login("mia", self.PASSWORD, ip="10.0.0.8",
                             totp_code=totp.totp(secret))
        self.assertEqual(res["status"], "ok", res)
        self.assertEqual(res["loa"], 2)
        self.assertTrue(res["degraded"])
        self.assertEqual(res["degrade_reason"], "bio_not_enrolled")
        evs = self.store.query_events(event_type="logon", limit=5)
        self.assertTrue(evs[0]["raw"]["auth"]["degraded"])

    def test_totp_replay_rejected_and_audited(self):
        _user, secret = self.make_user("nina")
        code = totp.totp(secret)
        first = self.eng.login("nina", self.PASSWORD, totp_code=code)
        self.assertEqual(first["status"], "ok")
        second = self.eng.login("nina", self.PASSWORD, totp_code=code)
        self.assertEqual(second["status"], "fail")
        rows = audit.tail(self.store, "nina", 5)
        self.assertTrue(any(r["factor"] == "totp" and r["result"] == "fail" for r in rows))
        fails = self.store.query_events(event_type="logon_fail", limit=5)
        self.assertTrue(fails)

    def test_wrong_password_generic(self):
        self.make_user("olga")
        res = self.eng.start_login("olga", "not-the-password")
        self.assertEqual(res["status"], "fail")
        self.assertEqual(res["error"], "invalid_credentials")
        self.assertNotIn("口令", json.dumps(res, ensure_ascii=False))

    def test_session_step_up_and_action_guard(self):
        _user, secret = self.make_user("peter", with_bio=True, embedding=_vec(1.3))
        now = time.time()
        res = self.eng.login("peter", self.PASSWORD, totp_code=totp.totp(secret, at=now))
        self.assertEqual(res["status"], "ok", res)
        token = res["token"]
        # LOA2 会话：读允许，写要求 step-up
        self.assertEqual(self.eng.require_action(token, "read")["decision"], "allow")
        self.assertEqual(self.eng.require_action(token, "write")["decision"],
                         "stepup_required")
        # 缺人脸输入时不消费 TOTP
        r = self.eng.step_up(token, totp.totp(secret, at=now + 30))
        self.assertEqual(r["status"], "bio_required")
        r = self.eng.step_up(token, totp.totp(secret, at=now + 30), embedding=_vec(1.3))
        self.assertEqual(r["status"], "ok", r)
        self.assertEqual(self.eng.require_action(token, "write")["decision"], "allow")
        # 登出后旧令牌立即失效
        self.assertTrue(self.eng.logout(token))
        self.assertEqual(self.eng.require_action(token, "read")["decision"], "deny")

    def test_password_change_revokes_sessions(self):
        _user, secret = self.make_user("quinn")
        res = self.eng.login("quinn", self.PASSWORD, totp_code=totp.totp(secret))
        self.assertEqual(res["status"], "ok")
        self.eng.set_password("quinn", "N3w-Str0ng-Passw0rd!", old_password=self.PASSWORD)
        self.assertEqual(self.eng.require_action(res["token"], "read")["decision"], "deny")
        self.assertFalse(password.verify_password(
            self.PASSWORD, *self._stored("quinn"), self.keys.pepper,
            {"m": 8192, "t": 1, "p": 1, "hash_len": 32}))

    def _stored(self, username: str):
        row = self.eng.get_user(username)
        return row["password_hash"], row["password_algo"]

    def test_audit_chain_tamper_detected(self):
        self.make_user("rita")
        self.assertTrue(audit.verify_chain(self.store)["ok"])
        row = self.store.query_one("SELECT id FROM auth_audit ORDER BY id LIMIT 1")
        self.store.execute("UPDATE auth_audit SET detail='tampered' WHERE id=?", (row["id"],))
        res = audit.verify_chain(self.store)
        self.assertFalse(res["ok"])
        self.assertEqual(res["bad_id"], row["id"])


if __name__ == "__main__":
    unittest.main()
