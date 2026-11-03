"""认证状态机：口令 → 风险评分 → TOTP →（LOA3 时）人脸 → 会话签发。

三因子是**串行编排**而不是并列"三选二"：
- 口令失败直接返回统一错误，不泄露"下一步要动态码"；
- 风险评分在口令通过后计算，决定"要几个因子"（LOA2 / LOA3）；
- 人脸不可用（未注册/服务不可用）时显式降级为 LOA2，并在审计与事件里标 degraded；
- 会话只在所需因子全部通过后签发，中间态用 120 s 的 challenge 承载。
"""

from __future__ import annotations

import re
import secrets
import time
from typing import Any

from . import audit, biometric, crypto, db, password, policy, ratelimit, risk, session, totp

USERNAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,31}$")
GENERIC_ERROR = "invalid_credentials"


class AuthEngine:
    def __init__(self, cfg: dict, store=None, keyring: crypto.KeyRing | None = None):
        self.cfg = cfg
        self.store = store or db.open_auth_store(cfg)
        self.keys = keyring or crypto.KeyRing.from_config(cfg, create=False)
        self.limiter = ratelimit.RateLimiter()
        self.reload_policy()
        self._pending: dict[str, dict] = {}

    # ------------------------------------------------------------------ 配置
    def reload_policy(self) -> None:
        self.policy = {key: db.get_policy(self.store, key) for key in db.POLICY_DEFAULTS}

    def _section(self, key: str) -> dict:
        val = self.policy.get(key)
        if isinstance(val, dict):
            return val
        return db.policy_section(self.store, key)

    @property
    def argon2_params(self) -> dict:
        return password.ar2params(self._section("argon2.params"))

    # ------------------------------------------------------------------ 用户
    def get_user(self, username: str) -> dict | None:
        return self.store.query_one(
            "SELECT * FROM auth_user WHERE username=?", (str(username or "").strip(),))

    def user_by_id(self, user_id: int) -> dict | None:
        return self.store.query_one("SELECT * FROM auth_user WHERE id=?", (int(user_id),))

    def create_user(self, username: str, user_password: str, display: str | None = None,
                    admin: bool = False) -> dict:
        username = str(username or "").strip()
        if not USERNAME_RE.match(username):
            raise ValueError("用户名需以小写字母开头，2~32 位，可含数字/._-")
        if self.get_user(username):
            raise ValueError(f"用户已存在：{username}")
        ok, reason = password.check_strength(
            user_password, username, self._section("password.policy"), admin=admin)
        if not ok:
            raise ValueError(reason)
        phc, algo = password.hash_password(
            user_password, self.keys.pepper, self.argon2_params)
        from ..store import now_utc

        ts = now_utc()
        cur = self.store.execute(
            "INSERT INTO auth_user(username, display_name, password_hash, password_algo,"
            " password_ts, status, loa_max, created_ts) VALUES(?,?,?,?,?,'active',3,?)",
            (username, display or username, phc, algo, ts, ts),
        )
        user_id = int(cur.lastrowid or 0)
        audit.append(self.store, event="user_create", result="ok", username=username,
                     user_id=user_id, detail=f"algo={algo} admin={admin}")
        return {"user_id": user_id, "username": username, "algo": algo}

    def set_password(self, username: str, new_password: str,
                     old_password: str | None = None) -> None:
        user = self.get_user(username)
        if not user:
            raise ValueError("用户不存在")
        params = self.argon2_params
        if old_password is not None and not password.verify_password(
                old_password, user["password_hash"], user["password_algo"],
                self.keys.pepper, params):
            raise ValueError("原口令不正确")
        ok, reason = password.check_strength(
            new_password, username, self._section("password.policy"))
        if not ok:
            raise ValueError(reason)
        phc, algo = password.hash_password(new_password, self.keys.pepper, params)
        from ..store import now_utc

        self.store.execute(
            "UPDATE auth_user SET password_hash=?, password_algo=?, password_ts=?,"
            " must_reset=0, failed_count=0, locked_until=NULL WHERE id=?",
            (phc, algo, now_utc(), int(user["id"])),
        )
        revoked = session.revoke_user(self.store, int(user["id"]), "password_changed")
        audit.append(self.store, event="password_change", result="ok",
                     username=username, user_id=int(user["id"]),
                     detail=f"revoked_sessions={revoked}")

    def list_users(self) -> list[dict]:
        return self.store.query(
            "SELECT id, username, display_name, password_algo, status, loa_max,"
            " failed_count, locked_until, mfa_enabled, last_login_ts FROM auth_user"
            " ORDER BY id")

    def lock_user(self, username: str, reason: str = "manual") -> bool:
        user = self.get_user(username)
        if not user:
            return False
        until = ratelimit.lock(self.store, user, int(
            self._section("lockout").get("lock_seconds", 900)))
        audit.append(self.store, event="lockout", result="ok", username=username,
                     user_id=int(user["id"]), detail=f"{reason};until={until}")
        return True

    def unlock_user(self, username: str) -> bool:
        user = self.get_user(username)
        if not user:
            return False
        ratelimit.unlock(self.store, user)
        self.store.execute("UPDATE auth_user SET status='active' WHERE id=?", (int(user["id"]),))
        audit.append(self.store, event="unlock", result="ok", username=username,
                     user_id=int(user["id"]))
        return True

    # ------------------------------------------------------------------ 因子注册
    def enroll_totp(self, username: str) -> dict:
        user = self._require_user(username)
        self.reload_policy()
        pol = self._section("totp")
        res = totp.enroll(self.store, self.keys, int(user["id"]),
                          label=username, secret_len=int(pol.get("secret_len", 20)),
                          issuer=str(pol.get("issuer", "Hornwork")))
        audit.append(self.store, event="totp_enroll", result="pending",
                     username=username, user_id=int(user["id"]), factor="totp")
        res["username"] = username
        return res

    def confirm_totp(self, username: str, code: str) -> tuple[bool, str]:
        user = self._require_user(username)
        self.reload_policy()
        ok, reason = totp.confirm(self.store, self.keys, int(user["id"]), code,
                                  self._section("totp"))
        audit.append(self.store, event="totp_enroll", result="ok" if ok else "fail",
                     username=username, user_id=int(user["id"]), factor="totp",
                     detail=reason)
        return ok, reason

    def enroll_biometric(self, username: str, embedding: list[float],
                         quality: float = 1.0) -> dict:
        user = self._require_user(username)
        self.reload_policy()
        res = biometric.enroll(self.store, self.keys, int(user["id"]), embedding,
                               quality=quality, policy=self._section("bio"))
        audit.append(self.store, event="bio_enroll", result="ok", username=username,
                     user_id=int(user["id"]), factor="bio",
                     detail=f"template_id={res['template_id']}")
        return res

    def delete_biometric(self, username: str) -> int:
        user = self._require_user(username)
        n = biometric.delete(self.store, int(user["id"]))
        audit.append(self.store, event="bio_delete", result="ok", username=username,
                     user_id=int(user["id"]), factor="bio", detail=f"revoked={n}")
        return n

    def revoke_totp(self, username: str) -> int:
        user = self._require_user(username)
        n = totp.revoke(self.store, int(user["id"]))
        audit.append(self.store, event="totp_revoke", result="ok", username=username,
                     user_id=int(user["id"]), factor="totp", detail=f"revoked={n}")
        return n

    def _require_user(self, username: str) -> dict:
        user = self.get_user(username)
        if not user:
            raise ValueError(f"用户不存在：{username}")
        return user

    # ------------------------------------------------------------------ 登录
    def start_login(self, username: str, user_password: str, ip: str | None = None,
                    device_token: str | None = None, now: float | None = None) -> dict:
        t0 = time.perf_counter()
        username = str(username or "").strip()
        lockout = self._section("lockout")
        # IP / 全局限速（只限速不锁定，避免 NAT 误伤）
        if ip and not self.limiter.allow("ip", str(ip), int(lockout.get("ip_rate", 20)),
                                         float(lockout.get("ip_window", 60)), now):
            return {"status": "rate_limited", "error": "too_many_requests"}
        if not self.limiter.allow("global", "login", int(lockout.get("global_rate", 50)),
                                  float(lockout.get("global_window", 60)), now):
            self._fail(username, None, "pw", "fail", ip=ip, device_id=None,
                       risk=None, detail="global_rate_limited", latency_ms=None)
            return {"status": "rate_limited", "error": "too_many_requests"}

        user = self.get_user(username)
        params = self.argon2_params
        # 防枚举：账号不存在也付一次 Argon2id 的代价，外部只看到统一错误
        if not user:
            password.dummy_verify(self.keys.pepper, params)
            self._fail(username, None, "pw", "fail", ip=ip, detail="unknown_user")
            return {"status": "fail", "error": GENERIC_ERROR}

        if ratelimit.is_locked(self.store, user, now=now):
            self._fail(username, user, "pw", "fail", ip=ip, detail="account_locked")
            return {"status": "fail", "error": GENERIC_ERROR, "reason": "locked"}
        if str(user["status"]) != "active":
            self._fail(username, user, "pw", "fail", ip=ip,
                       detail=f"status={user['status']}")
            return {"status": "fail", "error": GENERIC_ERROR}

        ok = password.verify_password(user_password, user["password_hash"],
                                      user["password_algo"], self.keys.pepper, params)
        if not ok:
            self._fail(username, user, "pw", "fail", ip=ip, detail="wrong_password")
            ratelimit.record_password_failure(
                self.store, user, lockout, now=now)
            return {"status": "fail", "error": GENERIC_ERROR}

        # 口令通过：清零失败计数；旧哈希在登录成功时渐进迁移
        ratelimit.reset_failures(self.store, user)
        if password.needs_rehash(user["password_algo"], user["password_hash"], params):
            phc, algo = password.hash_password(user_password, self.keys.pepper, params)
            from ..store import now_utc

            self.store.execute(
                "UPDATE auth_user SET password_hash=?, password_algo=?, password_ts=?"
                " WHERE id=?", (phc, algo, now_utc(), int(user["id"])))
            audit.append(self.store, event="rehash", result="ok", username=username,
                         user_id=int(user["id"]), factor="pw",
                         detail=f"{user['password_algo']}->{algo}")

        # 设备令牌（只降风险分，不减少因子）
        device_id = None
        dev = session.verify_device(self.keys, device_token) if device_token else None
        if dev and int(dev[1]) == int(user["id"]):
            device_id = dev[0]

        self.reload_policy()
        risk_res = risk.score(self.store, user, ip=ip, device_id=device_id,
                              weights=self._section("risk.weights"),
                              now=_dt(now))
        if risk_res["action"] == "lockout":
            ratelimit.lock(self.store, user, int(lockout.get("lock_seconds", 900)), now=now)
            self._fail(username, user, "risk", "fail", ip=ip, device_id=device_id,
                       risk=risk_res, detail="risk_lockout")
            return {"status": "fail", "error": "risk_lockout",
                    "risk": risk_res, "reason": "risk_lockout"}

        if not totp.active_credential(self.store, int(user["id"])):
            self._fail(username, user, "totp", "fail", ip=ip, device_id=device_id,
                       risk=risk_res, detail="totp_not_enrolled")
            return {"status": "enroll_required", "error": "totp_not_enrolled",
                    "risk": risk_res}

        required_loa = int(risk_res["required_loa"])
        degraded = False
        degrade_reason = None
        if required_loa >= 3:
            if not biometric.has_template(self.store, int(user["id"])):
                required_loa = 2
                degraded = True
                degrade_reason = "bio_not_enrolled"
        if int(user["loa_max"]) < required_loa:
            required_loa = int(user["loa_max"])
            degraded = True
            degrade_reason = "loa_capped"

        challenge_id = crypto.b64u(secrets.token_bytes(16))
        from ..config import cfg_get

        ttl = float(cfg_get(self.cfg, "auth.challenge_ttl_sec", 120))
        self._pending[challenge_id] = {
            "username": username, "user_id": int(user["id"]), "ip": ip,
            "device_id": device_id, "risk": risk_res,
            "required_loa": required_loa, "degraded": degraded,
            "degrade_reason": degrade_reason, "factors": ["pw"],
            "totp_ok": False, "totp_counter": 0, "t0": t0,
            "expires": time.time() + ttl,
        }
        return {
            "status": "totp_required",
            "challenge_id": challenge_id,
            "required_loa": required_loa,
            "degraded": degraded,
            "degrade_reason": degrade_reason,
            "risk": risk_res,
            "expires_in": int(ttl),
        }

    def advance(self, challenge_id: str, totp_code: str | None = None,
                embedding: list[float] | None = None,
                now: float | None = None) -> dict:
        ch = self._pending.get(str(challenge_id))
        if not ch:
            return {"status": "fail", "error": GENERIC_ERROR, "reason": "unknown_challenge"}
        if ch["expires"] < time.time():
            self._pending.pop(challenge_id, None)
            return {"status": "fail", "error": GENERIC_ERROR, "reason": "challenge_expired"}
        user = self.user_by_id(ch["user_id"])
        if not user:
            return {"status": "fail", "error": GENERIC_ERROR}
        self.reload_policy()
        username = ch["username"]

        # 第二因子：TOTP（独立失败计数）
        if not ch["totp_ok"]:
            if totp_code is None:
                return {"status": "totp_required", "challenge_id": challenge_id}
            if ratelimit.totp_denied(self.store, username, self._section("lockout"), now=now):
                self._fail(username, user, "totp", "fail", ip=ch["ip"],
                           device_id=ch["device_id"], risk=ch["risk"],
                           detail="totp_locked")
                self._pending.pop(challenge_id, None)
                return {"status": "fail", "error": GENERIC_ERROR, "reason": "totp_locked"}
            ok, reason, counter = totp.verify_user(
                self.store, self.keys, int(user["id"]), totp_code,
                self._section("totp"), at=now)
            if not ok:
                self._fail(username, user, "totp", "fail", ip=ch["ip"],
                           device_id=ch["device_id"], risk=ch["risk"], detail=reason)
                self._pending.pop(challenge_id, None)
                return {"status": "fail", "error": GENERIC_ERROR, "reason": reason}
            ch["totp_ok"] = True
            ch["totp_counter"] = counter
            ch["factors"].append("totp")

        # 第三因子：人脸（仅 LOA3 路径）
        if ch["required_loa"] >= 3:
            if embedding is None:
                return {"status": "bio_required", "challenge_id": challenge_id,
                        "required_loa": 3, "degraded": ch["degraded"]}
            ok, sim, reason = biometric.verify(
                self.store, self.keys, int(user["id"]), embedding, self._section("bio"))
            if not ok:
                self._fail(username, user, "bio", "fail", ip=ch["ip"],
                           device_id=ch["device_id"], risk=ch["risk"],
                           detail=f"{reason};sim={sim}")
                self._pending.pop(challenge_id, None)
                return {"status": "fail", "error": GENERIC_ERROR, "reason": reason,
                        "similarity": sim}
            ch["factors"].append("bio")
            ch["similarity"] = sim

        # 全部所需因子通过 → 签发会话（登录成功重新签发，防会话固定）
        self._pending.pop(challenge_id, None)
        issued = session.issue(
            self.store, self.keys, int(user["id"]), int(ch["required_loa"]),
            ip=ch["ip"], device_id=ch["device_id"], now=now,
            policy=self._section("session.ttl"), strong_auth=ch["required_loa"] >= 3)
        from ..store import now_utc

        self.store.execute("UPDATE auth_user SET last_login_ts=?, failed_count=0"
                           " WHERE id=?", (now_utc(), int(user["id"])))
        latency = int(round((time.perf_counter() - ch["t0"]) * 1000))
        result = "degraded" if ch["degraded"] else "ok"
        detail = None
        if ch["degraded"]:
            detail = f"degraded:{ch['degrade_reason']}"
        audit.append(self.store, event="logon", result=result, username=username,
                     user_id=int(user["id"]), factor="+".join(ch["factors"]),
                     loa=int(ch["required_loa"]), risk_score=int(ch["risk"]["score"]),
                     risk_why=ch["risk"]["why"], ip=ch["ip"],
                     device_id=ch["device_id"], latency_ms=latency, detail=detail)
        self._emit("logon", username, int(user["id"]), result=result,
                   factors=ch["factors"], loa=int(ch["required_loa"]), risk=ch["risk"],
                   degraded=bool(ch["degraded"]), latency_ms=latency, ip=ch["ip"],
                   detail=detail)
        return {
            "status": "ok", "token": issued["token"], "loa": int(ch["required_loa"]),
            "loa_name": policy.loa_name(int(ch["required_loa"])),
            "factors": ch["factors"], "risk": ch["risk"],
            "degraded": bool(ch["degraded"]),
            "degrade_reason": ch["degrade_reason"],
            "latency_ms": latency, "session": issued,
            "similarity": ch.get("similarity"),
        }

    def login(self, username: str, user_password: str, ip: str | None = None,
              device_token: str | None = None, totp_code: str | None = None,
              embedding: list[float] | None = None,
              now: float | None = None) -> dict:
        """一次性登录（状态机封装）：CLI / 中间件都走这一条路径。"""
        res = self.start_login(username, user_password, ip=ip,
                               device_token=device_token, now=now)
        if res["status"] != "totp_required":
            return res
        res = self.advance(res["challenge_id"], totp_code=totp_code, now=now)
        if res["status"] == "bio_required" and embedding is not None:
            res = self.advance(res["challenge_id"], embedding=embedding, now=now)
        return res

    # ------------------------------------------------------------------ 会话 / step-up
    def login_password_only(self, username: str, user_password: str,
                            ip: str | None = None,
                            embedding: list[float] | None = None,
                            now: float | None = None) -> dict:
        """平台统一登录：账号 + 口令；人脸为可选因子（提供且匹配则升 LOA3）。

        - 不做 TOTP 校验（演示阶段按需求关闭动态码）；
        - 保留 Argon2id+pepper 校验、锁定/限速、风险评分与会话签发；
        - 人脸仅在用户已注册模板且本次提供向量时校验，失败不阻断登录（降为 LOA2）。
        """
        t0 = time.perf_counter()
        username = str(username or "").strip()
        lockout = self._section("lockout")
        if ip and not self.limiter.allow("ip", str(ip), int(lockout.get("ip_rate", 20)),
                                         float(lockout.get("ip_window", 60)), now):
            return {"status": "rate_limited", "error": "too_many_requests"}
        if not self.limiter.allow("global", "login", int(lockout.get("global_rate", 50)),
                                  float(lockout.get("global_window", 60)), now):
            self._fail(username, None, "pw", "fail", ip=ip, device_id=None,
                       risk=None, detail="global_rate_limited", latency_ms=None)
            return {"status": "rate_limited", "error": "too_many_requests"}

        user = self.get_user(username)
        params = self.argon2_params
        if not user:
            password.dummy_verify(self.keys.pepper, params)
            self._fail(username, None, "pw", "fail", ip=ip, detail="unknown_user")
            return {"status": "fail", "error": GENERIC_ERROR}
        if ratelimit.is_locked(self.store, user, now=now):
            self._fail(username, user, "pw", "fail", ip=ip, detail="account_locked")
            return {"status": "fail", "error": GENERIC_ERROR, "reason": "locked"}
        if str(user["status"]) != "active":
            self._fail(username, user, "pw", "fail", ip=ip,
                       detail=f"status={user['status']}")
            return {"status": "fail", "error": GENERIC_ERROR}

        ok = password.verify_password(user_password, user["password_hash"],
                                      user["password_algo"], self.keys.pepper, params)
        if not ok:
            self._fail(username, user, "pw", "fail", ip=ip, detail="wrong_password")
            ratelimit.record_password_failure(self.store, user, lockout, now=now)
            return {"status": "fail", "error": GENERIC_ERROR}

        ratelimit.reset_failures(self.store, user)
        if password.needs_rehash(user["password_algo"], user["password_hash"], params):
            phc, algo = password.hash_password(user_password, self.keys.pepper, params)
            from ..store import now_utc

            self.store.execute(
                "UPDATE auth_user SET password_hash=?, password_algo=?, password_ts=?"
                " WHERE id=?", (phc, algo, now_utc(), int(user["id"])))

        self.reload_policy()
        risk_res = risk.score(self.store, user, ip=ip, device_id=None,
                              weights=self._section("risk.weights"), now=_dt(now))
        factors = ["pw"]
        loa = 2
        degraded = False
        degrade_reason = None
        similarity = None

        # 可选人脸因子：仅当用户已注册且本次提供向量时尝试，失败不阻断
        if embedding is not None and biometric.has_template(self.store, int(user["id"])):
            bio_ok, sim, _reason = biometric.verify(
                self.store, self.keys, int(user["id"]), embedding, self._section("bio"))
            similarity = sim
            if bio_ok:
                factors.append("bio")
                loa = 3
            else:
                degraded = True
                degrade_reason = "bio_mismatch"
        if int(user["loa_max"]) < loa:
            loa = int(user["loa_max"])
            degraded = True
            degrade_reason = degrade_reason or "loa_capped"
        if risk_res.get("action") == "lockout" and loa < 3:
            degraded = True
            degrade_reason = degrade_reason or "risk_high"

        issued = session.issue(
            self.store, self.keys, int(user["id"]), loa, ip=ip, device_id=None, now=now,
            policy=self._section("session.ttl"), strong_auth=loa >= 3)
        from ..store import now_utc

        self.store.execute("UPDATE auth_user SET last_login_ts=?, failed_count=0"
                           " WHERE id=?", (now_utc(), int(user["id"])))
        latency = int(round((time.perf_counter() - t0) * 1000))
        audit.append(self.store, event="logon", result="ok" if not degraded else "degraded",
                     username=username, user_id=int(user["id"]), factor="+".join(factors),
                     loa=loa, risk_score=int(risk_res.get("score") or 0),
                     risk_why=risk_res.get("why"), ip=ip, latency_ms=latency,
                     detail=degrade_reason)
        self._emit("logon", username, int(user["id"]), result="ok", factors=factors,
                   loa=loa, risk=risk_res, degraded=degraded, latency_ms=latency,
                   ip=ip, detail=degrade_reason)
        return {"status": "ok", "token": issued["token"], "loa": loa,
                "loa_name": policy.loa_name(loa), "factors": factors, "risk": risk_res,
                "degraded": degraded, "degrade_reason": degrade_reason,
                "similarity": similarity, "latency_ms": latency, "session": issued}

    def session_row(self, token: str) -> dict:
        self.reload_policy()
        return session.verify(self.store, self.keys, token,
                              policy=self._section("session.ttl"))

    def session_info(self, token: str) -> dict:
        row = self.session_row(token)
        user = self.user_by_id(int(row["user_id"])) or {}
        return {"session": row, "user": {
            "id": user.get("id"), "username": user.get("username")},
            "loa": int(row["loa"]), "loa_name": policy.loa_name(int(row["loa"])),
        }

    def step_up(self, token: str, totp_code: str, embedding: list[float] | None = None,
                now: float | None = None) -> dict:
        row = self.session_row(token)
        user = self.user_by_id(int(row["user_id"]))
        if not user:
            return {"status": "fail", "error": GENERIC_ERROR}
        self.reload_policy()
        # 先确认第三因子的输入是否到位，避免"消费了 TOTP 却卡在人脸"
        if biometric.has_template(self.store, int(user["id"])) and embedding is None:
            return {"status": "bio_required", "challenge_id": None}
        ok, reason, _counter = totp.verify_user(
            self.store, self.keys, int(user["id"]), totp_code,
            self._section("totp"), at=now)
        if not ok:
            self._fail(user["username"], user, "totp", "fail", ip=row.get("ip"),
                       detail=f"stepup:{reason}")
            return {"status": "fail", "error": GENERIC_ERROR, "reason": reason}
        if not biometric.has_template(self.store, int(user["id"])):
            self._fail(user["username"], user, "bio", "fail", ip=row.get("ip"),
                       detail="stepup:bio_not_enrolled")
            return {"status": "fail", "error": GENERIC_ERROR,
                    "reason": "bio_not_enrolled"}
        if embedding is None:
            return {"status": "bio_required", "challenge_id": None}
        ok, sim, reason = biometric.verify(
            self.store, self.keys, int(user["id"]), embedding, self._section("bio"))
        if not ok:
            self._fail(user["username"], user, "bio", "fail", ip=row.get("ip"),
                       detail=f"stepup:{reason};sim={sim}")
            return {"status": "fail", "error": GENERIC_ERROR, "reason": reason}
        session.upgrade(self.store, row["session_id"], 3, self._section("session.ttl"))
        audit.append(self.store, event="stepup", result="ok",
                     username=user["username"], user_id=int(user["id"]),
                     factor="totp+bio", loa=3, ip=row.get("ip"), detail=f"sim={sim}")
        return {"status": "ok", "loa": 3, "loa_name": policy.loa_name(3),
                "similarity": sim}

    def require_action(self, token: str, action: str = "read") -> dict:
        """中间件口径：返回 allow/stepup_required/deny + 上下文。"""
        try:
            row = self.session_row(token)
        except session.SessionError as exc:
            return {"decision": "deny", "reason": exc.reason}
        if not policy.can(row, action):
            return {"decision": "stepup_required", "reason": "loa_too_low",
                    "loa": int(row["loa"]), "action": action}
        if policy.step_up_required(row, action):
            return {"decision": "stepup_required", "reason": "strong_auth_expired",
                    "loa": int(row["loa"]), "action": action}
        return {"decision": "allow", "loa": int(row["loa"]), "action": action,
                "session": row}

    def logout(self, token: str) -> bool:
        ok = session.revoke_token(self.store, self.keys, token, "logout")
        if ok:
            audit.append(self.store, event="logout", result="ok", detail="session revoked")
        return ok

    # ------------------------------------------------------------------ 内部
    def _fail(self, username: str, user: dict | None, factor: str, result: str, *,
              ip: str | None = None, device_id: str | None = None,
              risk: dict | None = None, detail: str | None = None,
              latency_ms: int | None = None) -> None:
        risk = risk or {}
        audit.append(
            self.store, event="logon_fail", result=result, username=username,
            user_id=int(user["id"]) if user else None, factor=factor, ip=ip,
            device_id=device_id, risk_score=risk.get("score"),
            risk_why=risk.get("why"), latency_ms=latency_ms, detail=detail)
        self._emit("logon_fail", username, int(user["id"]) if user else None,
                   result=result, factors=[factor] if factor else [],
                   risk=risk, degraded=False, latency_ms=latency_ms, ip=ip,
                   detail=detail)

    def _emit(self, event_type: str, username: str, user_id: int | None, *,
              result: str = "ok", factors: list[str] | None = None,
              loa: int | None = None, risk: dict | None = None,
              degraded: bool = False, latency_ms: int | None = None,
              ip: str | None = None, detail: str | None = None) -> None:
        audit.emit_event(
            self.store, self.cfg, event_type, username=username, user_id=user_id,
            result=result, factors=factors, loa=loa, risk=risk, degraded=degraded,
            latency_ms=latency_ms, ip=ip, detail=detail)


def _dt(now: float | None):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(float(now), tz=timezone.utc) if now else None
