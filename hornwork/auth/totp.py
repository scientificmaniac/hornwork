"""动态验证码因子：RFC 4226（HOTP）+ RFC 6238（TOTP）全自研实现。

- 核心只有 hmac/hashlib/struct/base64 标准库，动态截断按 RFC 4226 §5.3；
- TOTP 是 HMAC 不是加密：它提供"持有共享密钥的证明"，密钥本身用 AES-256-GCM
  加密落库（AAD 绑 user_id，防止 A 的密钥行改挂到 B 名下）；
- 防重放：`auth_user.last_totp_counter` 单调递增 + 原子 UPDATE（并发下也只会成功一次）。
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time
from typing import Any

from ..store import now_utc
from . import crypto


# ---------------------------------------------------------------------------
# 核心算法（约 40 行，报告直接引用）
# ---------------------------------------------------------------------------
def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    """HOTP(K, C) = Truncate(HMAC-SHA1(K, C))，C 为 8 字节大端。"""
    hs = hmac.new(secret, struct.pack(">Q", int(counter)), hashlib.sha1).digest()
    offset = hs[19] & 0x0F                       # 动态截断：由哈希最后一字节低 4 位决定
    binary = struct.unpack(">I", hs[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def counter_at(at: float, step: int = 30) -> int:
    """C = floor((T - T0) / X)，T0=0、X=30。"""
    return int(at) // int(step)


def totp(secret: bytes, at: float | None = None, step: int = 30,
         digits: int = 6) -> str:
    """TOTP(K, T) = HOTP(K, floor(T / X))。"""
    return hotp(secret, counter_at(time.time() if at is None else at, step), digits)


def verify(secret: bytes, code: str, last_counter: int = 0,
           at: float | None = None, step: int = 30, window: int = 1,
           digits: int = 6) -> tuple[bool, int]:
    """窗口 ±window 校验；counter 必须 > last_counter（一次性 + 防重放）。

    返回 (是否通过, 命中的 counter)。调用方负责把 counter 持久化。
    """
    norm = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(norm) != digits:
        return False, last_counter
    now = time.time() if at is None else at
    base = counter_at(now, step)
    for delta in range(-window, window + 1):
        counter = base + delta
        if counter <= last_counter:
            continue
        if hmac.compare_digest(hotp(secret, counter, digits), norm.zfill(digits)):
            return True, counter
    return False, last_counter


def random_secret(length: int = 20) -> bytes:
    return crypto.os.urandom(int(length))


def to_b32(secret: bytes) -> str:
    return crypto.b32(secret)


def from_b32(text: str) -> bytes:
    return crypto.unb32(text)


def otpauth_uri(username: str, secret: bytes, issuer: str = "Hornwork",
                digits: int = 6, step: int = 30) -> str:
    """Google Authenticator Key Uri Format（社区事实标准，不是 RFC）。"""
    from urllib.parse import quote

    label = quote(f"{issuer}:{username}")
    return (
        f"otpauth://totp/{label}?secret={to_b32(secret)}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={digits}&period={step}"
    )


def _aad(user_id: int, key_id: int) -> bytes:
    return f"{user_id}|totp|{key_id}".encode("utf-8")


def _seal_secret(keyring: crypto.KeyRing, user_id: int, secret: bytes) -> dict:
    ct, nonce = crypto.seal(keyring.k_aead, secret, _aad(user_id, keyring.key_id))
    return {"secret_enc": ct, "nonce": nonce, "key_id": keyring.key_id}


def _open_secret(keyring: crypto.KeyRing, user_id: int, row: dict) -> bytes:
    aad = _aad(user_id, int(row["key_id"]))
    return crypto.open_(keyring.k_aead, row["secret_enc"], row["nonce"], aad)


# ---------------------------------------------------------------------------
# 落库与业务接口
# ---------------------------------------------------------------------------
def enroll(store, keyring: crypto.KeyRing, user_id: int, label: str = "",
           secret_len: int = 20, issuer: str = "Hornwork") -> dict[str, Any]:
    """生成共享密钥并加密落库；`active=0`，需用户输入一次当前码才生效。"""
    secret = random_secret(secret_len)
    sealed = _seal_secret(keyring, user_id, secret)
    ts = now_utc()
    cur = store.execute(
        "INSERT INTO auth_credential(user_id, kind, label, secret_enc, nonce, key_id,"
        " active, created_ts) VALUES(?, 'totp', ?, ?, ?, ?, 0, ?)",
        (user_id, label or "TOTP", sealed["secret_enc"], sealed["nonce"],
         sealed["key_id"], ts),
    )
    return {
        "credential_id": cur.lastrowid,
        "secret_b32": to_b32(secret),
        "uri": otpauth_uri(label or str(user_id), secret, issuer=issuer),
    }


def active_credential(store, user_id: int) -> dict | None:
    return store.query_one(
        "SELECT * FROM auth_credential WHERE user_id=? AND kind='totp'"
        " AND active=1 AND revoked_ts IS NULL ORDER BY id DESC LIMIT 1",
        (user_id,),
    )


def inactive_credential(store, user_id: int) -> dict | None:
    return store.query_one(
        "SELECT * FROM auth_credential WHERE user_id=? AND kind='totp'"
        " AND active=0 AND revoked_ts IS NULL ORDER BY id DESC LIMIT 1",
        (user_id,),
    )


def confirm(store, keyring: crypto.KeyRing, user_id: int, code: str,
            policy: dict | None = None, at: float | None = None) -> tuple[bool, str]:
    """注册确认：用户输入一次当前码后才激活（防止没配对成功就被锁在门外）。"""
    policy = policy or {}
    row = inactive_credential(store, user_id)
    if not row:
        return False, "没有待激活的 TOTP 凭证"
    try:
        secret = _open_secret(keyring, user_id, row)
    except Exception:  # noqa: BLE001 - AAD/tag 不符视为数据被篡改
        return False, "TOTP 密钥解密失败（密钥或数据被篡改）"
    ok, _counter = verify(secret, code, 0, at=at,
                          step=int(policy.get("step", 30)),
                          window=int(policy.get("window", 1)),
                          digits=int(policy.get("digits", 6)))
    if not ok:
        return False, "动态码不正确（请检查设备时间，30 秒内有效）"
    store.execute("UPDATE auth_credential SET active=1, last_used_ts=? WHERE id=?",
                  (now_utc(), row["id"]))
    store.execute("UPDATE auth_user SET mfa_enabled=1 WHERE id=?", (user_id,))
    return True, "TOTP 已激活"


def verify_user(store, keyring: crypto.KeyRing, user_id: int, code: str,
                policy: dict | None = None, at: float | None = None) -> tuple[bool, str, int]:
    """校验 + 原子推进 counter。返回 (ok, reason, counter)。"""
    policy = policy or {}
    row = active_credential(store, user_id)
    if not row:
        return False, "TOTP 未激活", 0
    try:
        secret = _open_secret(keyring, user_id, row)
    except Exception:  # noqa: BLE001
        return False, "TOTP 密钥解密失败（密钥或数据被篡改）", 0
    user = store.query_one("SELECT last_totp_counter FROM auth_user WHERE id=?", (user_id,))
    last = int(user["last_totp_counter"]) if user else 0
    ok, counter = verify(secret, code, last, at=at,
                         step=int(policy.get("step", 30)),
                         window=int(policy.get("window", 1)),
                         digits=int(policy.get("digits", 6)))
    if not ok:
        return False, "动态码错误或已使用", last
    # 原子推进：并发提交同一码时只有一个请求能成功（防重放的关键）
    cur = store.execute(
        "UPDATE auth_user SET last_totp_counter=? WHERE id=? AND last_totp_counter<?",
        (counter, user_id, counter),
    )
    if cur.rowcount != 1:
        return False, "动态码已被使用（重放）", last
    store.execute("UPDATE auth_credential SET last_used_ts=? WHERE id=?",
                  (now_utc(), row["id"]))
    return True, "ok", counter


def revoke(store, user_id: int) -> int:
    cur = store.execute(
        "UPDATE auth_credential SET revoked_ts=? WHERE user_id=? AND kind='totp'"
        " AND revoked_ts IS NULL",
        (now_utc(), user_id),
    )
    store.execute("UPDATE auth_user SET mfa_enabled=0 WHERE id=?", (user_id,))
    return cur.rowcount


def reencrypt_all(store, keyring: crypto.KeyRing) -> int:
    """主密钥轮换后重加密全部 TOTP 密钥（用户无感）。"""
    rows = store.query(
        "SELECT * FROM auth_credential WHERE kind='totp' AND revoked_ts IS NULL")
    done = 0
    for row in rows:
        try:
            secret = _open_secret(keyring, int(row["user_id"]), row)
        except Exception:  # noqa: BLE001 - 旧 key_id 的密文用新钥解不开属预期
            continue
        sealed = _seal_secret(keyring, int(row["user_id"]), secret)
        store.execute(
            "UPDATE auth_credential SET secret_enc=?, nonce=?, key_id=? WHERE id=?",
            (sealed["secret_enc"], sealed["nonce"], sealed["key_id"], row["id"]),
        )
        done += 1
    return done
