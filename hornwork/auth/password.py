"""口令因子：Argon2id（复用原语）+ 自研 PHC 格式处理 / 策略 / pepper / 渐进迁移。

密码算法落点（对应开发思路 §3.2 / §4.2）：
- 存储：`$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`，参数随串走；
- 预变换：HMAC-SHA256(pepper, 口令)，pepper 与库分离；
- 旧哈希：md5/sha1/pbkdf2 仅用于"识别+验证以便迁移"，绝不新写；
- 防枚举：账号不存在也做一次 dummy Argon2id，恒时比较。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from typing import Any

from argon2.low_level import Type, hash_secret_raw

from . import crypto

ARGON2_TYPE = Type.ID

# 本地弱口令表（离线环境，不调用 HIBP API）；报告口径"本地 top-N + 用户名变体"
WEAK_PASSWORDS = {
    "123456", "12345678", "123456789", "1234567890", "password", "passw0rd",
    "qwerty", "qwerty123", "abc123", "111111", "000000", "iloveyou", "admin",
    "admin123", "administrator", "root", "toor", "letmein", "welcome",
    "monkey", "dragon", "sunshine", "princess", "football", "baseball",
    "shadow", "master", "superman", "batman", "trustno1", "hello123",
    "password1", "password123", "passw0rd1", "qazwsx", "1q2w3e4r", "1qaz2wsx",
    "zaq12wsx", "asdfghjkl", "zxcvbnm", "qwertyuiop", "changeme", "secret",
    "test1234", "test12345", "P@ssw0rd", "P@ssw0rd!", "Aa123456", "Aa123456!",
    "123qwe", "abc123456", "wang123", "li123456", "zhang123", "liu123456",
    "hornwork", "hornwork123", "ubuntu", "kali", "centos",
}

_SEQ = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm")
PHC_RE = re.compile(
    r"^\$(?P<algo>argon2id|argon2i|argon2d)\$v=(?P<ver>\d+)\$m=(?P<m>\d+),"
    r"t=(?P<t>\d+),p=(?P<p>\d+)\$(?P<salt>[A-Za-z0-9+/]+)\$(?P<hash>[A-Za-z0-9+/]+)$"
)


class LegacyUnsupported(ValueError):
    """识别到旧哈希但本机缺少对应校验库（如 bcrypt）。"""


def _b64nopad(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _unb64nopad(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------------------
# PHC 串（自研解析/构造，不依赖库的内部结构）
# ---------------------------------------------------------------------------
def build_phc(digest: bytes, salt: bytes, params: dict, algo: str = "argon2id", ver: int = 19) -> str:
    return (
        f"${algo}$v={ver}$m={int(params['m'])},t={int(params['t'])},p={int(params['p'])}"
        f"${_b64nopad(salt)}${_b64nopad(digest)}"
    )


def parse_phc(phc: str) -> dict | None:
    m = PHC_RE.match(phc or "")
    if not m:
        return None
    return {
        "algo": m.group("algo"),
        "version": int(m.group("ver")),
        "m": int(m.group("m")),
        "t": int(m.group("t")),
        "p": int(m.group("p")),
        "salt": _unb64nopad(m.group("salt")),
        "hash": _unb64nopad(m.group("hash")),
    }


def _argon2(password_bytes: bytes, salt: bytes, params: dict) -> bytes:
    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=int(params["t"]),
        memory_cost=int(params["m"]),
        parallelism=int(params["p"]),
        hash_len=int(params.get("hash_len", 32)),
        type=ARGON2_TYPE,
        version=19,
    )


# ---------------------------------------------------------------------------
# 口令哈希 / 校验
# ---------------------------------------------------------------------------
def hash_password(password: str, pepper: bytes, params: dict,
                  salt: bytes | None = None) -> tuple[str, str]:
    """返回 (PHC 串, algo)。pepper 预变换在 Argon2id 之前。"""
    salt = salt or os.urandom(int(params.get("salt_len", 16)))
    digest = _argon2(crypto.pepper_password(pepper, password), salt, params)
    return build_phc(digest, salt, params), "argon2id"


def verify_argon2(password: str, phc: str, pepper: bytes) -> bool:
    parsed = parse_phc(phc)
    if not parsed:
        return False
    params = {"m": parsed["m"], "t": parsed["t"], "p": parsed["p"],
              "hash_len": len(parsed["hash"])}
    digest = _argon2(crypto.pepper_password(pepper, password), parsed["salt"], params)
    return hmac.compare_digest(digest, parsed["hash"])


def dummy_verify(pepper: bytes, params: dict) -> None:
    """账号不存在时也付出一次 Argon2id 的代价，消除存在性时序差。"""
    salt = b"\x00" * 16
    _argon2(crypto.pepper_password(pepper, "dummy-password-for-timing"), salt, params)


def detect_algo(stored: str) -> str:
    s = stored or ""
    if s.startswith("$argon2id$"):
        return "argon2id"
    if s.startswith("md5$"):
        return "md5"
    if s.startswith("sha1$"):
        return "sha1"
    if s.startswith("pbkdf2$"):
        return "pbkdf2"
    if s.startswith("bcrypt$"):
        return "bcrypt"
    return "unknown"


def verify_legacy(password: str, stored: str, algo: str, salt: bytes = b"") -> bool:
    """旧哈希只做验证，绝不用于新写入。"""
    try:
        if algo == "md5":
            return hmac.compare_digest(
                hashlib.md5(password.encode("utf-8")).hexdigest(), stored[4:].strip().lower())
        if algo == "sha1":
            return hmac.compare_digest(
                hashlib.sha1(password.encode("utf-8")).hexdigest(), stored[5:].strip().lower())
        if algo == "pbkdf2":
            _, digest_name, iters, salt_b64, hash_b64 = stored.split("$")
            calc = hashlib.pbkdf2_hmac(
                digest_name, password.encode("utf-8"), _unb64nopad(salt_b64), int(iters))
            return hmac.compare_digest(calc, _unb64nopad(hash_b64))
    except (ValueError, TypeError):
        return False
    if algo == "bcrypt":
        raise LegacyUnsupported("bcrypt 旧哈希需要 bcrypt 库；本机未安装，请走管理员重置流程")
    return False


def verify_password(password: str, stored: str, algo: str, pepper: bytes,
                    argon2_params: dict) -> bool:
    """统一验证入口；未知/不支持格式一律 False（外部只看到统一错误码）。"""
    if algo in ("argon2id", "unknown"):
        if parse_phc(stored):
            return verify_argon2(password, stored, pepper)
        return False
    if algo in ("md5", "sha1", "pbkdf2", "bcrypt"):
        try:
            return verify_legacy(password, stored, algo)
        except LegacyUnsupported:
            return False
    return False


def needs_rehash(algo: str, stored: str, params: dict) -> bool:
    if algo != "argon2id":
        return True
    parsed = parse_phc(stored)
    if not parsed:
        return True
    return (parsed["m"], parsed["t"], parsed["p"]) != (
        int(params["m"]), int(params["t"]), int(params["p"]))


# ---------------------------------------------------------------------------
# 口令策略（NIST SP 800-63B 口径）
# ---------------------------------------------------------------------------
def check_strength(password: str, username: str = "", policy: dict | None = None,
                   admin: bool = False) -> tuple[bool, str]:
    policy = policy or {}
    min_len = int(policy.get("admin_min_len" if admin else "min_len",
                             16 if admin else 12))
    max_len = int(policy.get("max_len", 128))
    if not password:
        return False, "口令不能为空"
    if len(password) < min_len:
        return False, f"口令长度不足（至少 {min_len} 位；长度是熵的主要来源）"
    if len(password) > max_len:
        return False, f"口令过长（上限 {max_len} 位）"
    low = password.lower()
    if low in {p.lower() for p in WEAK_PASSWORDS}:
        return False, "命中常见弱口令表，请更换"
    if username and username.lower() in low:
        return False, "口令不能包含用户名"
    if len(set(password)) <= 2:
        return False, "口令字符重复度过高"
    for start in range(max(0, len(low) - 5)):
        chunk = low[start:start + 6]
        if any(chunk in seq or chunk in seq[::-1] for seq in _SEQ):
            return False, "口令包含连续序列（如 qwerty/123456）"
    return True, "ok"


def strength_hint(password: str) -> int:
    """0~4 强度估计（给 CLI/前端展示，不透露具体规则）。"""
    score = 0
    score += 1 if len(password) >= 12 else 0
    score += 1 if len(password) >= 16 else 0
    score += 1 if len(set(password)) >= 8 else 0
    score += 1 if not password.lower() in {p.lower() for p in WEAK_PASSWORDS} else 0
    return min(score, 4)


def ar2params(policy: dict | None = None) -> dict:
    p = dict(policy or {})
    return {"m": int(p.get("m", 65536)), "t": int(p.get("t", 3)),
            "p": int(p.get("p", 4)), "hash_len": int(p.get("hash_len", 32)),
            "salt_len": int(p.get("salt_len", 16))}


def benchmark(params: dict, rounds: int = 5) -> dict[str, Any]:
    """实测 Argon2id 耗时（给报告"参数不是拍脑袋"的证据）。"""
    import time

    salt = os.urandom(16)
    times = []
    for _ in range(max(1, rounds)):
        t0 = time.perf_counter()
        _argon2(b"benchmark-secret", salt, params)
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    return {
        "params": {k: params[k] for k in ("m", "t", "p", "hash_len")},
        "rounds": rounds,
        "p50_ms": round(times[len(times) // 2], 2),
        "p95_ms": round(times[min(len(times) - 1, int(len(times) * 0.95))], 2),
        "min_ms": round(times[0], 2),
        "max_ms": round(times[-1], 2),
    }
