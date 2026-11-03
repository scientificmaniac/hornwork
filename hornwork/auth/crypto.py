"""密码学原语封装：主密钥 / pepper / HKDF 用途分离 / AES-256-GCM / HMAC / 编码。

红线：
1. 本文件不实现任何密码原语，只做参数选择、用途分离与封装；
2. 所有随机数来自 `os.urandom` / `secrets`，禁止 `random` 参与安全取值；
3. 主密钥与 pepper 分离存储（600），轮换主密钥 = 全体生物模板撤销。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32          # AES-256 / HMAC-SHA256 主密钥长度
NONCE_LEN = 12        # GCM 96 位 nonce
TAG_LEN = 16


class KeyMaterialError(RuntimeError):
    """密钥文件缺失或格式非法。"""


def _read_key(path: str | Path) -> bytes:
    data = Path(path).read_bytes()
    if len(data) < KEY_LEN:
        raise KeyMaterialError(f"密钥长度不足（{path}）：期望 ≥{KEY_LEN} 字节")
    return data[:KEY_LEN]


def load_or_create_key(path: str | Path, length: int = KEY_LEN, create: bool = False) -> bytes:
    """读取密钥文件；create=True 时生成（目录不存在则创建，权限 600/700）。"""
    p = Path(path)
    if p.is_file():
        return _read_key(p)[:length]
    if not create:
        raise KeyMaterialError(f"密钥文件不存在：{p}（可运行 hornworkctl auth db init 生成）")
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p.parent, 0o700)
    except OSError:
        pass
    data = secrets.token_bytes(length)
    # O_EXCL：绝不覆盖已有密钥（覆盖 = 旧模板/旧口令全部作废）
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return data


class KeyRing:
    """主密钥 + pepper + HKDF 子密钥（用途分离，避免一把钥匙开所有锁）。"""

    def __init__(self, master: bytes, pepper: bytes, key_id: int = 1):
        if len(master) < KEY_LEN:
            raise KeyMaterialError("主密钥长度不足")
        self.master = master[:KEY_LEN]
        self.pepper = pepper[:KEY_LEN]
        self.key_id = int(key_id)
        self._cache: dict[bytes, bytes] = {}

    # ------------------------------------------------------------------ 加载
    @classmethod
    def from_config(cls, cfg: dict, create: bool = False) -> "KeyRing":
        from ..config import cfg_get, cfg_path

        key_path = cfg_path(cfg, "auth.key_path", "/var/lib/hornwork/auth/auth.key")
        pepper_path = cfg_path(cfg, "auth.pepper_path",
                              "/var/lib/hornwork/auth/auth.pepper")
        master = load_or_create_key(key_path, create=create)
        pepper = load_or_create_key(pepper_path, create=create)
        return cls(master, pepper, int(cfg_get(cfg, "auth.key_id", 1)))

    # ------------------------------------------------------------------ 派生
    def derive(self, info: bytes, length: int = 32) -> bytes:
        """HKDF-SHA256 派生子密钥；info 绑定用途（如 b"aead"/b"session"/b"bio:<id>"）。"""
        info = info if isinstance(info, bytes) else str(info).encode()
        cached = self._cache.get(info)
        if cached and len(cached) >= length:
            return cached[:length]
        key = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(self.master)
        self._cache[info] = key
        return key

    @property
    def k_aead(self) -> bytes:
        return self.derive(b"auth|aead|v1")

    @property
    def k_session(self) -> bytes:
        return self.derive(b"auth|session|v1")

    @property
    def k_bio(self) -> bytes:
        return self.derive(b"auth|bio|v1")


# ---------------------------------------------------------------------------
# AEAD（模板 / TOTP 共享密钥共用一套封装）
# ---------------------------------------------------------------------------
def seal(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM 封装：返回 (密文含 16B tag, 12B nonce)。AAD 绑上下文。"""
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return ct, nonce


def open_(key: bytes, ct: bytes, nonce: bytes, aad: bytes) -> bytes:
    """解密；AAD/nonce/tag 任一不符抛 `cryptography.exceptions.InvalidTag`。"""
    return AESGCM(key).decrypt(nonce, ct, aad)


def aead_aad(*parts: object) -> bytes:
    return "|".join(str(p) for p in parts).encode("utf-8")


# ---------------------------------------------------------------------------
# HMAC 与口令预变换
# ---------------------------------------------------------------------------
def mac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def mac_hex(key: bytes, msg: bytes) -> str:
    return mac(key, msg).hex()


def pepper_password(pepper: bytes, password: str) -> bytes:
    """口令预变换：HMAC-SHA256(pepper, 口令)。

    不用裸 SHA-256：避免长度扩展与 UTF-8 边界问题；pepper 与库分离，
    拖库者拿不到 pepper 就等于拿不到 Argon2id 的输入。
    """
    return hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def const_compare(a: bytes | str, b: bytes | str) -> bool:
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# 编码（会话令牌 / TOTP 密钥 / 二进制列）
# ---------------------------------------------------------------------------
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def b32(data: bytes) -> str:
    """RFC 4648 Base32，去掉 padding（给用户手输/扫码）。"""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def unb32(text: str) -> bytes:
    s = "".join(text.split()).upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s)
