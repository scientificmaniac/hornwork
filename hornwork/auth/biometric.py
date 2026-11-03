"""生物特征因子：人脸模板保护 + 1:1 比对（本模块最大差异化点）。

分工（"复用什么、自研什么"的边界）：
- 嵌入提取：**不自研、也不在本仓库实现**——模型权重体积大、许可仅非商业，且
  onnxruntime + 对齐管线属于"做不完就该砍"的部分。这里定义可插拔输入：
  JSON 向量文件（测试/演示）或轻量图像描述子（仅链路验证，不代表人脸识别精度）。
  真实部署把 `embedding_from_*` 换成远程人脸服务的 512 维 ArcFace 输出即可。
- 模板保护（自研）：随机正交变换（符号翻转 + 置换 + 归一化 Walsh-Hadamard）
  → AES-256-GCM 封装 → 库中只有密文。
  * 正交性保证内积不变：⟨Ta, Tb⟩ = ⟨a, b⟩，所以比对逻辑不变；
  * 换主密钥 / 换用户盐 → 新变换 → 旧模板全部作废，实现"可撤销"；
  * 必须诚实：正交变换可逆，**机密性来自 AEAD，不是来自变换**。

红线：绝不对人脸向量取 SHA-256 后比对（哈希无距离语义，识别直接失效）。
"""

from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path
from typing import Any, Sequence

from ..store import now_utc
from . import crypto

DEFAULT_DIM = 512


# ---------------------------------------------------------------------------
# 可撤销正交变换（O(d log d)，纯标准库）
# ---------------------------------------------------------------------------
def _fwht(vec: list[float]) -> list[float]:
    """归一化 Walsh-Hadamard 变换（正交、自逆）。要求长度 2 的幂。"""
    n = len(vec)
    a = list(vec)
    h = 1
    while h < n:
        for i in range(0, n, 2 * h):
            for j in range(i, i + h):
                x, y = a[j], a[j + h]
                a[j], a[j + h] = x + y, x - y
        h *= 2
    scale = 1.0 / math.sqrt(n)
    return [x * scale for x in a]


def _transform_params(seed: bytes, dim: int) -> tuple[list[int], list[int]]:
    stream = hashlib.shake_256(seed + b"|perm").digest(dim * 8)
    keys = [int.from_bytes(stream[i * 8:(i + 1) * 8], "big") for i in range(dim)]
    perm = sorted(range(dim), key=lambda i: keys[i])
    bits = hashlib.shake_256(seed + b"|sign").digest((dim + 7) // 8)
    signs = [1 if (bits[i // 8] >> (i % 8)) & 1 else -1 for i in range(dim)]
    return perm, signs


def template_seed(keyring: crypto.KeyRing, user_id: int) -> bytes:
    return keyring.derive(f"auth|bio|seed|{user_id}".encode(), 32)


def transform(vec: Sequence[float], seed: bytes) -> list[float]:
    """可撤销正交变换 T(v) = FWHT(D(P(v)))。"""
    dim = len(vec)
    if dim < 2 or (dim & (dim - 1)) != 0:
        raise ValueError(f"向量维度必须是 2 的幂，当前 {dim}")
    perm, signs = _transform_params(seed, dim)
    permuted = [float(vec[perm[i]]) * signs[i] for i in range(dim)]
    return _fwht(permuted)


def inverse_transform(vec: Sequence[float], seed: bytes) -> list[float]:
    """逆变换（仅用于验证/测试：证明变换正交、不改变相似度）。"""
    dim = len(vec)
    perm, signs = _transform_params(seed, dim)
    spectral = _fwht(list(vec))
    out = [0.0] * dim
    for idx, src in enumerate(perm):
        out[src] = spectral[idx] * signs[idx]
    return out


def l2_normalize(vec: Sequence[float]) -> list[float]:
    norm = math.sqrt(sum(float(x) * float(x) for x in vec))
    if norm <= 1e-12:
        raise ValueError("向量为零向量，无法归一化")
    return [float(x) / norm for x in vec]


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """两者都 L2 归一化后，点积即余弦相似度。"""
    return sum(float(x) * float(y) for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# 模板生命周期：注册 / 比对 / 撤销
# ---------------------------------------------------------------------------
def _aad(user_id: int, model_ver: str) -> bytes:
    return f"{user_id}|bio|{model_ver}".encode("utf-8")


def encrypt_template(keyring: crypto.KeyRing, user_id: int, embedding: Sequence[float],
                     model_ver: str) -> tuple[bytes, bytes, list[float]]:
    """返回 (密文, nonce, 变换后向量)。变换后向量只在内存出现，不落盘。"""
    norm = l2_normalize(embedding)
    tmpl = transform(norm, template_seed(keyring, user_id))
    blob = struct.pack(f"<{len(tmpl)}f", *tmpl)
    ct, nonce = crypto.seal(keyring.k_aead, blob, _aad(user_id, model_ver))
    return ct, nonce, tmpl


def decrypt_template(keyring: crypto.KeyRing, user_id: int, row: dict,
                     model_ver: str | None = None) -> list[float]:
    aad = str(row["aad"]).encode("utf-8") if model_ver is None else _aad(user_id, model_ver)
    blob = crypto.open_(keyring.k_aead, row["tmpl_enc"], row["nonce"], aad)
    dim = int(row["dim"])
    return list(struct.unpack(f"<{dim}f", blob))


def enroll(store, keyring: crypto.KeyRing, user_id: int, embedding: Sequence[float],
           quality: float = 1.0, policy: dict | None = None) -> dict[str, Any]:
    policy = policy or {}
    model_ver = str(policy.get("model_ver", "arcface-r50/dev"))
    dim = int(policy.get("dim", DEFAULT_DIM))
    emb = list(embedding)
    if len(emb) != dim:
        raise ValueError(f"嵌入维度不符：期望 {dim}，实际 {len(emb)}")
    quality_min = float(policy.get("quality_min", 0.5))
    if float(quality) < quality_min:
        raise ValueError(f"图像质量不足（{quality:.2f} < {quality_min}）")
    # 重新注册 = 撤销旧模板（保留旧行便于审计，但不再参与比对）
    store.execute(
        "UPDATE bio_template SET revoked_ts=? WHERE user_id=? AND revoked_ts IS NULL",
        (now_utc(), int(user_id)),
    )
    ct, nonce, _tmpl = encrypt_template(keyring, user_id, emb, model_ver)
    cur = store.execute(
        "INSERT INTO bio_template(user_id, algo, model_ver, dim, tmpl_enc, nonce,"
        " key_id, aad, quality, created_ts) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (int(user_id), str(policy.get("algo", "revocable-orth")), model_ver, dim,
         ct, nonce, keyring.key_id, _aad(int(user_id), model_ver).decode(),
         float(quality), now_utc()),
    )
    return {"template_id": cur.lastrowid, "dim": dim, "model_ver": model_ver,
            "ciphertext_bytes": len(ct)}


def active_templates(store, user_id: int) -> list[dict]:
    return store.query(
        "SELECT * FROM bio_template WHERE user_id=? AND revoked_ts IS NULL ORDER BY id DESC",
        (int(user_id),),
    )


def verify(store, keyring: crypto.KeyRing, user_id: int, embedding: Sequence[float],
           policy: dict | None = None) -> tuple[bool, float, str]:
    """1:1 比对：解密 → 用同一变换处理实时向量 → 余弦相似度 ≥ τ。"""
    policy = policy or {}
    rows = active_templates(store, user_id)
    if not rows:
        return False, 0.0, "not_enrolled"
    dim = int(rows[0]["dim"])
    emb = list(embedding)
    if len(emb) != dim:
        return False, 0.0, "dim_mismatch"
    live = transform(l2_normalize(emb), template_seed(keyring, user_id))
    best = -1.0
    for row in rows:
        try:
            stored = decrypt_template(keyring, user_id, row)
        except Exception:  # noqa: BLE001 - AAD/tag 不符 = 数据被篡改，记审计但不放行
            continue
        sim = cosine(stored, live)
        best = max(best, sim)
    threshold = float(policy.get("threshold", 0.35))
    return best >= threshold, round(best, 4), "ok" if best >= threshold else "below_threshold"


def delete(store, user_id: int) -> int:
    cur = store.execute(
        "UPDATE bio_template SET revoked_ts=? WHERE user_id=? AND revoked_ts IS NULL",
        (now_utc(), int(user_id)),
    )
    return cur.rowcount


def has_template(store, user_id: int) -> bool:
    return bool(active_templates(store, user_id))


# ---------------------------------------------------------------------------
# 嵌入输入（可插拔边界）
# ---------------------------------------------------------------------------
def embedding_from_file(path: str | Path) -> list[float]:
    """从 JSON 文件读 512 维向量（真实人脸服务的输出格式）。"""
    import json

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("vector") or data.get("embedding") or []
    return [float(x) for x in data]


def embedding_from_image(path: str | Path, dim: int = DEFAULT_DIM) -> list[float]:
    """轻量图像描述子：**仅用于链路演示，不代表人脸识别精度**。

    真实人脸识别需要 5 点对齐 + ArcFace 前向，本实现按"难做即砍"原则不纳入；
    部署时应替换为远程人脸服务的 512 维输出（IF-26，独立进程 + 仅 localhost）。
    """
    try:
        from PIL import Image  # 可选依赖：只用于演示图片解码
    except ImportError as exc:  # pragma: no cover - 取决于运行环境
        raise RuntimeError("读取图像需要 Pillow；或改用 --embedding <json> 提供向量") from exc

    img = Image.open(str(path)).convert("L").resize((16, 16))
    pixels = [p / 255.0 for p in img.getdata()]
    gx, gy = [], []
    for y in range(16):
        for x in range(16):
            gx.append((pixels[y * 16 + min(x + 1, 15)] - pixels[y * 16 + max(x - 1, 0)]) / 2)
            gy.append((pixels[min(y + 1, 15) * 16 + x] - pixels[max(y - 1, 0) * 16 + x]) / 2)
    features = pixels + gx + gy                      # 16*16*3 = 768
    features = features[:dim] + [0.0] * max(0, dim - len(features))
    return l2_normalize(features)


def noise_variant(embedding: Sequence[float], sigma: float = 0.02,
                  seed: int = 0) -> list[float]:
    """给向量加高斯噪声（测试/标定流程用：模拟同人两次采集的差异）。"""
    import random

    rng = random.Random(seed)
    noisy = [float(x) + rng.gauss(0.0, sigma) for x in embedding]
    return l2_normalize(noisy)
