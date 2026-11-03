"""ClamAV clamd INSTREAM 客户端。

协议：Unix socket 上先发 `zINSTREAM\\0`，随后按"4 字节大端长度 + 数据块"分块发送
（每块默认 1 MiB），以 4 字节 0 结束；clamd 返回一行文本：
- `stream: OK`                 → 干净；
- `stream: <签名名> FOUND`     → 命中；
- 其它（size limit exceeded 等）→ 抛 RuntimeError，由级联隔离。

熔断：socket 不存在或 PING 失败后 `unavailable_backoff_sec`（默认 60 s）内
`available()` 直接返回 False，避免每个文件都白等一次 connect 超时。
仅深度扫描（ctx["deep"]=True）且文件 ≤ max_size 时才 `supports()`。
"""

from __future__ import annotations

import os
import re
import socket
import struct
import threading
import time
from pathlib import Path

from ..config import cfg_get
from ..log import get_logger
from .base import BaseScanEngine, make_hit

log = get_logger("engines.clamd")

INSTREAM_MAX_RESPONSE = 8192

# clamd 响应兼容性：
#   - 干净文件：`stream: OK`（可能带尾部空格 / \0 / 换行）
#   - 命中文件：`stream: <签名名> FOUND`
#   - PING：`PONG\0`
# 一律先去掉 \0/空白，再做大小写不敏感匹配。
_OK_RE = re.compile(r"(?:^|:\s*)OK$", re.IGNORECASE)
_PONG_RE = re.compile(r"(?:^|:\s*)PONG$", re.IGNORECASE)


def _read_response(sock: socket.socket, limit: int = INSTREAM_MAX_RESPONSE) -> str:
    """读取 clamd 的一行响应（可能以 \\n / \\0 结束），去掉 NUL 与首尾空白。"""
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if b"\n" in chunk or b"\x00" in chunk:
            break
    return b"".join(chunks).decode("utf-8", "replace").replace("\x00", "").strip()


def _parse_response(response: str | bytes, path: str) -> list[dict]:
    """解析 clamd INSTREAM 响应；干净返回 []，命中返回 Hit，其它抛 RuntimeError。

    兼容的真实响应形态（已实测）：
    - ``stream: OK`` / ``stream: OK \\0`` / ``OK``          → []
    - ``stream: Eicar-Test-Signature FOUND``               → Hit(name=Eicar-Test-Signature)
    - ``/tmp/eicar.com: Eicar-Test-Signature FOUND``       → 取最后一个冒号后的名称
    - ``INSTREAM size limit exceeded. ERROR``              → RuntimeError
    """
    if isinstance(response, bytes):
        response = response.decode("utf-8", "replace")
    text = str(response or "").replace("\x00", "").strip()
    if not text:
        raise RuntimeError("clamd 返回空响应")
    upper = text.upper()
    if "FOUND" not in upper and _OK_RE.search(text):
        return []
    if "FOUND" in upper:
        head = text[:upper.find("FOUND")].strip()
        # 名称取 FOUND 之前、最后一个 ':' 之后的部分（兼容 `stream: xxx` 与 `/path: xxx`）
        signature = head.rsplit(":", 1)[1].strip() if ":" in head else head.strip()
        signature = signature or "clamav-unknown"
        return [make_hit(
            "clamav", f"clamav:{signature}", f"ClamAV 检出病毒：{signature}", 100,
            {"family": signature, "signature": signature, "engine": "clamd", "source": "clamav"},
            {"path": str(path), "signature": signature, "response": text},
        )]
    raise RuntimeError(f"clamd 异常响应: {text}")


def scan_stream(sock_path: str, path: str, timeout: float = 30,
                chunk: int = 1 << 20) -> list[dict]:
    """通过 INSTREAM 让 clamd 扫描单个文件，返回 Hit 列表。"""
    af_unix = getattr(socket, "AF_UNIX", None)
    if af_unix is None:
        raise RuntimeError("当前平台不支持 AF_UNIX socket")
    chunk_size = max(1, int(chunk or (1 << 20)))
    sock: socket.socket | None = None
    try:
        sock = socket.socket(af_unix, socket.SOCK_STREAM)
        sock.settimeout(float(timeout or 30))
        sock.connect(str(sock_path))
        sock.sendall(b"zINSTREAM\x00")
        with open(path, "rb") as handle:
            while True:
                buf = handle.read(chunk_size)
                if not buf:
                    break
                sock.sendall(struct.pack(">I", len(buf)) + buf)
        sock.sendall(struct.pack(">I", 0))
        response = _read_response(sock)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return _parse_response(response, path)


def ping(sock_path: str, timeout: float = 2) -> bool:
    """PING 探活：发 `zPING\\0`，收到 PONG 视为可用。"""
    af_unix = getattr(socket, "AF_UNIX", None)
    if af_unix is None:
        return False
    sock: socket.socket | None = None
    try:
        sock = socket.socket(af_unix, socket.SOCK_STREAM)
        sock.settimeout(float(timeout or 2))
        sock.connect(str(sock_path))
        sock.sendall(b"zPING\x00")
        response = _read_response(sock, limit=256)
        # 真实 clamd 返回 "PONG\0"；_read_response 已去 NUL/空白
        return bool(_PONG_RE.search(response) or "PONG" in response.upper())
    except (OSError, socket.timeout):
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class ClamavEngine(BaseScanEngine):
    """clamd 深度扫描引擎（cost=slow，仅在 deep=True 时参与级联）。"""

    name = "clamav"
    version = "clamd"
    cost = "slow"

    def __init__(self, cfg: dict):
        self.cfg = dict(cfg or {})
        self.socket_path = str(cfg_get(self.cfg, "engines.clamav.socket", "/var/run/clamav/clamd.ctl"))
        self.timeout_sec = float(cfg_get(self.cfg, "engines.clamav.timeout_sec", 30) or 30)
        chunk_kb = int(cfg_get(self.cfg, "engines.clamav.chunk_kb", 1024) or 1024)
        self.chunk_bytes = max(1, chunk_kb) * 1024
        self.backoff_sec = float(cfg_get(self.cfg, "engines.clamav.unavailable_backoff_sec", 60) or 0)
        max_size_mb = int(cfg_get(self.cfg, "engines.max_size_mb", 100) or 100)
        self.max_size = max(1, max_size_mb) * 1024 * 1024
        self._down_until = 0.0
        self._lock = threading.Lock()
        self.last_error: str | None = None

    # ------------------------------------------------------------ 探活/熔断
    def _socket_ready(self) -> bool:
        try:
            return Path(self.socket_path).exists() or os.path.exists(self.socket_path)
        except OSError:
            return False

    def _mark_down(self, reason: str) -> None:
        with self._lock:
            self.last_error = reason
            self._down_until = time.time() + max(0.0, self.backoff_sec)
        log.warn("ClamAV 熔断", reason=reason, backoff_sec=self.backoff_sec)

    def ping(self) -> bool:
        """对已配置 socket 做一次 PING 探活。"""
        return ping(self.socket_path, timeout=2)

    def available(self) -> bool:
        with self._lock:
            if time.time() < self._down_until:
                return False
        if not self._socket_ready():
            self._mark_down(f"socket 不存在: {self.socket_path}")
            return False
        if not self.ping():
            self._mark_down("PING 失败")
            return False
        with self._lock:
            self.last_error = None
        return True

    # ------------------------------------------------------------ 协议
    def supports(self, ctx: dict) -> bool:
        """只对 deep 扫描且 ≤ max_size 的文件生效。"""
        ctx = dict(ctx or {})
        if not ctx.get("deep"):
            return False
        size = ctx.get("size")
        try:
            return size is None or int(size) <= self.max_size
        except (TypeError, ValueError):
            return True

    def scan(self, path: str, ctx: dict) -> list[dict]:
        """INSTREAM 扫描；失败时熔断并把异常抛给级联隔离。"""
        ctx = dict(ctx or {})
        if not self.supports(ctx):
            return []
        try:
            return scan_stream(
                self.socket_path, path,
                timeout=self.timeout_sec, chunk=self.chunk_bytes,
            )
        except (OSError, socket.timeout, RuntimeError) as exc:
            self._mark_down(f"扫描失败: {exc}")
            raise
