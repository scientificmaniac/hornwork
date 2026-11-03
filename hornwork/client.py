"""控制面客户端：hornworkctl 与 daemon 之间的一行 JSON-RPC。"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any


class CtlError(RuntimeError):
    def __init__(self, code: str, message: str, retryable: bool = False, detail: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.detail = detail


class CtlClient:
    def __init__(self, socket_path: str | Path, timeout: float = 600):
        self.path = Path(str(socket_path))
        self.timeout = float(timeout)

    def available(self) -> bool:
        return self.path.exists()

    def call(self, method: str, params: dict | None = None) -> Any:
        if not self.available():
            raise CtlError("daemon_down", f"控制 socket 不存在：{self.path}（daemon 未运行？）")
        req = {"id": 1, "method": method, "params": params or {}}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(str(self.path))
            sock.sendall(json.dumps(req, ensure_ascii=False).encode() + b"\n")
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        if not buf.strip():
            raise CtlError("bad_response", "daemon 无响应")
        resp = json.loads(buf.split(b"\n", 1)[0].decode("utf-8", "replace"))
        if not resp.get("ok"):
            err = resp.get("error") or {}
            raise CtlError(
                err.get("code", "error"),
                err.get("message", "unknown"),
                bool(err.get("retryable")),
                err.get("detail"),
            )
        return resp.get("result")
