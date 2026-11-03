"""控制面：Unix socket 上的单行 JSON-RPC 服务器。

协议：客户端写一行 JSON 请求 {"id","method","params"}，服务端回一行
{"id","ok":true,"result":{...}} 或 {"id","ok":false,"error":{...}}。
每个连接一个线程，避免慢操作（扫描/验证/取证）堵塞其他命令。
"""

from __future__ import annotations

import json
import os
import socket
import stat
import threading
from pathlib import Path
from typing import Any, Callable

from .log import get_logger

Handler = Callable[[dict], Any]


class CtlError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False, detail: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.detail = detail

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "detail": self.detail,
        }


class CtlServer:
    def __init__(
        self,
        socket_path: str | Path,
        handlers: dict[str, Handler],
        mode: int = 0o660,
        group: str | None = None,
    ):
        self.path = Path(str(socket_path))
        self.handlers = handlers
        self.mode = int(mode)
        self.group = group
        self.log = get_logger("ctl")
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self.stats = {"requests": 0, "errors": 0, "started_at": None}

    # ------------------------------------------------------------------ 生命周期
    def start(self) -> None:
        if os.name != "posix":
            self.log.warn("ctl socket 仅支持 Linux，已跳过")
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if self.path.exists() or self.path.is_symlink():
                self.path.unlink()
        except OSError as exc:
            self.log.warn("删除旧 socket 失败", error=str(exc))
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.path))
        srv.listen(16)
        try:
            chmod = self.mode
            os.chmod(self.path, chmod)
        except OSError:
            pass
        if self.group:
            try:
                import grp

                gid = grp.getgrnam(self.group).gr_gid
                os.chown(self.path, -1, gid)
            except (KeyError, OSError, ImportError):
                self.log.warn("ctl socket 设置属组失败", group=self.group)
        self._sock = srv
        self._running = True
        self.stats["started_at"] = True  # 具体时间由 daemon status 提供
        self._thread = threading.Thread(target=self._accept_loop, name="ctl", daemon=True)
        self._thread.start()
        self.log.info("ctl socket 已启动", path=str(self.path))

    def stop(self) -> None:
        self._running = False
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        self._sock = None
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError:
            pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def status(self) -> dict:
        return {
            "enabled": os.name == "posix",
            "path": str(self.path),
            "running": self._running,
            "requests": self.stats["requests"],
            "errors": self.stats["errors"],
        }

    # ------------------------------------------------------------------ 循环
    def _accept_loop(self) -> None:
        while self._running and self._sock is not None:
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    def _serve_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(600)
            buf = b""
            while self._running:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    resp = self._handle_line(line)
                    conn.sendall(json.dumps(resp, ensure_ascii=False, default=str).encode() + b"\n")
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle_line(self, line: bytes) -> dict:
        self.stats["requests"] += 1
        req_id = None
        try:
            req = json.loads(line.decode("utf-8", "replace"))
            req_id = req.get("id")
            method = req.get("method", "")
            params = req.get("params") or {}
            handler = self.handlers.get(method)
            if handler is None:
                raise CtlError("method_not_found", f"unknown method: {method}")
            result = handler(params)
            return {"id": req_id, "ok": True, "result": result}
        except CtlError as exc:
            self.stats["errors"] += 1
            return {"id": req_id, "ok": False, "error": exc.to_dict()}
        except Exception as exc:  # noqa: BLE001 - 兜底转成 JSON 错误
            self.stats["errors"] += 1
            self.log.error("ctl handler 失败", error=str(exc))
            return {
                "id": req_id,
                "ok": False,
                "error": {"code": "internal", "message": str(exc), "retryable": False, "detail": None},
            }
