"""结构化日志：JSONL 输出到 stderr 与（可选）滚动文件。

不依赖第三方库。每行一个 JSON 对象，字段：ts/level/logger/msg/额外键。
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    """UTC ISO8601，毫秒精度，带 Z 后缀（全链路统一口径）。"""
    return (
        datetime.now(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        + "Z"
    )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": utc_now_iso(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, val in getattr(record, "extra_fields", {}).items():
            payload[key] = val
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class _RotatingFile:
    """极简轮转写入器：单文件超限即改名为 .1（删旧 .5），线程安全。"""

    def __init__(self, path: str, max_bytes: int = 50 * 1024 * 1024, backups: int = 5):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a", encoding="utf-8")

    def write(self, line: str) -> None:
        with self._lock:
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
                if self.path.stat().st_size >= self.max_bytes:
                    self._rotate()
            except OSError:
                pass

    def _rotate(self) -> None:
        try:
            self._fh.close()
            for i in range(self.backups - 1, 0, -1):
                src = self.path.with_name(f"{self.path.name}.{i}")
                dst = self.path.with_name(f"{self.path.name}.{i + 1}")
                if src.exists():
                    os.replace(src, dst)
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        finally:
            self._fh = open(self.path, "a", encoding="utf-8")


class _FileHandler(logging.Handler):
    def __init__(self, writer: _RotatingFile):
        super().__init__()
        self.writer = writer

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.writer.write(self.format(record))
        except Exception:  # noqa: BLE001 - 日志失败不得影响主流程
            pass


def setup_logging(level: str = "INFO", jsonl_path: str | None = None) -> None:
    """初始化根日志：stderr(JSON) + 可选文件(JSONL)。可重复调用。"""
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(JsonFormatter())
    root.addHandler(stream)

    if jsonl_path:
        try:
            writer = _RotatingFile(jsonl_path)
            fh = _FileHandler(writer)
            fh.setFormatter(JsonFormatter())
            root.addHandler(fh)
        except OSError:
            pass


class Logger:
    """轻量封装：`log.info("msg", key=value)` → JSON 额外字段。"""

    def __init__(self, name: str):
        self._log = logging.getLogger(name)

    def _emit(self, level: str, msg: str, **fields: Any) -> None:
        record = self._log.makeRecord(
            self._log.name, getattr(logging, level), "(hornwork)", 0, msg, (), None
        )
        record.extra_fields = fields
        self._log.handle(record)

    def debug(self, msg: str, **fields: Any) -> None:
        if self._log.isEnabledFor(logging.DEBUG):
            self._emit("DEBUG", msg, **fields)

    def info(self, msg: str, **fields: Any) -> None:
        if self._log.isEnabledFor(logging.INFO):
            self._emit("INFO", msg, **fields)

    def warn(self, msg: str, **fields: Any) -> None:
        if self._log.isEnabledFor(logging.WARNING):
            self._emit("WARNING", msg, **fields)

    warning = warn

    def error(self, msg: str, **fields: Any) -> None:
        if self._log.isEnabledFor(logging.ERROR):
            self._emit("ERROR", msg, **fields)

    def exception(self, msg: str, **fields: Any) -> None:
        if self._log.isEnabledFor(logging.ERROR):
            self._emit("ERROR", msg, **fields)


def get_logger(name: str) -> Logger:
    return Logger(name)
