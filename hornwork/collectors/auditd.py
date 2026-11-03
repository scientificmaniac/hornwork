"""auditd 采集器：tail 跟随 + inode 轮转检测 + 按 `audit(ts:id)` 拼装。



- 逐行解析 `type=... msg=audit(<ts>:<id>) ...`；
- 同一 `audit_id` 的记录在 2 s 窗口内缓存、到点拼装（窗口可配
  `collect.auditd.assemble_window_ms`）；
- `EXECVE` 的 `a0..aN` 拼接 cmdline（无引号的十六进制参数会被解码），
  `PROCTITLE` 作为兜底；
- 映射：`syscall=59` → `process_create`；`key=hornwork_identity` → `file_modify`；
  `key=hornwork_persist` → `persist_item`；
- 日志不存在时每秒重试（记 WARN），轮转通过 inode 变化检测；
- 断点续读把 `(inode, offset)` 存入 store 的 `meta` 表（键 `audit:resume`）。

`parse_line()` / `assemble()` 是纯静态函数，可直接喂普通字符串做单测。
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import time
from typing import Any

from .. import schema
from ..log import get_logger
from . import BaseCollector

log = get_logger("collector.auditd")

#: execve / execveat 的系统调用号（x86_64 / arm64 中 execve 均为 59）
EXEC_SYSCALLS = {59, 322}

MAX_ARGS = 256
MAX_RECORDS_PER_AUDIT = 64
MAX_BUFFERED_AUDITS = 20000
SEEN_TTL_SEC = 120.0

#: key → 事件类型
KEY_EVENT_MAP = {
    "hornwork_identity": "file_modify",
    "hornwork_persist": "persist_item",
    "hornwork_tamper": "file_modify",
    "hornwork_exec": "process_create",
}

_AUDIT_ID_RE = re.compile(r"audit\((?P<ts>\d+(?:\.\d+)?):(?P<id>\d+)\)")
_TYPE_RE = re.compile(r"(?:^|\s)type=(?P<type>[A-Z0-9_]+)")
_KV_RE = re.compile(
    r'(?P<key>[A-Za-z0-9_\[\]]+)=(?P<val>"(?:[^"\\]|\\.)*"|\'[^\']*\'|\S+)'
)
_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _unquote(value: str) -> tuple[str, bool]:
    """去掉值两侧引号并反转义；返回 (值, 原本是否带引号)。"""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        inner = value[1:-1]
        if value[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner, True
    return value, False


def _decode_hex(value: str) -> str | None:
    """十六进制字符串 → UTF-8 文本；不是合法十六进制则返回 None。"""
    if not value or len(value) % 2 or not _HEX_RE.match(value):
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    return raw.decode("utf-8", "replace")


def _to_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


class AuditdCollector(BaseCollector):
    """auditd 日志采集器（daemon 线程跟随 + 拼装窗口）。"""

    name = "auditd"
    source_product = "hornwork-auditd"

    def __init__(
        self,
        cfg: dict | None,
        emit: Any,
        store: Any = None,
        emit_alert: Any = None,
        **kw: Any,
    ) -> None:
        super().__init__(cfg, emit, store, emit_alert, **kw)
        self.log_path = str(self.conf("collect.auditd.log_path", "/var/log/audit/audit.log"))
        self.window = float(self.conf("collect.auditd.assemble_window_ms", 2000)) / 1000.0
        self.poll = float(self.conf("collect.auditd.poll_interval_ms", 200)) / 1000.0
        keys = self.conf("collect.auditd.keys", []) or []
        self.keys = {str(k) for k in keys}

        self._fh: Any = None
        self._ino: int | None = None
        self._offset: int = 0
        self._resume_ino: int | None = None
        self._resume_off: int = 0
        self._resume_loaded = False
        self._last_save = 0.0
        self._last_missing_warn = 0.0
        self._buffer: dict[int, dict] = {}
        self._seen: dict[int, float] = {}
        self._alerts_sent: dict[str, float] = {}

    # ------------------------------------------------------------ 统计
    def _init_stats(self) -> dict[str, Any]:
        return {
            "lines": 0,
            "events": 0,
            "alerts": 0,
            "assembled": 0,
            "malformed": 0,
            "rotations": 0,
            "dropped": 0,
            "waiting": 0,
        }

    # ------------------------------------------------------------ 纯解析函数
    @staticmethod
    def parse_line(line: str) -> dict | None:
        """解析一行 audit 日志。

        返回 `{"type","ts","id","fields","_quoted"}`；非 audit 记录返回 None。
        `fields` 的值已去引号；`_quoted` 标记原值是否带引号（供 hex 判定）。
        """
        if not isinstance(line, str):
            return None
        text = line.strip()
        if not text or "type=" not in text:
            return None
        type_match = _TYPE_RE.search(text)
        id_match = _AUDIT_ID_RE.search(text)
        if type_match is None or id_match is None:
            return None

        fields: dict[str, str] = {}
        quoted: dict[str, bool] = {}
        for match in _KV_RE.finditer(text):
            key = match.group("key")
            if key in ("type", "node"):
                continue
            value, was_quoted = _unquote(match.group("val"))
            if key == "msg" and value.startswith("audit("):
                continue
            fields[key] = value
            quoted[key] = was_quoted
        try:
            ts = schema.to_utc(float(id_match.group("ts")))
        except ValueError:
            ts = schema.utc_now()
        return {
            "type": type_match.group("type"),
            "ts": ts,
            "id": int(id_match.group("id")),
            "fields": fields,
            "_quoted": quoted,
        }

    @staticmethod
    def _execve_args(record: dict) -> list[str]:
        """从 EXECVE 记录里拼装 argv（无引号十六进制参数会被解码）。"""
        fields = record.get("fields") or {}
        quoted = record.get("_quoted") or {}
        args: list[str] = []
        for index in range(MAX_ARGS):
            key = f"a{index}"
            if key not in fields:
                break
            value = str(fields[key])
            if not quoted.get(key):
                decoded = _decode_hex(value)
                if decoded is not None:
                    value = decoded
            args.append(value)
        return args

    @staticmethod
    def _proctitle(records: list[dict]) -> tuple[str | None, list[str]]:
        """PROCTITLE 兜底：返回 (整行字符串, 按 NUL 拆分的 argv)。"""
        for rec in records:
            value = (rec.get("fields") or {}).get("proctitle")
            if not value:
                continue
            text = _decode_hex(str(value))
            if text is None:
                text = str(value)
            parts = [p for p in text.split("\x00") if p]
            return text.replace("\x00", " ").strip() or None, parts
        return None, []

    @staticmethod
    def assemble(records: list[dict]) -> dict | None:
        """把同一 audit_id 的多条记录拼成半成品事件；无法映射时返回 None。"""
        valid = [r for r in records if isinstance(r, dict) and r.get("type")]
        if not valid:
            return None
        by_type: dict[str, list[dict]] = {}
        for rec in valid:
            by_type.setdefault(str(rec["type"]).upper(), []).append(rec)

        syscall_rec = (by_type.get("SYSCALL") or [{}])[0]
        sys_fields = dict(syscall_rec.get("fields") or {})
        execve_recs = by_type.get("EXECVE") or []
        path_recs = by_type.get("PATH") or []
        cwd_rec = (by_type.get("CWD") or [{}])[0]
        cwd = str((cwd_rec.get("fields") or {}).get("cwd") or "")

        argv = AuditdCollector._execve_args(execve_recs[0]) if execve_recs else []
        proctitle_text, proctitle_args = AuditdCollector._proctitle(valid)
        if not argv and proctitle_args:
            argv = proctitle_args

        audit_id = valid[0].get("id")
        ts = valid[0].get("ts") or schema.utc_now()
        syscall = _to_int(sys_fields.get("syscall"), -1)
        key = str(sys_fields.get("key") or "")
        if not key:
            for rec in valid:
                candidate = str((rec.get("fields") or {}).get("key") or "")
                if candidate:
                    key = candidate
                    break

        # ---- 文件路径（PATH 记录 name 可能是相对路径） --------------------
        paths: list[dict] = []
        for rec in path_recs:
            fields = rec.get("fields") or {}
            name = str(fields.get("name") or "")
            if not name:
                continue
            if not name.startswith("/") and cwd:
                # audit 日志里的路径永远是 POSIX 语义，不能用 os.path.join（Windows 会出反斜杠）
                name = posixpath.join(cwd, name)
            paths.append(
                {
                    "path": name,
                    "inode": _to_int(fields.get("inode")),
                    "nametype": fields.get("nametype"),
                    "mode": fields.get("mode"),
                }
            )
        primary_path = paths[0]["path"] if paths else None

        cmdline = " ".join(argv) if argv else (proctitle_text or None)
        exe = str(sys_fields.get("exe") or "")
        if exe.endswith(" (deleted)"):
            exe = exe[: -len(" (deleted)")]
        image = exe or (argv[0] if argv else None)

        # ---- 事件类型映射 -------------------------------------------------
        if key in KEY_EVENT_MAP:
            event_type = KEY_EVENT_MAP[key]
        elif syscall in EXEC_SYSCALLS:
            event_type = "process_create"
        elif primary_path:
            event_type = "file_modify"
        else:
            return None

        process: dict[str, Any] = {}
        if event_type == "process_create" or sys_fields:
            for name_, field in (
                ("pid", "pid"),
                ("ppid", "ppid"),
                ("uid", "uid"),
                ("comm", "comm"),
                ("tty", "tty"),
                ("success", "success"),
                ("exit", "exit"),
            ):
                if field in sys_fields:
                    raw_value = sys_fields[field]
                    process[name_] = (
                        _to_int(raw_value) if field in ("pid", "ppid", "uid", "exit") else raw_value
                    )
            if image:
                process["image"] = image
            if cmdline:
                process["cmdline"] = cmdline

        file_info: dict[str, Any] | None = None
        if primary_path:
            file_info = {"path": primary_path, "action": "modify"}
            for candidate in paths:
                for name_, field in (("inode", "inode"), ("mode", "mode"), ("nametype", "nametype")):
                    if candidate.get(field) is not None:
                        file_info.setdefault(name_, candidate[field])

        user = {"uid": process.get("uid")} if process.get("uid") is not None else None

        rule_id = f"AUD-{key}" if key else f"AUD-SYSCALL-{syscall}"
        rule = {
            "id": rule_id,
            "name": key or f"syscall {syscall}",
            "engine": "auditd",
            "version": "1.0",
            "level": 5,
            "mitre": [],
            "raw": {
                "audit_id": audit_id,
                "types": sorted(by_type),
                "syscall": syscall,
                "key": key,
            },
        }
        raw = {
            "collector": "auditd",
            "audit_id": audit_id,
            "types": sorted(by_type),
            "key": key,
            "syscall": syscall,
            "arch": sys_fields.get("arch"),
            "success": sys_fields.get("success"),
            "exit": sys_fields.get("exit"),
            "cwd": cwd or None,
            "exe": exe or None,
            "comm": sys_fields.get("comm"),
            "proctitle": proctitle_text,
            "paths": [p["path"] for p in paths][:8],
        }
        return {
            "event_type": event_type,
            "ts": ts,
            "process": process or None,
            "file": file_info,
            "user": user,
            "rule": rule,
            "raw": raw,
        }

    # ------------------------------------------------------------ 线程循环
    def _run(self) -> None:
        log.info("auditd 开始跟随日志", path=self.log_path)
        self._load_resume()
        try:
            while not self.stopping:
                if self._ensure_open():
                    try:
                        self._read_available()
                    except OSError as exc:
                        self.error("读取 audit 日志失败", exc=repr(exc))
                        self._close()
                self._flush_expired()
                self._save_resume(force=False)
                self.sleep(self.poll if self._fh is not None else 1.0)
        finally:
            self._flush_expired(force=True)
            self._save_resume(force=True)
            self._close()

    def _ensure_open(self) -> bool:
        """确保日志句柄有效并处理轮转；文件缺失返回 False（1 s 后重试）。"""
        try:
            stat = os.stat(self.log_path)
        except OSError:
            self._close()
            self.stat_set("waiting", 1)
            now = time.time()
            if now - self._last_missing_warn > 10.0:
                self._last_missing_warn = now
                self.error("audit 日志不存在，1s 后重试", path=self.log_path)
            return False

        if self._fh is not None and self._ino == stat.st_ino:
            self.stat_set("waiting", 0)
            return True

        if self._fh is not None and self._ino is not None and self._ino != stat.st_ino:
            self.stat_add("rotations")
            log.info("audit 日志轮转", old_inode=self._ino, new_inode=stat.st_ino)
        self._close()
        try:
            handle = open(self.log_path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            self.error("打开 audit 日志失败", path=self.log_path, exc=repr(exc))
            return False
        if self._resume_ino == stat.st_ino and 0 <= self._resume_off <= stat.st_size:
            start = self._resume_off
        else:
            start = stat.st_size  # 首次打开/轮转后从新文件末尾跟
        try:
            handle.seek(start)
        except OSError:
            start = 0
        self._fh = handle
        self._ino = stat.st_ino
        self._offset = start
        self.stat_set("waiting", 0)
        log.info("audit 日志已打开", path=self.log_path, inode=self._ino, offset=start)
        return True

    def _read_available(self, budget: int = 5000) -> int:
        """读取当前可读的完整行；返回本次读到的行数。"""
        handle = self._fh
        if handle is None:
            return 0
        count = 0
        while count < budget:
            pos = handle.tell()
            try:
                line = handle.readline()
            except (OSError, UnicodeDecodeError) as exc:
                self.error("auditd 读取行失败", exc=repr(exc))
                break
            if not line:
                break
            if not line.endswith("\n"):
                # 半行：回退，等下一次读
                handle.seek(pos)
                break
            self._offset = handle.tell()
            count += 1
            self.stat_add("lines")
            self._handle_line(line.rstrip("\r\n"))
        return count

    def _handle_line(self, line: str) -> None:
        try:
            record = self.parse_line(line)
        except Exception as exc:  # noqa: BLE001 - 单行失败不得影响采集
            self.stat_add("malformed")
            self.error("auditd 行解析异常", exc=repr(exc))
            return
        if record is None:
            self.stat_add("malformed")
            return
        audit_id = int(record["id"])
        slot = self._buffer.get(audit_id)
        if slot is None:
            if len(self._buffer) >= MAX_BUFFERED_AUDITS:
                self._flush_expired(force=True)
                if len(self._buffer) >= MAX_BUFFERED_AUDITS:
                    self.stat_add("dropped")
                    return
            slot = {"records": [], "deadline": time.monotonic() + self.window}
            self._buffer[audit_id] = slot
        if len(slot["records"]) < MAX_RECORDS_PER_AUDIT:
            slot["records"].append(record)

    def _flush_expired(self, force: bool = False) -> None:
        now = time.monotonic()
        for audit_id, slot in list(self._buffer.items()):
            if not force and slot["deadline"] > now:
                continue
            self._buffer.pop(audit_id, None)
            try:
                self._emit_assembled(audit_id, slot["records"])
            except Exception as exc:  # noqa: BLE001
                self.stat_add("dropped")
                self.error("auditd 拼装/投递失败", audit_id=audit_id, exc=repr(exc))
        # 清理去重表
        expire = time.time() - SEEN_TTL_SEC
        for audit_id in [k for k, v in self._seen.items() if v < expire]:
            self._seen.pop(audit_id, None)

    def _emit_assembled(self, audit_id: int, records: list[dict]) -> None:
        if audit_id in self._seen:
            return
        self._seen[audit_id] = time.time()
        assembled = self.assemble(records)
        self.stat_add("assembled")
        if not assembled:
            self.stat_add("dropped")
            return
        event = schema.new_event(
            assembled["event_type"],
            self.layer,
            self.source_product,
            self.cfg,
            ts=assembled.get("ts"),
            process=assembled.get("process"),
            file=assembled.get("file"),
            user=assembled.get("user"),
            rule=assembled.get("rule"),
            raw=assembled.get("raw"),
        )
        self.send(event)
        self.stat_add("events")
        if (assembled.get("raw") or {}).get("key") == "hornwork_tamper":
            self._alert_tamper(event)

    def _alert_tamper(self, event: dict) -> None:
        """审计规则被改写：直接告警（规则引擎之外兜底）。"""
        path = (event.get("file") or {}).get("path") or (event.get("raw") or {}).get("paths") or []
        mark = str(path[0] if isinstance(path, list) and path else path)
        now = time.time()
        if now - self._alerts_sent.get(mark, 0.0) < 60.0:
            return
        self._alerts_sent[mark] = now
        rule = schema.make_rule(
            "A-0101", "auditd 审计规则被篡改", "auditd", level=10, mitre=["T1562.001"]
        )
        alert = schema.new_alert(
            rule,
            event=event,
            entity={"src_ip": None},
            evidence=[{"path": mark, "audit_id": (event.get("raw") or {}).get("audit_id")}],
            confidence=80,
            dedup_extra=mark,
        )
        self.send_alert(alert)
        self.stat_add("alerts")

    # ------------------------------------------------------------ 断点续读
    def _load_resume(self) -> None:
        if self.store is None or self._resume_loaded:
            return
        self._resume_loaded = True
        try:
            raw = self.store.get_meta("audit:resume")
            if raw:
                data = json.loads(raw)
                self._resume_ino = int(data.get("inode")) if data.get("inode") is not None else None
                self._resume_off = int(data.get("offset") or 0)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            log.warn("auditd 断点续读信息无效", exc=repr(exc))

    def _save_resume(self, force: bool = False) -> None:
        if self.store is None or self._ino is None:
            return
        now = time.time()
        if not force and now - self._last_save < 5.0:
            return
        self._last_save = now
        try:
            self.store.set_meta(
                "audit:resume", json.dumps({"inode": self._ino, "offset": self._offset})
            )
        except Exception as exc:  # noqa: BLE001
            log.warn("auditd 断点续读写入失败", exc=repr(exc))

    def _close(self) -> None:
        handle, self._fh = self._fh, None
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        self._ino = None
