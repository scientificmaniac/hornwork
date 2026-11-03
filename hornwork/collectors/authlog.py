"""认证日志采集：/var/log/auth.log 跟随或 `journalctl -u ssh -f` 子进程。



- 文件源：inode 轮转检测 + tail 跟随；
- journal 源：`journalctl -u <unit> -o cat -f -n 0`（子进程在函数内启动）；
- 正则解析 Failed / Invalid / Accepted / useradd 等；
- `BruteForceTracker`：同一 src_ip 在 300 s 内失败 ≥5 且随后成功 → level=12、T1110 告警。

`parse_line()` 与 `BruteForceTracker` 是纯逻辑，可在 Windows 上单测。
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

from .. import schema
from ..log import get_logger
from . import BaseCollector

log = get_logger("collector.authlog")

WINDOW_SEC = 300.0
THRESHOLD = 5
IP_PATTERN = r"[0-9a-fA-F.:]+"

_SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
_FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>" + IP_PATTERN + r")(?: port (?P<port>\d+))?"
)
_INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>" + IP_PATTERN + r")")
_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>" + IP_PATTERN + r")(?: port (?P<port>\d+))?"
)
_ACCOUNT_RE = re.compile(r"\b(?:useradd|usermod|userdel|groupadd|groupdel|adduser|addgroup)\b")
_ACCOUNT_USER_RES = (
    re.compile(r"new user: name=(?P<user>[^,\s]+)"),
    re.compile(r"user '(?P<user>[^']+)'"),
    re.compile(r"name=(?P<user>[^,\s]+)"),
    re.compile(r"for user (?P<user>\S+)"),
)
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_ts(line: str) -> str | None:
    """解析 "Oct 26 20:10:57" 前缀（syslog 无年份，按当前年份近似，视为 UTC）。"""
    match = _SYSLOG_TS_RE.match(line)
    if match is None:
        return None
    try:
        hour, minute, second = (int(x) for x in match.group("time").split(":"))
        dt = datetime(
            datetime.now(timezone.utc).year,
            _MONTHS[match.group("mon")],
            int(match.group("day")),
            hour,
            minute,
            second,
            tzinfo=timezone.utc,
        )
    except (KeyError, ValueError):
        return None
    return schema.to_utc(dt)


def _ts_to_epoch(ts: Any) -> float:
    """ISO 字符串/数值 → epoch 秒。"""
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return datetime.fromisoformat(
            schema.to_utc(ts).replace("Z", "+00:00")
        ).timestamp()
    except ValueError:
        return time.time()


def parse_line(line: str) -> dict | None:
    """解析一行认证日志。

    返回 `{"kind","user","src_ip","ts","raw"}`：
    kind ∈ `failed` / `accepted` / `account`；无法识别返回 None。
    """
    if not isinstance(line, str):
        return None
    text = line.strip()
    if not text:
        return None
    ts = _parse_syslog_ts(text) or schema.utc_now()
    raw = {"line": text[:1024]}

    match = _ACCEPTED_RE.search(text)
    if match:
        return {
            "kind": "accepted",
            "user": match.group("user"),
            "src_ip": match.group("ip"),
            "ts": ts,
            "raw": raw,
        }
    match = _FAILED_RE.search(text)
    if match:
        return {
            "kind": "failed",
            "user": match.group("user"),
            "src_ip": match.group("ip"),
            "ts": ts,
            "raw": raw,
        }
    match = _INVALID_RE.search(text)
    if match:
        return {
            "kind": "failed",
            "user": match.group("user"),
            "src_ip": match.group("ip"),
            "ts": ts,
            "raw": raw,
        }
    if _ACCOUNT_RE.search(text):
        user = None
        for pattern in _ACCOUNT_USER_RES:
            found = pattern.search(text)
            if found:
                user = found.group("user")
                break
        return {"kind": "account", "user": user, "src_ip": None, "ts": ts, "raw": raw}
    return None


class BruteForceTracker:
    """滑动窗口暴力破解判定：失败计数 ≥ 阈值后紧跟一次成功即触发。"""

    def __init__(self, threshold: int = THRESHOLD, window: float = WINDOW_SEC) -> None:
        self.threshold = max(1, int(threshold))
        self.window = max(1.0, float(window))
        self._fails: dict[str, list[float]] = {}
        self._last_cleanup = time.time()

    def add(self, ip: str, ts: Any, success: bool) -> dict | None:
        """记录一次认证结果；触发时返回告警描述 dict，否则 None。"""
        if not ip:
            return None
        now = _ts_to_epoch(ts)
        fails = [t for t in self._fails.get(ip, []) if now - t <= self.window]
        if not success:
            fails.append(now)
            self._fails[ip] = fails
            self._maybe_cleanup(now)
            return None

        # 成功登录：窗口内失败次数达标 → 判定为爆破成功
        self._fails.pop(ip, None)
        if len(fails) < self.threshold:
            return None
        return {
            "src_ip": ip,
            "failures": len(fails),
            "threshold": self.threshold,
            "window_sec": int(self.window),
            "first_ts": schema.to_utc(fails[0]),
            "last_ts": schema.to_utc(fails[-1]),
            "success_ts": schema.to_utc(now),
        }

    def counts(self) -> dict[str, int]:
        return {ip: len(v) for ip, v in self._fails.items() if v}

    def _maybe_cleanup(self, now: float) -> None:
        if now - self._last_cleanup < 60.0:
            return
        self._last_cleanup = now
        for ip in [ip for ip, ts in self._fails.items() if not ts or now - ts[-1] > self.window]:
            self._fails.pop(ip, None)


class AuthLogCollector(BaseCollector):
    """认证日志采集器（file 或 journal 两种源）。"""

    name = "authlog"
    source_product = "hornwork-auth"

    def __init__(
        self,
        cfg: dict | None,
        emit: Any,
        store: Any = None,
        emit_alert: Any = None,
        **kw: Any,
    ) -> None:
        super().__init__(cfg, emit, store, emit_alert, **kw)
        self.source = str(self.conf("collect.auth.source", "file")).lower()
        self.path = str(self.conf("collect.auth.path", "/var/log/auth.log"))
        self.journal_unit = str(self.conf("collect.auth.journal_unit", "ssh"))
        self.tracker = BruteForceTracker(
            int(self.conf("collect.auth.bruteforce_threshold", THRESHOLD)),
            float(self.conf("collect.auth.bruteforce_window_sec", WINDOW_SEC)),
        )
        self.poll = float(self.conf("collect.auth.poll_interval_ms", 300)) / 1000.0
        self._fh: Any = None
        self._ino: int | None = None
        self._journal: subprocess.Popen | None = None
        self._last_missing_warn = 0.0

    def _init_stats(self) -> dict[str, Any]:
        return {
            "lines": 0,
            "logon": 0,
            "logon_fail": 0,
            "account": 0,
            "alerts": 0,
            "malformed": 0,
            "rotations": 0,
            "waiting": 0,
        }

    # ------------------------------------------------------------ 生命周期
    def _run(self) -> None:
        if self.source == "journal":
            self._run_journal()
        else:
            self._run_file()

    def stop(self) -> None:
        journal = self._journal
        self._journal = None
        if journal is not None:
            try:
                journal.terminate()
            except OSError:
                pass
            try:
                journal.wait(timeout=1.0)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    journal.kill()
                except OSError:
                    pass
        super().stop()

    # ------------------------------------------------------------ journal 源
    def _run_journal(self) -> None:
        if not sys.platform.startswith("linux"):
            self.error("journal 源仅支持 Linux，authlog 不启动")
            return
        argv = ["journalctl", "-u", self.journal_unit, "-o", "cat", "-f", "-n", "0"]
        try:
            self._journal = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                errors="replace",
                bufsize=1,
            )
        except (OSError, ValueError) as exc:
            self.error("启动 journalctl 失败，authlog 降级停止", exc=repr(exc))
            return
        stream = self._journal.stdout
        log.info("authlog 开始跟随 journal", unit=self.journal_unit)
        try:
            while not self.stopping and stream is not None:
                line = stream.readline()
                if not line:
                    break
                self.stat_add("lines")
                self._handle_line(line.rstrip("\r\n"))
                if self.stopping:
                    break
        finally:
            journal, self._journal = self._journal, None
            if journal is not None:
                try:
                    journal.terminate()
                except OSError:
                    pass

    # ------------------------------------------------------------ 文件源
    def _run_file(self) -> None:
        log.info("authlog 开始跟随文件", path=self.path)
        try:
            while not self.stopping:
                if self._ensure_open():
                    try:
                        self._read_available()
                    except OSError as exc:
                        self.error("读取 auth 日志失败", exc=repr(exc))
                        self._close()
                self.sleep(self.poll if self._fh is not None else 1.0)
        finally:
            self._close()

    def _ensure_open(self) -> bool:
        try:
            stat = os.stat(self.path)
        except OSError:
            self._close()
            self.stat_set("waiting", 1)
            now = time.time()
            if now - self._last_missing_warn > 10.0:
                self._last_missing_warn = now
                self.error("auth 日志不存在，1s 后重试", path=self.path)
            return False
        if self._fh is not None and self._ino == stat.st_ino:
            self.stat_set("waiting", 0)
            return True
        rotated = self._fh is not None or self._ino is not None
        if rotated:
            self.stat_add("rotations")
        self._close()
        try:
            handle = open(self.path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            self.error("打开 auth 日志失败", path=self.path, exc=repr(exc))
            return False
        if not rotated:
            # 首次打开从文件末尾跟随；轮转后的新文件从头读
            handle.seek(0, os.SEEK_END)
        self._fh = handle
        self._ino = stat.st_ino
        self.stat_set("waiting", 0)
        return True

    def _read_available(self, budget: int = 5000) -> int:
        handle = self._fh
        if handle is None:
            return 0
        count = 0
        while count < budget:
            pos = handle.tell()
            try:
                line = handle.readline()
            except (OSError, UnicodeDecodeError) as exc:
                self.error("authlog 读取行失败", exc=repr(exc))
                break
            if not line:
                break
            if not line.endswith("\n"):
                handle.seek(pos)
                break
            count += 1
            self.stat_add("lines")
            self._handle_line(line.rstrip("\r\n"))
        return count

    def _close(self) -> None:
        handle, self._fh = self._fh, None
        self._ino = None
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass

    # ------------------------------------------------------------ 事件处理
    def _handle_line(self, line: str) -> None:
        try:
            parsed = parse_line(line)
        except Exception as exc:  # noqa: BLE001 - 单行失败隔离
            self.stat_add("malformed")
            self.error("authlog 行解析异常", exc=repr(exc))
            return
        if parsed is None:
            self.stat_add("malformed")
            return

        kind = parsed["kind"]
        try:
            event = self._build_event(parsed)
        except Exception as exc:  # noqa: BLE001
            self.stat_add("malformed")
            self.error("authlog 事件构造失败", exc=repr(exc))
            return
        self.send(event)
        if kind == "failed":
            self.stat_add("logon_fail")
        elif kind == "accepted":
            self.stat_add("logon")
        else:
            self.stat_add("account")

        if kind in ("failed", "accepted"):
            ip = parsed.get("src_ip") or ""
            if ip:
                info = self.tracker.add(ip, parsed["ts"], success=(kind == "accepted"))
                if info:
                    try:
                        self._alert_bruteforce(parsed, event, info)
                    except Exception as exc:  # noqa: BLE001
                        self.error("暴力破解告警构造失败", exc=repr(exc))

    def _build_event(self, parsed: dict) -> dict:
        kind = parsed["kind"]
        user = {"name": parsed.get("user")} if parsed.get("user") else None
        network = None
        if parsed.get("src_ip"):
            network = {
                "src_ip": parsed["src_ip"],
                "dst_port": 22,
                "proto": "tcp",
                "direction": "inbound",
            }
        event_type = {
            "failed": "logon_fail",
            "accepted": "logon",
            "account": "account_create",
        }.get(kind, "logon")
        raw = {"collector": "authlog", "kind": kind, "line": (parsed.get("raw") or {}).get("line")}
        return self.make_event(
            event_type, ts=parsed.get("ts"), user=user, network=network, raw=raw
        )

    def _alert_bruteforce(self, parsed: dict, event: dict, info: dict) -> None:
        rule = schema.make_rule(
            "A-0102", "SSH 暴力破解成功登录", "authlog", level=12, mitre=["T1110"]
        )
        evidence = [
            {
                "src_ip": info["src_ip"],
                "user": parsed.get("user"),
                "failures": info["failures"],
                "window_sec": info["window_sec"],
                "first_fail_ts": info["first_ts"],
                "last_fail_ts": info["last_ts"],
                "success_ts": info["success_ts"],
            }
        ]
        alert = schema.new_alert(
            rule,
            event=event,
            entity={"src_ip": info["src_ip"]},
            evidence=evidence,
            confidence=85,
            dedup_extra=parsed.get("user"),
        )
        self.send_alert(alert)
        self.stat_add("alerts")


__all__ = ["AuthLogCollector", "BruteForceTracker", "parse_line"]
