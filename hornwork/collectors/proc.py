"""/proc 差分采集 + 连接表反查。



- 每 1 s 采样一次进程快照（`snapshot_procs`），与上一轮做集合差分；
- PID 复用通过 `starttime`（/proc/pid/stat 第 22 字段）识别，视为 created + exited；
- 解析 `/proc/net/tcp|tcp6|udp|udp6` 的十六进制地址/端口，扫 `/proc/*/fd`
  的 `socket:[inode]` 反查属主，产出 `net_connect` 事件（同一连接只发一次，带限流）；
- 非 Linux（或 `/proc` 不可用）时 `snapshot_procs()` 返回 `{}`，采集线程记录 WARN
  后退出，不会抛异常。
"""

from __future__ import annotations

import os
import socket
import sys
import time
from typing import Any

from .. import schema
from ..log import get_logger
from . import BaseCollector

log = get_logger("collector.proc")

#: /proc/net/tcp 的 st 字段（十六进制）→ 状态名
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

PROC_NET_FILES = (
    ("tcp", "tcp", False),
    ("tcp6", "tcp", True),
    ("udp", "udp", False),
    ("udp6", "udp", True),
)

#: 非监听/非通配的「已建立」状态，用于产出 net_connect
ACTIVE_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "LAST_ACK"}


def is_linux() -> bool:
    """当前是否运行在 Linux（且 /proc 可用）。"""
    return sys.platform.startswith("linux") and os.path.isdir("/proc")


# ---------------------------------------------------------------------------
# 快照与差分
# ---------------------------------------------------------------------------
def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _parse_proc_stat(text: str) -> dict[str, int] | None:
    """解析 /proc/pid/stat（comm 可能含空格/括号，用最后一个 ')' 切分）。"""
    end = text.rfind(")")
    if end < 0:
        return None
    head, tail = text[: text.find("(")], text[end + 2:]
    parts = tail.split()
    if len(parts) < 20:
        return None
    try:
        return {
            "ppid": int(parts[1]),
            "threads": int(parts[17]),
            "starttime": int(parts[19]),
            "state": parts[0],
        }
    except (ValueError, IndexError):
        return None


def _read_cmdline(path: str) -> str | None:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(4096)
    except OSError:
        return None
    if not raw:
        return None
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip() or None


def _read_uid(path: str) -> int | None:
    text = _read_text(path)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    return None
    return None


def _read_link(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def snapshot_procs() -> dict[int, dict]:
    """采集进程快照：{pid: {"pid","ppid","uid","threads","image","cmdline","starttime","state"}}。

    非 Linux 或 /proc 不可读时返回 `{}`（不抛异常），便于在 Windows 上单测。
    """
    if not is_linux():
        return {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return {}

    out: dict[int, dict] = {}
    for name in entries:
        if not name.isdigit():
            continue
        pid = int(name)
        base = f"/proc/{pid}"
        stat_text = _read_text(f"{base}/stat")
        if not stat_text:
            continue
        stat = _parse_proc_stat(stat_text)
        if stat is None:
            continue
        image = _read_link(f"{base}/exe")
        cmdline = _read_cmdline(f"{base}/cmdline")
        if image is None or cmdline is None:
            comm = _read_text(f"{base}/comm")
            comm = comm.strip() if comm else None
            if image is None:
                image = f"[{comm}]" if comm else None
        out[pid] = {
            "pid": pid,
            "ppid": stat["ppid"],
            "uid": _read_uid(f"{base}/status"),
            "threads": stat["threads"],
            "image": image,
            "cmdline": cmdline,
            "starttime": stat["starttime"],
            "state": stat["state"],
        }
    return out


def diff_procs(
    prev: dict[int, dict], cur: dict[int, dict]
) -> tuple[list[dict], list[dict], list[dict]]:
    """差分：返回 (created, exited, changed)；changed 表示 PID 被复用（starttime 变了）。"""
    prev_keys = set(prev or {})
    cur_keys = set(cur or {})
    created = [dict(cur[pid]) for pid in sorted(cur_keys - prev_keys)]
    exited = [dict(prev[pid]) for pid in sorted(prev_keys - cur_keys)]
    changed: list[dict] = []
    for pid in sorted(prev_keys & cur_keys):
        before = prev[pid]
        after = cur[pid]
        if before.get("starttime") != after.get("starttime"):
            changed.append(dict(after))
    return created, exited, changed


# ---------------------------------------------------------------------------
# 连接表
# ---------------------------------------------------------------------------
def _decode_addr(token: str, ipv6: bool) -> tuple[str, int]:
    """把 "0100007F:1F90" 这样的十六进制地址端口转成 (ip, port)。"""
    try:
        ip_hex, port_hex = token.split(":")
        port = int(port_hex, 16)
    except (ValueError, IndexError):
        return "", 0
    try:
        if ipv6:
            raw = b""
            for index in range(4):
                word = bytes.fromhex(ip_hex[index * 8:(index + 1) * 8])
                raw += word[::-1]
            return socket.inet_ntop(socket.AF_INET6, raw), port
        packed = bytes.fromhex(ip_hex)[::-1]
        return socket.inet_ntoa(packed), port
    except (ValueError, OSError):
        return "", 0


def read_connections() -> list[dict]:
    """解析 /proc/net/tcp|tcp6|udp|udp6。

    返回 `[{"proto","local_ip","local_port","remote_ip","remote_port","state","inode","v6"}]`。
    """
    if not is_linux():
        return []
    out: list[dict] = []
    for filename, proto, ipv6 in PROC_NET_FILES:
        text = _read_text(f"/proc/net/{filename}")
        if not text:
            continue
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            local_ip, local_port = _decode_addr(parts[1], ipv6)
            remote_ip, remote_port = _decode_addr(parts[2], ipv6)
            try:
                inode = int(parts[9])
            except ValueError:
                inode = 0
            state = TCP_STATES.get(parts[3].upper(), parts[3].upper()) if proto == "tcp" else "UDP"
            out.append(
                {
                    "proto": proto,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                    "inode": inode,
                    "v6": ipv6,
                }
            )
    return out


def socket_inode_owners() -> dict[str, list[int]]:
    """扫 /proc/*/fd 的 `socket:[inode]`，返回 {inode: [pid,...]}。"""
    if not is_linux():
        return {}
    try:
        entries = os.listdir("/proc")
    except OSError:
        return {}
    owners: dict[str, list[int]] = {}
    for name in entries:
        if not name.isdigit():
            continue
        pid = int(name)
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            target = _read_link(f"{fd_dir}/{fd}")
            if not target or not target.startswith("socket:["):
                continue
            inode = target[len("socket:["):-1]
            owners.setdefault(inode, []).append(pid)
    return owners


def _is_loopback(ip: str) -> bool:
    if not ip:
        return False
    if ip in ("0.0.0.0", "::", "::1", "127.0.0.1"):
        return True
    return ip.startswith("127.")


# ---------------------------------------------------------------------------
# 采集器
# ---------------------------------------------------------------------------
class ProcCollector(BaseCollector):
    """轮询 /proc 产出 process_create / process_exit / net_connect。"""

    name = "proc"
    source_product = "hornwork-proc"

    def __init__(
        self,
        cfg: dict | None,
        emit: Any,
        store: Any = None,
        emit_alert: Any = None,
        **kw: Any,
    ) -> None:
        super().__init__(cfg, emit, store, emit_alert, **kw)
        self.interval = max(0.2, float(self.conf("collect.proc.interval_ms", 1000)) / 1000.0)
        self.conn_scan = bool(self.conf("collect.proc.conn_scan", True))
        self.max_net_events = int(self.conf("collect.proc.max_net_events_per_round", 200))
        self._prev: dict[int, dict] | None = None
        self._seen_conns: dict[str, float] = {}
        self._listeners: set[tuple[str, str, int]] = set()
        self._conn_ttl = 600.0

    def _init_stats(self) -> dict[str, Any]:
        return {
            "created": 0,
            "exited": 0,
            "changed": 0,
            "net_connect": 0,
            "conns": 0,
            "unowned_sockets": 0,
            "net_dropped": 0,
        }

    # ------------------------------------------------------------ 线程循环
    def _run(self) -> None:
        if not is_linux():
            self.error("非 Linux 环境，proc 采集器不启动")
            return
        log.info("proc 采集器启动", interval=self.interval, conn_scan=self.conn_scan)
        while not self.stopping:
            started = time.monotonic()
            try:
                self._tick()
            except Exception as exc:  # noqa: BLE001 - 单轮失败不得终止线程
                self.error("proc 采样失败", exc=repr(exc))
            elapsed = time.monotonic() - started
            self.sleep(max(0.05, self.interval - elapsed))

    def _tick(self) -> None:
        current = snapshot_procs()
        if current or self._prev is not None:
            created, exited, changed = diff_procs(self._prev or {}, current)
            if self._prev is None:
                # 首轮只建立基线，避免一次性刷出全系统进程
                self.stat_set("baseline_pids", len(current))
            else:
                self._emit_proc_diff(created, exited, changed)
        self._prev = current
        if self.conn_scan:
            self._scan_connections()

    def _emit_proc_diff(
        self, created: list[dict], exited: list[dict], changed: list[dict]
    ) -> None:
        for info in created:
            self.stat_add("created")
            try:
                self._emit_proc_event("process_create", info)
            except Exception as exc:  # noqa: BLE001 - 单进程失败隔离
                self.error("process_create 事件构造失败", pid=info.get("pid"), exc=repr(exc))
        for info in exited:
            self.stat_add("exited")
            try:
                self._emit_proc_event("process_exit", info)
            except Exception as exc:  # noqa: BLE001
                self.error("process_exit 事件构造失败", pid=info.get("pid"), exc=repr(exc))
        for info in changed:
            # PID 复用：先退出旧进程，再按新进程处理
            self.stat_add("changed")
            try:
                self._emit_proc_event("process_exit", info, extra={"pid_reused": True})
                self._emit_proc_event("process_create", info, extra={"pid_reused": True})
            except Exception as exc:  # noqa: BLE001
                self.error("PID 复用事件构造失败", pid=info.get("pid"), exc=repr(exc))

    def _emit_proc_event(self, event_type: str, info: dict, extra: dict | None = None) -> None:
        process = {
            "pid": info.get("pid"),
            "ppid": info.get("ppid"),
            "uid": info.get("uid"),
            "image": info.get("image"),
            "cmdline": info.get("cmdline"),
            "threads": info.get("threads"),
            "state": info.get("state"),
            "starttime": info.get("starttime"),
        }
        raw = {"collector": "proc", "snapshot": True}
        raw.update(extra or {})
        event = schema.new_event(
            event_type,
            self.layer,
            self.source_product,
            self.cfg,
            process=process,
            raw=raw,
        )
        self.send(event)
        self.stat_add("events")

    # ------------------------------------------------------------ 连接扫描
    def _scan_connections(self) -> None:
        connections = read_connections()
        if not connections:
            return
        owners = socket_inode_owners()
        self.stat_set("conns", len(connections))

        listeners: set[tuple[str, str, int]] = set()
        for conn in connections:
            if conn.get("state") in ("LISTEN", "UDP"):
                listeners.add((conn["proto"], conn["local_ip"], conn["local_port"]))
        self._listeners = listeners

        emitted = 0
        now = time.time()
        for conn in connections:
            inode = conn.get("inode") or 0
            if not inode:
                continue
            if conn.get("remote_ip") in ("", "0.0.0.0", "::") and conn.get("remote_port", 0) == 0:
                continue
            if conn.get("state") not in ACTIVE_STATES:
                continue
            pids = owners.get(str(inode)) or []
            if not pids:
                self.stat_add("unowned_sockets")
                continue
            key = f"{conn['proto']}|{conn['local_ip']}:{conn['local_port']}|{conn['remote_ip']}:{conn['remote_port']}|{inode}"
            if key in self._seen_conns:
                continue
            if emitted >= self.max_net_events:
                self.stat_add("net_dropped")
                continue
            self._seen_conns[key] = now
            emitted += 1
            direction = (
                "inbound"
                if (conn["proto"], conn["local_ip"], conn["local_port"]) in listeners
                else "outbound"
            )
            try:
                self._emit_net_event(conn, pids[0], direction)
            except Exception as exc:  # noqa: BLE001 - 单连接失败隔离
                self.error("net_connect 事件构造失败", inode=inode, exc=repr(exc))

        expire = now - self._conn_ttl
        for key in [k for k, ts in self._seen_conns.items() if ts < expire]:
            self._seen_conns.pop(key, None)

    def _emit_net_event(self, conn: dict, pid: int, direction: str) -> None:
        process = None
        info = (self._prev or {}).get(pid)
        if info:
            process = {
                "pid": pid,
                "ppid": info.get("ppid"),
                "uid": info.get("uid"),
                "image": info.get("image"),
                "cmdline": info.get("cmdline"),
            }
        network = {
            "src_ip": conn.get("local_ip"),
            "src_port": conn.get("local_port"),
            "dst_ip": conn.get("remote_ip"),
            "dst_port": conn.get("remote_port"),
            "proto": conn.get("proto"),
            "direction": direction,
        }
        event = schema.new_event(
            "net_connect",
            self.layer,
            self.source_product,
            self.cfg,
            process=process,
            network=network,
            raw={
                "collector": "proc",
                "inode": conn.get("inode"),
                "state": conn.get("state"),
                "v6": conn.get("v6"),
            },
        )
        self.send(event)
        self.stat_add("net_connect")
        self.stat_add("events")


__all__ = [
    "ProcCollector",
    "snapshot_procs",
    "diff_procs",
    "read_connections",
    "socket_inode_owners",
    "is_linux",
]
