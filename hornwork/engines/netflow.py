"""网络 flow 表。

职责：
- 把解码后的 Packet 字典归并成双向 flow（同一连接的两个方向算一条流）；
- 维护 first_ts/last_ts/packets/bytes 以及 syn/ack/rst 计数；
- 支持按空闲时间老化（age）与容量淘汰（evict）。

实现说明：
- flow key 做**双向归一**：比较 (src_ip, src_port) 与 (dst_ip, dst_port) 的字典序，
  小的放前面，保证 A→B 与 B→A 落在同一个 key；
- 不依赖任何 Linux 专属 API，Windows 开发机可安全 import（纯标准库）。
"""

from __future__ import annotations

import threading
import time
from typing import Any, Iterable

from ..log import get_logger

log = get_logger("engines.netflow")

# ---------------------------------------------------------------------------
# TCP flag 位定义（与采集层 netdecode.FLAG_* 保持一致）
# ---------------------------------------------------------------------------
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
FLAG_ECE = 0x40
FLAG_CWR = 0x80

FLAG_BITS: dict[str, int] = {
    "fin": FLAG_FIN,
    "syn": FLAG_SYN,
    "rst": FLAG_RST,
    "psh": FLAG_PSH,
    "ack": FLAG_ACK,
    "urg": FLAG_URG,
    "ece": FLAG_ECE,
    "cwr": FLAG_CWR,
}

# 规则里可能出现的别名（N-0102 的 XMAS 扫描用 fin/psh/urg）
FLAG_ALIASES: dict[str, str] = {
    "f": "fin", "s": "syn", "r": "rst", "p": "psh", "a": "ack", "u": "urg",
}

_ZERO_TS = 0.0


def packet_ts(pkt: dict) -> float:
    """取 Packet 的时间戳并归一成 float epoch 秒。

    支持 float/int（采集层的首选形态）与 ISO8601 字符串（便于手工构造/回放）。
    取不到时返回 0.0，由调用方决定回退到 time.time()。
    """
    if not isinstance(pkt, dict):
        return _ZERO_TS
    raw = pkt.get("ts")
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str) and raw:
        try:
            from datetime import datetime, timezone

            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except (ValueError, OSError):
            return _ZERO_TS
    return _ZERO_TS


def parse_flags_set(flags: Any) -> set[str]:
    """把 Packet.flags 归一成 flag 名字集合。

    - int：按 TCP 位定义展开；
    - str：'syn' / 'syn,ack' / '0x12'；
    - 可迭代对象（set/list/tuple）：逐项转小写并做别名归一。
    """
    out: set[str] = set()
    if isinstance(flags, bool) or flags is None:
        return out
    if isinstance(flags, int):
        for name, bit in FLAG_BITS.items():
            if flags & bit:
                out.add(name)
        return out
    if isinstance(flags, str):
        text = flags.strip().lower()
        if not text:
            return out
        if text.startswith("0x"):
            try:
                return parse_flags_set(int(text, 16))
            except ValueError:
                return out
        for part in text.replace("|", ",").split(","):
            name = FLAG_ALIASES.get(part.strip(), part.strip())
            if name in FLAG_BITS:
                out.add(name)
        return out
    if isinstance(flags, Iterable):
        for item in flags:
            if isinstance(item, str):
                name = FLAG_ALIASES.get(item.strip().lower(), item.strip().lower())
                if name in FLAG_BITS:
                    out.add(name)
            elif isinstance(item, int) and not isinstance(item, bool):
                out |= parse_flags_set(item)
    return out


def flow_endpoints(pkt: dict) -> tuple[str, int, str, int]:
    """返回 (src_ip, src_port, dst_ip, dst_port)，端口统一 int（缺失记 0）。"""
    def _port(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    return (
        str(pkt.get("src_ip") or ""),
        _port(pkt.get("src_port")),
        str(pkt.get("dst_ip") or ""),
        _port(pkt.get("dst_port")),
    )


class FlowTable:
    """双向 flow 状态表（默认 20 万条容量、120 s 空闲老化）。"""

    def __init__(self, max_flows: int = 200000, timeout: float = 120):
        self.max_flows = max(1, int(max_flows))
        self.timeout = float(timeout)
        self.flows: dict[tuple, dict] = {}
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- key
    def key(self, pkt: dict) -> tuple:
        """双向归一后的 flow key：(proto, a_ip, a_port, b_ip, b_port)。"""
        src_ip, src_port, dst_ip, dst_port = flow_endpoints(pkt)
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        first, second = (a, b) if a <= b else (b, a)
        proto = str(pkt.get("proto") or "ip").lower()
        return (proto, first[0], first[1], second[0], second[1])

    # ---------------------------------------------------------------- update
    def update(self, pkt: dict) -> dict:
        """把包计入 flow 并返回该 flow 状态（首次出现时创建）。"""
        if not isinstance(pkt, dict):
            raise TypeError("pkt must be dict")
        k = self.key(pkt)
        ts = packet_ts(pkt)
        if ts <= 0:
            ts = time.time()
        ip_len = pkt.get("ip_len")
        if not isinstance(ip_len, (int, float)) or ip_len <= 0:
            ip_len = pkt.get("raw_len") or 0
        flags = pkt.get("flags")

        with self._lock:
            st = self.flows.get(k)
            if st is None:
                st = {
                    "key": k,
                    "proto": k[0],
                    "src_ip": pkt.get("src_ip"),
                    "dst_ip": pkt.get("dst_ip"),
                    "first_ts": ts,
                    "last_ts": ts,
                    "packets": 0,
                    "bytes": 0,
                    "syn": 0,
                    "ack": 0,
                    "rst": 0,
                }
                self.flows[k] = st
                if len(self.flows) > self.max_flows:
                    self.evict()
            st["packets"] += 1
            st["bytes"] += int(ip_len or 0)
            if isinstance(flags, int) and not isinstance(flags, bool):
                if flags & FLAG_SYN and not flags & FLAG_ACK:
                    st["syn"] += 1
                if flags & FLAG_RST:
                    st["rst"] += 1
                if flags & FLAG_ACK:
                    st["ack"] += 1
            elif flags is not None:
                names = parse_flags_set(flags)
                st["syn"] += 1 if ("syn" in names and "ack" not in names) else 0
                st["rst"] += 1 if "rst" in names else 0
                st["ack"] += 1 if "ack" in names else 0
            if ts > st["last_ts"]:
                st["last_ts"] = ts
            if ts < st["first_ts"]:
                st["first_ts"] = ts
            return st

    # ---------------------------------------------------------------- 老化/淘汰
    def evict(self, ratio: float = 0.1) -> int:
        """按 last_ts 最旧删除 ratio 比例的 flow，返回删除条数。"""
        with self._lock:
            total = len(self.flows)
            if total <= 0:
                return 0
            count = max(1, int(total * max(0.0, min(1.0, float(ratio)))))
            count = min(count, total)
            oldest = sorted(self.flows.items(), key=lambda kv: kv[1].get("last_ts", 0.0))[:count]
            for k, _st in oldest:
                self.flows.pop(k, None)
            return count

    def age(self, now: float | None = None) -> int:
        """清理空闲超过 timeout 的 flow，返回删除条数。"""
        now_ts = time.time() if now is None else float(now)
        cutoff = now_ts - self.timeout
        removed = 0
        with self._lock:
            for k in [k for k, st in self.flows.items() if st.get("last_ts", 0.0) < cutoff]:
                self.flows.pop(k, None)
                removed += 1
        return removed

    # ---------------------------------------------------------------- 查询
    def get(self, pkt: dict) -> dict | None:
        with self._lock:
            return self.flows.get(self.key(pkt))

    def stats(self) -> dict:
        with self._lock:
            return {"flows": len(self.flows), "max_flows": self.max_flows, "timeout": self.timeout}

    def __len__(self) -> int:
        return len(self.flows)
