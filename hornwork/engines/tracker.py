"""分片滑窗统计器 Tracker。

用途：
- 给网络规则的"行为维度"提供窗口内聚合值：
  `count_distinct: dst_port/dst_ip`、`count: packets`、`sum_bytes`、`avg_interval_between`；
- 按 src 统计窗口内出现过的 distinct 目的端口 / 目的 IP；
- 记录 (src, dst) 的最后报文时间，供心跳类规则判断。

实现：把时间轴切成 `window/shards` 的片，每片一个 epoch；
写入时按 `epoch % shards` 定位分片，分片 epoch 变化即整体重置（O(1) 过期）；
查询时只统计 epoch 落在窗口内的分片。分片带来 ≤1 个分片的时间误差（文档允许，
阈值建议留 20% 余量）。所有方法线程安全。
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any

_MAX_TRACKED_PAIRS = 200000


def _pair_key(src: Any, dst: Any) -> tuple[str, str]:
    return (str(src or ""), str(dst or ""))


class Tracker:
    """分片滑窗聚合器。window 单位秒。"""

    def __init__(self, window: float = 5.0, shards: int = 5):
        self.window = float(window) if float(window or 0) > 0 else 5.0
        self.n = max(1, int(shards))
        self.span = self.window / self.n
        self._shards: list[dict] = [self._new_shard() for _ in range(self.n)]
        self._last: dict[tuple[str, str], float] = {}
        self._adds = 0
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- 内部
    @staticmethod
    def _new_shard(epoch: int = -1) -> dict:
        return {
            "epoch": epoch,
            # src -> {(dst_ip, dst_port), ...}
            "pairs": defaultdict(set),
            # (src, dst) -> 包数 / 字节数
            "counts": defaultdict(int),
            "bytes": defaultdict(int),
            # (src, dst) -> 窗口内首/末包时间
            "first": {},
            "last": {},
        }

    def _epoch(self, ts: float) -> int:
        return int(float(ts) // self.span)

    def _shard_for_write(self, ts: float) -> dict | None:
        epoch = self._epoch(ts)
        shard = self._shards[epoch % self.n]
        if shard["epoch"] == epoch:
            return shard
        if epoch > shard["epoch"]:
            # 分片整体翻滚：直接换新的空分片
            fresh = self._new_shard(epoch)
            self._shards[epoch % self.n] = fresh
            return fresh
        # 乱序/过旧的包：分片已被更新的 epoch 覆盖，丢弃（不污染新窗口）
        return None

    def _valid_shards(self, now: float) -> list[dict]:
        e = self._epoch(now)
        oldest = e - (self.n - 1)
        return [s for s in list(self._shards) if oldest <= s["epoch"] <= e]

    # ---------------------------------------------------------------- 写入
    def add(self, ts: float, src: str, dst: str, dport: Any) -> None:
        """记录一个报文（契约签名）。"""
        self.add_packet(ts, src, dst, dport, 0)

    def add_packet(self, ts: float, src: str, dst: str, dport: Any, nbytes: int = 0) -> None:
        """记录报文并可选累计字节数（供 sum_bytes 规则使用）。"""
        if ts is None:
            return
        try:
            ts_f = float(ts)
        except (TypeError, ValueError):
            return
        try:
            port = int(dport)
        except (TypeError, ValueError):
            port = 0
        src_s = str(src or "")
        dst_s = str(dst or "")
        with self._lock:
            shard = self._shard_for_write(ts_f)
            if shard is not None:
                shard["pairs"][src_s].add((dst_s, port))
                key = (src_s, dst_s)
                shard["counts"][key] += 1
                shard["bytes"][key] += max(0, int(nbytes or 0))
                if key not in shard["first"] or ts_f < shard["first"][key]:
                    shard["first"][key] = ts_f
                if key not in shard["last"] or ts_f > shard["last"][key]:
                    shard["last"][key] = ts_f
            key = (src_s, dst_s)
            self._last[key] = ts_f
            self._adds += 1
            if self._adds % 4096 == 0:
                self._prune_last(ts_f)

    def _prune_last(self, now: float) -> None:
        if len(self._last) <= _MAX_TRACKED_PAIRS:
            return
        cutoff = now - max(self.window * 10.0, 60.0)
        for key in [k for k, v in self._last.items() if v < cutoff]:
            self._last.pop(key, None)

    # ---------------------------------------------------------------- 查询
    def distinct_ports(self, now: float, src: str, dst: str) -> int:
        """窗口内 src→dst 出现过的 distinct 目的端口数。"""
        src_s, dst_s = str(src or ""), str(dst or "")
        ports: set[int] = set()
        with self._lock:
            for shard in self._valid_shards(float(now)):
                for d, p in shard["pairs"].get(src_s, ()):
                    if d == dst_s:
                        ports.add(p)
        return len(ports)

    def distinct_dsts(self, now: float, src: str, key: str = "dst_ip") -> int:
        """窗口内 src 出现过的 distinct 目的维度数。

        key: "dst_ip"（默认，distinct 目的 IP）或 "dst_port"（distinct 目的端口）。
        """
        src_s = str(src or "")
        mode = str(key or "dst_ip").lower()
        want_ports = mode in ("dst_port", "dport", "port", "dstport")
        values: set[Any] = set()
        with self._lock:
            for shard in self._valid_shards(float(now)):
                for d, p in shard["pairs"].get(src_s, ()):
                    values.add(p if want_ports else d)
        return len(values)

    def count_packets(self, now: float, src: str, dst: str) -> int:
        """窗口内 (src, dst) 的报文数。"""
        key = _pair_key(src, dst)
        total = 0
        with self._lock:
            for shard in self._valid_shards(float(now)):
                total += int(shard["counts"].get(key, 0))
        return total

    def sum_bytes(self, now: float, src: str, dst: str) -> int:
        """窗口内 (src, dst) 的累计字节数。"""
        key = _pair_key(src, dst)
        total = 0
        with self._lock:
            for shard in self._valid_shards(float(now)):
                total += int(shard["bytes"].get(key, 0))
        return total

    def window_span(self, now: float, src: str, dst: str) -> tuple[int, float | None, float | None]:
        """窗口内 (src, dst) 的 (包数, 首包时间, 末包时间)。"""
        key = _pair_key(src, dst)
        count = 0
        first: float | None = None
        last: float | None = None
        with self._lock:
            for shard in self._valid_shards(float(now)):
                count += int(shard["counts"].get(key, 0))
                f = shard["first"].get(key)
                l = shard["last"].get(key)
                if f is not None and (first is None or f < first):
                    first = f
                if l is not None and (last is None or l > last):
                    last = l
        return count, first, last

    def avg_interval(self, now: float, src: str, dst: str) -> float | None:
        """窗口内 (src, dst) 的平均报文间隔（秒）；少于 2 个包返回 None。"""
        count, first, last = self.window_span(now, src, dst)
        if count < 2 or first is None or last is None:
            return None
        span = max(0.0, float(last) - float(first))
        return span / float(count - 1)

    def last_packet_ts(self, src: str, dst: str) -> float | None:
        """(src, dst) 最后一次报文时间（epoch 秒），无记录返回 None。"""
        with self._lock:
            return self._last.get(_pair_key(src, dst))

    # ---------------------------------------------------------------- 运维
    def stats(self) -> dict:
        with self._lock:
            pairs = sum(len(s["counts"]) for s in self._shards)
            return {
                "window": self.window,
                "shards": self.n,
                "tracked_pairs": pairs,
                "last_entries": len(self._last),
            }

    def clear(self) -> None:
        with self._lock:
            self._shards = [self._new_shard() for _ in range(self.n)]
            self._last.clear()
