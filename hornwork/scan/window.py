"""扫描窗口门（IF-23 的消费侧）：让检测模块知道"这段扫描流量是自己人"。

问题：扫描器天然"同一源 IP 短时间连多端口/多主机"，与攻击者的
探测流量同构；如果不做治理，每次定期扫描都会让检测模块's 扫描类规则大量误报（自扰）。

治理原则（**只降级、不关规则**）：
1. 扫描器在运行前后各发一条 ``scan_window`` 事件（:mod:`hornwork.scan.runner`），
   字段固定：``phase/start/end/src_ips/dst_ips/window_sec/run_id/plan_id``；
2. 本模块在内存里维护"活跃窗口"缓存，由 daemon 的后台线程周期刷新（默认 10 s）；
3. 网络规则求值时，仅当 **规则属于扫描类 + 源 IP 属于本机 + 目标在本次窗口目标集**
   才跳过命中并计入 ``scan_window_suppressed``；
4. 窗口外（含同一 IP）照常告警——**降级不等于关闭**，起止时间与事件都留痕在 ``event`` 表。

这样检测模块的真实攻击检测能力不变，只是把"自己扫自己"从告警里摘出去。
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from ..config import cfg_get
from ..log import get_logger

log = get_logger("scan.window")

#: 默认只在窗口内降级的规则（扫描/横向类；IOC、恶意报文、外传等永远不降级）
DEFAULT_SUPPRESS_RULES = ("N-0101", "N-0102", "N-0104", "N-0105")


def parse_ts(value: Any) -> float | None:
    """ISO 时间串 → epoch 秒；失败返回 None。"""
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


class ScanWindowGate:
    """活跃扫描窗口缓存 + 命中抑制判定（线程安全，可在规则引擎热路径调用）。"""

    def __init__(self, store: Any, cfg: dict | None = None):
        self.store = store
        self.cfg = cfg or {}
        self.suppress_rules = {
            str(x).upper()
            for x in (cfg_get(self.cfg, "scan.window_suppress_rules", DEFAULT_SUPPRESS_RULES) or [])
        }
        self.refresh_sec = float(cfg_get(self.cfg, "scan.gates.window_refresh_sec", 10) or 10)
        self._lock = threading.RLock()
        self._windows: list[dict] = []
        self._last_refresh = 0.0
        self._refreshes = 0
        self._suppressed = 0

    # ------------------------------------------------------------------ 刷新
    def refresh(self, force: bool = False) -> dict:
        """从 ``event`` 表重新计算活跃窗口（默认 10 s 节流，失败保留旧缓存）。"""
        now = time.time()
        with self._lock:
            if not force and (now - self._last_refresh) < self.refresh_sec:
                return self.stats()
        try:
            events = self.store.query_events(event_type="scan_window", since="2h", limit=500)
        except Exception as exc:  # noqa: BLE001 - 窗口治理失败不能影响检测
            log.warn("scan.window.query_failed", error=str(exc))
            return self.stats()
        windows = self._build_windows(events, now)
        with self._lock:
            self._windows = windows
            self._last_refresh = now
            self._refreshes += 1
        return self.stats()

    @staticmethod
    def _payload_of(event: dict) -> dict:
        raw = event.get("raw")
        if isinstance(raw, dict):
            return raw
        # 事件被直接展平的情况（例如手工插入的示例），兜底取字段
        return {k: event.get(k) for k in ("phase", "start", "end", "src_ips", "dst_ips",
                                          "window_sec", "run_id", "plan_id")}

    def _build_windows(self, events: list[dict], now: float) -> list[dict]:
        starts: dict[str, dict] = {}
        ends: dict[str, float] = {}
        for event in events or []:
            payload = self._payload_of(event)
            run_id = str(payload.get("run_id") or event.get("event_id") or "")
            phase = str(payload.get("phase") or "")
            if phase == "start":
                start = parse_ts(payload.get("start")) or parse_ts(event.get("ts")) or now
                grace = float(payload.get("window_sec") or 600)
                starts[run_id] = {
                    "run_id": run_id,
                    "plan_id": payload.get("plan_id"),
                    "start": start,
                    "end": None,
                    "grace": grace,
                    "src_ips": [str(x) for x in (payload.get("src_ips") or [])],
                    "dst_ips": [str(x) for x in (payload.get("dst_ips") or [])],
                    "profile": payload.get("profile"),
                }
            elif phase == "end":
                end = parse_ts(payload.get("end")) or parse_ts(event.get("ts")) or now
                ends[run_id] = end
        windows: list[dict] = []
        for run_id, window in starts.items():
            end = ends.get(run_id)
            if end is None:
                end = window["start"] + window["grace"]
            window["end"] = end
            # 保留"刚结束 60 s 内"的窗口，避免边界包漏判
            if now <= end + 60:
                windows.append(window)
        return windows

    # ------------------------------------------------------------------ 判定
    def active_windows(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else float(now)
        with self._lock:
            # 结束事件是硬边界：窗口一旦收到 end 就不再降级（避免"扫完仍静默"）
            return [w for w in self._windows if w["start"] - 5 <= now <= w["end"]]

    def is_scan_traffic(self, src_ip: Any, dst_ip: Any, now: float | None = None) -> bool:
        """源/目标是否落在某个活跃窗口的自扫流量集合内。"""
        now = time.time() if now is None else float(now)
        src, dst = str(src_ip or ""), str(dst_ip or "")
        if not dst:
            return False
        for window in self.active_windows(now):
            src_ips = window.get("src_ips") or []
            dst_ips = window.get("dst_ips") or []
            if dst not in dst_ips:
                continue
            # 本机扫描时源地址可能是回环、本机网卡地址之一；允许"源=本机目标地址"
            if src in src_ips or src in dst_ips:
                return True
        return False

    def suppress(self, rule_id: str, src_ip: Any, dst_ip: Any,
                 now: float | None = None) -> bool:
        """规则是否应在当前扫描窗口内被降级（只对扫描类规则生效）。"""
        if str(rule_id).upper() not in self.suppress_rules:
            return False
        if not self.is_scan_traffic(src_ip, dst_ip, now):
            return False
        with self._lock:
            self._suppressed += 1
        return True

    # ------------------------------------------------------------------ 统计
    def stats(self) -> dict:
        with self._lock:
            now = time.time()
            active = [w for w in self._windows if w["start"] - 5 <= now <= w["end"]]
            return {
                "windows": len(self._windows),
                "active": len(active),
                "suppressed": self._suppressed,
                "refreshes": self._refreshes,
                "last_refresh": self._last_refresh,
                "suppress_rules": sorted(self.suppress_rules),
                "active_runs": [w.get("run_id") for w in active],
            }

    def reset(self) -> None:
        with self._lock:
            self._windows = []
            self._last_refresh = 0.0
            self._refreshes = 0
            self._suppressed = 0
