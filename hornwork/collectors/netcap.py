"""抓包 + flow + tracker + 网络规则一体化流水线（AF_PACKET，Linux 专属）。



- 抓包线程：`socket.AF_PACKET, SOCK_RAW, ETH_P_ALL`；`iface=any` 时同时抓 `lo`
  与默认路由网卡；`SO_RCVBUF` 可配；原始帧进有界队列，满时丢最旧并计数；
- 处理线程：`decode()` → `FlowTable.update()` → `Tracker.add()` →
  `NetRuleSet.evaluate(pkt, flow, tracker, now)` → hit 转 `schema.new_alert()` → `emit_alert`；
- DNS 查询名：`decode()` 已解出 `pkt["domain"]`，查询方向按
  `(src_ip, domain)` 5 s 去重限流 emit 一条 `dns_query` 事件，供 N-0103 IOC 域名命中；
- 新 flow 按 `flow_event_interval_sec` 限频发 `net_connect` 事件；
- 统计 received/decoded/dropped/errors，`status()` 同时给出 flow 表大小与 tracker 计数；
- `reload()` 重新加载网络规则与 IOC，供 daemon 的 `rules.reload` 调用；
- 非 Linux 或权限不足（无 CAP_NET_RAW）：`start()` 记 WARN 后返回，`running=False`。
"""

from __future__ import annotations

import queue
import socket
import sys
import threading
import time
from typing import Any

from .. import schema
from ..log import get_logger
from . import BaseCollector
from .netdecode import decode

log = get_logger("collector.netcap")

ETH_P_ALL = 0x0003


# ---------------------------------------------------------------------------
# 降级实现：engines.netflow / engines.tracker 尚未可用时保证流水线可运行
# ---------------------------------------------------------------------------
class _SimpleFlow:
    """极简 flow 表（与 FlowTable 同名接口的降级版）。"""

    def __init__(self, max_flows: int = 200000, timeout: float = 120.0) -> None:
        self.max_flows = int(max_flows)
        self.timeout = float(timeout)
        self.flows: dict[tuple, dict] = {}

    def key(self, pkt: dict) -> tuple:
        a = (pkt.get("src_ip"), pkt.get("src_port"))
        b = (pkt.get("dst_ip"), pkt.get("dst_port"))
        return (pkt.get("proto"),) + (a + b if a <= b else b + a)

    def update(self, pkt: dict) -> dict:
        key = self.key(pkt)
        state = self.flows.get(key)
        if state is None:
            state = {"first_ts": pkt.get("ts"), "packets": 0, "bytes": 0, "syn": 0, "ack": 0, "rst": 0}
            self.flows[key] = state
            if len(self.flows) > self.max_flows:
                self.evict()
        state["packets"] += 1
        state["bytes"] += int(pkt.get("ip_len") or 0)
        flags = int(pkt.get("flags") or 0)
        state["syn"] += 1 if flags & 0x02 and not flags & 0x10 else 0
        state["rst"] += 1 if flags & 0x04 else 0
        state["ack"] += 1 if flags & 0x10 else 0
        state["last_ts"] = pkt.get("ts")
        return state

    def evict(self, ratio: float = 0.1) -> int:
        ordered = sorted(self.flows.items(), key=lambda item: item[1].get("last_ts") or 0)
        count = max(1, int(len(ordered) * max(0.0, min(1.0, ratio))))
        for key, _ in ordered[:count]:
            self.flows.pop(key, None)
        return count

    def age(self, now: float | None = None) -> int:
        now = time.time() if now is None else float(now)
        dead = [k for k, v in self.flows.items() if now - (v.get("last_ts") or 0) > self.timeout]
        for key in dead:
            self.flows.pop(key, None)
        return len(dead)

    def __len__(self) -> int:
        return len(self.flows)


class _SimpleTracker:
    """极简滑窗 tracker（与 Tracker 同名接口的降级版）。"""

    def __init__(self, window: float = 5.0, shards: int = 5) -> None:
        self.window = max(0.1, float(window))
        self._lock = threading.Lock()
        self._items: dict[str, list[tuple[float, str, int]]] = {}

    def add(self, ts: float, src: str, dst: str, dport: int) -> None:
        with self._lock:
            items = self._items.setdefault(str(src), [])
            items.append((float(ts), str(dst), int(dport or 0)))
            cutoff = float(ts) - self.window
            while items and items[0][0] < cutoff:
                items.pop(0)
            if len(items) > 20000:
                del items[: len(items) - 20000]

    def _slice(self, now: float, src: str) -> list[tuple[float, str, int]]:
        cutoff = float(now) - self.window
        return [item for item in self._items.get(str(src), []) if item[0] >= cutoff]

    def distinct_ports(self, now: float, src: str, dst: str) -> int:
        with self._lock:
            return len({dport for _, d, dport in self._slice(now, src) if d == dst})

    def distinct_dsts(self, now: float, src: str, key: Any = None) -> int:
        mode = str(key or "dst_ip").lower()
        want_ports = mode in ("dst_port", "dport", "port", "dstport")
        with self._lock:
            items = self._slice(now, src)
            return len({dport if want_ports else dst for _, dst, dport in items})

    def last_packet_ts(self, src: str, dst: str) -> float | None:
        with self._lock:
            values = [ts for ts, d, _ in self._items.get(str(src), []) if d == dst]
        return max(values) if values else None


def _default_iface() -> str | None:
    """从 /proc/net/route 找默认路由网卡名。"""
    try:
        with open("/proc/net/route", "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[1] == "00000000":
            return parts[0]
    return None


def resolve_ifaces(iface: str) -> list[str]:
    """`any` → [lo, 默认网卡]；否则 [iface]。"""
    name = str(iface or "").strip()
    if name and name not in ("any", "*"):
        return [name]
    names: list[str] = []
    try:
        available = {item[1] for item in socket.if_nameindex()}
    except OSError:
        available = set()
    for candidate in ("lo", _default_iface()):
        if candidate and (not available or candidate in available) and candidate not in names:
            names.append(candidate)
    if not names:
        names = ["eth0"]
    return names


class NetPipeline(BaseCollector):
    """网络采集与规则匹配流水线。"""

    name = "netcap"
    layer = "net"
    source_product = "hornwork-netcap"

    def __init__(
        self,
        cfg: dict | None,
        emit_event: Any,
        emit_alert: Any,
        ioc_provider: Any = None,
        store: Any = None,
        scan_gate: Any = None,
    ) -> None:
        super().__init__(cfg, emit_event, store, emit_alert)
        self.iface = str(self.conf("collect.net.iface", "any"))
        self.snaplen = int(self.conf("collect.net.snaplen", 65535))
        self.rcvbuf = int(float(self.conf("collect.net.rcvbuf_mb", 8)) * 1024 * 1024)
        self.emit_flow_event = bool(self.conf("collect.net.emit_flow_event", True))
        self.flow_event_interval = max(
            0.0, float(self.conf("collect.net.flow_event_interval_sec", 5))
        )
        self.queue_max = int(self.conf("bus.frame_queue_max", 20000))
        self.max_flows = int(self.conf("net.max_flows", 200000))
        self.flow_timeout = float(self.conf("net.flow_timeout_sec", 120))
        self.tracker_window = float(self.conf("net.tracker_window_sec", 5))
        self.dedup_sec = float(self.conf("net.dedup_sec", 60))
        self.max_alerts_per_sec = int(self.conf("collect.net.max_alerts_per_sec", 50))
        self.dns_event_interval = max(
            0.0, float(self.conf("collect.net.dns_event_interval_sec", 5))
        )
        self.ioc_provider = ioc_provider
        #: 扫描模块扫描窗口门（IF-23）：窗口内自扫流量不触发扫描类告警
        self.scan_gate = scan_gate

        self._queue: queue.Queue = queue.Queue(maxsize=max(1024, self.queue_max))
        self._socks: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._flow: Any = None
        self._tracker: Any = None
        self._ruleset: Any = None
        self._flow_marks: dict[str, float] = {}
        self._alert_marks: dict[str, float] = {}
        self._dns_marks: dict[str, float] = {}
        self._alerts_second = 0
        self._second_mark = 0.0
        self._last_age = 0.0
        # 先建好 flow/tracker（纯 Python，可在非 Linux 上初始化），
        # 便于 status()/reload() 在没有抓包线程时也能给出统计。
        self._init_flow_tracker()

    def _init_stats(self) -> dict[str, Any]:
        return {
            "received": 0,
            "decoded": 0,
            "dropped": 0,
            "malformed": 0,
            "evaluations": 0,
            "flow_events": 0,
            "dns_events": 0,
            "dns_deduped": 0,
            "alerts": 0,
            "deduped": 0,
            "rules": 0,
            "flow_table_size": 0,
        }

    # ------------------------------------------------------------ 生命周期
    def start(self) -> None:
        if not sys.platform.startswith("linux"):
            self.error("AF_PACKET 仅支持 Linux，netcap 不启动")
            return
        if self._threads and any(t.is_alive() for t in self._threads):
            return
        self._stop_evt.clear()
        self._started_at = time.time()
        self._init_flow_tracker()
        self.reload()
        try:
            self._open_sockets()
        except OSError as exc:
            self.error("打开抓包 socket 失败（需要 root 或 CAP_NET_RAW）", exc=repr(exc))
            self._close_sockets()
            return
        if not self._socks:
            self.error("没有可用的抓包接口", iface=self.iface)
            return

        self._threads = []
        for sock in self._socks:
            thread = threading.Thread(
                target=self._capture_loop, args=(sock,), name="netcap-capture", daemon=True
            )
            self._threads.append(thread)
        processor = threading.Thread(target=self._process_loop, name="netcap-process", daemon=True)
        self._threads.append(processor)
        for thread in self._threads:
            thread.start()
        log.info("netcap 已启动", ifaces=[s.getsockname()[0] for s in self._socks])

    def stop(self) -> None:
        self._stop_evt.set()
        self._close_sockets()
        deadline = time.monotonic() + 3.0
        for thread in self._threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)
        self._threads = []

    def running(self) -> bool:
        return bool(
            not self._stop_evt.is_set()
            and self._threads
            and any(thread.is_alive() for thread in self._threads)
        )

    def status(self) -> dict:
        base = super().status()
        stats = base["stats"]
        try:
            stats["flow_table_size"] = len(self._flow) if self._flow is not None else 0
            stats["queue_size"] = self._queue.qsize()
            stats["rules_loaded"] = int(self._ruleset is not None)
            tracker_stats: dict = {}
            tracker_status = getattr(self._tracker, "stats", None)
            if callable(tracker_status):
                tracker_stats = dict(tracker_status() or {})
            stats["tracker"] = tracker_stats
            if "tracked_pairs" in tracker_stats:
                stats["tracker_hits"] = int(tracker_stats.get("tracked_pairs") or 0)
        except Exception:  # noqa: BLE001 - 状态查询不得影响主流程
            pass
        return base

    # ------------------------------------------------------------ 规则与表
    def _init_flow_tracker(self) -> None:
        try:
            from ..engines.netflow import FlowTable
            from ..engines.tracker import Tracker

            self._flow = FlowTable(max_flows=self.max_flows, timeout=self.flow_timeout)
            self._tracker = Tracker(window=self.tracker_window)
        except Exception as exc:  # noqa: BLE001 - 引擎层未就绪时降级
            log.warn("engines.netflow/tracker 不可用，使用内置降级实现", exc=repr(exc))
            self._flow = _SimpleFlow(max_flows=self.max_flows, timeout=self.flow_timeout)
            self._tracker = _SimpleTracker(window=self.tracker_window)

    def _build_ruleset(self) -> Any:
        from ..engines.netrules import NetRuleSet

        ruleset = NetRuleSet(self.cfg, ioc_provider=self.ioc_provider, store=self.store)
        if self.scan_gate is not None:
            try:
                ruleset.set_scan_gate(self.scan_gate)
            except Exception as exc:  # noqa: BLE001 - 联动失败不影响检测
                log.warn("注入扫描窗口门失败", exc=repr(exc))
        return ruleset

    def reload(self) -> dict:
        """重新加载网络规则与 IOC；返回 `{"ok","rules","errors"}`。"""
        errors: list[str] = []
        rules = 0
        try:
            if self._ruleset is None:
                self._ruleset = self._build_ruleset()
            result = self._ruleset.load() or {}
            if isinstance(result, dict):
                errors.extend(str(e) for e in (result.get("errors") or []))
                rules = int(result.get("rules") or 0)
            if not rules:
                try:
                    rules = len(self._ruleset.rules() or [])
                except Exception:  # noqa: BLE001
                    rules = 0
        except Exception as exc:  # noqa: BLE001 - 规则加载失败保留现状
            errors.append(f"{type(exc).__name__}: {exc}")
            self._ruleset = None
        self.stat_set("rules", rules)
        ok = not errors
        if not ok:
            log.warn("网络规则加载存在错误", rules=rules, errors=errors[:5])
        else:
            log.info("网络规则已加载", rules=rules)
        return {"ok": ok, "rules": rules, "errors": errors}

    # ------------------------------------------------------------ socket
    def _open_sockets(self) -> None:
        for name in resolve_ifaces(self.iface):
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
                sock.bind((name, 0))
                sock.settimeout(0.3)
            except OSError:
                sock.close()
                raise
            self._socks.append(sock)
            log.info("开始抓包", iface=name, rcvbuf=self.rcvbuf)

    def _close_sockets(self) -> None:
        for sock in self._socks:
            try:
                sock.close()
            except OSError:
                pass
        self._socks = []

    # ------------------------------------------------------------ 抓包线程
    def _capture_loop(self, sock: socket.socket) -> None:
        while not self.stopping:
            try:
                frame, _addr = sock.recvfrom(self.snaplen)
            except socket.timeout:
                continue
            except OSError:
                if self.stopping:
                    break
                self.error("recvfrom 失败，抓包线程退出")
                break
            self.stat_add("received")
            self._enqueue_frame(frame)

    def _enqueue_frame(self, frame: bytes) -> None:
        try:
            self._queue.put_nowait(frame)
            return
        except queue.Full:
            self.stat_add("dropped")
        # 队列满：丢最旧，避免阻塞抓包
        try:
            self._queue.get_nowait()
        except queue.Empty:
            pass
        try:
            self._queue.put_nowait(frame)
        except queue.Full:
            self.stat_add("dropped")

    # ------------------------------------------------------------ 处理线程
    def _process_loop(self) -> None:
        while not self.stopping:
            try:
                frame = self._queue.get(timeout=0.2)
            except queue.Empty:
                self._maintenance()
                continue
            try:
                self._process_frame(frame)
            except Exception as exc:  # noqa: BLE001 - 单帧失败隔离
                self.error("报文处理失败", exc=repr(exc))
            self._maintenance()
        # 退出前把队列里剩余帧处理完（限时）
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                frame = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._process_frame(frame)
            except Exception as exc:  # noqa: BLE001
                self.error("报文处理失败", exc=repr(exc))

    def process_frame(self, frame: bytes) -> None:
        """处理单帧（供单元测试 / PCAP 回放使用，绕过抓包 socket）。"""
        self._process_frame(frame)

    def _process_frame(self, frame: bytes) -> None:
        packet = decode(frame)
        if packet is None:
            self.stat_add("dropped")
            return
        self.stat_add("decoded")
        if packet.get("malformed"):
            self.stat_add("malformed")

        # DNS 查询名：查询方向产一条 dns_query 事件，响应不产事件；
        # packet["domain"] 同时交给 NetRuleSet.evaluate 供 N-0103 命中 IOC 域名。
        if packet.get("domain") and not packet.get("dns_is_response"):
            self._maybe_emit_dns(packet)

        flow = None
        if self._flow is not None:
            try:
                flow = self._flow.update(packet)
                self.stat_set("flow_table_size", len(self._flow))
            except Exception as exc:  # noqa: BLE001
                self.error("flow 表更新失败", exc=repr(exc))

        # 注意：行为窗口的写入由 NetRuleSet.evaluate() 内部完成（见 engines/netrules.py
        # 的 _tracker_for/add_packet），此处只负责把 tracker 传下去，避免重复计数。

        if self.emit_flow_event and flow is not None and flow.get("packets") == 1:
            self._maybe_emit_flow(packet, flow)

        # 只按查询方向命中 IOC 域名规则（N-0103）：响应包不把 QNAME 交给规则引擎，
        # 避免同一域名在"查询 + 响应"两个方向各告警一次。dns_query 事件已在此之前
        # 只对查询方向发出，不受影响。
        if packet.get("dns_is_response"):
            packet.pop("domain", None)
            packet.pop("dns_qtype", None)

        hits: list[dict] = []
        if self._ruleset is not None:
            try:
                hits = self._ruleset.evaluate(
                    packet, flow=flow, tracker=self._tracker, now=packet["ts"]
                ) or []
                self.stat_add("evaluations")
            except Exception as exc:  # noqa: BLE001 - 规则失败不影响抓包
                self.error("网络规则求值失败", exc=repr(exc))
        elif packet.get("malformed"):
            hits = [self._malformed_hit()]
        for hit in hits:
            try:
                self._emit_hit(hit, packet)
            except Exception as exc:  # noqa: BLE001
                self.error("告警投递失败", exc=repr(exc))

    # ------------------------------------------------------------ 事件/告警
    def _network_dict(self, packet: dict) -> dict:
        return {
            "src_ip": packet.get("src_ip"),
            "src_port": packet.get("src_port"),
            "dst_ip": packet.get("dst_ip"),
            "dst_port": packet.get("dst_port"),
            "proto": packet.get("proto"),
        }

    def _maybe_emit_dns(self, packet: dict) -> None:
        """DNS 查询事件：按 (src_ip, domain) 限流（默认 5 s）避免刷总线。"""
        domain = str(packet.get("domain") or "").strip()
        if not domain:
            return
        now = time.time()
        key = f"{packet.get('src_ip')}|{domain}"
        if now - self._dns_marks.get(key, 0.0) < self.dns_event_interval:
            self.stat_add("dns_deduped")
            return
        self._dns_marks[key] = now
        if len(self._dns_marks) > 20000:
            cutoff = now - max(60.0, self.dns_event_interval * 4)
            for mark in [k for k, v in self._dns_marks.items() if v < cutoff]:
                self._dns_marks.pop(mark, None)
        network = self._network_dict(packet)
        network["domain"] = domain
        network["direction"] = "outbound"
        event = schema.new_event(
            "dns_query",
            self.layer,
            self.source_product,
            self.cfg,
            ts=packet.get("ts_iso"),
            network=network,
            raw={
                "collector": "netcap",
                "dns_qtype": packet.get("dns_qtype"),
                "is_response": False,
                "bytes": packet.get("raw_len"),
            },
        )
        self.send(event)
        self.stat_add("dns_events")

    def _maybe_emit_flow(self, packet: dict, flow: dict) -> None:
        now = time.time()
        key = "|".join(
            str(x)
            for x in (
                packet.get("proto"),
                packet.get("src_ip"),
                packet.get("dst_ip"),
                packet.get("dst_port"),
            )
        )
        if now - self._flow_marks.get(key, 0.0) < self.flow_event_interval:
            return
        self._flow_marks[key] = now
        if len(self._flow_marks) > 20000:
            cutoff = now - max(60.0, self.flow_event_interval * 4)
            for mark in [k for k, v in self._flow_marks.items() if v < cutoff]:
                self._flow_marks.pop(mark, None)
        event = schema.new_event(
            "net_connect",
            self.layer,
            self.source_product,
            self.cfg,
            ts=packet.get("ts_iso"),
            network=self._network_dict(packet),
            raw={
                "collector": "netcap",
                "flags": packet.get("flags"),
                "bytes": packet.get("raw_len"),
                "flow_packets": flow.get("packets"),
            },
        )
        self.send(event)
        self.stat_add("flow_events")

    @staticmethod
    def _malformed_hit() -> dict:
        from ..engines.base import make_hit

        return make_hit(
            "netrules",
            "N-0107",
            "协议畸形报文",
            4,
            {"severity": 4, "technique": None, "msg": "协议畸形报文", "rule_name": "malformed_packet"},
            {"reason": "malformed"},
        )

    def _emit_hit(self, hit: dict, packet: dict) -> None:
        from ..engines.base import hit_to_alert_fields

        fields = hit_to_alert_fields(hit)
        rule = fields["rule"]
        dedup = "|".join(
            str(x)
            for x in (
                rule.get("id"),
                packet.get("src_ip"),
                packet.get("dst_ip"),
                packet.get("dst_port"),
            )
        )
        now = time.time()
        if now - self._alert_marks.get(dedup, 0.0) < self.dedup_sec:
            self.stat_add("deduped")
            return
        if int(now) != int(self._second_mark):
            self._second_mark = now
            self._alerts_second = 0
        if self._alerts_second >= self.max_alerts_per_sec:
            self.stat_add("deduped")
            return
        self._alerts_second += 1
        self._alert_marks[dedup] = now

        network = self._network_dict(packet)
        context = schema.new_event(
            "net_flow",
            self.layer,
            self.source_product,
            self.cfg,
            ts=packet.get("ts_iso"),
            network=network,
            raw={
                "collector": "netcap",
                "flags": packet.get("flags"),
                "malformed": packet.get("malformed"),
                "bytes": packet.get("raw_len"),
            },
        )
        evidence = [hit.get("evidence") or {}]
        evidence.append(
            {
                "src_ip": network.get("src_ip"),
                "dst_ip": network.get("dst_ip"),
                "dst_port": network.get("dst_port"),
                "proto": network.get("proto"),
                "flags": packet.get("flags"),
            }
        )
        alert = schema.new_alert(
            rule,
            level=int(rule.get("level", 5)),
            event=context,
            entity=network,
            evidence=evidence,
            confidence=int(fields.get("confidence", 60)),
            dedup_extra=hit.get("rule_id"),
        )
        self.send_alert(alert)
        self.stat_add("alerts")

    # ------------------------------------------------------------ 维护
    def _maintenance(self) -> None:
        now = time.time()
        if now - self._last_age < 10.0:
            return
        self._last_age = now
        try:
            if self._flow is not None and hasattr(self._flow, "age"):
                self._flow.age(now)
        except Exception as exc:  # noqa: BLE001
            self.error("flow 老化失败", exc=repr(exc))
        cutoff = now - max(self.dedup_sec, 60.0) * 2
        for mark in [k for k, v in self._alert_marks.items() if v < cutoff]:
            self._alert_marks.pop(mark, None)
        dns_cutoff = now - max(60.0, self.dns_event_interval * 4)
        for mark in [k for k, v in self._dns_marks.items() if v < dns_cutoff]:
            self._dns_marks.pop(mark, None)


__all__ = ["NetPipeline", "resolve_ifaces", "ETH_P_ALL"]
