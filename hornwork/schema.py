"""统一事件/告警数据模型（schema v1.0）。

约定：
- C1 UTF-8，JSON 不允许 NaN/Infinity；本模块统一走 _dumps()；
- C2 时间一律 UTC ISO8601（毫秒 + Z）；
- C3 event_id/alert_id 用 UUIDv4，dedup_key 用 sha256 前 32 位十六进制；
- C4 载荷带 schema_version，校验器拒收未知 MAJOR；
- C6 单条消息 ≤ 1MB（超限由总线/存储层按引用处理）。
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import uuid
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"
SCHEMA_MAJOR = 1

EVENT_TYPES = {
    "process_create", "process_exit", "file_create", "file_modify", "file_delete",
    "net_connect", "dns_query", "logon", "logon_fail", "account_create",
    "persist_item", "memory_scan", "scan_result", "alert", "net_flow",
    # 靶场模块（靶场编排/漏洞档案）复用同一事件模型，不新建总线
    "lab_action", "vuln_finding",
    # 扫描模块（定期漏洞扫描）：任务生命周期、问题入库、扫描窗口（自扰治理）
    "scan_task", "scan_finding", "scan_window",
}

SOURCE_LAYERS = {"host", "net", "memory", "static", "scan"}

MAX_PAYLOAD_BYTES = 1024 * 1024

_ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"
)


# ---------------------------------------------------------------------------
# 时间与序列化
# ---------------------------------------------------------------------------
def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_utc(ts: Any) -> str:
    """把 datetime/float/str 统一成 UTC ISO 字符串。"""
    if isinstance(ts, str):
        if _ISO_RE.match(ts):
            return ts
        ts = ts.replace(" ", "T")
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )[:-3] + "Z"
        except ValueError:
            return utc_now()
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    if isinstance(ts, datetime):
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return utc_now()


def dumps(obj: Any) -> str:
    """安全 JSON 序列化：禁止 NaN/Infinity，非标准对象转字符串。"""
    return json.dumps(obj, ensure_ascii=False, default=str, allow_nan=False)


def dedup_key(*parts: Any) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 主机信息
# ---------------------------------------------------------------------------
_host_cache: dict[str, Any] = {}


def host_info(cfg: dict | None = None) -> dict:
    """返回 host 段：host_id/hostname/os。结果缓存。"""
    global _host_cache
    if _host_cache:
        return dict(_host_cache)
    general = (cfg or {}).get("general", {}) if cfg else {}
    hostname = general.get("hostname") or socket.gethostname()
    host_id = general.get("host_id") or hostname
    os_name = general.get("os_name") or "linux"
    _host_cache = {"host_id": str(host_id), "hostname": str(hostname), "os": str(os_name)}
    return dict(_host_cache)


def reset_host_cache() -> None:
    """测试用：清空主机信息缓存。"""
    global _host_cache
    _host_cache = {}


# ---------------------------------------------------------------------------
# 事件构造与校验
# ---------------------------------------------------------------------------
def new_event(
    event_type: str,
    source_layer: str,
    source_product: str,
    cfg: dict | None = None,
    *,
    ts: Any = None,
    process: dict | None = None,
    file: dict | None = None,
    network: dict | None = None,
    user: dict | None = None,
    rule: dict | None = None,
    raw: dict | None = None,
    host: dict | None = None,
) -> dict:
    """构造一条 CanonicalEvent；必填字段缺失时立即抛 ValueError。"""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event_type: {event_type}")
    if source_layer not in SOURCE_LAYERS:
        raise ValueError(f"unknown source_layer: {source_layer}")

    ev: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": to_utc(ts) if ts else utc_now(),
        "source_layer": source_layer,
        "source_product": source_product,
        "event_type": event_type,
        "host": dict(host or host_info(cfg)),
    }
    for key, val in (
        ("process", process),
        ("file", file),
        ("network", network),
        ("user", user),
        ("rule", rule),
        ("raw", raw),
    ):
        if val:
            ev[key] = dict(val)
    return ev


def validate_event(ev: dict) -> list[str]:
    """返回错误列表，空列表表示通过。"""
    errs: list[str] = []
    if not isinstance(ev, dict):
        return ["event is not an object"]
    ver = str(ev.get("schema_version", ""))
    try:
        major = int(ver.split(".")[0])
    except (ValueError, IndexError):
        major = -1
    if major != SCHEMA_MAJOR:
        errs.append(f"unsupported schema_version: {ver!r}")
    for field in ("event_id", "ts", "source_layer", "source_product", "event_type"):
        if not ev.get(field):
            errs.append(f"missing field: {field}")
    if ev.get("event_type") not in EVENT_TYPES:
        errs.append(f"bad event_type: {ev.get('event_type')!r}")
    if ev.get("source_layer") not in SOURCE_LAYERS:
        errs.append(f"bad source_layer: {ev.get('source_layer')!r}")
    ts = str(ev.get("ts", ""))
    if ts and not _ISO_RE.match(ts):
        errs.append(f"bad ts format: {ts!r}")
    host = ev.get("host")
    if not isinstance(host, dict) or not host.get("host_id"):
        errs.append("missing host.host_id")
    return errs


def normalize_event(raw: dict, cfg: dict | None = None) -> dict:
    """给采集器产出的半成品事件补齐必填字段；不合法时抛 ValueError。"""
    ev = dict(raw or {})
    if not ev.get("schema_version"):
        ev["schema_version"] = SCHEMA_VERSION
    if not ev.get("event_id"):
        ev["event_id"] = str(uuid.uuid4())
    if not ev.get("ts"):
        ev["ts"] = utc_now()
    else:
        ev["ts"] = to_utc(ev["ts"])
    if not ev.get("source_layer"):
        ev["source_layer"] = "host"
    if not ev.get("source_product"):
        ev["source_product"] = "hornwork"
    if not isinstance(ev.get("host"), dict) or not ev["host"].get("host_id"):
        ev["host"] = host_info(cfg)
    errs = validate_event(ev)
    if errs:
        raise ValueError("; ".join(errs))
    return ev


def event_size(ev: dict) -> int:
    return len(dumps(ev).encode("utf-8"))


# ---------------------------------------------------------------------------
# 规则与告警
# ---------------------------------------------------------------------------
def make_rule(
    rule_id: str,
    name: str,
    engine: str,
    level: int = 5,
    mitre: list[str] | None = None,
    version: str = "1.0",
) -> dict:
    return {
        "id": str(rule_id),
        "name": str(name),
        "engine": str(engine),
        "version": str(version),
        "level": int(level),
        "mitre": list(mitre or []),
    }


def new_alert(
    rule: dict,
    *,
    level: int | None = None,
    event: dict | None = None,
    entity: dict | None = None,
    evidence: list | None = None,
    intel: dict | None = None,
    contrib: dict | None = None,
    confidence: int = 60,
    ts: Any = None,
    scheme: str | None = None,
    dedup_extra: Any = None,
) -> dict:
    """构造 DetectionAlert。

    - 有 event 时继承其 ts/host/process/file/network 并回填 event_id/event_type；
    - 无 event（网络规则/情报命中）时用 entity 与 ts。
    """
    event = event or {}
    host = dict(event.get("host") or host_info())
    ent = {
        "host_id": host.get("host_id"),
        "src_ip": None,
        "dst_ip": None,
    }
    if event.get("network"):
        ent["src_ip"] = event["network"].get("src_ip")
        ent["dst_ip"] = event["network"].get("dst_ip")
        ent["dst_port"] = event["network"].get("dst_port")
        ent["proto"] = event["network"].get("proto")
    if entity:
        ent.update({k: v for k, v in entity.items() if v is not None})

    mitre = list(rule.get("mitre") or [])
    rule_level = int(rule.get("level", 5))
    lvl = int(level if level is not None else rule_level)

    alert: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "alert_id": str(uuid.uuid4()),
        "ts": to_utc(ts) if ts else (event.get("ts") or utc_now()),
        "rule": {
            "id": str(rule.get("id", "unknown")),
            "name": str(rule.get("name", "")),
            "engine": str(rule.get("engine", "unknown")),
            "version": str(rule.get("version", "1.0")),
            "level": rule_level,
            "mitre": mitre,
        },
        "level": lvl,
        "confidence": int(confidence),
        "technique": mitre[0] if mitre else None,
        "mitre": {"tactics": [], "techniques": mitre},
        "entity": ent,
        "dedup_key": dedup_key(
            rule.get("id"), ent.get("host_id"), ent.get("src_ip"), ent.get("dst_ip"),
            ent.get("dst_port"), scheme,
            # 进程类告警把 pid 纳入去重键：不同进程实例代表不同事件，
            # 避免"同一分钟两次 useradd/cp"被误当重复告警丢弃（验证用例依赖此语义）。
            (event.get("process") or {}).get("pid"),
            dedup_extra,
        ),
        "evidence": list(evidence or []),
        "intel": dict(intel or {}),
        "contrib": dict(contrib or {}),
        "status": "open",
        "event_type": event.get("event_type"),
        "event_id": event.get("event_id"),
        "source_layer": event.get("source_layer") or "host",
    }
    for key in ("host", "process", "file", "network", "user", "raw"):
        if event.get(key):
            alert[key] = event[key]
    try:
        if event_size(alert) > MAX_PAYLOAD_BYTES:
            alert["evidence"] = [
                {"note": "evidence-truncated", "orig_bytes": event_size(alert)}
            ]
    except ValueError:
        pass
    return alert


def validate_alert(alert: dict) -> list[str]:
    errs: list[str] = []
    if not isinstance(alert, dict):
        return ["alert is not an object"]
    try:
        major = int(str(alert.get("schema_version", "")).split(".")[0])
    except (ValueError, IndexError):
        major = -1
    if major != SCHEMA_MAJOR:
        errs.append("unsupported schema_version")
    for field in ("alert_id", "ts", "rule", "level", "entity"):
        if not alert.get(field):
            errs.append(f"missing field: {field}")
    rule = alert.get("rule")
    if isinstance(rule, dict):
        for field in ("id", "engine"):
            if not rule.get(field):
                errs.append(f"missing rule.{field}")
    else:
        errs.append("rule is not an object")
    if not isinstance(alert.get("entity"), dict) or not alert["entity"].get("host_id"):
        errs.append("missing entity.host_id")
    return errs


def severity_label(level: int) -> str:
    level = int(level)
    if level >= 12:
        return "critical"
    if level >= 9:
        return "high"
    if level >= 6:
        return "medium"
    if level >= 3:
        return "low"
    return "info"


def alert_to_event(alert: dict) -> dict:
    """把告警折叠成一条 event_type=alert 的事件（便于统一时间线）。"""
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": alert.get("ts") or utc_now(),
        "source_layer": "host",
        "source_product": "hornwork-alert",
        "event_type": "alert",
        "host": dict(alert.get("host") or host_info()),
        "rule": alert.get("rule"),
        "raw": {"alert_id": alert.get("alert_id"), "level": alert.get("level")},
    }
