"""情报 feed 解析与规范化。

职责：
- 自动识别 JSONL / CSV 两种格式；
- 把异构字段（abuse.ch 导出、自建 jsonl）统一成记录规范
  ``{"type","value","confidence","source","tlp"}``；
- 导入前过滤：内网/回环/保留地址、空值、超长值、保留域名后缀；
- 单个坏行只记 warning，不中断整批导入。

本模块只依赖标准库，Windows 上可 import / 单测。
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterable

from ..log import get_logger

log = get_logger("intel.feeds")

#: 记录规范允许的情报类型
IOC_TYPES: tuple[str, ...] = ("ip", "domain", "url", "hash", "filename")

#: 各类型 value 的最大长度（超长视为脏数据）
MAX_VALUE_LEN: dict[str, int] = {
    "ip": 64,
    "domain": 253,
    "url": 2048,
    "hash": 128,
    "filename": 1024,
}

DEFAULT_CONFIDENCE = 50
DEFAULT_TLP = "amber"
TLP_LEVELS: tuple[str, ...] = ("white", "green", "amber", "red")

#: 内网/保留域名后缀（命中即丢弃，避免把内网资产当情报告警）
RESERVED_SUFFIXES: tuple[str, ...] = (
    ".local", ".lan", ".internal", ".localhost", ".invalid", ".test",
    ".example", ".home", ".corp", ".intranet", ".arpa",
)

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

#: type 别名 → 规范类型
_TYPE_ALIASES: dict[str, str] = {
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip-address": "ip", "ip_address": "ip",
    "ipaddress": "ip", "ip:port": "ip", "ipv4-addr": "ip", "ipv6-addr": "ip",
    "domain": "domain", "domain-name": "domain", "domain_name": "domain",
    "hostname": "domain", "fqdn": "domain", "host": "domain",
    "url": "url", "uri": "url",
    "hash": "hash", "sha256": "hash", "sha256_hash": "hash", "sha-256": "hash",
    "md5": "hash", "md5_hash": "hash", "sha1": "hash", "sha-1": "hash",
    "sha1_hash": "hash", "filehash": "hash", "file_hash": "hash", "imphash": "hash",
    "filename": "filename", "file_name": "filename", "file": "filename",
    "path": "filename", "filepath": "filename", "file_path": "filename",
}

#: 自动 CSV 映射的候选列名（按优先级）
_FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "type": ("type", "ioc_type", "indicator_type", "kind"),
    "value": ("value", "indicator", "ioc", "indicator_value", "ioc_value"),
    "confidence": ("confidence", "score", "risk_score"),
    "source": ("source", "reporter", "provider", "threat", "malware"),
    "tlp": ("tlp", "sharing", "traffic_light_protocol"),
}

#: 没有 type 列时，按列名猜类型的顺序（越靠前越可信）
_VALUE_COLUMN_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("url", ("url", "uri", "urlhaus")),
    ("hash", ("sha256_hash", "sha256", "md5_hash", "md5", "sha1_hash")),
    ("ip", ("ip_address", "dst_ip", "src_ip", "ipaddress", "ip:port", "ip")),
    ("domain", ("domain", "hostname", "host")),
    ("filename", ("filename", "file_name", "file")),
)


# ---------------------------------------------------------------------------
# 基础规范化
# ---------------------------------------------------------------------------
def refang(value: str) -> str:
    """把常见去毒化写法还原：hxxp→http、[.]/(.)/{.}→.、[:]→:。"""
    out = value.strip()
    out = re.sub(r"(?i)^hxxps?", lambda m: "https" if m.group(0).lower().endswith("s") else "http", out)
    out = out.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    out = out.replace("[:]", ":").replace("[at]", "@").replace("(at)", "@")
    return out


def normalize_type(raw: Any) -> str | None:
    """把各种 type 写法归一成 :data:`IOC_TYPES` 之一；未知返回 None。"""
    if raw is None:
        return None
    key = str(raw).strip().lower()
    return _TYPE_ALIASES.get(key)


def detect_type(value: str) -> str | None:
    """无 type 列时按取值猜类型。"""
    val = value.strip()
    if not val:
        return None
    if val.lower().startswith(("http://", "https://")):
        return "url"
    if _HEX64.match(val) or _HEX40.match(val) or _HEX32.match(val):
        return "hash"
    try:
        ipaddress.ip_address(val)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(val):
        return "domain"
    # "1.2.3.4:443" 这类 ip:port 组合只取主机部分后判 IP
    host = _strip_port(val)
    if host != val:
        try:
            ipaddress.ip_address(host)
            return "ip"
        except ValueError:
            pass
    if "/" in val or "\\" in val:
        return "filename"
    return None


def _strip_port(value: str) -> str:
    """feodotracker 一类 ``1.2.3.4:443`` 只保留主机部分（IPv6 不处理）。"""
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit() and host:
            return host
    return value


def _url_host(value: str) -> str | None:
    """取 URL 的 host（不依赖 urllib 的额外开销，容错到无 scheme 的写法）。"""
    text = value
    if "://" not in text:
        text = "http://" + text
    try:
        from urllib.parse import urlsplit

        host = urlsplit(text).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def is_public_ip(value: str) -> bool:
    """是否公网可路由地址（内网/回环/保留/组播/未指定均返回 False）。"""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_public_domain(value: str) -> bool:
    """过滤保留后缀、单标签域名、IP 字面量与 localhost。"""
    dom = value.strip().lower().rstrip(".")
    if not dom or " " in dom:
        return False
    if dom == "localhost" or dom.endswith(RESERVED_SUFFIXES):
        return False
    if "." not in dom:
        return False
    try:
        ipaddress.ip_address(dom)
        return False
    except ValueError:
        pass
    return bool(_DOMAIN_RE.match(dom))


def _canonical_value(kind: str, value: str) -> str | None:
    """按类型做规范化；明显不合法返回 None。"""
    val = refang(value)
    if not val or len(val) > MAX_VALUE_LEN.get(kind, 2048):
        return None
    if kind == "ip":
        val = _strip_port(val)
        try:
            ip = ipaddress.ip_address(val)
        except ValueError:
            return None
        if not is_public_ip(str(ip)):
            return None
        return str(ip)
    if kind == "domain":
        dom = val.lower().rstrip(".")
        if not is_public_domain(dom):
            return None
        return dom
    if kind == "url":
        if len(val) > MAX_VALUE_LEN["url"]:
            return None
        host = _url_host(val)
        if not host:
            return None
        if not (is_public_domain(host) or is_public_ip(host)):
            return None
        if not val.lower().startswith(("http://", "https://")):
            val = "http://" + val
        return val
    if kind == "hash":
        hexval = val.strip().lower()
        if not (_HEX32.match(hexval) or _HEX40.match(hexval) or _HEX64.match(hexval)):
            return None
        return hexval
    if kind == "filename":
        name = val.strip().replace("\\", "/")
        if not name or len(name) > MAX_VALUE_LEN["filename"]:
            return None
        return name
    return None


def normalize_tlp(raw: Any) -> str:
    """TLP 归一：接受 ``amber`` / ``TLP:AMBER`` / ``tlp:amber``。"""
    if raw is None:
        return DEFAULT_TLP
    text = str(raw).strip().lower()
    if text.startswith("tlp:"):
        text = text[4:].strip()
    if text in TLP_LEVELS:
        return text
    if text in ("clear", "white", "unlimited"):
        return "white"
    return DEFAULT_TLP


def _clamp_confidence(raw: Any) -> int:
    try:
        val = int(float(raw))
    except (TypeError, ValueError):
        return DEFAULT_CONFIDENCE
    return max(0, min(100, val))


def normalize_record(raw: dict[str, Any], default_source: str = "") -> dict[str, Any] | None:
    """把单条原始记录规范化为 IOC 记录；被过滤时返回 None。"""
    if not isinstance(raw, dict):
        return None
    kind = normalize_type(raw.get("type") or raw.get("ioc_type"))
    value_raw = raw.get("value")
    if value_raw is None:
        for key in ("indicator", "ioc", "indicator_value"):
            if raw.get(key) is not None:
                value_raw = raw.get(key)
                break
    if value_raw is None:
        return None
    value_text = str(value_raw).strip()
    if not value_text:
        return None
    if kind is None:
        kind = detect_type(refang(value_text))
    if kind is None:
        return None
    value = _canonical_value(kind, value_text)
    if value is None:
        return None
    source = str(raw.get("source") or default_source or "feed").strip()[:200]
    return {
        "type": kind,
        "value": value,
        "confidence": _clamp_confidence(raw.get("confidence")),
        "source": source,
        "tlp": normalize_tlp(raw.get("tlp")),
    }


def filter_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """对已规范化的记录再做一次过滤（幂等，供外部批量校验用）。"""
    out: list[dict[str, Any]] = []
    for rec in records:
        norm = normalize_record(rec, default_source=str(rec.get("source") or ""))
        if norm is not None:
            out.append(norm)
    return out


# ---------------------------------------------------------------------------
# 解析器
# ---------------------------------------------------------------------------
def _read_text(path: str | Path) -> str:
    """按 UTF-8(含 BOM) 读取，失败回退 latin-1，保证不因编码中断导入。"""
    p = Path(path)
    data = p.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def parse_jsonl(path: str | Path) -> list[dict[str, Any]]:
    """解析 JSONL：每行一个记录 dict（也容忍顶层是数组的行）。"""
    text = _read_text(path)
    default_source = f"feed:{Path(path).name}"
    records: list[dict[str, Any]] = []
    bad = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            log.warn("jsonl 行解析失败", path=str(path), line=lineno)
            continue
        candidates = item if isinstance(item, list) else [item]
        for cand in candidates:
            norm = normalize_record(cand, default_source=default_source)
            if norm is not None:
                records.append(norm)
    if bad:
        log.warn("jsonl 存在坏行", path=str(path), bad=bad, kept=len(records))
    return records


def _auto_mapping(fieldnames: list[str]) -> dict[str, str]:
    """根据表头猜测映射：{目标字段: 列名}。"""
    headers = [h.strip() for h in fieldnames if h]
    lower = {h.lower(): h for h in headers}
    mapping: dict[str, str] = {}
    for target, cands in _FIELD_CANDIDATES.items():
        for cand in cands:
            if cand in lower:
                mapping[target] = lower[cand]
                break
    if "value" not in mapping:
        for kind, cands in _VALUE_COLUMN_HINTS:
            hit = next((lower[c] for c in cands if c in lower), None)
            if hit:
                mapping["value"] = hit
                mapping.setdefault("type", kind)
                break
    return mapping


def _pick(row: dict[str, Any], mapping: dict[str, str], key: str) -> Any:
    col = mapping.get(key)
    if col and col in row:
        return row.get(col)
    return None


def parse_csv(path: str | Path, mapping: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """解析 CSV（含 abuse.ch 导出格式）。

    ``mapping`` 形如 ``{"type": "type", "value": "url", "source": "reporter"}``，
    值可以是列名字符串或列名列表（取第一个非空）；缺省时按表头自动映射。
    """
    text = _read_text(path)
    default_source = f"feed:{Path(path).name}"
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return []
    auto = _auto_mapping(list(reader.fieldnames))

    def col(key: str) -> list[str]:
        if mapping and mapping.get(key):
            val = mapping[key]
            cols = val if isinstance(val, (list, tuple)) else [val]
            return [str(c) for c in cols]
        return [auto[key]] if key in auto else []

    records: list[dict[str, Any]] = []
    bad = 0
    for row in reader:
        if not row:
            continue
        try:
            raw: dict[str, Any] = {}
            for key in ("type", "value", "confidence", "source", "tlp"):
                raw[key] = next(
                    (row[c] for c in col(key) if c in row and str(row[c]).strip()),
                    None,
                )
            if not raw.get("value") and not raw.get("type"):
                bad += 1
                continue
            # 显式 type 与 value 同时缺失时，按 value 猜；有 type 但为垃圾则丢弃
            if raw.get("type") and normalize_type(raw["type"]) is None:
                raw["type"] = None
            norm = normalize_record(raw, default_source=default_source)
            if norm is not None:
                records.append(norm)
            else:
                bad += 1
        except (KeyError, TypeError, ValueError):
            bad += 1
            log.warn("csv 行解析失败", path=str(path))
    if bad:
        log.warn("csv 存在被过滤行", path=str(path), filtered=bad, kept=len(records))
    return records


def detect_format(path: str | Path) -> str:
    """返回 ``"jsonl"`` 或 ``"csv"``；先看扩展名，再看首个有效行。"""
    suffix = Path(path).suffix.lower()
    if suffix in (".csv", ".tsv"):
        return "csv"
    if suffix in (".jsonl", ".ndjson", ".json"):
        return "jsonl"
    try:
        text = _read_text(path)
    except OSError:
        return "csv"
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        return "jsonl" if line[:1] in ("{", "[") else "csv"
    return "csv"


def load_feed(path: str | Path) -> list[dict[str, Any]]:
    """加载情报 feed，自动识别 JSONL/CSV，返回已过滤的规范化记录。"""
    p = Path(path)
    if not p.is_file():
        log.warn("feed 文件不存在", path=str(p))
        return []
    try:
        fmt = detect_format(p)
        records = parse_jsonl(p) if fmt == "jsonl" else parse_csv(p)
    except OSError as exc:
        log.error("feed 读取失败", path=str(p), error=str(exc))
        return []
    log.info("feed 加载完成", path=str(p), format=fmt, records=len(records))
    return records
