"""STIX 2.1 子集：Indicator / MarkingDefinition(TLP) / Bundle。

只实现 要求的子集：
- ``ipv4-addr:value`` / ``ipv6-addr:value`` / ``domain-name:value`` / ``url:value``
  / ``file:hashes.'SHA-256'``（兼容 MD5/SHA-1）/ ``file:name``；
- TLP white/green/amber/red 四种 marking-definition；
- bundle 导出与解析（支持大小写、单双引号、宽松空白的 pattern）。

uuid 全部确定性生成（uuid5），保证同一 IOC 多次导出 id 稳定。
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from pathlib import Path
from typing import Any

from .. import schema
from ..log import get_logger
from . import feeds

log = get_logger("intel.stix")

SPEC_VERSION = "2.1"

#: STIX 2.0/2.1 官方 TLP marking-definition id（业界通用固定值）
TLP_MARKINGS: dict[str, dict[str, Any]] = {
    "white": {
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "name": "TLP:WHITE",
    },
    "green": {
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "name": "TLP:GREEN",
    },
    "amber": {
        "id": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        "name": "TLP:AMBER",
    },
    "red": {
        "id": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
        "name": "TLP:RED",
    },
}

_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # NAMESPACE_URL
_CREATED_MARKING = "2017-01-20T00:00:00.000Z"

#: 匹配 ``[object-type:path = 'value']``，容忍引号与空白差异
_PATTERN_RE = re.compile(
    r"\[\s*(?P<obj>[A-Za-z0-9._-]+)\s*:\s*(?P<path>[^\]=]*?)\s*=\s*"
    r"(?P<q>['\"])(?P<val>.*?)(?P=q)\s*\]",
    re.S,
)

_HASH_ALGO_BY_LEN = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def _deterministic_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(_NAMESPACE, f'hornwork:{stix_type}:{key}')}"


def _escape(value: str) -> str:
    """pattern 内的单引号转义（STIX pattern 用单引号包裹字符串）。"""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def pattern_for(kind: str, value: str) -> str:
    """按 IOC 类型生成 STIX pattern。"""
    kind = str(kind or "").strip().lower()
    val = str(value or "").strip()
    if kind == "ip":
        ip = ipaddress.ip_address(val)
        obj = "ipv4-addr" if ip.version == 4 else "ipv6-addr"
        return f"[{obj}:value = '{_escape(str(ip))}']"
    if kind == "domain":
        return f"[domain-name:value = '{_escape(val.lower())}']"
    if kind == "url":
        return f"[url:value = '{_escape(val)}']"
    if kind == "hash":
        algo = _HASH_ALGO_BY_LEN.get(len(val), "SHA-256")
        return f"[file:hashes.'{algo}' = '{_escape(val.lower())}']"
    if kind == "filename":
        return f"[file:name = '{_escape(val)}']"
    raise ValueError(f"不支持的情报类型: {kind!r}")


def parse_pattern(pattern: str) -> tuple[str, str] | None:
    """从 STIX pattern 反解 ``(kind, value)``；无法识别返回 None。"""
    if not isinstance(pattern, str):
        return None
    match = _PATTERN_RE.search(pattern)
    if not match:
        return None
    obj = match.group("obj").strip().lower()
    path = re.sub(r"\s+", "", match.group("path")).lower().replace('"', "'")
    value = match.group("val").strip()
    if not value:
        return None
    if obj in ("ipv4-addr", "ipv6-addr"):
        return "ip", value
    if obj == "domain-name":
        return "domain", value.lower()
    if obj == "url":
        return "url", value
    if obj == "file":
        if "hash" in path:
            return "hash", value.lower()
        if path.endswith("name"):
            return "filename", value
    return None


def tlp_marking(tlp: str) -> dict[str, Any]:
    """构造（或复用固定 id 的）TLP marking-definition 对象。"""
    level = feeds.normalize_tlp(tlp)
    spec = TLP_MARKINGS[level]
    return {
        "type": "marking-definition",
        "spec_version": SPEC_VERSION,
        "id": spec["id"],
        "created": _CREATED_MARKING,
        "definition_type": "tlp",
        "name": spec["name"],
        "definition": {"tlp": level},
    }


def _identity_object(identity: str) -> dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": _deterministic_id("identity", identity),
        "created": _CREATED_MARKING,
        "modified": _CREATED_MARKING,
        "name": identity,
        "identity_class": "system",
    }


def _indicator_object(rec: dict[str, Any]) -> dict[str, Any] | None:
    norm = feeds.normalize_record(rec, default_source=str(rec.get("source") or ""))
    if norm is None:
        return None
    kind, value = norm["type"], norm["value"]
    first_seen = str(rec.get("first_seen") or rec.get("ts") or schema.utc_now())
    last_seen = str(rec.get("last_seen") or first_seen)
    marking = TLP_MARKINGS[norm["tlp"]]["id"]
    return {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _deterministic_id("indicator", f"{kind}:{value}"),
        "created": schema.to_utc(first_seen),
        "modified": schema.to_utc(last_seen),
        "name": f"{kind}: {value}",
        "description": f"Hornwork 情报命中指标（{kind}）",
        "pattern": pattern_for(kind, value),
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": schema.to_utc(first_seen),
        "confidence": int(norm["confidence"]),
        "labels": ["malicious-activity"],
        "object_marking_refs": [marking],
        # 自定义扩展属性（STIX 允许 x_ 前缀）：保留来源，便于回环导入
        "x_ioc_type": kind,
        "x_ioc_source": norm["source"],
        "x_ioc_tlp": norm["tlp"],
    }


# ---------------------------------------------------------------------------
# 导出 / 导入
# ---------------------------------------------------------------------------
def export_bundle(iocs: list[dict[str, Any]], identity: str = "hornwork") -> dict[str, Any]:
    """把 IOC 列表导出成 STIX 2.1 bundle（含 identity 与用到的 TLP marking）。"""
    objects: list[dict[str, Any]] = [_identity_object(str(identity or "hornwork"))]
    used_tlp: set[str] = set()
    for rec in iocs or []:
        try:
            obj = _indicator_object(rec)
        except (ValueError, TypeError) as exc:
            log.warn("IOC 转 STIX 失败", ioc=rec.get("value"), error=str(exc))
            continue
        if obj is None:
            continue
        used_tlp.add(feeds.normalize_tlp(rec.get("tlp")))
        objects.append(obj)
    for level in TLP_MARKINGS:
        if level in used_tlp:
            objects.append(tlp_marking(level))
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": SPEC_VERSION,
        "objects": objects,
    }


def _marking_index(objects: list[dict[str, Any]]) -> dict[str, str]:
    """marking-definition id → tlp 等级。"""
    index: dict[str, str] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "marking-definition":
            continue
        definition = obj.get("definition") or {}
        level = feeds.normalize_tlp(definition.get("tlp") or obj.get("name"))
        index[str(obj.get("id"))] = level
    return index


def parse_bundle(bundle: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """解析 STIX bundle（或裸 objects 列表），返回 IOC 记录列表。"""
    if isinstance(bundle, list):
        objects = bundle
    elif isinstance(bundle, dict):
        objects = bundle.get("objects") or []
        if isinstance(objects, dict):  # 容错：极端写法
            objects = [objects]
    else:
        return []
    markings = _marking_index(objects)
    records: list[dict[str, Any]] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        parsed = parse_pattern(str(obj.get("pattern") or ""))
        if parsed is None:
            log.warn("STIX indicator 无法解析 pattern", id=obj.get("id"))
            continue
        kind, value = parsed
        tlp = "amber"
        for ref in obj.get("object_marking_refs") or []:
            if str(ref) in markings:
                tlp = markings[str(ref)]
                break
        record = {
            "type": kind,
            "value": value,
            "confidence": obj.get("confidence", feeds.DEFAULT_CONFIDENCE),
            "source": obj.get("x_ioc_source") or "stix",
            "tlp": tlp,
        }
        if obj.get("valid_from"):
            record["first_seen"] = obj["valid_from"]
        norm = feeds.normalize_record(record, default_source="stix")
        if norm is not None:
            if obj.get("valid_from"):
                norm["first_seen"] = schema.to_utc(obj["valid_from"])
            records.append(norm)
    log.info("STIX 解析完成", indicators=len(records), objects=len(objects))
    return records


def write_bundle(path: str | Path, iocs: list[dict[str, Any]]) -> int:
    """导出 STIX bundle 到 JSON 文件，返回写入的 indicator 数量。"""
    bundle = export_bundle(iocs)
    target = Path(path)
    if target.parent and str(target.parent):
        target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    count = len([o for o in bundle["objects"] if o.get("type") == "indicator"])
    log.info("STIX 导出完成", path=str(target), indicators=count)
    return count


def read_bundle(path: str | Path) -> list[dict[str, Any]]:
    """读取 STIX bundle JSON 文件，返回 IOC 记录列表。"""
    with open(Path(path), "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    return parse_bundle(bundle)
