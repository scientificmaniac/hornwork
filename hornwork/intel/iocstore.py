"""IOC 仓库：导入去重、生命周期、取值集合、STIX 导入导出。


- 状态机 ``candidate → active → aging → expired``，由 TTL 驱动老化；
- ``values(kind)`` 供 ``NetRuleSet`` 的 ioc_provider 使用（未过期且未白名单）；
- ``provider(kind)`` 返回可调用对象，兼容 ``ioc_provider("ip"/"domain")`` 调用约定。

只依赖标准库，可在 Windows 上单测。
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .. import schema
from ..config import cfg_get
from ..log import get_logger
from . import feeds, stix

log = get_logger("intel.iocstore")

#: kind 别名 → 存储层 type（netrules 可能传 "ips"/"domains" 等）
_KIND_ALIASES: dict[str, str] = {
    "ip": "ip", "ips": "ip", "ipv4": "ip", "ipv6": "ip",
    "domain": "domain", "domains": "domain", "hostname": "domain", "fqdn": "domain",
    "url": "url", "urls": "url", "uri": "url",
    "hash": "hash", "hashes": "hash", "sha256": "hash", "md5": "hash",
    "filename": "filename", "filenames": "filename", "file": "filename", "path": "filename",
}

DEFAULT_TTL_DAYS: dict[str, int] = {"ip": 30, "domain": 90, "hash": 0, "url": 30, "filename": 90}


def ioc_id_for(kind: str, value: str) -> str:
    """ioc_id = sha256("type|value") 前 32 位十六进制（与 store.dedup_key 一致）。"""
    return schema.dedup_key(kind, value)


def normalize_kind(kind: str) -> str | None:
    """把外部传入的 kind 归一成存储层 type。

    兼容 ``ip``/``ips``/``domain``/``domains``，也兼容规则里写的集合名
    （``ioc_ips``/``ioc_domains``），netrules 会先按集合名调用 ioc_provider。
    """
    key = str(kind or "").strip().lower()
    if key in _KIND_ALIASES:
        return _KIND_ALIASES[key]
    if key.startswith("ioc_"):
        key = key[4:]
    if key.endswith("s") and key[:-1] in ("ip", "domain", "url", "hash", "filename"):
        key = key[:-1]
    return _KIND_ALIASES.get(key)


def _ttl_from_cfg(cfg: dict | None) -> dict[str, int]:
    ttl = cfg_get(cfg or {}, "intel.ioc_ttl_days", None)
    if not isinstance(ttl, dict):
        return dict(DEFAULT_TTL_DAYS)
    merged = dict(DEFAULT_TTL_DAYS)
    for key, val in ttl.items():
        kind = normalize_kind(key)
        if kind:
            try:
                merged[kind] = int(val)
            except (TypeError, ValueError):
                continue
    return merged


def _plus_days(ts: str, days: int) -> str:
    """UTC ISO 字符串加天数（用于算 expires_at）。"""
    base = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return (base + timedelta(days=int(days))).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class IocStore:
    """IOC 仓库门面：所有持久化细节委托给 ``hornwork.store.Store``。"""

    def __init__(self, store: Any, cfg: dict | None = None):
        self.store = store
        self.cfg = cfg or {}
        self.ttl_days = _ttl_from_cfg(self.cfg)
        self.min_confidence_rule = int(cfg_get(self.cfg, "intel.min_confidence_rule", 60) or 60)

    # ------------------------------------------------------------------ 导入
    def import_records(self, records: list[dict[str, Any]]) -> dict[str, int]:
        """批量导入：规范化 → 去重 → 写库；返回 ``{"imported","skipped","total"}``。"""
        records = list(records or [])
        imported = 0
        skipped = 0
        seen: set[str] = set()
        now = schema.utc_now()
        for raw in records:
            norm = feeds.normalize_record(raw, default_source="import")
            if norm is None:
                skipped += 1
                continue
            ioc_id = ioc_id_for(norm["type"], norm["value"])
            if ioc_id in seen:
                skipped += 1
                continue
            seen.add(ioc_id)
            if self._exists(ioc_id):
                # 同 type+value 已存在：视为重复，不刷新生命周期
                skipped += 1
                continue
            days = int(self.ttl_days.get(norm["type"], 0) or 0)
            status = "active" if norm["confidence"] >= self.min_confidence_rule else "candidate"
            rec = {
                "ioc_id": ioc_id,
                "type": norm["type"],
                "value": norm["value"],
                "confidence": norm["confidence"],
                "tlp": norm["tlp"],
                "source": norm["source"],
                "status": status,
                "first_seen": now,
                "last_seen": now,
                "expires_at": _plus_days(now, days) if days > 0 else None,
                "whitelisted": 0,
            }
            if self.store.ioc_upsert(rec):
                imported += 1
            else:
                skipped += 1
        result = {"imported": imported, "skipped": skipped, "total": len(records)}
        log.info("IOC 导入完成", **result)
        return result

    def _exists(self, ioc_id: str) -> bool:
        row = self.store.query_one("SELECT 1 AS x FROM ioc WHERE ioc_id=?", (ioc_id,))
        return bool(row)

    # ------------------------------------------------------------------ 查询
    def _rows(self, kind: str | None = None, limit: int = 100000) -> list[dict[str, Any]]:
        """读取 IOC 行（可过滤未过期未白名单由调用方决定）。"""
        rows = self.store.ioc_list(kind=kind, limit=int(limit))
        return [dict(row) for row in rows]

    @staticmethod
    def _is_live(row: dict[str, Any], now: str) -> bool:
        if int(row.get("whitelisted") or 0):
            return False
        if str(row.get("status") or "") == "expired":
            return False
        expires = row.get("expires_at")
        return not (expires and str(expires) <= now)

    def rows(self, kind: str | None = None, live_only: bool = True,
             limit: int = 100000) -> list[dict[str, Any]]:
        """返回 IOC 行；``live_only=True`` 时只给未过期、未白名单的记录。"""
        norm_kind = normalize_kind(kind) if kind else None
        rows = self._rows(norm_kind, limit=limit)
        if not live_only:
            return rows
        now = schema.utc_now()
        return [row for row in rows if self._is_live(row, now)]

    def values(self, kind: str) -> set[str]:
        """返回某类情报的可用取值集合（未过期、未白名单）。"""
        norm_kind = normalize_kind(kind)
        if norm_kind is None:
            log.warn("未知情报类型", kind=kind)
            return set()
        out: set[str] = set()
        for row in self.rows(norm_kind, live_only=True):
            val = str(row.get("value") or "").strip()
            if not val:
                continue
            out.add(val.lower() if norm_kind in ("domain", "hash") else val)
        return out

    def provider(self, kind: str = "ip") -> Callable[..., set[str]]:
        """返回可调用对象 ``lambda kind=kind: self.values(kind)``，供 netrules 注入。"""

        def _provider(kind: str = kind) -> set[str]:
            return self.values(kind)

        return _provider

    # ------------------------------------------------------------------ 生命周期
    def aging(self) -> int:
        """按 cfg ``intel.ioc_ttl_days`` 老化，返回受影响条数。"""
        changed = int(self.store.ioc_aging(dict(self.ttl_days)) or 0)
        if changed:
            log.info("IOC 老化完成", expired=changed, ttl=self.ttl_days)
        return changed

    def stats(self) -> dict[str, Any]:
        """按类型计数 + 状态分布 + TTL 概览。"""
        by_type = {
            str(row["type"]): int(row["n"])
            for row in self.store.query("SELECT type, COUNT(*) AS n FROM ioc GROUP BY type")
        }
        by_status = {
            str(row["status"]): int(row["n"])
            for row in self.store.query("SELECT status, COUNT(*) AS n FROM ioc GROUP BY status")
        }
        total = sum(by_type.values())
        whitelisted = int(
            (self.store.query_one("SELECT COUNT(*) AS n FROM ioc WHERE whitelisted=1") or {}).get("n")
            or 0
        )
        return {
            "total": total,
            "by_type": by_type,
            "by_status": by_status,
            "whitelisted": whitelisted,
            "expired": int(by_status.get("expired", 0)),
            "ttl_days": dict(self.ttl_days),
        }

    # ------------------------------------------------------------------ STIX
    def export_stix(self, path: str) -> int:
        """导出全部（未过期未白名单）IOC 到 STIX bundle，返回 indicator 数。"""
        return stix.write_bundle(path, self.rows(live_only=True))

    def import_stix(self, path: str) -> dict[str, int]:
        """从 STIX bundle 导入，返回导入统计。"""
        records = stix.read_bundle(path)
        result = self.import_records(records)
        result["total"] = len(records)
        return result


def make_provider(store: Any, cfg: dict | None = None) -> IocStore:
    """便捷工厂：``NetPipeline(cfg, ..., ioc_provider=IocStore(store, cfg).provider("ip"))``。"""
    return IocStore(store, cfg)
