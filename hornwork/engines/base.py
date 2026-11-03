"""检测引擎协议与命中（Hit）数据类。

所有模块只依赖本文件里的字典结构与函数，避免交叉 import。
"""

from __future__ import annotations

from typing import Any, Protocol, TypedDict, runtime_checkable


class Hit(TypedDict, total=False):
    engine: str          # hash | sigdb | yara | clamav | hostrules | sigma | netrules | memory
    rule_id: str
    name: str
    score: int           # 0-100
    meta: dict           # family/attack/version 等
    evidence: dict       # offset/hash/matched 等


class ScanContext(TypedDict, total=False):
    deep: bool
    filetype: str
    size: int
    path: str


@runtime_checkable
class ScanEngine(Protocol):
    name: str
    version: str
    cost: str            # fast | medium | slow

    def available(self) -> bool: ...
    def supports(self, ctx: ScanContext) -> bool: ...
    def scan(self, path: str, ctx: ScanContext) -> list[Hit]: ...


@runtime_checkable
class EventEngine(Protocol):
    name: str

    def on_event(self, event: dict) -> list[Hit]: ...


def make_hit(
    engine: str,
    rule_id: str,
    name: str,
    score: int,
    meta: dict | None = None,
    evidence: dict | None = None,
) -> dict:
    """构造规范化的 Hit 字典（普通 dict，便于 JSON 序列化）。"""
    return {
        "engine": str(engine),
        "rule_id": str(rule_id),
        "name": str(name or rule_id),
        "score": max(0, min(100, int(score))),
        "meta": dict(meta or {}),
        "evidence": dict(evidence or {}),
    }


def normalize_hit(hit: dict, default_engine: str = "unknown") -> dict:
    return make_hit(
        hit.get("engine", default_engine),
        hit.get("rule_id", hit.get("id", "unknown")),
        hit.get("name", hit.get("rule_id", "unknown")),
        int(hit.get("score", 50)),
        hit.get("meta") or {},
        hit.get("evidence") or {},
    )


def hit_to_alert_fields(hit: dict) -> dict:
    """把 Hit 映射成 new_alert() 需要的 rule / evidence / level。

    level 采用 的 1~15 语义：优先用规则自带 level（hostrules/Sigma），
    否则由 score(0~100) 折算（score 80 → level 8），避免把 score 当成 level。
    """
    meta = hit.get("meta") or {}
    mitre = meta.get("mitre") or meta.get("attack") or []
    if isinstance(mitre, str):
        mitre = [mitre]
    score = int(hit.get("score", 50))
    if meta.get("level") is not None:
        level = int(meta["level"])
    elif meta.get("severity") is not None:
        level = int(meta["severity"])
    else:
        level = max(1, min(15, int(round(score / 10.0))))
    return {
        "rule": {
            "id": hit.get("rule_id", "unknown"),
            "name": hit.get("name", ""),
            "engine": hit.get("engine", "unknown"),
            "version": str(meta.get("version", "1.0")),
            "level": level,
            "mitre": list(mitre),
        },
        "evidence": [hit.get("evidence") or {}],
        "confidence": score,
    }


def merge_hits(hits: list[dict]) -> list[dict]:
    """按 (engine, rule_id, evidence 关键字段) 去重合并。"""
    seen = set()
    out = []
    for hit in hits:
        key = (
            hit.get("engine"),
            hit.get("rule_id"),
            (hit.get("evidence") or {}).get("offset"),
            (hit.get("evidence") or {}).get("path"),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


class BaseScanEngine:
    """扫描引擎基类：实现 available/supports 的默认行为。"""

    name = "base"
    version = "1.0"
    cost = "fast"

    def available(self) -> bool:
        return True

    def supports(self, ctx: ScanContext) -> bool:
        return True

    def scan(self, path: str, ctx: ScanContext) -> list[Hit]:  # pragma: no cover - 抽象
        raise NotImplementedError


class BaseEventEngine:
    """事件引擎基类。"""

    name = "base"
    version = "1.0"

    def on_event(self, event: dict) -> list[Hit]:  # pragma: no cover - 抽象
        raise NotImplementedError
