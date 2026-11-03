"""加固基线模型：items.yaml 是唯一事实来源（数据），本文件只做加载与校验。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import core

CATEGORIES = {"account", "service", "tls", "perms", "audit", "crypto", "kernel", "platform"}
RISKS = {"low", "mid", "high"}
ROLLBACK_MODES = {"restore", "reverse", "manual"}
ROLES = ("A", "B", "C")

# order → 批次。批次的含义见 docs/hardening.md：低风险先做，防火墙先于 SSH，密码学在 TLS 之前。
BATCH_OF_ORDER = ((20, 1), (30, 2), (50, 3), (60, 4), (70, 5))


@dataclass(frozen=True)
class Item:
    id: str
    category: str
    title: str
    risk: str
    check: str
    apply: str
    verify: str
    order: int = 50
    timeout: int = 60
    targets: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()
    scope: dict[str, str] = field(default_factory=dict)
    rollback_mode: str = "restore"
    reverse: str | None = None
    guard_seconds: int = 0
    manual_reason: str | None = None
    batch_override: int | None = None

    # ---- 场景适配：某角色是否适用 + 不适用的原因（报告要能回答“为什么没做”）
    def applicable(self, role: str) -> bool:
        value = str(self.scope.get(role, "no")).strip().lower()
        return value.startswith("yes")

    def scope_reason(self, role: str) -> str:
        value = str(self.scope.get(role, "no")).strip()
        if value.lower().startswith("no"):
            return value[2:].lstrip(" —-:：") or "该角色不适用"
        if value.lower().startswith("partial"):
            return value[7:].lstrip(" —-:：") or "部分适用，需人工"
        return ""

    @property
    def batch(self) -> int:
        if self.batch_override:
            return self.batch_override
        for limit, number in BATCH_OF_ORDER:
            if self.order <= limit:
                return number
        return 5

    @property
    def requires_confirm(self) -> bool:
        return self.risk == "high" or self.batch >= 3


def load_items(path: str | Path | None = None) -> list[Item]:
    path = Path(path or core.ITEMS_PATH)
    with open(path, "r", encoding="utf-8") as handle:
        doc = yaml.safe_load(handle) or {}
    raw_items = doc.get("items") or []
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError(f"{path}: items 为空")

    items: list[Item] = []
    seen: set[str] = set()
    for raw in raw_items:
        item = _build_item(raw)
        if item.id in seen:
            raise ValueError(f"重复的加固项 id：{item.id}")
        seen.add(item.id)
        items.append(item)
    items.sort(key=lambda it: (it.batch, it.order, it.id))
    return items


def _build_item(raw: dict[str, Any]) -> Item:
    for field_name in ("id", "category", "title", "risk", "check", "apply", "verify"):
        if not raw.get(field_name):
            raise ValueError(f"加固项缺字段 {field_name}：{raw!r}")
    item_id = core.check_id(str(raw["id"]))
    if not item_id.startswith("H-"):
        raise ValueError(f"加固项 id 必须 H- 开头：{item_id}")
    category = str(raw["category"])
    if category not in CATEGORIES:
        raise ValueError(f"{item_id}: 未知 category {category}")
    risk = str(raw["risk"])
    if risk not in RISKS:
        raise ValueError(f"{item_id}: 未知 risk {risk}")
    scope_raw = raw.get("scope") or {}
    scope = {role: str(scope_raw.get(role, "no")) for role in ROLES}
    rollback_mode = str(raw.get("rollback", "restore"))
    if rollback_mode not in ROLLBACK_MODES:
        raise ValueError(f"{item_id}: 未知 rollback {rollback_mode}")
    targets = raw.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]
    return Item(
        id=item_id,
        category=category,
        title=str(raw["title"]),
        risk=risk,
        check=str(raw["check"]).strip(),
        apply=str(raw["apply"]).strip(),
        verify=str(raw["verify"]).strip(),
        order=int(raw.get("order", 50)),
        timeout=int(raw.get("timeout", 60)),
        targets=tuple(str(t) for t in targets),
        refs=tuple(str(r) for r in (raw.get("refs") or [])),
        scope=scope,
        rollback_mode=rollback_mode,
        reverse=(str(raw["reverse"]).strip() if raw.get("reverse") else None),
        guard_seconds=int(raw.get("guard_seconds", 0)),
        manual_reason=(str(raw["manual_reason"]) if raw.get("manual_reason") else None),
        batch_override=(int(raw["batch"]) if raw.get("batch") else None),
    )


def items_hash(path: str | Path | None = None) -> str:
    return core.sha256_file(path or core.ITEMS_PATH)

