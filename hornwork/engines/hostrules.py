"""主机行为规则引擎 HostRuleEngine（CONTRACT §3、(c)、§4.2.7）。

规则文件 `rules/host/*.json`，单文件一个对象或对象数组::

    {"id":"H-0001","name":"tmp 目录执行","level":8,"mitre":["T1105"],
     "event_types":["process_create"],
     "condition":{"all":[
        {"field":"process.image","op":"prefix","value":"/tmp/"},
        {"field":"user.name","op":"neq","value":"root"}]},
     "description":"..."}

条件树：`{"all":[...]}` / `{"any":[...]}` / `{"not":[...]}`（not 也兼容单对象），
叶子 `{"field","op","value"}`；op ∈ eq/neq/in/nin/prefix/suffix/contains/regex/gt/lt/exists。
字段用点路径取值（缺失 = 不匹配）。命中返回 make_hit(engine="hostrules")，
score = min(level*10, 100)，meta 含 mitre/level/description。
坏规则整条跳过并记录错误，不中断事件处理。
"""

from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any, Iterable

from ..config import cfg_get
from ..log import get_logger
from .base import BaseEventEngine, make_hit

log = get_logger("engines.hostrules")

SUPPORTED_OPS = (
    "eq", "neq", "in", "nin", "prefix", "suffix", "contains", "regex", "gt", "lt", "exists",
)
_COND_KEYS = ("all", "any", "not")
_regex_cache: dict[str, re.Pattern | None] = {}
_regex_lock = threading.Lock()


# ---------------------------------------------------------------------------
# 字段取值与叶子求值（模块级函数，便于单测）
# ---------------------------------------------------------------------------
def get_field(event: Any, dotted: str) -> Any:
    """按点路径取字段；路径缺失/类型不符返回 None。"""
    if not dotted:
        return None
    current: Any = event
    for part in str(dotted).split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, (list, tuple)) and part.isdigit():
            index = int(part)
            current = current[index] if 0 <= index < len(current) else None
        else:
            return None
        if current is None:
            return None
    return current


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _to_list(value: Any) -> list:
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _equals(actual: Any, expected: Any) -> bool:
    """宽松相等：数字按数值比较，其余按字符串比较（布尔值单独处理）。"""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return bool(actual) == bool(expected)
    num_actual, num_expected = _as_number(actual), _as_number(expected)
    if num_actual is not None and num_expected is not None:
        return num_actual == num_expected
    return str(actual) == str(expected)


def _compile_regex(pattern: str) -> re.Pattern | None:
    with _regex_lock:
        if pattern in _regex_cache:
            return _regex_cache[pattern]
    try:
        compiled = re.compile(pattern)
    except re.error:
        compiled = None
    with _regex_lock:
        _regex_cache[pattern] = compiled
    return compiled


def eval_op(op: str, actual: Any, expected: Any) -> bool:
    """单个叶子的取值比较；不支持的 op 一律 False。"""
    op = str(op or "eq").strip().lower()
    if op == "exists":
        exists = actual is not None
        if isinstance(expected, bool):
            return exists == expected
        return exists
    if actual is None:
        return False
    if op == "eq":
        return _equals(actual, expected)
    if op == "neq":
        return not _equals(actual, expected)
    if op == "in":
        return any(_equals(actual, item) for item in _to_list(expected))
    if op == "nin":
        return not any(_equals(actual, item) for item in _to_list(expected))
    if op == "prefix":
        text = str(actual)
        return any(text.startswith(str(item)) for item in _to_list(expected))
    if op == "suffix":
        text = str(actual)
        return any(text.endswith(str(item)) for item in _to_list(expected))
    if op == "contains":
        text = str(actual)
        return any(str(item) in text for item in _to_list(expected))
    if op == "regex":
        text = str(actual)
        for item in _to_list(expected):
            compiled = _compile_regex(str(item))
            if compiled is not None and compiled.search(text):
                return True
        return False
    if op in ("gt", "lt"):
        num_actual, num_expected = _as_number(actual), _as_number(expected)
        if num_actual is None or num_expected is None:
            return False
        return num_actual > num_expected if op == "gt" else num_actual < num_expected
    return False


def eval_leaf(leaf: dict, event: dict) -> bool:
    """求值一个叶子条件。"""
    if not isinstance(leaf, dict):
        return False
    field_name = leaf.get("field")
    if not field_name:
        return False
    return eval_op(str(leaf.get("op", "eq")), get_field(event, str(field_name)),
                   leaf.get("value"))


def eval_condition(cond: Any, event: dict) -> bool:
    """递归求值条件树（all/any/not）。"""
    if isinstance(cond, list):  # 裸数组按 all 处理
        return bool(cond) and all(eval_condition(item, event) for item in cond)
    if not isinstance(cond, dict):
        return False
    for key in _COND_KEYS:
        if key in cond:
            children = cond[key]
            if not isinstance(children, (list, tuple)):
                children = [children]
            children = list(children)
            if key == "all":
                return bool(children) and all(eval_condition(item, event) for item in children)
            if key == "any":
                return any(eval_condition(item, event) for item in children)
            return not any(eval_condition(item, event) for item in children)  # not
    if "field" in cond:
        return eval_leaf(cond, event)
    return False


def collect_leaf_fields(cond: Any, out: list[str] | None = None) -> list[str]:
    """收集条件树里引用的字段名（用于 evidence 展示）。"""
    fields = out if out is not None else []
    if isinstance(cond, list):
        for item in cond:
            collect_leaf_fields(item, fields)
    elif isinstance(cond, dict):
        if "field" in cond:
            fields.append(str(cond["field"]))
        for key in _COND_KEYS:
            if key in cond:
                collect_leaf_fields(cond[key], fields)
    return fields


def validate_rule(rule: Any, fallback_id: str = "") -> tuple[dict | None, str | None]:
    """校验并归一化一条主机规则；非法返回 (None, 错误信息)。"""
    if not isinstance(rule, dict):
        return None, "规则不是 JSON 对象"
    rule_id = str(rule.get("id") or fallback_id or "").strip()
    if not rule_id:
        return None, "缺少 id"
    name = str(rule.get("name") or "").strip()
    if not name:
        return None, f"{rule_id}: 缺少 name"
    condition = rule.get("condition")
    if not isinstance(condition, (dict, list)) or not condition:
        return None, f"{rule_id}: condition 必须是非空对象/数组"
    leaves = collect_leaf_fields(condition)
    if not leaves:
        return None, f"{rule_id}: condition 中没有叶子条件"
    for op in _iter_ops(condition):
        if op not in SUPPORTED_OPS:
            return None, f"{rule_id}: 不支持的 op {op!r}"
    try:
        level = int(rule.get("level", 5))
    except (TypeError, ValueError):
        level = 5
    level = max(1, min(10, level))
    event_types = rule.get("event_types") or []
    if isinstance(event_types, str):
        event_types = [event_types]
    event_types = [str(item) for item in event_types if item]
    mitre = rule.get("mitre") or []
    if isinstance(mitre, str):
        mitre = [mitre]
    return {
        "id": rule_id,
        "name": name,
        "level": level,
        "mitre": [str(item) for item in mitre if item],
        "event_types": event_types,
        "condition": condition,
        "description": str(rule.get("description") or ""),
        "fields": leaves,
        "source": str(rule.get("source") or ""),
    }, None


def _iter_ops(cond: Any) -> Iterable[str]:
    if isinstance(cond, list):
        for item in cond:
            yield from _iter_ops(item)
    elif isinstance(cond, dict):
        if "field" in cond:
            yield str(cond.get("op", "eq")).lower()
        for key in _COND_KEYS:
            if key in cond:
                yield from _iter_ops(cond[key])


def _resolve_rule_dir(cfg: dict, kind: str, dotted: str) -> Path:
    """定位规则目录：配置目录存在则用它，否则回退到 `<general.rule_dir>/<kind>`。"""
    configured = cfg_get(cfg, dotted, "")
    if configured and Path(str(configured)).is_dir():
        return Path(str(configured))
    base = Path(str(cfg_get(cfg, "general.rule_dir", "/opt/hornwork/rules")))
    return base / kind


# ---------------------------------------------------------------------------
# 引擎
# ---------------------------------------------------------------------------
class HostRuleEngine(BaseEventEngine):
    """主机事件规则引擎（JSON DSL）。"""

    name = "hostrules"
    version = "1.0"

    def __init__(self, cfg: dict, store: Any = None):
        self.cfg = dict(cfg or {})
        self.store = store
        self.rule_dir = _resolve_rule_dir(self.cfg, "host", "engines.host_rule_dir")
        self._lock = threading.Lock()
        self._rules: list[dict] = []
        self._errors: list[str] = []
        self._hits = 0
        self._last_load: dict = {}
        self.reload()

    # ------------------------------------------------------------ 加载
    def reload(self) -> dict:
        """加载 `rules/host/*.json`；坏规则跳过并记录错误。返回统计。"""
        rules: list[dict] = []
        errors: list[str] = []
        files: list[Path] = []
        try:
            if self.rule_dir.is_dir():
                files = sorted(self.rule_dir.glob("*.json"))
        except OSError as exc:
            errors.append(f"规则目录不可读: {exc}")
        for path in files:
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"{path.name}: JSON 解析失败 {exc}")
                continue
            items = data if isinstance(data, list) else [data]
            for index, item in enumerate(items):
                fallback = f"{path.stem}-{index + 1}" if isinstance(data, list) else path.stem
                rule, error = validate_rule(item, fallback_id=fallback)
                if error:
                    errors.append(f"{path.name}: {error}")
                    continue
                rule["source"] = rule["source"] or path.name
                rules.append(rule)
        with self._lock:
            self._rules = rules
            self._errors = errors
            self._last_load = {"rules": len(rules), "errors": len(errors), "dir": str(self.rule_dir)}
        if errors:
            log.warn("主机规则加载存在错误", rules=len(rules), errors=len(errors), first=errors[0])
        else:
            log.info("主机规则加载完成", rules=len(rules), dir=str(self.rule_dir))
        return {"ok": not errors, "rules": len(rules), "errors": errors}

    def rules(self) -> list[dict]:
        """返回已加载规则的字段级预览（供控制台展示）。"""
        with self._lock:
            return [
                {
                    "id": rule["id"], "name": rule["name"], "level": rule["level"],
                    "mitre": list(rule["mitre"]), "event_types": list(rule["event_types"]),
                    "fields": list(rule["fields"]), "description": rule["description"],
                    "source": rule["source"],
                }
                for rule in self._rules
            ]

    def stats(self) -> dict:
        with self._lock:
            return {
                "rules": len(self._rules),
                "errors": len(self._errors),
                "hits": self._hits,
                "dir": str(self.rule_dir),
            }

    # ------------------------------------------------------------ 事件求值
    def on_event(self, event: dict) -> list[dict]:
        """对单个 CanonicalEvent 求值，返回命中列表。"""
        if not isinstance(event, dict):
            return []
        event_type = event.get("event_type")
        with self._lock:
            rules = list(self._rules)
        hits: list[dict] = []
        for rule in rules:
            event_types = rule.get("event_types") or []
            if event_types and event_type not in event_types:
                continue
            try:
                matched = eval_condition(rule["condition"], event)
            except Exception as exc:  # 单条规则失败不影响其它规则
                log.warn("主机规则求值失败", rule=rule["id"], err=str(exc))
                continue
            if not matched:
                continue
            meta = {
                "mitre": list(rule["mitre"]),
                "attack": list(rule["mitre"]),
                "level": int(rule["level"]),
                "description": rule["description"],
                "rule_name": rule["name"],
                "event_type": event_type,
                "source": rule["source"],
            }
            evidence = {
                "event_id": event.get("event_id"),
                "event_type": event_type,
                "ts": event.get("ts"),
                "matched": self._matched_leaves(rule["condition"], event),
            }
            hits.append(make_hit(
                self.name, rule["id"], rule["name"],
                min(int(rule["level"]) * 10, 100), meta, evidence,
            ))
            with self._lock:
                self._hits += 1
        return hits

    @staticmethod
    def _matched_leaves(cond: Any, event: dict, limit: int = 8) -> list[dict]:
        """把命中的叶子条件（字段/操作/实际值）整理成 evidence。"""
        out: list[dict] = []
        if isinstance(cond, list):
            for item in cond:
                out.extend(HostRuleEngine._matched_leaves(item, event, limit))
        elif isinstance(cond, dict):
            if "field" in cond:
                actual = get_field(event, str(cond.get("field")))
                if eval_leaf(cond, event):
                    out.append({
                        "field": cond.get("field"), "op": cond.get("op", "eq"),
                        "value": cond.get("value"), "actual": actual,
                    })
            for key in _COND_KEYS:
                if key in cond:
                    out.extend(HostRuleEngine._matched_leaves(cond[key], event, limit))
        return out[:limit]
