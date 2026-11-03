"""Sigma 子集匹配器。

加载 `rules/sigma/**/*.yml`（PyYAML `safe_load`），只支持如下子集：

| 维度 | 支持 |
|---|---|
| logsource.category | process_creation / file_event / network_connection |
| 字段 | Image/CommandLine/ParentImage/User/TargetFilename/DestinationIp/DestinationPort/QueryName |
| 修饰符 | contains / startswith / endswith / re / all |
| 条件 | selection、and/or/not、`1 of selection*`、`all of them`、`all of selection*` |

字段映射：Image→process.image、CommandLine→process.cmdline、ParentImage→process.parent_image、
User→user.name、TargetFilename→file.path、DestinationIp→network.dst_ip、
DestinationPort→network.dst_port、QueryName→network.domain。
status 为 test/deprecated、category/字段/修饰符/条件不支持、带 timeframe 或聚合的规则整条跳过，
并写 `sigma_stat(rule_id, supported=0)`；否则写 supported=1；命中时写 `sigma_stat_hit(rule_id)`。

求值核心（`eval_condition` / `match_selection`）是纯函数，可在无 PyYAML 的 Windows 上单测。
"""

from __future__ import annotations

import fnmatch
import re
import threading
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - 取决于运行环境
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore[assignment]

from ..config import cfg_get
from ..log import get_logger
from .base import BaseEventEngine, make_hit

log = get_logger("engines.sigma")

# logsource.category → 允许匹配的 event_type 集合
CATEGORY_EVENT_TYPES: dict[str, frozenset[str]] = {
    "process_creation": frozenset({"process_create"}),
    "file_event": frozenset({"file_create", "file_modify", "file_delete"}),
    "network_connection": frozenset({"net_connect"}),
}

# Sigma 字段 → CanonicalEvent 点路径（大小写不敏感）
FIELD_MAP: dict[str, str] = {
    "image": "process.image",
    "commandline": "process.cmdline",
    "parentimage": "process.parent_image",
    "user": "user.name",
    "targetfilename": "file.path",
    "destinationip": "network.dst_ip",
    "destinationport": "network.dst_port",
    "queryname": "network.domain",
}

SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "all"})

# Sigma level 字符串 → 1~12 级（score=level*10 截断 100）
LEVEL_MAP = {
    "critical": 12, "high": 9, "medium": 6, "low": 3,
    "informational": 1, "info": 1,
}

_COND_TOKEN_RE = re.compile(r"[()]|\*|[^\s()*]+")


class ConditionError(ValueError):
    """Sigma 条件表达式不支持/无法解析。"""


# ---------------------------------------------------------------------------
# 字段取值（避免与 hostrules 交叉依赖，保持模块独立）
# ---------------------------------------------------------------------------
def get_path(data: Any, dotted: str) -> Any:
    """按点路径取值，缺失返回 None。"""
    current: Any = data
    for part in str(dotted or "").split("."):
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
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _wildcard_regex(pattern: str) -> re.Pattern:
    """Sigma 默认字符串支持 `*` / `?` 通配，转成大小写不敏感正则。"""
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE)


# ---------------------------------------------------------------------------
# 选择项（selection）求值
# ---------------------------------------------------------------------------
def split_selection_key(key: str) -> tuple[str, list[str]]:
    """拆 `Image|contains|all` → ("image", ["contains","all"])。"""
    parts = str(key or "").split("|")
    field_name = parts[0].strip().lower()
    modifiers = [part.strip().lower() for part in parts[1:] if part.strip()]
    return field_name, modifiers


def _match_scalar(actual: Any, expected: Any, modifiers: set[str]) -> bool:
    if actual is None:
        return False
    if isinstance(actual, (list, tuple, set, frozenset)):
        return any(_match_scalar(item, expected, modifiers) for item in actual)
    actual_text = str(actual)
    expected_text = str(expected)
    if "re" in modifiers:
        try:
            return re.search(expected_text, actual_text, re.IGNORECASE) is not None
        except re.error:
            return False
    if "contains" in modifiers:
        return expected_text.lower() in actual_text.lower()
    if "startswith" in modifiers:
        return actual_text.lower().startswith(expected_text.lower())
    if "endswith" in modifiers:
        return actual_text.lower().endswith(expected_text.lower())
    # 无修饰符：布尔/数字/通配/大小写不敏感等值
    if isinstance(expected, bool) or isinstance(actual, bool):
        return bool(actual) == bool(expected)
    num_actual, num_expected = _as_number(actual), _as_number(expected)
    if num_actual is not None and num_expected is not None and not (
        isinstance(expected, str) and any(ch in expected for ch in "*?")
    ):
        return num_actual == num_expected
    if isinstance(expected, str) and ("*" in expected or "?" in expected):
        try:
            return _wildcard_regex(expected).match(actual_text) is not None
        except re.error:
            return False
    return actual_text.lower() == expected_text.lower()


def match_value(actual: Any, expected: Any, modifiers: Iterable[str] = ()) -> bool:
    """按 Sigma 修饰符语义比较一个字段值（列表 = OR，`all` = AND）。"""
    mods = {str(mod).lower() for mod in (modifiers or ())}
    if "all" in mods and isinstance(expected, (list, tuple)):
        inner = mods - {"all"}
        return bool(expected) and all(_match_scalar(actual, item, inner) for item in expected)
    values = list(expected) if isinstance(expected, (list, tuple)) else [expected]
    if not values:
        return False
    return any(_match_scalar(actual, item, mods) for item in values)


def match_selection(selection: Any, event: dict) -> bool:
    """求值一个 selection：映射内所有字段 AND；映射数组/列表值 OR。"""
    if isinstance(selection, (list, tuple)):
        return any(match_selection(item, event) for item in selection)
    if not isinstance(selection, dict):
        return False
    if not selection:
        return False
    for key, expected in selection.items():
        field_name, modifiers = split_selection_key(key)
        path = FIELD_MAP.get(field_name)
        if path is None:
            return False
        actual = get_path(event, path)
        if not match_value(actual, expected, modifiers):
            return False
    return True


# ---------------------------------------------------------------------------
# 条件表达式求值（递归下降）
# ---------------------------------------------------------------------------
def tokenize_condition(expr: str) -> list[str]:
    return _COND_TOKEN_RE.findall(str(expr or ""))


class _CondParser:
    """Sigma 条件：and/or/not/括号/`N of selection*`/`all of them`。"""

    def __init__(self, tokens: list[str], selections: dict, event: dict):
        self.tokens = tokens
        self.pos = 0
        self.selections = selections
        self.event = event

    # ------------------------------------------------------------ 工具
    def _peek(self, offset: int = 0) -> str | None:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else None

    def _peek_lower(self, offset: int = 0) -> str:
        token = self._peek(offset)
        return token.lower() if token is not None else ""

    def _next(self) -> str:
        token = self._peek()
        if token is None:
            raise ConditionError("条件意外结束")
        self.pos += 1
        return token

    # ------------------------------------------------------------ 求值
    def parse(self) -> bool:
        value = self._parse_or()
        if self.pos != len(self.tokens):
            raise ConditionError(f"条件尾部存在多余 token: {self._peek()!r}")
        return bool(value)

    def _parse_or(self) -> bool:
        value = self._parse_and()
        while self._peek_lower() == "or":
            self._next()
            value = self._parse_and() or value
        return value

    def _parse_and(self) -> bool:
        value = self._parse_not()
        while self._peek_lower() == "and":
            self._next()
            value = self._parse_not() and value
        return value

    def _parse_not(self) -> bool:
        if self._peek_lower() == "not":
            self._next()
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        token = self._peek()
        if token is None:
            raise ConditionError("条件意外结束")
        if token == "(":
            self._next()
            value = self._parse_or()
            if self._peek() != ")":
                raise ConditionError("条件括号不匹配")
            self._next()
            return value
        lowered = token.lower()
        # 数量表达式：1 of ... / all of ... / 2 of ...
        if lowered in ("all", "1") or lowered.isdigit():
            if self._peek_lower(1) == "of":
                return self._parse_quantifier(lowered)
        self._next()
        return self._eval_selection(token)

    def _parse_quantifier(self, count: str) -> bool:
        self._next()  # 数量 token
        self._next()  # of
        target_token = self._next()
        target = target_token
        wildcard = False
        if self._peek() == "*":
            self._next()
            wildcard = True
        if target.lower() == "them":
            names = list(self.selections.keys())
        elif wildcard:
            names = [name for name in self.selections if name.startswith(target)]
        else:
            names = [target] if target in self.selections else []
        if not names:
            raise ConditionError(f"数量表达式未匹配到 selection: {target}")
        results = [self._eval_selection(name) for name in names]
        if count == "all":
            return all(results)
        if count == "1":
            return any(results)
        return sum(1 for item in results if item) >= int(count)

    def _eval_selection(self, name: str) -> bool:
        if name not in self.selections:
            raise ConditionError(f"未知 selection: {name!r}")
        selection = self.selections[name]
        if isinstance(selection, bool):
            return selection
        if callable(selection):
            return bool(selection(self.event))
        return match_selection(selection, self.event)


def eval_condition(expr: str, selections: dict, event: dict) -> bool:
    """求值 Sigma 条件表达式；无法解析/不支持时返回 False。"""
    if not isinstance(expr, str) or not expr.strip():
        return False
    try:
        return _CondParser(tokenize_condition(expr), dict(selections or {}), event or {}).parse()
    except (ConditionError, ValueError, RecursionError):
        return False


def check_condition(expr: str, selection_names: Iterable[str]) -> str | None:
    """只做语法/引用校验（不求值），返回错误信息或 None。"""
    if not isinstance(expr, str) or not expr.strip():
        return "条件为空"
    selections = {name: False for name in selection_names}
    try:
        _CondParser(tokenize_condition(expr), selections, {}).parse()
    except (ConditionError, ValueError, RecursionError) as exc:
        return str(exc)
    return None


# ---------------------------------------------------------------------------
# 规则校验/加载
# ---------------------------------------------------------------------------
def validate_selection(selection: Any) -> str | None:
    """校验 selection 的字段/修饰符是否在支持子集内。"""
    if isinstance(selection, (list, tuple)):
        if not selection:
            return "空 selection 列表"
        for item in selection:
            error = validate_selection(item)
            if error:
                return error
        return None
    if not isinstance(selection, dict):
        return "selection 必须是映射或映射数组"
    if not selection:
        return "空 selection 映射"
    for key, expected in selection.items():
        field_name, modifiers = split_selection_key(key)
        if not field_name:
            return f"非法字段名 {key!r}"
        if field_name not in FIELD_MAP:
            return f"不支持的字段 {key!r}"
        unsupported = [mod for mod in modifiers if mod not in SUPPORTED_MODIFIERS]
        if unsupported:
            return f"不支持的修饰符 {unsupported}（字段 {key!r}）"
        if not isinstance(expected, (str, int, float, bool, list, tuple)):
            return f"字段 {key!r} 的值类型不支持"
    return None


def _extract_mitre(tags: Iterable[Any]) -> list[str]:
    techniques: list[str] = []
    for tag in tags:
        text = str(tag or "")
        if text.lower().startswith("attack.t"):
            techniques.append(text.split(".", 1)[1].upper())
    return techniques


def _resolve_rule_dir(cfg: dict, kind: str, dotted: str) -> Path:
    """定位规则目录：配置目录存在则用它，否则回退到 `<general.rule_dir>/<kind>`。"""
    configured = cfg_get(cfg, dotted, "")
    if configured and Path(str(configured)).is_dir():
        return Path(str(configured))
    base = Path(str(cfg_get(cfg, "general.rule_dir", "/opt/hornwork/rules")))
    return base / kind


class SigmaMatcher(BaseEventEngine):
    """Sigma 子集事件匹配器。"""

    name = "sigma"
    version = "1.0"

    def __init__(self, cfg: dict, store: Any = None):
        self.cfg = dict(cfg or {})
        self.store = store
        self.rule_dir = _resolve_rule_dir(self.cfg, "sigma", "engines.sigma_rule_dir")
        #  要求 status=test/deprecated 跳过；部署时可用该开关放开 test
        self.include_test = bool(cfg_get(self.cfg, "engines.sigma.include_status_test", False))
        self._lock = threading.Lock()
        self._rules: list[dict] = []
        self._by_type: dict[str, list[dict]] = {}
        self._errors: list[str] = []
        self._skips: list[dict] = []
        self._skip_reasons: dict[str, int] = {}
        self._load_stats: dict[str, Any] = {
            "loaded": 0, "supported": 0, "skipped": 0, "error": None,
        }
        self._hits = 0
        self.reload()

    # ------------------------------------------------------------ 加载
    # 跳过原因分类（stats().skip_reasons 用它汇总）
    SKIP_STATUS = "status"
    SKIP_DEPRECATED = "deprecated"
    SKIP_FIELD = "unsupported_field"
    SKIP_CONDITION = "unsupported_condition"
    SKIP_LOGSOURCE = "unsupported_logsource"
    SKIP_ERROR = "error"

    def _load_one(self, path: Path) -> tuple[dict | None, str | None, str | None]:
        """解析单个 yml；返回 (规则, 原因/错误, 跳过分类)。

        跳过分类为 None 表示加载成功；否则是 status/deprecated/unsupported_field/
        unsupported_condition/unsupported_logsource/error 之一。
        """
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            data = yaml.safe_load(text) if yaml is not None else None
        except Exception as exc:  # yaml.YAMLError / OSError
            return None, f"{path.name}: YAML 解析失败 {exc}", self.SKIP_ERROR
        if not isinstance(data, dict):
            return None, f"{path.name}: 顶层不是映射", self.SKIP_ERROR
        rule_id = str(data.get("id") or path.stem)
        title = str(data.get("title") or "").strip()
        if not title:
            return None, f"{rule_id}: 缺少 title", self.SKIP_ERROR
        status = str(data.get("status") or "stable").strip().lower()
        if status == "deprecated":
            return None, f"{rule_id}: status=deprecated 跳过", self.SKIP_DEPRECATED
        if status == "test" and not self.include_test:
            return None, f"{rule_id}: status=test 跳过（include_status_test=false）", self.SKIP_STATUS
        logsource = data.get("logsource")
        category = ""
        if isinstance(logsource, dict):
            category = str(logsource.get("category") or "").strip().lower()
        if category not in CATEGORY_EVENT_TYPES:
            return None, f"{rule_id}: 不支持的 logsource.category={category!r}", self.SKIP_LOGSOURCE
        detection = data.get("detection")
        if not isinstance(detection, dict):
            return None, f"{rule_id}: 缺少 detection", self.SKIP_ERROR
        if "timeframe" in detection:
            return None, f"{rule_id}: 不支持 detection.timeframe", self.SKIP_CONDITION
        condition = detection.get("condition")
        if not isinstance(condition, str):
            return None, f"{rule_id}: 缺少/不支持多条件列表形式的 condition", self.SKIP_CONDITION
        selections = {key: value for key, value in detection.items()
                      if key not in ("condition", "timeframe")}
        if not selections:
            return None, f"{rule_id}: detection 中没有 selection", self.SKIP_CONDITION
        for name, selection in selections.items():
            error = validate_selection(selection)
            if error:
                return None, f"{rule_id}: selection {name}: {error}", self.SKIP_FIELD
        error = check_condition(condition, list(selections))
        if error:
            return None, f"{rule_id}: 条件 {condition!r} 不支持: {error}", self.SKIP_CONDITION
        level_name = str(data.get("level") or "medium").strip().lower()
        level = LEVEL_MAP.get(level_name, 6)
        tags = [str(tag) for tag in (data.get("tags") or []) if tag]
        rule = {
            "id": rule_id,
            "title": title,
            "status": status,
            "category": category,
            "level": level,
            "level_name": level_name,
            "mitre": _extract_mitre(tags),
            "tags": tags,
            "selections": selections,
            "condition": condition,
            "description": str(data.get("description") or "").strip(),
            "path": path.name,
            "event_types": CATEGORY_EVENT_TYPES[category],
        }
        return rule, None, None


    def reload(self) -> dict:
        """重新加载 Sigma 规则，返回 {"ok","loaded","supported","skipped","error"}。"""
        if yaml is None:
            with self._lock:
                self._load_stats = {
                    "loaded": 0, "supported": 0, "skipped": 0,
                    "error": "PyYAML 未安装（pip install PyYAML==6.0.3）",
                }
            log.warn("Sigma 加载跳过：PyYAML 未安装")
            return {"ok": False, "loaded": 0, "supported": 0, "skipped": 0,
                    "error": self._load_stats["error"]}

        files: list[Path] = []
        try:
            if self.rule_dir.is_dir():
                files = sorted(self.rule_dir.rglob("*.yml")) + sorted(self.rule_dir.rglob("*.yaml"))
        except OSError as exc:
            log.warn("Sigma 规则目录不可读", dir=str(self.rule_dir), err=str(exc))
        rules: list[dict] = []
        errors: list[str] = []
        skips: list[dict] = []
        skip_reasons: dict[str, int] = {}
        for path in files:
            rule, reason, skip_kind = self._load_one(path)
            rule_id = rule["id"] if rule else self._guess_rule_id(path)
            if rule is not None:
                rules.append(rule)
                self._sigma_stat_inc(rule_id, 1)
                continue
            kind = skip_kind or self.SKIP_ERROR
            skip_reasons[kind] = skip_reasons.get(kind, 0) + 1
            skips.append({"rule_id": rule_id, "source": path.name,
                          "kind": kind, "reason": reason or ""})
            self._sigma_stat_inc(rule_id, 0)
            if kind == self.SKIP_ERROR:
                errors.append(reason or path.name)
        by_type: dict[str, list[dict]] = {}
        for rule in rules:
            for event_type in rule["event_types"]:
                by_type.setdefault(event_type, []).append(rule)
        with self._lock:
            self._rules = rules
            self._by_type = by_type
            self._errors = errors
            self._skips = skips
            self._skip_reasons = skip_reasons
            self._load_stats = {
                "loaded": len(files),
                "supported": len(rules),
                "skipped": len(files) - len(rules),
                "error": errors[0] if errors else None,
            }
        log.info("Sigma 规则加载完成", files=len(files), supported=len(rules),
                 skipped=len(skips), errors=len(errors), dir=str(self.rule_dir),
                 include_status_test=self.include_test)
        return {
            "ok": not errors,
            "loaded": len(files),
            "supported": len(rules),
            "skipped": len(files) - len(rules),
            "error": errors[0] if errors else None,
        }

    @staticmethod
    def _guess_rule_id(path: Path) -> str:
        return path.stem

    def _sigma_stat_inc(self, rule_id: str, supported: int) -> None:
        if self.store is None:
            return
        try:
            self.store.sigma_stat_inc(rule_id, supported)
        except Exception as exc:
            log.warn("sigma_stat_inc 失败", rule_id=rule_id, err=str(exc))

    def _sigma_stat_hit(self, rule_id: str) -> None:
        if self.store is None:
            return
        try:
            self.store.sigma_stat_hit(rule_id)
        except Exception as exc:
            log.warn("sigma_stat_hit 失败", rule_id=rule_id, err=str(exc))

    # ------------------------------------------------------------ 查询
    def rules(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "id": rule["id"], "title": rule["title"], "category": rule["category"],
                    "level": rule["level"], "mitre": list(rule["mitre"]),
                    "condition": rule["condition"], "path": rule["path"],
                }
                for rule in self._rules
            ]

    def stats(self) -> dict:
        """加载/命中统计：total/supported/skipped/errors/include_status_test + skip_reasons。"""
        with self._lock:
            stats = dict(self._load_stats)
            stats.update({
                "total": int(stats.get("loaded") or 0),
                "rules": len(self._rules),
                "errors": len(self._errors),
                "error_list": list(self._errors)[:20],
                "skip_reasons": dict(getattr(self, "_skip_reasons", {}) or {}),
                "skips": list(self._skips)[:50],
                "hits": self._hits,
                "dir": str(self.rule_dir),
                "include_status_test": self.include_test,
            })
        if self.store is not None:
            try:
                stats["db"] = self.store.sigma_stats()
            except Exception:
                stats["db"] = {}
        return stats

    def available(self) -> bool:
        return yaml is not None

    # ------------------------------------------------------------ 事件求值
    def on_event(self, event: dict) -> list[dict]:
        """对单个事件求值；命中写 sigma_stat 并返回 Hit 列表。"""
        if not isinstance(event, dict):
            return []
        event_type = event.get("event_type")
        with self._lock:
            candidates = list(self._by_type.get(str(event_type), []))
        if not candidates:
            return []
        hits: list[dict] = []
        for rule in candidates:
            try:
                matched = eval_condition(rule["condition"], rule["selections"], event)
            except Exception as exc:  # 单条规则失败隔离
                log.warn("Sigma 规则求值失败", rule=rule["id"], err=str(exc))
                continue
            if not matched:
                continue
            meta = {
                "mitre": list(rule["mitre"]),
                "attack": list(rule["mitre"]),
                "level": rule["level"],
                "level_name": rule["level_name"],
                "description": rule["description"],
                "rule_name": rule["title"],
                "logsource": rule["category"],
                "tags": list(rule["tags"]),
                "status": rule["status"],
                "source": rule["path"],
            }
            evidence = {
                "event_id": event.get("event_id"),
                "event_type": event_type,
                "condition": rule["condition"],
                "matched_selections": self._matched_selections(rule, event),
            }
            hits.append(make_hit(
                self.name, rule["id"], rule["title"],
                min(int(rule["level"]) * 10, 100), meta, evidence,
            ))
            self._sigma_stat_hit(rule["id"])
            with self._lock:
                self._hits += 1
        return hits

    @staticmethod
    def _matched_selections(rule: dict, event: dict, limit: int = 6) -> list[str]:
        matched: list[str] = []
        for name, selection in rule.get("selections", {}).items():
            try:
                if match_selection(selection, event):
                    matched.append(name)
            except (TypeError, ValueError):
                continue
            if len(matched) >= limit:
                break
        return matched
