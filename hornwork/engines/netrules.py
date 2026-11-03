"""网络规则 DSL：词法分析 + 递归下降解析 + 单包/窗口匹配（(b)、§4.3.5、§4.3.6）。

规则示例::

    rule N-0101 syn_scan {
      proto: tcp
      flags: syn
      not_flags: ack
      window: 5s
      group_by: src_ip, dst_ip
      count_distinct: dst_port >= 20
      severity: 8
      technique: T1046
      msg: "SYN 端口扫描"
    }

匹配分两步：
1. 单包维度（proto/flags/not_flags/flags_any_of/src_cidr/dst_cidr/dst_port/
   dst_port_in/icmp_type/malformed/direction/dst_domain_in/dst_ip_in）；
2. 行为维度（window + group_by + count_distinct/count/sum_bytes/
   avg_interval_between/threshold），依赖 FlowTable 与 Tracker 的窗口聚合。
命中结果由 make_hit() 生成，engine="netrules"，score=severity*10（截断 100）；
同一 (rule_id, src_ip, dst_ip, dst_port) 在 dedup_sec（默认 60 s）内只告警一次。

本模块只依赖标准库与同包纯工具，可在 Windows 开发机上 import/单测。
"""

from __future__ import annotations

import ipaddress
import operator
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from ..config import cfg_get
from ..log import get_logger
from .base import make_hit
from .netflow import FLAG_ALIASES, FLAG_BITS, packet_ts, parse_flags_set
from .tracker import Tracker

log = get_logger("engines.netrules")

_COMPARE_FUNCS: dict[str, Callable[[float, float], bool]] = {
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
    "==": operator.eq,
    "=": operator.eq,
    "!=": operator.ne,
}

# 单包字段（用于 README/报告与解析分支）
SINGLE_FIELDS = (
    "proto", "flags", "not_flags", "flags_any_of", "src_cidr", "dst_cidr",
    "dst_port", "dst_port_in", "icmp_type", "malformed", "direction",
    "dst_domain_in", "dst_ip_in",
)
BEHAVIOR_FIELDS = (
    "window", "group_by", "count_distinct", "count", "sum_bytes",
    "avg_interval_between", "threshold",
)
META_FIELDS = ("severity", "technique", "msg")

# 域名可能挂在 Packet 的不同键上（DNS/SNI/HTTP Host）
_DOMAIN_KEYS = ("domain", "dst_domain", "query_name", "qname", "sni", "http_host")


# ---------------------------------------------------------------------------
# 词法
# ---------------------------------------------------------------------------
class ParseError(Exception):
    """规则解析错误（带文件名与行号，便于定位规则文件问题）。"""


@dataclass
class _Token:
    kind: str           # string | punct | op | word
    value: str
    line: int


_TOKEN_RE = re.compile(
    r"""
    (?P<string>"(?:\\.|[^"\\])*")
  | (?P<punct>[{}\[\](),:])
  | (?P<op>>=|<=|==|!=|>|<|=)
  | (?P<word>[A-Za-z0-9_][A-Za-z0-9_./\-]*)
    """,
    re.VERBOSE,
)
_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)(ms|s|m|h)?$")
_INT_RE = re.compile(r"^-?\d+$")


def _strip_comment(line: str) -> str:
    """去掉行内 `#` / `//` 注释（字符串内的不算）。"""
    in_str = False
    escaped = False
    for i, ch in enumerate(line):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "#":
                return line[:i]
            elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                return line[:i]
    return line


def tokenize(text: str) -> list[_Token]:
    """把规则文本切成 token 列表（保留行号）。"""
    tokens: list[_Token] = []
    for lineno, raw in enumerate(str(text or "").splitlines(), start=1):
        line = _strip_comment(raw)
        for m in _TOKEN_RE.finditer(line):
            kind = m.lastgroup or "word"
            tokens.append(_Token(kind, m.group(), lineno))
    return tokens


def _unescape(text: str) -> str:
    """把双引号字符串去引号并处理常见转义。"""
    body = text[1:-1] if text.startswith('"') and text.endswith('"') else text
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# 规则对象
# ---------------------------------------------------------------------------
@dataclass
class NetRule:
    """一条已解析的网络规则。"""

    rule_id: str
    name: str
    proto: str | None = None
    flags: frozenset[str] = frozenset()
    not_flags: frozenset[str] = frozenset()
    flags_any_of: frozenset[str] = frozenset()
    src_cidr: Any = None            # ipaddress.IPv4Network/IPv6Network
    dst_cidr: Any = None
    dst_port: int | None = None
    dst_port_in: tuple[int, ...] = ()
    icmp_type: int | None = None
    malformed: bool | None = None
    direction: str | None = None    # outbound | inbound
    dst_domain_in: tuple[str, ...] = ()
    dst_ip_in: tuple[str, ...] = ()
    window: float | None = None
    group_by: tuple[str, ...] = ()
    count_distinct: dict | None = None
    count: dict | None = None
    sum_bytes: dict | None = None
    avg_interval_between: tuple[float, float] | None = None
    threshold: dict | None = None
    severity: int = 5
    technique: str | None = None
    msg: str = ""
    source: str = ""
    line: int = 0
    raw: dict = field(default_factory=dict)

    @property
    def has_behavior(self) -> bool:
        """是否需要走窗口/行为触发路径。"""
        return bool(
            self.count_distinct or self.count or self.sum_bytes
            or self.avg_interval_between or self.threshold
        )

    def to_dict(self) -> dict:
        """转成可 JSON 序列化的普通 dict。"""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "proto": self.proto,
            "flags": sorted(self.flags),
            "not_flags": sorted(self.not_flags),
            "flags_any_of": sorted(self.flags_any_of),
            "src_cidr": str(self.src_cidr) if self.src_cidr is not None else None,
            "dst_cidr": str(self.dst_cidr) if self.dst_cidr is not None else None,
            "dst_port": self.dst_port,
            "dst_port_in": list(self.dst_port_in),
            "icmp_type": self.icmp_type,
            "malformed": self.malformed,
            "direction": self.direction,
            "dst_domain_in": list(self.dst_domain_in),
            "dst_ip_in": list(self.dst_ip_in),
            "window": self.window,
            "group_by": list(self.group_by),
            "count_distinct": dict(self.count_distinct) if self.count_distinct else None,
            "count": dict(self.count) if self.count else None,
            "sum_bytes": dict(self.sum_bytes) if self.sum_bytes else None,
            "avg_interval_between": list(self.avg_interval_between) if self.avg_interval_between else None,
            "threshold": dict(self.threshold) if self.threshold else None,
            "severity": self.severity,
            "technique": self.technique,
            "msg": self.msg,
            "source": self.source,
            "line": self.line,
        }


# ---------------------------------------------------------------------------
# 语法：递归下降
# ---------------------------------------------------------------------------
class _RuleParser:
    """单文件规则解析器；一条规则出错不影响同文件其它规则。"""

    def __init__(self, tokens: list[_Token], source: str = ""):
        self.tokens = tokens
        self.pos = 0
        self.source = source
        self.errors: list[str] = []

    # ------------------------------------------------------------ token 工具
    def _eof(self) -> bool:
        return self.pos >= len(self.tokens)

    def _peek(self, offset: int = 0) -> _Token | None:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else None

    def _peek_value(self, offset: int = 0) -> str | None:
        tok = self._peek(offset)
        return tok.value if tok else None

    def _next(self) -> _Token:
        tok = self._peek()
        if tok is None:
            raise ParseError("规则意外结束")
        self.pos += 1
        return tok

    def _expect(self, value: str) -> _Token:
        tok = self._next()
        if tok.value != value:
            raise ParseError(f"第 {tok.line} 行：期望 {value!r}，实际 {tok.value!r}")
        return tok

    def _is(self, value: str) -> bool:
        tok = self._peek()
        return tok is not None and tok.value == value

    def _value(self) -> str:
        tok = self._next()
        if tok.kind not in ("word", "string"):
            raise ParseError(f"第 {tok.line} 行：期望取值，实际 {tok.value!r}")
        return _unescape(tok.value) if tok.kind == "string" else tok.value

    # ------------------------------------------------------------ 入口
    def parse(self) -> list[NetRule]:
        rules: list[NetRule] = []
        while not self._eof():
            if not self._is("rule"):
                tok = self._next()
                raise ParseError(f"第 {tok.line} 行：期望 'rule'，实际 {tok.value!r}")
            start_line = self._peek().line if self._peek() else 0
            try:
                rules.append(self._parse_rule())
            except ParseError as exc:
                self.errors.append(f"{self.source}:{exc}" if self.source else str(exc))
                self._skip_rule(start_line)
        return rules

    def _skip_rule(self, start_line: int) -> None:
        """错误恢复：吞到当前规则的右花括号。"""
        if self._eof():
            return
        # 从当前位置开始；若还没进入 body 就先找 '{'
        depth = 0
        while not self._eof():
            tok = self._next()
            if tok.value == "{":
                depth += 1
            elif tok.value == "}":
                if depth <= 0:
                    return
                depth -= 1
        self.errors.append(f"{self.source}：第 {start_line} 行规则缺少 '}}'")

    def _parse_rule(self) -> NetRule:
        self._expect("rule")
        rid_tok = self._next()
        if rid_tok.kind != "word":
            raise ParseError(f"第 {rid_tok.line} 行：非法 rule_id {rid_tok.value!r}")
        name_tok = self._next()
        rule = NetRule(
            rule_id=rid_tok.value,
            name=_unescape(name_tok.value) if name_tok.kind == "string" else name_tok.value,
            source=self.source,
            line=rid_tok.line,
        )
        self._expect("{")
        while not self._is("}"):
            if self._eof():
                raise ParseError(f"第 {rid_tok.line} 行规则 {rule.rule_id} 缺少 '}}'")
            key_tok = self._next()
            if key_tok.kind != "word":
                raise ParseError(f"第 {key_tok.line} 行：非法字段名 {key_tok.value!r}")
            self._expect(":")
            self._assign(rule, key_tok.value.lower(), key_tok.line)
        self._expect("}")
        rule.raw = rule.to_dict()
        return rule

    # ------------------------------------------------------------ 取值工具
    def _as_duration(self) -> float:
        tok = self._next()
        m = _DURATION_RE.match(tok.value)
        if not m:
            raise ParseError(f"第 {tok.line} 行：非法时长 {tok.value!r}")
        num = float(m.group(1))
        mult = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, None: 1.0}[m.group(2)]
        value = num * mult
        if value <= 0:
            raise ParseError(f"第 {tok.line} 行：时长必须为正数")
        return value

    def _as_int(self, lo: int | None = None, hi: int | None = None) -> int:
        tok = self._next()
        if not _INT_RE.match(tok.value):
            raise ParseError(f"第 {tok.line} 行：期望整数，实际 {tok.value!r}")
        value = int(tok.value)
        if lo is not None and value < lo:
            raise ParseError(f"第 {tok.line} 行：数值 {value} 小于下限 {lo}")
        if hi is not None and value > hi:
            raise ParseError(f"第 {tok.line} 行：数值 {value} 大于上限 {hi}")
        return value

    def _as_number(self) -> float:
        tok = self._next()
        try:
            return float(tok.value)
        except ValueError:
            raise ParseError(f"第 {tok.line} 行：期望数字，实际 {tok.value!r}") from None

    def _as_bool(self) -> bool:
        tok = self._next()
        text = tok.value.strip().lower()
        if text in ("true", "yes", "1", "on"):
            return True
        if text in ("false", "no", "0", "off"):
            return False
        raise ParseError(f"第 {tok.line} 行：期望布尔值，实际 {tok.value!r}")

    def _as_flags(self) -> frozenset[str]:
        names: list[str] = []
        if self._is("["):
            self._next()
            while not self._is("]"):
                names.append(self._next().value)
                if self._is(","):
                    self._next()
                elif not self._is("]"):
                    raise ParseError("flags 列表缺少 ',' 或 ']'")
            self._expect("]")
        else:
            names.append(self._next().value)
        out: set[str] = set()
        for raw in names:
            name = FLAG_ALIASES.get(raw.strip().lower(), raw.strip().lower())
            if name not in FLAG_BITS:
                raise ParseError(f"未知 TCP flag: {raw!r}")
            out.add(name)
        return frozenset(out)

    def _as_word_list(self) -> tuple[str, ...]:
        values: list[str] = []
        if self._is("["):
            self._next()
            while not self._is("]"):
                values.append(self._value())
                if self._is(","):
                    self._next()
                elif not self._is("]"):
                    raise ParseError("列表缺少 ',' 或 ']'")
            self._expect("]")
        else:
            values.append(self._value())
            # 无方括号的逗号分隔写法：group_by: src_ip, dst_ip
            while self._is(","):
                self._next()
                values.append(self._value())
        return tuple(values)

    def _as_cidr(self) -> Any:
        raw = self._value()
        try:
            return ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ParseError(f"非法 CIDR: {raw!r}") from None

    def _as_compare(self, with_field: bool) -> dict:
        field_name = self._value().lower() if with_field else None
        tok = self._next()
        if tok.value not in _COMPARE_FUNCS:
            raise ParseError(f"第 {tok.line} 行：期望比较符（>= <= > < == !=），实际 {tok.value!r}")
        value = self._as_number()
        return {"field": field_name, "op": tok.value, "value": value}

    # ------------------------------------------------------------ 字段分派
    def _assign(self, rule: NetRule, key: str, line: int) -> None:
        if key == "proto":
            rule.proto = self._value().strip().lower()
        elif key == "flags":
            rule.flags = self._as_flags()
        elif key == "not_flags":
            rule.not_flags = self._as_flags()
        elif key == "flags_any_of":
            rule.flags_any_of = self._as_flags()
        elif key == "src_cidr":
            rule.src_cidr = self._as_cidr()
        elif key == "dst_cidr":
            rule.dst_cidr = self._as_cidr()
        elif key == "dst_port":
            rule.dst_port = self._as_int(0, 65535)
        elif key == "dst_port_in":
            ports = []
            for raw in self._as_word_list():
                try:
                    port = int(raw)
                except ValueError:
                    raise ParseError(f"非法端口 {raw!r}") from None
                if not 0 <= port <= 65535:
                    raise ParseError(f"端口越界: {port}")
                ports.append(port)
            rule.dst_port_in = tuple(ports)
        elif key == "icmp_type":
            rule.icmp_type = self._as_int(-1, 255)
        elif key == "malformed":
            rule.malformed = self._as_bool()
        elif key == "direction":
            raw = self._value().strip().lower()
            alias = {"out": "outbound", "egress": "outbound", "in": "inbound", "ingress": "inbound"}
            rule.direction = alias.get(raw, raw)
            if rule.direction not in ("outbound", "inbound"):
                raise ParseError(f"direction 只支持 outbound/inbound，实际 {raw!r}")
        elif key == "dst_domain_in":
            rule.dst_domain_in = self._as_word_list()
        elif key == "dst_ip_in":
            rule.dst_ip_in = self._as_word_list()
        elif key == "window":
            rule.window = self._as_duration()
        elif key == "group_by":
            rule.group_by = self._as_word_list()
        elif key == "count_distinct":
            rule.count_distinct = self._as_compare(with_field=True)
        elif key == "count":
            rule.count = self._as_compare(with_field=True)
        elif key == "sum_bytes":
            rule.sum_bytes = self._as_compare(with_field=False)
        elif key == "avg_interval_between":
            lo = self._as_duration()
            self._expect(",")
            hi = self._as_duration()
            if lo > hi:
                raise ParseError("avg_interval_between 下限不能大于上限")
            rule.avg_interval_between = (lo, hi)
        elif key == "threshold":
            rule.threshold = self._as_compare(with_field=False)
        elif key == "severity":
            rule.severity = self._as_int(1, 10)
        elif key == "technique":
            rule.technique = self._value()
        elif key == "msg":
            rule.msg = self._value()
        else:
            raise ParseError(f"第 {line} 行：未知字段 {key!r}")

    # 解析器内部错误恢复需要记录行号
    def _check(self) -> None:  # pragma: no cover - 预留扩展点
        return None


def parse_rules(text: str, source: str = "") -> tuple[list[NetRule], list[str]]:
    """解析规则文本，返回 (规则列表, 错误列表)。"""
    parser = _RuleParser(tokenize(text), source)
    try:
        rules = parser.parse()
    except ParseError as exc:  # 文件级结构错误
        parser.errors.append(f"{source}:{exc}" if source else str(exc))
        rules = []
    return rules, list(parser.errors)


# ---------------------------------------------------------------------------
# 规则集
# ---------------------------------------------------------------------------
def _resolve_rule_dir(cfg: dict, kind: str, dotted: str) -> Path:
    """定位规则目录：配置目录存在则用它，否则回退到 `<general.rule_dir>/<kind>`。"""
    configured = cfg_get(cfg, dotted, "")
    if configured and Path(str(configured)).is_dir():
        return Path(str(configured))
    base = Path(str(cfg_get(cfg, "general.rule_dir", "/opt/hornwork/rules")))
    return base / kind


class NetRuleSet:
    """加载 `rules/net/*.rules` 并按包求值。"""

    def __init__(self, cfg: dict, ioc_provider: Callable[[str], Iterable[str]] | None = None,
                 store: Any = None):
        self.cfg = dict(cfg or {})
        self.ioc_provider = ioc_provider if callable(ioc_provider) else None
        self.store = store
        #: 扫描模块扫描窗口门（可选）。daemon 注入后，窗口内的自扫流量不再触发扫描类告警。
        self.scan_gate: Any = None
        self.net_dir = _resolve_rule_dir(self.cfg, "net", "engines.net_rule_dir")
        self.home_net = self._parse_home_net(cfg_get(self.cfg, "net.home_net", ""))
        self.dedup_sec = float(cfg_get(self.cfg, "net.dedup_sec", 60) or 60)
        self.default_window = float(cfg_get(self.cfg, "net.tracker_window_sec", 5) or 5)
        self._rules: list[NetRule] = []
        self._errors: list[str] = []
        self._trackers: dict[float, Tracker] = {}
        self._dedup: dict[tuple, float] = {}
        self._ioc_cache: dict[str, tuple[float, frozenset[str]]] = {}
        self._lock = threading.RLock()
        self._stats = {"evaluations": 0, "hits": 0, "dedup_dropped": 0, "rule_errors": 0}
        self._last_clean = 0.0
        self.load()

    # ------------------------------------------------------------ 加载
    @staticmethod
    def _parse_home_net(raw: Any) -> Any:
        try:
            return ipaddress.ip_network(str(raw or ""), strict=False)
        except ValueError:
            return None

    def load(self) -> dict:
        """加载/重载规则目录（按文件隔离错误）。"""
        rules: list[NetRule] = []
        errors: list[str] = []
        files: list[Any] = []
        try:
            if self.net_dir.is_dir():
                files = sorted(self.net_dir.rglob("*.rules"))
        except OSError as exc:
            errors.append(f"规则目录不可读: {exc}")
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                errors.append(f"{path.name}: 读取失败 {exc}")
                continue
            parsed, file_errors = parse_rules(text, source=path.name)
            rules.extend(parsed)
            errors.extend(file_errors)
        with self._lock:
            self._rules = rules
            self._errors = errors
            self._trackers.clear()
            self._dedup.clear()
        if errors:
            log.warn("网络规则加载存在错误", rules=len(rules), errors=len(errors), first=errors[0])
        else:
            log.info("网络规则加载完成", rules=len(rules), dir=str(self.net_dir))
        return {"ok": not errors, "rules": len(rules), "errors": errors}

    def rules(self) -> list[dict]:
        """返回规则的结构化表示（list[dict]，可 JSON 序列化）。"""
        return [rule.to_dict() for rule in self._rules]

    def set_scan_gate(self, gate: Any) -> None:
        """注入扫描模块的扫描窗口门（``None`` 表示关闭联动）。

        门对象需提供 ``suppress(rule_id, src_ip, dst_ip, now) -> bool``；
        注入失败不影响规则引擎本身（检测优先）。
        """
        self.scan_gate = gate
        log.info("网络规则已接入扫描窗口门", enabled=gate is not None)

    def stats(self) -> dict:
        with self._lock:
            out = dict(self._stats)
        out.update({
            "rules": len(self._rules),
            "errors": len(self._errors),
            "trackers": len(self._trackers),
            "dedup_entries": len(self._dedup),
        })
        return out

    # ------------------------------------------------------------ 求值入口
    def evaluate(self, pkt: dict, flow: dict | None = None,
                 tracker: Tracker | None = None, now: float | None = None) -> list[dict]:
        """对单个 Packet 求值，返回命中的 Hit 列表。"""
        if not isinstance(pkt, dict) or not self._rules:
            return []
        pkt_ts = packet_ts(pkt)
        now_ts = float(now) if now is not None else (pkt_ts if pkt_ts > 0 else time.time())
        evt_ts = pkt_ts if pkt_ts > 0 else now_ts
        flags = parse_flags_set(pkt.get("flags"))
        hits: list[dict] = []
        with self._lock:
            self._stats["evaluations"] += 1
            rules = list(self._rules)
        for rule in rules:
            try:
                if not self._single_match(rule, pkt, flags):
                    continue
                behavior_evidence: dict = {}
                if rule.has_behavior:
                    tr = self._tracker_for(rule, tracker)
                    ip_len = pkt.get("ip_len")
                    if not isinstance(ip_len, (int, float)) or ip_len <= 0:
                        ip_len = pkt.get("raw_len") or 0
                    tr.add_packet(evt_ts, pkt.get("src_ip"), pkt.get("dst_ip"),
                                  pkt.get("dst_port"), int(ip_len or 0))
                    fired, behavior_evidence = self._behavior_fire(rule, pkt, tr, flow, now_ts)
                    if not fired:
                        continue
                if self._is_duplicate(rule, pkt, now_ts):
                    with self._lock:
                        self._stats["dedup_dropped"] += 1
                    continue
                # 扫描模块联动（IF-23）：扫描窗口内对"自扫流量"的扫描类规则降级为 observe，
                # 窗口外（含同一 IP）照常告警——只降级不关规则，起止留痕在 event 表。
                if self.scan_gate is not None and self.scan_gate.suppress(
                    rule.rule_id, pkt.get("src_ip"), pkt.get("dst_ip"), now_ts
                ):
                    with self._lock:
                        self._stats["scan_window_suppressed"] = int(
                            self._stats.get("scan_window_suppressed") or 0
                        ) + 1
                    log.info("扫描窗口内命中已降级", rule=rule.rule_id,
                             src=pkt.get("src_ip"), dst=pkt.get("dst_ip"))
                    continue
                hits.append(self._make_rule_hit(rule, pkt, evt_ts, flags, behavior_evidence))
                with self._lock:
                    self._stats["hits"] += 1
            except Exception as exc:  # 单条规则失败不影响其它规则
                with self._lock:
                    self._stats["rule_errors"] += 1
                log.warn("网络规则求值失败", rule=rule.rule_id, err=str(exc))
        self._maybe_clean(now_ts)
        return hits

    # ------------------------------------------------------------ 单包匹配
    def _single_match(self, rule: NetRule, pkt: dict, flags: set[str]) -> bool:
        if rule.malformed is not None and bool(pkt.get("malformed", False)) != bool(rule.malformed):
            return False
        if rule.proto and rule.proto != "any":
            if str(pkt.get("proto") or "").strip().lower() != rule.proto:
                return False
        if rule.flags and not rule.flags.issubset(flags):
            return False
        if rule.not_flags and (rule.not_flags & flags):
            return False
        if rule.flags_any_of and not (rule.flags_any_of & flags):
            return False
        if rule.src_cidr is not None and not self._ip_in_net(pkt.get("src_ip"), rule.src_cidr):
            return False
        if rule.dst_cidr is not None and not self._ip_in_net(pkt.get("dst_ip"), rule.dst_cidr):
            return False
        if rule.dst_port is not None and not self._port_equals(pkt.get("dst_port"), rule.dst_port):
            return False
        if rule.dst_port_in and not self._port_in(pkt.get("dst_port"), rule.dst_port_in):
            return False
        if rule.icmp_type is not None:
            try:
                if int(pkt.get("icmp_type")) != int(rule.icmp_type):
                    return False
            except (TypeError, ValueError):
                return False
        if rule.direction and not self._match_direction(pkt, rule.direction):
            return False
        if rule.dst_domain_in and not self._match_domain(pkt, rule.dst_domain_in):
            return False
        if rule.dst_ip_in and not self._match_dst_ip(pkt, rule.dst_ip_in):
            return False
        return True

    @staticmethod
    def _port_equals(value: Any, expected: int) -> bool:
        try:
            return int(value) == int(expected)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _port_in(value: Any, expected: Iterable[int]) -> bool:
        try:
            return int(value) in {int(x) for x in expected}
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _ip_in_net(raw: Any, network: Any) -> bool:
        try:
            return ipaddress.ip_address(str(raw)) in network
        except (TypeError, ValueError):
            return False

    def _match_direction(self, pkt: dict, direction: str) -> bool:
        if self.home_net is None:
            return False
        try:
            src = ipaddress.ip_address(str(pkt.get("src_ip")))
            dst = ipaddress.ip_address(str(pkt.get("dst_ip")))
        except (TypeError, ValueError):
            return False
        src_in = src in self.home_net
        dst_in = dst in self.home_net
        if direction == "outbound":
            return src_in and not dst_in
        return dst_in and not src_in

    def _match_domain(self, pkt: dict, sets: Iterable[str]) -> bool:
        domain = None
        for key in _DOMAIN_KEYS:
            value = pkt.get(key)
            if isinstance(value, str) and value.strip():
                domain = value.strip().rstrip(".").lower()
                break
        if domain is None:
            dns = pkt.get("dns")
            if isinstance(dns, dict):
                for key in _DOMAIN_KEYS:
                    value = dns.get(key)
                    if isinstance(value, str) and value.strip():
                        domain = value.strip().rstrip(".").lower()
                        break
        if not domain:
            return False
        for name in sets:
            if domain in self._ioc_set(name):
                return True
        return False

    def _match_dst_ip(self, pkt: dict, sets: Iterable[str]) -> bool:
        raw = pkt.get("dst_ip")
        if not raw:
            return False
        ip_text = str(raw).strip().lower()
        for name in sets:
            values = self._ioc_set(name)
            if ip_text in values:
                return True
            for item in values:
                if "/" in item:
                    try:
                        if ipaddress.ip_address(ip_text) in ipaddress.ip_network(item, strict=False):
                            return True
                    except (TypeError, ValueError):
                        continue
        return False

    # ------------------------------------------------------------ 行为维度
    def _tracker_for(self, rule: NetRule, tracker: Tracker | None) -> Tracker:
        window = float(rule.window or self.default_window)
        if tracker is not None and abs(float(getattr(tracker, "window", 0.0)) - window) < 1e-9:
            return tracker
        with self._lock:
            tr = self._trackers.get(window)
            if tr is None:
                tr = Tracker(window=window, shards=5)
                self._trackers[window] = tr
            return tr

    def _behavior_fire(self, rule: NetRule, pkt: dict, tracker: Tracker,
                       flow: dict | None, now: float) -> tuple[bool, dict]:
        src = str(pkt.get("src_ip") or "")
        dst = str(pkt.get("dst_ip") or "")
        evidence: dict = {}
        ok = True

        if rule.count_distinct:
            field_name = str(rule.count_distinct.get("field") or "dst_ip").lower()
            if field_name in ("dst_port", "dport", "dstport", "port"):
                actual = tracker.distinct_ports(now, src, dst)
            elif field_name in ("dst_ip", "dstip", "dst", "dip"):
                actual = tracker.distinct_dsts(now, src, "dst_ip")
            elif field_name in ("src_ip", "src"):
                actual = 1
            else:
                actual = tracker.distinct_dsts(now, src, field_name)
            evidence["count_distinct"] = {
                "field": field_name, "count": actual,
                "op": rule.count_distinct["op"], "threshold": rule.count_distinct["value"],
            }
            ok = ok and _compare(actual, rule.count_distinct["op"], rule.count_distinct["value"])

        if rule.count:
            field_name = str(rule.count.get("field") or "packets").lower()
            actual = tracker.count_packets(now, src, dst)
            evidence["count"] = {
                "field": field_name, "count": actual,
                "op": rule.count["op"], "threshold": rule.count["value"],
            }
            ok = ok and _compare(actual, rule.count["op"], rule.count["value"])

        if rule.sum_bytes:
            actual_bytes = tracker.sum_bytes(now, src, dst)
            if not actual_bytes and isinstance(flow, dict):
                actual_bytes = int(flow.get("bytes") or 0)
            evidence["sum_bytes"] = {
                "bytes": actual_bytes,
                "op": rule.sum_bytes["op"], "threshold": rule.sum_bytes["value"],
            }
            ok = ok and _compare(actual_bytes, rule.sum_bytes["op"], rule.sum_bytes["value"])

        if rule.avg_interval_between:
            lo, hi = rule.avg_interval_between
            avg = tracker.avg_interval(now, src, dst)
            if avg is None and isinstance(flow, dict):
                packets = int(flow.get("packets") or 0)
                if packets > 1:
                    span = float(flow.get("last_ts") or 0.0) - float(flow.get("first_ts") or 0.0)
                    avg = max(0.0, span) / float(packets - 1)
            evidence["avg_interval"] = {"avg": avg, "min": lo, "max": hi}
            ok = ok and avg is not None and lo <= avg <= hi

        if rule.threshold:
            actual = tracker.count_packets(now, src, dst)
            evidence["threshold"] = {
                "count": actual, "op": rule.threshold["op"], "threshold": rule.threshold["value"],
            }
            ok = ok and _compare(actual, rule.threshold["op"], rule.threshold["value"])

        return bool(ok), evidence

    # ------------------------------------------------------------ 去重/清理
    def _is_duplicate(self, rule: NetRule, pkt: dict, now: float) -> bool:
        key = (rule.rule_id, str(pkt.get("src_ip") or ""), str(pkt.get("dst_ip") or ""),
               str(pkt.get("dst_port")))
        with self._lock:
            last = self._dedup.get(key)
            if last is not None and now - last < self.dedup_sec:
                return True
            self._dedup[key] = now
            return False

    def _maybe_clean(self, now: float) -> None:
        with self._lock:
            if now - self._last_clean < 30.0 and len(self._dedup) < 100000:
                return
            self._last_clean = now
            keep_after = now - self.dedup_sec * 2.0
            for key in [k for k, ts in self._dedup.items() if ts < keep_after]:
                self._dedup.pop(key, None)
            # 过期的 IOC 缓存一起清掉
            for name in [n for n, (ts, _v) in self._ioc_cache.items() if now - ts > 120.0]:
                self._ioc_cache.pop(name, None)

    # ------------------------------------------------------------ 命中构造
    def _make_rule_hit(self, rule: NetRule, pkt: dict, evt_ts: float,
                       flags: set[str], behavior_evidence: dict) -> dict:
        severity = int(rule.severity or 5)
        score = max(0, min(100, severity * 10))
        evidence: dict = {
            "src_ip": pkt.get("src_ip"),
            "dst_ip": pkt.get("dst_ip"),
            "src_port": pkt.get("src_port"),
            "dst_port": pkt.get("dst_port"),
            "proto": pkt.get("proto"),
            "flags": sorted(flags),
            "ts": evt_ts,
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
        }
        evidence.update(behavior_evidence or {})
        mitre = [rule.technique] if rule.technique else []
        meta = {
            "mitre": mitre,
            "attack": mitre,
            "severity": severity,
            "severity_score": score,
            "technique": rule.technique,
            "msg": rule.msg or rule.name,
            "rule_name": rule.name,
            "evidence": evidence,
        }
        return make_hit("netrules", rule.rule_id, rule.name, score, meta, evidence)

    # ------------------------------------------------------------ IOC
    def _ioc_set(self, name: str) -> frozenset[str]:
        """按 kind 取 IOC 集合；优先 ioc_provider，其次 store，带 30 s 缓存。"""
        now = time.time()
        with self._lock:
            cached = self._ioc_cache.get(name)
        if cached is not None and now - cached[0] < 30.0:
            return cached[1]
        lowered = str(name or "").lower()
        kind = "domain" if "domain" in lowered else "ip"
        values: set[str] = set()
        provider = self.ioc_provider
        if provider is not None:
            for key in (name, kind + "s", kind):
                try:
                    got = provider(key)
                except Exception:  # provider 实现失败按空集处理
                    got = None
                if got:
                    values = {str(v) for v in got if v}
                    break
        if not values and self.store is not None:
            try:
                values = {str(v) for v in self.store.ioc_values(kind) if v}
            except Exception as exc:
                log.warn("IOC 读取失败", kind=kind, err=str(exc))
        normalized = frozenset(v.strip().lower() for v in values if v and v.strip())
        with self._lock:
            self._ioc_cache[name] = (now, normalized)
        return normalized


def _compare(actual: float, op: str, expected: float) -> bool:
    func = _COMPARE_FUNCS.get(str(op))
    if func is None:
        return False
    try:
        return bool(func(float(actual), float(expected)))
    except (TypeError, ValueError):
        return False
