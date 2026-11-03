"""CVSS 3.1 基础评分计算器。

- 只支持 CVSS 3.1（NVD 主评口径），3.0/4.0 向量直接报错；支持省略 ``CVSS:3.1/`` 前缀。
- ``roundup`` 用整数运算实现 FIRST 规范"向上取整到 1 位小数"，避开浮点误差
  （直接 ``ceil(x*10)/10`` 会把 9.8 算成 9.7）。
- ``parse`` / ``build`` 互为逆操作，固定分量顺序 AV,AC,PR,UI,S,C,I,A。
- 纯函数、无全局状态，导入期不触碰 Linux 设施，Windows 可直接单测。

对拍：``tests/test_cvss.py`` 用 的 8 个公开向量逐条断言
（9.8 / 10.0 / 9.9 / 7.8 / 7.5 / 5.9 / 6.1 / 0.0）。
"""

from __future__ import annotations

from typing import Any

#: 唯一支持的向量前缀
PREFIX = "CVSS:3.1"

#: 固定序列化顺序（也是 CVSS 3.1 规范建议的书写顺序）
METRIC_ORDER: tuple[str, ...] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

#: 各分量合法取值
_ALLOWED: dict[str, tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("H", "L", "N"),
    "I": ("H", "L", "N"),
    "A": ("H", "L", "N"),
}

#: 分量权重表
_AV_W: dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_W: dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_W_U: dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_W_C: dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_W: dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA_W: dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.00}


def _normalize_metrics(metrics: dict[str, Any]) -> dict[str, str]:
    """校验分量集合与取值，返回按 ``METRIC_ORDER`` 排列的新 dict。"""
    if not isinstance(metrics, dict):
        raise ValueError("CVSS 分量必须是 dict")
    upper: dict[str, Any] = {}
    for key, val in metrics.items():
        name = str(key).strip().upper()
        if name not in _ALLOWED:
            raise ValueError(f"未知或暂不支持的 CVSS 分量: {key!r}（仅支持 {', '.join(METRIC_ORDER)}）")
        if name in upper:
            raise ValueError(f"CVSS 分量重复: {name}")
        upper[name] = val
    out: dict[str, str] = {}
    for name in METRIC_ORDER:
        if name not in upper:
            raise ValueError(f"缺少 CVSS 分量: {name}")
        value = str(upper[name]).strip().upper()
        if value not in _ALLOWED[name]:
            raise ValueError(
                f"CVSS 分量 {name} 取值非法: {value!r}（允许 {'/'.join(_ALLOWED[name])}）"
            )
        out[name] = value
    return out


def parse(vector: str) -> dict[str, str]:
    """把 CVSS 3.1 向量串解析成 ``{"AV": "N", ...}``。

    - 支持带前缀 ``CVSS:3.1/...`` 与省略前缀 ``AV:N/...`` 两种写法；
    - 前缀只接受 3.1（大小写不敏感），3.0/4.0 一律 ``ValueError``；
    - 分量顺序无关，但会校验"不重不漏"。
    """
    text = str(vector or "").strip()
    if not text:
        raise ValueError("CVSS 向量为空")
    head, sep, rest = text.partition("/")
    if head.strip().upper().startswith("CVSS:"):
        if head.strip().upper() != PREFIX:
            raise ValueError(f"仅支持 {PREFIX} 向量，收到前缀: {head.strip()!r}")
        if not sep:
            raise ValueError(f"CVSS 向量缺少分量: {text!r}")
        body = rest
    else:
        body = text
    raw: dict[str, str] = {}
    seen: set[str] = set()
    for segment in body.split("/"):
        segment = segment.strip()
        if not segment:
            continue
        key, colon, value = segment.partition(":")
        if not colon:
            raise ValueError(f"CVSS 分量缺少冒号: {segment!r}")
        name = key.strip().upper()
        if name in seen:
            raise ValueError(f"CVSS 分量重复: {name}")
        seen.add(name)
        raw[name] = value
    return _normalize_metrics(raw)


def build(metrics: dict[str, str]) -> str:
    """按固定顺序 AV,AC,PR,UI,S,C,I,A 序列化向量（缺项/越界会报错）。"""
    norm = _normalize_metrics(metrics)
    return PREFIX + "/" + "/".join(f"{name}:{norm[name]}" for name in METRIC_ORDER)


def roundup(x: float) -> float:
    """向上取整到 1 位小数（整数运算，避开浮点误差）。

    规范实现：``i = round(x*100000)``；``i % 10000 == 0`` 时取 ``i/100000``，
    否则取 ``(floor(i/10000) + 1) / 10``。与 FIRST 官方计算器 / NVD 结果一致。
    """
    value = float(x)
    if value <= 0:
        return 0.0
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000
    return (scaled // 10000 + 1) / 10


def _weights(metrics: dict[str, str]) -> tuple[dict[str, float], bool]:
    """返回各分量权重与"Scope 是否改变"。"""
    scope_changed = metrics["S"] == "C"
    pr_table = _PR_W_C if scope_changed else _PR_W_U
    weights = {
        "AV": _AV_W[metrics["AV"]],
        "AC": _AC_W[metrics["AC"]],
        "PR": pr_table[metrics["PR"]],
        "UI": _UI_W[metrics["UI"]],
        "C": _CIA_W[metrics["C"]],
        "I": _CIA_W[metrics["I"]],
        "A": _CIA_W[metrics["A"]],
    }
    return weights, scope_changed


def _to_metrics(vector: str | dict) -> dict[str, str]:
    """统一入口：字符串走 parse，dict 走 build（复用同一套校验）。"""
    if isinstance(vector, dict):
        return parse(build(vector))
    return parse(str(vector))


def explain(vector: str | dict) -> dict:
    """返回评分的完整中间量，供报告"关键实现"章节展开。

    键：vector / metrics / weights / scope_changed / iss / impact /
        exploitability / base_score / severity。
    """
    metrics = _to_metrics(vector)
    weights, scope_changed = _weights(metrics)

    iss = 1.0 - (1.0 - weights["C"]) * (1.0 - weights["I"]) * (1.0 - weights["A"])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = (
        8.22 * weights["AV"] * weights["AC"] * weights["PR"] * weights["UI"]
    )

    if impact <= 0:
        base = 0.0
    else:
        total = impact + exploitability
        if scope_changed:
            total = 1.08 * total
        base = roundup(min(total, 10.0))

    return {
        "vector": build(metrics),
        "metrics": dict(metrics),
        "weights": dict(weights),
        "scope_changed": scope_changed,
        "iss": round(iss, 6),
        "impact": round(impact, 6),
        "exploitability": round(exploitability, 6),
        "base_score": base,
        "severity": severity(base),
    }


def calculate(vector: str | dict) -> float:
    """计算 BaseScore，返回 1 位小数（0.0～10.0）。"""
    return float(explain(vector)["base_score"])


def severity(score: float) -> str:
    """分值 → 中文等级：0 / 0.1-3.9 低 / 4.0-6.9 中 / 7.0-8.9 高 / 9.0-10.0 严重。"""
    value = float(score)
    if value <= 0:
        return "无"
    if value < 4.0:
        return "低"
    if value < 7.0:
        return "中"
    if value < 9.0:
        return "高"
    return "严重"
