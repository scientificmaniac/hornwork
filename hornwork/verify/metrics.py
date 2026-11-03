"""验证指标：TPR / FPR / MTTD / 技术覆盖率。

输入是"用例判定结果行"列表，既可以是 judge_case() 的返回值，也可以是
validation 表的行（含 verdict/technique/mttd_sec 字段）；未知 verdict 一律计入 inconclusive。
分母为 0 的比率返回 None（JSON 里呈现为 null，不伪造 0）。
"""

from __future__ import annotations

from typing import Any

_VERDICTS = ("TP", "TN", "FP", "FN", "inconclusive")


def _rate(numerator: int, denominator: int) -> float | None:
    """安全除法：分母为 0 返回 None。"""
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def compute_metrics(rows: list[dict]) -> dict:
    """汇总验证指标。

    返回（契约第 6 节）：
    {"TP","TN","FP","FN","inconclusive","tpr","fpr","mttd_sec","coverage","techniques"}
    - tpr = TP/(TP+FN)，无正样本时 None；
    - fpr = FP/(FP+TN)，无阴性样本时 None；
    - mttd_sec = TP 用例首个告警时延均值（秒，保留 2 位小数），无样本时 None；
    - coverage = 有 TP 命中的技术数 / 用例涉及的技术数；
    - techniques = 用例涉及的 ATT&CK 技术编号（去重保序）。
    """
    counts = {key: 0 for key in _VERDICTS}
    mttd_samples: list[float] = []
    techniques: list[str] = []
    covered: set[str] = set()

    for raw in rows or []:
        row = raw or {}
        verdict = str(row.get("verdict") or "").strip()
        if verdict not in counts:
            verdict = "inconclusive"
        counts[verdict] += 1

        technique = str(row.get("technique") or "").strip()
        if technique:
            if technique not in techniques:
                techniques.append(technique)
            if verdict == "TP":
                covered.add(technique)

        if verdict == "TP":
            mttd = row.get("mttd_sec")
            if mttd is not None:
                try:
                    mttd_samples.append(float(mttd))
                except (TypeError, ValueError):
                    pass

    tp, tn, fp, fn = counts["TP"], counts["TN"], counts["FP"], counts["FN"]
    mttd_mean: float | None = None
    if mttd_samples:
        mttd_mean = round(sum(mttd_samples) / len(mttd_samples), 2)

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "inconclusive": counts["inconclusive"],
        "tpr": _rate(tp, tp + fn),
        "fpr": _rate(fp, fp + tn),
        "mttd_sec": mttd_mean,
        "coverage": _rate(len(covered), len(techniques)),
        "techniques": techniques,
    }


def metrics_from_validation(rows: list[dict]) -> dict:
    """validation 表行 → 指标（payload 里的技术/时延补齐到行顶层，便于复用）。"""
    normalized: list[dict] = []
    for row in rows or []:
        item = dict(row or {})
        payload: Any = item.get("payload")
        if isinstance(payload, dict):
            item.setdefault("technique", payload.get("technique"))
            item.setdefault("mttd_sec", payload.get("mttd_sec"))
        normalized.append(item)
    return compute_metrics(normalized)
