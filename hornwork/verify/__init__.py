"""验证层：行为模拟、TP/TN/FP/FN 判定、指标汇总与整机内存取证。

对外出口（与 docs/CONTRACT.md 第 6 节一致）：
- judge_case(store, case, t0, window_sec) -> dict；
- compute_metrics(rows) -> dict；
- VerifyRunner(store, cfg, ctl_call=None)；
- Forensics(store, cfg) / parse_malfind(text) / parse_pslist(text)。
"""

from __future__ import annotations

from .forensics import Forensics, parse_malfind, parse_pslist
from .judge import judge_case
from .metrics import compute_metrics
from .runner import VerifyRunner

__all__ = [
    "Forensics",
    "VerifyRunner",
    "compute_metrics",
    "judge_case",
    "parse_malfind",
    "parse_pslist",
]
