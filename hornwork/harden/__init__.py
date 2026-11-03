"""加固模块：加固编排（基线数据 + 画像 → 计划 → 幂等执行 → 回滚 → 前后验证 → 报告）。

入口：
- `hardenctl <plan|check|apply|verify|rollback|confirm|drill|report|asset|status>`
- `python -m hornwork.harden ...`（等价）
"""

from __future__ import annotations

__version__ = "1.0.0"
