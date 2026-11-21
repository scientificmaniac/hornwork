"""CLI 的 stderr 提示与结构化日志接入点。

## 为什么 CLI 默认**不**初始化结构化日志

``hornwork.log.setup_logging`` 会把根 logger 换成 JSONL 格式化器。CLI 重构前
从未调用它，因此第三方库与内部 logger 的 WARNING 走 ``logging.lastResort``，
输出为裸文本。若在 CLI 里顺手初始化，所有告警都会突然变成 JSON 行 —— 这是
对外输出格式变更，违反「无感迁移」红线。

所以：

- 面向用户的提示统一走本模块的 :func:`error` / :func:`warn` / :func:`note`，
  保证前缀、流向（stderr）与重构前逐字一致；
- 需要结构化日志的子命令（长任务、后台动作）通过 :func:`enable_structured_logging`
  **显式**开启，由该子命令自行承担输出格式后果。
"""

from __future__ import annotations

import sys


def error(message: str) -> None:
    """``[错误] <msg>`` → stderr（重构前遍布各处的失败提示）。"""
    print(f"[错误] {message}", file=sys.stderr)


def warn(message: str) -> None:
    """``[warn] <msg>`` → stderr（落库失败等可降级告警）。"""
    print(f"[warn] {message}", file=sys.stderr)


def note(message: str) -> None:
    """``[!] <msg>`` → stderr（环境异常但有降级路径，例如 daemon 未运行）。"""
    print(f"[!] {message}", file=sys.stderr)


def info(message: str) -> None:
    """``[i] <msg>`` → stderr（引导性提示，例如"先执行 setup"）。"""
    print(f"[i] {message}", file=sys.stderr)


def enable_structured_logging(level: str = "INFO", jsonl_path: str | None = None) -> None:
    """显式开启 JSONL 结构化日志（仅供需要长期日志的子命令调用）。

    默认**没有任何调用方**：CLI 的对外 stderr 契约依赖裸文本输出。
    """
    from ..log import setup_logging

    setup_logging(level=level, jsonl_path=jsonl_path)
