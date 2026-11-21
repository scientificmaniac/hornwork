"""靶场（lab）子系统在 CLI 侧的装配。

## 为什么要单独抽这一层

``lab`` 命令需要把每次靶场动作**同时**写进两个地方：

1. 事件库（``store.insert_event``）—— 供检测模块的关联分析使用；
2. 审计哈希链（``ActionExecutor.audit_event``）—— 供事后追溯。

这两个 sink 的重试/降级语义只应该有一份实现。重构前它内联在 ``Cli._lab_ctl``
里；抽到公共层后 ``commands/lab.py`` 只剩参数搬运，也避免了「lab 命令模块
反向依赖 respond 模块」这种跨命令耦合。

## 依赖方向

本模块 → ``lab.ctl`` / ``respond.actions`` / ``schema``（业务子系统），
不依赖任何 ``hornwork.commands.*``，因此不会成环。
"""

from __future__ import annotations

import sys
from typing import Any

from ..schema import normalize_event
from ..store import Store


def build_lab_ctl(cfg: dict, store: Store) -> Any:
    """构造 ``LabCtl``，并接好事件库与审计链两个 sink。

    Raises
    ------
    Exception
        可选组件缺失（docker/compose 不可用等）时原样抛出，由命令模块转成
        可读错误。这里刻意不吞异常：靶场不可用属于"能力缺失"，必须显式告知。
    """
    from ..lab.ctl import LabCtl
    from ..respond.actions import ActionExecutor

    auditor = ActionExecutor(store, cfg)

    def event_sink(event: dict) -> None:
        """靶场动作事件落库；失败只告警，绝不阻断动作（与重构前一致）。"""
        try:
            store.insert_event(normalize_event(event, cfg))
        except Exception as exc:  # noqa: BLE001 - 事件失败不影响靶场动作
            print(f"[warn] lab 事件落库失败：{exc}", file=sys.stderr)

    def audit_sink(action: str, target: str, ok: bool) -> None:
        """审计链写入；失败只告警，不阻断动作。

        ``mode`` 固定为 ``enforce``：靶场动作是**已发生**的事实（容器真的起来了），
        审计记录写的是既成事实而非待审批的响应动作，因此与 ``respond.default_mode``
        无关。这一点与重构前完全一致。
        """
        try:
            auditor.audit_event(action=action, target=target, mode="enforce", ok=ok)
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] lab 审计写入失败：{exc}", file=sys.stderr)

    return LabCtl(cfg, store, event_sink=event_sink, audit_sink=audit_sink)
