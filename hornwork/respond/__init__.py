"""响应层：工单状态机 + 处置动作 + playbook + 模式门禁。

子模块：
- :mod:`hornwork.respond.case`      工单 CRUD 与状态机；
- :mod:`hornwork.respond.actions`   6 类处置动作、审计哈希链、回滚；
- :mod:`hornwork.respond.playbook`  playbook 加载/校验/编排执行；
- :mod:`hornwork.respond.approve`   observe/dry-run/enforce 模式门禁。

导入期不执行任何 Linux 专属调用，Windows 开发机可安全 import。
"""

from __future__ import annotations

from . import actions, approve, case, playbook
from .actions import ACTIONS, SUPPORTED_ACTIONS, ActionExecutor, verify_chain
from .approve import ModeGuard
from .case import CaseManager, STATES, severity_from_level
from .playbook import DEFAULT_PLAYBOOKS, PlaybookRunner, load_playbook, validate_playbook

__all__ = [
    "actions",
    "approve",
    "case",
    "playbook",
    "ActionExecutor",
    "ACTIONS",
    "SUPPORTED_ACTIONS",
    "verify_chain",
    "ModeGuard",
    "CaseManager",
    "STATES",
    "severity_from_level",
    "DEFAULT_PLAYBOOKS",
    "PlaybookRunner",
    "load_playbook",
    "validate_playbook",
]
