"""模式门禁：``observe`` / ``dry-run`` / ``enforce`` 的解析与审批判定。

 的安全底线：
- 默认模式取 ``respond.default_mode``（仓库默认 observe）；
- ``enforce`` 必须显式审批：环境变量 ``HORNWORK_APPROVED=1``、或配置
  ``respond.approval_required = false``、或 ``respond.allow_enforce = true``；
- 任一不满足时 ``allowed("enforce")`` 为 False，``require_approval()`` 为 True，
  CLI 应据此拒绝真实执行。
"""

from __future__ import annotations

import os
from typing import Any

from ..config import cfg_get
from ..log import get_logger
from .actions import SUPPORTED_ACTIONS, MODES, normalize_mode

log = get_logger("respond.approve")

#: 审批开关环境变量
APPROVAL_ENV = "HORNWORK_APPROVED"

#: 破坏性动作（审批提示中优先强调）
HIGH_RISK_ACTIONS: tuple[str, ...] = (
    "isolate_host", "disable_account", "kill_process", "block_ip",
)

_TRUTHY = ("1", "true", "yes", "on", "y")


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in _TRUTHY


class ModeGuard:
    """解析默认模式并判定 enforce 是否已获得审批。"""

    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or {}
        default = cfg_get(self.cfg, "respond.default_mode", "observe")
        self.default_mode = normalize_mode(str(default or "observe"))
        self.approval_required = bool(cfg_get(self.cfg, "respond.approval_required", True))
        self.allow_enforce = _truthy(cfg_get(self.cfg, "respond.allow_enforce", False))
        self.cfg_approved = _truthy(cfg_get(self.cfg, "respond.approved", False))

    # ------------------------------------------------------------------ 模式
    def resolve(self, requested: str | None = None) -> str:
        """解析模式：空值取默认；非法字符串抛 ``ValueError``。"""
        if requested is None or str(requested).strip() == "":
            return self.default_mode
        text = str(requested).strip().lower().replace("_", "-")
        if text == "dryrun":
            text = "dry-run"
        if text not in MODES:
            raise ValueError(f"非法执行模式: {requested!r}（可选 {', '.join(MODES)}）")
        return text

    def approved(self) -> bool:
        """是否已获得 enforce 审批（环境变量或配置）。"""
        if _truthy(os.environ.get(APPROVAL_ENV, "")):
            return True
        if self.cfg_approved:
            return True
        if self.allow_enforce:
            return True
        return not self.approval_required

    def allowed(self, mode: str) -> bool:
        """该模式是否允许执行；enforce 需要审批。"""
        try:
            norm = self.resolve(mode)
        except ValueError:
            return False
        if norm != "enforce":
            return True
        return self.approved()

    def require_approval(self, action: dict[str, Any] | str | None, mode: str) -> bool:
        """该动作在当前模式与审批状态下是否"必须先审批"（True = 拒绝执行）。"""
        try:
            norm = self.resolve(mode)
        except ValueError:
            return True
        if norm != "enforce":
            return False
        if self.approved():
            return False
        name = action.get("action") if isinstance(action, dict) else action
        name = str(name or "").strip().lower()
        if name and name not in SUPPORTED_ACTIONS:
            log.warn("未知动作将按高风险处理", action=name)
        return True

    # ------------------------------------------------------------------ 组合判定
    def check(self, action: dict[str, Any] | str | None, mode: str | None) -> tuple[bool, str]:
        """返回 ``(是否可执行, 拒绝原因)``，供 CLI/daemon 直接使用。"""
        try:
            norm = self.resolve(mode)
        except ValueError as exc:
            return False, str(exc)
        if self.allowed(norm):
            return True, ""
        name = action.get("action") if isinstance(action, dict) else action
        name = str(name or "").strip().lower()
        hint = "高风险动作" if name in HIGH_RISK_ACTIONS else "enforce 模式"
        reason = (
            f"{hint}需要审批：设置环境变量 {APPROVAL_ENV}=1，"
            "或在 config.toml 中允许（respond.approval_required=false / respond.allow_enforce=true）"
        )
        log.warn("enforce 未获审批", action=name, mode=norm)
        return False, reason

    def describe(self) -> dict[str, Any]:
        """门禁状态快照（CLI status 用）。"""
        return {
            "default_mode": self.default_mode,
            "approval_required": self.approval_required,
            "allow_enforce": self.allow_enforce,
            "approved": self.approved(),
            "env": APPROVAL_ENV,
        }
