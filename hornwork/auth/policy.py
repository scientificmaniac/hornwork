"""认证等级（LOA）与 step-up 策略。

三因子不是"三选二叠加"：风险评分决定**要几个因子**，step-up 把强认证延伸到
会话生命周期（敏感操作要求 15 min 内重新强认证）。
"""

from __future__ import annotations

from datetime import datetime, timezone

LOA_NAMES = {
    0: "unauthenticated",
    1: "口令（+图形码）",
    2: "口令 + TOTP",
    3: "口令 + TOTP + 人脸",
}

# 动作 → 最低 LOA；写操作/响应动作/SSH 必须 LOA3
ACTION_MIN_LOA = {
    "read": 2,
    "write": 3,
    "admin": 3,
    "sensitive": 3,
    "ssh": 3,
    "sudo": 3,
}


def min_loa(action: str) -> int:
    return ACTION_MIN_LOA.get(str(action or "read"), 2)


# 角色 action 白名单：与 LOA 是 AND 关系——角色过 ≠ 放行，仍要过 min_loa/step-up。
# admin 也要 LOA3 才能写；viewer 就算 LOA3 也不能写。
ROLE_ACTIONS = {
    "viewer": {"read"},
    "operator": {"read", "write", "sensitive", "ssh", "sudo"},
    "admin": {"read", "write", "sensitive", "ssh", "sudo", "admin"},
}


def role_allows(role: str, action: str) -> bool:
    """角色是否允许该 action（纯权限判定，不含 LOA/强认证窗口）。"""
    return str(action or "read") in ROLE_ACTIONS.get(str(role or ""), set())


def min_role(action: str) -> str | None:
    """能执行该 action 的最低角色（用于 wrong_role 的可诊断 detail）。"""
    for name in ("viewer", "operator", "admin"):
        if str(action or "read") in ROLE_ACTIONS[name]:
            return name
    return None


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def step_up_required(session_row: dict, action: str = "write",
                     strong_window_sec: int = 900,
                     now: datetime | None = None) -> bool:
    """会话 LOA 够、但最近强认证超窗 → 要求 step-up（重新 TOTP+人脸）。"""
    if int(session_row.get("loa") or 0) < min_loa(action):
        return True
    if min_loa(action) < 3:
        return False          # 只读操作不要求"最近强认证"窗口
    strong = _parse(session_row.get("strong_auth_ts"))
    if strong is None:
        return True
    now = now or datetime.now(timezone.utc)
    return (now - strong).total_seconds() > int(strong_window_sec)


def can(session_row: dict, action: str = "read") -> bool:
    return int(session_row.get("loa") or 0) >= min_loa(action)


def loa_name(loa: int) -> str:
    return LOA_NAMES.get(int(loa), f"LOA{loa}")
