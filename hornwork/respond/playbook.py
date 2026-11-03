"""playbook：JSON 编排的处置流程（加载 / 校验 / 逐步执行）。

 结构::

    {
      "id": "PB-001",
      "name": "可疑样本处置",
      "steps": [
        {"id": "s1", "action": "quarantine_file", "mode": "enforce", "params": {"path": "${path}"}},
        {"id": "s2", "action": "collect_forensics", "mode": "observe"},
        {"id": "s3", "action": "update_case", "params": {"status": "investigating"}}
      ],
      "rollback": [{"action": "restore_file", "when": "verdict == benign"}]
    }

约束：
- 步骤 ``action`` ∈ 6 类处置动作 ∪ ``open_case/update_case/close_case/notify``；
- 步骤 ``mode`` 会被调用方 run(mode=...) 向下封顶（observe 模式下不会真执行 enforce 步骤）；
- 失败即停：任意步骤失败后不再执行后续步骤，结果里保留已完成步骤明细；
- 内置 :data:`DEFAULT_PLAYBOOKS` 供 CLI ``hornworkctl playbook run`` 使用。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..log import get_logger
from .actions import ACTIONS, MODES, ROLLBACK_ACTIONS, normalize_mode
from .case import CaseManager

log = get_logger("respond.playbook")

#: 工单/通知类步骤（不经过 ActionExecutor 的 6 类动作）
CASE_ACTIONS: tuple[str, ...] = ("open_case", "update_case", "close_case", "notify")

#: 处置动作类步骤（6 类动作 + 回滚别名 restore_file）
ACTION_STEPS: tuple[str, ...] = ACTIONS + ROLLBACK_ACTIONS

#: playbook 支持的步骤动作
SUPPORTED_ACTIONS: tuple[str, ...] = ACTION_STEPS + CASE_ACTIONS

#: 可作为 params 占位符的来源键
CONTEXT_KEYS: tuple[str, ...] = (
    "path", "file", "pid", "ip", "src_ip", "dst_ip", "user", "case_id", "host_id",
)

CASE_STATUSES: tuple[str, ...] = ("open", "investigating", "contained", "closed")
CASE_VERDICTS: tuple[str, ...] = ("tp", "fp", "benign", "unknown")
SEVERITIES: tuple[str, ...] = ("P1", "P2", "P3")

_MODE_ORDER = {"observe": 0, "dry-run": 1, "enforce": 2}


def _capped_mode(requested: str | None, cap: str | None) -> str:
    """取 ``requested`` 与 ``cap`` 中更保守的模式（observe < dry-run < enforce）。"""
    limit = normalize_mode(cap)
    if requested is None or str(requested).strip() == "":
        return limit
    req = normalize_mode(requested)
    return req if _MODE_ORDER[req] <= _MODE_ORDER[limit] else limit


def _resolve(value: Any, context: dict[str, Any]) -> Any:
    """把 ``${key}`` 占位符替换成上下文值；缺值时返回 None（由调用方判失败）。"""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("${") and text.endswith("}"):
            key = text[2:-1].strip()
            return context.get(key)
        out = value
        for key, val in context.items():
            if val is None:
                continue
            out = out.replace("${" + str(key) + "}", str(val))
        return out
    if isinstance(value, list):
        resolved = [_resolve(item, context) for item in value]
        return [item for item in resolved if item is not None]
    if isinstance(value, dict):
        resolved_dict: dict[str, Any] = {}
        for key, val in value.items():
            item = _resolve(val, context)
            if item is not None:
                resolved_dict[key] = item
        return resolved_dict
    return value


def resolve_params(params: dict[str, Any] | None, context: dict[str, Any] | None = None) -> dict[str, Any]:
    """解析步骤参数里的占位符，去掉解析不到的键。"""
    return dict(_resolve(dict(params or {}), dict(context or {})) or {})


# ---------------------------------------------------------------------------
# 加载与校验
# ---------------------------------------------------------------------------
def validate_playbook(pb: dict[str, Any]) -> list[str]:
    """校验 playbook 结构，返回错误列表（空表示通过）。"""
    errs: list[str] = []
    if not isinstance(pb, dict):
        return ["playbook 必须是 JSON 对象"]
    pb_id = str(pb.get("id") or "").strip()
    if not pb_id:
        errs.append("playbook 缺少 id")
    if not str(pb.get("name") or "").strip():
        errs.append("playbook 缺少 name")
    steps = pb.get("steps")
    if not isinstance(steps, list) or not steps:
        errs.append("playbook.steps 必须是非空数组")
        steps = []
    seen_ids: set[str] = set()
    for index, step in enumerate(steps, 0):
        prefix = f"steps[{index}]"
        if not isinstance(step, dict):
            errs.append(f"{prefix} 必须是对象")
            continue
        step_id = str(step.get("id") or "").strip()
        if not step_id:
            errs.append(f"{prefix} 缺少 id")
        elif step_id in seen_ids:
            errs.append(f"{prefix} id 重复: {step_id}")
        else:
            seen_ids.add(step_id)
        action = str(step.get("action") or "").strip()
        if action not in SUPPORTED_ACTIONS:
            errs.append(f"{prefix} 不支持的动作: {action!r}（可选 {', '.join(SUPPORTED_ACTIONS)}）")
        mode = step.get("mode")
        if mode is not None and str(mode) not in MODES:
            errs.append(f"{prefix} 非法 mode: {mode!r}（可选 {', '.join(MODES)}）")
        params = step.get("params")
        if params is not None and not isinstance(params, dict):
            errs.append(f"{prefix}.params 必须是对象")
        timeout = step.get("timeout")
        if timeout is not None:
            try:
                if int(timeout) <= 0:
                    errs.append(f"{prefix}.timeout 必须为正整数")
            except (TypeError, ValueError):
                errs.append(f"{prefix}.timeout 必须是整数")
    rollback = pb.get("rollback")
    if rollback is not None:
        if not isinstance(rollback, list):
            errs.append("playbook.rollback 必须是数组")
        else:
            for index, item in enumerate(rollback):
                if not isinstance(item, dict):
                    errs.append(f"rollback[{index}] 必须是对象")
                    continue
                if not str(item.get("action") or "").strip():
                    errs.append(f"rollback[{index}] 缺少 action")
                when = item.get("when")
                if when is not None and not isinstance(when, str):
                    errs.append(f"rollback[{index}].when 必须是字符串表达式")
    return errs


def load_playbook(path: str | Path) -> dict[str, Any]:
    """读取并校验 playbook 文件；不合法时抛 ``ValueError``。"""
    target = Path(path)
    with open(target, "r", encoding="utf-8") as fh:
        pb = json.load(fh)
    errors = validate_playbook(pb)
    if errors:
        raise ValueError(f"playbook 校验失败 {target.name}: " + "; ".join(errors))
    return pb


def default_playbook(pb_id: str) -> dict[str, Any]:
    """取内置 playbook（深拷贝，避免调用方改动全局定义）。"""
    if pb_id not in DEFAULT_PLAYBOOKS:
        raise KeyError(f"未知内置 playbook: {pb_id}")
    return json.loads(json.dumps(DEFAULT_PLAYBOOKS[pb_id]))


# ---------------------------------------------------------------------------
# 执行器
# ---------------------------------------------------------------------------
class PlaybookRunner:
    """按步骤执行 playbook；case/notify 类步骤由本类处理，其余交给 ActionExecutor。"""

    def __init__(self, store: Any, actions: Any, notify: Callable[[dict[str, Any]], None] | None = None):
        self.store = store
        self.actions = actions
        self.notify = notify
        self.cases = CaseManager(store)

    # ------------------------------------------------------------------ 入口
    def run(self, case_id: str, playbook: Any, mode: str = "observe",
            context: dict[str, Any] | None = None) -> dict[str, Any]:
        """逐步执行 playbook，失败即停；返回契约结构。"""
        run_mode = normalize_mode(mode)
        if isinstance(playbook, (str, Path)):
            try:
                pb = load_playbook(playbook)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                return {
                    "case_id": case_id, "playbook": Path(str(playbook)).name,
                    "mode": run_mode, "steps": [], "ok": False, "errors": [str(exc)],
                }
        else:
            pb = dict(playbook or {})
        errors = validate_playbook(pb)
        pb_id = str(pb.get("id") or "")
        if errors:
            log.warn("playbook 校验失败", playbook=pb_id, errors=errors)
            return {
                "case_id": case_id, "playbook": pb_id, "mode": run_mode,
                "steps": [], "ok": False, "errors": errors,
            }
        ctx = self._auto_context(case_id)
        for key, val in (context or {}).items():
            if val is not None:
                ctx[key] = val
        ctx.setdefault("case_id", case_id)
        results: list[dict[str, Any]] = []
        ok = True
        for step in pb.get("steps") or []:
            step_mode = _capped_mode(step.get("mode"), run_mode)
            params = resolve_params(step.get("params"), ctx)
            action = str(step.get("action"))
            step_result = self._execute_step(
                case_id, action, params, step_mode, timeout=step.get("timeout")
            )
            results.append(
                {
                    "id": str(step.get("id")),
                    "action": action,
                    "mode": step_mode,
                    "ok": bool(step_result.get("ok")),
                    "detail": str(step_result.get("detail") or ""),
                }
            )
            if not step_result.get("ok"):
                ok = False
                log.warn(
                    "playbook 步骤失败，停止后续执行",
                    playbook=pb_id, case_id=case_id, step=step.get("id"), action=action,
                )
                break
        result = {
            "case_id": case_id,
            "playbook": pb_id,
            "mode": run_mode,
            "steps": results,
            "ok": ok,
        }
        log.info("playbook 执行结束", playbook=pb_id, case_id=case_id, ok=ok,
                 steps=len(results), mode=run_mode)
        return result

    # ------------------------------------------------------------------ 上下文
    def _auto_context(self, case_id: str) -> dict[str, Any]:
        """从工单关联告警（同 dedup_key）自动提取参数上下文，供 ``${path}`` 等占位符使用。"""
        ctx: dict[str, Any] = {}
        try:
            case = self.store.get_case(case_id)
            if not case:
                return ctx
            dedup = case.get("dedup_key")
            if not dedup:
                return ctx
            row = self.store.query_one(
                "SELECT payload FROM alert WHERE dedup_key=? ORDER BY ts DESC LIMIT 1",
                (dedup,),
            )
            if not row:
                return ctx
            alert = json.loads(row.get("payload") or "{}")
        except Exception as exc:  # noqa: BLE001 - 自动上下文失败不影响 playbook
            log.warn("自动上下文提取失败", case_id=case_id, error=str(exc))
            return ctx
        entity = alert.get("entity") or {}
        for key in ("dst_ip", "src_ip"):
            if entity.get(key):
                ctx.setdefault(key, entity[key])
        if entity.get("dst_ip"):
            ctx.setdefault("ip", entity["dst_ip"])
        elif entity.get("src_ip"):
            ctx.setdefault("ip", entity["src_ip"])
        file_info = alert.get("file") or {}
        if file_info.get("path"):
            ctx.setdefault("path", file_info["path"])
        process = alert.get("process") or {}
        if process.get("pid"):
            ctx.setdefault("pid", process["pid"])
        if not ctx.get("path") and process.get("image"):
            ctx.setdefault("path", process["image"])
        user = alert.get("user") or {}
        if user.get("name"):
            ctx.setdefault("user", user["name"])
        return ctx

    # ------------------------------------------------------------------ 单步
    def _execute_step(self, case_id: str, action: str, params: dict[str, Any],
                      mode: str, timeout: Any = None) -> dict[str, Any]:
        """执行单个步骤：处置动作走 ActionExecutor，工单动作走 Store。"""
        if action in ACTION_STEPS:
            if self.actions is None:
                return {"ok": False, "detail": f"缺少 ActionExecutor，无法执行 {action}"}
            payload = dict(params)
            payload.setdefault("case_id", case_id)
            if timeout is not None:
                payload.setdefault("timeout", timeout)
            return self.actions.execute(action, payload, mode)
        if action == "notify":
            message = {
                "case_id": case_id,
                "title": str(params.get("message") or params.get("title") or "playbook 通知"),
                "level": str(params.get("level") or "info"),
                "mode": mode,
            }
            try:
                if self.notify is not None:
                    self.notify(message)
                self._audit(action, case_id, mode, True, case_id)
            except Exception as exc:  # noqa: BLE001 - 通知失败不影响流程
                log.warn("通知失败", error=str(exc), case_id=case_id)
                return {"ok": False, "detail": f"通知失败: {exc}"}
            return {"ok": True, "detail": f"已发送通知: {message['title']}"}
        return self._case_step(case_id, action, params, mode)

    def _case_step(self, case_id: str, action: str, params: dict[str, Any],
                   mode: str) -> dict[str, Any]:
        """处理 open_case / update_case / close_case 三种工单步骤。"""
        row = self.store.get_case(case_id)
        if action == "open_case":
            if row is not None:
                return {"ok": True, "detail": f"工单已存在: {case_id}"}
            severity = str(params.get("severity") or "P3").upper()
            if severity not in SEVERITIES:
                severity = "P3"
            self.store.insert_case(
                {
                    "case_id": case_id,
                    "title": str(params.get("title") or f"playbook 工单 {case_id}"),
                    "severity": severity,
                    "status": "open",
                    "dedup_key": params.get("dedup_key"),
                    "created_at": None,
                    "verdict": None,
                }
            )
            self._audit(action, case_id, mode, True, case_id)
            return {"ok": True, "detail": f"已创建工单 {case_id}（{severity}）"}
        if row is None:
            return {"ok": False, "detail": f"工单不存在: {case_id}"}

        fields: dict[str, Any] = {}
        status = params.get("status")
        if action == "close_case":
            status = "closed"
        if status is not None:
            status = str(status)
            if status not in CASE_STATUSES:
                return {"ok": False, "detail": f"非法工单状态: {status}"}
        verdict = params.get("verdict")
        if verdict is not None:
            verdict = str(verdict)
            if verdict not in CASE_VERDICTS:
                return {"ok": False, "detail": f"非法结论: {verdict}"}
        title = params.get("title")
        if title:
            fields["title"] = str(title)
        if not fields and status is None and verdict is None:
            return {"ok": False, "detail": "工单步骤缺少 status/verdict/title 参数"}
        ok = True
        if fields:
            ok = bool(self.store.update_case(case_id, **fields)) and ok
        if status is not None or verdict is not None:
            ok = self.cases.update(case_id, status=status, verdict=verdict) and ok
        self._audit(action, case_id, mode, ok, case_id)
        detail = f"工单 {case_id} 已更新 (status={status}, verdict={verdict}, title={title})"
        return {"ok": ok, "detail": detail if ok else f"工单更新失败（状态迁移不合法？）: {case_id}"}

    def _audit(self, action: str, target: str, mode: str, ok: bool,
               case_id: str | None) -> None:
        """工单类步骤也写审计链（与处置动作同链）。"""
        if self.actions is None:
            return
        try:
            self.actions.audit_event(action, target=target, mode=mode, ok=ok, case_id=case_id)
        except Exception as exc:  # noqa: BLE001 - 审计失败不影响流程
            log.warn("审计写入失败", action=action, error=str(exc))


# ---------------------------------------------------------------------------
# 内置 playbook（供 CLI / demo 直接使用）
# ---------------------------------------------------------------------------
DEFAULT_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "PB-001": {
        "id": "PB-001",
        "name": "可疑样本处置",
        "description": "隔离可疑样本 → 采集取证 → 工单转为调查中",
        "steps": [
            {"id": "s1", "action": "quarantine_file", "mode": "enforce",
             "params": {"path": "${path}"}, "timeout": 30},
            {"id": "s2", "action": "collect_forensics", "mode": "observe",
             "params": {"paths": ["${path}"]}},
            {"id": "s3", "action": "update_case", "params": {"status": "investigating"}},
        ],
        "rollback": [{"action": "restore_file", "when": "verdict == benign"}],
    },
    "PB-002": {
        "id": "PB-002",
        "name": "C2 外联处置",
        "description": "封禁外联 IP → 取证打包 → 工单转已遏制",
        "steps": [
            {"id": "s1", "action": "block_ip", "mode": "enforce",
             "params": {"ip": "${ip}"}, "timeout": 30},
            {"id": "s2", "action": "collect_forensics", "mode": "observe"},
            {"id": "s3", "action": "update_case", "params": {"status": "contained"}},
        ],
        "rollback": [{"action": "unblock_ip", "when": "verdict == benign"}],
    },
    "PB-003": {
        "id": "PB-003",
        "name": "暴力破解处置",
        "description": "封禁来源 IP → 锁定被爆破账号 → 工单转调查中",
        "steps": [
            {"id": "s1", "action": "block_ip", "mode": "enforce",
             "params": {"ip": "${src_ip}", "direction": "inbound"}, "timeout": 30},
            {"id": "s2", "action": "disable_account", "mode": "observe",
             "params": {"user": "${user}"}},
            {"id": "s3", "action": "update_case", "params": {"status": "investigating"}},
        ],
        "rollback": [{"action": "enable_account", "when": "verdict == fp"}],
    },
    "PB-004": {
        "id": "PB-004",
        "name": "失陷主机隔离",
        "description": "断网隔离（保留管理 IP/lo）→ 取证 → 工单转已遏制",
        "steps": [
            {"id": "s1", "action": "isolate_host", "mode": "enforce", "timeout": 30},
            {"id": "s2", "action": "collect_forensics", "mode": "observe"},
            {"id": "s3", "action": "update_case", "params": {"status": "contained"}},
        ],
        "rollback": [{"action": "unisolate_host", "when": "verdict == benign"}],
    },
    "PB-005": {
        "id": "PB-005",
        "name": "工单结案",
        "description": "写结论并关闭工单（用于验证层判定后归档）",
        "steps": [
            {"id": "s1", "action": "close_case",
             "params": {"verdict": "tp", "status": "closed"}},
        ],
        "rollback": [],
    },
}

__all__ = [
    "ACTIONS",
    "CASE_ACTIONS",
    "SUPPORTED_ACTIONS",
    "DEFAULT_PLAYBOOKS",
    "PlaybookRunner",
    "load_playbook",
    "validate_playbook",
    "resolve_params",
    "default_playbook",
]
