"""扫描调度：周期槽位、时间窗、合法性白名单、资源闸门、计划到 profile 的展开。

设计要点：
- **幂等靠数据库约束不靠内存标志**：槽位字符串由 :func:`slot_of` 生成，
  ``scan_task`` 的 ``UNIQUE(plan_id, asset_id, slot)`` 兜底防重入；
- **计划表是数据，timer 只是闹钟**：改周期只改 ``scan_plan`` 行，不改代码；
- **闸门在扫描前统一判定**：``allow_cidrs``（合法性硬边界）、时间窗、主机并发、磁盘余量；
  事件触发（targeted/verify-fix/manual/change）不受时间窗限制，但**白名单永远生效**。
"""

from __future__ import annotations

import ipaddress
import shutil
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..config import cfg_get
from ..log import get_logger

log = get_logger("scan.scheduler")

#: 周期类型 → 槽位模板说明
PLAN_KINDS = ("daily", "weekly", "quarterly", "targeted", "manual", "verify-fix", "change")

#: 不受时间窗限制的触发类型（事件驱动，24h 内要能立即跑）
WINDOW_EXEMPT_KINDS = ("targeted", "manual", "verify-fix", "change")

#: 扫描 profile 默认引擎集合（可被 config 覆盖）
DEFAULT_PROFILES: dict[str, dict] = {
    "quick": {
        "ports": "top:200",
        "engines": ["nmap"],
        "service_detect": True,
        "timeout_sec": 120,
        "max_hosts": 4,
        "rate_limit": 500,
    },
    "weekly": {
        "ports": "top:1000",
        "engines": ["nmap", "pkgs", "nuclei", "lynis", "testssl"],
        "service_detect": True,
        "timeout_sec": 900,
        "max_hosts": 4,
        "rate_limit": 500,
    },
    "full": {
        "ports": "1-65535",
        "engines": ["nmap", "pkgs", "nuclei", "lynis", "testssl"],
        "service_detect": True,
        "timeout_sec": 1800,
        "max_hosts": 2,
        "rate_limit": 500,
    },
    "targeted": {
        "ports": "declared",
        "engines": ["nmap"],
        "service_detect": True,
        "timeout_sec": 300,
        "max_hosts": 8,
        "rate_limit": 500,
    },
    "verify-fix": {
        "ports": "declared",
        "engines": ["nmap", "lynis", "testssl"],
        "service_detect": True,
        "timeout_sec": 300,
        "max_hosts": 8,
        "rate_limit": 500,
    },
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def slot_of(plan: dict, now: datetime | None = None) -> str:
    """周期槽位：同计划同周期只允许一个任务，重复触发返回已有任务。

    - daily → ``YYYYMMDD``；weekly → ``YYYYWww``；quarterly → ``YYYYQn``；
    - targeted → ``cve-<id>``；manual / verify-fix / change → 带时间戳（允许同一天多次）。
    """
    now = (now or _utcnow()).astimezone(timezone.utc)
    kind = str((plan or {}).get("kind") or "manual")
    params = (plan or {}).get("params_json") or {}
    if isinstance(params, str):
        try:
            import json

            params = json.loads(params)
        except (TypeError, ValueError):
            params = {}
    if kind == "daily":
        return now.strftime("%Y%m%d")
    if kind == "weekly":
        return f"{now:%G}W{now:%V}"
    if kind == "quarterly":
        return f"{now:%Y}Q{(now.month - 1) // 3 + 1}"
    if kind == "targeted":
        cve = params.get("cve_id") or params.get("target") or (plan or {}).get("plan_id")
        return f"cve-{cve}"
    if kind == "verify-fix":
        target = params.get("check_id") or params.get("asset_id") or "all"
        return f"verify-{target}-{now:%Y%m%dT%H%M}"
    if kind == "change":
        return f"change-{now:%Y%m%d}"
    return f"manual-{now:%Y%m%dT%H%M%S}"


def parse_hhmm(value: str | None, default: str = "00:00") -> dtime:
    """解析 ``"02:30"`` 为 ``time``；非法时返回默认值。"""
    text = str(value or default).strip()
    try:
        hour, minute = text.split(":", 1)
        return dtime(int(hour), int(minute))
    except (TypeError, ValueError):
        return parse_hhmm(default, "00:00")


def in_window(now: datetime | None, start: str | None, end: str | None) -> bool:
    """判断当前时间是否在扫描窗口内（支持跨午夜，如 23:00–02:00）。"""
    now = (now or _utcnow()).astimezone(timezone.utc)
    if not start or not end:
        return True
    t0, t1 = parse_hhmm(start), parse_hhmm(end)
    current = now.time()
    if t0 <= t1:
        return t0 <= current <= t1
    return current >= t0 or current <= t1


def check_allow_cidrs(cfg: dict, ip: str) -> tuple[bool, str]:
    """合法性硬边界：目标必须落在 ``[scan] allow_cidrs`` 内（默认仅回环与本机段）。

    越界一律拒绝并返回原因，由 runner 写 ``action_audit``；不扫校园网/互联网。
    """
    allow = cfg_get(cfg, "scan.allow_cidrs", ["127.0.0.1/32"]) or []
    try:
        target = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False, f"非法目标地址：{ip}"
    for entry in allow:
        try:
            if target in ipaddress.ip_network(str(entry).strip(), strict=False):
                return True, ""
        except ValueError:
            log.warn("scan.allow_cidrs 中存在非法网段", entry=str(entry))
            continue
    return False, f"目标 {ip} 不在 allow_cidrs 白名单内（越界拒绝）"


def profile_of(cfg: dict, plan: dict) -> dict:
    """把计划展开成可执行的 profile（端口规格、引擎集合、超时、并发、限速）。

    优先级：config ``scan.profiles.<name>`` > 代码内置 DEFAULT_PROFILES > 计划自身覆盖。
    """
    name = str((plan or {}).get("profile") or "weekly")
    configured = cfg_get(cfg, f"scan.profiles.{name}", {}) or {}
    profile: dict[str, Any] = dict(DEFAULT_PROFILES.get(name, DEFAULT_PROFILES["weekly"]))
    if isinstance(configured, dict):
        profile.update(configured)
    plan_engines = (plan or {}).get("engines_json")
    if plan_engines:
        profile["engines"] = list(plan_engines)
    if (plan or {}).get("rate_limit"):
        profile["rate_limit"] = int(plan["rate_limit"])
    if (plan or {}).get("max_hosts"):
        profile["max_hosts"] = int(plan["max_hosts"])
    profile["name"] = name
    return profile


def gate_check(
    cfg: dict,
    plan: dict,
    assets: list[dict],
    *,
    trigger: str = "manual",
    force_window: bool = False,
    store: Any = None,
) -> dict:
    """扫描前闸门：白名单 → 时间窗 → 并发/磁盘。返回 ``{ok, checks, reason, assets}``。

    - 白名单：**任一目标越界即整体拒绝**（不做部分扫描，避免"悄悄少扫"）；
    - 时间窗：仅周期计划受约束（L1/L2/L3），事件触发豁免；越窗时给 ``ok=False``；
    - 并发：按 profile.max_hosts 截取前 N 个资产（并记录被截断的资产，由调用方决定是否排队）。
    """
    checks: list[dict] = []
    # 1) 合法性白名单（永不豁免）
    for asset in assets:
        ok, reason = check_allow_cidrs(cfg, str(asset.get("ip")))
        checks.append({
            "check": "allow_cidrs", "asset_id": asset.get("asset_id"),
            "ip": asset.get("ip"), "ok": ok, "reason": reason,
        })
        if not ok:
            log.warn("scan.gate.rejected", asset_id=asset.get("asset_id"),
                     ip=asset.get("ip"), reason=reason)
            return {"ok": False, "checks": checks, "reason": reason, "assets": []}

    # 2) 时间窗（事件触发豁免）
    kind = str((plan or {}).get("kind") or "manual")
    start = (plan or {}).get("window_start") or cfg_get(cfg, "scan.gates.window_start", "")
    end = (plan or {}).get("window_end") or cfg_get(cfg, "scan.gates.window_end", "")
    exempt = kind in WINDOW_EXEMPT_KINDS or trigger in WINDOW_EXEMPT_KINDS
    window_ok = force_window or exempt or in_window(None, start, end)
    checks.append({
        "check": "window", "ok": window_ok, "kind": kind, "trigger": trigger,
        "start": start, "end": end, "exempt": exempt or force_window,
    })
    if not window_ok:
        reason = f"当前不在扫描时间窗 {start}-{end}（周期计划需在窗口内执行）"
        log.warn("scan.gate.window_closed", plan_id=(plan or {}).get("plan_id"), reason=reason)
        return {"ok": False, "checks": checks, "reason": reason, "assets": []}

    # 3) 磁盘余量（只警告不阻断；扫描是只读探测，报告/证据才写盘）
    min_disk_gb = float(cfg_get(cfg, "scan.gates.min_disk_gb", 1) or 0)
    try:
        data_dir = Path(str(cfg_get(cfg, "general.data_dir", "/var/lib/hornwork")))
        usage = shutil.disk_usage(str(data_dir if data_dir.exists() else data_dir.parent))
        free_gb = round(usage.free / (1024 ** 3), 2)
        disk_ok = free_gb >= min_disk_gb
    except OSError:
        free_gb, disk_ok = None, True
    checks.append({"check": "disk", "ok": disk_ok, "free_gb": free_gb,
                   "min_gb": min_disk_gb})
    if not disk_ok:
        reason = f"磁盘余量不足：{free_gb} GB < {min_disk_gb} GB"
        log.warn("scan.gate.disk_low", reason=reason)
        return {"ok": False, "checks": checks, "reason": reason, "assets": []}

    # 4) 主机并发：截断到 max_hosts（按 criticality 降序优先）
    profile = profile_of(cfg, plan)
    max_hosts = max(1, int(profile.get("max_hosts") or cfg_get(cfg, "scan.gates.max_hosts", 4)))
    ordered = sorted(
        assets,
        key=lambda a: (-int(a.get("criticality") or 3), str(a.get("asset_id"))),
    )
    selected = ordered[:max_hosts]
    deferred = [a.get("asset_id") for a in ordered[max_hosts:]]
    checks.append({"check": "max_hosts", "ok": True, "max_hosts": max_hosts,
                   "selected": len(selected), "deferred": deferred})
    return {"ok": True, "checks": checks, "reason": "", "assets": selected}


def next_run(plan: dict, now: datetime | None = None) -> str | None:
    """计算下一次计划触发时间（UTC ISO 字符串），用于 ``scan_plan.next_run`` 展示。

    - daily：每天 ``params.time``（默认 02:30）；
    - weekly：每周日 ``params.time``（默认 03:00）；
    - quarterly：每季度首个周六 ``params.time``（默认 03:00）；
    - 其它（targeted/manual/verify-fix/change）：None（事件触发，无固定周期）。
    """
    now = (now or _utcnow()).astimezone(timezone.utc)
    kind = str((plan or {}).get("kind") or "manual")
    params = (plan or {}).get("params_json") or {}
    if isinstance(params, str):
        try:
            import json

            params = json.loads(params)
        except (TypeError, ValueError):
            params = {}
    at = parse_hhmm(params.get("time"), "02:30" if kind == "daily" else "03:00")
    if kind == "daily":
        candidate = datetime.combine(now.date(), at, tzinfo=timezone.utc)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate.isoformat().replace("+00:00", "Z")
    if kind == "weekly":
        # 周日 = 6（datetime.weekday()）
        candidate = datetime.combine(now.date(), at, tzinfo=timezone.utc)
        delta = (6 - candidate.weekday()) % 7
        candidate += timedelta(days=delta)
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate.isoformat().replace("+00:00", "Z")
    if kind == "quarterly":
        quarter = (now.month - 1) // 3 + 1
        year = now.year
        # 当季第一个周六
        first = datetime(year, 3 * (quarter - 1) + 1, 1, at.hour, at.minute, tzinfo=timezone.utc)
        delta = (5 - first.weekday()) % 7  # 周六 = 5
        candidate = first + timedelta(days=delta)
        if candidate <= now:
            quarter += 1
            if quarter > 4:
                quarter, year = 1, year + 1
            first = datetime(year, 3 * (quarter - 1) + 1, 1, at.hour, at.minute,
                             tzinfo=timezone.utc)
            delta = (5 - first.weekday()) % 7
            candidate = first + timedelta(days=delta)
        return candidate.isoformat().replace("+00:00", "Z")
    return None


def plan_summary(plan: dict, cfg: dict | None = None) -> dict:
    """计划展示视图（含下一周期、展开后的 profile）。"""
    profile = profile_of(cfg or {}, plan)
    return {
        "plan_id": plan.get("plan_id"),
        "name": plan.get("name"),
        "kind": plan.get("kind"),
        "profile": plan.get("profile"),
        "enabled": bool(plan.get("enabled")),
        "selector": plan.get("selector_json") or {},
        "engines": profile.get("engines"),
        "ports": profile.get("ports"),
        "window": f"{plan.get('window_start') or '-'}~{plan.get('window_end') or '-'}",
        "last_run": plan.get("last_run"),
        "next_run": plan.get("next_run") or next_run(plan),
    }
