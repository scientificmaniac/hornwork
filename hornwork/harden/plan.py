"""计划生成：基线 + 资产画像 → harden_plan（执行器只认计划，不读基线）。"""

from __future__ import annotations

import platform
import socket
import sys
from pathlib import Path
from typing import Any

from . import core, items as items_mod


def collect_profile(cfg: dict | None = None, asset: str = "A", role: str = "A") -> dict[str, Any]:
    """资产画像：能自动采集的自动采集，角色/数据敏感度等由调用方显式指定（不猜）。"""
    import shutil

    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    except OSError:
        pass
    ports = core.sh("ss -lntuH 2>/dev/null | awk '{print $1}' | sort | uniq -c | tr '\\n' ' '")
    audit = core.sh("auditctl -l 2>/dev/null | wc -l")
    ufw = core.sh("ufw status 2>/dev/null | head -1")
    tls_conf = Path("/etc/nginx/conf.d/hornwork-tls.conf")
    profile = {
        "asset_id": asset,
        "role": role,
        "hostname": socket.gethostname(),
        "os_id": os_release.get("ID", "unknown"),
        "os_version": os_release.get("VERSION_ID", "unknown"),
        "os_pretty": os_release.get("PRETTY_NAME", platform.platform()),
        "kernel": platform.release(),
        "python": sys.version.split()[0],
        "ips": core.sh("hostname -I 2>/dev/null").get("out", "").split(),
        "listen_summary": ports.get("out", ""),
        "audit_rules": int(audit.get("out") or 0) if audit.get("rc") == 0 else 0,
        "ufw": ufw.get("out", ""),
        "tools": {
            name: bool(shutil.which(name))
            for name in ("openssl", "lynis", "nginx", "cryptsetup", "ufw", "augenrules", "systemd-run")
        },
        "tls_service": tls_conf.is_file(),
        "data_sensitivity": "mid（测试环境数据）",
        "backup_device": "loopback 文件（无第二块虚拟盘；设备名人工确认后由 H-CR-04 使用）",
        "platform_note": "防护主机全量加固；靶场主机故意不加固（受控弱点样本）；第三台主机 Windows 用人工检查单",
    }
    return profile


def _batch_map(items: list[items_mod.Item]) -> dict[int, list[str]]:
    batches: dict[int, list[str]] = {}
    for item in items:
        batches.setdefault(item.batch, []).append(item.id)
    return dict(sorted(batches.items()))


def build_plan(
    items: list[items_mod.Item] | None = None,
    role: str = "A",
    asset: str = "A",
    cfg: dict | None = None,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    items = items or items_mod.load_items()
    profile = collect_profile(cfg, asset=asset, role=role)
    applicable: list[items_mod.Item] = []
    excluded: list[dict[str, str]] = []
    for item in items:
        if item.applicable(role):
            applicable.append(item)
        else:
            excluded.append(
                {"id": item.id, "title": item.title, "reason": item.scope_reason(role) or "不适用"}
            )
    batches = _batch_map(applicable)
    plan: dict[str, Any] = {
        "plan_id": core.new_id("pln"),
        "asset_id": asset,
        "role": role,
        "generated_at": core.utc_now(),
        "baseline_ref": {
            "path": str(items_mod.core.ITEMS_PATH),
            "sha256": items_mod.items_hash(),
        },
        "profile": profile,
        "batches": [
            {
                "n": number,
                "items": batch_items,
                "requires_confirm": number >= 3,
            }
            for number, batch_items in batches.items()
        ],
        "items": [
            {
                "id": item.id,
                "title": item.title,
                "category": item.category,
                "risk": item.risk,
                "batch": item.batch,
                "requires_confirm": item.requires_confirm,
                "targets": list(item.targets),
                "refs": list(item.refs),
                "manual_reason": item.manual_reason,
                "guard_seconds": item.guard_seconds,
            }
            for item in applicable
        ],
        "excluded": excluded,
        "estimated_minutes": max(5, len(applicable)),
        "snapshot": snapshot or {},
        "counts": {
            "applicable": len(applicable),
            "excluded": len(excluded),
            "high_risk": sum(1 for it in applicable if it.risk == "high"),
        },
        "scenario": {
            "A": "全量加固（六类基线 + 密码学）",
            "B": "故意不加固：仅审计/时间同步/证书台账，其余排除并给理由",
            "C": "Windows 手工检查单，不纳入自动执行",
        }[role if role in "ABC" else "A"],
    }
    plan["plan_sha256"] = plan_digest(plan)
    return plan


def plan_digest(plan: dict[str, Any]) -> str:
    payload = {k: v for k, v in plan.items() if k not in ("plan_sha256", "signature")}
    return core.sha256_text(core.json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str))


def save_plan(plan: dict[str, Any], cfg: dict | None = None) -> Path:
    return core.write_json(core.state(cfg)["plans"] / f"{core.check_id(plan['plan_id'])}.json", plan)


def load_plan(plan_id: str, cfg: dict | None = None) -> dict[str, Any]:
    path = core.state(cfg)["plans"] / f"{core.check_id(plan_id)}.json"
    plan = core.read_json(path)
    if not plan:
        raise FileNotFoundError(f"计划不存在：{path}")
    return plan


def verify_plan_integrity(plan: dict[str, Any]) -> tuple[bool, str]:
    expected = plan.get("plan_sha256")
    actual = plan_digest(plan)
    if expected != actual:
        return False, f"计划哈希不匹配（期望 {expected}，实际 {actual}）"
    return True, "计划哈希一致"
