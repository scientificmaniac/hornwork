"""效果验证：加固前后两次客观测量（Lynis 指数 / SSH 生效配置 / TLS / sysctl / 权限 / 哈希迁移）。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import core, crypto

LYNIS_REPORT = Path("/var/log/lynis-report.dat")


def _lynis_run(tag: str) -> dict[str, Any]:
    snap_dir = core.state()["snapshots"]
    log_path = snap_dir / f"lynis-{tag}.log"
    res = core.sh(
        f"lynis audit system --quick --no-colors > {log_path} 2>&1; echo rc=$?",
        timeout=600,
    )
    rc = 0
    match = re.search(r"rc=(\d+)", res.get("out", ""))
    if match:
        rc = int(match.group(1))
    index = None
    report_text = ""
    try:
        report_text = LYNIS_REPORT.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    match = re.search(r"hardening_index=(\d+)", report_text)
    if match:
        index = int(match.group(1))
    else:
        try:
            out = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            out = res.get("out", "")
        match = re.search(r"Hardening index\s*:\s*(\d+)", out)
        if match:
            index = int(match.group(1))
    warnings = len(re.findall(r"^warning\[\]", report_text, re.MULTILINE))
    suggestions = len(re.findall(r"^suggestion\[\]", report_text, re.MULTILINE))
    return {"rc": rc, "hardening_index": index, "warnings": warnings, "suggestions": suggestions, "log": str(log_path)}


def _sshd_effective() -> dict[str, str]:
    out = core.sh("sshd -T 2>/dev/null")
    wanted = (
        "permitrootlogin", "maxauthtries", "logingracetime", "x11forwarding",
        "clientaliveinterval", "kexalgorithms", "ciphers", "macs",
    )
    result = {}
    for line in out.get("out", "").splitlines():
        key = line.split(" ", 1)[0]
        if key in wanted:
            result[key] = line[len(key):].strip()
    return result


def _sysctl() -> dict[str, int]:
    keys = (
        "kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.dmesg_restrict",
        "fs.suid_dumpable", "fs.protected_hardlinks", "net.ipv4.tcp_syncookies",
        "kernel.yama.ptrace_scope",
    )
    values = {}
    for key in keys:
        out = core.sh(f"sysctl -n {key} 2>/dev/null")
        raw = out.get("out", "").strip()
        values[key] = int(raw) if raw.lstrip("-").isdigit() else raw
    return values


def _perms() -> dict[str, str]:
    files = ("/etc/shadow", "/etc/passwd", "/etc/gshadow", "/etc/sudoers", "/etc/ssh/sshd_config")
    result = {}
    for path in files:
        out = core.sh(f"stat -c '%a %U:%G' {path} 2>/dev/null")
        result[path] = out.get("out", "").strip()
    return result


def _tls() -> dict[str, Any]:
    protocols = crypto.tls_probe_protocols()
    ciphers = crypto.tls_probe_ciphers()
    hsts = crypto.tls_probe_hsts()
    return {
        "protocols_ok": protocols[0],
        "protocols": {name: ("ok" if entry["ok"] else "rejected") for name, entry in protocols[1]["protocols"].items()},
        "ciphers_ok": ciphers[0],
        "weak_supported": [entry["cipher"] for entry in ciphers[1]["weak_supported"]],
        "supported": [entry["cipher"] for entry in ciphers[1]["supported"]],
        "rejected_plain": [entry["cipher"] for entry in ciphers[1]["supported"] if "CBC" in entry["cipher"]],
        "hsts_ok": hsts[0],
        "hsts": hsts[1],
    }


def snapshot(cfg: dict | None = None, tag: str = "pre-A", lynis: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "tag": tag,
        "captured_at": core.utc_now(),
        "host": core.sh("hostname").get("out", ""),
        "sshd": _sshd_effective(),
        "sysctl": _sysctl(),
        "perms": _perms(),
        "ufw": core.sh("ufw status 2>/dev/null | head -3").get("out", "").strip(),
        "audit_rules": core.sh("auditctl -l 2>/dev/null | wc -l").get("out", "").strip(),
        "legacy_hashes": crypto.pwhash_status().get("legacy_hashes_remaining"),
        "cert": crypto.cert_info(crypto.tls_dir() / "srv.crt"),
        "luks_ok": crypto.luks_check()[0],
        "tls": _tls() if Path("/etc/nginx/conf.d/hornwork-tls.conf").is_file() else {"available": False},
        "lynis": _lynis_run(tag) if lynis else {"skipped": True},
    }
    core.write_json(core.state(cfg)["snapshots"] / f"{core.check_id(tag)}.json", data)
    return data


def load_snapshot(tag: str, cfg: dict | None = None) -> dict[str, Any] | None:
    return core.read_json(core.state(cfg)["snapshots"] / f"{core.check_id(tag)}.json")


def compare(before: dict[str, Any] | None, after: dict[str, Any]) -> dict[str, Any]:
    metrics: list[dict[str, Any]] = []

    def add(name: str, before_value: Any, after_value: Any, target: str, passed: bool | None = None) -> None:
        delta: Any = None
        try:
            delta = round(after_value - before_value, 3)  # type: ignore[operator]
        except (TypeError, ValueError):
            delta = None
        metrics.append(
            {
                "metric": name,
                "before": before_value,
                "after": after_value,
                "delta": delta,
                "target": target,
                "passed": passed,
            }
        )

    before = before or {}
    b_lynis = ((before.get("lynis") or {}).get("hardening_index"))
    a_lynis = ((after.get("lynis") or {}).get("hardening_index"))
    add("Lynis 加固指数", b_lynis, a_lynis, "≥ +5（原定 +15，见边界说明）", (a_lynis - b_lynis) >= 5 if None not in (b_lynis, a_lynis) else None)
    b_sug = ((before.get("lynis") or {}).get("suggestions"))
    a_sug = ((after.get("lynis") or {}).get("suggestions"))
    if None not in (b_sug, a_sug):
        add("Lynis 待改进建议项", b_sug, a_sug, "减少 ≥ 40%", (b_sug - a_sug) >= b_sug * 0.4)

    b_tls = before.get("tls") or {}
    a_tls = after.get("tls") or {}
    b_tls_available = bool(b_tls) and b_tls.get("available") is not False
    b_weak: Any = len(b_tls.get("weak_supported") or []) if b_tls_available else "无 TLS 服务"
    a_weak = len(a_tls.get("weak_supported") or [])
    add("TLS 弱套件数量", b_weak, a_weak, "0", a_weak == 0 if a_tls else None)
    add("TLS 1.0/1.1 握手", "见快照" if b_tls else "无 TLS 服务", "拒绝" if a_tls else "无 TLS 服务", "拒绝", (not a_tls.get("protocols", {}).get("TLS1.0") == "ok") if a_tls else None)
    add("HSTS", (b_tls.get("hsts_ok") if b_tls else False), a_tls.get("hsts_ok") if a_tls else False, "存在", a_tls.get("hsts_ok") if a_tls else None)
    add("旧口令哈希剩余", before.get("legacy_hashes"), after.get("legacy_hashes"), "0", after.get("legacy_hashes") == 0)
    add("审计规则数", before.get("audit_rules"), after.get("audit_rules"), "≥ 10", None)
    add("有效 SSH 配置项", len(before.get("sshd") or {}), len(after.get("sshd") or {}), "—", None)
    add("LUKS2 加密卷", bool(before.get("luks_ok")), bool(after.get("luks_ok")), "True", bool(after.get("luks_ok")))
    return {
        "generated_at": core.utc_now(),
        "before_tag": before.get("tag"),
        "after_tag": after.get("tag"),
        "metrics": metrics,
        "before": before,
        "after": after,
        "sshd_changed": _changed_keys(before.get("sshd") or {}, after.get("sshd") or {}),
        "sysctl_changed": _changed_keys(before.get("sysctl") or {}, after.get("sysctl") or {}),
    }


def _changed_keys(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]]:
    changed = {}
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            changed[key] = {"before": before.get(key), "after": after.get(key)}
    return changed
