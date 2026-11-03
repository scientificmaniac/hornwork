"""Hornwork 配置加载。

职责：
- 用标准库 tomllib 读取 config.toml；
- 与内置 DEFAULTS 深合并（配置文件缺项时用默认值）；
- 提供点路径读取工具 cfg_get()，供各模块取配置；
- 做少量路径展开与派生字段（host_id/hostname）。

注意：本模块不依赖任何第三方库，Windows 上也可 import（便于本地单元测试）。
"""

from __future__ import annotations

import copy
import os
import socket
import tomllib
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 默认配置：与仓库根目录 config.toml 保持一致，缺省即用
# ---------------------------------------------------------------------------
DEFAULTS: dict[str, Any] = {
    "general": {
        "host_id": "",                 # 空则取 hostname
        "hostname": "",                # 空则取 hostname
        "os_name": "ubuntu",
        "timezone": "UTC",
        "data_dir": "/var/lib/hornwork",
        "raw_dir": "/opt/hornwork/raw",
        "rule_dir": "/opt/hornwork/rules",
        "log_level": "INFO",
        "app_log": "/var/log/hornwork/app.jsonl",
    },
    "collect": {
        "auditd": {
            "enabled": True,
            "log_path": "/var/log/audit/audit.log",
            "keys": ["hornwork_exec", "hornwork_identity", "hornwork_persist"],
            "assemble_window_ms": 2000,
        },
        "proc": {
            "enabled": True,
            "interval_ms": 1000,
            "conn_scan": True,
        },
        "fim": {
            "enabled": True,
            "dirs": ["/etc", "/usr/local/bin", "/tmp", "/var/www"],
            "debounce_ms": 300,
            "max_watches": 20000,
            "baseline": True,
        },
        "auth": {
            "enabled": True,
            "source": "file",             # file | journal
            "path": "/var/log/auth.log",
            "journal_unit": "ssh",
            "bruteforce_threshold": 5,
            "bruteforce_window_sec": 300,
        },
        "net": {
            "enabled": True,
            "iface": "any",               # any = lo + 默认网卡
            "bpf": "ip",
            "pcap_dump": False,
            "snaplen": 65535,
            "rcvbuf_mb": 8,
            "emit_flow_event": True,
            "flow_event_interval_sec": 5,
        },
    },
    "engines": {
        "order": ["hash", "sigdb", "yara", "clamav"],
        "deep_default": False,
        "stop_score": 90,
        "max_size_mb": 100,
        "yara_rule_dir": "/opt/hornwork/rules/yara",
        "net_rule_dir": "/opt/hornwork/rules/net",
        "host_rule_dir": "/opt/hornwork/rules/host",
        "sigma_rule_dir": "/opt/hornwork/rules/sigma",
        "sigma": {
            # SigmaHQ Linux 规则大多 status: test；严格按文档应跳过 test。
            # 演示时置 true 以扩大覆盖（严格模式可改回 false）。
            "include_status_test": False,
        },
        "sigdb": {
            "hash_file": "/opt/hornwork/rules/sigdb/hashes.txt",
            "hex_file": "/opt/hornwork/rules/sigdb/hex.txt",
            "regex_file": "/opt/hornwork/rules/sigdb/regex.txt",
            "entropy_threshold": 7.2,
            "entropy_min_size": 4096,
            "regex_timeout_ms": 200,
            "regex_max_len": 2048,
        },
        "clamav": {
            "socket": "/var/run/clamav/clamd.ctl",
            "timeout_sec": 30,
            "chunk_kb": 1024,
            "unavailable_backoff_sec": 60,
        },
    },
    "scan": {
        "workers": 4,
        "budget_sec": 60,
        "skip_dirs": ["/proc", "/sys", "/dev", "/run"],
        "whitelist_paths": ["/usr/lib", "/var/lib/apt"],
        "watch_on_file_event": True,
        # ------------------------------------------------------------------
        # 扫描模块：定期漏洞扫描（端口/服务识别复用 nmap，编排/匹配/差异自研）
        # ------------------------------------------------------------------
        "enabled": True,
        "allow_cidrs": ["127.0.0.1/32", "192.168.234.135/32"],
        "local_ips": ["127.0.0.1", "192.168.234.135"],
        "window_suppress_rules": ["N-0101", "N-0102", "N-0104", "N-0105"],
        "engine_timeout_sec": 900,
        "nmap": {
            "bin": "nmap",
            "timing": "T4",
            "version_intensity": 7,
            "max_retries": 2,
        },
        "pkgs": {
            "bin": "dpkg-query",
            "backend": "local",              # local | ssh
            "ssh_key": "",
            "fact_filter": "mapped",         # mapped=只留有 CPE 映射的安全组件；all=全量
        },
        "lynis": {"bin": "lynis"},
        "testssl": {"bin": "testssl"},
        "nuclei": {
            "bin": "nuclei",
            "templates": "",
            "rate_limit": 50,
            "timeout_sec": 10,
        },
        "self": {"declared_ports": []},
        "gates": {
            "window_start": "02:00",
            "window_end": "05:00",
            "max_hosts": 4,
            "pps": 500,
            "min_disk_gb": 1,
            "window_grace_sec": 600,
        },
        "profiles": {},
        "rules": {
            "comp_map": "",
            "cve_exclude": "",
        },
        "feed_dir": "/var/lib/hornwork/feed",
        "report_dir": "/opt/hornwork/reports/scan",
        "cve": {
            "import_from_year": 2015,
            "batch_commit": 500,
            "max_candidates": 500,
        },
        "coverage": {
            "weights": {"D1": 0.15, "D2": 0.30, "D3": 0.20, "D4": 0.15, "D5": 0.10, "D6": 0.10},
            "role_domains": {},
        },
    },
    "net": {
        "home_net": "192.168.234.0/24",
        "flow_timeout_sec": 120,
        "max_flows": 200000,
        "tracker_window_sec": 5,
        "dedup_sec": 60,
        "ioc_ip_set": "ioc_ips",
        "ioc_domain_set": "ioc_domains",
    },
    "host": {
        "baseline_path": "/var/lib/hornwork/baseline.json",
        "persist_whitelist": ["/etc/cron.d/hornwork-test"],
        "persist_paths": [
            "/etc/cron.d", "/etc/crontab", "/var/spool/cron", "/etc/systemd/system",
            "/etc/rc.local", "/etc/profile.d", "/root/.bashrc", "/home",
            "/etc/ld.so.preload", "/etc/sudoers.d",
        ],
        "check_interval_sec": 60,
        "suid_scan_dirs": ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"],
    },
    "memory": {
        "max_region": 1048576,
        "interval_sec": 0,                # 0 = 仅按需
        "min_size": 4096,
        "whitelist_paths": ["/usr/lib", "/usr/bin", "/usr/local/lib"],
    },
    "intel": {
        "ioc_ttl_days": {"ip": 30, "domain": 90, "hash": 0, "url": 30, "filename": 90},
        "min_confidence_rule": 60,
        "min_confidence_block": 80,
        "feed_dir": "/opt/hornwork/rules/ioc",
        "bundle_dir": "/opt/hornwork/rules/intel",
    },
    "respond": {
        "default_mode": "observe",        # observe | dry-run | enforce
        "approval_required": True,
        "action_timeout_sec": 30,
        "quarantine_dir": "/var/lib/hornwork/quarantine",
        "management_ip": "",
        "playbook_dir": "/opt/hornwork/rules/playbooks",
    },
    "verify": {
        "suite": "baseline",
        "window_sec": 60,
        "clock_skew_max_sec": 2,
        "simulate_dir": "",
        "report_dir": "/opt/hornwork/reports",
        "settle_sec": 3,
    },
    "forensics": {
        "work_dir": "/data/forensics",
        "avml_bin": "/opt/forensics/bin/avml",
        "vol_bin": "/opt/vol3/bin/vol",
        "symbol_dir": "/opt/symbols",
        "max_capture_mb": 0,
    },
    "web": {
        "enabled": True,
        "bind": "127.0.0.1",
        "port": 8787,
        "token_env": "HORNWORK_TOKEN",
        "token": "",
    },
    "ctl": {
        "socket": "/run/hornwork/ctl.sock",
        "mode": 0o660,
        "group": "adm",
    },
    "bus": {
        "event_queue_max": 100000,
        "frame_queue_max": 20000,
        "detect_queue_max": 5000,
        "dlq_retry": 3,
    },
    # ------------------------------------------------------------------
    # 靶场模块：Vulhub 靶场编排 + 漏洞档案
    # 说明：默认 backend=local（单机测试主机同时承担 A/B 角色）；真实双机拓扑
    # 时可改 backend=ssh，由 sshrunner 连 靶场主机执行 docker compose。
    # ------------------------------------------------------------------
    "lab": {
        "backend": "local",                     # local | ssh
        "vulhub_root": "/opt/vulhub",
        "overrides_dir": "/opt/lab/overrides",
        "state_file": "/opt/lab/state.json",
        "data_dir": "/opt/hornwork/data",
        "index_path": "/opt/hornwork/data/vulhub-index.json",
        "evidence_dir": "/opt/hornwork/data/evidence",
        "host_bind": "127.0.0.1",               # 容器端口只绑回环（单机部署最安全）
        "max_envs": 2,
        "min_mem_mb": 800,
        "min_disk_gb": 5,
        "default_ttl_min": 90,
        "pull_timeout_sec": 600,
        "up_timeout_sec": 180,
        "healthy_timeout_sec": 120,
        "health_poll_sec": 2,
        "port_range": [18000, 18999],           # 宿主端口分配区间（高于常用服务段）
        "target_whitelist": ["127.0.0.1", "192.168.56.20"],
        "ssh": {
            "host": "192.168.56.20",
            "user": "lab",
            "key": "~/.ssh/id_ed25519_lab",
            "connect_timeout": 5,
            "remote_vulhub_root": "/opt/vulhub",
            "remote_overrides_dir": "/opt/lab/overrides",
        },
    },
    "vuln": {
        "records_dir": "/opt/hornwork/data/records",
        "templates_dir": "/opt/hornwork/data/templates",
        "evidence_dir": "/opt/hornwork/data/evidence",
        "index_path": "/opt/hornwork/data/vulhub-index.json",
        "min_references": 2,
    },
    # ------------------------------------------------------------------
    # 认证模块：三因子认证（口令 + TOTP + 人脸模板保护）
    # 密钥放 /etc/hornwork/auth/（目录属主 hornwork，600）：与库分离存储，
    # 轮换 auth.key 等价于全体生物模板撤销。
    # ------------------------------------------------------------------
    "auth": {
        "key_path": "/var/lib/hornwork/auth/auth.key",
        "pepper_path": "/var/lib/hornwork/auth/auth.pepper",
        "key_id": 1,
        "db_path": "",                        # 空 = 与检测模块 共库 data_dir/hornwork.db
        "challenge_ttl_sec": 120,
        "strong_auth_window_sec": 900,
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    """递归合并：override 覆盖 base，dict 递归，list/scalar 直接替换。"""
    out = copy.deepcopy(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = copy.deepcopy(val)
    return out


def load_config(path: str | os.PathLike | None = None) -> dict:
    """读取配置并与默认值合并，返回普通 dict。"""
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        p = Path(path)
        if p.is_file():
            with open(p, "rb") as fh:
                cfg = deep_merge(cfg, tomllib.load(fh))
    general = cfg.setdefault("general", {})
    hostname = socket.gethostname()
    if not general.get("hostname"):
        general["hostname"] = hostname
    if not general.get("host_id"):
        general["host_id"] = general["hostname"]
    # 允许用环境变量覆盖关键路径（便于在开发机/临时目录跑）
    for env_name, dotted in (
        ("HORNWORK_DATA_DIR", "general.data_dir"),
        ("HORNWORK_RAW_DIR", "general.raw_dir"),
        ("HORNWORK_RULE_DIR", "general.rule_dir"),
        ("HORNWORK_LOG", "general.app_log"),
        ("HORNWORK_TOKEN", "web.token"),
    ):
        val = os.environ.get(env_name)
        if val:
            _set(cfg, dotted, val)
    return cfg


def _split(dotted: str) -> list[str]:
    return [p for p in dotted.split(".") if p]


def _set(cfg: dict, dotted: str, value: Any) -> None:
    cur = cfg
    parts = _split(dotted)
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def cfg_get(cfg: dict, dotted: str, default: Any = None) -> Any:
    """按点路径取值，例如 cfg_get(cfg, "engines.clamav.timeout_sec", 30)。"""
    cur: Any = cfg
    for part in _split(dotted):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def cfg_path(cfg: dict, dotted: str, default: str = "") -> Path:
    """取路径型配置并做 expanduser。"""
    raw = cfg_get(cfg, dotted, default) or default
    return Path(os.path.expanduser(str(raw)))


def rule_dir(cfg: dict, kind: str) -> Path:
    """返回规则子目录：kind ∈ yara/net/host/sigma/ioc/playbooks。"""
    base = Path(str(cfg_get(cfg, "general.rule_dir", "/opt/hornwork/rules")))
    if kind == "playbooks":
        return Path(str(cfg_get(cfg, "respond.playbook_dir", str(base / "playbooks"))))
    if kind == "ioc":
        return Path(str(cfg_get(cfg, "intel.feed_dir", str(base / "ioc"))))
    return Path(str(cfg_get(cfg, f"engines.{kind}_rule_dir", str(base / kind))))


def ensure_dirs(cfg: dict) -> None:
    """创建运行时目录（尽力而为，无权限时不抛出）。"""
    candidates = [
        cfg_get(cfg, "general.data_dir", "/var/lib/hornwork"),
        cfg_get(cfg, "general.raw_dir", "/opt/hornwork/raw"),
        str(Path(str(cfg_get(cfg, "general.app_log", "/var/log/hornwork/app.jsonl"))).parent),
        cfg_get(cfg, "respond.quarantine_dir", "/var/lib/hornwork/quarantine"),
        cfg_get(cfg, "verify.report_dir", "/opt/hornwork/reports"),
    ]
    for cand in candidates:
        try:
            Path(str(cand)).mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
