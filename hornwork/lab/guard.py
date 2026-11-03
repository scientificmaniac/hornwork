"""up 前的守卫：资源闸门、快照标记、目标白名单（靶场编排层）。

守卫原则：
- 并发环境数 ≤ lab.max_envs；
- 可用内存 ≥ lab.min_mem_mb；磁盘剩余 ≥ lab.min_disk_gb；
- 复现前应已回滚快照 S0-B（标记文件存在），否则拒绝，除非显式 --force；
- 任何 URL/端口探测只允许 [lab].target_whitelist 内的地址。

本模块全部为纯函数：内存/磁盘读取在函数体内完成，读不到时返回 -1 表示
"未知"，由 check_resources 跳过该项而不是误报（Windows 开发机即走此分支）。
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

from ..config import cfg_get

DEFAULT_SNAPSHOT_MARKER = "/opt/lab/S0-B.ok"
DEFAULT_WHITELIST = ("127.0.0.1", "192.168.56.20")


def free_mem_mb() -> int:
    """返回 Linux MemAvailable（MB）；非 Linux/读取失败返回 -1（未知）。"""
    if not sys.platform.startswith("linux"):
        return -1
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        return int(parts[1]) // 1024
    except OSError:
        return -1
    return -1


def free_disk_gb(path: str) -> float:
    """返回 path 所在分区的剩余空间（GB）；路径不存在/不可访问返回 -1.0。"""
    try:
        target = Path(str(path))
        while not target.exists() and target.parent != target:
            target = target.parent
        usage = shutil.disk_usage(str(target))
        return round(usage.free / (1024 ** 3), 2)
    except (OSError, ValueError):
        return -1.0


def check_resources(cfg: dict, running_count: int) -> list[str]:
    """资源闸门：返回拒绝原因列表，空列表表示通过。"""
    reasons: list[str] = []
    try:
        max_envs = int(cfg_get(cfg, "lab.max_envs", 2) or 2)
    except (TypeError, ValueError):
        max_envs = 2
    if int(running_count) >= max_envs:
        reasons.append(
            f"并发环境数已达上限 max_envs={max_envs}（当前运行 {int(running_count)} 个），"
            "请先 down 一个环境或调大 [lab].max_envs"
        )

    try:
        min_mem = int(cfg_get(cfg, "lab.min_mem_mb", 800) or 800)
    except (TypeError, ValueError):
        min_mem = 800
    mem_mb = free_mem_mb()
    if mem_mb >= 0 and mem_mb < min_mem:
        reasons.append(f"可用内存不足：剩余 {mem_mb} MB < 下限 {min_mem} MB")

    try:
        min_disk = float(cfg_get(cfg, "lab.min_disk_gb", 5) or 5)
    except (TypeError, ValueError):
        min_disk = 5.0
    disk_path = str(
        cfg_get(cfg, "lab.overrides_dir", "")
        or cfg_get(cfg, "lab.index_path", "")
        or cfg_get(cfg, "lab.data_dir", "/opt/lab")
        or "/"
    )
    disk_gb = free_disk_gb(disk_path)
    if disk_gb >= 0 and disk_gb < min_disk:
        reasons.append(
            f"磁盘剩余空间不足：{disk_path} 剩余 {disk_gb} GB < 下限 {min_disk} GB"
        )
    return reasons


def snapshot_marker(cfg: dict) -> Path:
    """快照标记文件路径（默认 /opt/lab/S0-B.ok）。"""
    raw = cfg_get(cfg, "lab.snapshot_marker", DEFAULT_SNAPSHOT_MARKER) or DEFAULT_SNAPSHOT_MARKER
    return Path(str(raw))


def snapshot_guard(cfg: dict, force: bool) -> list[str]:
    """快照标记守卫：标记缺失时返回提醒；force=True 跳过检查。"""
    if force:
        return []
    marker = snapshot_marker(cfg)
    try:
        if marker.is_file():
            return []
    except OSError:
        pass
    return [
        f"未检测到快照标记 {marker}（复现前应先创建/回滚 S0-B 快照）；"
        "确认继续请追加 --force"
    ]


def whitelist(cfg: dict) -> set[str]:
    """读取目标白名单（规范化成小写主机名/IP）。"""
    raw = cfg_get(cfg, "lab.target_whitelist", list(DEFAULT_WHITELIST))
    if isinstance(raw, str):
        raw = [x.strip() for x in raw.split(",") if x.strip()]
    if not isinstance(raw, (list, tuple, set)):
        raw = list(DEFAULT_WHITELIST)
    allowed = {str(item).strip().casefold() for item in raw if str(item).strip()}
    return allowed or {x.casefold() for x in DEFAULT_WHITELIST}


def check_targets(cfg: dict, url_or_host: str) -> bool:
    """目标白名单：只允许 [lab].target_whitelist 内的地址；无法解析返回 False。"""
    text = str(url_or_host or "").strip()
    if not text:
        return False
    host = ""
    if "://" in text:
        try:
            host = urlparse(text).hostname or ""
        except ValueError:
            return False
    elif text.startswith("["):
        # [::1]:8080 形式
        end = text.find("]")
        host = text[1:end] if end > 0 else ""
    elif text.count(":") == 1:
        host = text.split(":", 1)[0]
    else:
        host = text
    host = host.strip().strip("[]").casefold()
    if not host:
        return False
    return host in whitelist(cfg)
