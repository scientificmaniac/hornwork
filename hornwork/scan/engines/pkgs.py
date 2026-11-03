"""包清单适配器（D2 系统补丁 CVE 的事实来源）。

两种后端（配置 ``scan.pkgs.backend``）：

- ``local``（默认）：本机 ``dpkg-query -W -f='${Package} ${Version}\\n'``，无需凭据；
- ``ssh``：对台账资产用 SSH key（``BatchMode``，**不实现密码登录**）取远端包清单，
  仅当资产带 ``cred_ref`` 时启用；凭据只存引用，命令行里不出现密码。

输出 ``kind="component"`` 事实（``check_id="PKG-<pkg>"``、``target="package:<pkg>"``），
供 CVE 区间匹配使用；不做匹配、不写库。导入期无副作用（Windows 可 import）。
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

from ...log import get_logger
from .base import (
    ScanContext,
    asset_is_self,
    binary_available,
    cfg_get_default,
    clip_timeout,
    make_raw,
    run_capture,
)

log = get_logger("scan.engines.pkgs")

#: dpkg-query 输出格式（``\\n`` 由 dpkg-query 自身解释为换行）
DPKG_FORMAT = "${Package} ${Version}\\n"

#: 单次取包清单的耗时上限（包清单是秒级操作，不吃掉整份引擎预算）
MAX_TIMEOUT_SEC = 120.0


def parse_os_release(text: str) -> str | None:
    """从 ``/etc/os-release`` 文本取 ``VERSION_CODENAME``（如 ``noble``）；缺失返回 ``None``。"""
    for line in str(text or "").splitlines():
        key, sep, value = line.partition("=")
        if not sep or key.strip() != "VERSION_CODENAME":
            continue
        return value.strip().strip("\"'") or None
    return None


def read_distro_codename() -> str | None:
    """读本机发行版代号；Windows / 文件缺失 / 无权限一律返回 ``None``（不抛异常）。"""
    path = Path("/etc/os-release")
    try:
        if not path.is_file():
            return None
        return parse_os_release(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


def parse_dpkg_output(
    text: str,
    *,
    distro: str | None = None,
    backend: str = "local",
) -> list[dict]:
    """解析 ``dpkg-query -W -f='${Package} ${Version}\\n'`` 的输出为 component 事实列表。"""
    results: list[dict] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("="):
            continue
        parts = line.split(None, 1)
        package = parts[0].strip()
        version = parts[1].strip() if len(parts) > 1 else ""
        if not package:
            continue
        results.append(make_raw(
            "pkgs",
            "component",
            f"PKG-{package}",
            f"package:{package}",
            title=f"{package} {version}".strip(),
            severity=None,
            evidence={
                "package": package,
                "version_raw": version,
                "distro": distro,
                "backend": backend,
            },
            comp_norm=package,
            version=version or None,
            facts={"source": "dpkg", "distro": distro},
        ))
    return results


class PkgsAdapter:
    """dpkg 包清单适配器（本地 dpkg-query 或 SSH 远端查询）。"""

    name = "pkgs"
    version = "1.0"
    cost = "medium"
    requires = ["dpkg"]

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    # ---------------------------------------------------------------- 配置
    def backend(self) -> str:
        """``local``（默认）或 ``ssh``。"""
        return str(cfg_get_default(self.cfg, "scan.pkgs.backend", "local") or "local").strip().lower()

    def binary(self) -> str:
        """dpkg-query 可执行文件（命令名或路径）。"""
        return str(cfg_get_default(self.cfg, "scan.pkgs.bin", "dpkg-query") or "dpkg-query").strip()

    def ssh_key(self) -> str:
        """SSH 私钥路径（空表示用 ssh-agent 默认身份）。"""
        raw = str(cfg_get_default(self.cfg, "scan.pkgs.ssh_key", "") or "").strip()
        return os.path.expanduser(raw) if raw else ""

    def ssh_binary(self) -> str:
        """ssh 客户端（命令名或路径）。"""
        return str(cfg_get_default(self.cfg, "scan.pkgs.ssh_bin", "ssh") or "ssh").strip()

    def ssh_user(self) -> str:
        """远端只读账号的兜底值（优先取资产上的 ``ssh_user``/``user``）。"""
        return str(cfg_get_default(self.cfg, "scan.pkgs.ssh_user", "scan") or "scan").strip()

    # ---------------------------------------------------------------- 探测
    def available(self) -> bool:
        """本地后端要求 dpkg-query 可用；ssh 后端要求 ssh 客户端可用。"""
        try:
            if self.backend() == "ssh":
                return binary_available(self.cfg, "scan.pkgs.ssh_bin", "ssh")
            return binary_available(self.cfg, "scan.pkgs.bin", "dpkg-query")
        except Exception:  # noqa: BLE001 - 探测失败等价于不可用
            return False

    def supports(self, asset: dict, profile: str = "weekly") -> bool:
        """本地后端只支持本机；ssh 后端要求资产带 ``cred_ref``（只存引用）。"""
        asset = asset if isinstance(asset, dict) else {}
        if not str(asset.get("ip") or "").strip():
            return False
        if self.backend() == "ssh":
            return bool(asset.get("cred_ref"))
        # 只把"显式标记为本机"的资产当本机：单机部署里 ast-lab 也用 127.0.0.1
        # 表示 靶场主机角色，但它不是本机包清单的来源，不能跑两次 dpkg。
        return bool(asset.get("is_self"))

    # ---------------------------------------------------------------- 命令
    def build_args(self, asset: dict) -> list[str]:
        """拼命令：本地 ``dpkg-query ...``；ssh 后端包成 BatchMode 的 ssh 子进程。"""
        if self.backend() != "ssh":
            return [self.binary() or "dpkg-query", "-W", f"-f={DPKG_FORMAT}"]
        asset = asset if isinstance(asset, dict) else {}
        ip = str(asset.get("ip") or "").strip()
        user = str(asset.get("ssh_user") or asset.get("user") or self.ssh_user() or "scan").strip()
        args = [self.ssh_binary() or "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
        key = self.ssh_key()
        if key:
            args += ["-i", key]
        remote = f"{shlex.quote(self.binary() or 'dpkg-query')} -W -f={shlex.quote(DPKG_FORMAT)}"
        args += [f"{user}@{ip}", remote]
        return args

    # ---------------------------------------------------------------- 执行
    def run(self, asset: dict, ctx: ScanContext) -> list[dict]:
        """执行包清单查询并解析为 component 事实；失败返回 ``[]`` 并告警。"""
        asset = asset if isinstance(asset, dict) else {}
        if not self.available():
            log.warn("pkgs 引擎不可用，跳过", backend=self.backend())
            return []
        if not self.supports(asset, ctx.profile):
            log.info("pkgs 引擎不适用该资产（非本机或缺少 cred_ref）", ip=asset.get("ip"))
            return []
        args = self.build_args(asset)
        timeout = min(MAX_TIMEOUT_SEC, clip_timeout(ctx, cap=MAX_TIMEOUT_SEC, floor=5.0))
        proc = run_capture(args, timeout)
        if not proc.ok:
            log.warn(
                "pkgs 取包清单失败",
                ip=asset.get("ip"), backend=self.backend(), rc=proc.rc,
                error=proc.brief(), stderr=proc.tail(3),
            )
            return []
        results = parse_dpkg_output(
            proc.stdout or "", distro=read_distro_codename(), backend=self.backend()
        )
        if not results:
            log.warn("pkgs 未解析到任何包", ip=asset.get("ip"), bytes=len(proc.stdout or ""))
        return results


__all__ = [
    "DPKG_FORMAT",
    "PkgsAdapter",
    "parse_dpkg_output",
    "parse_os_release",
    "read_distro_codename",
]
