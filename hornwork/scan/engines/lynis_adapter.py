"""Lynis 适配器（D4 主机配置基线）。

调用 ``lynis audit system --quick --no-colors --quiet --report-file <tmp>``，
解析 report 文件中的 ``hardening_index`` / ``warning[]`` / ``suggestion[]``，
产出 ``kind="config"``、``check_id="LYNIS-<TEST-ID>"`` 的基线问题条目。

权限：Lynis 需要 root。按设计，扫描任务由 ``hornwork-scan@.service``
以 root（或 ``sudo -n`` 白名单）运行；本适配器**不自行提权**，``available()`` 只探测二进制。
GPL-3.0 边界：仅以独立进程调用，不链接、不改源码、不复制其代码。
"""

from __future__ import annotations

import os
import tempfile
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
    temp_dir_for,
)

log = get_logger("scan.engines.lynis")

#: 允许运行基线审计的 profile（快扫不含 D4，基线审计太重）
SUPPORTED_PROFILES: tuple[str, ...] = ("weekly", "full", "verify-fix")

#: Lynis 单次审计超时上限
MAX_TIMEOUT_SEC = 300.0


def parse_report(
    text: str,
    *,
    target: str = "",
    warning_severity: str = "中",
    suggestion_severity: str = "低",
) -> list[dict]:
    """解析 Lynis report 文本为 config 类 RawResult。

    支持的行格式::

        hardening_index=64
        warning[]=SSH-7408|Consider hardening SSH configuration|Details: ...
        suggestion[]=BOOT-5122|Set a password on GRUB boot loader|Details: ...

    ``hardening_index`` 会写入每条证据，便于加固模块做"加固前后对比"。
    """
    lines = str(text or "").splitlines()
    hardening_index: int | None = None
    for line in lines:
        key, sep, value = line.strip().partition("=")
        if not sep or key.strip() != "hardening_index":
            continue
        try:
            hardening_index = int(value.strip().split()[0])
        except (ValueError, IndexError):
            hardening_index = None

    results: list[dict] = []
    for raw_line in lines:
        line = raw_line.strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if key not in ("warning[]", "warning", "suggestion[]", "suggestion"):
            continue
        severity = warning_severity if key.startswith("warning") else suggestion_severity
        # 行格式：<TEST-ID>|<message>|Details: <细节>
        parts = value.split("|", 2)
        test_id = parts[0].strip()
        message = parts[1].strip() if len(parts) > 1 else ""
        details = parts[2].strip() if len(parts) > 2 else ""
        if not test_id:
            continue
        results.append(make_raw(
            "lynis",
            "config",
            f"LYNIS-{test_id}",
            target,
            title=(message or test_id)[:200],
            severity=severity,
            evidence={
                "message": message,
                "details": details,
                "raw": line,
                "hardening_index": hardening_index,
            },
            # 基线为实测到的配置事实，置信度按 exact；normalize 据此直接入 new
            confidence="exact",
            facts={"source": "lynis", "test_id": test_id},
        ))
    return results


class LynisAdapter:
    """Lynis 主机基线适配器（仅本机、仅 weekly/full/verify-fix）。"""

    name = "lynis"
    version = "1.0"
    cost = "slow"
    requires = ["root"]

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    # ---------------------------------------------------------------- 探测
    def binary(self) -> str:
        """lynis 可执行文件（命令名或路径）。"""
        return str(cfg_get_default(self.cfg, "scan.lynis.bin", "lynis") or "lynis").strip()

    def warning_severity(self) -> str:
        """``warning[]`` 映射的严重级（默认"中"）。"""
        return str(cfg_get_default(self.cfg, "scan.lynis.severity_warning", "中") or "中").strip()

    def suggestion_severity(self) -> str:
        """``suggestion[]`` 映射的严重级（默认"低"）。"""
        return str(cfg_get_default(self.cfg, "scan.lynis.severity_suggestion", "低") or "低").strip()

    def available(self) -> bool:
        """只检查 lynis 二进制（root 由 runner/unit 保证，不在此提权）。"""
        try:
            return binary_available(self.cfg, "scan.lynis.bin", "lynis")
        except Exception:  # noqa: BLE001 - 探测失败等价于不可用
            return False

    def supports(self, asset: dict, profile: str = "weekly") -> bool:
        """仅 ``weekly|full|verify-fix`` 且资产显式标记为本机（is_self）。"""
        if str(profile or "").strip().lower() not in SUPPORTED_PROFILES:
            return False
        # 同 pkgs：只有显式 is_self 的资产才跑 lynis，避免 ast-lab 重复跑一遍导致耗时翻倍。
        return bool(asset.get("is_self"))

    # ---------------------------------------------------------------- 执行
    def build_args(self, report_path: str) -> list[str]:
        """拼 lynis 命令（report 文件路径由调用方创建）。"""
        return [
            self.binary() or "lynis",
            "audit", "system",
            "--quick",
            "--no-colors",
            "--quiet",
            "--report-file", report_path,
        ]

    def run(self, asset: dict, ctx: ScanContext) -> list[dict]:
        """跑一次 Lynis 审计并解析 report；临时文件在 finally 删除。"""
        asset = asset if isinstance(asset, dict) else {}
        if not self.available():
            log.warn("lynis 不可用，跳过主机基线审计")
            return []
        if not self.supports(asset, ctx.profile):
            log.info("lynis 不适用该资产/计划", ip=asset.get("ip"), profile=ctx.profile)
            return []
        ip = str(asset.get("ip") or "127.0.0.1")
        target = f"host:{ip}"
        report_path = ""
        try:
            fd, report_path = tempfile.mkstemp(
                prefix="hornwork-lynis-", suffix=".log", dir=temp_dir_for(ctx)
            )
            os.close(fd)
            proc = run_capture(self.build_args(report_path), clip_timeout(ctx, cap=MAX_TIMEOUT_SEC, floor=30.0))
            if not proc.ok:
                # lynis 发现告警时也可能返回非 0，只要 report 有内容就继续解析
                log.warn(
                    "lynis 执行失败，尝试解析已有 report",
                    ip=ip, rc=proc.rc, error=proc.brief(), stderr=proc.tail(3),
                )
            try:
                text = Path(report_path).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                log.warn("lynis report 读取失败", path=report_path, error=str(exc))
                return []
            if not text.strip():
                log.warn("lynis report 为空", ip=ip)
                return []
            results = parse_report(
                text,
                target=target,
                warning_severity=self.warning_severity(),
                suggestion_severity=self.suggestion_severity(),
            )
            log.info("lynis 基线审计完成", ip=ip, findings=len(results), rc=proc.rc)
            return results
        except Exception as exc:  # noqa: BLE001 - 适配器绝不中断整次扫描
            log.warn("lynis 适配器异常", ip=ip, error=str(exc)[:200])
            return []
        finally:
            if report_path:
                try:
                    os.unlink(report_path)
                except OSError:
                    pass


__all__ = ["MAX_TIMEOUT_SEC", "SUPPORTED_PROFILES", "LynisAdapter", "parse_report"]
