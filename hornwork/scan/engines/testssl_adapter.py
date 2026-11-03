"""testssl.sh 适配器（D5 TLS 配置检测）。

调用 ``testssl --quiet --jsonfile <tmp> --severity HIGH --vulnerable --protocols <ip:port>``，
解析其 JSON 输出（对象数组，元素含 id/severity/finding/cve/port），产出 ``kind="tls"``、
``check_id="TLS-<id>"`` 的问题条目。GPL-2.0 边界：独立进程调用，只读 JSON 输出。

端口来源优先级：``ctx.extra["tls_ports"]`` > 台账 ``asset.facts_json`` 中带 ``tls`` 标签的
声明端口 > 默认 ``[443, 8443]``。
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from ...log import get_logger
from .base import (
    ScanContext,
    binary_exists,
    cfg_get_default,
    clip_timeout,
    make_raw,
    port_list,
    run_capture,
    temp_dir_for,
)

log = get_logger("scan.engines.testssl")

#: 默认探测的 TLS 端口
DEFAULT_TLS_PORTS: tuple[int, ...] = (443, 8443)

#: 单端口检测超时上限
MAX_TIMEOUT_SEC = 300.0

#: testssl 严重级 → 本项目中文严重级；"无" 表示"非问题/信息项"
SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "严重",
    "HIGH": "高",
    "MEDIUM": "中",
    "LOW": "低",
    "WARN": "无",
    "WARNING": "无",
    "INFO": "无",
    "OK": "无",
    "DEBUG": "无",
}


def map_severity(value: Any) -> str:
    """testssl 严重级 → 中文严重级；未知值一律 ``"无"``。"""
    return SEVERITY_MAP.get(str(value or "").strip().upper(), "无")


def _declared_tls_ports(asset: dict) -> list[int]:
    """从 ``asset.facts_json`` 取声明了 tls/https 标签的端口。"""
    facts = (asset or {}).get("facts_json")
    if facts in (None, ""):
        facts = (asset or {}).get("facts")
    if isinstance(facts, str):
        text = facts.strip()
        if not text:
            return []
        try:
            facts = json.loads(text)
        except ValueError:
            return []
    if isinstance(facts, dict):
        facts = facts.get("services") or facts.get("ports") or []
    if not isinstance(facts, list):
        return []
    out: list[int] = []
    for item in facts:
        if not isinstance(item, dict):
            continue
        tags = item.get("tags") or []
        if isinstance(tags, str):
            tags = [part.strip() for part in tags.split(",")]
        tags_lower = {str(tag).strip().lower() for tag in tags}
        if "tls" not in tags_lower and "https" not in tags_lower:
            continue
        for port in port_list(item.get("port")):
            if port not in out:
                out.append(port)
    return out


def parse_testssl_json(text: str, *, ip: str = "", default_port: int = 443) -> list[dict]:
    """解析 testssl ``--jsonfile`` 输出为 tls 类 RawResult。

    ``OK/INFO/DEBUG`` 项（检查通过/纯信息）会被跳过——它们不是问题，保留只会淹没
    报告与 ``scan_finding`` 表；``WARN`` 保留并映射为"无"，``LOW`` 起映射为正式严重级。
    """
    try:
        data = json.loads(str(text or ""))
    except ValueError:
        log.warn("testssl JSON 解析失败", ip=ip, bytes=len(str(text or "")))
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    results: list[dict] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        test_id = str(item.get("id") or "").strip()
        if not test_id:
            continue
        raw_severity = str(item.get("severity") or "").strip().upper()
        # 跳过"检查通过/纯信息"项（OK/INFO/DEBUG）：它们不是问题，保留会把报告与
        # scan_finding 表淹没；WARN（弱配置/不符合最佳实践）仍保留，映射为"无"。
        if raw_severity in ("OK", "INFO", "DEBUG"):
            continue
        port = port_list(item.get("port")) or [default_port]
        port_num = port[0]
        target = f"{ip}:{port_num}" if ip else str(port_num)
        finding = str(item.get("finding") or "").strip()
        results.append(make_raw(
            "testssl",
            "tls",
            f"TLS-{test_id}",
            target,
            title=f"{test_id}: {finding}"[:200] if finding else test_id,
            severity=map_severity(item.get("severity")),
            evidence={
                "id": test_id,
                "severity": item.get("severity"),
                "finding": item.get("finding"),
                "cve": item.get("cve"),
                "port": port_num,
                "protocol": item.get("protocol"),
            },
            # TLS 探针为实测结论，按 exact 置信度入 finding
            confidence="exact",
            facts={"source": "testssl", "test_id": test_id},
        ))
    return results


class TestsslAdapter:
    """testssl.sh TLS 检测适配器（逐端口执行，超时按单端口计）。"""

    name = "testssl"
    version = "1.0"
    cost = "slow"
    requires = ["testssl"]

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    # ---------------------------------------------------------------- 探测
    def binary_candidates(self) -> list[str]:
        """候选可执行名：配置值优先，其次 ``testssl`` / ``testssl.sh``。"""
        configured = str(
            cfg_get_default(self.cfg, "scan.testssl.bin", "testssl") or "testssl"
        ).strip()
        candidates = [configured] if configured else []
        for name in ("testssl", "testssl.sh"):
            if name not in candidates:
                candidates.append(name)
        return candidates

    def binary(self) -> str:
        """取第一个可用的 testssl 可执行名；都不可用时返回配置值。"""
        for candidate in self.binary_candidates():
            if binary_exists(candidate):
                return candidate
        return self.binary_candidates()[0]

    def available(self) -> bool:
        """配置的 testssl（或 testssl.sh）二进制是否存在。"""
        try:
            return any(binary_exists(name) for name in self.binary_candidates())
        except Exception:  # noqa: BLE001 - 探测失败等价于不可用
            return False

    def supports(self, asset: dict, profile: str = "weekly") -> bool:
        """有 IP 就支持；是否真有 TLS 端口由 :meth:`ports_for` 决定。"""
        return bool(str((asset or {}).get("ip") or "").strip())

    def ports_for(self, asset: dict, ctx: ScanContext) -> list[int]:
        """TLS 端口：``ctx.extra["tls_ports"]`` > 台账声明 > 默认 [443, 8443]。"""
        extra = ctx.extra if isinstance(ctx.extra, dict) else {}
        ports = port_list(extra.get("tls_ports"))
        if not ports:
            ports = _declared_tls_ports(asset if isinstance(asset, dict) else {})
        return ports or list(DEFAULT_TLS_PORTS)

    # ---------------------------------------------------------------- 执行
    def build_args(self, ip: str, port: int, json_path: str) -> list[str]:
        """拼 testssl 命令（单端口）。"""
        return [
            self.binary() or "testssl",
            "--quiet",
            "--jsonfile", json_path,
            "--severity", "HIGH",
            "--vulnerable",
            "--protocols", f"{ip}:{port}",
        ]

    def run(self, asset: dict, ctx: ScanContext) -> list[dict]:
        """逐端口执行 testssl 并解析 JSON；单个端口失败不影响其它端口。"""
        asset = asset if isinstance(asset, dict) else {}
        if not self.available():
            log.warn("testssl 不可用，跳过 TLS 检测")
            return []
        ip = str(asset.get("ip") or "").strip()
        if not ip or not self.supports(asset, ctx.profile):
            return []
        results: list[dict] = []
        for port in self.ports_for(asset, ctx):
            remain = ctx.remaining_sec(None)
            if remain is not None and remain <= 1.0:
                log.warn("扫描预算耗尽，跳过剩余 TLS 端口", ip=ip, port=port)
                break
            json_path = ""
            try:
                fd, json_path = tempfile.mkstemp(
                    prefix=f"hornwork-testssl-{port}-", suffix=".json", dir=temp_dir_for(ctx)
                )
                os.close(fd)
                proc = run_capture(
                    self.build_args(ip, port, json_path),
                    clip_timeout(ctx, cap=MAX_TIMEOUT_SEC, floor=30.0),
                )
                if not proc.ok:
                    log.warn(
                        "testssl 执行失败",
                        ip=ip, port=port, rc=proc.rc, error=proc.brief(), stderr=proc.tail(3),
                    )
                try:
                    text = Path(json_path).read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    log.warn("testssl JSON 读取失败", ip=ip, port=port, error=str(exc))
                    continue
                if not text.strip():
                    continue
                parsed = parse_testssl_json(text, ip=ip, default_port=port)
                if parsed:
                    log.info("testssl 检测完成", ip=ip, port=port, findings=len(parsed))
                results.extend(parsed)
            except Exception as exc:  # noqa: BLE001 - 适配器绝不中断整次扫描
                log.warn("testssl 适配器异常", ip=ip, port=port, error=str(exc)[:200])
                continue
            finally:
                if json_path:
                    try:
                        os.unlink(json_path)
                    except OSError:
                        pass
        return results


__all__ = [
    "DEFAULT_TLS_PORTS",
    "MAX_TIMEOUT_SEC",
    "SEVERITY_MAP",
    "TestsslAdapter",
    "map_severity",
    "parse_testssl_json",
]
