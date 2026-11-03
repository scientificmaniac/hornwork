"""Nuclei 适配器（D6 Web/应用 PoC 验证）。

调用 ``nuclei -u <url> -jsonl -silent -rate-limit <n> -timeout 10
-etags fuzz,dos,bruteforce -severity critical,high,medium``，逐行解析 JSONL，
产出 ``kind="web"``、``check_id="<template-id>"`` 的 PoC 命中条目。

MIT 许可证：模板与引擎均以独立进程/数据方式复用，只读 JSONL 输出
。多 URL 时逐个执行，超时按单个 URL 计；``ctx.deadline`` 用于
提前止损。导入期无副作用（Windows 可 import）。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ...log import get_logger
from .base import (
    ScanContext,
    binary_available,
    cfg_get_default,
    clip_timeout,
    make_raw,
    run_capture,
)

log = get_logger("scan.engines.nuclei")

#: 单个 URL 的执行超时上限
MAX_TIMEOUT_SEC = 900.0

#: 单请求超时（nuclei ``-timeout``，秒）
REQUEST_TIMEOUT_SEC = 10

#: 排除破坏性标签（fuzz/dos/bruteforce 会打挂靶场或制造噪声）
EXCLUDE_TAGS = "fuzz,dos,bruteforce"

#: 只跑中危及以上（低危 PoC 噪声大，报告价值低）
INCLUDE_SEVERITIES = "critical,high,medium"

#: 证据字段截断长度（request/response 原文过长，报告只留片段）
EVIDENCE_LIMIT = 2000

#: nuclei 严重级 → 中文严重级
SEVERITY_MAP: dict[str, str] = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "无",
    "unknown": "无",
}


def map_severity(value: Any) -> str:
    """nuclei 严重级 → 中文严重级；未知值返回 ``"无"``。"""
    return SEVERITY_MAP.get(str(value or "").strip().lower(), "无")


def _as_list(value: Any) -> list[str]:
    """把 ``"CVE-2020-1"`` / ``["CVE-2020-1"]`` 统一成字符串列表。"""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()]


def _truncate(value: Any, limit: int = EVIDENCE_LIMIT) -> str | None:
    """截断证据文本；空值返回 ``None``（JSON 可序列化且不占空间）。"""
    if value is None:
        return None
    text = str(value)
    return text[:limit] if text else ""


def parse_nuclei_jsonl(text: str, *, default_url: str = "") -> list[dict]:
    """解析 nuclei ``-jsonl`` 输出为 web 类 RawResult（坏行跳过，不中断）。"""
    results: list[dict] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except ValueError:
            log.warn("nuclei JSONL 行解析失败", line=line[:120])
            continue
        if not isinstance(item, dict):
            continue
        template_id = str(item.get("template-id") or item.get("templateID") or "").strip()
        if not template_id:
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        name = str(info.get("name") or template_id)
        matched_at = str(item.get("matched-at") or item.get("matched") or default_url)
        results.append(make_raw(
            "nuclei",
            "web",
            template_id,
            matched_at,
            title=name[:200],
            severity=map_severity(info.get("severity")),
            evidence={
                "template_id": template_id,
                "name": name,
                "severity": info.get("severity"),
                "cve": _as_list(classification.get("cve-id") or classification.get("cve_id")),
                "cwe": _as_list(classification.get("cwe-id") or classification.get("cwe_id")),
                "matched_at": item.get("matched-at") or item.get("matched"),
                "request": _truncate(item.get("request")),
                "response": _truncate(item.get("response")),
            },
            # PoC 命中是证据最强的一类，按 tool 置信度直接 confirmed
            confidence="tool",
            facts={"source": "nuclei", "template_id": template_id},
        ))
    return results


class NucleiAdapter:
    """Nuclei Web PoC 适配器（模板目录 + 二进制都就绪才可用）。"""

    name = "nuclei"
    version = "1.0"
    cost = "slow"
    requires = ["nuclei"]

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    # ---------------------------------------------------------------- 探测
    def binary(self) -> str:
        """nuclei 可执行文件（命令名或路径）。"""
        return str(cfg_get_default(self.cfg, "scan.nuclei.bin", "nuclei") or "nuclei").strip()

    def templates_dir(self) -> str:
        """模板目录：配置 ``scan.nuclei.templates``，缺省 ``~/nuclei-templates``。"""
        raw = str(cfg_get_default(self.cfg, "scan.nuclei.templates", "") or "").strip()
        if not raw:
            raw = "~/nuclei-templates"
        return os.path.expanduser(raw)

    def available(self) -> bool:
        """二进制存在**且**模板目录存在（缺一不可，避免空跑）。"""
        try:
            if not binary_available(self.cfg, "scan.nuclei.bin", "nuclei"):
                return False
            return Path(self.templates_dir()).is_dir()
        except (OSError, ValueError):
            return False

    def supports(self, asset: dict, profile: str = "weekly") -> bool:
        """所有 profile 都有 D6 的可能；是否有 URL 由 ``ctx.extra["web_targets"]`` 决定。"""
        return True

    # ---------------------------------------------------------------- 执行
    def build_args(self, url: str, rate_limit: int) -> list[str]:
        """拼单个 URL 的 nuclei 命令。"""
        args = [
            self.binary() or "nuclei",
            "-u", url,
            "-jsonl",
            "-silent",
            "-rate-limit", str(max(1, int(rate_limit))),
            "-timeout", str(REQUEST_TIMEOUT_SEC),
            "-etags", EXCLUDE_TAGS,
            "-severity", INCLUDE_SEVERITIES,
            "-no-color",
        ]
        templates = self.templates_dir()
        if templates:
            args += ["-t", templates]
        # 测试环境使用加固模块自建 CA 签发的自签证书，仅本地授权资产可跳过校验
        args.append("-insecure")
        return args

    def run(self, asset: dict, ctx: ScanContext) -> list[dict]:
        """逐 URL 执行 nuclei；单 URL 超时/失败不影响其它 URL。"""
        if not self.available():
            log.warn("nuclei 不可用（二进制或模板目录缺失），跳过 Web PoC")
            return []
        extra = ctx.extra if isinstance(ctx.extra, dict) else {}
        urls = extra.get("web_targets") or []
        if isinstance(urls, str):
            urls = [urls]
        if not isinstance(urls, (list, tuple)) or not urls:
            return []
        try:
            rate_limit = int(float(ctx.rate_limit or 0)) or 150
        except (TypeError, ValueError):
            rate_limit = 150
        results: list[dict] = []
        for url in urls:
            text_url = str(url or "").strip()
            if not text_url:
                continue
            remain = ctx.remaining_sec(None)
            if remain is not None and remain <= 1.0:
                log.warn("扫描预算耗尽，跳过剩余 Web 目标", url=text_url)
                break
            proc = run_capture(
                self.build_args(text_url, rate_limit),
                clip_timeout(ctx, cap=MAX_TIMEOUT_SEC, floor=30.0),
            )
            stdout = proc.stdout if isinstance(proc.stdout, str) else ""
            if not proc.ok and not stdout.strip():
                log.warn(
                    "nuclei 执行失败",
                    url=text_url, rc=proc.rc, error=proc.brief(), stderr=proc.tail(3),
                )
                continue
            parsed = parse_nuclei_jsonl(stdout, default_url=text_url)
            log.info("nuclei 检测完成", url=text_url, hits=len(parsed), rc=proc.rc)
            results.extend(parsed)
        return results


__all__ = [
    "EVIDENCE_LIMIT",
    "EXCLUDE_TAGS",
    "INCLUDE_SEVERITIES",
    "MAX_TIMEOUT_SEC",
    "NucleiAdapter",
    "REQUEST_TIMEOUT_SEC",
    "SEVERITY_MAP",
    "map_severity",
    "parse_nuclei_jsonl",
]

