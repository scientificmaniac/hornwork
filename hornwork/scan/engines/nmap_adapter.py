"""nmap 适配器（D1 端口与服务 / D3 组件识别；复用 ``nmap -sV`` + XML 输出）。

项目决策（v2）：端口发现与服务版本识别**直接复用 nmap**，不再自研 connect/banner。
本文件只做"拼命令 + 执行 + 解析 XML + 转 RawResult"，不含端口扫描算法，也不复制
nmap 的任何源码/规则。

覆盖能力：
- ``kind="port"``：每个 ``state="open"`` 端口一条，含 state/reason/service/tunnel；
- ``kind="component"``：端口识别出 product/version/CPE 时追加一条组件事实，供 CVE 匹配；
- ``kind="host_summary"``：每台主机一条收尾汇总（scanned/open/closed/filtered/耗时/命令）。

失败语义：缺二进制、超时、非零退出码、XML 畸形一律 ``log.warn`` + 返回 ``[]`` 或已解析的
部分结果，**不抛异常**（单引擎失败不影响整次扫描）。
"""

from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from typing import Any

from ...log import get_logger
from .base import (
    ScanContext,
    binary_available,
    cfg_get_default,
    cfg_int,
    clip_timeout,
    make_raw,
    port_list,
    run_capture,
)

log = get_logger("scan.engines.nmap")

#: 未指定端口规格时的默认扫描量（nmap --top-ports）
DEFAULT_TOP_PORTS = 200

#: "top:200" / "top=200" / "top 200" / "top" 的识别
_TOP_RE = re.compile(r"^top\s*[:=]?\s*(\d*)$", re.IGNORECASE)

#: 视为"应用"部分的 CPE（component 事实只接受 part=a，避免把 OS 当组件）
_APP_PART = "a"


# ---------------------------------------------------------------------------
# 端口规格翻译
# ---------------------------------------------------------------------------
def build_port_args(ports: str | None, declared_ports: Any = None) -> list[str]:
    """把 ``ctx.ports`` 翻译成 nmap 端口参数。

    - ``"top:200"`` / ``"top"`` / 空 → ``--top-ports 200``（不加 ``-p``）；
    - ``"1-65535"`` / ``"22,80,18000"`` → ``-p <规格>``；
    - ``"declared"`` → 取 ``ctx.extra["declared_ports"]``（台账声明端口）拼 ``-p 22,80``，
      声明为空时回退 ``--top-ports 200``（targeted / verify-fix 计划只扫声明端口）。
    """
    text = str(ports or "").strip()
    if not text:
        return ["--top-ports", str(DEFAULT_TOP_PORTS)]
    if text.lower() == "declared":
        declared = port_list(declared_ports)
        if declared:
            return ["-p", ",".join(str(port) for port in declared)]
        return ["--top-ports", str(DEFAULT_TOP_PORTS)]
    match = _TOP_RE.match(text)
    if match:
        count = int(match.group(1)) if match.group(1) else DEFAULT_TOP_PORTS
        return ["--top-ports", str(count if count > 0 else DEFAULT_TOP_PORTS)]
    return ["-p", text]


# ---------------------------------------------------------------------------
# CPE 与组件归一
# ---------------------------------------------------------------------------
def parse_cpe(value: str | None) -> dict:
    """解析 nmap 输出的 CPE（CPE 2.2 URI 或 CPE 2.3 格式）为 part/vendor/product/version。

    - ``cpe:/a:openbsd:openssh:10.2p1`` → ``{"part":"a","vendor":"openbsd","product":"openssh",...}``
    - ``cpe:2.3:a:nginx:nginx:1.18.0:...`` → 同上（取前 6 段）
    - 非法输入返回 ``{}``。
    """
    text = str(value or "").strip()
    if not text.startswith("cpe:"):
        return {}
    if text.startswith("cpe:2.3:"):
        fields = text.split(":")
        if len(fields) < 6:
            return {}
        return {
            "part": fields[2].strip(),
            "vendor": fields[3].strip(),
            "product": fields[4].strip(),
            "version": fields[5].strip(),
        }
    body = text[len("cpe:"):]
    if body.startswith("/"):
        body = body[1:]
    fields = body.split(":")
    if len(fields) < 3:
        return {}
    return {
        "part": fields[0].strip(),
        "vendor": fields[1].strip(),
        "product": fields[2].strip(),
        "version": fields[3].strip() if len(fields) > 3 else "",
    }


def _app_cpe(cpes: list[str]) -> dict:
    """从 CPE 列表中取第一个"应用"CPE（part=a）的解析结果。"""
    for cpe in cpes or []:
        parsed = parse_cpe(cpe)
        if parsed.get("part") == _APP_PART and parsed.get("product"):
            return parsed
    return {}


def normalize_component(product: str | None, cpes: list[str] | None = None) -> str:
    """组件归一：优先取应用 CPE 的 product 字段，否则 product 小写 + 空格/下划线→``-``。

    例：``OpenSSH`` + ``cpe:/a:openbsd:openssh:10.2p1`` → ``openssh``；
    ``CUPS`` + ``cpe:/a:apple:cups:2.4`` → ``cups``；无 CPE 时 ``Some Product`` → ``some-product``。
    """
    parsed = _app_cpe(cpes or [])
    if parsed.get("product"):
        return str(parsed["product"]).strip().lower()
    text = re.sub(r"[\s_]+", "-", str(product or "").strip().lower())
    return re.sub(r"[^a-z0-9.+~-]", "", text)


# ---------------------------------------------------------------------------
# XML 解析
# ---------------------------------------------------------------------------
def _host_ip(host: ET.Element) -> str:
    """取主机地址：优先 ipv4，其次 ipv6/mac。"""
    fallback = ""
    for addr in host.findall("address"):
        value = str(addr.get("addr") or "").strip()
        if not value:
            continue
        addrtype = str(addr.get("addrtype") or "").strip()
        if addrtype == "ipv4":
            return value
        if not fallback:
            fallback = value
    return fallback


def _service_fields(service_el: ET.Element | None) -> dict:
    """提取 ``<service>`` 的属性与 ``<cpe>`` 子元素。"""
    fields: dict[str, Any] = {
        "name": "", "product": "", "version": "", "extrainfo": "",
        "tunnel": "", "method": "", "ostype": "", "conf": None, "cpes": [],
    }
    if service_el is None:
        return fields
    for key in ("name", "product", "version", "extrainfo", "tunnel", "method", "ostype"):
        fields[key] = str(service_el.get(key) or "").strip()
    try:
        fields["conf"] = int(service_el.get("conf"))
    except (TypeError, ValueError):
        fields["conf"] = None
    fields["cpes"] = [
        str(cpe.text).strip()
        for cpe in service_el.findall("cpe")
        if cpe.text and str(cpe.text).strip()
    ]
    return fields


def _component_raw(portid: str, proto: str, target: str, svc: dict) -> dict:
    """由 ``<service>`` 生成一条 component 事实。"""
    cpes: list[str] = svc["cpes"]
    app = _app_cpe(cpes)
    product = svc["product"] or str(app.get("product") or "")
    version = svc["version"]
    comp_norm = normalize_component(svc["product"], cpes)
    # 顶层 cpe 用"应用 CPE"原文；没有应用 CPE 时退到第一条（便于人工核对）
    cpe_raw = next((c for c in cpes if c.startswith("cpe:/a:")), None)
    if cpe_raw is None:
        cpe_raw = next((c for c in cpes if c.startswith("cpe:2.3:a:")), cpes[0] if cpes else None)
    label = " ".join(part for part in (product, version) if part).strip() or f"{portid}/{proto}"
    evidence: dict[str, Any] = {
        "service": svc["name"],
        "product": svc["product"],
        "version": version,
        "extrainfo": svc["extrainfo"],
        "cpe": cpe_raw,
        "tunnel": svc["tunnel"],
        "confidence": svc["conf"],
        "method": svc["method"],
        # 端口信息：runner 的资产事实（asset.facts_json.services）按 evidence.port 汇总
        "port": int(portid) if str(portid).isdigit() else portid,
        "proto": proto,
    }
    if len(cpes) > 1:
        evidence["cpes"] = list(cpes)
    facts = {
        "source": "nmap",
        "vendor": app.get("vendor") or None,
        # product 统一用归一后的组件名（与 comp_norm 一致，便于 matcher 直接使用）
        "product": comp_norm or product or None,
        "ostype": svc["ostype"] or None,
    }
    return make_raw(
        "nmap",
        "component",
        f"SVC-{portid}/{proto}",
        target,
        title=f"{label} ({portid}/{proto})",
        severity=None,
        evidence=evidence,
        comp_norm=comp_norm or None,
        version=version or None,
        cpe=cpe_raw,
        facts=facts,
    )


def _elapsed_ms(host: ET.Element, fallback: Any = None) -> int:
    """主机扫描耗时：优先 host 的 starttime/endtime，其次调用方计时。"""
    try:
        start = float(host.get("starttime"))
        end = float(host.get("endtime"))
        if end >= start:
            return int((end - start) * 1000)
    except (TypeError, ValueError):
        pass
    try:
        return int(fallback) if fallback is not None else 0
    except (TypeError, ValueError):
        return 0


def _parse_host(
    host: ET.Element,
    default_ip: str,
    cmd: list[str] | None,
    elapsed_ms: Any,
    nmap_version: str,
    scaninfo_services: int,
) -> list[dict]:
    """解析单个 ``<host>``：open 端口 → port/component 条目，末尾一条 host_summary。"""
    results: list[dict] = []
    status_el = host.find("status")
    state = str(status_el.get("state") or "").strip() if status_el is not None else ""
    up = state == "up"
    ip = _host_ip(host) or str(default_ip or "").strip()

    # 端口状态统计：extraports 汇总 + 显式 <port> 的 state（两者互不重叠）
    counts: dict[str, int] = {}
    ports_el = host.find("ports")
    if ports_el is not None:
        for extra in ports_el.findall("extraports"):
            extra_state = str(extra.get("state") or "").strip()
            try:
                extra_count = int(extra.get("count") or 0)
            except (TypeError, ValueError):
                extra_count = 0
            if extra_state:
                counts[extra_state] = counts.get(extra_state, 0) + extra_count

        for port_el in ports_el.findall("port"):
            proto = str(port_el.get("protocol") or "tcp").strip() or "tcp"
            portid = str(port_el.get("portid") or "").strip()
            if not portid:
                continue
            state_el = port_el.find("state")
            port_state = str(state_el.get("state") or "").strip() if state_el is not None else ""
            reason = str(state_el.get("reason") or "").strip() if state_el is not None else ""
            counts[port_state] = counts.get(port_state, 0) + 1
            svc = _service_fields(port_el.find("service"))
            target = f"{ip}:{portid}/{proto}"
            if port_state != "open":
                continue
            service_name = svc["name"]
            results.append(make_raw(
                "nmap",
                "port",
                f"PORT-{portid}/{proto}",
                target,
                title=f"{portid}/{proto} {port_state} {service_name}".strip(),
                severity=None,
                evidence={
                    "port": int(portid) if portid.isdigit() else portid,
                    "proto": proto,
                    "state": port_state,
                    "reason": reason,
                    "service": service_name,
                    "tunnel": svc["tunnel"],
                },
            ))
            if svc["product"] or svc["version"] or svc["cpes"]:
                results.append(_component_raw(portid, proto, target, svc))

    total_ports = sum(counts.values())
    scanned = max(total_ports, int(scaninfo_services or 0))
    evidence: dict[str, Any] = {
        "up": up,
        "scanned": scanned,
        "open": counts.get("open", 0),
        "closed": counts.get("closed", 0),
        "filtered": counts.get("filtered", 0),
        "elapsed_ms": _elapsed_ms(host, elapsed_ms),
        "cmd": [str(part) for part in (cmd or [])],
        "nmap_version": nmap_version,
    }
    for extra_key in ("open|filtered", "unfiltered", "closed|filtered"):
        if counts.get(extra_key):
            evidence[extra_key.replace("|", "_")] = counts[extra_key]
    results.append(make_raw(
        "nmap",
        "host_summary",
        f"HOST-{ip}",
        ip,
        title=f"{ip} host summary",
        severity=None,
        evidence=evidence,
    ))
    return results


def _scaninfo_services(root: ET.Element) -> int:
    """``<scaninfo numservices="N">`` 求和（多协议时累加），作为 scanned 的下限。"""
    total = 0
    for info in root.findall("scaninfo"):
        try:
            total += int(info.get("numservices") or 0)
        except (TypeError, ValueError):
            continue
    return total


def parse_nmap_xml(
    xml_text: str,
    ip: str = "",
    *,
    cmd: list[str] | None = None,
    elapsed_ms: Any = None,
) -> list[dict]:
    """解析 ``nmap -oX -`` 的 XML 文本，返回 RawResult 列表。

    只关心 ``<host>`` 下的 ``<ports><port>``：portid/protocol、``<state>``、
    ``<service>``（name/product/version/extrainfo/tunnel/method/conf）与 ``<cpe>``。
    XML 畸形/为空时返回 ``[]`` 并 ``log.warn``。
    """
    results: list[dict] = []
    if not isinstance(xml_text, str) or not xml_text.strip():
        return results
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        log.warn("nmap XML 解析失败（畸形/截断）", ip=ip, error=str(exc)[:200])
        return results
    nmap_version = str(root.get("version") or "")
    scaninfo = _scaninfo_services(root)
    hosts = [root] if root.tag == "host" else list(root.findall("host"))
    if not hosts:
        log.warn("nmap XML 中没有 <host> 节点", ip=ip)
        return results
    for host in hosts:
        try:
            results.extend(_parse_host(host, ip, cmd, elapsed_ms, nmap_version, scaninfo))
        except (AttributeError, TypeError, ValueError) as exc:  # 极端畸形节点
            log.warn("nmap XML 单主机解析失败", ip=ip, error=str(exc)[:200])
            continue
    return results


# ---------------------------------------------------------------------------
# 适配器
# ---------------------------------------------------------------------------
class NmapAdapter:
    """nmap 适配器：一次 ``-sV`` 扫描同时完成端口发现与组件版本识别（D1+D3）。

    ``available()`` 只探测二进制（走配置 ``scan.nmap.bin``）；``supports()`` 对所有
    profile 开放，端口范围与是否 ``-sV`` 由 runner 通过 :class:`ScanContext` 控制。
    """

    name = "nmap"
    version = "7.x"
    cost = "medium"
    requires = ["tcp"]

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    # ---------------------------------------------------------------- 探测
    def binary(self) -> str:
        """nmap 可执行文件（命令名或绝对路径）。"""
        return str(cfg_get_default(self.cfg, "scan.nmap.bin", "nmap") or "nmap").strip()

    def version_intensity(self) -> int:
        """``--version-intensity``（0~9，默认 7）。"""
        return min(9, max(0, cfg_int(self.cfg, "scan.nmap.version_intensity", 7)))

    def max_retries(self) -> int:
        """``--max-retries``（默认 2）。"""
        return min(10, max(0, cfg_int(self.cfg, "scan.nmap.max_retries", 2)))

    def available(self) -> bool:
        """配置的 nmap 二进制是否存在；Windows 开发机恒为 ``False``。"""
        try:
            return binary_available(self.cfg, "scan.nmap.bin", "nmap")
        except Exception:  # noqa: BLE001 - 探测失败等价于不可用
            return False

    def supports(self, asset: dict, profile: str = "weekly") -> bool:
        """所有 profile 均支持（targeted/verify-fix 由 runner 限制端口规格）。"""
        return bool(str((asset or {}).get("ip") or "").strip())

    # ---------------------------------------------------------------- 命令
    def build_args(self, asset: dict, ctx: ScanContext) -> list[str]:
        """拼 nmap 命令：``-oX -`` + 可选 ``-sV`` + 端口规格 + 目标 IP。"""
        ip = str((asset or {}).get("ip") or "").strip()
        args: list[str] = [self.binary() or "nmap", "-oX", "-"]
        if ctx.service_detect:
            args += ["-sV", "--version-intensity", str(self.version_intensity())]
        try:
            host_timeout = max(1, int(float(ctx.timeout_sec)))
        except (TypeError, ValueError):
            host_timeout = 900
        args += [
            "-T4",
            "--host-timeout", f"{host_timeout}s",
            "--max-retries", str(self.max_retries()),
        ]
        try:
            rate_limit = int(float(ctx.rate_limit or 0))
        except (TypeError, ValueError):
            rate_limit = 0
        if rate_limit > 0:
            # connect 扫描下 nmap 可能提示 --max-rate 不适用，属告警级，不视为失败
            args += ["--max-rate", str(rate_limit)]
        extra = ctx.extra if isinstance(ctx.extra, dict) else {}
        args += build_port_args(ctx.ports, extra.get("declared_ports"))
        if ip:
            args.append(ip)
        return args

    # ---------------------------------------------------------------- 执行
    def run(self, asset: dict, ctx: ScanContext) -> list[dict]:
        """执行一次 nmap 扫描并解析 XML；任何失败都只告警、返回部分结果或 ``[]``。"""
        asset = asset if isinstance(asset, dict) else {}
        if not self.available():
            log.warn("nmap 不可用，跳过端口/服务扫描", ip=asset.get("ip"))
            return []
        if not self.supports(asset, ctx.profile):
            return []
        args = self.build_args(asset, ctx)
        # nmap 自身 --host-timeout 到点会输出不完整 XML，进程层再留 30s 收尾余量
        try:
            cap = max(60.0, float(ctx.timeout_sec))
        except (TypeError, ValueError):
            cap = 900.0
        proc_timeout = clip_timeout(ctx, cap=cap, floor=30.0) + 30.0
        started = time.monotonic()
        proc = run_capture(args, proc_timeout)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if proc.rc == 127:
            log.warn("nmap 二进制不存在", bin=args[0])
            return []
        stdout = proc.stdout if isinstance(proc.stdout, str) else ""
        if not stdout.strip():
            log.warn("nmap 无输出", ip=asset.get("ip"), rc=proc.rc, error=proc.brief())
            return []
        if proc.rc != 0:
            log.warn(
                "nmap 退出码非 0，尝试解析已有 XML",
                ip=asset.get("ip"), rc=proc.rc, error=proc.brief(), stderr=proc.tail(5),
            )
        results = parse_nmap_xml(
            stdout, ip=str(asset.get("ip") or ""), cmd=args, elapsed_ms=elapsed_ms
        )
        if not results:
            log.warn("nmap 输出未解析出任何结果", ip=asset.get("ip"), rc=proc.rc)
        return results


__all__ = [
    "DEFAULT_TOP_PORTS",
    "NmapAdapter",
    "build_port_args",
    "normalize_component",
    "parse_cpe",
    "parse_nmap_xml",
]
