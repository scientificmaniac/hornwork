"""资产台账的高层操作（扫描模块 D1~D6 的"目标来源"）。

设计原则：
- **台账是扫描的唯一目标来源**，不扫台账外的地址（既是工程质量，也是合法性边界）；
- 凭据只存 ``cred_ref`` 引用，不存明文；
- 资产"声明端口"写进 ``facts_json.declared_ports``，供 targeted / verify-fix 计划只扫声明端口；
- 资产变更（新增）触发首扫，历史 finding 不删除（``enabled=0`` 只影响覆盖率分母）。
"""

from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any

from ..config import cfg_get
from ..log import get_logger
from . import store as sstore

log = get_logger("scan.assets")

#: 资产角色（决定 coverage 的适用域与报告分组）
ROLES = ("self", "server", "web", "db", "lab", "workstation", "network", "windows")


def normalize_ip(value: str) -> str:
    """校验并归一 IPv4/IPv6 字面量；非法抛 ValueError。"""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError(f"非法 IP 地址：{value}") from exc


def normalize_tags(tags: Any) -> list[str]:
    """标签归一：接受 str（逗号/分号分隔）或 list。"""
    if tags is None:
        return []
    if isinstance(tags, str):
        raw = tags.strip()
        if not raw:
            return []
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    return [str(x).strip() for x in parsed if str(x).strip()]
            except (TypeError, ValueError):
                pass
        return [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
    if isinstance(tags, (list, tuple, set)):
        return [str(x).strip() for x in tags if str(x).strip()]
    return []


def declared_ports(asset: dict | None) -> list[int]:
    """取资产声明端口：``facts_json.declared_ports`` 或 ``tags`` 里的 ``ports:...``。"""
    if not asset:
        return []
    ports: list[int] = []
    facts = asset.get("facts_json") or {}
    if isinstance(facts, str):
        try:
            facts = json.loads(facts)
        except (TypeError, ValueError):
            facts = {}
    for item in facts.get("declared_ports") or []:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 0 < port < 65536 and port not in ports:
            ports.append(port)
    for tag in asset.get("tags") or []:
        text = str(tag)
        if text.startswith("ports:"):
            for part in text.split(":", 1)[1].replace(";", ",").split(","):
                part = part.strip()
                if part.isdigit() and 0 < int(part) < 65536:
                    if int(part) not in ports:
                        ports.append(int(part))
    return ports


def tls_ports(asset: dict | None) -> list[int]:
    """取资产声明里的 TLS 端口（tag=``tls`` 或 ``tls_ports`` 列表），缺省 []。"""
    if not asset:
        return []
    ports: list[int] = []
    facts = asset.get("facts_json") or {}
    for item in facts.get("tls_ports") or []:
        try:
            ports.append(int(item))
        except (TypeError, ValueError):
            continue
    for svc in facts.get("declared_services") or []:
        if not isinstance(svc, dict):
            continue
        try:
            port = int(svc.get("port"))
        except (TypeError, ValueError):
            continue
        if svc.get("tls") or "tls" in (svc.get("tags") or []):
            ports.append(port)
    deduped: list[int] = []
    for port in ports:
        if port not in deduped:
            deduped.append(port)
    return deduped


def web_targets(asset: dict | None) -> list[str]:
    """生成 Web 探测目标（nuclei 用）：声明端口 + 常见 80/443/8080 等。"""
    if not asset:
        return []
    ip = str(asset.get("ip") or "")
    if not ip:
        return []
    ports = declared_ports(asset)
    if not ports:
        ports = [80, 443, 8000, 8080, 8443]
    targets: list[str] = []
    for port in ports:
        scheme = "https" if port in (443, 8443) else "http"
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        host = f"[{ip}]" if ":" in ip else ip
        url = f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"
        if url not in targets:
            targets.append(url)
    return targets


def add_asset(
    store: Any,
    cfg: dict | None = None,
    *,
    ip: str,
    asset_id: str | None = None,
    hostname: str | None = None,
    role: str | None = None,
    criticality: int = 3,
    group: str | None = None,
    tags: Any = None,
    cred_ref: str | None = None,
    is_self: bool = False,
    enabled: bool = True,
    declared_ports: list[int] | None = None,
    facts: dict | None = None,
) -> dict:
    """新增/更新一个台账资产（按 asset_id 或 IP 幂等；显式 asset_id 支持同 IP 双角色）。"""
    ip = normalize_ip(ip)
    facts_json: dict[str, Any] = dict(facts or {})
    if declared_ports:
        cleaned: list[int] = []
        for item in declared_ports:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 0 < port < 65536 and port not in cleaned:
                cleaned.append(port)
        if cleaned:
            facts_json["declared_ports"] = cleaned
    record = {
        "asset_id": asset_id,
        "ip": ip,
        "hostname": hostname,
        "role": role or "server",
        "criticality": criticality,
        "group_name": group,
        "tags": ",".join(normalize_tags(tags)) or None,
        "cred_ref": cred_ref,
        "is_self": 1 if is_self else 0,
        "enabled": 1 if enabled else 0,
        "facts_json": facts_json,
    }
    asset = sstore.upsert_asset(store, record)
    log.info("scan.asset.upserted", asset_id=asset.get("asset_id"), ip=ip, role=record["role"])
    return asset


def ensure_self_asset(store: Any, cfg: dict, *, ip: str = "127.0.0.1") -> dict:
    """注册本机资产（role=self、is_self=1）；已存在则只补默认字段。

    单机部署里 防护主机同时承担"防护机 + 被扫主机"角色；声明常用本地服务端口，
    让 targeted / verify-fix 计划不必全端口扫描。
    """
    existing = sstore.get_asset(store, "ast-self") or sstore.get_asset_by_ip(store, ip)
    default_ports = [int(p) for p in (cfg_get(cfg, "scan.self.declared_ports", []) or [])]
    if not default_ports:
        default_ports = [22, 80, 443, 631, 8787]
    if existing:
        return existing
    return add_asset(
        store, cfg,
        asset_id="ast-self",
        ip=ip,
        hostname=socket.gethostname(),
        role="self",
        criticality=5,
        group="self",
        tags="self,linux",
        is_self=True,
        declared_ports=default_ports,
        facts={"os_family": "linux", "cpe_os": "cpe:/o:canonical:ubuntu_linux"},
    )


def asset_view(asset: dict) -> dict:
    """CLI/Web 展示用的精简视图。"""
    return {
        "asset_id": asset.get("asset_id"),
        "ip": asset.get("ip"),
        "hostname": asset.get("hostname"),
        "role": asset.get("role"),
        "criticality": asset.get("criticality"),
        "group_name": asset.get("group_name"),
        "tags": asset.get("tags") or [],
        "is_self": bool(asset.get("is_self")),
        "enabled": bool(asset.get("enabled")),
        "declared_ports": declared_ports(asset),
        "last_seen": asset.get("last_seen"),
    }


def selector_from_args(args: Any) -> dict:
    """从 CLI 参数构造选择器（asset/group/role/tag/min-criticality）。"""
    selector: dict[str, Any] = {}
    for attr, key in (
        ("asset", "asset_ids"), ("assets", "asset_ids"), ("group", "group"),
        ("role", "role"), ("tag", "tags"), ("min_criticality", "min_criticality"),
    ):
        value = getattr(args, attr, None) if args is not None else None
        if value in (None, "", []):
            continue
        selector[key] = value if key != "asset_ids" else (value if isinstance(value, list) else [value])
    return selector
