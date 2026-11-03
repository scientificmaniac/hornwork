"""intel2rule：IOC → 可下发规则产物。


| IOC 类型 | 产物 | mode |
|---|---|---|
| hash | YARA 规则（``hash`` 模块哈希条件） | enforce |
| domain/url 主机名 | 网络规则 ``dst_domain_in`` | observe |
| ip | 网络规则 ``dst_ip_in`` | observe |
| filename/path | 主机规则 JSON（``file.path`` 条件） | observe |

产物命名约定（不覆盖他人规则文件）：
- ``<rule_dir>/yara/intel-<bundle_id>.yar``
- ``<rule_dir>/net/intel-<bundle_id>.rules``
- ``<rule_dir>/host/intel-<bundle_id>.json``
- ``<rule_dir>/intel/bundle.json``（固定清单）+ ``intel/intel-<bundle_id>.json``

``validate_files()`` 做 YARA 试编译与 netrules 试解析；依赖缺失（yara-python /
engines.netrules 未就绪）时降级为"跳过"而不是抛错。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .. import schema
from ..config import cfg_get, rule_dir as cfg_rule_dir
from ..log import get_logger
from .iocstore import IocStore

log = get_logger("intel.intel2rule")

MODES: dict[str, str] = {
    "hash": "enforce",
    "domain": "observe",
    "url": "observe",
    "ip": "observe",
    "filename": "observe",
}

#: hash 类 IOC 关联的 ATT&CK 技术（规则 meta 必填字段）
HASH_ATTACK = "T1204.002"
HASH_SEVERITY = 10
DOMAIN_ATTACK = "T1071.001"
IP_ATTACK = "T1071"
NET_SEVERITY = 10
HOST_SEVERITY = 8
HOST_ATTACK = "T1105"

#: 网络规则 id（N-9xxx 段留给情报自动生成，避免与自研 8 条冲突）
RULE_ID_DOMAIN = "N-9010"
RULE_ID_IP = "N-9020"

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe(bundle_id: str) -> str:
    """bundle_id → 安全文件名片段（空则回落 bundle-1）。"""
    text = _SAFE_NAME.sub("_", str(bundle_id or "").strip())
    return text or "bundle-1"


def _dirs(cfg: dict) -> dict[str, Path]:
    """解析四类规则目录（yara/net/host/intel）。"""
    base = Path(str(cfg_get(cfg, "general.rule_dir", "/opt/hornwork/rules")))
    return {
        "base": base,
        "yara": cfg_rule_dir(cfg, "yara"),
        "net": cfg_rule_dir(cfg, "net"),
        "host": cfg_rule_dir(cfg, "host"),
        "intel": Path(str(cfg_get(cfg, "intel.bundle_dir", str(base / "intel")))),
    }


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _url_host(value: str) -> str | None:
    """取 URL 主机名（容错无 scheme 写法）。"""
    from urllib.parse import urlsplit

    text = value if "://" in value else "http://" + value
    try:
        host = urlsplit(text).hostname
    except ValueError:
        return None
    return host.lower() if host else None


# ---------------------------------------------------------------------------
# 各类型渲染
# ---------------------------------------------------------------------------
def render_yara(hashes: list[str], bundle_id: str) -> str:
    """渲染 YARA 规则：hash 类 IOC 用内置 ``hash`` 模块做全文件哈希比对。"""
    lines = [
        "/* 由 hornwork intel2rule 自动生成，请勿手工修改 */",
        f"/* bundle: {bundle_id}  ioc: hash  mode: enforce */",
        'import "hash"',
        "",
    ]
    for idx, value in enumerate(hashes, 1):
        algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value), "sha256")
        lines.extend(
            [
                f"rule intel_hash_{idx}",
                "{",
                "    meta:",
                f'        attack = "{HASH_ATTACK}"',
                f"        severity = {HASH_SEVERITY}",
                f'        source = "hornwork-intel:{bundle_id}"',
                '        ioc_type = "hash"',
                f'        ioc_value = "{value}"',
                "    condition:",
                f'        hash.{algo}(0, filesize) == "{value}"',
                "}",
                "",
            ]
        )
    return "\n".join(lines)


def render_net(domains: list[str], ips: list[str], cfg: dict, bundle_id: str) -> str:
    """渲染网络规则（引用 cfg 里固定的 IOC 集合名，与 NetRuleSet 解析器兼容）。"""
    domain_set = str(cfg_get(cfg, "net.ioc_domain_set", "ioc_domains") or "ioc_domains")
    ip_set = str(cfg_get(cfg, "net.ioc_ip_set", "ioc_ips") or "ioc_ips")
    blocks: list[str] = []
    if domains:
        blocks.append(
            "\n".join(
                [
                    f"rule {RULE_ID_DOMAIN} ioc_domain_1 {{",
                    "  proto: tcp",
                    f"  dst_domain_in: {domain_set}",
                    f"  severity: {NET_SEVERITY}",
                    f"  technique: {DOMAIN_ATTACK}",
                    f'  msg: "出站命中威胁情报域名（intel {bundle_id}）"',
                    "}",
                ]
            )
        )
    if ips:
        blocks.append(
            "\n".join(
                [
                    f"rule {RULE_ID_IP} ioc_ip_1 {{",
                    "  proto: tcp",
                    f"  dst_ip_in: {ip_set}",
                    f"  severity: {NET_SEVERITY}",
                    f"  technique: {IP_ATTACK}",
                    f'  msg: "出站命中威胁情报 IP（intel {bundle_id}）"',
                    "}",
                ]
            )
        )
    return "\n\n".join(blocks) + ("\n" if blocks else "")


def render_host(names: list[str], bundle_id: str) -> dict[str, Any]:
    """渲染主机规则 JSON（``file.path`` 的 suffix/contains 条件）。"""
    conditions: list[dict[str, Any]] = []
    for name in names:
        conditions.append({"field": "file.path", "op": "suffix", "value": name})
        if "/" in name:
            conditions.append({"field": "file.path", "op": "contains", "value": name})
    return {
        "id": f"H-IOC-{_safe(bundle_id)}",
        "name": f"情报命中：可疑文件名/路径（intel {bundle_id}）",
        "level": HOST_SEVERITY,
        "mitre": [HOST_ATTACK],
        "event_types": ["file_create", "file_modify"],
        "condition": {"any": conditions},
        "description": "由 intel2rule 自动生成：文件名/路径类 IOC 命中，mode=observe（24h 观察后人工提升）",
    }


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------
def _validate_yara(paths: list[Path]) -> dict[str, Any]:
    """YARA 试编译；yara-python 缺失或编译失败都写进结果。"""
    info: dict[str, Any] = {"checked": False, "rules": 0, "files": [str(p) for p in paths], "errors": []}
    if not paths:
        return info
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError:
        info["reason"] = "yara-python 未安装，跳过试编译"
        return info
    filepaths = {p.stem: str(p) for p in paths}
    try:
        compiled = yara.compile(filepaths=filepaths)
    except Exception as exc:  # noqa: BLE001 - 编译失败必须降级为错误列表
        info["errors"].append(f"YARA 编译失败: {exc}")
        return info
    info["checked"] = True
    try:
        info["rules"] = len(compiled)
    except TypeError:
        info["rules"] = 0
    return info


def _validate_net(paths: list[Path], cfg: dict | None) -> dict[str, Any]:
    """用 engines.netrules.NetRuleSet 试解析；模块未就绪时跳过。"""
    info: dict[str, Any] = {"checked": False, "rules": 0, "files": [str(p) for p in paths], "errors": []}
    if not paths:
        return info
    if cfg is None:
        info["reason"] = "未提供 cfg，跳过 netrules 试解析"
        return info
    try:
        from ..engines.netrules import NetRuleSet  # type: ignore[import-not-found]
    except ImportError as exc:
        info["reason"] = f"netrules 未就绪，跳过试解析（{exc}）"
        return info
    try:
        ruleset = NetRuleSet(cfg, ioc_provider=lambda kind="ip": set())
        result = ruleset.load() or {}
    except Exception as exc:  # noqa: BLE001 - 解析器异常降级为错误列表
        info["errors"].append(f"netrules 试解析失败: {exc}")
        return info
    info["checked"] = True
    if isinstance(result, dict):
        info["rules"] = int(result.get("rules") or 0)
        for err in result.get("errors") or []:
            info["errors"].append(str(err))
    return info


def _validate_host(paths: list[Path]) -> dict[str, Any]:
    """主机规则 JSON 结构校验（不依赖 engines.hostrules）。"""
    info: dict[str, Any] = {"checked": False, "rules": 0, "files": [str(p) for p in paths], "errors": []}
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            info["errors"].append(f"主机规则读取失败 {path.name}: {exc}")
            continue
        rules = data if isinstance(data, list) else [data]
        for rule in rules:
            if not isinstance(rule, dict):
                info["errors"].append(f"主机规则不是对象: {path.name}")
                break
            missing = [k for k in ("id", "name", "condition") if not rule.get(k)]
            if missing:
                info["errors"].append(f"主机规则缺少字段 {missing}: {path.name}")
            else:
                info["rules"] += 1
    info["checked"] = True
    return info


def validate_files(paths: Iterable[str | Path], cfg: dict | None = None) -> dict[str, Any]:
    """对产物做试编译/试解析。

    返回 ``{"ok","checked","errors","yara","net","host"}``；依赖缺失记为 skip 不计错误。
    """
    items = [Path(p) for p in paths]
    missing = [str(p) for p in items if not p.is_file()]
    yara_paths = [p for p in items if p.suffix in (".yar", ".yara") and p.is_file()]
    net_paths = [p for p in items if p.suffix == ".rules" and p.is_file()]
    host_paths = [p for p in items if p.suffix == ".json" and p.is_file()]
    yara_info = _validate_yara(yara_paths)
    net_info = _validate_net(net_paths, cfg)
    host_info = _validate_host(host_paths)
    errors: list[str] = [f"文件不存在: {p}" for p in missing]
    errors.extend(yara_info["errors"])
    errors.extend(net_info["errors"])
    errors.extend(host_info["errors"])
    checked = bool(yara_info["checked"] or net_info["checked"] or host_info["checked"])
    return {
        "ok": not errors,
        "checked": checked,
        "errors": errors,
        "missing": missing,
        "yara": yara_info,
        "net": net_info,
        "host": host_info,
    }


# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------
def _group(iocs: IocStore) -> dict[str, list[dict[str, Any]]]:
    """按 type 分组（只取未过期未白名单记录）。"""
    groups: dict[str, list[dict[str, Any]]] = {kind: [] for kind in MODES}
    for row in iocs.rows(live_only=True):
        kind = str(row.get("type") or "")
        if kind in groups:
            groups[kind].append(row)
    return groups


def _dedup_values(rows: list[dict[str, Any]], *, lower: bool = False) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for row in rows:
        val = str(row.get("value") or "").strip()
        if not val:
            continue
        key = val.lower() if lower else val
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def build(store: Any, cfg: dict, bundle_id: str = "bundle-1") -> dict[str, Any]:
    """生成规则产物并校验，返回契约结构。"""
    dirs = _dirs(cfg or {})
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    slug = _safe(bundle_id)
    iocs = IocStore(store, cfg or {})
    groups = _group(iocs)

    hashes = _dedup_values(groups["hash"], lower=True)
    domains = _dedup_values(groups["domain"], lower=True)
    ips = _dedup_values(groups["ip"])
    filenames = _dedup_values(groups["filename"])

    # URL 类 IOC 只取主机名，合并进 domain / ip 集合（网络规则只按主机匹配）
    extra_domains: list[str] = []
    extra_ips: list[str] = []
    for url in _dedup_values(groups["url"]):
        host = _url_host(url)
        if not host:
            continue
        try:
            import ipaddress

            ipaddress.ip_address(host)
            if host not in ips and host not in extra_ips:
                extra_ips.append(host)
        except ValueError:
            if host not in domains and host not in extra_domains:
                extra_domains.append(host)
    domains = domains + extra_domains
    ips = ips + extra_ips

    files: list[str] = []
    details: list[dict[str, Any]] = []
    errors: list[str] = []

    if hashes:
        target = dirs["yara"] / f"intel-{slug}.yar"
        try:
            _write_text(target, render_yara(hashes, bundle_id))
            files.append(str(target))
            details.append({"path": str(target), "kind": "yara", "count": len(hashes),
                            "mode": MODES["hash"], "filename": target.name})
        except OSError as exc:
            errors.append(f"写入 YARA 规则失败: {exc}")
            log.error("写入 YARA 规则失败", path=str(target), error=str(exc))

    if domains or ips:
        target = dirs["net"] / f"intel-{slug}.rules"
        try:
            _write_text(target, render_net(domains, ips, cfg or {}, bundle_id))
            files.append(str(target))
            details.append({"path": str(target), "kind": "net", "count": len(domains) + len(ips),
                            "mode": MODES["domain"], "filename": target.name})
        except OSError as exc:
            errors.append(f"写入网络规则失败: {exc}")
            log.error("写入网络规则失败", path=str(target), error=str(exc))

    if filenames:
        target = dirs["host"] / f"intel-{slug}.json"
        try:
            payload = render_host(filenames, bundle_id)
            _write_text(target, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            files.append(str(target))
            details.append({"path": str(target), "kind": "host", "count": len(filenames),
                            "mode": MODES["filename"], "filename": target.name})
        except OSError as exc:
            errors.append(f"写入主机规则失败: {exc}")
            log.error("写入主机规则失败", path=str(target), error=str(exc))

    validation = validate_files(files, cfg) if files else {"ok": True, "checked": False, "errors": []}
    errors.extend(validation.get("errors") or [])

    counts = {
        "hash": len(hashes),
        "domain": len(domains),
        "ip": len(ips),
        "url": len(groups["url"]),
        "filename": len(filenames),
    }
    manifest: dict[str, Any] = {
        "bundle_id": str(bundle_id),
        "generated_at": schema.utc_now(),
        "host_id": str(cfg_get(cfg or {}, "general.host_id", "") or ""),
        "rule_dir": str(dirs["base"]),
        "counts": counts,
        "mode": dict(MODES),
        "files": details,
        "validation": {
            "ok": bool(validation.get("ok")),
            "checked": bool(validation.get("checked")),
            "yara": validation.get("yara"),
            "net": validation.get("net"),
            "host": validation.get("host"),
            "errors": validation.get("errors") or [],
        },
        "notes": "hash 类默认 enforce；domain/url/ip/filename 默认 observe，观察 24h 后人工提升",
    }
    try:
        manifest_json = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
        manifest_path = dirs["intel"] / "bundle.json"
        _write_text(manifest_path, manifest_json)
        per_bundle = dirs["intel"] / f"intel-{slug}.json"
        _write_text(per_bundle, manifest_json)
        files.extend([str(manifest_path), str(per_bundle)])
    except OSError as exc:
        errors.append(f"写入 bundle.json 失败: {exc}")
        log.error("写入 bundle.json 失败", error=str(exc))

    result = {
        "bundle_id": str(bundle_id),
        "dir": str(dirs["base"]),
        "files": files,
        "counts": counts,
        "validated": bool(validation.get("ok")) and not errors,
        "errors": errors,
    }
    log.info(
        "intel2rule 构建完成",
        bundle_id=str(bundle_id),
        files=len(files),
        validated=result["validated"],
        errors=len(errors),
    )
    return result
