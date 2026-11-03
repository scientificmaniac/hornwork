"""漏洞档案数据模型与校验。

档案共 21 个顶层字段，其中 18 个必填（``REQUIRED_FIELDS``）；另外 3 个为
``attack_technique``（可选）与 ``created_at`` / ``updated_at``（由写入流程自动维护）。
校验对齐文档"校验"一节：缺字段/空字段拒绝；``cvss_score`` 必须等于向量计算值；
``severity`` 必须等于分档结果；``references`` ≥ N 条；``status=verified`` 要求证据非空且
每条含 path + 合法 sha256 + ts。所有校验离线可做（不访问文件系统），YAML 读写用 PyYAML。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:  # 允许在未装 PyYAML 的开发机上 import 本模块（只有读写 YAML 时才强制依赖）
    import yaml
except ImportError:  # pragma: no cover - 部署环境用 setup.sh 安装 PyYAML
    yaml = None  # type: ignore[assignment]

_YAML_ERROR = yaml.YAMLError if yaml is not None else Exception


def _require_yaml() -> None:
    if yaml is None:
        raise RuntimeError("缺少 PyYAML：请安装 PyYAML 或使用 /opt/hornwork-venv 运行")

from ..log import get_logger
from ..schema import utc_now
from . import cvss

log = get_logger("vuln.model")

#: 18 个必填字段（attack_technique 可选；created_at/updated_at 由 save_record 补齐）
REQUIRED_FIELDS: list[str] = [
    "id", "cve", "title", "component", "affected_versions", "cwe",
    "cvss_vector", "cvss_score", "severity", "attack_path", "preconditions",
    "repro_steps", "evidence", "fix", "references", "lab", "status", "owner",
]

#: 等级枚举（与 cvss.severity / vuln_record DDL 的 CHECK 一致）
SEVERITIES: tuple[str, ...] = ("严重", "高", "中", "低", "无")
#: 状态机：draft（待复现）→ verified（证据已复核）→ published（对外发布）
STATUSES: tuple[str, ...] = ("draft", "verified", "published")
#: 靶场类型：server（Vulhub 容器）/ client（办公软件线，无 Docker）
LAB_KINDS: tuple[str, ...] = ("server", "client")
#: 支持的版本体系（与 vuln.version 对齐）
_SCHEMES = ("generic", "deb", "debian", "dpkg", "semver", "sem")

_ID_RE = re.compile(r"^VULN-\d{4}-\d{4}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CVE_PLACEHOLDER_RE = re.compile(r"^CVE-XXXX-XXXXX$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_LIST_FIELDS = ("affected_versions", "attack_path", "preconditions", "repro_steps", "evidence", "references")
_TEXT_FIELDS = ("id", "cve", "title", "component", "cwe", "cvss_vector", "severity", "status", "owner")


def _normalize_record(rec: dict) -> dict:
    """YAML 裸 dict 规范化：分数转 float、元组转 list、子对象兜底。"""
    out: dict[str, Any] = dict(rec or {})
    if out.get("cvss_score") is not None:
        try:
            out["cvss_score"] = round(float(out["cvss_score"]), 1)
        except (TypeError, ValueError):
            pass
    for field in _LIST_FIELDS:
        if isinstance(out.get(field), tuple):
            out[field] = list(out[field])
    if not isinstance(out.get("fix"), dict):
        out["fix"] = {}
    if not isinstance(out.get("lab"), dict):
        out["lab"] = {}
    if not isinstance(out.get("affected_versions"), list):
        out["affected_versions"] = []
    return out


def load_record(path: str) -> dict:
    """读取单份档案 YAML；文件不存在或 YAML 非法时抛异常（由调用方决定是否隔离）。"""
    file_path = Path(str(path))
    if not file_path.is_file():
        raise FileNotFoundError(f"档案文件不存在: {file_path}")
    _require_yaml()
    with open(file_path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"档案不是 YAML 映射: {file_path}")
    return _normalize_record(data)


def save_record(path: str, rec: dict) -> None:
    """写回档案 YAML（UTF-8、中文不转义、保持字段顺序）；缺时间戳时自动补当前 UTC。"""
    out = _normalize_record(dict(rec or {}))
    now = utc_now()
    out.setdefault("created_at", now)
    out.setdefault("updated_at", now)
    if not out.get("created_at"):
        out["created_at"] = now
    if not out.get("updated_at"):
        out["updated_at"] = now
    out.pop("_yaml_path", None)
    out.pop("_row", None)
    file_path = Path(str(path))
    file_path.parent.mkdir(parents=True, exist_ok=True)
    _require_yaml()
    with open(file_path, "w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(out, handle, allow_unicode=True, sort_keys=False, default_flow_style=False, width=120)


def load_records(dir_path: str) -> list[dict]:
    """读取目录下全部 ``*.yaml/*.yml``；单份失败只告警跳过，不中断整批。"""
    base = Path(str(dir_path))
    if not base.is_dir():
        return []
    out: list[dict] = []
    for pattern in ("*.yaml", "*.yml"):
        for file_path in sorted(base.glob(pattern)):
            try:
                out.append(load_record(str(file_path)))
            except (OSError, _YAML_ERROR, ValueError) as exc:
                log.warn("vuln.record.load_failed", path=str(file_path), error=str(exc))
    return out


def severity_of(score: float) -> str:
    """分值 → 等级（委托 ``cvss.severity``，越界抛 ValueError）。"""
    value = float(score)
    if value < 0 or value > 10:
        raise ValueError(f"CVSS 分值越界: {value}")
    return cvss.severity(value)


def _is_blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def _check_text_fields(rec: dict, errs: list[str]) -> None:
    for field in _TEXT_FIELDS:
        value = rec.get(field)
        if field not in rec:
            errs.append(f"缺少必填字段: {field}")
        elif _is_blank(value):
            errs.append(f"必填字段为空: {field}")
        elif not isinstance(value, str):
            errs.append(f"字段类型错误: {field} 应为字符串")


def _check_identity(rec: dict, errs: list[str]) -> None:
    vuln_id = str(rec.get("id") or "").strip()
    if vuln_id and not _ID_RE.match(vuln_id):
        errs.append(f"id 格式非法: {vuln_id!r}（应为 VULN-<年>-<4位>）")
    cve = str(rec.get("cve") or "").strip()
    if cve:
        if _CVE_PLACEHOLDER_RE.match(cve):
            if str(rec.get("status") or "") != "draft":
                errs.append("cve 为占位值时 status 必须为 draft")
        elif not _CVE_RE.match(cve):
            errs.append(f"cve 格式非法: {cve!r}")
    status = rec.get("status")
    if isinstance(status, str) and status.strip() and status not in STATUSES:
        errs.append(f"status 不在枚举内: {status!r}")
    technique = rec.get("attack_technique")
    if technique not in (None, ""):
        if not isinstance(technique, str) or not _TECHNIQUE_RE.match(technique.strip()):
            errs.append(f"attack_technique 格式非法: {technique!r}")
    for field in ("created_at", "updated_at"):
        value = rec.get(field)
        if value in (None, ""):
            continue
        if not isinstance(value, str) or not _ISO_RE.match(value.strip()):
            errs.append(f"{field} 不是 UTC ISO8601 时间: {value!r}")


def _check_versions(rec: dict, errs: list[str]) -> None:
    ranges = rec.get("affected_versions")
    if not isinstance(ranges, list) or not ranges:
        errs.append("字段 affected_versions 必须是非空列表")
        return
    for index, rule in enumerate(ranges):
        if not isinstance(rule, dict):
            errs.append(f"affected_versions[{index}] 不是映射")
            continue
        scheme = str(rule.get("scheme") or "generic").strip().lower()
        if scheme not in _SCHEMES:
            errs.append(f"affected_versions[{index}].scheme 非法: {rule.get('scheme')!r}")
        if not any(rule.get(key) not in (None, "") for key in ("introduced", "fixed", "versions")):
            errs.append(f"affected_versions[{index}] 至少需要 introduced / fixed / versions 之一")


def _check_cvss(rec: dict, errs: list[str]) -> None:
    vector, score = rec.get("cvss_vector"), rec.get("cvss_score")
    if _is_blank(vector) or score is None:
        return
    try:
        computed = cvss.calculate(str(vector))
    except ValueError as exc:
        errs.append(f"cvss_vector 无法解析: {exc}")
        return
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        errs.append("cvss_score 不是数值")
        return
    if numeric < 0 or numeric > 10:
        errs.append(f"cvss_score 越界: {numeric}")
        return
    if abs(numeric - computed) > 1e-9:
        errs.append(f"cvss_score={numeric} 与向量计算值 {computed} 不一致")
    expected = cvss.severity(computed)
    severity = rec.get("severity")
    if isinstance(severity, str) and severity.strip():
        if severity not in SEVERITIES:
            errs.append(f"severity 不在枚举内: {severity!r}")
        elif severity != expected:
            errs.append(f"severity={severity} 与分值 {computed} 的档位 {expected} 不一致")


def _check_evidence(rec: dict, errs: list[str]) -> None:
    evidence = rec.get("evidence")
    if not isinstance(evidence, list):
        errs.append("字段 evidence 必须是列表（draft 可为空列表）")
        return
    status = str(rec.get("status") or "").strip()
    if status == "verified" and not evidence:
        errs.append("status=verified 要求 evidence 非空")
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            errs.append(f"evidence[{index}] 不是映射")
            continue
        if _is_blank(item.get("path")):
            errs.append(f"evidence[{index}] 缺少 path")
        digest = str(item.get("sha256") or "")
        if digest and not _SHA256_RE.match(digest):
            errs.append(f"evidence[{index}].sha256 格式非法（应为 64 位小写十六进制）")
        if status == "verified" and not digest:
            errs.append(f"evidence[{index}] 在 verified 状态下必须带 sha256")
        if _is_blank(item.get("ts")):
            errs.append(f"evidence[{index}] 缺少 ts")


def _check_fix_and_lab(rec: dict, errs: list[str]) -> None:
    fix = rec.get("fix")
    if not isinstance(fix, dict):
        errs.append("字段 fix 必须是映射")
    else:
        if _is_blank(fix.get("patch_version")):
            errs.append("fix.patch_version 不能为空")
        for key in ("config_mitigation", "detection_rule"):
            if key not in fix:
                errs.append(f"fix 缺少子字段: {key}")
        if "config_mitigation" in fix and not isinstance(fix.get("config_mitigation"), list):
            errs.append("fix.config_mitigation 必须是列表")
    lab = rec.get("lab")
    if not isinstance(lab, dict):
        errs.append("字段 lab 必须是映射")
        return
    kind = str(lab.get("kind") or "").strip()
    if kind not in LAB_KINDS:
        errs.append(f"lab.kind 必须是 {'/'.join(LAB_KINDS)}")
    if kind == "server" and _is_blank(lab.get("path")):
        errs.append("lab.path 在 kind=server 时不能为空")
    if "ports" not in lab:
        errs.append("lab 缺少子字段: ports")
    elif not isinstance(lab.get("ports"), list):
        errs.append("lab.ports 必须是列表")


def _check_references(rec: dict, errs: list[str], min_references: int) -> None:
    references = rec.get("references")
    if not isinstance(references, list):
        errs.append("字段 references 必须是列表")
        return
    if len(references) < int(min_references):
        errs.append(f"references 至少 {int(min_references)} 条，当前 {len(references)} 条")
    for index, item in enumerate(references):
        text = str(item or "").strip()
        if not text:
            errs.append(f"references[{index}] 为空")
        elif not text.startswith(("http://", "https://")):
            errs.append(f"references[{index}] 不是 HTTP(S) 链接: {text}")


def validate_record(rec: dict, min_references: int = 2) -> list[str]:
    """校验单份档案，返回中文错误列表（空列表 = 通过）。

    只做结构与"向量/分数/等级一致性""引用条数""证据格式"等可离线判断的项目，
    sha256 复核由 ``vuln.store`` / 命令行在需要时执行。
    """
    if not isinstance(rec, dict):
        return ["档案不是 YAML 映射（dict）"]
    errs: list[str] = [f"缺少必填字段: {field}" for field in REQUIRED_FIELDS if field not in rec]
    _check_text_fields(rec, errs)
    _check_identity(rec, errs)
    _check_versions(rec, errs)
    _check_cvss(rec, errs)
    _check_evidence(rec, errs)
    _check_fix_and_lab(rec, errs)
    _check_references(rec, errs, min_references)
    for field in ("attack_path", "preconditions", "repro_steps"):
        value = rec.get(field)
        if not isinstance(value, list):
            errs.append(f"字段 {field} 必须是列表")
        elif not value:
            errs.append(f"字段 {field} 不能为空列表")
        elif any(_is_blank(item) for item in value):
            errs.append(f"字段 {field} 含空条目")
    return errs
