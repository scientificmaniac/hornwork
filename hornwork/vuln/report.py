"""IF-19：漏洞档案渲染与导出（漏洞卡 / 整改单 / JSON / CSV）。

- :func:`render_card`：单条档案的 Markdown 漏洞卡（类型/等级/修复/复现/证据），
  直接贴进报告"漏洞分析"章节；
- :func:`render_rectification`：整改单 Markdown（表列 CVE/组件/类型/等级/修复/验证方式）；
- :func:`export_report`：落盘并返回 ``{"path","sha256","count"}``。

渲染全部由内置代码完成、不依赖外部模板文件（模板缺失即"回退内置模板"），
字段缺失显示 ``-`` / ``待补充`` 而不丢行。
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import cfg_get
from ..log import get_logger
from ..schema import sha256_file
from . import model, version
from .store import get_record, list_records

log = get_logger("vuln.report")

_FORMATS = {"md": "md", "markdown": "md", "json": "json", "csv": "csv"}
_RECT_COLUMNS = ("CVE", "组件", "类型", "等级", "修复", "验证方式")


def _text(value: Any, default: str = "-") -> str:
    """字段转单行文本：None/空 → default，列表用顿号连接，内部换行折成空格。"""
    if value is None:
        return default
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value if str(item).strip()]
        return "、".join(items) if items else default
    text = str(value).strip()
    return re.sub(r"\s+", " ", text) if text else default


def _cell(value: Any) -> str:
    """Markdown 表格单元格转义（竖线与换行）。"""
    return _text(value).replace("|", "\\|")


def _bullet(items: Any, marker: str = "- ") -> list[str]:
    """列表渲染成 Markdown 行；空列表给"待补充"占位。"""
    if not items:
        return [marker + "（待补充）"]
    lines: list[str] = []
    for item in items:
        if isinstance(item, dict):
            lines.append(marker + "；".join(f"{key}={val}" for key, val in item.items()))
        else:
            lines.append(marker + _text(item))
    return lines


def _fix_of(record: dict) -> dict:
    fix = record.get("fix")
    return fix if isinstance(fix, dict) else {}


def _repair_of(record: dict) -> str:
    """修复方案单行摘要：优先 patch_version，其次区间 fixed。"""
    patch = _text(_fix_of(record).get("patch_version"), "")
    if patch:
        return patch
    for rule in record.get("affected_versions") or []:
        if isinstance(rule, dict) and rule.get("fixed") not in (None, ""):
            return f"升级到 {rule['fixed']} 及以上"
    return "待补充"


def _verify_of(record: dict) -> str:
    """验证方式：detection_rule（检测模块规则 ID + 思路）优先。"""
    return _text(_fix_of(record).get("detection_rule"))


def render_card(record: dict) -> str:
    """渲染单条档案的 Markdown 漏洞卡（空记录也能渲染，绝不返回空串）。"""
    record = record or {}
    lab = record.get("lab") if isinstance(record.get("lab"), dict) else {}
    fix = _fix_of(record)
    vuln_id = _text(record.get("id"), "VULN-UNKNOWN")
    cve = _text(record.get("cve"), "CVE-XXXX-XXXXX")
    score = record.get("cvss_score")
    score_text = f"{float(score):.1f}" if isinstance(score, (int, float)) else _text(score)
    severity = _text(record.get("severity"), model.severity_of(float(score)) if score is not None else "无")

    lines: list[str] = [
        f"## {vuln_id} · {cve}",
        "",
        f"**{_text(record.get('title'), '（未命名漏洞）')}**",
        "",
        "| 项 | 值 |",
        "|---|---|",
        f"| 类型 | {_cell(record.get('cwe'))} |",
        f"| 等级 | {_cell(severity)}（CVSS 3.1 {score_text}） |",
        f"| 组件 | {_cell(record.get('component'))} |",
        f"| 状态 | {_cell(record.get('status'))} |",
        f"| 责任人 | {_cell(record.get('owner'))} |",
        f"| ATT&CK | {_cell(record.get('attack_technique'))} |",
        f"| 靶场 | {_cell(lab.get('kind'))} {_cell(lab.get('path'))}（端口 {_cell(lab.get('ports'))}） |",
        "",
        f"**CVSS 向量**：`{_text(record.get('cvss_vector'))}`",
        "",
        "### 受影响版本",
        "",
    ]
    ranges = [rule for rule in (record.get("affected_versions") or []) if isinstance(rule, dict)]
    lines += [f"- {version.describe_range(rule)}" for rule in ranges] or ["- （待补充）"]

    lines += ["", "### 攻击路径", ""] + _bullet(record.get("attack_path"), marker="")
    lines += ["", "### 前置条件", ""] + _bullet(record.get("preconditions"))

    lines += ["", "### 复现步骤", ""]
    steps = record.get("repro_steps") or []
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            lines.append(f"{index}. {_text(step)}")
            continue
        raw_cmd = step.get("cmd")
        cmd_text = "" if raw_cmd is None else str(raw_cmd).strip()
        lines.append(f"{index}. 命令：")
        lines.append("")
        lines.append("   ```bash")
        lines += [f"   {cmd_line}".rstrip() for cmd_line in cmd_text.splitlines() or [""]]
        lines.append("   ```")
        lines.append(f"   - 预期：{_text(step.get('expect'), '（未注明预期）')}")
    if not steps:
        lines.append("（待补充）")

    lines += ["", "### 证据", ""]
    evidence = record.get("evidence") or []
    if evidence:
        for item in evidence:
            if isinstance(item, dict):
                lines.append(
                    f"- `{_text(item.get('path'))}` sha256={_text(item.get('sha256'))} ts={_text(item.get('ts'))}"
                )
            else:
                lines.append(f"- {_text(item)}")
    else:
        lines.append("- 待回填：在靶场按上面复现步骤执行后，把请求/响应/命令回显写入 `evidence`")
        lines.append("  （每条含 `path` + `sha256` + `ts`），复核通过后把 `status` 从 `draft` 改为 `verified`。")

    lines += ["", "### 修复方案", "", f"- **升级**：{_text(fix.get('patch_version'))}"]
    mitigations = fix.get("config_mitigation") or []
    if mitigations:
        lines.append("- **缓解**：")
        lines += ["  " + line for line in _bullet(mitigations)]
    else:
        lines.append("- **缓解**：（待补充）")
    lines.append(f"- **检测**：{_text(fix.get('detection_rule'))}")
    lines += ["", "### 参考", ""] + _bullet(record.get("references"))
    lines.append("")
    return "\n".join(lines)


def render_rectification(records: list[dict]) -> str:
    """渲染整改单 Markdown（表列：CVE/组件/类型/等级/修复/验证方式）。"""
    items = [record for record in (records or []) if isinstance(record, dict)]
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = [
        "# 漏洞整改单",
        "",
        f"- 生成时间：{stamp}",
        f"- 档案数量：{len(items)}",
        "- 数据来源：`hornwork/data/records/`（NVD API 2.0 + 厂商公告，2026-10-26 抓取）",
        "- 说明：等级按 CVSS 3.1 BaseScore 分档；验证方式列给出检测模块的检测规则与复现口径。",
        "",
        "| # | " + " | ".join(_RECT_COLUMNS) + " |",
        "|---|" + "|".join(["---"] * len(_RECT_COLUMNS)) + "|",
    ]
    for index, record in enumerate(items, 1):
        row = [
            _cell(record.get("cve")), _cell(record.get("component")), _cell(record.get("cwe")),
            _cell(record.get("severity")), _cell(_repair_of(record)), _cell(_verify_of(record)),
        ]
        lines.append(f"| {index} | " + " | ".join(row) + " |")
    if not items:
        lines.append("| - | （无记录） | - | - | - | - | - |")
    lines.append("")
    return "\n".join(lines)


def _select_records(store: Any, ids: list[str] | None) -> list[dict]:
    """按 ids 取记录（缺失的告警跳过）；ids 为空表示全量。"""
    if not ids:
        return list_records(store, limit=10000)
    records: list[dict] = []
    for vuln_id in ids:
        record = get_record(store, str(vuln_id))
        if record:
            records.append(record)
        else:
            log.warn("vuln.report.missing_record", vuln_id=str(vuln_id))
    return records


def _render_json(records: list[dict]) -> str:
    return json.dumps(records, ensure_ascii=False, indent=2, default=str, allow_nan=False)


def _render_csv(records: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        ["vuln_id", "cve", "component", "cwe", "severity", "cvss_score",
         "fixed_version", "status", "detection_rule"]
    )
    for record in records:
        writer.writerow(
            [
                _text(record.get("id"), ""), _text(record.get("cve"), ""),
                _text(record.get("component"), ""), _text(record.get("cwe"), ""),
                _text(record.get("severity"), ""),
                record.get("cvss_score") if record.get("cvss_score") is not None else "",
                _repair_of(record), _text(record.get("status"), ""), _verify_of(record),
            ]
        )
    return buffer.getvalue()


def _default_path(cfg: dict, fmt: str) -> Path:
    """默认输出路径：优先 ``[verify].report_dir``，其次 ``[general].data_dir/reports``。"""
    report_dir = str(cfg_get(cfg, "verify.report_dir", "") or "").strip()
    if not report_dir:
        report_dir = str(Path(str(cfg_get(cfg, "general.data_dir", "/opt/hornwork"))) / "reports")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(report_dir).expanduser() / f"vuln-rectification-{stamp}.{fmt}"


def export_report(
    store: Any,
    cfg: dict,
    ids: list[str] | None = None,
    fmt: str = "md",
    out: str | None = None,
) -> dict:
    """导出整改单/报告，返回 ``{"path","sha256","count"}``（IF-19）。

    ``fmt`` 支持 ``md``（整改单）/ ``json``（档案数组）/ ``csv``（整改单表格），未知格式回退
    Markdown；``out`` 为空时按配置生成 UTC 时间戳文件名（Windows 下安全）。
    """
    normalized = _FORMATS.get(str(fmt or "md").strip().lower())
    if normalized is None:
        log.warn("vuln.report.unknown_format", fmt=str(fmt), fallback="md")
        normalized = "md"
    records = _select_records(store, ids)
    if normalized == "json":
        content = _render_json(records)
    elif normalized == "csv":
        content = _render_csv(records)
    else:
        content = render_rectification(records)
    target = Path(str(out)).expanduser() if out else _default_path(cfg, normalized)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    digest = sha256_file(str(target))
    log.info("vuln.report.exported", path=str(target), fmt=normalized, count=len(records), sha256=digest)
    return {"path": str(target), "sha256": digest, "count": len(records)}
