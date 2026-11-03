"""漏洞档案持久化：``vuln_record`` 表。

- ``init_schema``：建表 + 索引（幂等，CLI/Web 首次访问自动调用）；
- ``sync_records``：校验 → upsert；不合格档案不写库，错误逐条返回（不抛异常）；
- ``seed_from_dir``：读 ``[vuln].records_dir`` 整批同步（配置目录不存在时回退仓库内置
  ``hornwork/data/records``，便于开发机/演示）；
- ``list_records`` / ``get_record``：返回完整档案 dict（payload 已 JSON 解码 + ``_row`` 元数据）。

表结构遵循文档 DDL，另加 ``payload`` / ``affected_versions`` 两列 JSON 明细（供 IF-18 直接
读区间），风格与检测模块 ``event`` 表"标量列 + JSON 明细"一致，不新建数据库。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..config import cfg_get
from ..log import get_logger
from . import model

log = get_logger("vuln.store")

#: 表结构
DDL: list[str] = [
    """CREATE TABLE IF NOT EXISTS vuln_record (
      id TEXT PRIMARY KEY, cve TEXT, title TEXT NOT NULL, component TEXT NOT NULL,
      cwe TEXT NOT NULL, cvss_vector TEXT NOT NULL, cvss_score REAL NOT NULL,
      severity TEXT CHECK (severity IN ('严重','高','中','低','无')),
      kind TEXT DEFAULT 'server', status TEXT DEFAULT 'draft',
      yaml_path TEXT NOT NULL, updated_at TEXT NOT NULL,
      payload JSON, affected_versions JSON,
      CHECK (cvss_score BETWEEN 0 AND 10))""",
    "CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vuln_record(cve)",
    "CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vuln_record(severity)",
    "CREATE INDEX IF NOT EXISTS idx_vuln_status ON vuln_record(status)",
]

_COLUMNS = (
    "id", "cve", "title", "component", "cwe", "cvss_vector", "cvss_score",
    "severity", "kind", "status", "yaml_path", "updated_at",
)


def init_schema(store: Any) -> None:
    """创建 ``vuln_record`` 表与索引（幂等）。"""
    for statement in DDL:
        store.execute(statement)


def _records_dir(cfg: dict) -> Path | None:
    """解析档案目录：优先 ``[vuln].records_dir``，不存在时回退仓库内置目录。"""
    configured = str(cfg_get(cfg, "vuln.records_dir", "") or "").strip()
    fallback = Path(__file__).resolve().parents[2] / "data" / "records"
    if configured:
        path = Path(configured).expanduser()
        if path.is_dir():
            return path
    if fallback.is_dir():
        return fallback
    return Path(configured).expanduser() if configured else None


def _yaml_path_of(rec: dict) -> str:
    for key in ("_yaml_path", "yaml_path"):
        value = rec.get(key)
        if value not in (None, ""):
            return str(value)
    return f"data/records/{rec.get('id') or 'unknown'}.yaml"


def _upsert(store: Any, rec: dict) -> None:
    """单条 upsert（主键冲突整行更新，保证同步幂等）。"""
    lab = rec.get("lab") if isinstance(rec.get("lab"), dict) else {}
    store.execute(
        """INSERT INTO vuln_record(
             id, cve, title, component, cwe, cvss_vector, cvss_score, severity,
             kind, status, yaml_path, updated_at, payload, affected_versions)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET
             cve=excluded.cve, title=excluded.title, component=excluded.component,
             cwe=excluded.cwe, cvss_vector=excluded.cvss_vector,
             cvss_score=excluded.cvss_score, severity=excluded.severity,
             kind=excluded.kind, status=excluded.status, yaml_path=excluded.yaml_path,
             updated_at=excluded.updated_at, payload=excluded.payload,
             affected_versions=excluded.affected_versions""",
        (
            rec.get("id"), rec.get("cve"), rec.get("title"), rec.get("component"),
            rec.get("cwe"), rec.get("cvss_vector"), float(rec.get("cvss_score") or 0.0),
            rec.get("severity"), str(lab.get("kind") or "server"),
            rec.get("status") or "draft", _yaml_path_of(rec),
            str(rec.get("updated_at") or rec.get("created_at") or ""),
            json.dumps(rec, ensure_ascii=False, default=str, allow_nan=False),
            json.dumps(rec.get("affected_versions") or [], ensure_ascii=False, default=str, allow_nan=False),
        ),
    )


def _sync(store: Any, records: list[dict], min_references: int) -> dict:
    """内部同步：逐条校验、upsert、错误隔离。"""
    init_schema(store)
    upserted = 0
    rejected = 0
    errors: list[dict] = []
    for raw in records or []:
        if not isinstance(raw, dict):
            rejected += 1
            errors.append({"id": None, "errors": ["记录不是 dict"]})
            continue
        vuln_id = str(raw.get("id") or "").strip()
        record_errors = model.validate_record(raw, min_references=min_references)
        if record_errors:
            rejected += 1
            errors.append({"id": vuln_id or None, "errors": record_errors})
            log.warn("vuln.record.rejected", vuln_id=vuln_id, errors=record_errors)
            continue
        try:
            _upsert(store, raw)
            upserted += 1
            log.info("vuln.record.upserted", vuln_id=vuln_id, cve=raw.get("cve"))
        except (ValueError, TypeError) as exc:  # JSON 序列化/数值异常
            rejected += 1
            errors.append({"id": vuln_id or None, "errors": [f"入库失败: {exc}"]})
            log.warn("vuln.record.upsert_failed", vuln_id=vuln_id, error=str(exc))
    return {"upserted": upserted, "rejected": rejected, "errors": errors}


def sync_records(store: Any, records: list[dict]) -> dict:
    """校验并同步一批档案，返回 ``{"upserted","rejected","errors"}``（幂等、逐条隔离）。"""
    return _sync(store, records, min_references=2)


def seed_from_dir(store: Any, cfg: dict) -> dict:
    """读 ``[vuln].records_dir`` 整批同步；返回统计并附 ``dir`` / ``total``。"""
    directory = _records_dir(cfg)
    result: dict[str, Any] = {
        "upserted": 0, "rejected": 0, "errors": [],
        "dir": str(directory) if directory else "", "total": 0,
    }
    if directory is None or not directory.is_dir():
        result["errors"].append({"id": None, "errors": ["找不到档案目录，请检查 [vuln].records_dir"]})
        log.warn("vuln.seed.no_dir", dir=str(directory))
        return result

    records: list[dict] = []
    load_errors: list[dict] = []
    for pattern in ("*.yaml", "*.yml"):
        for file_path in sorted(directory.glob(pattern)):
            try:
                record = model.load_record(str(file_path))
                record["_yaml_path"] = str(file_path)
                records.append(record)
            except (OSError, ValueError) as exc:
                load_errors.append({"id": None, "errors": [f"{file_path.name}: {exc}"]})
                log.warn("vuln.seed.load_failed", path=str(file_path), error=str(exc))

    synced = _sync(store, records, int(cfg_get(cfg, "vuln.min_references", 2) or 2))
    synced["errors"] = load_errors + synced["errors"]
    synced["rejected"] += len(load_errors)
    synced["dir"] = str(directory)
    synced["total"] = len(records) + len(load_errors)
    log.info(
        "vuln.seed.done", dir=str(directory), total=synced["total"],
        upserted=synced["upserted"], rejected=synced["rejected"],
    )
    return synced


def _decode_row(row: dict) -> dict:
    """表行 → 完整档案 dict（payload 优先，附 ``_row`` 元数据）。"""
    record: dict[str, Any] = {}
    payload = row.get("payload")
    if isinstance(payload, str) and payload:
        try:
            loaded = json.loads(payload)
            if isinstance(loaded, dict):
                record.update(loaded)
        except json.JSONDecodeError:
            pass
    for column in _COLUMNS:
        if row.get(column) is not None and column not in record:
            record[column] = row[column]
    record["id"] = row.get("id") or record.get("id")
    record["_row"] = {
        "yaml_path": row.get("yaml_path"), "updated_at": row.get("updated_at"),
        "kind": row.get("kind"), "status": row.get("status"),
        "cvss_score": row.get("cvss_score"), "severity": row.get("severity"),
        "cve": row.get("cve"),
    }
    return record


def list_records(
    store: Any,
    cwe: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """按类型/等级/状态筛选档案（CVSS 降序）；``cwe`` 支持前缀或包含匹配。"""
    init_schema(store)
    sql = "SELECT * FROM vuln_record WHERE 1=1"
    args: list[Any] = []
    if cwe:
        sql += " AND (cwe LIKE ? OR cwe LIKE ?)"
        args.extend([f"{cwe}%", f"%{cwe}%"])
    if severity:
        sql += " AND severity=?"
        args.append(severity)
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY cvss_score DESC, id ASC LIMIT ?"
    args.append(int(limit))
    return [_decode_row(row) for row in store.query(sql, args)]


def get_record(store: Any, vuln_id: str) -> dict | None:
    """按档案 ID 取单条（不存在返回 None）。"""
    init_schema(store)
    row = store.query_one("SELECT * FROM vuln_record WHERE id=?", (str(vuln_id),))
    return _decode_row(row) if row else None


def count_records(store: Any) -> int:
    """档案总数（Web 概览用）。"""
    init_schema(store)
    row = store.query_one("SELECT COUNT(*) AS n FROM vuln_record")
    return int(row["n"]) if row else 0
