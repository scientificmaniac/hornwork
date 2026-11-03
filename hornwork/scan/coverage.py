"""覆盖率计算。

**为什么不用"扫了多少端口"当覆盖率**：端口数是"探测量"不是"覆盖面"——一个资产开
1 个端口也可能完全没做基线与 TLS 检查，用探测量当覆盖率会系统性高估，掩盖真盲区
（例如无凭据 → D2 永远为空）。因此这里按"资产 × 检查域"逐格判定：

=================  ==========================  ============================
单格 covered 值    条件                         来源
=================  ==========================  ============================
``1.0``            ``checkpoint.domains[d].status == "done"``
``0.5``            ``status == "partial"``（执行了但失败/超时/低置信）
``0``              ``skipped`` / ``error`` / 缺失（引擎未执行）
=================  ==========================  ============================

综合覆盖率 = Σ(w×covered) / Σ(w×applicable)，applicable 只计该资产角色下适用的域。
权重默认 D1 0.15 / D2 0.30 / D3 0.20 / D4 0.15 / D5 0.10 / D6 0.10，可用
``scan.coverage.weights`` 覆盖；角色→适用域可用 ``scan.coverage.role_domains`` 覆盖。

资产口径：以台账 ``asset WHERE enabled=1`` 为分母（覆盖率回答的是"台账资产被覆盖了
多少"）；该快照所属 run 内没有任务的资产按 0 计并写入未覆盖清单，理由写明"本次运行
未包含该资产"。快照不存在/无任务时返回 coverage=0 + 全量未覆盖清单 + ``error``，不抛。
"""

from __future__ import annotations

import json
from typing import Any

from ..config import cfg_get
from ..log import get_logger
from ..schema import utc_now

log = get_logger("scan.coverage")

#: 六个检查域（顺序即报告列顺序）
DOMAINS: tuple[str, ...] = ("D1", "D2", "D3", "D4", "D5", "D6")

#: 检查域中文名（报告表头/未覆盖清单共用）
DOMAIN_NAMES: dict[str, str] = {
    "D1": "端口与服务",
    "D2": "系统补丁 CVE",
    "D3": "应用组件 CVE",
    "D4": "主机配置基线",
    "D5": "TLS 配置",
    "D6": "Web PoC",
}

#: 默认权重（合计 1.0；D2 最重，因为"无凭据"是最容易漏的盲区）
DEFAULT_WEIGHTS: dict[str, float] = {
    "D1": 0.15,
    "D2": 0.30,
    "D3": 0.20,
    "D4": 0.15,
    "D5": 0.10,
    "D6": 0.10,
}

#: 默认角色 → 适用域（未命中任何键的角色走 FALLBACK_DOMAINS）
DEFAULT_ROLE_DOMAINS: dict[str, tuple[str, ...]] = {
    "self": DOMAINS,
    "server": DOMAINS,
    "linux": DOMAINS,
    "web": ("D1", "D3", "D5", "D6"),
    "lab": ("D1", "D3", "D6"),
    "workstation": ("D1", "D3", "D5"),
    "windows": ("D1", "D3", "D5"),
    "network": ("D1",),
}

#: 其他角色（db / network / 空角色等）只保底做端口与组件两个域
FALLBACK_DOMAINS: tuple[str, ...] = ("D1", "D3")

#: 单格状态 → covered 值
_STATUS_COVERED: dict[str, float] = {"done": 1.0, "partial": 0.5}

#: 未覆盖理由兜底文案
_REASON_MISSING = "引擎未执行"
_REASON_NO_SNAPSHOT = "快照不存在，无法判定覆盖"
_REASON_NO_TASK = "本次运行未包含该资产"


def _json_obj(raw: Any) -> dict:
    """JSON 字符串 → dict；解析失败返回空 dict（checkpoint 损坏不能让覆盖率崩）。"""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _weights(cfg: dict | None) -> dict[str, float]:
    """取生效权重：默认值 + ``scan.coverage.weights``（非法值忽略、未知域忽略）。"""
    weights = dict(DEFAULT_WEIGHTS)
    raw = cfg_get(cfg, "scan.coverage.weights", None) if isinstance(cfg, dict) else None
    if isinstance(raw, dict):
        for key, value in raw.items():
            code = str(key).strip().upper()
            if code not in weights:
                continue
            try:
                weights[code] = max(0.0, float(value))
            except (TypeError, ValueError):
                continue
    return weights


def _role_domains(cfg: dict | None) -> dict[str, tuple[str, ...]]:
    """取生效"角色 → 适用域"映射（可被 ``scan.coverage.role_domains`` 覆盖/扩展）。"""
    mapping: dict[str, tuple[str, ...]] = {
        role: tuple(domains) for role, domains in DEFAULT_ROLE_DOMAINS.items()
    }
    raw = cfg_get(cfg, "scan.coverage.role_domains", None) if isinstance(cfg, dict) else None
    if isinstance(raw, dict):
        for role, domains in raw.items():
            name = str(role).strip().lower()
            if not name or not isinstance(domains, (list, tuple)):
                continue
            clean = tuple(str(item).strip().upper() for item in domains)
            valid = tuple(code for code in clean if code in DOMAINS)
            if valid:
                mapping[name] = valid
    return mapping


def domains_for(role: Any, mapping: dict[str, tuple[str, ...]] | None = None) -> tuple[str, ...]:
    """返回某资产角色适用的检查域（未识别的角色回退 D1+D3）。"""
    table = mapping if mapping is not None else DEFAULT_ROLE_DOMAINS
    key = str(role or "").strip().lower()
    if key in table:
        return tuple(table[key])
    return tuple(FALLBACK_DOMAINS)


def _enabled_assets(store: Any) -> list[dict]:
    """台账中启用的资产（覆盖率分母）；读取失败返回空列表。"""
    try:
        return store.query(
            "SELECT asset_id, ip, hostname, role, enabled, criticality"
            " FROM asset WHERE enabled=1 ORDER BY asset_id"
        ) or []
    except Exception as exc:  # noqa: BLE001 - 未建表/未初始化时按"无资产"处理
        log.warn("coverage 读取 asset 失败", error=str(exc))
        return []


def _tasks_of_run(store: Any, snapshot: dict | None, snapshot_id: str) -> dict[str, dict]:
    """取该快照所属 run 的任务，返回 ``{asset_id: task}``。

    优先按 ``run_id`` 取（一个 run 可能对应多台资产的多条 task），再用
    ``snapshot_id`` 兜底；同一资产多条 task 时优先"归属于本快照"的那条。
    """
    rows: list[dict] = []
    run_id = str((snapshot or {}).get("run_id") or "").strip()
    try:
        if run_id:
            rows.extend(
                store.query("SELECT * FROM scan_task WHERE run_id=?", (run_id,)) or []
            )
        rows.extend(
            store.query("SELECT * FROM scan_task WHERE snapshot_id=?", (snapshot_id,)) or []
        )
    except Exception as exc:  # noqa: BLE001
        log.warn("coverage 读取 scan_task 失败", snapshot=snapshot_id, error=str(exc))
    tasks: dict[str, dict] = {}
    for row in rows:
        asset_id = str(row.get("asset_id") or "")
        if not asset_id:
            continue
        current = tasks.get(asset_id)
        if current is None:
            tasks[asset_id] = row
            continue
        # 优先保留 snapshot_id 与本快照一致、或已有快照号的任务
        row_owned = str(row.get("snapshot_id") or "") == str(snapshot_id)
        cur_owned = str(current.get("snapshot_id") or "") == str(snapshot_id)
        if row_owned and not cur_owned:
            tasks[asset_id] = row
    return tasks


def _domain_cell(entry: Any) -> tuple[float, str]:
    """单个资产单个域的 ``(covered, status)``；缺失/异常按 0 + missing。"""
    if not isinstance(entry, dict):
        return 0.0, "missing"
    status = str(entry.get("status") or "").strip().lower()
    return _STATUS_COVERED.get(status, 0.0), status or "missing"


def _reason_of(entry: Any, status: str, task: dict | None) -> str:
    """未覆盖理由：优先 checkpoint 里记录的 reason，其次按状态给中文兜底。"""
    reason = ""
    if isinstance(entry, dict):
        raw = entry.get("reason")
        if raw not in (None, ""):
            reason = str(raw)
    if reason:
        return reason
    if task is None:
        return _REASON_NO_TASK
    if status == "partial":
        return "部分执行（结果可用但不完整）"
    if status == "skipped":
        return "引擎跳过"
    if status == "error":
        return "引擎执行失败"
    task_status = str(task.get("status") or "").strip().lower()
    if task_status in ("failed", "aborted", "queued", "running"):
        return f"任务未完成（{task_status}）"
    return _REASON_MISSING


def _empty_result(snapshot_id: str, ts: str) -> dict:
    """快照缺失时的全零骨架（保持字段齐全，前端/报告无需特判）。"""
    return {
        "snapshot_id": str(snapshot_id or ""),
        "ts": ts,
        "assets": 0,
        "coverage": 0.0,
        "by_domain": {code: _domain_bucket(code) for code in DOMAINS},
        "matrix": [],
        "uncovered": [],
        "weights": dict(DEFAULT_WEIGHTS),
    }


def _domain_bucket(code: str, weight: float | None = None) -> dict:
    """``by_domain`` 的单域骨架。"""
    return {
        "name": DOMAIN_NAMES.get(code, code),
        "weight": float(DEFAULT_WEIGHTS.get(code, 0.0) if weight is None else weight),
        "applicable": 0,
        "done": 0,
        "partial": 0,
        "missing": 0,
        "avg": 0.0,
    }


def compute(store: Any, snapshot_id: str, cfg: dict | None = None) -> dict:
    """计算某快照的加权覆盖率、资产×检查域矩阵与未覆盖清单。

    返回::

        {"snapshot_id","ts","assets":n,"coverage":0.0~1.0,
         "by_domain":{"D1":{"name","weight","applicable","done","partial","missing","avg"},...},
         "matrix":[{"asset_id","ip","hostname","role","domains":{"D1":1.0,...},
                    "score":0.0~1.0,"notes":{...},"status":任务状态}],
         "uncovered":[{"asset_id","domain","name","reason","status","covered","ip"}],
         "weights":{...}}   # 外加 plan_id/run_id/error 等辅助字段

    快照不存在/无任务：返回 coverage=0、全量未覆盖清单 + ``error``，不抛异常。
    """
    snapshot_id = str(snapshot_id or "").strip()
    weights = _weights(cfg)
    role_map = _role_domains(cfg)
    result = _empty_result(snapshot_id, utc_now())
    result["weights"] = dict(weights)

    snapshot: dict | None = None
    try:
        snapshot = store.query_one(
            "SELECT * FROM scan_snapshot WHERE snapshot_id=?", (snapshot_id,)
        )
    except Exception as exc:  # noqa: BLE001 - 表未建（还没跑过扫描）
        log.warn("coverage 读取 scan_snapshot 失败", snapshot=snapshot_id, error=str(exc))
    if snapshot:
        result["ts"] = snapshot.get("ts") or result["ts"]
        result["plan_id"] = snapshot.get("plan_id")
        result["run_id"] = snapshot.get("run_id")

    assets = _enabled_assets(store)
    result["assets"] = len(assets)
    if not snapshot:
        result["error"] = f"快照不存在：{snapshot_id}"
    tasks = _tasks_of_run(store, snapshot, snapshot_id) if snapshot else {}

    by_domain: dict[str, dict] = {code: _domain_bucket(code, weights.get(code)) for code in DOMAINS}
    matrix: list[dict] = []
    uncovered: list[dict] = []
    numerator = 0.0
    denominator = 0.0

    for asset in assets:
        asset_id = str(asset.get("asset_id") or "")
        ip = asset.get("ip")
        role = asset.get("role")
        applicable = domains_for(role, role_map)
        task = tasks.get(asset_id)
        checkpoint = _json_obj((task or {}).get("checkpoint"))
        domains_ckpt = checkpoint.get("domains")
        if not isinstance(domains_ckpt, dict):
            domains_ckpt = {}
        cells: dict[str, float] = {}
        notes: dict[str, str] = {}
        asset_num = 0.0
        asset_den = 0.0
        for code in applicable:
            weight = float(weights.get(code, 0.0))
            entry = domains_ckpt.get(code)
            if snapshot is None:
                covered, status = 0.0, "missing"
                reason = _REASON_NO_SNAPSHOT
            elif task is None:
                covered, status = 0.0, "missing"
                reason = _REASON_NO_TASK
            else:
                covered, status = _domain_cell(entry)
                reason = "" if covered >= 1.0 else _reason_of(entry, status, task)
            cells[code] = covered
            if reason:
                notes[code] = reason
            asset_num += weight * covered
            asset_den += weight
            bucket = by_domain[code]
            bucket["applicable"] += 1
            bucket["avg"] += covered
            if covered >= 1.0:
                bucket["done"] += 1
            elif covered > 0:
                bucket["partial"] += 1
            else:
                bucket["missing"] += 1
            if covered < 1.0:
                uncovered.append(
                    {
                        "asset_id": asset_id,
                        "ip": ip,
                        "domain": code,
                        "name": DOMAIN_NAMES.get(code, code),
                        "reason": reason or _REASON_MISSING,
                        "status": status,
                        "covered": covered,
                    }
                )
        score = (asset_num / asset_den) if asset_den > 0 else 0.0
        matrix.append(
            {
                "asset_id": asset_id,
                "ip": ip,
                "hostname": asset.get("hostname"),
                "role": role,
                "domains": cells,
                "score": round(score, 4),
                "notes": notes,
                "status": (task or {}).get("status"),
            }
        )
        numerator += asset_num
        denominator += asset_den

    for code, bucket in by_domain.items():
        applicable = int(bucket["applicable"])
        bucket["avg"] = round(bucket["avg"] / applicable, 4) if applicable else 0.0

    result["coverage"] = round(numerator / denominator, 4) if denominator > 0 else 0.0
    result["by_domain"] = by_domain
    result["matrix"] = matrix
    result["uncovered"] = uncovered
    if not assets and not snapshot:
        result["error"] = result.get("error") or "台账为空且快照不存在，无法计算覆盖率"
    log.info(
        "scan.coverage.computed",
        snapshot=snapshot_id,
        assets=len(assets),
        coverage=result["coverage"],
        uncovered=len(uncovered),
    )
    return result
