"""引擎贡献统计。

`Cascade` 在扫描过程中已按引擎累计 `engine_stat`（files/hits/malicious/cost_ms/errors）；
本模块提供一层薄封装：
- `record(scan_result)`：写哈希缓存（verdict != error），并补记引擎统计
  （若 Cascade 已写统计，则通过结果里的 `stat_written` 标记避免重复计数）；
- `top(days)`：按 first_hit 统计"谁先发现恶意样本"（委托 store.engine_contribution）；
- `engine_table(days)`：把按天明细聚合成引擎维度表格，供控制台"引擎贡献"页展示。
"""

from __future__ import annotations

from typing import Any

from ..log import get_logger

log = get_logger("engines.contribution")

_MALICIOUS_SCORE = 80


class ContributionTracker:
    """引擎贡献统计器（store 可为 None，此时 record/top/table 均为安全空操作）。"""

    def __init__(self, store: Any = None):
        self.store = store

    # ------------------------------------------------------------ 记录
    def record(self, scan_result: dict) -> None:
        """根据一次 Cascade 结果更新哈希缓存与按引擎统计。"""
        if self.store is None or not isinstance(scan_result, dict):
            return
        result = scan_result
        sha = result.get("sha256")
        verdict = str(result.get("verdict") or "error")
        if sha and verdict != "error":
            try:
                self.store.set_hash_cache(str(sha), verdict)
            except Exception as exc:
                log.warn("hash_cache 写入失败", sha=str(sha), err=str(exc))

        if result.get("stat_written"):
            return  # Cascade 已按引擎写过 engine_stat，避免重复计数
        per_engine: dict[str, dict[str, int]] = {}
        for hit in result.get("hits") or []:
            if not isinstance(hit, dict):
                continue
            name = str(hit.get("engine") or "unknown")
            slot = per_engine.setdefault(name, {"hits": 0, "max": 0})
            slot["hits"] += 1
            try:
                slot["max"] = max(slot["max"], int(hit.get("score") or 0))
            except (TypeError, ValueError):
                pass
        costs = result.get("engine_costs") or {}
        engines = list(result.get("engines_used") or per_engine.keys())
        for name in engines:
            slot = per_engine.get(name, {"hits": 0, "max": 0})
            try:
                cost_ms = int(costs.get(name) or 0)
            except (TypeError, ValueError):
                cost_ms = 0
            try:
                self.store.engine_stat_add(
                    name, files=1, hits=slot["hits"],
                    malicious=1 if slot["max"] >= _MALICIOUS_SCORE else 0,
                    cost_ms=cost_ms,
                )
            except Exception as exc:
                log.warn("engine_stat_add 失败", engine=name, err=str(exc))

    # ------------------------------------------------------------ 查询
    def top(self, days: int = 7) -> list[dict]:
        """按 first_hit 汇总恶意样本归属（含占比），按数量降序。"""
        if self.store is None:
            return []
        try:
            rows = self.store.engine_contribution(days=days) or []
        except Exception as exc:
            log.warn("engine_contribution 查询失败", err=str(exc))
            return []
        out: list[dict] = []
        total = sum(int(row.get("n") or 0) for row in rows) or 0
        for row in rows:
            count = int(row.get("n") or 0)
            out.append({
                "first_hit": row.get("first_hit") or "unknown",
                "count": count,
                "share": round(count * 100.0 / total, 1) if total else 0.0,
            })
        return out

    def engine_table(self, days: int = 7) -> list[dict]:
        """把按天 engine_stat 明细聚合成引擎维度表格。"""
        if self.store is None:
            return []
        try:
            rows = self.store.engine_stats(days=days) or []
        except Exception as exc:
            log.warn("engine_stats 查询失败", err=str(exc))
            return []
        merged: dict[str, dict] = {}
        for row in rows:
            name = str(row.get("engine") or "unknown")
            slot = merged.setdefault(name, {
                "engine": name, "files": 0, "hits": 0, "malicious": 0,
                "cost_ms": 0, "errors": 0,
            })
            for key in ("files", "hits", "malicious", "cost_ms", "errors"):
                try:
                    slot[key] += int(row.get(key) or 0)
                except (TypeError, ValueError):
                    continue
        table = list(merged.values())
        for slot in table:
            files = slot["files"] or 0
            slot["hit_rate"] = round(slot["hits"] * 100.0 / files, 2) if files else 0.0
            slot["malicious_rate"] = round(slot["malicious"] * 100.0 / files, 2) if files else 0.0
            slot["avg_cost_ms"] = round(slot["cost_ms"] / files, 2) if files else 0.0
        table.sort(key=lambda item: (-item["malicious"], -item["hits"], item["engine"]))
        return table
