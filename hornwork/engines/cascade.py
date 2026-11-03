"""成本感知级联调度。

一次 `scan()` 的流程：
1. 取文件大小 / SHA-256；哈希缓存命中直接返回 `cached=True`（伪引擎 `hash`）；
2. 文件超过 `engines.max_size_mb` 时只算哈希，标记 `partial=True`；
3. 按 `engines.order` 排序依次调用引擎：
   - `available()` / `supports()` 不满足则跳过；
   - `cost=="slow"` 且 `deep=False` 跳过（clamd 只在深度扫描参与）；
   - 单引擎异常隔离，`engine_stat_add(errors=1)` 后继续；
   - 命中最高分 >= `engines.stop_score` 提前停止；
4. 汇总 `hits`、`engines_used`、`first_hit`（最高分且最早命中）、`verdict/score`；
5. 默认每次扫描都写一行 `scan_result`（可用 `engines.write_all_scans=false` 关闭）。

verdict：malicious(score>=80) / suspicious(>=50) / clean / error。
"""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Any

from ..config import cfg_get
from ..log import get_logger
from ..schema import sha256_file, utc_now
from .base import merge_hits, normalize_hit

log = get_logger("engines.cascade")

VERDICT_MALICIOUS = 80
VERDICT_SUSPICIOUS = 50
_CACHE_SCORES = {"malicious": 100, "suspicious": 60, "clean": 0, "error": 0}

_MAGIC_TYPES = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"#!", "script"),
    (b"\xca\xfe\xba\xbe", "macho"),
    (b"PK\x03\x04", "zip"),
)


def guess_filetype(path: str) -> str:
    """用文件头魔数 + 后缀猜 filetype（供 YARA externals 使用）。"""
    suffix = Path(str(path)).suffix.lstrip(".").lower()
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return suffix or "unknown"
    for magic, name in _MAGIC_TYPES:
        if head.startswith(magic):
            return name
    return suffix or "unknown"


class Cascade:
    """多引擎级联扫描器。"""

    def __init__(self, cfg: dict, engines: list, store: Any = None):
        self.cfg = dict(cfg or {})
        self.store = store
        self.engines: list = list(engines or [])
        order = cfg_get(self.cfg, "engines.order", ["hash", "sigdb", "yara", "clamav"])
        self.order: list[str] = [str(name) for name in (order or [])]
        self.stop_score = int(cfg_get(self.cfg, "engines.stop_score", 90) or 90)
        self.deep_default = bool(cfg_get(self.cfg, "engines.deep_default", False))
        max_size_mb = int(cfg_get(self.cfg, "engines.max_size_mb", 100) or 100)
        self.max_size = max(1, max_size_mb) * 1024 * 1024
        self.default_budget_ms = int(
            float(cfg_get(self.cfg, "scan.budget_sec", 60) or 60) * 1000
        )
        self.write_all_scans = bool(cfg_get(self.cfg, "engines.write_all_scans", True))
        self._ordered = self._sort_engines()

    # ------------------------------------------------------------ 引擎排序
    def _sort_engines(self) -> list:
        """按 engines.order 排序；未列出的引擎保持传入顺序排在其后。"""
        rank = {name: index for index, name in enumerate(self.order)}
        indexed = list(enumerate(self.engines))
        indexed.sort(key=lambda item: (rank.get(str(getattr(item[1], "name", "")), len(rank)),
                                       item[0]))
        return [engine for _idx, engine in indexed]

    # ------------------------------------------------------------ 统计/落库
    def _engine_stat(self, engine: str, *, files: int = 0, hits: int = 0,
                     malicious: int = 0, cost_ms: int = 0, errors: int = 0) -> None:
        if self.store is None:
            return
        try:
            self.store.engine_stat_add(engine, files=files, hits=hits,
                                       malicious=malicious, cost_ms=cost_ms, errors=errors)
        except Exception as exc:  # 统计失败不影响扫描
            log.warn("engine_stat 写入失败", engine=engine, err=str(exc))

    def _record(self, result: dict, started: float | None = None) -> None:
        """写 scan_result（每引擎统计已在扫描过程中累计）。"""
        if self.store is None:
            return
        if started is not None:
            result["cost_ms"] = int((time.monotonic() - started) * 1000)
        result["stat_written"] = True
        if not self.write_all_scans and not result.get("hits"):
            return
        rec = {
            "ts": result.get("ts") or utc_now(),
            "path": result.get("path"),
            "sha256": result.get("sha256"),
            "size": result.get("size"),
            "verdict": result.get("verdict"),
            "score": int(result.get("score") or 0),
            "hits": result.get("hits") or [],
            "first_hit": result.get("first_hit"),
            "cost_ms": int(result.get("cost_ms") or 0),
        }
        try:
            scan_id = self.store.insert_scan_result(rec)
            if scan_id:
                result["scan_id"] = scan_id
        except Exception as exc:
            log.warn("scan_result 写入失败", path=result.get("path"), err=str(exc))
        # 同步哈希缓存，保证下一次同哈希文件可直接走 cached 快路径
        sha = result.get("sha256")
        verdict = str(result.get("verdict") or "")
        if sha and verdict in ("malicious", "suspicious", "clean"):
            try:
                self.store.set_hash_cache(str(sha), verdict)
            except Exception as exc:
                log.warn("hash_cache 写入失败", sha=str(sha), err=str(exc))

    # ------------------------------------------------------------ 哈希缓存
    def _hash_cache_lookup(self, sha256: str) -> dict | None:
        """查询哈希缓存；命中返回 {verdict,score,hits,first_hit}。"""
        if self.store is None or not sha256:
            return None
        try:
            verdict = self.store.get_hash_cache(sha256)
        except Exception as exc:
            log.warn("hash_cache 查询失败", err=str(exc))
            return None
        if verdict not in ("malicious", "suspicious", "clean"):
            return None
        row: dict | None = None
        try:
            row = self.store.scan_by_sha(sha256)
        except Exception:
            row = None
        hits: list = []
        score = _CACHE_SCORES.get(verdict, 0)
        first_hit: str | None = "hash" if verdict == "malicious" else None
        if isinstance(row, dict):
            if isinstance(row.get("hits"), list):
                hits = row["hits"]
            try:
                score = int(row.get("score") or score)
            except (TypeError, ValueError):
                pass
            first_hit = row.get("first_hit") or first_hit
        return {"verdict": verdict, "score": score, "hits": hits, "first_hit": first_hit}

    # ------------------------------------------------------------ 主流程
    def scan(self, path: str, deep: bool = False, ctx: dict | None = None,
             budget_ms: int | None = None) -> dict:
        """扫描单个文件，返回契约约定的结果字典。"""
        started = time.monotonic()
        budget = self.default_budget_ms if budget_ms is None else max(0, int(budget_ms))
        deadline = started + budget / 1000.0
        path_str = str(path)
        base_ctx: dict = dict(ctx or {})
        base_ctx["path"] = path_str
        base_ctx["deep"] = bool(deep or base_ctx.get("deep") or self.deep_default)

        result: dict = {
            "path": path_str,
            "sha256": None,
            "size": None,
            "verdict": "error",
            "score": 0,
            "hits": [],
            "engines_used": [],
            "first_hit": None,
            "cost_ms": 0,
            "partial": False,
            "cached": False,
            "error": None,
            "ts": utc_now(),
            "engine_costs": {},
        }

        # 0) 文件检查
        try:
            st = os.stat(path_str)
            if not stat.S_ISREG(st.st_mode):
                return self._finish(result, started, error=f"不是普通文件: {path_str}")
            size = int(st.st_size)
        except OSError as exc:
            return self._finish(result, started, error=f"文件不可读: {exc}")
        result["size"] = size

        # 1) SHA-256 + 哈希缓存
        hash_started = time.monotonic()
        try:
            sha = sha256_file(path_str)
        except OSError as exc:
            return self._finish(result, started, error=f"计算哈希失败: {exc}")
        result["sha256"] = sha
        cached = self._hash_cache_lookup(sha)
        if cached is not None:
            cost_ms = int((time.monotonic() - hash_started) * 1000)
            result.update({
                "verdict": cached["verdict"],
                "score": int(cached["score"]),
                "hits": cached["hits"],
                "engines_used": ["hash"],
                "first_hit": cached["first_hit"],
                "cached": True,
                "engine_costs": {"hash": cost_ms},
            })
            self._engine_stat("hash", files=1, hits=len(cached["hits"]),
                              malicious=1 if cached["verdict"] == "malicious" else 0,
                              cost_ms=cost_ms)
            self._record(result, started)
            return self._finish(result, started)

        # 2) 超限文件只算哈希
        if size > self.max_size:
            cost_ms = int((time.monotonic() - hash_started) * 1000)
            result.update({
                "verdict": "clean", "score": 0, "partial": True,
                "engines_used": ["hash"], "engine_costs": {"hash": cost_ms},
                "error": f"文件超过 max_size（{size} > {self.max_size}），仅计算哈希",
            })
            self._engine_stat("hash", files=1, cost_ms=cost_ms)
            self._record(result, started)
            return self._finish(result, started)

        # 3) 级联
        base_ctx["size"] = size
        base_ctx["filetype"] = base_ctx.get("filetype") or guess_filetype(path_str)
        all_hits: list[dict] = []
        used: list[str] = []
        errors: list[str] = []
        engine_costs: dict[str, int] = {}
        best_score = -1
        best_engine: str | None = None
        partial = False

        for engine in self._ordered:
            name = str(getattr(engine, "name", "unknown"))
            if time.monotonic() > deadline:
                partial = True
                errors.append(f"扫描预算 {budget} ms 用尽")
                break
            engine_started = time.monotonic()
            try:
                if not engine.available():
                    continue
                if not engine.supports(base_ctx):
                    continue
                if str(getattr(engine, "cost", "fast")) == "slow" and not base_ctx["deep"]:
                    continue
                raw_hits = engine.scan(path_str, base_ctx) or []
            except Exception as exc:  # 单引擎失败隔离
                cost_ms = int((time.monotonic() - engine_started) * 1000)
                engine_costs[name] = cost_ms
                errors.append(f"{name}: {exc}")
                self._engine_stat(name, files=1, cost_ms=cost_ms, errors=1)
                log.warn("引擎扫描失败", engine=name, path=path_str, err=str(exc))
                continue

            cost_ms = int((time.monotonic() - engine_started) * 1000)
            engine_costs[name] = cost_ms
            hits = [normalize_hit(hit, name) for hit in raw_hits]
            used.append(name)
            all_hits.extend(hits)
            max_hit = max((int(hit.get("score") or 0) for hit in hits), default=0)
            self._engine_stat(name, files=1, hits=len(hits),
                              malicious=1 if max_hit >= VERDICT_MALICIOUS else 0,
                              cost_ms=cost_ms)
            for hit in hits:
                score = int(hit.get("score") or 0)
                if score > best_score:  # 严格大于 → 同分保留最早命中的引擎
                    best_score = score
                    best_engine = name
            if max_hit >= self.stop_score:
                break

        merged = merge_hits(all_hits)
        score = max((int(h.get("score") or 0) for h in merged), default=0)
        if score >= VERDICT_MALICIOUS:
            verdict = "malicious"
        elif score >= VERDICT_SUSPICIOUS:
            verdict = "suspicious"
        else:
            verdict = "clean"
        if not used and errors:  # 所有引擎都不可用/失败
            verdict = "error"

        result.update({
            "verdict": verdict,
            "score": score,
            "hits": merged,
            "engines_used": used,
            "first_hit": best_engine if score >= VERDICT_SUSPICIOUS else None,
            "partial": partial,
            "error": "; ".join(errors) if errors else None,
            "engine_costs": engine_costs,
        })
        self._record(result, started)
        return self._finish(result, started)

    # ------------------------------------------------------------ 收尾
    @staticmethod
    def _finish(result: dict, started: float, error: str | None = None) -> dict:
        """补齐 cost_ms / error 并返回（保证所有 key 都存在）。"""
        if error is not None:
            result["error"] = error
            if result.get("verdict") != "error":
                result["verdict"] = "error"
        result["cost_ms"] = int((time.monotonic() - started) * 1000)
        result.setdefault("engine_costs", {})
        result.setdefault("stat_written", False)
        return result
