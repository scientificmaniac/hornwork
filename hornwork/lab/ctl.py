"""labctl 靶场编排器（靶场编排层，IF-17 的编排端）。

对外只暴露 `LabCtl`：索引、环境清单、up/down/status/logs/isolate、TTL 清理、
统计。所有 Docker/SSH 交互都委托给 `lab.runner.CommandRunner`（可注入替身），
本类只做守卫、状态机、端口规划、事件/审计投递与落库。

`up` 守卫顺序::

    TTL 清理 → 查索引 → 是否已运行 → 快照标记(force 跳过)
    → 资源闸门(并发/内存/磁盘) → 端口分配(port_range, 避开 ss 已占用)
    → 生成 patched compose 副本 → 写 lab_env(启动中) → compose pull(重试 1)
    → compose up -d(重试 1) → 健康检查(轮询 TCP)
    → set_env_running(True) → lab_run(ok) → event_sink + audit_sink

失败路径：lab_run(error/timeout, detail=原因+日志尾) → 若已 up 则 down -v →
状态置 error → 返回 ok=False。事件经注入的 event_sink 发出，绝不直接 import daemon。
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .. import schema
from ..config import cfg_get, cfg_path
from ..log import get_logger
from . import compose as complib
from . import guard
from . import ports as portlib
from . import store as labstore
from .index import build_index, load_index
from .runner import CommandRunner

log = get_logger("lab.ctl")

RUN_RESULTS = ("ok", "error", "timeout", "auto_cleanup")


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def _norm_ports(ports: dict | None) -> dict[int, int]:
    out: dict[int, int] = {}
    for key, val in (ports or {}).items():
        try:
            out[int(key)] = int(val)
        except (TypeError, ValueError):
            continue
    return out


def _parse_iso(text: Any) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _iso_after_minutes(minutes: int) -> str:
    moment = datetime.now(timezone.utc) + timedelta(minutes=max(0, int(minutes)))
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _ttl_left(expires_at: Any) -> int | None:
    moment = _parse_iso(expires_at)
    if moment is None:
        return None
    return max(0, int((moment - datetime.now(timezone.utc)).total_seconds()))


def _is_due(expires_at: Any, now_iso: Any) -> bool:
    moment = _parse_iso(expires_at)
    now = _parse_iso(now_iso)
    return bool(moment and now and moment <= now)


def _age_sec(ts: Any) -> float | None:
    moment = _parse_iso(ts)
    if moment is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - moment).total_seconds())


class LabCtl:
    """Vulhub 靶场编排器。"""

    def __init__(self, cfg: dict, store, event_sink=None, audit_sink=None):
        self.cfg = cfg or {}
        self.store = store
        self.event_sink = event_sink
        self.audit_sink = audit_sink
        self.runner = CommandRunner(self.cfg)
        self._lock = threading.RLock()
        self._entries_cache: list[dict] | None = None
        self.index_path = cfg_path(self.cfg, "lab.index_path", "/opt/hornwork/data/vulhub-index.json")
        self.state_path = cfg_path(self.cfg, "lab.state_file", "/opt/lab/state.json")
        self.overrides_dir = cfg_path(self.cfg, "lab.overrides_dir", "/opt/lab/overrides")
        self.host_bind = str(cfg_get(self.cfg, "lab.host_bind", "127.0.0.1") or "127.0.0.1")
        try:
            labstore.init_schema(store)
        except Exception as exc:  # noqa: BLE001 - 建表失败要显式暴露给调用方
            log.error("lab 表初始化失败", error=str(exc))
            raise

    # ==================================================================
    # 索引
    # ==================================================================
    def index(self, force: bool = False) -> dict:
        """构建/加载 Vulhub 索引，并同步到 lab_env 表。"""
        started = time.monotonic()
        index_path = Path(str(self.index_path))
        if not force and index_path.is_file():
            entries = load_index(str(index_path))
            self._entries_cache = entries
            errors = self._sync_envs(entries)
            return {
                "ok": True,
                "count": len(entries),
                "path": str(index_path),
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "errors": errors,
            }
        root = str(cfg_path(self.cfg, "lab.vulhub_root", "/opt/vulhub"))
        res = build_index(root, str(index_path))
        entries = load_index(str(index_path))
        self._entries_cache = entries
        errors = list(res.get("errors") or []) + self._sync_envs(entries)
        return {
            "ok": bool(res.get("ok")),
            "count": int(res.get("count", len(entries)) or len(entries)),
            "path": str(index_path),
            "elapsed_ms": int(res.get("elapsed_ms") or (time.monotonic() - started) * 1000),
            "errors": errors,
        }

    def _entries(self) -> list[dict]:
        if self._entries_cache is None:
            self._entries_cache = load_index(str(self.index_path))
        return self._entries_cache

    def _find_entry(self, env_id: str) -> dict | None:
        for entry in self._entries():
            if str(entry.get("env_id")) == str(env_id):
                return entry
        return None

    def _sync_envs(self, entries: list[dict]) -> list[str]:
        errors: list[str] = []
        for entry in entries:
            try:
                labstore.upsert_env(self.store, entry)
            except Exception as exc:  # noqa: BLE001 - 单条失败不阻断索引
                errors.append(f"{entry.get('env_id')}: 同步 lab_env 失败: {exc}")
        return errors

    # ==================================================================
    # 清单
    # ==================================================================
    def list(self, type: str | None = None, status: str | None = None, limit: int = 100) -> list[dict]:
        """环境清单：索引字段 + 运行态；--type 按 category/CVE 过滤，--status 按状态过滤。"""
        entries = list(self._entries())
        rows = {str(row.get("env_id")): row for row in labstore.list_envs(self.store)}
        seen: set[str] = set()
        items: list[dict] = []
        for entry in entries:
            env_id = str(entry.get("env_id") or "")
            if not env_id or env_id in seen:
                continue
            seen.add(env_id)
            item = self._list_item(entry, rows.get(env_id))
            if self._match_filters(item, type, status):
                items.append(item)
        for env_id, row in rows.items():
            if env_id in seen:
                continue
            item = self._list_item({"env_id": env_id}, row)
            if self._match_filters(item, type, status):
                items.append(item)
        items.sort(key=lambda item: item.get("env_id") or "")
        try:
            cap = max(0, int(limit))
        except (TypeError, ValueError):
            cap = 100
        return items[:cap]

    @staticmethod
    def _list_item(entry: dict, row: dict | None) -> dict:
        row = row or {}
        return {
            "env_id": str(entry.get("env_id") or row.get("env_id") or ""),
            "category": row.get("category") or entry.get("category"),
            "dir": entry.get("dir"),
            "cve": row.get("cve") or entry.get("cve"),
            "compose_path": row.get("compose_path") or entry.get("compose_path"),
            "services": entry.get("services") or [],
            "images": row.get("images") or entry.get("images") or [],
            "summary": row.get("summary") or entry.get("summary") or "",
            "readme_path": entry.get("readme_path"),
            "state": row.get("state") or "down",
            "running": bool(row.get("running")),
            "ports": row.get("ports") or {},
            "expires_at": row.get("expires_at"),
            "updated_at": row.get("updated_at"),
        }

    @staticmethod
    def _match_filters(item: dict, type: str | None, status: str | None) -> bool:
        if type:
            wanted = str(type).strip()
            env_id = str(item.get("env_id") or "")
            if wanted and not (
                wanted == item.get("category")
                or wanted == item.get("cve")
                or wanted == env_id
                or env_id.startswith(wanted + "/")
            ):
                return False
        if status:
            wanted = str(status).strip().lower()
            running = bool(item.get("running"))
            state = str(item.get("state") or "down").lower()
            if wanted in ("running", "up"):
                return running
            if wanted in ("down", "stopped"):
                return not running
            return state == wanted
        return True

    # ==================================================================
    # up
    # ==================================================================
    def up(self, env_id: str, ttl_min: int | None = None, force: bool = False) -> dict:
        """启动一个 Vulhub 环境，返回 {ok,env_id,ports,containers,elapsed_ms,run_id}。"""
        with self._lock:
            started = time.monotonic()
            run = self._new_run(env_id, "up")
            env_id = str(env_id or "")

            # 1) TTL 清理：先回收过期环境，避免占满并发
            try:
                self.cleanup_expired()
            except Exception as exc:  # noqa: BLE001 - 清理失败不阻断本次启动
                log.warn("TTL 清理异常", error=str(exc))

            # 2) 查索引
            entry = self._find_entry(env_id)
            if entry is None and not Path(str(self.index_path)).is_file():
                self.index()
                entry = self._find_entry(env_id)
            if entry is None:
                return self._fail(
                    run, "env_not_found",
                    f"索引中不存在环境 {env_id!r}；请先执行 `lab index`（或检查 env_id 拼写）",
                    started,
                )
            try:
                labstore.upsert_env(self.store, entry)
            except Exception as exc:  # noqa: BLE001
                return self._fail(run, "db_error", f"写入 lab_env 失败: {exc}", started)

            # 3) 是否已运行
            env = labstore.get_env(self.store, env_id) or {}
            if env.get("running"):
                return self._fail(
                    run, "already_running",
                    "环境已在运行，拒绝重复启动；如需重启请先 `lab down`",
                    started, ports=env.get("ports"),
                )

            # 4) 快照标记（force 跳过）
            reasons = guard.snapshot_guard(self.cfg, bool(force))
            if reasons:
                return self._fail(run, "snapshot_missing", "；".join(reasons), started)

            # 5) 资源闸门
            reasons = guard.check_resources(self.cfg, labstore.count_running(self.store))
            if reasons:
                return self._fail(run, "resource_denied", "；".join(reasons), started)

            # 绑定地址必须在白名单内（后续端口探测只对白名单地址发起）
            bind = self._safe_bind()
            if not guard.check_targets(self.cfg, bind):
                return self._fail(
                    run, "target_not_allowed",
                    f"绑定/探测地址 {bind} 不在 [lab].target_whitelist 内",
                    started,
                )

            # 6) 端口分配（区间 + 避开 ss 已占用 + 其它环境已占端口）
            try:
                port_map, port_err = self._plan_ports(entry)
            except Exception as exc:  # noqa: BLE001
                return self._fail(run, "port_alloc_failed", f"端口规划异常: {exc}", started)
            if port_err:
                return self._fail(run, "port_conflict", port_err, started)

            try:
                ttl = int(
                    ttl_min if ttl_min is not None
                    else cfg_get(self.cfg, "lab.default_ttl_min", 90) or 90
                )
            except (TypeError, ValueError):
                ttl = 90
            expires_at = _iso_after_minutes(ttl) if ttl > 0 else None

            # 7) 生成 patched compose 副本（只写 overrides_dir）
            override = self._override_path(env_id)
            try:
                complib.render_patched_compose(entry, str(override), bind, port_map)
            except Exception as exc:  # noqa: BLE001
                return self._fail(run, "render_failed", f"生成覆盖文件失败: {exc}", started)

            # 7.1) ssh 双机模式：覆盖副本生成在 防护主机，需 scp 下发到 靶场主机 overrides_dir
            if getattr(self.runner, "remote", False):
                push = getattr(self.runner, "push_file", None)
                if push is None:
                    return self._fail(
                        run, "upload_failed",
                        "ssh 后端缺少 push_file 能力，无法把覆盖副本下发到 靶场主机", started,
                    )
                pushed = push(str(override))
                if not pushed.ok:
                    return self._fail(
                        run, "upload_failed",
                        f"覆盖副本下发失败 rc={pushed.rc}：{pushed.tail(10)}", started,
                        ports=port_map,
                    )

            # 8) 写 lab_env(启动中) + 状态文件
            try:
                labstore.set_env_state(self.store, env_id, "starting", host_ports=port_map)
            except Exception as exc:  # noqa: BLE001
                return self._fail(run, "db_error", f"更新启动状态失败: {exc}", started)
            self._state_set(env_id, "starting", ports=port_map, override=str(override),
                            expires_at=expires_at)

            # 9) compose pull（超时 600s，失败重试 1 次）
            pull_timeout = int(cfg_get(self.cfg, "lab.pull_timeout_sec", 600) or 600)
            pull = self._compose_retry(str(override), ("pull",), pull_timeout, retries=1)
            if not pull.ok:
                detail = f"compose pull 失败 rc={pull.rc}：{pull.tail(20)}"
                self._cleanup(env_id, str(override))
                return self._fail(
                    run, "pull_failed", detail, started, ports=port_map,
                    result="timeout" if pull.rc == 124 else "error",
                )

            # 10) compose up -d（超时 180s，失败重试 1 次）
            up_timeout = int(cfg_get(self.cfg, "lab.up_timeout_sec", 180) or 180)
            up_res = self._compose_retry(
                str(override), ("up", "-d", "--remove-orphans"), up_timeout, retries=1
            )
            if not up_res.ok:
                tail = self._logs_tail(str(override))
                self._cleanup(env_id, str(override))
                return self._fail(
                    run, "up_failed",
                    f"compose up 失败 rc={up_res.rc}：{up_res.tail(20)}；日志尾部：\n{tail}",
                    started, ports=port_map,
                    result="timeout" if up_res.rc == 124 else "error",
                )

            # 11) 健康检查（轮询 TCP host:port；UDP 端口无法 TCP 探测，跳过）
            health = self._wait_healthy(self._probe_ports(entry, port_map))
            if not health.get("ok"):
                tail = self._logs_tail(str(override))
                self._cleanup(env_id, str(override))
                return self._fail(
                    run, "health_timeout",
                    f"健康检查失败（{health.get('reason')}）；日志尾部：\n{tail}",
                    started, ports=port_map, result="timeout",
                )

            # 12) 成功：落运行态 + lab_run + 事件/审计
            try:
                labstore.set_env_running(self.store, env_id, True, port_map, expires_at)
            except Exception as exc:  # noqa: BLE001
                self._cleanup(env_id, str(override))
                return self._fail(run, "db_error", f"写入运行态失败: {exc}", started)
            self._state_set(env_id, "healthy", ports=port_map, override=str(override),
                            expires_at=expires_at)
            ps_timeout = int(cfg_get(self.cfg, "lab.ps_timeout_sec", 60) or 60)
            containers = complib.compose_ps(self.runner, str(override), timeout=ps_timeout)
            elapsed = self._elapsed_ms(started)
            detail = f"启动成功 ports={port_map} expires_at={expires_at}"
            if health.get("reason"):
                detail += f"；{health['reason']}"
            self._finish_run(run, "ok", detail, elapsed, ports=port_map, cleanup_ok=1)
            self._emit("up", env_id, "ok", elapsed, port_map, run["run_id"], ok=True)
            log.info("lab up 成功", env_id=env_id, ports=port_map, elapsed_ms=elapsed)
            return {
                "ok": True,
                "env_id": env_id,
                "ports": port_map,
                "containers": containers,
                "elapsed_ms": elapsed,
                "run_id": run["run_id"],
                "expires_at": expires_at,
                "override": str(override),
            }

    # ==================================================================
    # down / isolate
    # ==================================================================
    def down(self, env_id: str, keep_volume: bool = False) -> dict:
        """停止环境并释放端口；keep_volume=True 时保留数据卷。"""
        return self._down(env_id, keep_volume=keep_volume, action="down", ok_result="ok")

    def _down(self, env_id: str, *, keep_volume: bool = False, action: str = "down",
              ok_result: str = "ok") -> dict:
        with self._lock:
            started = time.monotonic()
            env_id = str(env_id or "")
            run = self._new_run(env_id, action)
            env = labstore.get_env(self.store, env_id)
            if env is None:
                entry = self._find_entry(env_id)
                if entry is None:
                    return self._fail(run, "env_not_found", f"未知环境 {env_id!r}", started,
                                      action=action)
                labstore.upsert_env(self.store, entry)
                env = labstore.get_env(self.store, env_id) or {}

            ports = dict(env.get("ports") or {})
            freed = sorted({int(v) for v in ports.values()})
            compose_path = self._compose_for(env_id, env)
            down_timeout = int(cfg_get(self.cfg, "lab.down_timeout_sec", 180) or 180)

            if compose_path is None:
                labstore.set_env_running(self.store, env_id, False, {}, None)
                self._state_set(env_id, "down", ports={})
                elapsed = self._elapsed_ms(started)
                detail = "未找到 compose 文件（覆盖副本与原文件都不存在），仅清理数据库运行态"
                self._finish_run(run, ok_result, detail, elapsed, cleanup_ok=1)
                self._emit(action, env_id, ok_result, elapsed, None, run["run_id"], ok=True)
                return {
                    "ok": True, "env_id": env_id, "elapsed_ms": elapsed,
                    "run_id": run["run_id"], "freed_ports": freed,
                    "cleanup_ok": True, "rc": 0, "detail": detail,
                }

            res = complib.compose_down(
                self.runner, str(compose_path), keep_volume=keep_volume, timeout=down_timeout
            )
            bind = self._safe_bind()
            released = True
            # 端口释放复核同样只对白名单地址发起探测
            if freed and guard.check_targets(self.cfg, bind):
                released = all(portlib.port_free(bind, port) for port in freed)
            elif freed:
                log.warn("绑定地址不在白名单，跳过端口释放复核", bind=bind)
            cleanup_ok = bool(res.ok and released)
            try:
                labstore.set_env_running(self.store, env_id, False, {}, None)
            except Exception as exc:  # noqa: BLE001
                log.warn("清理运行态失败", env_id=env_id, error=str(exc))
            self._state_set(env_id, "down" if res.ok else "error", ports={})
            elapsed = self._elapsed_ms(started)
            detail = f"compose down keep_volume={keep_volume} rc={res.rc}"
            if not res.ok:
                detail += f"；stderr：{res.tail(20)}"
            elif not released:
                detail += "；端口仍被占用，cleanup_ok=false"
            result = ok_result if res.ok else "error"
            self._finish_run(run, result, detail, elapsed, cleanup_ok=1 if cleanup_ok else 0)
            self._emit(action, env_id, result, elapsed, None, run["run_id"], ok=res.ok)
            log.info("lab down", env_id=env_id, keep_volume=keep_volume, rc=res.rc,
                     freed_ports=freed, cleanup_ok=cleanup_ok)
            return {
                "ok": bool(res.ok), "env_id": env_id, "elapsed_ms": elapsed,
                "run_id": run["run_id"], "freed_ports": freed,
                "cleanup_ok": cleanup_ok, "rc": res.rc, "detail": detail,
            }

    def isolate(self, env_id: str) -> dict:
        """隔离：down -v 释放端口，并在 Linux 上用 ufw 拒绝端口区间入站。"""
        down_res = self._down(env_id, keep_volume=False, action="isolate", ok_result="ok")
        notes: list[str] = []
        blocked: list[dict] = []
        ports = [int(p) for p in (down_res.get("freed_ports") or [])]
        if not sys.platform.startswith("linux"):
            notes.append("非 Linux 平台跳过 ufw 规则（端口已随 down 释放）")
        elif not ports:
            notes.append("环境没有对外绑定端口，无需 ufw 规则")
        else:
            # 隔离对象是整段分配区间（lab.port_range），不局限于本次用到的端口
            try:
                range_lo, range_hi = cfg_get(self.cfg, "lab.port_range", [min(ports), max(ports)])
                range_lo, range_hi = int(range_lo), int(range_hi)
            except (TypeError, ValueError):
                range_lo, range_hi = min(ports), max(ports)
            spec = f"{range_lo}:{range_hi}/tcp" if range_hi > range_lo else f"{range_lo}/tcp"
            res = self.runner.run(["ufw", "deny", spec], timeout=15)
            blocked.append(
                {"spec": spec, "ok": res.ok, "rc": res.rc,
                 "detail": (res.stderr or res.stdout or "").strip()[:200]}
            )
            if not res.ok:
                notes.append(f"ufw deny {spec} 失败（可能缺少 root）：{res.tail(3)}")
        return {
            "ok": bool(down_res.get("ok")),
            "env_id": env_id,
            "isolated": bool(down_res.get("ok")),
            "down": down_res,
            "ports_blocked": blocked,
            "notes": notes,
        }

    # ==================================================================
    # status / logs / 清理 / 统计
    # ==================================================================
    def status(self, env_id: str | None = None) -> dict:
        """单个环境状态，或全部环境状态 + running 数。"""
        if env_id is not None:
            return self._status_one(str(env_id), include_containers=True)
        envs = [
            self._status_one(str(row.get("env_id")), include_containers=False, row=row)
            for row in labstore.list_envs(self.store)
        ]
        running = sum(1 for item in envs if item.get("running"))
        state_counts: dict[str, int] = {}
        for item in envs:
            state = str(item.get("state") or "down")
            state_counts[state] = state_counts.get(state, 0) + 1
        return {
            "ok": True,
            "env_id": None,
            "running": running,
            "total": len(envs),
            "state_counts": state_counts,
            "envs": envs,
            "index": {
                "count": len(self._entries()),
                "path": str(self.index_path),
                "exists": Path(str(self.index_path)).is_file(),
            },
            "ts": schema.utc_now(),
        }

    def _status_one(self, env_id: str, *, include_containers: bool,
                    row: dict | None = None) -> dict:
        env = row if row is not None else labstore.get_env(self.store, env_id)
        entry = self._find_entry(env_id)
        if env is None and entry is None:
            return {
                "ok": False, "env_id": env_id, "error": "env_not_found",
                "state": "down", "running": False, "ports": {},
                "containers": [], "expires_at": None, "ttl_left_sec": None,
            }
        env = env or {}
        ports = _norm_ports(env.get("ports"))
        running = bool(env.get("running"))
        override = self._override_path(env_id)
        containers: list[dict] = []
        if include_containers and override.is_file():
            ps_timeout = int(cfg_get(self.cfg, "lab.ps_timeout_sec", 60) or 60)
            containers = complib.compose_ps(self.runner, str(override), timeout=ps_timeout)
        state = self._live_state(
            running, self._probe_ports(entry, ports), env.get("state"), env.get("updated_at")
        )
        expires_at = env.get("expires_at")
        return {
            "ok": True,
            "env_id": env_id,
            "state": state,
            "running": running,
            "ports": ports,
            "containers": containers,
            "expires_at": expires_at,
            "ttl_left_sec": _ttl_left(expires_at),
            "category": env.get("category") or (entry or {}).get("category"),
            "cve": env.get("cve") or (entry or {}).get("cve"),
            "summary": env.get("summary") or (entry or {}).get("summary"),
            "compose_path": env.get("compose_path") or (entry or {}).get("compose_path"),
            "override": str(override) if override.is_file() else None,
        }

    def _live_state(self, running: bool, ports: dict[int, int],
                    db_state: str | None, updated_at: str | None) -> str:
        """结合 DB 状态与端口探测给出状态机的当前取值。"""
        if not running:
            state = str(db_state or "down")
            return state if state in ("error", "stopped") else "down"
        if not ports:
            return "healthy"
        bind = self._safe_bind()
        if not guard.check_targets(self.cfg, bind):
            # 白名单外地址不做探测，避免越界；按 DB 状态保守返回
            return "healthy" if str(db_state or "") in ("", "healthy") else str(db_state)
        if any(not portlib.port_free(bind, int(port)) for port in ports.values()):
            return "healthy"
        if str(db_state or "") == "starting":
            age = _age_sec(updated_at)
            limit = int(cfg_get(self.cfg, "lab.healthy_timeout_sec", 120) or 120)
            if age is not None and age < limit:
                return "starting"
        return "error"

    def logs(self, env_id: str, tail: int = 100) -> dict:
        """返回容器日志（≤64 KB）；不探测网络。"""
        env = labstore.get_env(self.store, env_id)
        compose_path = self._compose_for(env_id, env)
        if compose_path is None:
            return {
                "ok": False, "env_id": env_id, "error": "compose_not_found",
                "logs": "", "tail": int(tail), "truncated": False,
            }
        log_timeout = int(cfg_get(self.cfg, "lab.logs_timeout_sec", 60) or 60)
        text = complib.compose_logs(
            self.runner, str(compose_path), tail=int(tail), timeout=log_timeout
        )
        return {
            "ok": True,
            "env_id": env_id,
            "tail": int(tail),
            "logs": text,
            "truncated": complib.TRUNCATE_MARK in text,
        }

    def cleanup_expired(self) -> dict:
        """TTL 到点自动 down（读 state_file + DB 双保险），并记 lab_run=auto_cleanup。"""
        now_iso = schema.utc_now()
        candidates: dict[str, str] = {}
        state = self._load_state()
        for env_id, item in (state.get("envs") or {}).items():
            if not isinstance(item, dict):
                continue
            expires_at = item.get("expires_at")
            if (
                expires_at
                and _is_due(expires_at, now_iso)
                and item.get("state") in ("healthy", "starting", "error")
            ):
                candidates[str(env_id)] = "state_file"
        for row in labstore.expired_envs(self.store, now_iso):
            candidates.setdefault(str(row.get("env_id")), "db")

        cleaned: list[dict] = []
        for env_id in sorted(candidates):
            try:
                res = self._down(
                    env_id, keep_volume=False, action="cleanup", ok_result="auto_cleanup"
                )
                cleaned.append({
                    "env_id": env_id,
                    "ok": bool(res.get("ok")),
                    "run_id": res.get("run_id"),
                    "source": candidates[env_id],
                })
            except Exception as exc:  # noqa: BLE001 - 单个失败不阻断其它清理
                log.error("TTL 清理失败", env_id=env_id, error=str(exc))
                cleaned.append({
                    "env_id": env_id, "ok": False, "error": str(exc),
                    "source": candidates[env_id],
                })
        if candidates:
            log.info("TTL 清理完成", checked=len(candidates),
                     cleaned=sum(1 for item in cleaned if item.get("ok")))
        return {
            "ok": True,
            "checked": len(candidates),
            "count": sum(1 for item in cleaned if item.get("ok")),
            "cleaned": cleaned,
            "ts": schema.utc_now(),
        }

    def stats(self) -> dict:
        """运行数、lab_run 汇总与最近动作。"""
        rows = labstore.list_envs(self.store)
        state_counts: dict[str, int] = {}
        for row in rows:
            state = str(row.get("state") or "down")
            state_counts[state] = state_counts.get(state, 0) + 1
        summary = labstore.run_summary(self.store)
        return {
            "ok": True,
            "running": labstore.count_running(self.store),
            "total_envs": len(rows),
            "state_counts": state_counts,
            "index_count": len(self._entries()),
            "index_path": str(self.index_path),
            "runs": summary,
            "recent": labstore.recent_runs(self.store, 10),
            "last_action": summary.get("last"),
            "ts": schema.utc_now(),
        }

    # ==================================================================
    # 内部：端口 / compose 路径
    # ==================================================================
    def _safe_bind(self) -> str:
        return complib.safe_bind(self.host_bind)

    def _plan_ports(self, entry: dict) -> tuple[dict[int, int], str | None]:
        """从 port_range 分配宿主端口，避开 ss 监听端口与已占用环境端口。"""
        used: set[int] = set(portlib.listening_ports())
        for env in labstore.running_envs(self.store):
            used.update(int(val) for val in (env.get("ports") or {}).values())
        state = self._load_state()
        for item in (state.get("envs") or {}).values():
            if not isinstance(item, dict):
                continue
            if item.get("state") in ("healthy", "starting"):
                for val in (item.get("ports") or {}).values():
                    try:
                        used.add(int(val))
                    except (TypeError, ValueError):
                        continue
        containers: list[int] = []
        for svc in entry.get("services") or []:
            if not isinstance(svc, dict):
                continue
            for item in svc.get("ports") or []:
                if not isinstance(item, dict):
                    continue
                try:
                    cport = int(item.get("container"))
                except (TypeError, ValueError):
                    continue
                if cport not in containers:
                    containers.append(cport)
        if not containers:
            return {}, None
        try:
            lo, hi = cfg_get(self.cfg, "lab.port_range", [18000, 18999])
            lo, hi = int(lo), int(hi)
        except (TypeError, ValueError):
            lo, hi = 18000, 18999
        return portlib.allocate_ports(containers, used, lo, hi)

    def _probe_ports(self, entry: dict | None, port_map: dict[int, int]) -> dict[int, int]:
        """过滤掉 UDP 端口：健康检查/状态探测只能对 TCP 端口发起。"""
        mapping = _norm_ports(port_map)
        original = str((entry or {}).get("compose_path") or "")
        if not original:
            return mapping
        try:
            compose = complib.load_compose(original)
        except (ValueError, OSError):
            return mapping
        udp_ports = {
            int(item["container"])
            for item in portlib.compose_ports(compose)
            if str(item.get("protocol") or "tcp") == "udp"
        }
        if not udp_ports:
            return mapping
        return {container: host for container, host in mapping.items() if container not in udp_ports}

    def _override_path(self, env_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(env_id or "")).strip("_") or "env"
        return Path(str(self.overrides_dir)) / (safe + ".yml")

    def _compose_for(self, env_id: str, env: dict | None) -> Path | None:
        """定位该环境当前可用的 compose 文件：覆盖副本 → 状态文件 → 原文件。"""
        override = self._override_path(env_id)
        if override.is_file():
            return override
        state = self._load_state()
        saved = (state.get("envs") or {}).get(str(env_id)) or {}
        saved_path = str(saved.get("override") or "") if isinstance(saved, dict) else ""
        if saved_path and Path(saved_path).is_file():
            return Path(saved_path)
        env = env or {}
        compose_path = str(env.get("compose_path") or "")
        if compose_path and Path(compose_path).is_file():
            return Path(compose_path)
        entry = self._find_entry(env_id) or {}
        original = str(entry.get("compose_path") or "")
        if original and Path(original).is_file():
            return Path(original)
        return None

    def _compose_retry(self, compose_path: str, args, timeout: int, retries: int = 0):
        result = None
        for attempt in range(max(0, int(retries)) + 1):
            result = self.runner.compose(str(compose_path), *args, timeout=int(timeout))
            if result.ok:
                return result
            if attempt < max(0, int(retries)):
                log.warn("compose 命令失败，准备重试", compose=compose_path,
                         args=list(args), rc=result.rc, attempt=attempt + 1)
        return result

    def _wait_healthy(self, port_map: dict[int, int]) -> dict:
        """轮询 TCP：全部发布端口可连接即健康；超时返回 ok=False。"""
        if not port_map:
            return {"ok": True, "reason": "compose 未声明发布端口，跳过 TCP 健康检查", "ready": []}
        timeout = int(cfg_get(self.cfg, "lab.healthy_timeout_sec", 120) or 120)
        try:
            poll = float(cfg_get(self.cfg, "lab.health_poll_sec", 2) or 2)
        except (TypeError, ValueError):
            poll = 2.0
        poll = max(0.1, poll)
        bind = self._safe_bind()
        begin = time.monotonic()
        deadline = begin + max(1.0, float(timeout))
        ready: list[int] = []
        while True:
            ready = [
                int(port) for port in port_map.values()
                if not portlib.port_free(bind, int(port))
            ]
            if len(ready) >= len(port_map):
                return {
                    "ok": True,
                    "ready": ready,
                    "waited_ms": int((time.monotonic() - begin) * 1000),
                }
            if time.monotonic() >= deadline:
                break
            time.sleep(poll)
        missing = sorted(set(int(p) for p in port_map.values()) - set(ready))
        return {
            "ok": False,
            "reason": f"等待 {timeout}s 后端口仍未就绪: {missing}",
            "ready": ready,
        }

    def _logs_tail(self, compose_path: str, lines: int = 200) -> str:
        try:
            text = complib.compose_logs(self.runner, compose_path, tail=lines, timeout=30)
        except Exception as exc:  # noqa: BLE001 - 日志失败只影响详情
            return f"<获取日志失败: {exc}>"
        return (text or "").strip()[-8000:]

    def _cleanup(self, env_id: str, compose_path: str) -> bool:
        """失败后清理：down -v + 运行态/状态置 error。返回 down 是否成功。"""
        try:
            down_timeout = int(cfg_get(self.cfg, "lab.down_timeout_sec", 180) or 180)
            res = complib.compose_down(
                self.runner, str(compose_path), keep_volume=False, timeout=down_timeout
            )
            ok = bool(res.ok)
            if not ok:
                log.warn("失败后清理 down 未成功", env_id=env_id, rc=res.rc)
        except Exception as exc:  # noqa: BLE001
            log.error("失败后清理异常", env_id=env_id, error=str(exc))
            ok = False
        try:
            labstore.set_env_running(self.store, env_id, False, {}, None)
            labstore.set_env_state(self.store, env_id, "error")
        except Exception as exc:  # noqa: BLE001
            log.warn("清理运行态失败", env_id=env_id, error=str(exc))
        self._state_set(env_id, "error", ports={})
        return ok

    # ==================================================================
    # 内部：lab_run / 事件 / 审计 / 状态文件
    # ==================================================================
    def _new_run(self, env_id: str, action: str) -> dict:
        return {
            "run_id": "lab-" + uuid.uuid4().hex[:12],
            "env_id": str(env_id or ""),
            "action": str(action or ""),
            "started_at": schema.utc_now(),
            "ended_at": None,
            "elapsed_ms": None,
            "result": "pending",
            "detail": "",
            "ports_bound": None,
            "cleanup_ok": 0,
        }

    def _finish_run(self, run: dict, result: str, detail: str, elapsed_ms: int,
                    ports: dict | None = None, cleanup_ok: int = 0) -> None:
        run.update(
            {
                "ended_at": schema.utc_now(),
                "result": str(result if result in RUN_RESULTS else "error"),
                "detail": str(detail or "")[:8000],
                "elapsed_ms": int(elapsed_ms),
                "ports_bound": {str(k): int(v) for k, v in (ports or {}).items()} or None,
                "cleanup_ok": 1 if cleanup_ok else 0,
            }
        )
        try:
            labstore.add_run(self.store, run)
        except Exception as exc:  # noqa: BLE001 - 落库失败不改变动作结论
            log.warn("lab_run 写入失败", error=str(exc), run_id=run.get("run_id"))

    def _fail(self, run: dict, error: str, detail: str, started: float,
              ports: dict | None = None, result: str = "error", action: str = "up") -> dict:
        """统一失败收尾：写 lab_run(error/timeout) + 事件 + 审计，返回 ok=False。"""
        elapsed = self._elapsed_ms(started)
        self._finish_run(run, result, detail, elapsed, ports=ports)
        self._emit(action, run.get("env_id"), result, elapsed, ports, run.get("run_id"), ok=False)
        log.warn("lab 动作失败", action=action, env_id=run.get("env_id"),
                 error=error, detail=str(detail)[:300])
        return {
            "ok": False,
            "env_id": run.get("env_id"),
            "error": error,
            "detail": str(detail),
            "ports": dict(ports or {}),
            "elapsed_ms": elapsed,
            "run_id": run.get("run_id"),
        }

    def _emit(self, action: str, env_id: str, result: str, elapsed_ms: int,
              ports: dict | None = None, run_id: str | None = None,
              ok: bool | None = None) -> None:
        """投递 lab_action 事件与审计；sink 缺失/异常都不影响动作结论。"""
        ports_norm = _norm_ports(ports)
        if self.event_sink is not None:
            try:
                ev = schema.new_event(
                    "lab_action", "host", "hornwork-lab", self.cfg,
                    raw={
                        "env_id": str(env_id or ""),
                        "action": str(action or ""),
                        "result": str(result or ""),
                        "elapsed_ms": int(elapsed_ms or 0),
                        "ports": {str(k): int(v) for k, v in ports_norm.items()},
                        "run_id": run_id,
                    },
                )
                errors = schema.validate_event(ev)
                if errors:
                    log.warn("lab_action 事件字段异常", errors=errors)
                self.event_sink(ev)
            except Exception as exc:  # noqa: BLE001
                log.warn("lab 事件投递失败", error=str(exc))
        if self.audit_sink is not None:
            ok_flag = bool(ok if ok is not None else str(result) in ("ok", "auto_cleanup"))
            try:
                self.audit_sink(
                    action="lab." + str(action or ""),
                    target=str(env_id or ""),
                    ok=ok_flag,
                )
            except Exception as exc:  # noqa: BLE001
                log.warn("lab 审计写入失败", error=str(exc))

    def _load_state(self) -> dict:
        path = Path(str(self.state_path))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            return {"version": 1, "updated_at": None, "envs": {}}
        if not isinstance(data, dict):
            return {"version": 1, "updated_at": None, "envs": {}}
        if not isinstance(data.get("envs"), dict):
            data["envs"] = {}
        data.setdefault("version", 1)
        return data

    def _save_state(self, data: dict) -> None:
        data["updated_at"] = schema.utc_now()
        path = Path(str(self.state_path))
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(str(tmp), str(path))
        except OSError as exc:
            log.warn("state_file 写入失败", path=str(path), error=str(exc))

    def _state_set(self, env_id: str, state: str, *, ports: dict | None = None,
                   override: str | None = None, expires_at: str | None = None) -> None:
        with self._lock:
            data = self._load_state()
            envs = data.setdefault("envs", {})
            key = str(env_id)
            item = envs.get(key)
            if not isinstance(item, dict):
                item = {}
            item["env_id"] = key
            item["state"] = str(state)
            if ports is not None:
                item["ports"] = {str(int(k)): int(v) for k, v in _norm_ports(ports).items()}
            if override is not None:
                item["override"] = str(override)
            if state in ("down", "stopped", "error"):
                item["expires_at"] = None
            elif expires_at is not None:
                item["expires_at"] = expires_at
            item["updated_at"] = schema.utc_now()
            envs[key] = item
            self._save_state(data)

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return int((time.monotonic() - started) * 1000)
