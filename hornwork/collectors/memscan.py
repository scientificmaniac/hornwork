"""在线内存扫描：/proc/pid/maps 解析 + 可疑段读取 + 注入判定矩阵。



- `parse_maps_text()` / `parse_maps()` 解析 `start-end perms offset dev inode pathname`，
  合并连续同权限同路径的段；
- 对可疑段（匿名可执行、memfd、路径以 `[` 开头、exe 已删除仍运行）用 `os.pread`
  读 `/proc/pid/mem`，判定 ELF/PE 魔数并算 sha256；
- 注入判定矩阵（§4.4.3）：条件 A（内存侧） + 条件 B（10 s 内新连接 / 线程数 +5）
  → level 10 告警；仅 A 无 B 记为观察项不告警；
- `snapshot()` 写 `raw/mem/<host>-<ts>/`（maps.txt / hits.json / regions/*.bin）；
- `verify()` 复核快照文件的 sha256；`sweep()` 限时限量扫描全部可读进程；
- 非 root / 权限不足返回 `{"error": ...}`，不抛异常。
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from typing import Any

from .. import schema
from ..log import get_logger
from . import BaseCollector

log = get_logger("collector.memscan")

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MAX_SWEEP_PIDS = 300
SWEEP_BUDGET_SEC = 20.0
B_ACTION_WINDOW = 10.0
THREAD_JUMP = 5
#: 内核自身提供的可执行段，属正常
_CORE_BRACKETS = {"[vdso]", "[vsyscall]", "[vvar]", "[vvvar]", "[sigpage]"}


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _to_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# maps 解析
# ---------------------------------------------------------------------------
def parse_maps_text(text: str) -> list[dict]:
    """解析 `/proc/pid/maps` 文本，返回并合并连续段。

    元素字段：`{"start","end","perms","offset","dev","inode","pathname"}`。
    """
    regions: list[dict] = []
    for line in (text or "").splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 5:
            continue
        try:
            start_text, end_text = parts[0].split("-")
            start = int(start_text, 16)
            end = int(end_text, 16)
        except (ValueError, AttributeError):
            continue
        if end <= start:
            continue
        perms = parts[1]
        pathname = parts[5].strip() if len(parts) > 5 and parts[5].strip() else None
        region = {
            "start": start,
            "end": end,
            "perms": perms,
            "offset": parts[2],
            "dev": parts[3],
            "inode": _to_int(parts[4], 0),
            "pathname": pathname,
        }
        previous = regions[-1] if regions else None
        if (
            previous is not None
            and previous["end"] == start
            and previous["perms"] == perms
            and previous["pathname"] == pathname
            and previous["dev"] == region["dev"]
            and previous["inode"] == region["inode"]
        ):
            previous["end"] = end
            continue
        regions.append(region)
    return regions


def parse_maps(pid: int) -> list[dict]:
    """读取并解析 `/proc/<pid>/maps`；进程不存在/不可读时返回 []。"""
    if not _is_linux():
        return []
    try:
        with open(f"/proc/{int(pid)}/maps", "r", encoding="utf-8", errors="replace") as handle:
            return parse_maps_text(handle.read())
    except (OSError, ValueError):
        return []


def _read_maps_raw(pid: int) -> str | None:
    if not _is_linux():
        return None
    try:
        with open(f"/proc/{int(pid)}/maps", "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except (OSError, ValueError):
        return None


def _read_threads(pid: int) -> int | None:
    try:
        with open(f"/proc/{int(pid)}/status", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("Threads:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    try:
        return len(os.listdir(f"/proc/{int(pid)}/task"))
    except OSError:
        return None


def _readlink(path: str) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


class MemoryScanner(BaseCollector):
    """在线内存扫描器（按需扫描 + 可选周期 sweep）。"""

    name = "memscan"
    layer = "memory"
    source_product = "hornwork-memscan"

    def __init__(
        self,
        cfg: dict | None,
        store: Any = None,
        emit_alert: Any = None,
        emit_event: Any = None,
        **kw: Any,
    ) -> None:
        super().__init__(cfg, emit_event, store, emit_alert, **kw)
        self.max_region = int(self.conf("memory.max_region", 1024 * 1024))
        self.min_size = int(self.conf("memory.min_size", 4096))
        self.whitelist_paths = [str(p) for p in (self.conf("memory.whitelist_paths", []) or [])]
        self.interval = float(self.conf("memory.interval_sec", 0) or 0)
        self._conn_marks: dict[str, float] = {}
        self._thread_marks: dict[int, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def _init_stats(self) -> dict[str, Any]:
        return {
            "scans": 0,
            "pids": 0,
            "regions": 0,
            "hits": 0,
            "alerts": 0,
            "observed": 0,
            "sweeps": 0,
            "skipped": 0,
        }

    # ------------------------------------------------------------ 周期扫描
    def start(self) -> None:
        """interval_sec > 0 时启动后台 sweep 线程；否则只提供按需扫描。"""
        if self.interval <= 0:
            log.info("memscan 未启用周期扫描（memory.interval_sec=0）")
            return
        if not _is_linux():
            self.error("非 Linux 环境，memscan 周期扫描不启动")
            return
        super().start()

    def _run(self) -> None:
        log.info("memscan 周期扫描启动", interval=self.interval)
        while not self.stopping:
            started = time.monotonic()
            try:
                self.sweep()
            except Exception as exc:  # noqa: BLE001
                self.error("memscan sweep 失败", exc=repr(exc))
            elapsed = time.monotonic() - started
            self.sleep(max(1.0, self.interval - elapsed))

    # ------------------------------------------------------------ 判定辅助
    def _is_suspicious(self, region: dict, exe_deleted: bool = False) -> bool:
        perms = str(region.get("perms") or "")
        pathname = region.get("pathname") or ""
        if "x" not in perms:
            return False
        if pathname in _CORE_BRACKETS:
            return False
        if any(
            pathname == prefix or pathname.startswith(prefix.rstrip("/") + "/")
            for prefix in self.whitelist_paths
            if prefix
        ):
            return False
        if exe_deleted:
            return True
        if "memfd:" in pathname:
            return True
        if pathname == "" or pathname.startswith("["):
            return True
        return False

    @staticmethod
    def _region_kind(region: dict, exe_deleted: bool) -> str:
        pathname = region.get("pathname") or ""
        perms = str(region.get("perms") or "")
        if "memfd:" in pathname:
            return "memfd_exec"
        # 匿名可执行段是最强信号，优先于"exe 已删除"归类：
        # （exe 被删/临时文件被清后，目标进程的匿名 RWX 段仍应按 anon_rwx 计分）
        if pathname == "":
            return "anon_rwx" if "w" in perms else "anon_exec"
        if pathname.startswith("["):
            return "bracket_exec"
        if exe_deleted:
            return "exe_deleted"
        return "other_exec"

    def _behavior_side(self, pid: int) -> dict:
        """条件 B：10 s 内出现新连接，或线程数 +5。"""
        result: dict[str, Any] = {"new_connections": [], "threads_delta": 0}
        now = time.time()
        try:
            from .proc import read_connections, socket_inode_owners

            owners = socket_inode_owners()
            own_inodes = {
                str(inode) for inode, pids in owners.items() if int(pid) in pids
            }
            for conn in read_connections():
                inode = str(conn.get("inode") or "")
                if not inode or inode not in own_inodes:
                    continue
                key = f"{pid}|{inode}|{conn.get('remote_ip')}:{conn.get('remote_port')}"
                mark = self._conn_marks.get(key)
                if mark is not None and now - mark <= B_ACTION_WINDOW:
                    result["new_connections"].append(
                        {
                            "proto": conn.get("proto"),
                            "remote": f"{conn.get('remote_ip')}:{conn.get('remote_port')}",
                            "state": conn.get("state"),
                        }
                    )
                if mark is None:
                    self._conn_marks[key] = now
        except Exception as exc:  # noqa: BLE001 - 行为侧失败不影响内存判定
            log.debug("行为侧检查失败", pid=pid, exc=repr(exc))

        threads = _read_threads(pid)
        if threads is not None:
            previous = self._thread_marks.get(pid)
            if previous is not None:
                old_threads, old_ts = previous
                if now - old_ts <= B_ACTION_WINDOW and threads - old_threads >= THREAD_JUMP:
                    result["threads_delta"] = threads - old_threads
            self._thread_marks[pid] = (threads, now)
        return result

    # ------------------------------------------------------------ 核心扫描
    def _scan_pid_impl(self, pid: int, snapshot_dir: str | None = None) -> dict:
        result: dict[str, Any] = {
            "pid": int(pid),
            "regions": [],
            "hits": [],
            "verdict": "clean",
            "score": 0,
        }
        if not _is_linux():
            result["error"] = "memscan 仅支持 Linux"
            self.stat_add("skipped")
            return result
        if not os.path.isdir(f"/proc/{int(pid)}"):
            result["error"] = "进程不存在"
            self.stat_add("skipped")
            return result

        maps_text = _read_maps_raw(pid)
        if maps_text is None:
            result["error"] = "无法读取 /proc/pid/maps（权限不足或进程已退出）"
            self.stat_add("skipped")
            return result
        regions = parse_maps_text(maps_text)
        result["regions"] = regions
        self.stat_add("scans")
        self.stat_add("pids")
        self.stat_add("regions", len(regions))
        if not regions:
            return result

        exe = _readlink(f"/proc/{int(pid)}/exe") or ""
        exe_deleted = exe.endswith(" (deleted)")
        suspicious = [
            region
            for region in regions
            if self._is_suspicious(region, exe_deleted=exe_deleted)
            and (region["end"] - region["start"]) >= self.min_size
        ]
        if not suspicious:
            return result

        # 行为侧先采（线程数需要"上一次"的值，放到下面 mem 读取后即可）
        behavior = self._behavior_side(pid)
        has_b = bool(behavior["new_connections"]) or behavior["threads_delta"] >= THREAD_JUMP

        try:
            mem_fd = os.open(f"/proc/{int(pid)}/mem", os.O_RDONLY)
        except OSError as exc:
            result["error"] = f"无法打开 /proc/pid/mem：{exc}"
            self.stat_add("skipped")
            return result

        hits: list[dict] = []
        try:
            for region in suspicious:
                size = region["end"] - region["start"]
                read_len = int(min(size, self.max_region))
                try:
                    data = os.pread(mem_fd, read_len, region["start"])
                except OSError:
                    continue
                if not data:
                    continue
                kind = self._region_kind(region, exe_deleted)
                is_elf = data[:4] == ELF_MAGIC
                is_pe = data[:2] == PE_MAGIC
                hit = {
                    "pid": int(pid),
                    "start": region["start"],
                    "end": region["end"],
                    "perms": region["perms"],
                    "pathname": region["pathname"],
                    "kind": kind,
                    "elf": is_elf,
                    "pe": is_pe,
                    "sha256": schema.sha256_bytes(data),
                    "bytes": len(data),
                    "exe": exe or None,
                }
                hits.append(hit)
                if snapshot_dir:
                    self._write_region(snapshot_dir, hit, data)
        finally:
            try:
                os.close(mem_fd)
            except OSError:
                pass

        if not hits:
            return result
        score = self._score(hits, has_b)
        verdict = "observed"
        if has_b and score >= 70:
            verdict = "injected"
        elif has_b:
            verdict = "suspicious"
        result.update(
            {
                "hits": hits,
                "score": score,
                "verdict": verdict,
                "behavior": behavior,
                "exe_deleted": exe_deleted,
            }
        )
        timestamp = schema.utc_now()
        if snapshot_dir:
            result["snapshot_dir"] = snapshot_dir
            self._write_snapshot_files(snapshot_dir, maps_text, hits, result)
        if self.store is not None:
            try:
                self.store.insert_mem_hits(timestamp, hits)
            except Exception as exc:  # noqa: BLE001
                self.error("mem_hits 落库失败", pid=pid, exc=repr(exc))
            try:
                self.store.insert_mem_scan(
                    {
                        "ts": timestamp,
                        "pid": int(pid),
                        "snapshot_dir": snapshot_dir,
                        "verdict": verdict,
                        "hits": len(hits),
                        "score": score,
                        "regions": len(regions),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                self.error("mem_scan 落库失败", pid=pid, exc=repr(exc))

        self.stat_add("hits", len(hits))
        if verdict == "observed":
            self.stat_add("observed")
        try:
            self._emit_result(result, timestamp)
        except Exception as exc:  # noqa: BLE001
            self.error("内存扫描事件投递失败", pid=pid, exc=repr(exc))
        return result

    @staticmethod
    def _score(hits: list[dict], has_b: bool) -> int:
        score = 40
        if any(hit.get("kind") in ("anon_rwx", "memfd_exec") for hit in hits):
            score += 20
        if any(hit.get("elf") for hit in hits):
            score += 20
        if any(hit.get("pe") for hit in hits):
            score += 15
        if has_b:
            score += 20
        return max(0, min(100, score))

    # ------------------------------------------------------------ 对外 API
    def scan_pid(self, pid: int, snapshot: bool = False) -> dict:
        """扫描单个进程；`snapshot=True` 时同时落盘快照。"""
        try:
            snapshot_dir = self._new_snapshot_dir(pid) if snapshot else None
        except Exception as exc:  # noqa: BLE001
            self.error("创建快照目录失败", pid=pid, exc=repr(exc))
            snapshot_dir = None
        try:
            return self._scan_pid_impl(pid, snapshot_dir)
        except Exception as exc:  # noqa: BLE001 - 采集入口绝不抛出
            self.error("扫描进程失败", pid=pid, exc=repr(exc))
            return {"pid": int(pid), "regions": [], "hits": [], "verdict": "error",
                    "score": 0, "error": repr(exc)}

    def snapshot(self, pid: int) -> str:
        """扫描并写快照目录，返回目录路径（失败返回 ""）。"""
        try:
            snapshot_dir = self._new_snapshot_dir(pid)
        except Exception as exc:  # noqa: BLE001
            self.error("创建快照目录失败", pid=pid, exc=repr(exc))
            return ""
        try:
            result = self._scan_pid_impl(pid, snapshot_dir)
        except Exception as exc:  # noqa: BLE001
            self.error("快照扫描失败", pid=pid, exc=repr(exc))
            return ""
        return str(result.get("snapshot_dir") or "")

    def verify(self, snapshot_dir: str) -> dict:
        """复核快照：重算 regions/*.bin 的 sha256 并与 hits.json 对照。"""
        out: dict[str, Any] = {"dir": snapshot_dir, "ok": False, "hits": 0,
                               "regions": 0, "mismatch": [], "errors": []}
        path = str(snapshot_dir or "")
        if not path or not os.path.isdir(path):
            out["errors"].append("快照目录不存在")
            return out
        hits_file = os.path.join(path, "hits.json")
        try:
            with open(hits_file, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            out["errors"].append(f"读取 hits.json 失败：{exc}")
            return out
        # 兼容两种落盘格式：snapshot() 写 {"hits": [...]}，外部工具可能直接写 [...]
        hits = payload.get("hits") if isinstance(payload, dict) else payload
        if not isinstance(hits, list):
            out["errors"].append("hits.json 结构非法（缺少 hits 列表）")
            return out
        out["hits"] = len(hits)
        regions_dir = os.path.join(path, "regions")
        for hit in hits:
            name = self._region_filename(hit)
            region_file = os.path.join(regions_dir, name)
            if not os.path.isfile(region_file):
                out["mismatch"].append({"file": name, "reason": "missing"})
                continue
            out["regions"] += 1
            try:
                with open(region_file, "rb") as handle:
                    digest = schema.sha256_bytes(handle.read())
            except OSError as exc:
                out["errors"].append(f"读取 {name} 失败：{exc}")
                continue
            if hit.get("sha256") and digest != hit["sha256"]:
                out["mismatch"].append(
                    {"file": name, "reason": "sha256", "expected": hit["sha256"], "actual": digest}
                )
        out["ok"] = not out["mismatch"] and not out["errors"]
        return out

    def sweep(self) -> list[dict]:
        """限时限量扫描全部可读进程，返回有命中的扫描结果。"""
        self.stat_add("sweeps")
        if not _is_linux():
            self.error("memscan 仅支持 Linux，跳过 sweep")
            return []
        pids = self._list_pids()
        deadline = time.monotonic() + SWEEP_BUDGET_SEC
        results: list[dict] = []
        for pid in pids[:MAX_SWEEP_PIDS]:
            if self.stopping or time.monotonic() > deadline:
                break
            if _readlink(f"/proc/{pid}/exe") is None and not _has_exec_region(pid):
                # 内核线程没有 exe 也没有可执行映射，跳过
                continue
            result = self.scan_pid(pid)
            if result.get("hits"):
                results.append(
                    {
                        "pid": pid,
                        "hits": len(result["hits"]),
                        "verdict": result.get("verdict"),
                        "score": result.get("score", 0),
                    }
                )
        log.info("memscan sweep 完成", scanned=min(len(pids), MAX_SWEEP_PIDS), hits=len(results))
        return results

    @staticmethod
    def _list_pids() -> list[int]:
        try:
            names = os.listdir("/proc")
        except OSError:
            return []
        return sorted(int(name) for name in names if name.isdigit())

    # ------------------------------------------------------------ 快照落盘
    def _new_snapshot_dir(self, pid: int) -> str:
        raw_dir = str(self.conf("general.raw_dir", "/opt/hornwork/raw"))
        host = str((schema.host_info(self.cfg) or {}).get("host_id") or "host")
        safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
        stamp = schema.utc_now().replace("-", "").replace(":", "").replace(".", "")
        path = os.path.join(raw_dir, "mem", f"{safe_host}-{stamp}-{int(pid)}")
        os.makedirs(path, exist_ok=True)
        os.makedirs(os.path.join(path, "regions"), exist_ok=True)
        return path

    @staticmethod
    def _region_filename(hit: dict) -> str:
        return f"{int(hit.get('start') or 0):x}-{int(hit.get('end') or 0):x}.bin"

    def _write_region(self, snapshot_dir: str, hit: dict, data: bytes) -> None:
        try:
            path = os.path.join(snapshot_dir, "regions", self._region_filename(hit))
            with open(path, "wb") as handle:
                handle.write(data)
        except OSError as exc:
            self.error("写内存段快照失败", entry=hit.get("start"), exc=repr(exc))

    def _write_snapshot_files(
        self, snapshot_dir: str, maps_text: str, hits: list[dict], result: dict
    ) -> None:
        try:
            with open(os.path.join(snapshot_dir, "maps.txt"), "w", encoding="utf-8") as handle:
                handle.write(maps_text)
        except OSError as exc:
            self.error("写 maps.txt 失败", exc=repr(exc))
        payload = {
            "pid": result.get("pid"),
            "ts": schema.utc_now(),
            "verdict": result.get("verdict"),
            "score": result.get("score"),
            "behavior": result.get("behavior"),
            "hits": hits,
        }
        try:
            with open(os.path.join(snapshot_dir, "hits.json"), "w", encoding="utf-8") as handle:
                handle.write(schema.dumps(payload))
        except OSError as exc:
            self.error("写 hits.json 失败", exc=repr(exc))

    # ------------------------------------------------------------ 事件/告警
    def _emit_result(self, result: dict, timestamp: str) -> None:
        hits = result.get("hits") or []
        summary = [{k: v for k, v in hit.items() if k != "bytes"} for hit in hits[:20]]
        event = self.make_event(
            "memory_scan",
            ts=timestamp,
            process={"pid": result.get("pid")},
            raw={
                "collector": "memscan",
                "verdict": result.get("verdict"),
                "score": result.get("score"),
                "hits": summary,
                "regions": len(result.get("regions") or []),
                "snapshot_dir": result.get("snapshot_dir"),
            },
        )
        self.send(event)
        if result.get("verdict") in ("injected", "suspicious"):
            self._alert(result, event, hits)

    def _alert(self, result: dict, event: dict, hits: list[dict]) -> None:
        rule = schema.make_rule(
            "M-0101", "内存注入/无文件执行（内存侧+行为侧佐证）", "memscan",
            level=10, mitre=["T1055"],
        )
        evidence = []
        for hit in hits[:8]:
            evidence.append(
                {
                    "start": hex(int(hit.get("start") or 0)),
                    "end": hex(int(hit.get("end") or 0)),
                    "perms": hit.get("perms"),
                    "pathname": hit.get("pathname"),
                    "kind": hit.get("kind"),
                    "sha256": hit.get("sha256"),
                    "elf": hit.get("elf"),
                }
            )
        evidence.append({"behavior": result.get("behavior") or {}})
        alert = schema.new_alert(
            rule,
            level=10,
            event=event,
            entity={"pid": result.get("pid")},
            evidence=evidence,
            confidence=80,
            dedup_extra=result.get("pid"),
        )
        self.send_alert(alert)
        self.stat_add("alerts")


def _has_exec_region(pid: int) -> bool:
    for region in parse_maps(pid):
        if "x" in str(region.get("perms") or ""):
            return True
    return False


__all__ = [
    "MemoryScanner",
    "parse_maps",
    "parse_maps_text",
    "ELF_MAGIC",
    "PE_MAGIC",
]
