"""后门 / 持久化检查（7 类），。

检查项：隐藏进程、无文件进程、LD_PRELOAD、内核模块、持久化项、账号异常、SUID 新增。

- `build_baseline()` 把 SUID 清单 / 内核模块 / 持久化文件状态 / sudoers 摘要写入 store 的
  `meta` 表（键如 `baseline:sudoers`、`baseline:suid`、`baseline:persist:<path>`）；
- `run_checks()` 返回固定结构 `[{"check","findings","errors"}]`，每项独立 try/except；
- 发现项 emit 对应事件并告警（level 6–10，带 MITRE 技术号）；
- 所有 `/proc`、`/etc` 读取均在函数体内且对路径不存在/权限不足容错。
"""

from __future__ import annotations

import json
import os
import stat as stat_mod
import sys
import time
from typing import Any

from .. import schema
from ..log import get_logger
from . import BaseCollector

log = get_logger("collector.persist")

#: 每个检查的告警元数据（rule_id / 名称 / 级别 / MITRE）
CHECK_RULES: dict[str, dict] = {
    "hidden_process": {"id": "P-0101", "name": "隐藏进程（socket 无属主）", "level": 9, "mitre": ["T1014"]},
    "fileless": {"id": "P-0102", "name": "无文件执行（memfd/已删除 exe）", "level": 9, "mitre": ["T1620"]},
    "ld_preload": {"id": "P-0103", "name": "LD_PRELOAD 动态库劫持", "level": 9, "mitre": ["T1574.006"]},
    "kernel_module": {"id": "P-0104", "name": "内核模块异常", "level": 10, "mitre": ["T1547.006"]},
    "persist_item": {"id": "P-0105", "name": "持久化项新增/变更", "level": 8, "mitre": ["T1547.001"]},
    "account_anomaly": {"id": "P-0106", "name": "账号异常（uid0/空口令/sudoers）", "level": 10, "mitre": ["T1136.001"]},
    "suid_new": {"id": "P-0107", "name": "新增 SUID 文件", "level": 9, "mitre": ["T1548.001"]},
}

#: 检查项 → 发现项对应的事件类型
CHECK_EVENT: dict[str, str] = {
    "hidden_process": "process_create",
    "fileless": "process_create",
    "ld_preload": "file_modify",
    "kernel_module": "persist_item",
    "persist_item": "persist_item",
    "account_anomaly": "account_create",
    "suid_new": "file_modify",
}

MAX_PIDS = 3000
MAX_DIR_ENTRIES = 5000
META_PREFIX = "baseline:"


# ---------------------------------------------------------------------------
# 文件/进程小工具（全部 Linux 专属行为放在函数体内）
# ---------------------------------------------------------------------------
def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _sha256(path: str) -> str | None:
    try:
        return schema.sha256_file(path)
    except (OSError, ValueError):
        return None


def _mode_str(mode: int) -> str:
    return f"{mode & 0o7777:04o}"


def _proc_pids(limit: int = MAX_PIDS) -> list[int]:
    if not _is_linux():
        return []
    try:
        names = os.listdir("/proc")
    except OSError:
        return []
    pids = [int(name) for name in names if name.isdigit()]
    pids.sort()
    return pids[:limit]


def _whitelisted(path: str, patterns: list[str]) -> bool:
    for pattern in patterns or []:
        if pattern and (path == pattern or path.startswith(pattern.rstrip("/") + "/")):
            return True
    return False


class PersistenceChecker(BaseCollector):
    """7 类后门检查器（既可按需调用，也可由后台线程周期执行）。"""

    name = "persist"
    source_product = "hornwork-persist"

    def __init__(
        self,
        cfg: dict | None,
        store: Any,
        emit: Any,
        emit_alert: Any = None,
        **kw: Any,
    ) -> None:
        super().__init__(cfg, emit, store, emit_alert, **kw)
        self.persist_paths = [str(p) for p in (self.conf("host.persist_paths", []) or [])]
        self.persist_whitelist = [str(p) for p in (self.conf("host.persist_whitelist", []) or [])]
        self.suid_dirs = [str(p) for p in (self.conf("host.suid_scan_dirs", []) or [])]
        self.interval = max(10.0, float(self.conf("host.check_interval_sec", 60)))
        self.hash_limit = int(self.conf("host.persist_hash_limit_bytes", 16 * 1024 * 1024))
        self._last_run: dict[str, Any] = {}

    def _init_stats(self) -> dict[str, Any]:
        return {
            "checks": 0,
            "findings": 0,
            "alerts": 0,
            "baseline": 0,
            "last_run_ts": None,
            "check_errors": 0,
        }

    # ------------------------------------------------------------ 周期执行
    def _run(self) -> None:
        log.info("persist 检查线程启动", interval=self.interval)
        while not self.stopping:
            started = time.monotonic()
            try:
                self.run_checks()
            except Exception as exc:  # noqa: BLE001 - 单轮失败不得终止线程
                self.error("persist 检查轮次失败", exc=repr(exc))
            elapsed = time.monotonic() - started
            self.sleep(max(1.0, self.interval - elapsed))

    def status(self) -> dict:
        base = super().status()
        base["stats"]["last_run"] = self._last_run
        return base

    # ------------------------------------------------------------ 基线
    def build_baseline(self) -> dict:
        """记录 SUID / 内核模块 / 持久化路径 / sudoers 基线到 meta 表。"""
        result: dict[str, Any] = {"ts": schema.utc_now()}
        if self.store is None:
            self.error("store 未注入，无法写基线")
            result["error"] = "store missing"
            return result

        suid = self._collect_suid()
        modules = self._collect_modules()
        sudoers = self._collect_sudoers()
        persist: dict[str, Any] = {}
        for path in self.persist_paths:
            state = self._collect_persist_state(path)
            if state is None:
                continue
            persist[path] = state

        try:
            self._set_meta("suid", suid)
            self._set_meta("modules", modules)
            self._set_meta("sudoers", sudoers)
            for path, state in persist.items():
                self._set_meta(f"persist:{path}", state)
            self._set_meta("ts", result["ts"])
        except Exception as exc:  # noqa: BLE001
            self.error("写基线失败", exc=repr(exc))
            result["error"] = repr(exc)
            return result

        result.update(
            {
                "suid": len(suid),
                "modules": len(modules),
                "sudoers": len(sudoers),
                "persist": len(persist),
            }
        )
        self.stat_set("baseline", 1)
        log.info("persist 基线已建立", suid=len(suid), modules=len(modules), persist=len(persist))
        return result

    def _set_meta(self, suffix: str, value: Any) -> None:
        if self.store is None:
            return
        self.store.set_meta(META_PREFIX + suffix, json.dumps(value, ensure_ascii=False, default=str))

    def _get_meta(self, suffix: str, default: Any = None) -> Any:
        if self.store is None:
            return default
        try:
            raw = self.store.get_meta(META_PREFIX + suffix)
        except Exception as exc:  # noqa: BLE001
            self.error("读基线失败", key=suffix, exc=repr(exc))
            return default
        if raw is None:
            return default
        try:
            return json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return default

    # ------------------------------------------------------------ 7 类检查
    def run_checks(self) -> list[dict]:
        """执行 7 类检查，返回固定结构列表。"""
        results: list[dict] = []
        for check in CHECK_RULES:
            method = getattr(self, f"_check_{check}", None)
            findings: list[dict] = []
            errors: list[str] = []
            if method is None:  # pragma: no cover - 防御性
                errors.append("检查未实现")
            else:
                try:
                    findings, errors = method()
                except Exception as exc:  # noqa: BLE001 - 单项检查失败隔离
                    errors.append(f"{type(exc).__name__}: {exc}")
                    self.stat_add("check_errors")
            results.append({"check": check, "findings": findings, "errors": errors})
            self.stat_add("checks")
            if findings:
                try:
                    self._handle_findings(check, findings)
                except Exception as exc:  # noqa: BLE001
                    self.error("发现项投递失败", check=check, exc=repr(exc))
        self._last_run = {
            "ts": schema.utc_now(),
            "findings": sum(len(r["findings"]) for r in results),
            "errors": sum(len(r["errors"]) for r in results),
        }
        self.stat_set("last_run_ts", self._last_run["ts"])
        return results

    # ---- 1) 隐藏进程 ------------------------------------------------------
    def _check_hidden_process(self) -> tuple[list[dict], list[str]]:
        findings: list[dict] = []
        errors: list[str] = []
        if not _is_linux():
            return findings, ["非 Linux 环境，跳过隐藏进程检查"]
        if not _is_root():
            return findings, ["非 root：无法读取全部 /proc/*/fd，跳过隐藏进程检查"]
        from .proc import read_connections, socket_inode_owners

        owners = socket_inode_owners()
        seen: set[int] = set()
        for conn in read_connections():
            inode = int(conn.get("inode") or 0)
            if not inode or inode in seen:
                continue
            if conn.get("state") not in ("ESTABLISHED", "SYN_SENT", "SYN_RECV", "LISTEN"):
                continue
            if str(inode) in owners:
                continue
            seen.add(inode)
            findings.append(
                {
                    "kind": "hidden_process",
                    "reason": "socket 存在但 /proc 中无属主进程",
                    "pid": None,
                    "inode": inode,
                    "proto": conn.get("proto"),
                    "local": f"{conn.get('local_ip')}:{conn.get('local_port')}",
                    "remote": f"{conn.get('remote_ip')}:{conn.get('remote_port')}",
                }
            )
        return findings, errors

    # ---- 2) 无文件进程 ----------------------------------------------------
    def _check_fileless(self) -> tuple[list[dict], list[str]]:
        findings: list[dict] = []
        errors: list[str] = []
        if not _is_linux():
            return findings, ["非 Linux 环境，跳过无文件进程检查"]
        from .memscan import parse_maps

        for pid in _proc_pids():
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                continue
            if exe.endswith(" (deleted)"):
                findings.append(
                    {
                        "kind": "fileless",
                        "reason": "exe 已删除但进程仍在运行",
                        "pid": pid,
                        "path": exe[: -len(" (deleted)")] or exe,
                    }
                )
            try:
                regions = parse_maps(pid)
            except Exception:  # noqa: BLE001 - 进程可能已退出
                continue
            for region in regions:
                pathname = region.get("pathname") or ""
                if "memfd:" in pathname and "x" in str(region.get("perms") or ""):
                    findings.append(
                        {
                            "kind": "fileless",
                            "reason": "memfd 可执行映射",
                            "pid": pid,
                            "path": pathname,
                            "start": region.get("start"),
                            "end": region.get("end"),
                        }
                    )
        return findings, errors

    # ---- 3) LD_PRELOAD ----------------------------------------------------
    def _check_ld_preload(self) -> tuple[list[dict], list[str]]:
        findings: list[dict] = []
        errors: list[str] = []
        preload_file = "/etc/ld.so.preload"
        if os.path.exists(preload_file):
            text = _read_text(preload_file) or ""
            entries = [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if entries:
                findings.append(
                    {
                        "kind": "ld_preload",
                        "reason": "/etc/ld.so.preload 非空",
                        "path": preload_file,
                        "value": ",".join(entries[:8]),
                    }
                )
        if not _is_linux():
            return findings, errors
        for pid in _proc_pids():
            try:
                with open(f"/proc/{pid}/environ", "rb") as handle:
                    raw = handle.read(65536)
            except OSError:
                continue
            for item in raw.split(b"\x00"):
                if item.startswith(b"LD_PRELOAD="):
                    value = item[len(b"LD_PRELOAD="):].decode("utf-8", "replace")
                    if value:
                        findings.append(
                            {
                                "kind": "ld_preload",
                                "reason": "进程环境含 LD_PRELOAD",
                                "pid": pid,
                                "path": f"/proc/{pid}/environ",
                                "value": value,
                            }
                        )
                    break
        return findings, errors

    # ---- 4) 内核模块 ------------------------------------------------------
    def _collect_modules(self) -> list[str]:
        text = _read_text("/proc/modules") or ""
        modules = []
        for line in text.splitlines():
            name = line.split(" ", 1)[0].strip()
            if name:
                modules.append(name)
        return sorted(set(modules))

    def _check_kernel_module(self) -> tuple[list[dict], list[str]]:
        findings: list[dict] = []
        errors: list[str] = []
        if not _is_linux():
            return findings, ["非 Linux 环境，跳过内核模块检查"]
        current = self._collect_modules()
        baseline = self._get_meta("modules", None)
        if baseline is None:
            return findings, ["缺少内核模块基线（先执行 build_baseline）"]
        baseline_set = set(baseline)
        current_set = set(current)
        for name in sorted(current_set - baseline_set):
            findings.append({"kind": "kernel_module", "reason": "新增内核模块", "module": name})
        for name in sorted(baseline_set - current_set):
            findings.append({"kind": "kernel_module", "reason": "基线模块消失（可能被卸载）", "module": name})
        return findings, errors

    # ---- 5) 持久化项 ------------------------------------------------------
    def _collect_persist_state(self, path: str) -> dict | None:
        """采集单个持久化路径状态（文件记 sha256，目录记子项 size/mtime）。"""
        try:
            st = os.lstat(path)
        except OSError:
            return None
        if stat_mod.S_ISDIR(st.st_mode):
            entries: dict[str, Any] = {}
            try:
                names = sorted(os.listdir(path))[:MAX_DIR_ENTRIES]
            except OSError:
                names = []
            for name in names:
                child = os.path.join(path, name)
                try:
                    cst = os.lstat(child)
                except OSError:
                    continue
                entries[name] = {
                    "size": cst.st_size,
                    "mtime": schema.to_utc(cst.st_mtime),
                    "mode": _mode_str(cst.st_mode),
                }
            return {"type": "dir", "entries": entries, "mode": _mode_str(st.st_mode)}
        digest = None
        if stat_mod.S_ISREG(st.st_mode) and st.st_size <= self.hash_limit:
            digest = _sha256(path)
        return {
            "type": "file",
            "sha256": digest,
            "size": st.st_size,
            "mtime": schema.to_utc(st.st_mtime),
            "mode": _mode_str(st.st_mode),
        }

    def _check_persist_item(self) -> tuple[list[dict], list[str]]:
        findings: list[dict] = []
        errors: list[str] = []
        for raw_path in self.persist_paths:
            path = str(raw_path)
            if _whitelisted(path, self.persist_whitelist):
                continue
            if not os.path.exists(path):
                continue
            baseline = self._get_meta(f"persist:{path}", None)
            if baseline is None:
                errors.append(f"缺少持久化基线: {path}")
                continue
            current = self._collect_persist_state(path)
            if current is None:
                continue
            if current.get("type") != baseline.get("type"):
                findings.append(
                    {"kind": "persist_item", "reason": "路径类型变化", "path": path}
                )
                continue
            if current.get("type") == "file":
                for field in ("sha256", "size", "mode"):
                    if current.get(field) != baseline.get(field):
                        findings.append(
                            {
                                "kind": "persist_item",
                                "reason": f"持久化文件变更({field})",
                                "path": path,
                                "baseline": baseline.get(field),
                                "current": current.get(field),
                            }
                        )
                        break
                continue
            # 目录：比对子项
            before = baseline.get("entries") or {}
            after = current.get("entries") or {}
            for name in sorted(set(after) - set(before)):
                findings.append(
                    {
                        "kind": "persist_item",
                        "reason": "新增持久化文件",
                        "path": os.path.join(path, name),
                    }
                )
            for name in sorted(set(after) & set(before)):
                old = before[name]
                new = after[name]
                if old.get("size") != new.get("size") or old.get("mode") != new.get("mode"):
                    findings.append(
                        {
                            "kind": "persist_item",
                            "reason": "持久化文件变更",
                            "path": os.path.join(path, name),
                            "baseline": old,
                            "current": new,
                        }
                    )
            for name in sorted(set(before) - set(after)):
                findings.append(
                    {
                        "kind": "persist_item",
                        "reason": "持久化文件被删除",
                        "path": os.path.join(path, name),
                    }
                )
        return findings, errors

    # ---- 6) 账号异常 ------------------------------------------------------
    def _collect_sudoers(self) -> dict[str, Any]:
        files: dict[str, Any] = {}
        for path in ("/etc/sudoers", "/etc/sudoers.d"):
            if os.path.isdir(path):
                try:
                    names = sorted(os.listdir(path))[:MAX_DIR_ENTRIES]
                except OSError:
                    names = []
                for name in names:
                    child = os.path.join(path, name)
                    digest = _sha256(child) if os.path.isfile(child) else None
                    if digest:
                        files[child] = digest
            elif os.path.isfile(path):
                digest = _sha256(path)
                if digest:
                    files[path] = digest
        return files

    def _check_account_anomaly(self) -> tuple[list[dict], list[str]]:
        findings: list[dict] = []
        errors: list[str] = []
        passwd = _read_text("/etc/passwd")
        if passwd is None:
            errors.append("无法读取 /etc/passwd")
        else:
            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) < 4 or parts[0].startswith("#"):
                    continue
                if parts[2] == "0" and parts[0] not in ("root", "toor"):
                    findings.append(
                        {
                            "kind": "account_anomaly",
                            "reason": "uid=0 非 root 账号",
                            "user": parts[0],
                            "path": "/etc/passwd",
                        }
                    )
        shadow = _read_text("/etc/shadow")
        if shadow is None:
            errors.append("无法读取 /etc/shadow（需要 root）")
        else:
            for line in shadow.splitlines():
                parts = line.split(":")
                if len(parts) < 2 or parts[0].startswith("#"):
                    continue
                if parts[1] == "":
                    findings.append(
                        {
                            "kind": "account_anomaly",
                            "reason": "空口令账号",
                            "user": parts[0],
                            "path": "/etc/shadow",
                        }
                    )
        baseline = self._get_meta("sudoers", None)
        current = self._collect_sudoers()
        if baseline is None:
            errors.append("缺少 sudoers 基线（先执行 build_baseline）")
        else:
            for path in sorted(set(current) - set(baseline)):
                findings.append(
                    {"kind": "account_anomaly", "reason": "新增 sudoers 文件", "path": path}
                )
            for path in sorted(set(current) & set(baseline)):
                if current[path] != baseline[path]:
                    findings.append(
                        {"kind": "account_anomaly", "reason": "sudoers 文件被修改", "path": path}
                    )
        return findings, errors

    # ---- 7) SUID 新增 -----------------------------------------------------
    def _collect_suid(self, limit: int = 20000) -> list[str]:
        suid: list[str] = []
        for directory in self.suid_dirs:
            if not os.path.isdir(directory):
                continue
            try:
                entries = os.scandir(directory)
            except OSError:
                continue
            with entries:
                for entry in entries:
                    if len(suid) >= limit:
                        return sorted(set(suid))
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat_mod.S_ISREG(st.st_mode) and st.st_mode & stat_mod.S_ISUID:
                        suid.append(entry.path)
        return sorted(set(suid))

    def _check_suid_new(self) -> tuple[list[dict], list[str]]:
        findings: list[dict] = []
        errors: list[str] = []
        baseline = self._get_meta("suid", None)
        if baseline is None:
            return findings, ["缺少 SUID 基线（先执行 build_baseline）"]
        current = set(self._collect_suid())
        for path in sorted(current - set(baseline)):
            findings.append({"kind": "suid_new", "reason": "新增 SUID 文件", "path": path})
        return findings, errors

    # ------------------------------------------------------------ 发现项投递
    def _handle_findings(self, check: str, findings: list[dict]) -> None:
        meta = CHECK_RULES.get(check) or {}
        event_type = CHECK_EVENT.get(check, "persist_item")
        last_event: dict | None = None
        for finding in findings:
            process = {"pid": finding["pid"]} if finding.get("pid") is not None else None
            file_info = None
            if finding.get("path"):
                file_info = {"path": finding["path"], "action": "modify"}
            user = {"name": finding["user"]} if finding.get("user") else None
            raw = dict(finding)
            raw["collector"] = "persist"
            raw["check"] = check
            try:
                event = self.make_event(
                    event_type, process=process, file=file_info, user=user, raw=raw
                )
            except Exception as exc:  # noqa: BLE001
                self.error("发现项事件构造失败", check=check, exc=repr(exc))
                continue
            self.send(event)
            last_event = event
            self.stat_add("findings")

        if not findings:
            return
        rule = schema.make_rule(
            str(meta.get("id", f"P-{check}")),
            str(meta.get("name", check)),
            "persist",
            level=int(meta.get("level", 8)),
            mitre=list(meta.get("mitre") or []),
        )
        context = last_event
        if context is None:
            context = self.make_event(event_type, raw={"collector": "persist", "check": check})
        evidence = []
        for finding in findings[:10]:
            evidence.append({k: v for k, v in finding.items() if k != "collector"})
        alert = schema.new_alert(
            rule,
            event=context,
            entity={"src_ip": None},
            evidence=evidence,
            confidence=75,
            dedup_extra=check,
        )
        self.send_alert(alert)
        self.stat_add("alerts")


__all__ = ["PersistenceChecker", "CHECK_RULES", "CHECK_EVENT"]
