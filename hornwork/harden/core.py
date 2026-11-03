"""加固模块：加固编排公共基础设施。

- 路径/状态目录/JSON 原子读写/子进程封装/备份还原/事件旁路写入。
- 状态全部落文件（plan/run/assets/backups），不新增数据库表，减少与检测模块/四的耦合面。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat as stat_mod
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CODE_DIR = Path(__file__).resolve().parent
ITEMS_PATH = CODE_DIR / "items.yaml"
TEMPLATE_DIR = CODE_DIR / "templates"

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

DEFAULT_DATA_DIR = "/var/lib/hornwork"


# ---------------------------------------------------------------- 时间/哈希/IO
def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(text: str) -> datetime:
    text = text.strip()
    if " " in text and text.endswith("Z"):
        text = text.replace(" ", "T", 1)
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def days_left(not_after: str) -> int:
    return (parse_ts(not_after) - datetime.now(timezone.utc)).days


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_id(prefix: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:4]}"


def check_id(value: str) -> str:
    if not SAFE_ID.match(value):
        raise ValueError(f"非法标识：{value!r}")
    return value


def read_json(path: str | Path, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json(path: str | Path, data: Any) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, default=str)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    return path


def write_text(path: str | Path, text: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)
    return path


# ---------------------------------------------------------------- 状态目录
def data_dir(cfg: dict | None = None) -> Path:
    if cfg:
        from ..config import cfg_get

        base = str(cfg_get(cfg, "general.data_dir", DEFAULT_DATA_DIR))
    else:
        base = DEFAULT_DATA_DIR
    if os.environ.get("HORNWORK_HARDEN_DIR"):
        return Path(os.environ["HORNWORK_HARDEN_DIR"])
    return Path(base) / "harden"


def state(cfg: dict | None = None) -> dict[str, Path]:
    root = data_dir(cfg)
    paths = {
        "root": root,
        "plans": root / "plans",
        "runs": root / "runs",
        "backups": root / "backups",
        "snapshots": root / "snapshots",
        "assets": root / "assets",
        "luks": root / "luks",
        "demo": root / "demo",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def is_root() -> bool:
    return getattr(os, "geteuid", lambda: 1)() == 0


# ---------------------------------------------------------------- 子进程
def sh(cmd: str, timeout: int = 60) -> dict[str, Any]:
    """以 bash 执行命令；非 root 时走 sudo -n（不自研提权逻辑）。"""
    env = dict(os.environ)
    env.update({"LANG": "C", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"})
    argv = ["/bin/bash", "-lc", cmd] if is_root() else ["sudo", "-n", "/bin/bash", "-lc", cmd]
    started = time.time()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": f"timeout>{timeout}s", "ms": timeout * 1000}
    except FileNotFoundError as exc:
        return {"rc": 127, "out": "", "err": str(exc), "ms": 0}
    return {
        "rc": proc.returncode,
        "out": proc.stdout.strip(),
        "err": proc.stderr.strip(),
        "ms": int((time.time() - started) * 1000),
    }


def ok(res: dict[str, Any]) -> bool:
    return res.get("rc") == 0


# ---------------------------------------------------------------- 备份/还原
def _flat(path: str) -> str:
    return str(path).lstrip("/").replace("/", "__")


def backup_paths(targets: list[str], run_id: str, item_id: str, backups_root: Path) -> dict[str, Any]:
    """备份目标文件（存在才备份），记录内容 sha256/权限/属主，供 L1 还原。"""
    check_id(run_id)
    check_id(item_id)
    dest = backups_root / run_id / item_id
    entries: list[dict[str, Any]] = []
    for target in targets:
        path = Path(target)
        if not path.is_file():
            entries.append({"path": target, "exists": False})
            continue
        dest.mkdir(parents=True, exist_ok=True)
        copy = dest / _flat(target)
        shutil.copy2(path, copy)
        info = path.stat()
        entries.append(
            {
                "path": target,
                "exists": True,
                "backup": str(copy),
                "sha256": sha256_file(path),
                "mode": stat_mod.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
            }
        )
    return {"dir": str(dest), "entries": entries}


def restore_backup(record: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for entry in record.get("entries", []):
        target = entry.get("path")
        if not entry.get("exists"):
            # apply 新建的文件：回滚即删除
            path = Path(target)
            if path.is_file():
                path.unlink()
                results.append({"path": target, "restored": "deleted"})
            continue
        shutil.copy2(entry["backup"], target)
        os.chmod(target, entry["mode"])
        try:
            os.chown(target, entry["uid"], entry["gid"])
        except PermissionError:
            pass
        same = sha256_file(target) == entry["sha256"]
        results.append({"path": target, "restored": "sha256_ok" if same else "sha256_mismatch"})
    return results


# ---------------------------------------------------------------- 事件旁路
def emit_event(cfg: dict | None, phase: str, payload: dict[str, Any]) -> bool:
    """把 harden_* 事件写入检测模块同一个 hornwork.db；失败不影响加固主流程。"""
    try:
        from uuid import uuid4

        from .. import schema
        from ..store import open_store

        store = open_store(cfg) if cfg else None
        if store is None:
            return False
        event = {
            "schema_version": schema.SCHEMA_VERSION,
            "event_id": str(uuid4()),
            "ts": schema.utc_now(),
            "source_layer": "host",
            "source_product": "hornwork-harden",
            "event_type": f"harden_{phase}",
            "host": schema.host_info(cfg),
            "raw": {"module": "harden", "phase": phase, **payload},
        }
        return store.insert_event(event, engine="harden")
    except Exception:  # noqa: BLE001 - 旁路失败不阻断
        return False


def write_evidence_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


# ---------------------------------------------------------------- 时间窗
def wait_until(deadline: float) -> None:
    remaining = deadline - time.time()
    if remaining > 0:
        time.sleep(remaining)
