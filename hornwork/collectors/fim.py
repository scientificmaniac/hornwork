"""inotify 文件完整性监控（ctypes 调 libc，Linux 专属调用全部在函数体内）。



- 递归注册监控目录（`inotify_add_watch`），维护 `wd → 目录` 映射，新目录动态加 watch；
- 运行期用 `select + os.read` 解析 `inotify_event`（wd/mask/cookie/len/name）；
- 同一路径 300 ms 去抖（可配 `collect.fim.debounce_ms`），合并为一条事件；
- 首次启动若 `collect.fim.baseline=true`，全量 `stat + sha256` 写入 store 的 `baseline` 表；
- `diff_baseline()` 供定时校验，返回与基线不一致的条目（不修改基线）；
- inotify 不可用（非 Linux / libc 缺失）时 `start()` 记 WARN 后返回，不抛异常。
"""

from __future__ import annotations

import ctypes
import os
import select
import stat as stat_mod
import struct
import sys
import time
from typing import Any

from .. import schema
from ..log import get_logger
from . import BaseCollector

log = get_logger("collector.fim")

# ---------------------------------------------------------------------------
# inotify 常量（Linux <sys/inotify.h>）
# ---------------------------------------------------------------------------
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000
IN_DONT_FOLLOW = 0x02000000

WATCH_MASK = (
    IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CREATE
    | IN_DELETE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_DONT_FOLLOW
)

_IN_NONBLOCK = getattr(os, "O_NONBLOCK", 0o4000)
_IN_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

EVENT_HDR = struct.calcsize("iIII")  # wd, mask, cookie, len
MAX_READ_BYTES = 256 * 1024
HASH_LIMIT = 32 * 1024 * 1024  # 超过 32MB 不再算 sha256（只记 stat）

#: 事件类型 ↔ inotify 掩码
_MASK_CREATE = IN_CREATE | IN_MOVED_TO
_MASK_DELETE = IN_DELETE | IN_MOVED_FROM
_MASK_MODIFY = IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE


def inotify_supported() -> bool:
    """平台/能力检查：Linux 且能找到 libc。"""
    return sys.platform.startswith("linux") and _find_libc() is not None


def _find_libc() -> Any:
    """加载 libc 并绑定 inotify 函数原型（仅 Linux 调用，异常返回 None）。"""
    if not sys.platform.startswith("linux"):
        return None
    try:
        import ctypes.util

        name = ctypes.util.find_library("c") or "libc.so.6"
        lib = ctypes.CDLL(name, use_errno=True)
        lib.inotify_init1.argtypes = [ctypes.c_int]
        lib.inotify_init1.restype = ctypes.c_int
        lib.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        lib.inotify_add_watch.restype = ctypes.c_int
        lib.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
        lib.inotify_rm_watch.restype = ctypes.c_int
        return lib
    except (OSError, AttributeError, ImportError):
        return None


def _sha256(path: str) -> str | None:
    try:
        return schema.sha256_file(path)
    except (OSError, ValueError):
        return None


def _mode_str(mode: int) -> str:
    return f"{mode & 0o7777:04o}"


class FimCollector(BaseCollector):
    """基于 inotify 的文件完整性采集器。"""

    name = "fim"
    source_product = "hornwork-fim"

    def __init__(
        self,
        cfg: dict | None,
        emit: Any,
        store: Any = None,
        emit_alert: Any = None,
        **kw: Any,
    ) -> None:
        super().__init__(cfg, emit, store, emit_alert, **kw)
        dirs = self.conf("collect.fim.dirs", ["/etc", "/tmp"]) or []
        self.dirs: list[str] = [str(d) for d in dirs]
        self.debounce_s = max(0.0, float(self.conf("collect.fim.debounce_ms", 300)) / 1000.0)
        self.max_watches = int(self.conf("collect.fim.max_watches", 20000))
        self.use_baseline = bool(self.conf("collect.fim.baseline", True))
        self.hash_limit = int(self.conf("collect.fim.hash_limit_bytes", HASH_LIMIT))
        self._libc: Any = None
        self._fd: int | None = None
        self._wd_path: dict[int, str] = {}
        self._watches = 0
        self._watch_warned = False
        self._pending: dict[str, dict] = {}

    def _init_stats(self) -> dict[str, Any]:
        return {
            "file_create": 0,
            "file_modify": 0,
            "file_delete": 0,
            "watches": 0,
            "baseline_files": 0,
            "diff_changes": 0,
            "overflow": 0,
            "events": 0,
        }

    # ------------------------------------------------------------ 生命周期
    def start(self) -> None:
        """非 Linux / 无 libc 时记 WARN 后直接返回（不抛异常）。"""
        if not sys.platform.startswith("linux"):
            self.error("inotify 仅支持 Linux，FIM 不启动")
            return
        self._libc = _find_libc()
        if self._libc is None:
            self.error("无法加载 libc/inotify，FIM 不启动")
            return
        super().start()

    def _run(self) -> None:
        libc = self._libc
        if libc is None:
            self.error("libc 未就绪，FIM 退出")
            return
        fd = libc.inotify_init1(_IN_NONBLOCK | _IN_CLOEXEC)
        if fd < 0:
            errno = ctypes.get_errno()
            self.error("inotify_init1 失败", errno=errno)
            return
        self._fd = fd
        try:
            self._register_all()
            if self.use_baseline:
                self._ensure_baseline()
            while not self.stopping:
                try:
                    ready, _, _ = select.select([fd], [], [], 0.2)
                except (OSError, ValueError) as exc:
                    self.error("inotify select 失败", exc=repr(exc))
                    break
                if ready:
                    self._drain()
                self._flush_pending()
                self.stat_set("watches", len(self._wd_path))
        finally:
            self._close_fd(fd)

    def stop(self) -> None:
        super().stop()
        self._pending.clear()

    def _close_fd(self, fd: int) -> None:
        try:
            os.close(fd)
        except OSError:
            pass
        self._fd = None
        self._wd_path.clear()

    # ------------------------------------------------------------ watch 注册
    def _register_all(self) -> None:
        for root in self.dirs:
            if self.stopping:
                return
            if not os.path.isdir(root):
                self.error("FIM 监控目录不存在，跳过", path=root)
                continue
            self._register_tree(root)
        self.stat_set("watches", len(self._wd_path))

    def _register_tree(self, root: str) -> None:
        """递归注册目录（不跟随符号链接，避免环）。"""
        for dirpath, dirnames, _ in os.walk(root, followlinks=False):
            if self.stopping:
                return
            if len(self._wd_path) >= self.max_watches:
                if not self._watch_warned:
                    self._watch_warned = True
                    self.error("FIM watch 数量达到上限", limit=self.max_watches)
                return
            self._add_watch(dirpath)
            dirnames[:] = [
                name for name in dirnames if not os.path.islink(os.path.join(dirpath, name))
            ]

    def _add_watch(self, path: str) -> int | None:
        if self._fd is None or self._libc is None:
            return None
        if len(self._wd_path) >= self.max_watches:
            return None
        try:
            wd = self._libc.inotify_add_watch(
                self._fd, path.encode("utf-8", "replace"), WATCH_MASK
            )
        except (OSError, ValueError) as exc:
            self.error("inotify_add_watch 异常", path=path, exc=repr(exc))
            return None
        if wd < 0:
            errno = ctypes.get_errno()
            # 权限/目录消失属正常降级，DEBUG 级即可
            log.debug("inotify_add_watch 失败", path=path, errno=errno)
            return None
        self._wd_path[wd] = path
        return wd

    # ------------------------------------------------------------ 事件读取
    def _drain(self) -> None:
        """把内核队列读空（非阻塞），异常不外泄。"""
        fd = self._fd
        if fd is None:
            return
        for _ in range(64):
            try:
                buffer = os.read(fd, MAX_READ_BYTES)
            except BlockingIOError:
                return
            except OSError as exc:
                self.error("inotify 读取失败", exc=repr(exc))
                return
            if not buffer:
                return
            self._parse_events(buffer)

    def _parse_events(self, buffer: bytes) -> None:
        offset = 0
        size = len(buffer)
        while offset + EVENT_HDR <= size:
            wd, mask, cookie, name_len = struct.unpack_from("iIII", buffer, offset)
            offset += EVENT_HDR
            name = ""
            if name_len:
                raw_name = buffer[offset:offset + name_len]
                offset += name_len
                name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")
            try:
                self._handle_event(wd, mask, cookie, name)
            except Exception as exc:  # noqa: BLE001 - 单事件失败隔离
                self.error("inotify 事件处理失败", wd=wd, mask=mask, exc=repr(exc))

    def _handle_event(self, wd: int, mask: int, cookie: int, name: str) -> None:
        if mask & IN_Q_OVERFLOW:
            self.stat_add("overflow")
            self.error("inotify 队列溢出，可能丢失事件")
            return
        if mask & IN_IGNORED:
            self._wd_path.pop(wd, None)
            return
        directory = self._wd_path.get(wd)
        if directory is None:
            return
        target = os.path.join(directory, name) if name else directory
        is_dir = bool(mask & IN_ISDIR)
        if is_dir and mask & _MASK_CREATE:
            self._register_tree(target)
        kind = self._mask_to_kind(mask, name)
        if kind is None:
            return
        self._enqueue(kind, target, is_dir)

    @staticmethod
    def _mask_to_kind(mask: int, name: str) -> str | None:
        if mask & _MASK_DELETE:
            return "file_delete"
        if mask & _MASK_CREATE:
            return "file_create"
        if mask & _MASK_MODIFY:
            return "file_modify"
        if mask & IN_DELETE_SELF:
            return "file_delete"
        return None

    # ------------------------------------------------------------ 去抖与投递
    def _enqueue(self, kind: str, path: str, is_dir: bool) -> None:
        now = time.monotonic()
        slot = self._pending.get(path)
        if slot is not None and now - slot["last"] < self.debounce_s:
            slot["last"] = now
            # 去抖窗口内按优先级合并：delete > create > modify
            rank = {"file_modify": 0, "file_create": 1, "file_delete": 2}
            if rank.get(kind, 0) > rank.get(slot["kind"], 0):
                slot["kind"] = kind
            return
        self._pending[path] = {"kind": kind, "first": now, "last": now, "isdir": is_dir}

    def _flush_pending(self) -> None:
        now = time.monotonic()
        for path, slot in list(self._pending.items()):
            if now - slot["last"] < self.debounce_s:
                continue
            self._pending.pop(path, None)
            try:
                self._emit_file_event(slot["kind"], path, bool(slot["isdir"]))
            except Exception as exc:  # noqa: BLE001
                self.error("FIM 事件投递失败", path=path, exc=repr(exc))

    def _emit_file_event(self, event_type: str, path: str, is_dir: bool) -> None:
        file_info: dict[str, Any] = {
            "path": path,
            "action": {
                "file_create": "create",
                "file_modify": "modify",
                "file_delete": "delete",
            }.get(event_type, "modify"),
        }
        if event_type != "file_delete":
            try:
                st = os.stat(path)
            except OSError:
                st = None
            if st is not None:
                file_info["size"] = st.st_size
                file_info["mode"] = _mode_str(st.st_mode)
                file_info["uid"] = st.st_uid
                file_info["mtime"] = schema.to_utc(st.st_mtime)
                if stat_mod.S_ISREG(st.st_mode) and st.st_size <= self.hash_limit:
                    digest = _sha256(path)
                    if digest:
                        file_info["sha256"] = digest
        self.send(
            self.make_event(
                event_type,
                file=file_info,
                raw={"collector": "fim", "isdir": is_dir},
            )
        )
        self.stat_add(event_type)
        self.stat_add("events")

    # ------------------------------------------------------------ 基线
    def _ensure_baseline(self) -> None:
        """首次启动（baseline 表为空）才构建全量基线，避免每次重启覆盖旧基线。"""
        existing: list[dict] = []
        if self.store is not None:
            try:
                existing = self.store.baseline_all()
            except Exception as exc:  # noqa: BLE001
                self.error("读取 FIM 基线失败", exc=repr(exc))
                return
        if existing:
            log.info("FIM 基线已存在，跳过重建", entries=len(existing))
            self.stat_set("baseline_files", len(existing))
            return
        try:
            count = self.build_baseline()
            log.info("FIM 基线构建完成", files=count)
        except Exception as exc:  # noqa: BLE001
            self.error("FIM 基线构建失败", exc=repr(exc))

    def build_baseline(self) -> int:
        """全量 stat + sha256 写入 `baseline` 表，返回写入条目数。"""
        if self.store is None:
            self.error("store 未注入，无法构建 FIM 基线")
            return 0
        count = 0
        for root in self.dirs:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                if self.stopping:
                    break
                dirnames[:] = [
                    name
                    for name in dirnames
                    if not os.path.islink(os.path.join(dirpath, name))
                ]
                for filename in filenames:
                    path = os.path.join(dirpath, filename)
                    try:
                        st = os.lstat(path)
                    except OSError:
                        continue
                    if not stat_mod.S_ISREG(st.st_mode):
                        continue
                    digest = _sha256(path) if st.st_size <= self.hash_limit else None
                    try:
                        self.store.baseline_upsert(
                            {
                                "path": path,
                                "sha256": digest,
                                "mode": _mode_str(st.st_mode),
                                "uid": st.st_uid,
                                "size": st.st_size,
                                "mtime": schema.to_utc(st.st_mtime),
                            }
                        )
                    except Exception as exc:  # noqa: BLE001
                        self.error("基线写入失败", path=path, exc=repr(exc))
                        continue
                    count += 1
        self.stat_set("baseline_files", count)
        return count

    def diff_baseline(self) -> list[dict]:
        """与 baseline 表比对，返回新增/变更/删除条目（不修改基线）。"""
        if self.store is None:
            return []
        try:
            baseline = {row["path"]: row for row in self.store.baseline_all()}
        except Exception as exc:  # noqa: BLE001
            self.error("读取基线失败", exc=repr(exc))
            return []

        changes: list[dict] = []
        for root in self.dirs:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = [
                    name
                    for name in dirnames
                    if not os.path.islink(os.path.join(dirpath, name))
                ]
                for filename in filenames:
                    path = os.path.join(dirpath, filename)
                    try:
                        st = os.lstat(path)
                    except OSError:
                        continue
                    if not stat_mod.S_ISREG(st.st_mode):
                        continue
                    row = baseline.get(path)
                    if row is None:
                        changes.append(
                            {
                                "path": path,
                                "reason": "new",
                                "sha256": _sha256(path) if st.st_size <= self.hash_limit else None,
                                "size": st.st_size,
                                "mode": _mode_str(st.st_mode),
                            }
                        )
                        continue
                    reason = None
                    if int(row.get("size") or -1) != st.st_size:
                        reason = "size"
                    elif str(row.get("mode") or "") != _mode_str(st.st_mode):
                        reason = "mode"
                    elif int(row.get("uid") or -1) != st.st_uid:
                        reason = "uid"
                    current_sha = None
                    if reason is None and row.get("sha256") and st.st_size <= self.hash_limit:
                        same_mtime = str(row.get("mtime") or "") == schema.to_utc(st.st_mtime)
                        if not same_mtime:
                            current_sha = _sha256(path)
                            if current_sha != row.get("sha256"):
                                reason = "sha256"
                    if reason:
                        changes.append(
                            {
                                "path": path,
                                "reason": reason,
                                "sha256": current_sha,
                                "baseline_sha256": row.get("sha256"),
                                "size": st.st_size,
                                "mode": _mode_str(st.st_mode),
                            }
                        )

        # 删除项：基线中存在、但仍属监控目录且文件已消失
        for path, row in baseline.items():
            if not any(path == root or path.startswith(root.rstrip("/") + "/") for root in self.dirs):
                continue
            if os.path.exists(path):
                continue
            changes.append(
                {
                    "path": path,
                    "reason": "deleted",
                    "baseline_sha256": row.get("sha256"),
                    "size": 0,
                    "mode": row.get("mode"),
                }
            )
        self.stat_set("diff_changes", len(changes))
        return changes


__all__ = ["FimCollector", "inotify_supported", "IN_ISDIR", "WATCH_MASK"]
