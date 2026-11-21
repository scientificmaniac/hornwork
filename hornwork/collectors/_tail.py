"""日志文件 tail 跟随：打开 / inode 轮转检测 / 完整行读取 / 半行回退。

供 auditd 与 authlog 采集器复用；差异（起始偏移、行处理、统计、报错）
通过回调注入，本模块只维护通用骨架。
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable

# 起始偏移策略：(stat, rotated, previous_inode) -> offset
StartOffset = Callable[[os.stat_result, bool, int | None], int]


class TailFollower:
    """跟随一个文本日志文件的追加内容。

    - 文件缺失时返回 False，由调用方决定重试间隔；
    - inode 变化视为轮转，重新打开并按 ``start_offset`` 决定起点；
    - 只读完整行，半行回退到行首等下次读取。
    """

    def __init__(
        self,
        path: str,
        on_line: Callable[[str], None],
        on_stat: Callable[[str], None],
        on_error: Callable[[str], None],
        start_offset: StartOffset,
        label: str = "日志",
    ) -> None:
        self.path = path
        self._on_line = on_line
        self._on_stat = on_stat
        self._on_error = on_error
        self._start_offset = start_offset
        self._label = label
        self.fh: Any = None
        self.ino: int | None = None
        self.offset = 0
        self._last_missing_warn = 0.0

    @property
    def open(self) -> bool:
        """句柄是否有效（调用方据此决定 poll 间隔）。"""
        return self.fh is not None

    def ensure_open(self) -> bool:
        """确保句柄有效并处理轮转；文件缺失返回 False。"""
        try:
            st = os.stat(self.path)
        except OSError:
            self.close()
            now = time.time()
            if now - self._last_missing_warn > 10.0:
                self._last_missing_warn = now
                self._on_error(f"{self._label}不存在，1s 后重试")
            return False

        if self.fh is not None and self.ino == st.st_ino:
            return True

        rotated = self.fh is not None or self.ino is not None
        if rotated:
            self._on_stat("rotations")
        self.close()
        try:
            handle = open(self.path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            self._on_error(f"打开{self._label}失败: {exc!r}")
            return False
        start = self._start_offset(st, rotated, self.ino)
        try:
            handle.seek(start)
        except OSError:
            start = 0
        self.fh = handle
        self.ino = st.st_ino
        self.offset = start
        return True

    def read_available(self, budget: int = 5000) -> int:
        """读取当前可读的完整行，返回本次读到的行数。"""
        handle = self.fh
        if handle is None:
            return 0
        count = 0
        while count < budget:
            pos = handle.tell()
            try:
                line = handle.readline()
            except (OSError, UnicodeDecodeError) as exc:
                self._on_error(f"{self._label}读取行失败: {exc!r}")
                break
            if not line:
                break
            if not line.endswith("\n"):
                handle.seek(pos)  # 半行：回退，等下一次读
                break
            self.offset = handle.tell()
            count += 1
            self._on_stat("lines")
            self._on_line(line.rstrip("\r\n"))
        return count

    def close(self) -> None:
        """关闭句柄并清空 inode。"""
        handle, self.fh = self.fh, None
        self.ino = None
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
