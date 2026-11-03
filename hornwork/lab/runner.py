"""命令执行器（靶场编排层，IF-17 的执行端）。

两种后端：
- ``lab.backend = "local"``：单机部署模式，容器直接跑在本机 Docker 上；
- ``lab.backend = "ssh"``：双机拓扑，防护主机用 ssh BatchMode 子进程在 靶场主机执行，
  远端路径按 [lab.ssh] 的 remote_vulhub_root / remote_overrides_dir 映射。

设计约束：
- 只负责"拼命令 + 执行 + 返回结构化 Result"，不做业务判断；
- 每次执行都带超时，超时返回 rc=124；命令缺失返回 rc=127；
- 重试策略由调用方指定（retries），只在失败时重试；
- 所有子进程调用都在函数体内，模块 import 期无副作用（Windows 可 import）。
"""

from __future__ import annotations

import posixpath
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..config import cfg_get
from ..log import get_logger

log = get_logger("lab.runner")

RC_NOT_FOUND = 127
RC_TIMEOUT = 124


@dataclass
class Result:
    """一次命令执行的结果。"""

    ok: bool
    rc: int
    stdout: str
    stderr: str
    elapsed_ms: int
    cmd: list[str] = field(default_factory=list)

    def tail(self, lines: int = 40, limit: int = 8000) -> str:
        """取 stderr 优先的尾部若干行，便于写进 lab_run.detail。"""
        text = (self.stderr or "").strip() or (self.stdout or "").strip()
        if not text:
            return ""
        rows = text.splitlines()[-max(1, int(lines)):]
        return "\n".join(rows)[-max(1, int(limit)):]

    def brief(self) -> str:
        return f"rc={self.rc} elapsed={self.elapsed_ms}ms"


class CommandRunner:
    """按配置执行本地或 ssh 命令；compose() 统一追加 `docker compose -f -p`。"""

    def __init__(self, cfg: dict):
        self.cfg = cfg or {}
        self.backend = str(cfg_get(self.cfg, "lab.backend", "local") or "local").strip().lower()
        self.remote = self.backend == "ssh"
        self.vulhub_root = str(cfg_get(self.cfg, "lab.vulhub_root", "/opt/vulhub"))
        self.overrides_dir = str(cfg_get(self.cfg, "lab.overrides_dir", "/opt/lab/overrides"))
        ssh = cfg_get(self.cfg, "lab.ssh", {}) or {}
        if not isinstance(ssh, dict):
            ssh = {}
        self.ssh_host = str(ssh.get("host") or "").strip()
        self.ssh_user = str(ssh.get("user") or "lab").strip() or "lab"
        self.ssh_key = str(Path(str(ssh.get("key") or "~/.ssh/id_ed25519_lab")).expanduser())
        try:
            self.connect_timeout = max(1, int(ssh.get("connect_timeout") or 5))
        except (TypeError, ValueError):
            self.connect_timeout = 5
        self.remote_vulhub_root = str(ssh.get("remote_vulhub_root") or self.vulhub_root)
        self.remote_overrides_dir = str(ssh.get("remote_overrides_dir") or self.overrides_dir)
        if self.remote and not self.ssh_host:
            log.warn("lab.backend=ssh 但未配置 [lab.ssh].host，执行将失败")

    # ------------------------------------------------------------------ 执行
    def run(self, args: list[str], timeout: int = 120, retries: int = 0) -> Result:
        """执行一条命令；失败时最多重试 retries 次，返回最后一次结果。"""
        argv = [str(a) for a in (args or [])]
        if not argv:
            return Result(False, 2, "", "空命令", 0, [])
        attempts = max(0, int(retries)) + 1
        last: Result | None = None
        for attempt in range(attempts):
            last = self._run_once(argv, timeout)
            if last.ok:
                return last
            if attempt + 1 < attempts:
                log.warn(
                    "lab 命令失败，准备重试",
                    cmd=argv[:4], rc=last.rc, attempt=attempt + 1,
                )
        return last if last is not None else Result(False, 1, "", "未执行", 0, argv)

    def _run_once(self, args: list[str], timeout: int) -> Result:
        return self._execute(self._wrap(args), timeout)

    def _execute(self, cmd: list[str], timeout: int) -> Result:
        """真正执行子进程（local/ssh/scp 共用）。"""
        started = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=float(timeout), check=False
            )
        except FileNotFoundError as exc:
            return Result(
                False, RC_NOT_FOUND, "", f"命令不存在: {cmd[0]} ({exc})",
                int((time.monotonic() - started) * 1000), cmd,
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else ""
            return Result(
                False, RC_TIMEOUT, out, f"命令超时 {timeout}s: {shlex.join(cmd)[:400]}",
                int((time.monotonic() - started) * 1000), cmd,
            )
        except OSError as exc:
            return Result(
                False, 126, "", f"命令执行失败: {exc}",
                int((time.monotonic() - started) * 1000), cmd,
            )
        return Result(
            proc.returncode == 0,
            int(proc.returncode),
            proc.stdout or "",
            proc.stderr or "",
            int((time.monotonic() - started) * 1000),
            cmd,
        )

    # ------------------------------------------------------------------ ssh 包装
    def _wrap(self, args: list[str]) -> list[str]:
        """本地后端原样返回；ssh 后端包成 BatchMode 的 ssh 子进程。"""
        if not self.remote:
            return list(args)
        remote_args = [self._remote_path(a) for a in args]
        return [
            "ssh",
            "-i", self.ssh_key,
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "StrictHostKeyChecking=accept-new",
            f"{self.ssh_user}@{self.ssh_host}",
            shlex.join(remote_args),
        ]

    def _remote_path(self, value: str) -> str:
        """把 防护主机路径映射为 靶场主机路径（只命中 vulhub_root / overrides_dir 前缀）。"""
        for local, remote in (
            (self.overrides_dir, self.remote_overrides_dir),
            (self.vulhub_root, self.remote_vulhub_root),
        ):
            local_base = str(local or "").rstrip("/")
            remote_base = str(remote or "").rstrip("/")
            if not local_base or not remote_base:
                continue
            if value == local_base:
                return remote_base
            if value.startswith(local_base + "/"):
                return remote_base + value[len(local_base):]
        return value

    # ------------------------------------------------------------------ compose
    @staticmethod
    def project_name(compose_path: str) -> str:
        """由 compose 文件名派生稳定的 compose project 名。

        覆盖副本统一放在 overrides_dir 下，若用目录名做 project，多个环境会
        都叫 "overrides" 而互相覆盖；因此显式指定 `-p`。
        """
        stem = Path(str(compose_path or "")).stem.casefold()
        name = re.sub(r"[^a-z0-9_-]+", "-", stem).strip("-_")
        if not name:
            return "hornwork-lab"
        return ("hornwork-" + name)[:63].rstrip("-_")

    def compose(self, compose_path: str, *args: str, timeout: int = 120) -> Result:
        """执行 `docker compose -f <compose_path> -p <project> <args...>`。"""
        project = self.project_name(compose_path)
        cmd = ["docker", "compose", "-f", str(compose_path), "-p", project] + [str(a) for a in args]
        return self.run(cmd, timeout=timeout)

    # ------------------------------------------------------------------ 文件下发
    def push_file(self, local_path: str, remote_path: str | None = None,
                  timeout: int = 60) -> Result:
        """把本地文件推到远端（ssh 双机模式用 scp 下发覆盖副本）。

        local 后端直接返回成功（文件本来就在同一台机器上）；remote_path 为空时
        按 overrides_dir 前缀自动映射到 靶场主机路径。
        """
        if not self.remote:
            return Result(True, 0, "", "", 0, [])
        remote = str(remote_path) if remote_path else self._remote_path(str(local_path))
        # 先确保远端目录存在（靶场主机首次运行时 overrides_dir 可能还没建）
        remote_dir = posixpath.dirname(remote) or remote
        mkdir = self._execute(self._wrap(["mkdir", "-p", remote_dir]), timeout)
        if not mkdir.ok:
            return mkdir
        cmd = [
            "scp",
            "-i", self.ssh_key,
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "StrictHostKeyChecking=accept-new",
            str(local_path),
            f"{self.ssh_user}@{self.ssh_host}:{remote}",
        ]
        return self._execute(cmd, timeout)
