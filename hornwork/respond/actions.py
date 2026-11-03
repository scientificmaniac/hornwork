"""处置动作执行器：6 类动作 + 审计哈希链 + 回滚。


| 动作 | Linux 命令 | 回滚 |
|---|---|---|
| quarantine_file | ``mv <path> <quarantine>/<sha256>`` + ``chmod 000`` | 移回原位 |
| kill_process | ``kill -TERM`` → 等待 3 s → ``kill -KILL`` | 无（记录 cmdline） |
| block_ip | ``iptables -I OUTPUT/INPUT -d/-s <ip> -j DROP``（带 comment 标签） | 按标签删除 |
| isolate_host | 只放行管理 IP 与 lo，其余 DROP | 删规则 |
| disable_account | ``usermod -L`` / ``passwd -l`` | ``usermod -U`` |
| collect_forensics | 打包进程树/连接/文件哈希到 ``raw/forensics/<ts>.tar.gz`` | 无需 |

- ``observe`` 只记录；``dry-run`` 只返回将执行的命令；``enforce`` 才真正执行；
- 每次执行（含 observe/dry-run）写 ``action_audit``：
  ``hash = sha256(prev_hash + "|".join(规范化字段))``，首行 ``prev_hash=""``；
- 所有外部命令统一 ``subprocess.run([...], timeout=..., check=False)``，不经过 shell。
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any

from .. import schema
from ..config import cfg_get
from ..log import get_logger

log = get_logger("respond.actions")

#: 三种执行模式
MODES: tuple[str, ...] = ("observe", "dry-run", "enforce")

#: 支持的 6 类处置动作
ACTIONS: tuple[str, ...] = (
    "quarantine_file",
    "kill_process",
    "block_ip",
    "isolate_host",
    "disable_account",
    "collect_forensics",
)

#:  的回滚动作（不是独立取证动作，等价于对应动作的 undo）
ROLLBACK_ACTIONS: tuple[str, ...] = ("restore_file",)

#: 可通过 execute() 调度的全部动作名
SUPPORTED_ACTIONS: tuple[str, ...] = ACTIONS + ROLLBACK_ACTIONS

#: 参与哈希链的行字段（顺序固定，改动会破坏历史链）
AUDIT_FIELDS: tuple[str, ...] = (
    "ts", "action_id", "case_id", "actor", "action", "target", "mode", "result",
)

_USER_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,31}$")
_CHAIN_BY_DIRECTION = {"outbound": "OUTPUT", "inbound": "INPUT"}


# ---------------------------------------------------------------------------
# 模式与审计链工具
# ---------------------------------------------------------------------------
def normalize_mode(mode: str | None) -> str:
    """模式归一：``dry_run``/``dryrun`` → ``dry-run``；未知值降级为 observe。"""
    text = str(mode or "").strip().lower().replace("_", "-")
    if text in ("dry-run", "dryrun", "dry"):
        return "dry-run"
    if text == "enforce":
        return "enforce"
    return "observe"


def _is_linux() -> bool:
    return platform.system().lower() == "linux"


def _field_values(rec: dict[str, Any]) -> list[str]:
    return [str(rec.get(key) if rec.get(key) is not None else "") for key in AUDIT_FIELDS]


def compute_hash(prev_hash: str | None, rec: dict[str, Any]) -> str:
    """审计行哈希：``sha256(prev_hash + "|".join(规范化字段))``。"""
    raw = str(prev_hash or "") + "|".join(_field_values(rec))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_chain(rows: list[dict[str, Any]]) -> tuple[bool, int | None]:
    """重算审计链；返回 ``(ok, 首个断链 seq)``，完整时 seq 为 None。"""
    ordered = sorted(rows or [], key=lambda row: int(row.get("seq") or 0))
    prev = ""
    for row in ordered:
        seq = row.get("seq")
        if str(row.get("prev_hash") or "") != prev:
            return False, seq
        if compute_hash(prev, row) != str(row.get("hash") or ""):
            return False, seq
        prev = str(row.get("hash") or "")
    return True, None


# ---------------------------------------------------------------------------
# 执行器
# ---------------------------------------------------------------------------
class ActionExecutor:
    """处置动作执行器；mode 决定"只记录 / 只演练 / 真执行"。"""

    def __init__(self, store: Any, cfg: dict | None = None):
        self.store = store
        self.cfg = cfg or {}
        self.timeout = int(cfg_get(self.cfg, "respond.action_timeout_sec", 30) or 30)
        self.quarantine_dir = Path(
            str(cfg_get(self.cfg, "respond.quarantine_dir", "/var/lib/hornwork/quarantine"))
        )
        self.raw_dir = Path(str(cfg_get(self.cfg, "general.raw_dir", "/opt/hornwork/raw")))
        self.management_ip = str(cfg_get(self.cfg, "respond.management_ip", "") or "")

    # ------------------------------------------------------------------ 入口
    def execute(self, action: str, params: dict[str, Any], mode: str = "observe") -> dict[str, Any]:
        """执行（或演练/记录）一个处置动作，写审计并返回契约结构。"""
        name = str(action or "").strip().lower().replace("-", "_")
        norm_mode = normalize_mode(mode)
        params = dict(params or {})
        action_id = f"ACT-{uuid.uuid4().hex[:12].upper()}"
        case_id = str(params.get("case_id") or "") or None

        if name not in SUPPORTED_ACTIONS:
            detail = f"未知动作: {action!r}（支持 {', '.join(SUPPORTED_ACTIONS)}）"
            log.error("未知动作", action=action)
            result = {
                "action": name, "mode": norm_mode, "ok": False, "detail": detail,
                "target": "", "rollback": {}, "action_id": action_id,
            }
            self._audit(name, "", norm_mode, "error", action_id, case_id)
            return result

        try:
            payload = self._dispatch(name, params, norm_mode, action_id)
        except Exception as exc:  # noqa: BLE001 - 单动作失败不影响调用方
            log.error("动作执行异常", action=name, error=str(exc))
            payload = {"ok": False, "detail": f"执行异常: {exc}", "target": "", "rollback": {}}

        ok = bool(payload.get("ok"))
        if ok:
            result_code = {"observe": "observed", "dry-run": "planned", "enforce": "applied"}[norm_mode]
        else:
            result_code = "error"
        self._audit(name, str(payload.get("target") or ""), norm_mode, result_code, action_id, case_id)
        result = {
            "action": name,
            "mode": norm_mode,
            "ok": ok,
            "detail": str(payload.get("detail") or ""),
            "target": str(payload.get("target") or ""),
            "rollback": dict(payload.get("rollback") or {}),
            "action_id": action_id,
        }
        log.info(
            "动作执行", action=name, mode=norm_mode, ok=ok,
            target=result["target"], action_id=action_id,
        )
        return result

    def _dispatch(self, name: str, params: dict[str, Any], mode: str,
                  action_id: str) -> dict[str, Any]:
        """按动作名把 params 映射到对应方法。"""
        if name == "quarantine_file":
            return self.quarantine_file(
                params.get("path") or params.get("file") or params.get("target"), mode, action_id
            )
        if name == "kill_process":
            return self.kill_process(params.get("pid"), mode, action_id)
        if name == "block_ip":
            return self.block_ip(
                params.get("ip"), params.get("direction", "outbound"), mode, action_id
            )
        if name == "isolate_host":
            return self.isolate_host(mode, action_id)
        if name == "disable_account":
            return self.disable_account(params.get("user"), mode, action_id)
        if name == "restore_file":
            return self.restore_file(params, mode, action_id)
        return self.collect_forensics(params, mode, action_id)

    # ------------------------------------------------------------------ 审计
    def audit_event(self, action: str, target: str = "", mode: str = "observe",
                    ok: bool = True, case_id: str | None = None) -> str:
        """给非处置类步骤（如工单状态变更）补一条审计记录，返回 action_id。"""
        action_id = f"ACT-{uuid.uuid4().hex[:12].upper()}"
        self._audit(action, str(target or ""), normalize_mode(mode), "ok" if ok else "error",
                    action_id, case_id)
        return action_id

    def _audit(self, action: str, target: str, mode: str, result: str,
               action_id: str, case_id: str | None) -> None:
        """追加一行审计记录并计算哈希链。"""
        try:
            last = self.store.audit_last() or {}
        except Exception:  # noqa: BLE001 - 存储异常不得阻断动作
            last = {}
        prev_hash = str(last.get("hash") or "")
        rec = {
            "ts": schema.utc_now(),
            "action_id": action_id,
            "case_id": case_id or "",
            "actor": "hornwork",
            "action": action,
            "target": target,
            "mode": mode,
            "result": result,
            "prev_hash": prev_hash,
        }
        rec["hash"] = compute_hash(prev_hash, rec)
        try:
            self.store.audit_append(rec)
        except Exception as exc:  # noqa: BLE001
            log.error("审计写入失败", error=str(exc), action_id=action_id)

    # ------------------------------------------------------------------ 命令执行
    def _run(self, cmd: list[str], timeout: int | None = None) -> dict[str, Any]:
        """执行外部命令：列表参数、check=False、捕获输出。"""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "rc": None, "stdout": "", "stderr": str(exc), "cmd": cmd}
        return {
            "ok": proc.returncode == 0,
            "rc": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "cmd": cmd,
        }

    @staticmethod
    def _fail(detail: str, target: str = "") -> dict[str, Any]:
        return {"ok": False, "detail": detail, "target": target, "rollback": {}}

    # ------------------------------------------------------------------ 1) 文件隔离
    def quarantine_file(self, path: Any, mode: str = "observe",
                        action_id: str | None = None) -> dict[str, Any]:
        """把样本移入隔离目录并置 000 权限（enforce 才真正落盘）。"""
        action_id = action_id or f"ACT-{uuid.uuid4().hex[:12].upper()}"
        if not path:
            return self._fail("quarantine_file 缺少参数 path")
        target = str(path)
        src = Path(target)
        if mode == "observe":
            return {
                "ok": True,
                "detail": "observe：将把文件移入隔离目录（未执行）",
                "target": target,
                "rollback": {},
            }
        if mode == "dry-run":
            dest = self.quarantine_dir / "<sha256>"
            return {
                "ok": True,
                "detail": f"dry-run: ['mv', '-f', '{target}', '{dest}'] ; ['chmod', '000', ...]",
                "target": target,
                "rollback": {"kind": "quarantine_file", "src": target, "dst": str(dest)},
            }
        # enforce
        if not src.is_file():
            return self._fail(f"文件不存在或不是普通文件: {target}", target)
        try:
            digest = schema.sha256_file(str(src))
            orig_mode = int(src.stat().st_mode & 0o7777)
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            dest = self.quarantine_dir / digest
            if dest.exists():
                dest = self.quarantine_dir / f"{digest}-{action_id}"
            shutil.move(str(src), str(dest))
            try:
                os.chmod(dest, 0o000)
            except OSError:
                pass
        except OSError as exc:
            return self._fail(f"隔离失败: {exc}", target)
        return {
            "ok": True,
            "detail": f"已隔离到 {dest}（sha256={digest}）",
            "target": target,
            "rollback": {
                "kind": "quarantine_file",
                "src": target,
                "dst": str(dest),
                "orig_mode": orig_mode,
                "sha256": digest,
            },
        }

    # ------------------------------------------------------------------ 2) 杀进程
    def kill_process(self, pid: Any, mode: str = "observe",
                     action_id: str | None = None) -> dict[str, Any]:
        """TERM → 3 s → KILL 两阶段终止进程（记录 cmdline 备查）。"""
        action_id = action_id or f"ACT-{uuid.uuid4().hex[:12].upper()}"
        try:
            pid_int = int(str(pid).strip())
        except (TypeError, ValueError):
            return self._fail(f"kill_process 缺少合法 pid: {pid!r}")
        if pid_int <= 1:
            return self._fail(f"拒绝对 pid={pid_int} 执行（1 号/非法进程）", str(pid_int))
        target = str(pid_int)
        cmdline = self._read_cmdline(pid_int)
        cmds = [
            ["kill", "-TERM", target],
            ["kill", "-KILL", target],
        ]
        if mode == "observe":
            return {
                "ok": True,
                "detail": f"observe：将对 pid={target} 执行 TERM→3s→KILL（cmdline={cmdline or '未知'}）",
                "target": target,
                "rollback": {},
            }
        if mode == "dry-run":
            return {
                "ok": True,
                "detail": "dry-run: ['kill', '-TERM', '%s'] → 等待 3s → ['kill', '-KILL', '%s']" % (target, target),
                "target": target,
                "rollback": {},
            }
        if not _is_linux():
            return self._fail("kill_process enforce 仅在 Linux 支持", target)
        first = self._run(cmds[0])
        if not first["ok"] and "No such process" not in first["stderr"]:
            return self._fail(f"kill -TERM 失败: {first['stderr'].strip()}", target)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            if not self._pid_alive(pid_int):
                break
            time.sleep(0.2)
        if self._pid_alive(pid_int):
            second = self._run(cmds[1])
            if not second["ok"] and "No such process" not in second["stderr"]:
                return self._fail(f"kill -KILL 失败: {second['stderr'].strip()}", target)
        return {
            "ok": True,
            "detail": f"已终止 pid={target}（cmdline={cmdline or '未知'}）",
            "target": target,
            "rollback": {},
        }

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    @staticmethod
    def _read_cmdline(pid: int) -> str:
        """尽量读取 /proc/<pid>/cmdline（非 Linux 返回空串）。"""
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return ""
        return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()

    # ------------------------------------------------------------------ 3) 封禁 IP
    def block_ip(self, ip: Any, direction: str = "outbound", mode: str = "observe",
                 action_id: str | None = None) -> dict[str, Any]:
        """按方向封禁单个 IP，iptables 规则带 ``hornwork:<action_id>`` 注释。"""
        action_id = action_id or f"ACT-{uuid.uuid4().hex[:12].upper()}"
        if not ip:
            return self._fail("block_ip 缺少参数 ip")
        try:
            addr = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError:
            return self._fail(f"非法 IP: {ip!r}", str(ip))
        direction = str(direction or "outbound").lower()
        if direction not in _CHAIN_BY_DIRECTION:
            direction = "outbound"
        chain = _CHAIN_BY_DIRECTION[direction]
        flag = "-d" if direction == "outbound" else "-s"
        comment = f"hornwork:{action_id}"
        cmd = [
            "iptables", "-w", "-I", chain, flag, addr,
            "-m", "comment", "--comment", comment, "-j", "DROP",
        ]
        delete_cmd = [("-D" if arg == "-I" else arg) for arg in cmd]
        target = addr
        if mode == "observe":
            return {
                "ok": True,
                "detail": f"observe：将封禁 {addr}（{direction}）",
                "target": target,
                "rollback": {},
            }
        if mode == "dry-run":
            return {
                "ok": True,
                "detail": "dry-run: " + " ".join(shlex.quote(a) for a in cmd),
                "target": target,
                "rollback": {"kind": "block_ip", "ip": addr, "direction": direction,
                             "chain": chain, "comment": comment, "delete": delete_cmd},
            }
        if not _is_linux():
            return self._fail("block_ip enforce 仅在 Linux 支持（需要 iptables）", target)
        res = self._run(cmd)
        if not res["ok"]:
            return self._fail(f"iptables 封禁失败: {res['stderr'].strip()}", target)
        return {
            "ok": True,
            "detail": f"已封禁 {addr}（{direction}，comment={comment}）",
            "target": target,
            "rollback": {"kind": "block_ip", "ip": addr, "direction": direction,
                         "chain": chain, "comment": comment, "delete": delete_cmd},
        }

    # ------------------------------------------------------------------ 4) 主机隔离
    def _isolate_commands(self, comment: str) -> list[list[str]]:
        """生成隔离规则命令序列（先插 DROP，再插放行规则，最后插入的排最前）。"""
        cmds: list[list[str]] = []

        def add(chain: str, spec: list[str]) -> None:
            idx = spec.index("-j") if "-j" in spec else len(spec)
            cmds.append(
                ["iptables", "-w", "-I", chain]
                + spec[:idx]
                + ["-m", "comment", "--comment", comment]
                + spec[idx:]
            )

        add("INPUT", ["-j", "DROP"])
        add("OUTPUT", ["-j", "DROP"])
        add("INPUT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        add("OUTPUT", ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        add("INPUT", ["-i", "lo", "-j", "ACCEPT"])
        add("OUTPUT", ["-o", "lo", "-j", "ACCEPT"])
        mgmt = self.management_ip.strip()
        if mgmt:
            try:
                mgmt = str(ipaddress.ip_address(mgmt))
            except ValueError:
                log.warn("管理 IP 配置非法，隔离时忽略放行", management_ip=mgmt)
                mgmt = ""
        if mgmt:
            add("INPUT", ["-s", mgmt, "-j", "ACCEPT"])
            add("OUTPUT", ["-d", mgmt, "-j", "ACCEPT"])
        return cmds

    def isolate_host(self, mode: str = "observe",
                     action_id: str | None = None) -> dict[str, Any]:
        """隔离主机：只放行 lo、已建立连接与管理 IP，其余 DROP。"""
        action_id = action_id or f"ACT-{uuid.uuid4().hex[:12].upper()}"
        comment = f"hornwork:{action_id}"
        cmds = self._isolate_commands(comment)
        target = str(schema.host_info(self.cfg).get("host_id") or "localhost")
        rollback = {"kind": "isolate_host", "comment": comment, "comments": [comment],
                    "commands": cmds, "management_ip": self.management_ip}
        if mode == "observe":
            return {
                "ok": True,
                "detail": f"observe：将隔离主机（{len(cmds)} 条 iptables 规则，未执行）",
                "target": target,
                "rollback": {},
            }
        if mode == "dry-run":
            return {
                "ok": True,
                "detail": "dry-run: " + " ; ".join(
                    " ".join(shlex.quote(a) for a in cmd) for cmd in cmds
                ),
                "target": target,
                "rollback": rollback,
            }
        if not _is_linux():
            return self._fail("isolate_host enforce 仅在 Linux 支持（需要 iptables）", target)
        applied: list[list[str]] = []
        for cmd in cmds:
            res = self._run(cmd)
            if not res["ok"]:
                rollback["commands"] = applied
                return {
                    "ok": False,
                    "detail": f"隔离规则下发失败: {res['stderr'].strip()}（已下发 {len(applied)} 条）",
                    "target": target,
                    "rollback": rollback,
                }
            applied.append(cmd)
        return {
            "ok": True,
            "detail": f"已隔离主机，下发 {len(applied)} 条 iptables 规则（comment={comment}）",
            "target": target,
            "rollback": rollback,
        }

    # ------------------------------------------------------------------ 5) 停用账号
    def disable_account(self, user: Any, mode: str = "observe",
                        action_id: str | None = None) -> dict[str, Any]:
        """锁定账号（usermod -L，失败回落 passwd -l）。"""
        action_id = action_id or f"ACT-{uuid.uuid4().hex[:12].upper()}"
        name = str(user or "").strip()
        if not name or not _USER_RE.match(name):
            return self._fail(f"disable_account 用户名非法: {user!r}", name)
        primary = ["usermod", "-L", name]
        fallback = ["passwd", "-l", name]
        rollback = {"kind": "disable_account", "user": name,
                    "unlock": [["usermod", "-U", name], ["passwd", "-u", name]]}
        if mode == "observe":
            return {
                "ok": True,
                "detail": f"observe：将锁定账号 {name}（未执行）",
                "target": name,
                "rollback": {},
            }
        if mode == "dry-run":
            return {
                "ok": True,
                "detail": "dry-run: " + " ".join(primary) + f"（失败回落 {' '.join(fallback)}）",
                "target": name,
                "rollback": rollback,
            }
        if not _is_linux():
            return self._fail("disable_account enforce 仅在 Linux 支持", name)
        res = self._run(primary)
        if not res["ok"]:
            res = self._run(fallback)
        if not res["ok"]:
            return self._fail(f"账号锁定失败: {res['stderr'].strip()}", name)
        return {"ok": True, "detail": f"已锁定账号 {name}", "target": name, "rollback": rollback}

    # ------------------------------------------------------------------ 6) 取证打包
    def collect_forensics(self, params: dict[str, Any] | None = None, mode: str = "observe",
                          action_id: str | None = None) -> dict[str, Any]:
        """打包进程树、连接表、文件哈希与元数据到 tar.gz。"""
        action_id = action_id or f"ACT-{uuid.uuid4().hex[:12].upper()}"
        params = dict(params or {})
        stamp = schema.utc_now().replace(":", "-").replace(".", "-")
        dest = self.raw_dir / "forensics" / f"{stamp}.tar.gz"
        paths = self._forensics_paths(params)
        if mode == "observe":
            return {
                "ok": True,
                "detail": f"observe：将打包取证材料到 {dest}（进程树/连接/文件哈希，未执行）",
                "target": str(dest),
                "rollback": {},
            }
        if mode == "dry-run":
            cmds = [
                ["ps", "-eo", "pid,ppid,user,stat,etimes,args"],
                ["ss", "-tunap"],
                ["tar", "-czf", str(dest), "proc_tree.txt", "connections.txt", "file_hashes.txt", "meta.json"],
            ]
            return {
                "ok": True,
                "detail": "dry-run: " + " ; ".join(
                    " ".join(shlex.quote(a) for a in cmd) for cmd in cmds
                ),
                "target": str(dest),
                "rollback": {},
            }
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            meta = {
                "action_id": action_id,
                "host": schema.host_info(self.cfg),
                "ts": schema.utc_now(),
                "pid": params.get("pid"),
                "paths": paths,
            }
            with tarfile.open(dest, "w:gz") as tar:
                self._tar_add_bytes(tar, "proc_tree.txt", self._proc_tree_text().encode("utf-8"))
                self._tar_add_bytes(tar, "connections.txt", self._connections_text().encode("utf-8"))
                self._tar_add_bytes(tar, "file_hashes.txt", self._file_hashes_text(paths).encode("utf-8"))
                self._tar_add_bytes(
                    tar, "meta.json", (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                )
        except (OSError, tarfile.TarError) as exc:
            return self._fail(f"取证打包失败: {exc}", str(dest))
        size = dest.stat().st_size if dest.exists() else 0
        return {
            "ok": True,
            "detail": f"取证包已生成 {dest}（{size} 字节）",
            "target": str(dest),
            "rollback": {},
        }

    def _forensics_paths(self, params: dict[str, Any]) -> list[str]:
        raw = params.get("paths")
        if isinstance(raw, (list, tuple)):
            return [str(p) for p in raw if str(p).strip()]
        if raw:
            return [str(raw)]
        if params.get("path"):
            return [str(params["path"])]
        return []

    @staticmethod
    def _tar_add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(data))

    def _proc_tree_text(self) -> str:
        """进程树：优先 ps，回落 /proc 快照。"""
        res = self._run(["ps", "-eo", "pid,ppid,user,stat,etimes,args"], timeout=10)
        if res["ok"] and res["stdout"].strip():
            return res["stdout"]
        lines = ["# ps 不可用，以下为 /proc 快照（pid ppid comm cmdline）"]
        proc = Path("/proc")
        if proc.is_dir():
            try:
                names = sorted((p for p in proc.iterdir() if p.name.isdigit()), key=lambda p: int(p.name))
            except OSError:
                names = []
            for entry in names[:500]:
                try:
                    comm = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
                    status = (entry / "status").read_text(encoding="utf-8", errors="replace")
                    ppid = ""
                    for line in status.splitlines():
                        if line.startswith("PPid:"):
                            ppid = line.split(":", 1)[1].strip()
                            break
                    cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode(
                        "utf-8", "replace"
                    ).strip()
                    lines.append(f"{entry.name} {ppid} {comm} {cmdline}")
                except OSError:
                    continue
        else:
            lines.append(f"# 当前平台 {platform.system()} 无 /proc")
        return "\n".join(lines) + "\n"

    def _connections_text(self) -> str:
        """连接表：优先 ss，回落 /proc/net/{tcp,tcp6,udp,udp6}。"""
        res = self._run(["ss", "-tunap"], timeout=10)
        if res["ok"] and res["stdout"].strip():
            return res["stdout"]
        chunks: list[str] = [f"# ss 不可用，以下为 /proc/net 快照（平台 {platform.system()}）"]
        net = Path("/proc/net")
        for name in ("tcp", "tcp6", "udp", "udp6"):
            path = net / name
            try:
                chunks.append(f"## {path}")
                chunks.append(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
        return "\n".join(chunks) + "\n"

    def _file_hashes_text(self, paths: list[str]) -> str:
        lines: list[str] = []
        for item in paths:
            path = Path(item)
            try:
                stat = path.stat()
                digest = schema.sha256_file(str(path)) if path.is_file() else "-"
                lines.append(f"{digest}  {stat.st_size}  {stat.st_mode & 0o7777:04o}  {item}")
            except OSError as exc:
                lines.append(f"-  -  -  {item}  (error: {exc})")
        if not lines:
            lines.append("# 未指定待哈希文件")
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------ 回滚
    def restore_file(self, params: dict[str, Any] | None = None, mode: str = "observe",
                     action_id: str | None = None) -> dict[str, Any]:
        """ 的 ``restore_file``：按 quarantine_file 的回滚信息恢复文件。"""
        action_id = action_id or f"ACT-{uuid.uuid4().hex[:12].upper()}"
        params = dict(params or {})
        rollback = dict(params.get("rollback") or {})
        if not rollback:
            rollback = {
                "kind": "quarantine_file",
                "src": params.get("src") or params.get("path"),
                "dst": params.get("dst"),
                "orig_mode": params.get("orig_mode"),
            }
        if not rollback.get("kind"):
            rollback["kind"] = "quarantine_file"
        if not rollback.get("src") or not rollback.get("dst"):
            return self._fail("restore_file 需要 rollback（src/dst）或 params 里的 src/dst")
        return self._undo_quarantine(rollback, mode)

    def undo(self, rollback: dict[str, Any], mode: str = "observe") -> dict[str, Any]:
        """按回滚信息恢复现场（观察/演练只描述，enforce 才真执行）。"""
        norm_mode = normalize_mode(mode)
        rollback = dict(rollback or {})
        kind = str(rollback.get("kind") or "").strip().lower().replace("-", "_")
        action_id = f"ACT-{uuid.uuid4().hex[:12].upper()}"
        target = str(
            rollback.get("src") or rollback.get("ip") or rollback.get("user")
            or rollback.get("dst") or rollback.get("comment") or ""
        )
        if not kind:
            payload = self._fail("回滚信息缺少 kind")
        elif kind == "quarantine_file":
            payload = self._undo_quarantine(rollback, norm_mode)
        elif kind == "block_ip":
            payload = self._undo_block_ip(rollback, norm_mode)
        elif kind == "isolate_host":
            payload = self._undo_isolate(rollback, norm_mode)
        elif kind == "disable_account":
            payload = self._undo_disable_account(rollback, norm_mode)
        elif kind in ("kill_process", "collect_forensics"):
            payload = {"ok": True, "detail": "该动作无需回滚（仅记录）", "target": target, "rollback": {}}
        else:
            payload = self._fail(f"不支持的回滚类型: {kind}", target)

        ok = bool(payload.get("ok"))
        result_code = "ok" if ok else "error"
        self._audit(f"undo:{kind or 'unknown'}", str(payload.get("target") or target),
                    norm_mode, result_code, action_id, None)
        return {
            "action": f"undo:{kind}" if kind else "undo",
            "mode": norm_mode,
            "ok": ok,
            "detail": str(payload.get("detail") or ""),
            "target": str(payload.get("target") or target),
            "rollback": dict(payload.get("rollback") or {}),
            "action_id": action_id,
        }

    def _undo_quarantine(self, rollback: dict[str, Any], mode: str) -> dict[str, Any]:
        src = str(rollback.get("src") or "")
        dst = str(rollback.get("dst") or "")
        if not src or not dst:
            return self._fail("回滚信息缺少 src/dst", src or dst)
        cmd_mv = ["mv", "-f", dst, src]
        cmd_chmod = ["chmod", oct(int(rollback.get("orig_mode") or 0o644))[2:], src]
        if mode == "observe":
            return {"ok": True, "detail": f"observe：将把 {dst} 移回 {src}（未执行）",
                    "target": src, "rollback": {}}
        if mode == "dry-run":
            return {"ok": True, "detail": f"dry-run: {cmd_mv} ; {cmd_chmod}",
                    "target": src, "rollback": {}}
        if not Path(dst).is_file():
            return self._fail(f"隔离文件不存在: {dst}", src)
        try:
            Path(src).parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(dst, 0o600)
            except OSError:
                pass
            shutil.move(dst, src)
            orig = int(rollback.get("orig_mode") or 0o644)
            try:
                os.chmod(src, orig)
            except OSError:
                pass
        except OSError as exc:
            return self._fail(f"恢复失败: {exc}", src)
        return {"ok": True, "detail": f"已恢复 {src}", "target": src, "rollback": {}}

    def _undo_block_ip(self, rollback: dict[str, Any], mode: str) -> dict[str, Any]:
        delete = list(rollback.get("delete") or [])
        comment = str(rollback.get("comment") or "")
        chain = str(rollback.get("chain") or "OUTPUT")
        target = str(rollback.get("ip") or "")
        if not delete:
            delete = ["iptables", "-w", "-D", chain, "-d" if chain == "OUTPUT" else "-s",
                      target, "-m", "comment", "--comment", comment, "-j", "DROP"]
        if mode == "observe":
            return {"ok": True, "detail": f"observe：将删除封禁规则（未执行）", "target": target,
                    "rollback": {}}
        if mode == "dry-run":
            return {"ok": True, "detail": "dry-run: " + " ".join(shlex.quote(a) for a in delete),
                    "target": target, "rollback": {}}
        if not _is_linux():
            return self._fail("undo block_ip 仅在 Linux 支持", target)
        res = self._run(delete)
        if not res["ok"] and comment:
            # 精确删除失败时按 comment 标签兜底清扫
            swept = self._sweep_comment(chain, comment)
            if not swept:
                return self._fail(f"删除封禁规则失败: {res['stderr'].strip()}", target)
        return {"ok": True, "detail": f"已删除封禁规则 {target}", "target": target, "rollback": {}}

    def _sweep_comment(self, chain: str, comment: str) -> int:
        """按 comment 标签清扫某条链上的规则，返回删除条数。"""
        listed = self._run(["iptables", "-w", "-S", chain], timeout=10)
        if not listed["ok"]:
            return 0
        removed = 0
        for line in listed["stdout"].splitlines():
            line = line.strip()
            if "--comment" not in line or comment not in line:
                continue
            try:
                parts = shlex.split(line)
            except ValueError:
                continue
            if not parts or parts[0] != "-A":
                continue
            if self._run(["iptables", "-w", "-D"] + parts[1:])["ok"]:
                removed += 1
        return removed

    def _undo_isolate(self, rollback: dict[str, Any], mode: str) -> dict[str, Any]:
        comments = [str(c) for c in (rollback.get("comments") or []) if c]
        if not comments and rollback.get("comment"):
            comments = [str(rollback["comment"])]
        target = str(rollback.get("management_ip") or "") or "isolate_host"
        if not comments:
            return self._fail("回滚信息缺少 comment 标签", target)
        planned = [f"iptables -w -S <chain> | 匹配 --comment {c} → iptables -w -D <chain> <rule>" for c in comments]
        if mode == "observe":
            return {"ok": True, "detail": "observe：将按 comment 标签删除隔离规则（未执行）",
                    "target": target, "rollback": {}}
        if mode == "dry-run":
            return {"ok": True, "detail": "dry-run: " + " ; ".join(planned),
                    "target": target, "rollback": {}}
        if not _is_linux():
            return self._fail("undo isolate_host 仅在 Linux 支持", target)
        removed = 0
        for comment in comments:
            for chain in ("INPUT", "OUTPUT", "FORWARD"):
                removed += self._sweep_comment(chain, comment)
        if removed == 0:
            return self._fail("未找到可删除的隔离规则（可能已恢复）", target)
        return {"ok": True, "detail": f"已删除 {removed} 条隔离规则", "target": target, "rollback": {}}

    def _undo_disable_account(self, rollback: dict[str, Any], mode: str) -> dict[str, Any]:
        user = str(rollback.get("user") or "")
        if not user:
            return self._fail("回滚信息缺少 user")
        unlock = [list(cmd) for cmd in (rollback.get("unlock") or [])]
        if not unlock:
            unlock = [["usermod", "-U", user], ["passwd", "-u", user]]
        if mode == "observe":
            return {"ok": True, "detail": f"observe：将解锁账号 {user}（未执行）",
                    "target": user, "rollback": {}}
        if mode == "dry-run":
            return {"ok": True, "detail": "dry-run: " + " ; ".join(
                " ".join(shlex.quote(a) for a in cmd) for cmd in unlock
            ), "target": user, "rollback": {}}
        if not _is_linux():
            return self._fail("undo disable_account 仅在 Linux 支持", user)
        last_err = ""
        for cmd in unlock:
            res = self._run([str(a) for a in cmd])
            if res["ok"]:
                return {"ok": True, "detail": f"已解锁账号 {user}", "target": user, "rollback": {}}
            last_err = res["stderr"].strip()
        return self._fail(f"账号解锁失败: {last_err}", user)
