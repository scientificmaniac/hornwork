"""扫描引擎适配器协议与公共工具（扫描模块 IF-20 的提供方一侧）。

本模块只定义"引擎怎么被调度"的接口与少量纯工具函数，**不含任何业务匹配逻辑**：

- :class:`ScanContext`：一次扫描的上下文（计划 / profile / 端口规格 / 超时 / 限速 / 截止时间）；
- :class:`ScanAdapter`：引擎协议（runner 按 ``name``/``cost``/``requires`` 选择与消融）；
- 工具函数：配置读取、外部二进制探测、本机判定、子进程执行、RawResult 构造。

硬约束：

- 适配器**不得**访问数据库、不得写业务文件；临时文件用完即删；
- 所有子进程统一走 :func:`run_capture`（``subprocess.run([...], timeout=..., capture_output=True,
  text=True, check=False, shell=False)``），超时 / 缺二进制 / 非零退出码一律转成返回值，
  **绝不抛异常中断整次扫描**；
- 每条 RawResult 必须是 JSON 可序列化的普通 dict（``json.dumps`` 不抛）；
- 导入期不执行外部命令、不做文件 I/O，Windows 开发机上可安全 import。
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ...config import cfg_get
from ...log import get_logger

log = get_logger("scan.engines")

#: 统一严重级枚举（与靶场模块档案/检测模块告警同一套中文标签；``None`` 表示"非问题事实"）
SEVERITIES: tuple[str, ...] = ("严重", "高", "中", "低", "无")

#: 引擎成本等级（runner 据此做预算裁剪：quick 只跑 fast/medium）
COSTS: tuple[str, ...] = ("fast", "medium", "slow")

#: 扫描 profile 取值（与 :mod:`hornwork.scan.scheduler` 的 DEFAULT_PROFILES 对齐）
PROFILES: tuple[str, ...] = ("quick", "weekly", "full", "targeted", "verify-fix")


# ---------------------------------------------------------------------------
# 配置与二进制探测
# ---------------------------------------------------------------------------
def cfg_get_default(cfg: dict | None, dotted: str, default: Any) -> Any:
    """按点路径读配置，缺失时返回 default（薄封装 :func:`hornwork.config.cfg_get`）。

    适配器统一用它读 ``scan.nmap.bin`` 之类的键，便于单测直接传小字典。
    """
    return cfg_get(cfg or {}, dotted, default)


def cfg_int(cfg: dict | None, dotted: str, default: int) -> int:
    """读整型配置；类型非法时回退 default（不抛异常）。"""
    try:
        return int(cfg_get_default(cfg, dotted, default))
    except (TypeError, ValueError):
        return int(default)


def binary_exists(name: Any) -> bool:
    """判断一个命令名或绝对路径是否可执行（Windows 上恒为 ``False``）。

    目标运行环境是 Ubuntu，外部工具只部署在虚拟机；开发机（Windows）上返回
    ``False`` 让适配器的 ``available()`` 自然为假，避免误触子进程。
    """
    try:
        if os.name == "nt":
            return False
        text = str(name or "").strip()
        if not text:
            return False
        path = Path(os.path.expanduser(text))
        if path.is_absolute() or os.sep in text or (os.altsep and os.altsep in text):
            return path.is_file() and os.access(str(path), os.X_OK)
        return shutil.which(text) is not None
    except (OSError, ValueError):
        return False


def binary_available(cfg: dict | None, dotted: str, default: Any) -> bool:
    """配置项（命令名或路径）指向的二进制是否存在且可执行。

    例：``binary_available(cfg, "scan.nmap.bin", "nmap")``。
    """
    return binary_exists(cfg_get_default(cfg, dotted, default) or default)


# ---------------------------------------------------------------------------
# 本机判定
# ---------------------------------------------------------------------------
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def _local_addresses() -> set[str]:
    """尽力获取本机网卡地址集合（失败返回空集，绝不抛异常）。"""
    out: set[str] = set()
    try:
        hostname = socket.gethostname()
    except OSError:
        return out
    try:
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr:
                out.add(str(addr))
    except (OSError, socket.gaierror, UnicodeError):
        pass
    try:
        out.add(socket.gethostbyname(hostname))
    except (OSError, socket.gaierror, UnicodeError):
        pass
    return out


def is_local_ip(ip: Any) -> bool:
    """判断地址是否属于本机（回环 + 本机网卡地址）；非法输入返回 ``False``。"""
    try:
        text = str(ip or "").strip()
        if not text:
            return False
        if text.lower() in _LOOPBACK_NAMES:
            return True
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            return False
        if addr.is_loopback:
            return True
        return str(addr) in _local_addresses()
    except (OSError, ValueError, TypeError):
        return False


def asset_is_self(asset: dict | None) -> bool:
    """判断台账资产是否"本机"：``is_self`` 为真或以本机地址出现。"""
    if not isinstance(asset, dict):
        return False
    flag = asset.get("is_self")
    if isinstance(flag, str):
        if flag.strip().lower() in ("1", "true", "yes", "on"):
            return True
    elif flag:
        return True
    return is_local_ip(asset.get("ip"))


# ---------------------------------------------------------------------------
# 扫描上下文
# ---------------------------------------------------------------------------
@dataclass
class ScanContext:
    """一次扫描的上下文（runner 构造，适配器只读）。

    参数顺序与扫描模块契约一致：``asset, plan, profile, ports, service_detect,
    timeout_sec, rate_limit, deadline, extra``。

    - ``ports``：端口规格，取值形态 ``"top:200"`` / ``"1-65535"`` / ``"22,80,18000"`` /
      ``"declared"``（targeted、verify-fix 计划只扫台账声明端口，见
      :func:`hornwork.scan.engines.nmap_adapter.build_port_args`）；
    - ``deadline``：可选截止时间，支持 ``time.monotonic()`` 时间戳（float）、
      ``datetime`` 或 ISO8601 字符串；适配器用 :meth:`remaining_sec` 收紧超时；
    - ``extra``：可选附加参数（``tls_ports`` / ``web_targets`` / ``declared_ports`` /
      ``tmp_dir`` 等），由 runner 按计划注入。
    """

    asset: dict
    plan: dict | None = None
    profile: str = "weekly"
    ports: str = "top:200"
    service_detect: bool = True
    timeout_sec: int = 900
    rate_limit: int = 500
    deadline: float | None = None
    extra: dict | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.asset, dict):
            self.asset = dict(self.asset) if self.asset else {}
        if not isinstance(self.plan, dict):
            self.plan = dict(self.plan) if self.plan else {}
        if not isinstance(self.extra, dict):
            self.extra = dict(self.extra) if self.extra else {}
        self.ports = "" if self.ports is None else str(self.ports).strip()
        self.profile = str(self.profile or "weekly").strip() or "weekly"

    def remaining_sec(self, default: float | None = None) -> float | None:
        """按 ``deadline`` 计算剩余秒数；未设置或无法识别时返回 ``default``。"""
        deadline = self.deadline
        if deadline is None:
            return default
        try:
            if isinstance(deadline, (int, float)):
                return max(0.0, float(deadline) - time.monotonic())
            if isinstance(deadline, datetime):
                now = datetime.now(deadline.tzinfo) if deadline.tzinfo else datetime.now()
                return max(0.0, (deadline - now).total_seconds())
            if isinstance(deadline, str):
                parsed = datetime.fromisoformat(deadline.strip().replace("Z", "+00:00"))
                now = datetime.now(parsed.tzinfo) if parsed.tzinfo else datetime.now()
                return max(0.0, (parsed - now).total_seconds())
        except (TypeError, ValueError):
            return default
        return default


def clip_timeout(ctx: ScanContext, cap: float, floor: float = 5.0) -> float:
    """把 ``ctx.timeout_sec`` 夹到 ``[floor, cap]``，再按 deadline 剩余时间收紧。

    单引擎超时：nmap 120~900s、nuclei 900s、lynis/testssl 300s。
    deadline 已过时返回 ``floor``（适配器应在执行前检查剩余预算）。
    """
    try:
        value = float(ctx.timeout_sec)
    except (TypeError, ValueError, AttributeError):
        value = float(cap)
    value = min(float(cap), max(float(floor), value))
    try:
        remain = ctx.remaining_sec(None)
    except AttributeError:
        remain = None
    if remain is not None:
        value = min(value, max(1.0, float(remain)))
    return value


# ---------------------------------------------------------------------------
# 子进程执行
# ---------------------------------------------------------------------------
@dataclass
class ProcResult:
    """一次外部命令执行的结果；``error`` 非空表示根本没拿到有效输出。"""

    ok: bool
    rc: int
    stdout: str = ""
    stderr: str = ""
    error: str = ""

    def brief(self, limit: int = 300) -> str:
        """失败的简短原因（写日志用）。"""
        text = (self.error or self.stderr or "").strip()
        return text[:limit]

    def tail(self, lines: int = 20, limit: int = 1500) -> str:
        """取 stderr 优先的尾部若干行。"""
        text = (self.stderr or "").strip() or (self.stdout or "").strip()
        if not text:
            return ""
        rows = text.splitlines()[-max(1, int(lines)):]
        return "\n".join(rows)[-max(1, int(limit)):]


def run_capture(cmd: list[str], timeout: float) -> ProcResult:
    """执行外部命令并统一吞掉异常。

    - 超时 → ``ProcResult(ok=False, rc=-1, error="timeout ...")``，保留已捕获的部分输出；
    - 二进制缺失 → ``rc=127``；其它 OSError → ``rc=126``；
    - ``shell=False`` + 列表参数，天然规避命令注入与引号问题。
    """
    argv = [str(part) for part in (cmd or [])]
    if not argv:
        return ProcResult(False, 2, "", "", "empty command")
    try:
        proc = subprocess.run(
            argv,
            timeout=float(timeout),
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        err = exc.stderr if isinstance(exc.stderr, str) else ""
        return ProcResult(False, -1, out, err, f"timeout after {timeout:g}s")
    except FileNotFoundError:
        return ProcResult(False, 127, "", "", f"binary not found: {argv[0]}")
    except OSError as exc:
        return ProcResult(False, 126, "", "", f"exec failed: {exc}")
    return ProcResult(
        int(proc.returncode) == 0,
        int(proc.returncode),
        proc.stdout or "",
        proc.stderr or "",
    )


def port_list(value: Any) -> list[int]:
    """把端口声明（int / ``"443"`` / ``"443,8443"`` / ``[443, 8443]``）解析成去重端口列表。"""
    if value is None or value == "":
        return []
    if isinstance(value, (int, float)):
        items: list[Any] = [value]
    elif isinstance(value, str):
        items = [part for part in value.replace(";", ",").split(",")]
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        return []
    out: list[int] = []
    for item in items:
        try:
            port = int(str(item).strip())
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in out:
            out.append(port)
    return out


def temp_dir_for(ctx: ScanContext) -> str | None:
    """取适配器临时目录：优先 ``ctx.extra["tmp_dir"]``，否则返回 ``None``（系统临时目录）。

    允许 runner / 受限环境（如只读沙箱）指定可写目录；目录不可写时同样回退。
    """
    try:
        extra = getattr(ctx, "extra", None) or {}
        cand = extra.get("tmp_dir") if isinstance(extra, dict) else None
        if cand:
            path = Path(str(cand))
            path.mkdir(parents=True, exist_ok=True)
            if os.access(str(path), os.W_OK):
                return str(path)
    except (OSError, ValueError):
        pass
    return None


# ---------------------------------------------------------------------------
# RawResult
# ---------------------------------------------------------------------------
@runtime_checkable
class ScanAdapter(Protocol):
    """引擎适配器协议。

    四类实现同接口，收益：可并列对照、可逐个禁用作消融、换引擎不改调度与匹配、
    报告能出"引擎贡献率"表。``cost`` ∈ ``fast|medium|slow``；``requires`` 声明
    前置能力（``tcp``/``root``/``ssh``/``dpkg``/``testssl``/``nuclei``）。
    """

    name: str
    version: str
    cost: str
    requires: list[str]

    def available(self) -> bool:
        """外部二进制/宿主机能力是否就绪（不执行真实扫描）。"""
        ...

    def supports(self, asset: dict, profile: str) -> bool:
        """该资产 + 该 profile 下是否适用本引擎。"""
        ...

    def run(self, asset: dict, ctx: ScanContext) -> list[dict]:
        """执行扫描并返回 RawResult 列表（JSON 可序列化；失败返回 [] 或部分结果）。"""
        ...


def make_raw(
    engine: str,
    kind: str,
    check_id: str,
    target: Any,
    *,
    title: str = "",
    severity: str | None = None,
    evidence: dict | None = None,
    **fields: Any,
) -> dict:
    """构造一条 RawResult（统一字段，额外字段按需附加）。

    ``kind`` ∈ ``port|component|config|tls|web``（``host_summary`` 为端口扫描的收尾汇总）；
    ``severity=None`` 表示"事实"而非问题。额外字段（``comp_norm``/``version``/``cpe``/
    ``confidence``/``facts`` 等）只有非 ``None`` 时才写入，保持结果紧凑。
    """
    payload: dict[str, Any] = {
        "engine": str(engine),
        "kind": str(kind),
        "check_id": str(check_id),
        "target": target,
        "title": str(title or check_id),
        "severity": severity,
        "evidence": dict(evidence or {}),
    }
    for key, value in fields.items():
        if value is not None:
            payload[key] = value
    return payload


__all__ = [
    "COSTS",
    "PROFILES",
    "SEVERITIES",
    "ProcResult",
    "ScanAdapter",
    "ScanContext",
    "asset_is_self",
    "binary_available",
    "binary_exists",
    "cfg_get_default",
    "cfg_int",
    "clip_timeout",
    "is_local_ip",
    "make_raw",
    "port_list",
    "run_capture",
    "temp_dir_for",
]
