"""端口规划与探测（靶场编排层）。

职责：
- 解析 compose 的端口声明（短语法 "host:container"/"bind:host:container"、裸端口、
  长语法 dict），统一成 (bind, host, container)；
- 把整个 compose 的端口声明摊平成列表，供索引与端口分配使用；
- 探测宿主机已监听端口（Linux `ss -ltn`，其他平台返回空集）；
- TCP 端口连通性判断与从区间内挑选空闲端口。

约定：本模块 import 期不执行任何系统调用；Docker/ss/socket 均在函数体内调用，
因此在 Windows 开发机上 import 安全（`listening_ports()` 返回空集，
`free_mem_mb()` 等见 guard.py）。
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
from typing import Any, Iterable

# 端口声明里允许出现的协议
_PROTOCOLS = {"tcp", "udp", "sctp"}
_PORT_RE = re.compile(r"^\d{1,5}$")


def _port_int(value: Any) -> int | None:
    """把单个端口值转成 1..65535 的整数，非法返回 None。"""
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            port = value
        elif isinstance(value, str) and _PORT_RE.match(value.strip()):
            port = int(value.strip())
        else:
            return None
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _parse(spec: Any) -> tuple[str | None, int, int, str] | None:
    """把一段 compose 端口声明解析成 (bind, host, container, protocol)。

    支持：
    - 短语法："3000:3000"、"127.0.0.1:8000:80"、"[::1]:8000:80"、"3000"；
    - 带协议："8000:80/udp"；
    - 长语法：{"target": 80, "published": 8080, "host_ip": "127.0.0.1",
               "protocol": "tcp"}；
    - 裸整数（compose 只声明容器端口）与 PyYAML 1.1 六十进制陷阱
      （未加引号的 "23:23" 会被解析成整数 1403，这里尽量还原）。

    说明：compose 短语法里裸端口只声明容器端口、宿主端口由 Docker 随机分配。
    本层需要一份"可规划"的宿主端口，因此约定裸端口 host=container。
    端口区间（"8000-8005:8000-8005"）不支持，返回 None。
    """
    if spec is None or isinstance(spec, bool):
        return None

    # 裸整数：单个端口，或 PyYAML 六十进制还原
    if isinstance(spec, int):
        if 1 <= spec <= 65535:
            return None, spec, spec, "tcp"
        hi, lo = divmod(spec, 60)
        if 1 <= hi <= 65535 and 0 <= lo <= 59:
            # "23:23" → 1403，还原为 host=23 / container=23
            return None, hi, lo, "tcp"
        return None

    # 长语法
    if isinstance(spec, dict):
        target = _port_int(spec.get("target"))
        if target is None:
            return None
        host = _port_int(spec.get("published"))
        if host is None:
            host = target
        bind = str(spec.get("host_ip") or "").strip() or None
        proto = str(spec.get("protocol") or "tcp").strip().lower()
        if proto not in _PROTOCOLS:
            proto = "tcp"
        return bind, host, target, proto

    if not isinstance(spec, str):
        return None
    text = spec.strip()
    if not text:
        return None

    proto = "tcp"
    if "/" in text:
        text, _, proto_part = text.partition("/")
        proto_part = proto_part.strip().lower()
        if proto_part not in _PROTOCOLS:
            return None
        proto = proto_part
        text = text.strip()

    # IPv6 绑定地址：[::1]:8000:80
    bind: str | None = None
    if text.startswith("["):
        idx = text.find("]")
        if idx < 0:
            return None
        bind = text[1:idx] or None
        text = text[idx + 1:]
        if text.startswith(":"):
            text = text[1:]
        if not text:
            return None

    parts = text.split(":")
    if len(parts) == 1:
        port = _port_int(parts[0])
        if port is None:
            return None
        return bind, port, port, proto

    if len(parts) == 2:
        host_raw = parts[0].strip()
        container = _port_int(parts[1])
        if container is None:
            return None
        if host_raw:
            host = _port_int(host_raw)
            if host is None:
                return None
        else:
            host = container
        return bind, host, container, proto

    if len(parts) == 3:
        if bind is None:
            bind = parts[0].strip() or None
        host_raw = parts[1].strip()
        container = _port_int(parts[2])
        if container is None:
            return None
        if host_raw:
            host = _port_int(host_raw)
            if host is None:
                return None
        else:
            host = container
        return bind, host, container, proto

    return None


def parse_port_spec(spec: Any) -> tuple[str | None, int, int] | None:
    """解析单条端口声明，返回 (bind, host, container)；非法返回 None。

    bind 为 None 表示未显式声明绑定地址（交给上层用 host_bind 兜底）。
    """
    parsed = _parse(spec)
    if parsed is None:
        return None
    bind, host, container, _proto = parsed
    return bind, host, container


def service_ports(service: dict) -> list[dict]:
    """解析单个 compose service 的 ports，输出统一结构。"""
    raw = (service or {}).get("ports") or []
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for spec in raw:
        parsed = _parse(spec)
        if parsed is None:
            continue
        bind, host, container, protocol = parsed
        out.append(
            {"container": int(container), "host": int(host), "bind": bind, "protocol": protocol}
        )
    return out


def compose_ports(compose: dict) -> list[dict]:
    """摊平整个 compose 的端口声明。

    返回 [{"container":3000,"host":3000,"bind":None,"protocol":"tcp"}, ...]，
    同一 container 端口可能在多个 service 重复出现，这里保留原始顺序不去重。
    """
    services = (compose or {}).get("services") or {}
    if not isinstance(services, dict):
        return []
    out: list[dict] = []
    for _name, svc in services.items():
        if isinstance(svc, dict):
            out.extend(service_ports(svc))
    return out


def listening_ports() -> set[int]:
    """返回宿主机正在监听的 TCP 端口集合；非 Linux 或命令不可用时返回空集。"""
    if not sys.platform.startswith("linux"):
        return set()
    try:
        proc = subprocess.run(
            ["ss", "-ltn"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    ports: set[int] = set()
    for line in (proc.stdout or "").splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0].upper() != "LISTEN":
            continue
        local = fields[3]
        if ":" not in local:
            continue
        tail = local.rsplit(":", 1)[1]
        if tail.isdigit():
            port = int(tail)
            if 1 <= port <= 65535:
                ports.add(port)
    return ports


def port_free(host: str, port: int, timeout: float = 0.3) -> bool:
    """TCP 探测：端口未监听/连接被拒返回 True。

    注意：只用于 127.0.0.1 / 白名单地址，调用方必须先过 guard.check_targets。
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(float(timeout))
            return sock.connect_ex((str(host), int(port))) != 0
    except (OSError, ValueError, TypeError):
        # 地址不可解析/超时等情况，保守认为"未就绪"
        return False


def pick_port(used: Iterable[int], range_lo: int, range_hi: int) -> int | None:
    """在 [range_lo, range_hi] 内挑第一个不在 used 里的端口；耗尽返回 None。"""
    try:
        lo = int(range_lo)
        hi = int(range_hi)
    except (TypeError, ValueError):
        return None
    if hi < lo:
        lo, hi = hi, lo
    taken = {int(p) for p in used}
    for port in range(lo, hi + 1):
        if port not in taken:
            return port
    return None


def allocate_ports(
    container_ports: Iterable[int],
    used: Iterable[int],
    range_lo: int,
    range_hi: int,
) -> tuple[dict[int, int], str | None]:
    """为一组容器端口分配宿主端口。

    返回 ({container: host}, None) 或 ({已分配的部分}, 失败原因)。
    同一 container 端口只分配一次；分配结果按 container 端口升序稳定输出。
    """
    wanted: list[int] = []
    for value in container_ports:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in wanted:
            wanted.append(port)
    taken = {int(p) for p in used}
    mapping: dict[int, int] = {}
    for container in sorted(wanted):
        host = pick_port(taken, range_lo, range_hi)
        if host is None:
            return mapping, (
                f"端口区间 [{range_lo}, {range_hi}] 已耗尽（已分配 {len(mapping)}/{len(wanted)}，"
                f"占用 {len(taken)} 个）"
            )
        mapping[container] = host
        taken.add(host)
    return mapping, None
