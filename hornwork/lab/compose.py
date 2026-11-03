"""compose 覆盖副本生成与命令封装（靶场编排层）。

核心原则：**覆盖不修改**——只把改写后的 compose 写到
`[lab].overrides_dir`，`/opt/vulhub` 原件永远是只读事实源。

`render_patched_compose()` 做四件事：
1. 把每个 service 的 ports 重写成 ``"<bind>:<hostport>:<cport>"``（bind 只允许
   回环/白名单地址，绝不写 0.0.0.0）；
2. 把相对 build context / bind 挂载 / env_file 改成绝对路径——覆盖副本位于
   overrides_dir，若保留相对路径会被 Docker 基于错误目录解析；
3. 追加 `x-hornwork-lab` 元数据（环境 id、原文件、端口映射、被丢弃的端口声明）；
4. 输出到 out_path（绝不写回原文件）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:  # 允许在未装 PyYAML 的开发机上 import（真正读写 compose 时才强制依赖）
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

_YAML_ERROR = yaml.YAMLError if yaml is not None else Exception

from .. import schema
from . import ports as portlib
from .runner import Result

SAFE_BIND = "127.0.0.1"
MAX_LOG_BYTES = 64 * 1024
TRUNCATE_MARK = "\n...[日志已截断]"
_UNSAFE_BINDS = {"", "0.0.0.0", "::", "[::]", "*", ":::"}


def safe_bind(bind: str | None) -> str:
    """把绑定地址收敛到安全值：空白/通配地址一律改为 127.0.0.1。"""
    text = str(bind or "").strip()
    return text if text not in _UNSAFE_BINDS else SAFE_BIND


def _abs_path(value: str, base: Path) -> str:
    """把以 ./ 或 ../ 开头的相对路径按原 compose 目录绝对化。"""
    text = str(value).strip()
    if not text or text.startswith(("/", "$")):
        return text
    if text.startswith("./") or text.startswith("../") or text == "." or text == "..":
        try:
            return str((base / text).resolve())
        except OSError:
            return text
    return text


def _absolutize(service: dict, base: Path) -> None:
    """就地修正 service 中依赖相对路径的字段（仅作用于内存副本）。"""
    build = service.get("build")
    if isinstance(build, str):
        service["build"] = _abs_path(build, base)
    elif isinstance(build, dict):
        context = build.get("context")
        if isinstance(context, str):
            build["context"] = _abs_path(context, base)

    volumes = service.get("volumes")
    if isinstance(volumes, list):
        new_volumes: list[Any] = []
        for item in volumes:
            if isinstance(item, str):
                pieces = item.split(":")
                if len(pieces) >= 2 and pieces[0] and (
                    pieces[0].startswith(".") or pieces[0].startswith("~")
                ):
                    pieces[0] = _abs_path(pieces[0], base)
                    new_volumes.append(":".join(pieces))
                else:
                    new_volumes.append(item)
            elif isinstance(item, dict):
                item = dict(item)
                source = item.get("source")
                if item.get("type") == "bind" and isinstance(source, str):
                    item["source"] = _abs_path(source, base)
                new_volumes.append(item)
            else:
                new_volumes.append(item)
        service["volumes"] = new_volumes

    env_file = service.get("env_file")
    if isinstance(env_file, str) and env_file.startswith("."):
        service["env_file"] = _abs_path(env_file, base)
    elif isinstance(env_file, list):
        service["env_file"] = [
            _abs_path(str(item), base)
            if isinstance(item, str) and item.startswith(".")
            else item
            for item in env_file
        ]


def load_compose(path: str | Path) -> dict:
    """读取原 compose（只读），返回 dict；非法内容抛 ValueError。"""
    if yaml is None:  # pragma: no cover - 部署环境有 PyYAML
        raise RuntimeError("缺少 PyYAML：无法解析 docker-compose.yml")
    raw = Path(str(path))
    try:
        data = yaml.safe_load(raw.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"读取 compose 失败 {raw}: {exc}") from exc
    except _YAML_ERROR as exc:
        raise ValueError(f"compose YAML 解析失败 {raw}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("services"), dict):
        raise ValueError(f"compose 缺少 services 段: {raw}")
    return data


def render_patched_compose(
    entry: dict, out_path: str, bind: str, port_map: dict[int, int]
) -> str:
    """生成端口重写后的 compose 副本，返回副本路径。绝不修改原文件。"""
    source = Path(str((entry or {}).get("compose_path") or ""))
    if not source.is_file():
        raise ValueError(f"原 compose 不存在: {source}")
    doc = load_compose(source)
    bind = safe_bind(bind)
    mapping: dict[int, int] = {}
    for key, val in (port_map or {}).items():
        try:
            mapping[int(key)] = int(val)
        except (TypeError, ValueError):
            continue

    dropped: list[str] = []
    resolved: dict[str, int] = {}
    services = doc.get("services") or {}
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        raw_ports = service.get("ports")
        if raw_ports is None:
            continue
        if not isinstance(raw_ports, list):
            dropped.append(f"{name}: ports 不是列表")
            service.pop("ports", None)
            continue
        new_ports: list[str] = []
        for spec in raw_ports:
            parsed = portlib.parse_port_spec(spec)
            if parsed is None:
                # 无法安全解析（区间/非法值）就丢弃，避免 Docker 按原声明绑 0.0.0.0
                dropped.append(f"{name}: {spec!r}")
                continue
            _declared_bind, declared_host, container = parsed
            host = mapping.get(container)
            if host is None:
                host = declared_host if declared_host else container
            new_ports.append(f"{bind}:{int(host)}:{int(container)}")
            resolved[str(container)] = int(host)
        if new_ports:
            service["ports"] = new_ports
        else:
            service.pop("ports", None)
        _absolutize(service, source.parent)

    doc["x-hornwork-lab"] = {
        "env_id": str((entry or {}).get("env_id") or ""),
        "source_compose": str(source),
        "generated_at": schema.utc_now(),
        "bind": bind,
        "port_map": resolved,
        "dropped_ports": dropped[:50],
    }

    out = Path(str(out_path))
    out.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, default_flow_style=False)
    out.write_text(text, encoding="utf-8")
    return str(out)


# ---------------------------------------------------------------------------
# compose 子命令封装
# ---------------------------------------------------------------------------
def compose_up(runner, compose_path, timeout) -> Result:
    """`docker compose up -d`。"""
    return runner.compose(str(compose_path), "up", "-d", "--remove-orphans", timeout=int(timeout))


def compose_down(runner, compose_path, keep_volume: bool = False, timeout: int = 120) -> Result:
    """`docker compose down [-v] --remove-orphans`。"""
    args = ["down", "--remove-orphans"]
    if not keep_volume:
        args.insert(1, "-v")
    return runner.compose(str(compose_path), *args, timeout=int(timeout))


def compose_ps(runner, compose_path, timeout: int = 60) -> list[dict]:
    """`docker compose ps --format json`，逐行 JSON 解析成 dict 列表。"""
    res = runner.compose(str(compose_path), "ps", "--format", "json", timeout=int(timeout))
    if not res.ok:
        return []
    rows: list[dict] = []
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def compose_logs(runner, compose_path, tail: int = 100, timeout: int = 60) -> str:
    """`docker compose logs --tail N`，返回截断到 64 KB 的文本。"""
    res = runner.compose(
        str(compose_path), "logs", "--tail", str(int(tail)), timeout=int(timeout)
    )
    text = (res.stdout or "") + (("\n" + res.stderr) if res.stderr else "")
    encoded = text.encode("utf-8", "replace")
    if len(encoded) > MAX_LOG_BYTES:
        text = encoded[:MAX_LOG_BYTES].decode("utf-8", "replace") + TRUNCATE_MARK
    return text
