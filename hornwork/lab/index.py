"""Vulhub 索引构建（靶场编排层）。

`vulhub-index.json` 是 labctl 的唯一事实来源：遍历
`<vulhub_root>/*/*/docker-compose.yml`，解析 services/image/ports/build，
抓 README 首段作摘要，产出可直接被 `lab list` / `vuln` 消费的 JSON。

索引条目结构（与 Lead 约定一致）::

    {"env_id": "grafana/CVE-2021-43798",
     "category": "grafana", "dir": "CVE-2021-43798",
     "compose_path": "/opt/vulhub/grafana/CVE-2021-43798/docker-compose.yml",
     "cve": "CVE-2021-43798" | None,
     "services": [{"name","image","build","ports":[{"container","host","bind"}]}],
     "images": ["vulhub/grafana:8.2.6"],
     "summary": "README 首段（≤200 字）",
     "readme_path": "/opt/vulhub/.../README.md" | None}

本模块只读 /opt/vulhub，不写；解析失败的单文件被隔离到 errors，不中断整体构建。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

try:  # 允许在未装 PyYAML 的开发机上 import（真正解析 compose 时才强制依赖）
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

_YAML_ERROR = yaml.YAMLError if yaml is not None else Exception

from .. import schema
from ..log import get_logger
from . import ports as portlib

log = get_logger("lab.index")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml")
_README_NAMES = ("README.md", "README.MD", "README.zh-cn.md", "README.zh-CN.md", "readme.md", "README")
_SUMMARY_LIMIT = 200


# ---------------------------------------------------------------------------
# README 摘要
# ---------------------------------------------------------------------------
def _read_readme(env_dir: Path) -> tuple[str, str | None]:
    """读取环境目录下第一个 README，返回 (全文, 路径)；都没有返回 ("", None)。"""
    for name in _README_NAMES:
        path = env_dir / name
        try:
            if path.is_file():
                return path.read_text(encoding="utf-8", errors="replace"), str(path)
        except OSError:
            continue
    return "", None


def _first_paragraph(text: str, limit: int = _SUMMARY_LIMIT) -> str:
    """从 Markdown 中抽首段正文：跳过标题/徽章/图片/引用/代码块，去掉链接标记。"""
    buf: list[str] = []
    in_fence = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith("```") or line.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if not line:
            if buf:
                break
            continue
        if line.startswith("#") or line.startswith(">") or line.startswith("|"):
            continue
        # 图片 / 徽章（[![alt](img)](link)）整行跳过
        if line.startswith("![") or line.startswith("[!["):
            continue
        line = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", line)
        line = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", line)
        line = re.sub(r"<[^>]+>", "", line)
        line = line.strip(" *_`>-|")
        if line:
            buf.append(line)
    summary = re.sub(r"\s+", " ", " ".join(buf)).strip()
    return summary[:limit]


# ---------------------------------------------------------------------------
# 单文件解析
# ---------------------------------------------------------------------------
def parse_compose(path: str, vulhub_root: str) -> dict | None:
    """解析单个 docker-compose.yml 为索引条目；文件非法/compose 无 services 返回 None。"""
    if yaml is None:  # pragma: no cover - 部署环境有 PyYAML
        raise RuntimeError("缺少 PyYAML：无法解析 docker-compose.yml")
    compose_path = Path(str(path))
    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, _YAML_ERROR) as exc:
        log.warn("compose 解析失败", path=str(compose_path), error=str(exc))
        return None
    if not isinstance(data, dict):
        return None
    services_raw = data.get("services")
    if not isinstance(services_raw, dict) or not services_raw:
        return None

    root = Path(str(vulhub_root))
    try:
        rel_parent = compose_path.parent.relative_to(root)
        parts = [p for p in rel_parent.parts if p not in ("", ".")]
    except ValueError:
        # compose 不在 root 下：退化为自文件名，便于单测/手工指向
        parts = [compose_path.parent.name or compose_path.stem]
    if not parts:
        parts = [compose_path.parent.name or compose_path.stem]

    env_id = "/".join(parts)
    category = parts[0]
    env_dir_name = parts[-1]

    services: list[dict[str, Any]] = []
    images: list[str] = []
    for name, svc in services_raw.items():
        svc = svc if isinstance(svc, dict) else {}
        image = svc.get("image")
        image_ref = str(image).strip() if image else None
        build_raw = svc.get("build")
        has_build = "build" in svc and build_raw is not None and build_raw is not False
        svc_ports = [
            {"container": p["container"], "host": p["host"], "bind": p["bind"]}
            for p in portlib.service_ports(svc)
        ]
        services.append(
            {
                "name": str(name),
                "image": image_ref,
                "build": bool(has_build),
                "ports": svc_ports,
            }
        )
        if image_ref and image_ref not in images:
            images.append(image_ref)

    readme_text, readme_path = _read_readme(compose_path.parent)
    summary = _first_paragraph(readme_text)

    # CVE：优先目录名，其次 README 正文
    cve = None
    for part in parts:
        found = CVE_RE.search(part)
        if found:
            cve = found.group(0).upper()
            break
    if cve is None:
        found = CVE_RE.search(readme_text or "")
        if found:
            cve = found.group(0).upper()

    return {
        "env_id": env_id,
        "category": category,
        "dir": env_dir_name,
        "compose_path": str(compose_path),
        "cve": cve,
        "services": services,
        "images": images,
        "summary": summary,
        "readme_path": readme_path,
    }


# ---------------------------------------------------------------------------
# 索引构建 / 读取
# ---------------------------------------------------------------------------
def _iter_compose_files(root: Path) -> list[Path]:
    """遍历 root 下所有 compose 文件（跳过隐藏目录），同一环境目录只保留一个。"""
    found: list[Path] = []
    seen: set[str] = set()
    for name in _COMPOSE_NAMES:
        try:
            candidates = sorted(root.rglob(name))
        except OSError:
            continue
        for path in candidates:
            try:
                rel_parent = path.parent.relative_to(root)
            except ValueError:
                continue
            if any(part.startswith(".") for part in rel_parent.parts):
                continue
            key = str(rel_parent).casefold()
            if key in seen:
                continue
            seen.add(key)
            found.append(path)
    return found


def build_index(vulhub_root: str, out_path: str) -> dict:
    """扫描 vulhub_root 生成索引 JSON，返回 {"ok","count","path","elapsed_ms","errors"}。"""
    started = time.monotonic()
    root = Path(str(vulhub_root))
    out = Path(str(out_path))
    errors: list[str] = []
    entries: list[dict] = []

    def _done(ok: bool) -> dict:
        return {
            "ok": bool(ok),
            "count": len(entries),
            "path": str(out),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "errors": errors,
        }

    if not root.is_dir():
        errors.append(f"vulhub_root 不存在或不可读: {root}")
        return _done(False)

    for compose_path in _iter_compose_files(root):
        try:
            entry = parse_compose(str(compose_path), str(root))
        except Exception as exc:  # noqa: BLE001 - 单文件失败不得中断索引
            errors.append(f"{compose_path}: {exc}")
            continue
        if entry is None:
            errors.append(f"{compose_path}: 不是有效 compose（缺少 services）")
            continue
        entries.append(entry)

    entries.sort(key=lambda item: item.get("env_id") or "")
    payload = {
        "version": 1,
        "generated_at": schema.utc_now(),
        "vulhub_root": str(root),
        "count": len(entries),
        "entries": entries,
    }
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
    except OSError as exc:
        errors.append(f"写入索引失败 {out}: {exc}")
        return _done(False)

    log.info("vulhub 索引完成", entries=len(entries), path=str(out), errors=len(errors))
    return _done(True)


def load_index(path: str) -> list[dict]:
    """读取索引 JSON，返回条目列表；文件缺失/损坏返回空列表。"""
    try:
        data = json.loads(Path(str(path)).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return []
    if isinstance(data, dict):
        raw = data.get("entries")
    elif isinstance(data, list):
        raw = data
    else:
        return []
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict) and item.get("env_id")]
