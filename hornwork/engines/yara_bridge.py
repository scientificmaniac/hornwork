"""libyara 封装 YaraEngine。

要点：
- `yara.compile(filepaths={文件 stem: 路径})`，同一对象在进程内常驻（避免每次扫描重编译）；
- namespace 用文件 stem，便于定位规则来源；
- `scan()` 用 `rules.match(path, externals=..., timeout=...)`，externals 含
  filename/filetype/filesize，超时取 `engines.timeout_ms.yara`（毫秒 → 秒）；
- 热加载失败时**保留旧规则**并返回带行号的错误信息；
- `import yara` 放在 try/except 内：Windows 开发机缺 yara-python 时
  `available()` 返回 False，模块 import 不报错。
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

try:  # pragma: no cover - 取决于运行环境
    import yara  # type: ignore
except Exception:  # ImportError/OSError（缺 libyara）
    yara = None  # type: ignore[assignment]

from ..config import cfg_get
from ..log import get_logger
from .base import BaseScanEngine, make_hit

log = get_logger("engines.yara")

DEFAULT_TIMEOUT_MS = 10000


def _severity_score(value: Any, default: int = 60) -> int:
    """把 YARA meta.severity 归一成 0-100 分；支持 int / 数字串 / low-medium-high 词。"""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        score = int(value)
    else:
        text = str(value or "").strip().lower()
        words = {
            "informational": 20, "info": 20, "low": 35, "medium": 60,
            "high": 80, "critical": 95,
        }
        if text in words:
            return words[text]
        try:
            score = int(float(text))
        except (TypeError, ValueError):
            return default
    if 0 <= score <= 10:  # 形如 8 的"级别"写法按 10 分制换算
        return max(0, min(100, score * 10))
    return max(0, min(100, score))


def _resolve_rule_dir(cfg: dict) -> Path:
    """定位 YARA 规则目录：配置目录存在则用它，否则回退到 `<general.rule_dir>/yara`。"""
    configured = cfg_get(cfg, "engines.yara_rule_dir", "")
    if configured and Path(str(configured)).is_dir():
        return Path(str(configured))
    base = Path(str(cfg_get(cfg, "general.rule_dir", "/opt/hornwork/rules")))
    return base / "yara"


class YaraEngine(BaseScanEngine):
    """YARA 扫描引擎（进程内常驻编译结果）。"""

    name = "yara"
    version = getattr(yara, "__version__", "unavailable") if yara is not None else "unavailable"
    cost = "medium"

    def __init__(self, cfg: dict):
        self.cfg = dict(cfg or {})
        self.rule_dir = _resolve_rule_dir(self.cfg)
        max_size_mb = int(cfg_get(self.cfg, "engines.max_size_mb", 100) or 100)
        self.max_size = max(1, max_size_mb) * 1024 * 1024
        timeout_ms = int(cfg_get(self.cfg, "engines.timeout_ms.yara", DEFAULT_TIMEOUT_MS)
                          or DEFAULT_TIMEOUT_MS)
        self.timeout_sec = max(1, int(round(timeout_ms / 1000.0)))
        self._lock = threading.Lock()
        self.rules: Any = None
        self.rule_count = 0
        self.error: str | None = None
        self._files: dict[str, str] = {}
        self.reload()

    # ------------------------------------------------------------ 编译/热加载
    def _collect_files(self) -> dict[str, str]:
        files: dict[str, str] = {}
        try:
            if not self.rule_dir.is_dir():
                return files
            for path in sorted(self.rule_dir.rglob("*.yar")) + sorted(self.rule_dir.rglob("*.yara")):
                stem = path.stem
                if stem in files:  # namespace 冲突：用带后缀的名字避免编译失败
                    stem = f"{stem}_{len(files)}"
                files[stem] = str(path)
        except OSError as exc:
            log.warn("YARA 规则目录不可读", dir=str(self.rule_dir), err=str(exc))
        return files

    @staticmethod
    def _is_path_error(message: str) -> bool:
        """libyara 在 Windows 上按 ANSI 打开文件，路径含非 ASCII 时会报这类错误。"""
        text = str(message or "").lower()
        return ("no such file or directory" in text or "cannot open" in text
                or "could not open" in text or "(2," in text or "error 2" in text)

    def reload(self) -> dict:
        """重新编译规则；失败保留旧规则。返回 {"ok","rules","error"}。"""
        files = self._collect_files()
        if yara is None:
            with self._lock:
                self.error = "yara-python 未安装（pip install yara-python==4.5.4）"
            return {"ok": False, "rules": 0, "error": self.error}
        if not files:
            with self._lock:
                self._files = {}
                self.rules = None
                self.rule_count = 0
                self.error = f"未找到 YARA 规则文件：{self.rule_dir}"
            log.warn("YARA 规则目录为空", dir=str(self.rule_dir))
            return {"ok": False, "rules": 0, "error": self.error}
        try:
            compiled = yara.compile(filepaths=files)
        except Exception as exc:  # yara.SyntaxError / yara.Error
            message = str(exc)
            if self._is_path_error(message):
                # 非 ASCII 路径回退：把规则读成文本用 sources 编译（Windows 开发机专用兜底）
                try:
                    sources = {
                        stem: Path(file_path).read_text(encoding="utf-8", errors="replace")
                        for stem, file_path in files.items()
                    }
                    compiled = yara.compile(sources=sources)
                    log.info("YARA 规则按源码编译成功（路径含非 ASCII 字符的回退路径）",
                             files=len(files))
                except Exception as exc2:
                    message = str(exc2)
                    with self._lock:
                        self.error = message
                    log.warn("YARA 编译失败，保留旧规则", error=message, rules=self.rule_count)
                    return {"ok": False, "rules": self.rule_count, "error": message}
            else:
                with self._lock:
                    self.error = message
                log.warn("YARA 编译失败，保留旧规则", error=message, rules=self.rule_count)
                return {"ok": False, "rules": self.rule_count, "error": message}
        with self._lock:
            self.rules = compiled
            self._files = files
            self.rule_count = len(files)
            self.error = None
        log.info("YARA 规则编译完成", files=len(files), rules_dir=str(self.rule_dir))
        return {"ok": True, "rules": len(files), "error": None}

    # ------------------------------------------------------------ 协议
    def available(self) -> bool:
        return yara is not None and self.rules is not None

    def supports(self, ctx: dict) -> bool:
        ctx = ctx or {}
        size = ctx.get("size")
        try:
            return size is None or int(size) <= self.max_size
        except (TypeError, ValueError):
            return True

    @staticmethod
    def _externals(path: str, ctx: dict) -> dict:
        ctx = dict(ctx or {})
        try:
            size = int(ctx.get("size") if ctx.get("size") is not None else os.path.getsize(path))
        except (OSError, TypeError, ValueError):
            size = 0
        filetype = ctx.get("filetype") or Path(str(path)).suffix.lstrip(".") or "unknown"
        return {
            "filename": Path(str(path)).name,
            "filetype": str(filetype),
            "filesize": size,
        }

    def _match(self, path: str, externals: dict) -> Any:
        """执行一次 match，处理 externals 兼容与 Windows 非 ASCII 路径回退。"""
        try:
            return self.rules.match(path, externals=externals, timeout=self.timeout_sec)
        except Exception as exc:
            message = str(exc)
            # 1) 规则未声明 external 变量时，libyara 可能报未定义 → 不传 externals 重试
            if "external" in message.lower() or "undefined identifier" in message.lower():
                try:
                    return self.rules.match(path, timeout=self.timeout_sec)
                except Exception as exc2:
                    message = str(exc2)
            # 2) Windows libyara 用 ANSI 打开路径，含非 ASCII 字符会 "No such file" → 读入内存匹配
            if self._is_path_error(message):
                try:
                    data = Path(str(path)).read_bytes()
                except OSError as exc3:
                    log.warn("YARA 读取文件失败", path=str(path), err=str(exc3))
                    return None
                for kwargs in (
                    {"data": data, "externals": externals, "timeout": self.timeout_sec},
                    {"data": data, "timeout": self.timeout_sec},
                ):
                    try:
                        return self.rules.match(**kwargs)
                    except Exception:
                        continue
                log.warn("YARA 扫描失败（内存回退亦失败）", path=str(path), err=message)
                return None
            if "timeout" in message.lower():
                log.warn("YARA 扫描超时", path=str(path), timeout_sec=self.timeout_sec)
                return None
            log.warn("YARA 扫描失败", path=str(path), err=message)
            return None

    def scan(self, path: str, ctx: dict) -> list[dict]:
        """扫描文件并返回 YARA 命中（含命中偏移与字符串信息）。"""
        if yara is None:
            return []
        if self.rules is None:
            raise RuntimeError(self.error or "YARA 规则尚未编译")
        externals = self._externals(path, ctx)
        matches: Any = self._match(path, externals)
        if matches is None:
            return []

        hits: list[dict] = []
        for match in matches or []:
            meta = dict(getattr(match, "meta", {}) or {})
            score = _severity_score(meta.get("severity"), 60)
            offset = None
            matched_string = None
            try:
                strings = list(getattr(match, "strings", []) or [])
                if strings:
                    instances = list(getattr(strings[0], "instances", []) or [])
                    if instances:
                        offset = int(getattr(instances[0], "offset", 0))
                    matched_string = str(getattr(strings[0], "identifier", "")) or None
            except (TypeError, ValueError, AttributeError):
                pass
            evidence = {
                "path": str(path),
                "offset": offset,
                "matched": matched_string,
                "namespace": getattr(match, "namespace", ""),
                "tags": list(getattr(match, "tags", []) or []),
            }
            rule_meta = {
                "family": meta.get("family") or meta.get("malware") or meta.get("description") or "",
                "attack": meta.get("attack") or meta.get("mitre") or [],
                "severity": meta.get("severity"),
                "description": meta.get("description", ""),
                "namespace": getattr(match, "namespace", ""),
                "tags": list(getattr(match, "tags", []) or []),
                "yara_meta": meta,
                "source": meta.get("source", ""),
            }
            hits.append(make_hit(
                self.name,
                str(getattr(match, "rule", "unknown")),
                str(meta.get("description") or getattr(match, "rule", "yara_rule")),
                score,
                rule_meta,
                evidence,
            ))
        return hits
