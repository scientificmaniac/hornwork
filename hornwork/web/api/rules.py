"""规则域 handler：规则清单扫描与热加载标记。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ...config import cfg_get
from ..errors import HttpError as _HttpError
from ..common import (
    iso_now as _iso_now,
    NET_RULE_RE as _NET_RULE_RE,
    YARA_RULE_RE as _YARA_RULE_RE,
)


class RulesMixin:
    """规则域 handler：规则清单扫描与热加载标记。"""

    def _h_rules_get(self, query: dict[str, str]) -> None:
        items, missing, sources = self._collect_rules()
        self._send_json(
            200,
            {
                "ts": _iso_now(),
                "items": items,
                "count": len(items),
                "sources": sources,
                "missing": missing,
                "sigma": self.app.store.sigma_stats(),
                "reload": self.app.reload_state(),
            },
        )
    def _collect_rules(self) -> tuple[list[dict], list[str], dict[str, str]]:
        """扫描配置的规则目录，产出规则/规则文件清单（只读文件系统，不做规则求值）。"""
        cfg = self.app.cfg
        groups = (
            ("yara", "engines.yara_rule_dir", ("*.yar", "*.yara")),
            ("net", "engines.net_rule_dir", ("*.rules",)),
            ("host", "engines.host_rule_dir", ("*.json",)),
            ("sigma", "engines.sigma_rule_dir", ("*.yml", "*.yaml")),
        )
        items: list[dict] = []
        missing: list[str] = []
        sources: dict[str, str] = {}
        for kind, key, patterns in groups:
            raw = str(cfg_get(cfg, key, "") or "")
            sources[kind] = raw
            path = Path(os.path.expanduser(raw)) if raw else None
            if path is None or not path.is_dir():
                if raw:
                    missing.append(raw)
                continue
            for pattern in patterns:
                for file_path in sorted(path.rglob(pattern)):
                    if not file_path.is_file():
                        continue
                    item = self._describe_rule_file(kind, file_path)
                    if item:
                        items.append(item)
        return items, missing, sources
    @staticmethod
    def _describe_rule_file(kind: str, path: Path) -> dict | None:
        """单个规则文件 → 列表项（host JSON 解析元数据，net/yara 抽规则名）。"""
        try:
            stat = path.stat()
        except OSError:
            return None
        item: dict[str, Any] = {
            "source": kind,
            "id": path.stem,
            "name": path.stem,
            "path": str(path),
            "size": int(stat.st_size),
            "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": None,
            "technique": None,
            "rule_count": None,
        }
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return item
        if kind == "host":
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                item["error"] = "JSON 解析失败"
                return item
            if isinstance(doc, dict):
                item["id"] = str(doc.get("id") or item["id"])
                item["name"] = str(doc.get("name") or item["name"])
                item["level"] = doc.get("level")
                mitre = doc.get("mitre") or []
                item["technique"] = str(mitre[0]) if mitre else None
                item["event_types"] = doc.get("event_types") or []
                item["description"] = str(doc.get("description") or "")[:300]
        elif kind == "net":
            ids = [match.group(1) for match in _NET_RULE_RE.finditer(text)]
            item["rule_count"] = len(ids)
            item["rules"] = ids[:50]
        elif kind == "yara":
            ids = [match.group(1) for match in _YARA_RULE_RE.finditer(text)]
            item["rule_count"] = len(ids)
            item["rules"] = ids[:50]
        else:
            # Sigma：不引入 PyYAML 依赖，只按文件计数（加载状态由 store.sigma_stats 提供）
            item["rule_count"] = text.count("\ntitle:") + (1 if text.lstrip().startswith("title:") else 0)
        return item
    def _h_rules_post(self) -> None:
        body = self._read_json()
        action = str(body.get("action") or ("reload" if body.get("reload") else "")).strip()
        if action not in ("reload",):
            raise _HttpError(400, "仅支持 action=reload（规则热加载标记）")
        state = self.app.request_reload(note=str(body.get("note") or "")[:200])
        self._send_json(
            201,
            {
                "ok": True,
                "action": "reload",
                "requested_at": state.get("requested_at"),
                "count": state.get("count"),
                "note": "已记录重载请求，daemon 轮询后生效",
            },
        )
