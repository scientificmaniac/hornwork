"""规则目录解析：各检测引擎共用，避免四处重复同一段回退逻辑。"""

from __future__ import annotations

from pathlib import Path

from ..config import cfg_get


def resolve_rule_dir(cfg: dict, kind: str, dotted: str) -> Path:
    """定位规则目录：配置目录存在则用它，否则回退到 ``<general.rule_dir>/<kind>``。"""
    configured = cfg_get(cfg, dotted, "")
    if configured and Path(str(configured)).is_dir():
        return Path(str(configured))
    base = Path(str(cfg_get(cfg, "general.rule_dir", "/opt/hornwork/rules")))
    return base / kind
