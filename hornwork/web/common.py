"""Web 层共享工具与常量（server.py 与各 api/* mixin 的公共依赖）。

从 server.py 抽出，避免 mixin 反向依赖入口模块造成循环导入。
server.py 通过 re-export 保持原有模块级名字（_iso_now/_q_int/_ASSET_TYPES 等），
不破坏 tests/test_verify_web.py 对 server_mod._ASSET_TYPES 的直接引用。
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import parse_qs

from ..log import get_logger

log = get_logger("web")

STATIC_DIR = None  # 由 server.py 定义后回填；mixin 不依赖它

# 网络规则/YARA 规则文件里取规则名的轻量正则（只做列表展示，不参与匹配）
_NET_RULE_RE = re.compile(r"^\s*rule\s+([A-Za-z0-9_.\-]+)\s+([A-Za-z0-9_.\-]+)")
_YARA_RULE_RE = re.compile(r"^\s*rule\s+([A-Za-z0-9_]+)")

# 兼容导入别名（mixin 以 "NET_RULE_RE as _NET_RULE_RE" 形式引用）
NET_RULE_RE = _NET_RULE_RE
YARA_RULE_RE = _YARA_RULE_RE


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def query_dict(query_string: str) -> dict[str, str]:
    """同名参数取最后一个（简单、可预期）。"""
    return {key: values[-1] for key, values in parse_qs(query_string, keep_blank_values=False).items()}


def q_int(query: dict[str, str], key: str, default: int, minimum: int = 0, maximum: int = 10000) -> int:
    raw = query.get(key)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(float(str(raw).strip()))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))
