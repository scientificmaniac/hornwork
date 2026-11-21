"""配置加载：命令行 ``-c`` → 部署路径 → 当前目录，再与 ``DEFAULTS`` 深合并。

重构前这段逻辑内联在 ``main()`` 里：

```python
if not args.config:
    for cand in ("/opt/hornwork/config.toml", "config.toml"):
        if Path(cand).is_file():
            args.config = cand
            break
```

它被抽出来的原因很实际：任何一个子命令模块做离线兜底时都要知道自己「到底用了
哪份配置」，而 ``load_config`` 只认显式路径。集中到一处后，行为与查找顺序只有
一份定义。
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ..cli_common.constants import DEFAULT_CONFIG_CANDIDATES, DEFAULT_SOCKET
from ..config import cfg_get, load_config


def resolve_config_path(explicit: str | None) -> str | None:
    """返回实际使用的配置文件路径。

    显式传入的路径**原样返回**（即使不存在）—— 与重构前一致：用户给了
    ``-c /path/x.toml`` 却写错时，应当得到基于 DEFAULTS 的运行而不是静默
    换成别的配置。只有未显式指定时才走候选列表。
    """
    if explicit:
        return explicit
    for candidate in DEFAULT_CONFIG_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def load_cli_config(config_path: str | None) -> dict[str, Any]:
    """按解析出的路径加载配置（路径为空时返回纯 DEFAULTS）。

    保留为公共 API：独立入口（如未来的 ``hornworkctl`` 子命令包装脚本）可直接
    复用"先解析路径、再加载"的两步，而不必重复实现查找顺序。
    """
    return load_config(config_path)


def socket_path(args: argparse.Namespace, cfg: dict[str, Any]) -> str:
    """计算控制面 socket 路径：``--socket`` 优先，其次 ``ctl.socket``。"""
    explicit = getattr(args, "socket", None)
    if explicit:
        return str(explicit)
    return str(cfg_get(cfg, "ctl.socket", DEFAULT_SOCKET))


def apply_config_default(args: argparse.Namespace) -> argparse.Namespace:
    """就地补齐 ``args.config`` 并返回同一个对象。

    放在入口调用，保证后续所有模块读到的 ``args.config`` 都是"已解析"的。
    """
    args.config = resolve_config_path(getattr(args, "config", None))
    return args
