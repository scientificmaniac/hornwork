"""HTTP 请求辅助。

**范围说明**：CLI 子命令本身不直接访问 HTTP —— 网络侧的取数（NVD/OVAL 情报、
feed 拉取）全部在各自业务模块内完成，CLI 只负责"把本地文件交给它们"。因此本
模块不引入 requests/urllib3，只提供标准库 ``urllib.request`` 的薄封装，供后续
新增「在线校验/在线情报拉取」类子命令使用，避免每个新命令各写一遍超时与
User-Agent 处理。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from ..cli_common.errors import CliError

DEFAULT_TIMEOUT_SEC = 30.0
"""单次 HTTP 请求默认超时秒数。"""

USER_AGENT = "hornworkctl/1.0 (+https://github.com/scientificmaniac/hornwork)"
"""固定 UA：便于对端识别与限流排查。"""


def fetch_text(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SEC,
    headers: dict[str, str] | None = None,
) -> str:
    """GET 一个 URL 并以 UTF-8 返回文本。

    Raises
    ------
    CliError
        网络不可达、HTTP 非 2xx 或解码失败时抛出，退出码 2。
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        # 仅支持 http(s)；调用方负责保证 URL 来自可信配置。
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise CliError(f"HTTP {exc.code}：{url}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise CliError(f"请求失败：{url}（{exc}）") from exc


def fetch_json(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SEC,
    headers: dict[str, str] | None = None,
) -> Any:
    """GET 一个 URL 并解析为 JSON 对象。

    Raises
    ------
    CliError
        网络失败或响应体不是合法 JSON。
    """
    text = fetch_text(url, timeout=timeout, headers=headers)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CliError(f"响应不是合法 JSON：{url}（{exc}）") from exc
