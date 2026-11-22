"""Web 控制台的统一错误模型（从 server.py 抽出，供传输层与各 API 域共用）。

错误契约三态（与前端 frontend/src/api/client.ts 一一对应）：
- C7：通用接口，异常 → 非 2xx + C7 JSON（code/message/retryable/detail）；
- SOFT：扫描类接口，异常 → HTTP 200 + {"items":[],"error":...}，由前端 softErrorOf 解读；
- AUTH_STATE：认证类接口，401 时返回完整状态机 body（status/reason/degraded）。

任何一态的改变都必须同步 frontend/tests/api.spec.ts 的三态用例。
"""

from __future__ import annotations

from typing import Any

# error_mode 常量：由 Route 声明，transport 出口据此转换异常
C7 = "c7"
SOFT = "soft"
AUTH_STATE = "auth"

_ERROR_MODES = {C7, SOFT, AUTH_STATE}


def is_valid_mode(mode: str) -> bool:
    return mode in _ERROR_MODES


def error_payload(code: int, message: str, retryable: bool = False, detail: Any = None) -> dict:
    """C7 统一错误结构。"""
    return {
        "code": int(code),
        "message": str(message),
        "retryable": bool(retryable),
        "detail": None if detail is None else str(detail)[:800],
    }


class HttpError(Exception):
    """路由层主动抛出的 HTTP 错误（由统一异常处理转成响应）。

    保留原 _HttpError 的 payload 语义；额外携带 body 供 AUTH_STATE 模式返回状态机原文。
    """

    def __init__(
        self,
        status: int,
        message: str,
        retryable: bool = False,
        detail: Any = None,
        body: dict | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.payload = error_payload(status, message, retryable, detail)
        self.body = body
