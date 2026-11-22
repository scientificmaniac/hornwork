"""情报域 handler：IOC 列表与导入。

方法体从 server.py 原样搬迁；通过 self 访问传输层（_send_json/app 等），
由 _Handler 多继承装配。
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

from ..errors import HttpError as _HttpError
from ..common import (
    iso_now as _iso_now,
    q_int as _q_int,
)


class IntelMixin:
    """情报域 handler：IOC 列表与导入。"""

    def _h_intel_get(self, query: dict[str, str]) -> None:
        kind = query.get("kind") or None
        status = query.get("status") or None
        items = self.app.store.ioc_list(kind=kind, limit=_q_int(query, "limit", 500, 1, 5000), status=status)
        by_type = dict(Counter(str(item.get("type") or "unknown") for item in items))
        self._send_json(200, {"ts": _iso_now(), "items": items, "count": len(items), "by_type": by_type})
    def _h_intel_post(self) -> None:
        body = self._read_json()
        try:
            from ...intel.iocstore import IocStore
        except Exception as exc:  # noqa: BLE001 - 情报层缺失时降级为 503
            raise _HttpError(503, "情报层不可用（hornwork.intel.iocstore 导入失败）", detail=exc) from exc

        records: Any = None
        if isinstance(body.get("records"), list):
            records = body["records"]
        elif body.get("path"):
            try:
                from ...intel.feeds import load_feed
            except Exception as exc:  # noqa: BLE001
                raise _HttpError(503, "情报导入器不可用（hornwork.intel.feeds 导入失败）", detail=exc) from exc
            path = Path(os.path.expanduser(str(body["path"])))
            if not path.is_file():
                raise _HttpError(400, "情报文件不存在", detail=str(path))
            try:
                records = load_feed(str(path))
            except Exception as exc:  # noqa: BLE001 - 解析失败属于可重试错误
                raise _HttpError(422, "情报文件解析失败", retryable=True, detail=exc) from exc
        if not isinstance(records, list) or not records:
            raise _HttpError(400, "请求体需要 records 数组或 path 文件路径")

        try:
            result = IocStore(self.app.store, self.app.cfg).import_records(records)
        except Exception as exc:  # noqa: BLE001 - 导入失败按 500 返回
            raise _HttpError(500, "情报导入失败", retryable=True, detail=exc) from exc
        payload = {"ok": True, "ts": _iso_now()}
        if isinstance(result, dict):
            payload.update(result)
        else:
            payload["imported"] = result
        self._send_json(201, payload)
