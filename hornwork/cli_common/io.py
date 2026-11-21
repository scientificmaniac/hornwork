"""CLI 层文件读写辅助（导出、报告落盘、CSV 导入）。

只封装「路径判断 + 编码 + 目录创建 + 落盘」这类样板，业务格式由调用方决定。
"""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from collections.abc import Iterable, Iterator
from typing import Any

from ..cli_common.constants import DEFAULT_RAW_DIR


def resolve_out_dir(raw: str | None, default: str = DEFAULT_RAW_DIR) -> Path:
    """解析导出目录并确保存在。

    传入空值时退回 ``default``；目录会按需递归创建（``parents=True``）。
    """
    out_dir = Path(raw or default)
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def timestamped_name(prefix: str, suffix: str, *, sep: str = "-") -> str:
    """生成 ``<prefix>-YYYYmmdd-HHMMSS.<suffix>`` 形式的文件名。

    与重构前 ``time.strftime('%Y%m%d-%H%M%S')`` 完全一致。
    """
    return f"{prefix}{sep}{time.strftime('%Y%m%d-%H%M%S')}.{suffix}"


def resolve_report_target(raw: str | None, fmt: str, prefix: str = "vuln-report") -> str | None:
    """把 ``--out`` 归一成具体文件路径。

    若用户传的是**已存在的目录**，自动补一个带时间戳的文件名；否则原样返回
    （可能为 ``None``，表示由下游决定落盘位置）。
    """
    if not raw:
        return raw
    path = Path(raw)
    if path.is_dir():
        return str(path / timestamped_name(prefix, fmt))
    return raw


def write_jsonl(path: Path | str, items: Iterable[dict]) -> int:
    """把 dict 序列逐行写成 JSONL，返回写入行数。"""
    count = 0
    with open(path, "w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
            count += 1
    return count


def read_csv_rows(path: str | Path) -> Iterator[dict[str, Any]]:
    """按 UTF-8 逐行读取 CSV（表头作为字典键）。

    文件不存在或不可读时抛 :class:`OSError`，由调用方转成业务错误文案。
    """
    with open(path, "r", encoding="utf-8", newline="") as handle:
        yield from csv.DictReader(handle)
