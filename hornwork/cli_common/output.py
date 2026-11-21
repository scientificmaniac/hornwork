"""CLI 输出原语：JSON 与等宽表格。

这里是**对外输出格式的唯一实现**。重构前后必须逐字节一致，因此：

- :func:`print_json` 固定 ``ensure_ascii=False, indent=2, default=str``；
- :func:`print_table`` 的列宽算法、60 字符上限、``None``/容器值的渲染方式、
  空数据占位语全部照搬原实现，不要"顺手优化"。

``hornwork.auth.cli`` 曾自带一份近似实现（上限 48、无 ``empty`` 参数）。为遵守
"一个格式只有一处实现"的约束，它已改为调用本模块，但**通过参数保留其原行为**。
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from ..cli_common.constants import EMPTY_TABLE

# 单列最大渲染宽度：超长内容截断，避免表格在终端里换行错位。
MAX_COL_WIDTH = 60

Column = tuple[str, str]
"""``(字段名, 表头文案)`` 二元组。"""


def print_json(obj: Any) -> None:
    """把任意对象按统一口径打印成 JSON（中文不转义，未知类型转 str）。"""
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def render_cell(value: Any) -> str:
    """把单元格取值渲染成单行文本。

    ``None`` → 空串；``dict``/``list`` → 紧凑 JSON；其余 → ``str()``。
    """
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def print_table(
    rows: Sequence[dict],
    columns: Iterable[Column],
    empty: str = EMPTY_TABLE,
    max_col_width: int = MAX_COL_WIDTH,
    render: Callable[[Any], str] = render_cell,
) -> None:
    """以「表头 + 分隔线 + 数据行」打印等宽表格。

    列宽取「表头长度」与「该列最长单元格长度（截到 ``max_col_width``）」的较大者；
    单元格超宽时按列宽硬截断，保证每行在终端里正好对齐。

    Parameters
    ----------
    rows:
        数据行；为空时只打印 ``empty`` 占位语。
    columns:
        ``(字段名, 表头文案)`` 序列，决定列顺序。
    empty:
        无数据行的占位提示。
    max_col_width:
        列宽上限。默认 60；``hornwork.auth.cli`` 沿用历史的 48。
    render:
        单元格渲染函数。默认 :func:`render_cell`（``None``→空串、
        ``dict``/``list``→JSON）；``hornwork.auth.cli`` 传入
        ``lambda v: str(v or "")`` 以保留其历史行为。
    """
    columns = list(columns)
    if not rows:
        print(empty)
        return
    widths = {key: len(title) for key, title in columns}
    rendered: list[dict[str, str]] = []
    for row in rows:
        cells: dict[str, str] = {}
        for key, _title in columns:
            text = render(row.get(key))
            cells[key] = text
            widths[key] = max(widths[key], min(len(text), max_col_width))
        rendered.append(cells)
    print("  ".join(title.ljust(widths[key]) for key, title in columns))
    print("  ".join("-" * widths[key] for key, _title in columns))
    for cells in rendered:
        print("  ".join(
            cells[key][: widths[key]].ljust(widths[key]) for key, _title in columns
        ))
