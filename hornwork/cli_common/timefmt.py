"""统一的时间戳渲染。

为什么是公共函数而不是各命令自带：``events`` / ``alerts`` / ``case`` 三处表格都要
把 canonical 时间戳渲染成同一形态，否则同一份数据在两个命令里显示不一致。

函数名用 ``format_`` 而不是 ``print_``：它只返回字符串，不产生副作用，调用方
决定往哪输出（表格 / JSON / 文件）。
"""

from __future__ import annotations


def format_ts(ts: str | None) -> str:
    """把 ISO8601 时间戳渲染成 ``YYYY-MM-DD HH:MM:SSZ``。

    - 空值 → 空串（表格留白，而不是 "None"）；
    - 可解析的 ISO8601 → ``to_utc()[:19]`` 后把 ``T`` 换成空格并补 ``Z``；
    - 解析失败 → 原值截断到 19 字符。终端渲染不能因一条脏数据崩掉整张表。

    Parameters
    ----------
    ts:
        canonical 事件时间戳，形如 ``2026-11-21T10:00:00.123Z``。
    """
    from ..schema import to_utc

    if not ts:
        return ""
    try:
        return to_utc(ts)[:19].replace("T", " ") + "Z"
    except Exception:  # noqa: BLE001 - 脏时间戳降级为原样截断
        return str(ts)[:19]
