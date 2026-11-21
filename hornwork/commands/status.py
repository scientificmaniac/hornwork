"""``hornworkctl status``：平台运行状态。

两种数据来源，优先级由可观测性决定而非偏好：

1. daemon 在跑 → 走控制面 ``status``，拿到线程/采集器/总线的实时快照；
2. daemon 没跑 → 直接读 SQLite 做**只读统计**，并以退出码 1 明确告知"这不是
   实时状态"。

第 2 条是答辩/排障现场最常见的情形（服务没起来但仍要证明数据链路通），因此
它必须是可用的降级路径而不是报错。
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_FAIL, EXIT_OK
from ..cli_common.output import print_json
from ..cli_common.runtime import CliRuntime

NAME = "status"
"""子命令名，与 ``argparse`` 的 dest 取值一致。"""

HELP = "运行状态"
"""``--help`` 里显示的说明文案。"""


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``status`` 子命令（无参数）。"""
    sub.add_parser(NAME, help=HELP)


def run(ctx: CliRuntime) -> int:
    """打印运行状态；daemon 缺席时降级为数据库只读统计。"""
    if not ctx.daemon_up():
        print(f"[!] daemon 未运行（socket 不存在：{ctx.socket_path}）")
        _print_offline_counts(ctx)
        return EXIT_FAIL
    status = ctx.ctl("status")
    if ctx.json_output:
        print_json(status)
        return EXIT_OK
    _print_live_status(status)
    return EXIT_OK


def _print_offline_counts(ctx: CliRuntime) -> None:
    """离线分支：尽力打印各表计数，读不到库也不改变退出码。"""
    try:
        counts = ctx.store().counts()
        print("数据库只读统计：")
        for key, val in counts.items():
            print(f"  {key:16s} {val}")
    except Exception as exc:  # noqa: BLE001 - 读不到库只提示，不影响退出码
        print(f"[!] 无法读取数据库：{exc}")


def _print_live_status(status: dict) -> None:
    """人类可读的现场报告：进程/主机/计数/引擎/Sigma/采集器/总线/Web/ctl。"""
    print(
        f"Hornwork {status.get('version')}  pid={status.get('pid')}  "
        f"运行 {status.get('uptime_sec')}s"
    )
    host = status.get("host", {})
    print(f"主机：{host.get('host_id')}  ({host.get('hostname')})")

    counts = status.get("counts") or {}
    print(
        "事件 {}（24h {}）  告警 {}（24h {}，未处理 {}）  工单 {}  IOC {}  DLQ {}".format(
            counts.get("events_total"), counts.get("events_24h"),
            counts.get("alerts_total"), counts.get("alerts_24h"),
            counts.get("alerts_open"), counts.get("cases_total"),
            counts.get("iocs"), counts.get("dlq"),
        )
    )
    print(f"引擎：{status.get('engines')}")

    sigma = status.get("sigma") or {}
    print(
        "Sigma：loaded={} supported={} skipped={} errors={} hits={} include_status_test={}".format(
            sigma.get("loaded"), sigma.get("supported"), sigma.get("skipped"),
            sigma.get("errors"), sigma.get("hits"), sigma.get("include_status_test"),
        )
    )

    print("采集器：")
    for collector in status.get("collectors") or []:
        print(
            f"  - {collector.get('name')}: running={collector.get('running')} "
            f"stats={collector.get('stats')}"
        )

    bus = status.get("bus") or {}
    print(f"总线：metrics={bus.get('metrics')} pending={bus.get('pending')}")
    print(f"Web：{status.get('web')}")
    print(f"ctl：{status.get('ctl')}")
