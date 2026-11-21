"""``hornworkctl lab``：Vulhub 靶场编排（索引/启停/状态/日志/隔离）。

## 为什么在本模块里装配 ``LabCtl``

靶场动作要同时写入事件库与审计哈希链。这两个 sink 的降级语义（失败只告警、
不阻断动作）属于**共享装配**，已下沉到 :mod:`hornwork.cli_common.labsupport`；
本模块只负责参数搬运与结果呈现，不会因此反向依赖 ``respond`` 命令模块。

## 退出码约定

- ``index`` / ``list`` / ``status`` / ``logs`` 成功即 0；
- ``up`` / ``down`` / ``isolate`` 以 ``res["ok"]`` 决定 0 或 1 —— 动作已执行但
  失败属于业务失败，不是用法错误；
- 组件不可用（docker/compose 缺失）→ 2，因为"没法执行"是前置条件问题。
"""

from __future__ import annotations

import argparse
import json
import sys

from ..cli_common.constants import EXIT_FAIL, EXIT_OK, EXIT_USAGE
from ..cli_common.labsupport import build_lab_ctl
from ..cli_common.runtime import CliRuntime

NAME = "lab"
HELP = "靶场模块：Vulhub 靶场编排"

COLUMNS = [
    ("env_id", "环境"), ("category", "分类"), ("cve", "CVE"),
    ("state", "状态"), ("ports", "端口"), ("expires_at", "TTL 到期"),
]

# 容器日志在终端只回显尾部 20000 字符，避免一次性刷屏；完整内容可用 --json。
LOG_TAIL_CHARS = 20000


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``lab index|list|up|down|status|logs|isolate``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="lab_cmd", required=True)

    index = actions.add_parser("index", help="扫描 /opt/vulhub 生成索引")
    index.add_argument("--force", action="store_true", help="强制重建")

    lister = actions.add_parser("list", help="列出环境")
    lister.add_argument("--type", default=None, help="按分类过滤（如 grafana）")
    lister.add_argument("--status", default=None, help="按状态过滤")
    lister.add_argument("--limit", type=int, default=100)

    up = actions.add_parser("up", help="启动环境（含守卫与健康检查）")
    up.add_argument("env_id")
    up.add_argument("--ttl", type=int, default=None, help="TTL 分钟（默认配置值）")
    up.add_argument("--force", action="store_true", help="跳过快照提醒")

    down = actions.add_parser("down", help="停止环境并清理数据卷")
    down.add_argument("env_id")
    down.add_argument("--keep-volume", action="store_true")

    status = actions.add_parser("status", help="环境状态/端口探测")
    status.add_argument("env_id", nargs="?", default=None)

    logs = actions.add_parser("logs", help="查看容器日志")
    logs.add_argument("env_id")
    logs.add_argument("--tail", type=int, default=100)

    isolate = actions.add_parser("isolate", help="下线并隔离环境")
    isolate.add_argument("env_id")


def run(ctx: CliRuntime) -> int:
    """构造 LabCtl 后按 ``lab_cmd`` 分派。

    分派表的键与 :func:`register` 里注册的子命令一一对应；未知值由
    ``add_subparsers(required=True)`` 在 argparse 层拦下（退出码 2），
    此处无需再保留不可达的兜底分支。
    """
    try:
        ctl = build_lab_ctl(ctx.cfg, ctx.store())
    except Exception as exc:  # noqa: BLE001 - 模块缺失时给出可读错误
        print(f"[错误] 靶场模块 lab 组件不可用：{exc}", file=sys.stderr)
        return EXIT_USAGE

    action = ctx.args.lab_cmd
    if action == "index":
        return _index(ctx, ctl)
    if action == "list":
        return _list(ctx, ctl)
    if action == "up":
        return _act(ctx, ctl.up(ctx.args.env_id, ttl_min=getattr(ctx.args, "ttl", None),
                                force=bool(getattr(ctx.args, "force", False))), "up")
    if action == "down":
        return _act(ctx, ctl.down(ctx.args.env_id,
                                  keep_volume=bool(getattr(ctx.args, "keep_volume", False))), "down")
    if action == "status":
        return _status(ctx, ctl)
    if action == "logs":
        return _logs(ctx, ctl)
    return _act(ctx, ctl.isolate(ctx.args.env_id), "isolate")


def _index(ctx: CliRuntime, ctl) -> int:
    """重建/增量更新 Vulhub 索引。"""
    result = ctl.index(force=bool(getattr(ctx.args, "force", False)))
    if ctx.json_output:
        ctx.print_json(result)
        return EXIT_OK
    print(f"索引完成：{result.get('count')} 个环境，耗时 {result.get('elapsed_ms')}ms")
    print(f"输出：{result.get('path')}")
    for err in result.get("errors") or []:
        print(f"  [warn] {err}")
    return EXIT_OK


def _list(ctx: CliRuntime, ctl) -> int:
    """列出环境（分类/状态/数量过滤）。"""
    args = ctx.args
    rows = ctl.list(
        type=getattr(args, "type", None),
        status=getattr(args, "status", None),
        limit=int(getattr(args, "limit", 100)),
    )
    if ctx.json_output:
        ctx.print_json({"envs": rows})
        return EXIT_OK
    ctx.print_table(
        [
            {
                "env_id": row.get("env_id"),
                "category": row.get("category"),
                "cve": row.get("cve") or "-",
                "state": row.get("state") or "-",
                "ports": json.dumps(row.get("ports") or {}, ensure_ascii=False),
                "expires_at": row.get("expires_at") or "-",
            }
            for row in rows
        ],
        COLUMNS,
    )
    return EXIT_OK


def _act(ctx: CliRuntime, result: dict, action: str) -> int:
    """统一处理 up/down/isolate 的结果（返回码由 ``ok`` 决定）。"""
    if ctx.json_output:
        ctx.print_json(result)
    else:
        _print_result(action, result)
    return EXIT_OK if result.get("ok") else EXIT_FAIL


def _status(ctx: CliRuntime, ctl) -> int:
    """查看单个环境或全局运行状态。"""
    result = ctl.status(getattr(ctx.args, "env_id", None))
    if ctx.json_output:
        ctx.print_json(result)
        return EXIT_OK
    for item in result.get("envs") or [result]:
        containers = len(item.get("containers") or [])
        print(
            f"{item.get('env_id')}: {item.get('state')} ports={item.get('ports')}"
            f" ttl_left={item.get('ttl_left_sec')}s containers={containers}"
        )
    if result.get("env_id") is None:
        print(f"运行中环境数：{result.get('running')} / {result.get('total')}")
        print(f"索引：{result.get('index')}")
    return EXIT_OK


def _logs(ctx: CliRuntime, ctl) -> int:
    """查看容器日志尾部。"""
    result = ctl.logs(ctx.args.env_id, tail=int(getattr(ctx.args, "tail", 100)))
    if ctx.json_output:
        ctx.print_json(result)
    else:
        print((result.get("logs") or "")[-LOG_TAIL_CHARS:])
    return EXIT_OK if result.get("ok") else EXIT_FAIL


def _print_result(action: str, result: dict) -> None:
    """人类可读的动作结果：状态行 + 可选端口/错误/详情/提示。"""
    print(
        f"[{action}] ok={result.get('ok')} env={result.get('env_id')} "
        f"耗时={result.get('elapsed_ms')}ms"
    )
    if result.get("ports"):
        print(f"  端口：{json.dumps(result.get('ports'), ensure_ascii=False)}")
    if result.get("error"):
        print(f"  错误：{result.get('error')}")
    if result.get("detail"):
        print(f"  详情：{str(result.get('detail'))[:1000]}")
    for line in result.get("hints") or []:
        print(f"  提示：{line}")
