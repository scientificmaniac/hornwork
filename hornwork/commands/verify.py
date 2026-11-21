"""``hornworkctl verify``：检测能力验证（TC 用例套件）。

## 为什么这里要判断 euid

验证脚本里 TC-03/04/05/06/10 需要 root（写 ``/etc``、``useradd`` 等）。daemon 以
``hornwork`` 用户运行，若把执行权经控制面转给它，这些用例只能 SKIP。因此：

- root 执行且未加 ``--remote`` → **本进程内**跑验证器（脚本继承 root 权限），
  仅通过控制面借用 daemon 的其它能力；
- 非 root → 回退到 daemon 内执行；daemon 也不在时仍在本进程内跑（能得到部分
  结论，好过直接报错）。

## 为什么 ``mem.scan`` 就地实现

daemon 以 ``hornwork`` 用户运行，读 root 目标进程的 ``/proc/<pid>/mem`` 会被
Yama/权限拒绝。root 进程自己扫描既等价又不需要给服务提权。
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable
from typing import Any

from ..cli_common.constants import EXIT_OK
from ..cli_common.runtime import CliRuntime

NAME = "verify"
HELP = "验证"

COLUMNS = [
    ("case", "用例"), ("name", "名称"), ("technique", "技术"),
    ("expected", "期望"), ("observed", "观测"), ("verdict", "判定"), ("mttd", "MTTD(s)"),
]


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``verify run``。"""
    parser = sub.add_parser(NAME, help=HELP)
    actions = parser.add_subparsers(dest="verify_cmd", required=True)
    runner = actions.add_parser("run")
    runner.add_argument("--suite", default="baseline")
    runner.add_argument("--no-execute", action="store_true")
    runner.add_argument(
        "--remote", action="store_true",
        help="强制交给 daemon 执行（默认 root 时本进程执行）",
    )


def run(ctx: CliRuntime) -> int:
    """执行验证套件并输出报告。"""
    args = ctx.args
    if _should_run_locally(ctx):
        report = _run_local(ctx)
    else:
        report = ctx.ctl(
            "verify.run", {"suite": args.suite, "execute": not args.no_execute}
        )
    if ctx.json_output:
        ctx.print_json(report)
        return EXIT_OK
    _print_report(ctx, report)
    return EXIT_OK


def _is_root() -> bool:
    """当前进程是否具备 root 权限（Windows 上恒为 False）。"""
    return bool(getattr(os, "geteuid", lambda: 1)() == 0)


def _should_run_locally(ctx: CliRuntime) -> bool:
    """root 且未强制 remote，或 daemon 缺席时，在本进程执行。"""
    if _is_root() and not getattr(ctx.args, "remote", False):
        return True
    return not ctx.daemon_up()


def _run_local(ctx: CliRuntime) -> dict:
    """在本进程内构造 ``VerifyRunner`` 并执行。

    控制面替身的选择与 :func:`_should_run_locally` 使用同一套判定，避免出现
    "走本地执行但没有 ctl_call"这种半残状态。
    """
    from ..verify.runner import VerifyRunner

    ctl_call: Callable[[str, dict | None], dict] | None = None
    if _is_root() and not getattr(ctx.args, "remote", False):
        # root：mem.scan 就地做（daemon 以 hornwork 用户运行，读不到 root 目标进程）
        ctl_call = _local_ctl_call(ctx)
    elif ctx.daemon_up():
        # 非 root 但 daemon 在线：全部经控制面转发
        ctl_call = _remote_ctl_call(ctx)
    runner = VerifyRunner(ctx.store(), ctx.cfg, ctl_call=ctl_call)
    return runner.run(suite=ctx.args.suite, execute=not ctx.args.no_execute)


def _local_ctl_call(ctx: CliRuntime) -> Callable[[str, dict | None], dict]:
    """root 本进程执行时使用的控制面替身：``mem.scan`` 就地做，其余转发。"""
    from ..collectors.memscan import MemoryScanner

    store = ctx.store()

    def local_alert(alert: dict) -> None:
        """本地验证进程直接落库（daemon 的告警消费链路不经过这里）。

        落库失败**静默忽略**：验证器关心的是"用例是否被检出"，而不是"告警是否
        入库成功"；在此打印告警会往 stderr 引入原本没有的内容，破坏输出契约。
        """
        try:
            store.insert_alert(alert)
        except Exception:  # noqa: BLE001, S110 - 落库失败不改变 stderr 输出
            pass

    scanner = MemoryScanner(ctx.cfg, store, local_alert, None)

    def ctl_call(method: str, params: dict | None = None) -> dict:
        params = params or {}
        if method == "mem.scan":
            return {
                "ok": True,
                "result": scanner.scan_pid(
                    int(params.get("pid") or 0),
                    snapshot=bool(params.get("snapshot", False)),
                ),
            }
        if ctx.daemon_up():
            return {"ok": True, "result": ctx.ctl(method, params)}
        return {"ok": False, "error": "daemon_down"}

    return ctl_call


def _remote_ctl_call(ctx: CliRuntime) -> Callable[[str, dict | None], dict]:
    """非 root 但 daemon 在线时：所有方法都经控制面转发。"""

    def ctl_call(method: str, params: dict | None = None) -> dict:
        return {"ok": True, "result": ctx.ctl(method, params or {})}

    return ctl_call


def _print_report(ctx: CliRuntime, report: dict[str, Any]) -> None:
    """人类可读报告：用例表 + TP/TN/FP/FN 汇总。"""
    metrics = report.get("metrics") or {}
    print(f"验证报告：{report.get('report_path')}")
    ctx.print_table(
        [
            {
                "case": case.get("case_id"),
                "name": case.get("name"),
                "technique": case.get("technique"),
                "expected": case.get("expected"),
                "observed": case.get("observed"),
                "verdict": case.get("verdict"),
                "mttd": case.get("mttd_sec"),
            }
            for case in report.get("cases") or []
        ],
        COLUMNS,
    )
    print(
        "TP={} TN={} FP={} FN={} inconclusive={} TPR={} FPR={} MTTD={}s 覆盖率={}".format(
            metrics.get("TP"), metrics.get("TN"), metrics.get("FP"), metrics.get("FN"),
            metrics.get("inconclusive"), metrics.get("tpr"), metrics.get("fpr"),
            metrics.get("mttd_sec"), metrics.get("coverage"),
        )
    )
