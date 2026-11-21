"""``hornworkctl scan file``：单文件扫描（sigdb → yara → clamav 级联）。

这是检测模块的入口，也是历史写法 ``hornworkctl scan <path>`` 经过
:func:`hornwork.cli._normalize_argv` 补全 ``file`` 后落到的地方。

## 双路径

- daemon 在线 → 走控制面 ``scan.file``：结果会写库缓存（同一文件二次扫描
  直接命中 ``hash_cache``）；
- daemon 离线 → **本进程**构造 Cascade。离线不写库：非 root/非服务用户通常
  没有写权限，Cascade 内部的落库失败会被忽略，因此扫描结论仍可信。
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from ...cli_common.constants import EXIT_OK
from ...cli_common.runtime import CliRuntime

NAME = "file"
HELP = "检测模块：文件扫描（sigdb→yara→clamav）"


def register(actions: argparse._SubParsersAction) -> None:
    """注册 ``scan file``。"""
    parser = actions.add_parser(NAME, help=HELP)
    parser.add_argument("path")
    parser.add_argument("--deep", action="store_true")


def run(ctx: CliRuntime) -> int:
    """执行扫描并输出结论（非 ``--json`` 时为多行人类可读摘要）。"""
    args = ctx.args
    path = str(Path(args.path).resolve())
    result = ctx.ctl("scan.file", {"path": path, "deep": args.deep}) \
        if ctx.daemon_up() else _scan_offline(ctx, path, args.deep)
    if ctx.json_output:
        ctx.print_json(result)
    else:
        _print_result(result)
    return EXIT_OK


def _scan_offline(ctx: CliRuntime, path: str, deep: bool) -> dict:
    """daemon 缺席时在本进程跑同一套引擎级联。"""
    from ...engines.cascade import Cascade
    from ...engines.clamd_client import ClamavEngine
    from ...engines.sigdb import SigDbEngine
    from ...engines.yara_bridge import YaraEngine

    store = ctx.store()
    cascade = Cascade(
        ctx.cfg,
        [SigDbEngine(ctx.cfg, store), YaraEngine(ctx.cfg), ClamavEngine(ctx.cfg)],
        store,
    )
    scan_ctx = {
        "path": path,
        "size": os.path.getsize(path),
        "deep": deep,
        "filetype": "unknown",
    }
    return cascade.scan(path, deep=deep, ctx=scan_ctx)


def _print_result(result: dict) -> None:
    """文件扫描结果摘要：判定、引擎、耗时与逐条命中。"""
    print(f"文件：{result.get('path')}")
    print(
        f"sha256：{result.get('sha256')}  大小：{result.get('size')}  "
        f"verdict：{result.get('verdict')}  score：{result.get('score')}"
    )
    print(
        f"引擎：{result.get('engines_used')}  耗时：{result.get('cost_ms')}ms  "
        f"cached={result.get('cached')}"
    )
    for hit in result.get("hits") or []:
        print(f"  - [{hit.get('engine')}] {hit.get('rule_id')} {hit.get('name')} "
              f"score={hit.get('score')}")
