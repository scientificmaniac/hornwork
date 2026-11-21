"""``hornworkctl auth``：三因子认证（口令 + TOTP + 人脸模板）。

## 为什么这个模块只做转发

认证子系统的 CLI 早已是**独立实现**（``hornwork/auth/cli.py``，自带解析器与
13 个二级子命令），并且刻意与 ``hornworkctl`` 解耦：它同时被独立入口复用。
把它再拆一遍只会制造两份需要同步的代码。

因此本模块的职责被限定为三件事，且只有三件：

1. 把 ``auth`` 挂到顶级解析器上（依赖缺失时退化为占位解析器）；
2. 把执行转交给 ``auth.cli.run(args, cfg)``；
3. **不改变**认证模块自身的异常与退出码语义。

## 关于第 3 点（重要）

认证模块初始化（``AuthEngine``）失败时，``auth.cli.run`` 内部会
``raise SystemExit(2)``（``crypto.KeyMaterialError`` 分支，带友好提示）；而
``ImportError`` 等未预期异常则**原样向上传播**，由解释器打印 traceback 并以
退出码 1 结束。

重构前后都必须保持这个行为，因此本模块**不捕获** ``auth.cli.run`` 的异常：
一旦在这里包一层 ``except Exception``，退出码就会从 1 变成 2、traceback 也会
被替换成自定义文案 —— 那是对外可见的行为变更，违反「无感迁移」红线。
"""

from __future__ import annotations

import argparse

from ..cli_common.runtime import CliRuntime

NAME = "auth"
HELP = "认证模块：三因子认证（口令 + TOTP + 人脸模板保护）"

FALLBACK_HELP = "认证模块：三因子认证（依赖未安装）"
"""``argon2-cffi`` / ``cryptography`` 缺失时的占位说明（与重构前逐字一致）。"""


def _add_parsers() -> object | None:
    """尝试导入认证子系统的解析器注册函数。

    认证模块依赖 argon2-cffi / cryptography；缺失时**不影响其他子命令**，
    因此这里把导入失败收敛成 ``None``，由 :func:`register` 走占位分支。
    这与重构前 ``hornwork/cli.py`` 顶部的 ``try/except`` 完全等价。
    """
    try:  # pragma: no cover - 取决于运行环境
        from ..auth.cli import add_parsers
    except Exception:  # noqa: BLE001 - 可选依赖缺失不应影响其他子命令
        return None
    return add_parsers


def register(sub: argparse._SubParsersAction) -> None:
    """挂载 ``auth`` 子命令树（依赖缺失时退化为占位解析器）。"""
    add_parsers = _add_parsers()
    if add_parsers is None:
        parser = sub.add_parser(NAME, help=FALLBACK_HELP)
        parser.add_argument("auth_args", nargs=argparse.REMAINDER)
        return
    add_parsers(sub)  # type: ignore[operator] - 动态导入后的可调用对象


def run(ctx: CliRuntime) -> int:
    """转交给认证子系统的 ``run(args, cfg)``（异常语义原样保留）。"""
    from ..auth.cli import run as auth_run

    return auth_run(ctx.args, ctx.cfg)
