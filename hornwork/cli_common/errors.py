"""CLI 层通用异常与「失败前置条件」的统一表达。

设计要点：
- **不改变退出语义**。重构前的各类前置检查都是「打印 `[错误] xxx` 到 stderr
  并 ``return 2``」，本模块把这套模式收敛成一个异常 :class:`CliError`，
  由入口统一转换成 stderr 文案 + 退出码，输出逐字保持原样。
- 只有真正「无法继续」的前置条件才抛异常；能降级的分支（例如 daemon 未运行
  时改读 SQLite）仍走原有返回值路径，不抛异常。
"""

from __future__ import annotations

from ..cli_common.constants import EXIT_FAIL, EXIT_USAGE


class CliError(RuntimeError):
    """可预期的 CLI 失败：携带退出码与面向用户的单行提示。

    Parameters
    ----------
    message:
        面向用户的提示正文，**不含** ``[错误]`` 前缀（入口负责加）。
    exit_code:
        进程退出码，默认 ``2``（用法/前置条件不满足），与重构前一致。
    hint:
        可选补充说明，输出为下一行的缩进提示；默认不输出任何额外内容。
    """

    def __init__(self, message: str, exit_code: int = EXIT_USAGE, hint: str | None = None):
        super().__init__(message)
        self.message = message
        self.exit_code = int(exit_code)
        self.hint = hint


class NotFoundError(CliError):
    """目标对象不存在（资产/工单/档案/finding/快照）。"""

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message, exit_code=EXIT_USAGE, hint=hint)


class UnavailableError(CliError):
    """所需能力不可用（daemon 未运行、可选模块缺失、依赖未安装）。"""

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message, exit_code=EXIT_USAGE, hint=hint)


class RejectedError(CliError):
    """业务规则拒绝执行（校验失败、闸门不通过、状态未变更）。"""

    def __init__(self, message: str, hint: str | None = None):
        super().__init__(message, exit_code=EXIT_FAIL, hint=hint)
