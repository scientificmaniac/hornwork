"""CLI 层的共享常量。

判定标准：只收录「跨 ≥2 个子命令模块使用」或「属于对外契约」的字面量。
后者尤指 ``argparse`` 的 ``choices`` 与默认值 —— 它们会原样出现在 ``--help``
与参数解析结果里，改动即构成对外行为变更，因此必须只改一处。

依赖约束：本模块不得导入 ``hornwork.cli`` 或任何 ``hornwork.commands.*``，
以保证依赖方向恒为「公共层 ← 命令层 ← 入口」。
"""

from __future__ import annotations

from typing import Final

# --------------------------------------------------------------------------- 退出码
# 集中定义的理由：脚本与 CI 依赖这些数值，散落各处的字面量容易被改坏。
EXIT_OK: Final = 0
"""成功。"""

EXIT_FAIL: Final = 1
"""业务失败（审计断链、计划/资产状态未变更、报告生成失败等）。"""

EXIT_USAGE: Final = 2
"""用法或前置条件不满足（daemon 未运行、目标不存在、参数非法）。"""

EXIT_INTERRUPT: Final = 130
"""被 SIGINT 打断；沿用 shell 惯例 ``128 + SIGINT(2)``。"""

# --------------------------------------------------------------------------- 默认值
DEFAULT_SOCKET: Final = "/run/hornwork/ctl.sock"
"""控制面 Unix socket 默认路径，与 ``config.py`` 的 ``ctl.socket`` 默认值一致。"""

DEFAULT_TIMEOUT: Final = 600
"""控制面超时秒数。

类型必须保持 ``int``：``--timeout`` 声明为 ``default=600, type=float``，
其中 ``type`` 只作用于用户输入，默认值按原样保存。这一组合决定了 argparse
内部把默认值显示/比较成 ``600`` 还是 ``600.0``，因此**不要**改成 ``600.0``
—— 那是对外契约里一个看不见但真实存在的差异。
"""

DEFAULT_CONFIG_CANDIDATES: Final = ("/opt/hornwork/config.toml", "config.toml")
"""未显式指定 ``-c/--config`` 时的搜索顺序：部署路径优先，其次当前工作目录。"""

DEFAULT_RAW_DIR: Final = "./raw"
"""``general.raw_dir`` 未配置时，离线导出的落盘目录。"""

# --------------------------------------------------------------------------- choices
# 顺序与内容必须与重构前逐字一致：argparse 按列表顺序渲染 "{a,b,c}"。
SCAN_PLAN_KINDS: Final = [
    "daily", "weekly", "quarterly", "targeted", "manual", "verify-fix", "change",
]
"""``scan plan add --kind`` 的取值。"""

SCAN_PROFILES: Final = ["quick", "weekly", "full", "targeted", "verify-fix"]
"""扫描 profile 取值（``scan plan add --profile`` 与 ``scan run --profile`` 共用）。"""

ASSET_ROLES: Final = [
    "self", "server", "web", "db", "lab", "workstation", "network", "windows",
]
"""``asset add --role`` 的取值。"""

FINDING_STATUSES: Final = [
    "new", "observed", "confirmed", "false_positive", "fixed", "reopened",
]
"""``scan finding set --status`` 的取值（finding 生命周期状态机）。"""

RESPOND_MODES: Final = ["observe", "dry-run", "enforce"]
"""``respond --mode`` 的取值；``observe`` 为默认（不触碰目标）。"""

CVE_IMPORT_SOURCES: Final = ["nvd", "oval"]
"""``scan cve import --source`` 的取值。"""

EXPORT_FORMATS: Final = ["md", "jsonl"]
"""``export --format`` 的取值。"""

SCAN_REPORT_FORMATS: Final = ["html", "json"]
"""``scan report --format`` 的取值。"""

VULN_REPORT_FORMATS: Final = ["md", "json", "csv"]
"""``vuln report --format`` 的取值。"""

# --------------------------------------------------------------------------- 兼容层
SCAN_SUBCOMMANDS: Final = {
    "file", "plan", "run", "status", "findings", "finding", "diff",
    "coverage", "report", "snapshot", "cve", "retry", "cancel",
}
"""``scan`` 的二级子命令全集。

供 :func:`hornwork.cli._normalize_argv` 判定 ``hornworkctl scan <file>`` 这类
旧写法（把路径当作第一个位置参数）是否需要补 ``file`` 子命令。
"""

# --------------------------------------------------------------------------- 提示语
EMPTY_TABLE: Final = "（无数据）"
"""``print_table`` 在无数据行时的占位提示。"""
