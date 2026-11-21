"""CLI 公共层：子命令模块唯一允许依赖的横向基础设施。

本包解决重构前 ``cli.py`` 里反复出现的横切逻辑，按职责分为：

=================================  ===============================================
模块                                职责
=================================  ===============================================
:mod:`~hornwork.cli_common.constants`  对外契约常量（退出码、choices、默认值）
:mod:`~hornwork.cli_common.errors`     可预期失败的统一表达（带退出码）
:mod:`~hornwork.cli_common.output`     JSON / 等宽表格输出原语
:mod:`~hornwork.cli_common.validation` 参数校验与字符串→基础类型解析
:mod:`~hornwork.cli_common.io`         导出落盘、CSV 读取、目标路径归一
:mod:`~hornwork.cli_common.http`       ``urllib`` 薄封装（供未来的在线子命令）
:mod:`~hornwork.cli_common.logging`    stderr 提示前缀与可选结构化日志
:mod:`~hornwork.cli_common.config`     配置文件查找顺序与 socket 路径推导
:mod:`~hornwork.cli_common.runtime`    :class:`CliRuntime` 运行上下文
:mod:`~hornwork.cli_common.labsupport` 靶场子系统的事件/审计装配
=================================  ===============================================

## 依赖方向（硬约束）

```text
  cli.py (入口)
      │  只导入 commands 注册表 + cli_common.config
      ▼
  commands/*   (每个子命令一个模块)
      │  只导入 cli_common + 自己的业务子系统
      ▼
  cli_common/*  (横向基础设施)
      │
      ▼
  hornwork.{config,store,schema,client,...}  (业务子系统)
```

三条禁令：

1. ``cli_common`` **不得**导入 ``hornwork.cli`` 或 ``hornwork.commands.*``；
2. ``commands`` 之间**不得**互相导入（共享逻辑一律下沉到本包）；
3. 入口 ``cli.py`` **不得**包含业务逻辑或 argparse 细节以外的实现。

## 为什么不做成 "utils.py"

按职责分文件而非堆成一个大 ``utils`` 模块，是为了让"改表格列宽"和"改退出码"
落在不同文件、不同评审人手里；也让每个文件保持在百行量级，符合"避免超大文件"。
"""

from __future__ import annotations

__all__ = [
    "config",
    "constants",
    "errors",
    "http",
    "io",
    "labsupport",
    "logging",
    "output",
    "runtime",
    "validation",
]
