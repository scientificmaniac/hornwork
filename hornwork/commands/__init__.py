"""子命令模块包：一个子命令 = 一个模块 = 一份业务逻辑。

## 模块契约

每个命令模块固定导出四项：

=================  ==========================================================
符号                含义
=================  ==========================================================
``NAME``           子命令名，同时是 ``argparse`` 的 dest 与调度键
``HELP``           ``--help`` 里的一行说明
``register(sub)``  把该命令（含其二级子命令）挂到解析器上
``run(ctx)``       执行命令，返回进程退出码
=================  ==========================================================

多级子命令（``scan`` / ``lab`` / ``vuln`` / ``asset`` …）在其**专属子包或同目录**
再开模块，由该命令的 ``run`` 做一层分派，保证「一个文件 = 一个业务关注点」，
单文件不会长成第二个 1552 行。``scan`` 因为二级子命令最多（13 个），单独成包：

```text
commands/
├── scan/
│   ├── __init__.py      # 注册与静态分派表
│   ├── file.py plan.py run.py status.py findings.py finding.py
│   ├── diff.py coverage.py report.py snapshot.py cve.py
│   └── retry.py cancel.py
```

## 两条硬约束

1. **命令之间禁止互相 import**。共享逻辑一律下沉到 :mod:`hornwork.cli_common`；
2. 模块顶层**只允许**导入 :mod:`hornwork.cli_common` 与标准库。业务子系统
   （``scan`` / ``lab`` / ``respond`` / ``verify`` …）必须在函数内惰性导入 ——
   这样缺 yara/argon2 的环境里，未受影响的子命令仍可正常工作。
"""

from __future__ import annotations

# 顺序即 ``--help`` 中顶层子命令的展示顺序，与重构前逐一对应。
from . import (
    alerts,
    asset,
    audit,
    auth,
    case,
    events,
    export,
    forensics,
    intel,
    lab,
    mem,
    prune,
    respond,
    rules,
    scan,
    status,
    verify,
    vuln,
)

COMMANDS = (
    status,
    events,
    alerts,
    scan,
    asset,
    mem,
    rules,
    intel,
    case,
    respond,
    verify,
    audit,
    forensics,
    lab,
    vuln,
    auth,
    export,
    prune,
)
"""按展示顺序排列的全部内置命令模块。"""

__all__ = ["COMMANDS"]
