# CLI 按子命令模块化拆分（重构说明）

> 对象：`hornwork/cli.py`，重构前 **1552 行**，单文件承载全部 CLI 子命令实现与
> argparse 定义。目标：按子命令维度模块化，解耦并便于后续维护与新增子命令，
> **对外接口无感迁移**。

## 1. 结论速览

| 指标 | 重构前 | 重构后 |
|---|---|---|
| `hornwork/cli.py` | 1552 行 | **117 行**（只做注册/归一化/调度） |
| 承担实现的文件数 | 1 | **53**（`cli_common/` 12 + `commands/` 41） |
| 最大单文件行数 | 1552 | **209**（`commands/scan/run.py`） |
| 子命令之间互相 import | 无（同文件自然无此问题） | **0**（架构自检强制） |
| 命令树节点数 | 119 | **119**（逐字一致） |
| `--help` / 参数元数据 diff | — | **0 行差异** |
| 63 条命令行为 diff（归一化后） | — | **4 条变化**，全部是第 10 节两个缺陷的修复 |
| 单元测试 | 525 项 | **559 项**（新增 34 项：架构约束 + 缺陷回归） |

## 2. 目录结构

```text
hornwork/
├── cli.py                      # 入口：117 行，注册 + argv 归一化 + 调度
├── cli_common/                 # 公共层（子命令模块唯一允许依赖的横向设施）
│   ├── __init__.py             # 依赖方向约束的文档化（含 ASCII 架构图）
│   ├── constants.py            # 退出码 / choices / 默认值 / 兼容子命令集
│   ├── errors.py               # CliError + NotFound/Unavailable/Rejected 三态
│   ├── output.py               # print_json / print_table（唯一输出原语）
│   ├── validation.py           # 端口解析 / CSV 拆分 / JSON 参数 / daemon 前置校验
│   ├── io.py                   # 导出落盘 / 时间戳文件名 / CSV 读取 / 报告目标归一
│   ├── http.py                 # urllib 薄封装（供未来在线子命令）
│   ├── logging.py              # stderr 提示前缀（[错误]/[warn]/[!]/[i]）
│   ├── config.py               # 配置文件查找顺序 + socket 路径推导
│   ├── runtime.py              # CliRuntime：参数+配置+ctl 客户端+惰性 SQLite
│   ├── timefmt.py              # 时间戳统一渲染
│   └── labsupport.py           # 靶场 LabCtl 的事件库/审计链装配
└── commands/                   # 命令层：一个子命令 = 一个模块
    ├── __init__.py             # COMMANDS 注册表（顺序即 --help 展示顺序）
    ├── status.py  events.py  alerts.py  mem.py  rules.py  intel.py
    ├── case.py  respond.py  verify.py  audit.py  forensics.py
    ├── export.py  prune.py  auth.py  asset.py  lab.py  vuln.py
    └── scan/                   # scan：13 个二级子命令，各自一个文件
        ├── __init__.py         # 注册 + 静态分派表
        ├── file.py  plan.py  run.py  status.py  findings.py  finding.py
        ├── diff.py  coverage.py  report.py  snapshot.py  cve.py
        └── retry.py  cancel.py
```

## 3. 子命令映射清单

### 3.1 顶级子命令（18 条）

| 原子命令 | 新模块 | 原 `Cli` 方法 |
|---|---|---|
| `status` | `commands/status.py` | `cmd_status` |
| `events` | `commands/events.py` | `cmd_events` |
| `alerts` | `commands/alerts.py` | `cmd_alerts` |
| `scan` | `commands/scan/__init__.py`（分派） | `cmd_scan` + `_cmd_scan_subsystem` |
| `asset` | `commands/asset.py` | `cmd_asset` |
| `mem` | `commands/mem.py` | `cmd_mem` |
| `rules` | `commands/rules.py` | `cmd_rules` |
| `intel` | `commands/intel.py` | `cmd_intel` |
| `case` | `commands/case.py` | `cmd_case` |
| `respond` | `commands/respond.py` | `cmd_respond` |
| `verify` | `commands/verify.py` | `cmd_verify` |
| `audit` | `commands/audit.py` | `cmd_audit` |
| `forensics` | `commands/forensics.py` | `cmd_forensics` |
| `lab` | `commands/lab.py` | `cmd_lab` + `_lab_ctl` + `_print_lab_result` |
| `vuln` | `commands/vuln.py` | `cmd_vuln` + `_vuln_module` |
| `auth` | `commands/auth.py` | `cmd_auth`（转发 `auth/cli.py`） |
| `export` | `commands/export.py` | `cmd_export` |
| `prune` | `commands/prune.py` | `cmd_prune` |

### 3.2 `scan` 的二级子命令（13 条，一个子命令一个文件）

| 原子命令 | 新模块 | 原 `Cli` 方法 |
|---|---|---|
| `scan file` | `commands/scan/file.py` | `_cmd_scan_file` + `_offline_scan` |
| `scan plan` | `commands/scan/plan.py` | `_cmd_scan_plan` |
| `scan run` | `commands/scan/run.py` | `_cmd_scan_run` + `_print_scan_summary` |
| `scan status` | `commands/scan/status.py` | `_cmd_scan_status` |
| `scan findings` | `commands/scan/findings.py` | `_cmd_scan_findings` |
| `scan finding` | `commands/scan/finding.py` | `_cmd_scan_finding_set` |
| `scan diff` | `commands/scan/diff.py` | `_cmd_scan_diff` |
| `scan coverage` | `commands/scan/coverage.py` | `_cmd_scan_coverage` |
| `scan report` | `commands/scan/report.py` | `_cmd_scan_report` |
| `scan snapshot` | `commands/scan/snapshot.py` | `_cmd_scan_snapshot` |
| `scan cve` | `commands/scan/cve.py` | `_cmd_scan_cve` + `_import_cve_exclude` |
| `scan retry` | `commands/scan/retry.py` | `_cmd_scan_retry` |
| `scan cancel` | `commands/scan/cancel.py` | `_cmd_scan_cancel` |

### 3.3 公共逻辑抽离映射

| 原 `cli.py` 中的内容 | 去向 |
|---|---|
| `_print_json` | `cli_common/output.py::print_json` |
| `_table` | `cli_common/output.py::print_table` |
| `_fmt_ts` | `cli_common/timefmt.py::format_ts` |
| `Cli.ctl` / `store` / `daemon_up` / `emit` | `cli_common/runtime.py::CliRuntime` |
| `main()` 里的配置文件查找 | `cli_common/config.py::resolve_config_path` |
| `SCAN_SUBCOMMANDS` 常量 | `cli_common/constants.py` |
| 端口字符串解析（`asset add --ports`） | `cli_common/validation.py::parse_ports` |
| `--engines` 逗号/空格拆分 | `cli_common/validation.py::split_csv` |
| `--params` JSON 解析 | `cli_common/validation.py::parse_json_arg` |
| 各处 `"[错误] X 需要 daemon 运行"` + `return 2` | `cli_common/validation.py::require_daemon` + `errors.py` |
| 离线导出的目录/文件名/写 JSONL | `cli_common/io.py` |
| `vuln report --out` 传目录补时间戳 | `cli_common/io.py::resolve_report_target` |
| `_lab_ctl` 的事件/审计 sink | `cli_common/labsupport.py::build_lab_ctl` |

## 4. 架构约束（可执行）

`tools/check_cli_layout.py` 把这些约束变成 CI 可执行的检查，而不是文档口号：

```bash
python tools/check_cli_layout.py       # 退出码 0 = 全部通过
python tools/check_cli_layout.py -v    # 附带每个文件的行数明细
```

检查项：

1. **依赖方向**：`cli_common/*` 不得 import `hornwork.cli` 或 `hornwork.commands.*`；
2. **命令隔离**：`commands/*` 之间零互相 import（子包 `__init__` 导入自身成员除外）；
3. **导入健康**：逐个 import 每个模块（含 `commands/scan/*`），捕获循环导入与导入期异常；
4. **命令契约**：每个模块导出 `NAME`/`HELP`/`register`/`run`，同一层级内 `NAME` 唯一；
5. **注册表一致**：`COMMANDS` 与磁盘文件（含子包 `x/__init__.py`）一一对应；
6. **文件体量**：单文件 ≤ 400 行，入口 ≤ 200 行。

同样的约束在 `tests/test_cli_layout.py` 里有 15 个单元测试覆盖（含顶层顺序、
`scan <path>` 兼容归一化、`SCAN_SUBCOMMANDS` 与实际挂载一致、子包模块契约）。

## 5. 依赖方向

```text
  cli.py (入口, 117 行)
      │  只导入 commands 注册表 + cli_common.config
      ▼
  commands/*  (每个子命令一个模块)
      │  只导入 cli_common + 自己的业务子系统（函数内惰性导入）
      ▼
  cli_common/*  (横向基础设施)
      │
      ▼
  hornwork.{config,store,schema,client,...}  (业务子系统)
```

三条禁令：`cli_common` 不依赖上层；`commands` 之间不互相依赖；入口不含业务逻辑。

**循环导入的规避方式**：命令模块顶层只 import `cli_common` 与标准库；对业务
子系统（`scan`/`lab`/`vuln`/`verify`/`respond`…）一律**函数内惰性导入**。这既
避免了环，也带来一个额外收益：缺少可选依赖（`yara-python`/`argon2-cffi`）时，
未受影响的子命令仍可正常使用 —— 已在实机上验证。

## 6. 分步迁移改造顺序（低风险优先）

实际执行顺序，每一步都可独立验证、独立回滚：

| 步骤 | 内容 | 风险 | 验证手段 |
|---|---|---|---|
| **0** | 建立基线：`cli_surface.py` 导出 119 节点 help+参数树；75 条命令行为快照 | 无（只读） | diff 为空 |
| **1** | 抽 `cli_common/output.py`、`timefmt.py`、`constants.py` | 极低 | `--help` diff 为 0 |
| **2** | 抽 `cli_common/runtime.py`（`Cli` → `CliRuntime`） | 低 | 逐个迁移 `status`/`events`/`alerts` 三个只读命令后跑行为快照 |
| **3** | 迁移无二级子命令的命令：`mem`/`rules`/`intel`/`case`/`respond`/`audit`/`forensics`/`export`/`prune` | 低 | 每条命令 `--help` + 一次执行快照 |
| **4** | 迁移 `asset`（台账，离线可用） | 低 | 离线 `asset add/list/show` 全流程 |
| **5** | 迁移 `verify`（含 root 分支判定） | 中 | `verify run --no-execute` + root 路径人工确认 |
| **6** | 迁移 `lab`（事件/审计双 sink） | 中 | `lab list/status`；`lab up` 用不存在的 env 验证拒绝路径 |
| **7** | 迁移 `vuln`（档案校验 + 报告落盘） | 中 | `vuln record sync`、`vuln report --out <dir>` |
| **8** | 拆 `scan` 成子包：先 `file`/`plan`/`status`/`findings`，再 `run`/`diff`/`coverage`/`report`/`snapshot`/`cve`/`retry`/`cancel` | 中 | 全部 `scan` 子命令的 `--help` + 离线执行快照 |
| **9** | `auth` 仅做转发（保留其独立解析器与异常语义） | 低 | 缺 argon2 环境下退出码必须仍为 1 |
| **10** | 重写入口 `cli.py`，加 `commands/__init__.py` 注册表 | 中 | 全量回归 + 架构自检 |
| **11** | 加 `tools/check_cli_layout.py` 与 `tests/test_cli_layout.py` 锁定结构 | 无 | CI 全矩阵 |
| **12** | 修复第 10 节两个既有缺陷 + `tests/test_scan_regressions.py` | 中（**有意改变行为**） | 行为快照只剩 4 条预期差异 |

**为什么这个顺序**：先把「输出原语」和「运行上下文」抽对（步骤 1–2），后面每个
命令的迁移都变成机械搬运；只读命令先迁（步骤 3），写路径后迁；`scan` 最复杂放
在倒数第二；入口最后重写 —— 这样任何一步出问题，回滚范围都只有当前一个文件。

## 7. 入口注册代码（实际实现）

```python
# hornwork/cli.py —— 全部内容就是这三个函数：注册 / 归一化 / 调度

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hornworkctl", description="Hornwork 控制台 CLI")
    parser.add_argument("-c", "--config", default=None, help="配置文件（默认 ...）")
    parser.add_argument("--socket", default=None, help="控制面 socket 路径")
    parser.add_argument("--json", action="store_true", help="JSON 输出")
    parser.add_argument("--timeout", default=DEFAULT_TIMEOUT, type=float, help="控制面超时秒")
    parser.add_argument("--version", action="version", version=f"hornworkctl {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for module in COMMANDS:          # ← 注册表驱动，顺序即 --help 展示顺序
        module.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(argv if argv is not None else sys.argv[1:])
    args = build_parser().parse_args(_normalize_argv(raw))
    apply_config_default(args)
    handlers = {module.NAME: module.run for module in COMMANDS}
    try:
        return handlers[args.cmd](CliRuntime(args))
    except CliError as exc:
        _report_cli_error(exc)
        return exc.exit_code
    except KeyboardInterrupt:
        return EXIT_INTERRUPT          # 130
```

新增一个子命令只需两步：写 `commands/xxx.py`，在 `commands/__init__.py`
的 `COMMANDS` 元组里加一行。**不需要改 `cli.py`。**

## 8. 单个子命令模块模板

```python
"""``hornworkctl xxx``：<一句话说明这个命令解决什么问题>。

<必要时补充：数据来源、离线/在线两条路径的差别、退出码约定>
"""

from __future__ import annotations

import argparse

from ..cli_common.constants import EXIT_FAIL, EXIT_OK
from ..cli_common.runtime import CliRuntime
from .??? import ...          # ✗ 禁止：不得 import 兄弟命令模块

NAME = "xxx"                  # 子命令名 = argparse dest = 调度键
HELP = "<--help 里的一行说明>"

COLUMNS = [("field", "表头"), ...]   # 表格列（若用 emit）


def register(sub: argparse._SubParsersAction) -> None:
    """注册 ``xxx`` 子命令。

    参数名、顺序、默认值、choices、help 文案都是对外契约，改动即破坏兼容。
    有二级子命令时在此挂 ``dest="xxx_cmd"`` 的子解析器。
    """
    parser = sub.add_parser(NAME, help=HELP)
    parser.add_argument("--limit", type=int, default=20)


def run(ctx: CliRuntime) -> int:
    """执行命令并返回进程退出码。

    - 优先 ``ctx.ctl(...)``，daemon 缺席时按需 ``ctx.store()`` 兜底；
    - 前置条件不满足 → 抛 ``CliError``（带退出码），不自行 ``print`` 后 return；
    - 输出统一走 ``ctx.emit`` / ``ctx.print_json`` / ``ctx.print_table``。
    """
    from ..xxx import service          # ← 业务子系统惰性导入，避免环与硬依赖

    if not ctx.daemon_up():
        raise CliError("xxx 需要 daemon 运行")
    data = ctx.ctl("xxx.query", {"limit": ctx.args.limit}).get("items") or []
    ctx.emit({"items": data}, _rows(data), COLUMNS)
    return EXIT_OK


def _rows(items: list[dict]) -> list[dict]:
    """把业务对象压平成表格行（保持与旧输出完全相同的字段与截断长度）。"""
    return [{"field": item.get("field")} for item in items]
```

要点：

- `NAME`/`HELP`/`register`/`run` 四项是**契约**，架构自检会校验；
- 业务子系统**函数内导入**，不在模块顶层；
- 失败一律抛 `CliError` 子类（`NotFoundError`→2、`UnavailableError`→2、
  `RejectedError`→1），由入口统一渲染，**不要**自己 `print` 后 `return`；
- 输出只走 `ctx.*`，不要在命令模块里另写一套表格/JSON 格式化。

## 9. 回归测试清单

自动化已就位：

```bash
python -m compileall -q hornwork                # 字节编译
python -m unittest discover -s tests -t .       # 559 项
python tools/check_cli_layout.py                # 架构约束
python tools/cli_surface.py dump > after.txt    # 与重构前快照 diff
```

`cli_surface.py` 覆盖全部 **119** 个命令节点的 help 文本与参数元数据（参数名、
顺序、`type`、`choices`、`default`、`required`、`metavar`）。重构前后 **0 行差异**。

### 9.1 逐命令验证场景

| 命令 | 必须验证的场景 |
|---|---|
| `status` | ① daemon 在线：全字段正常打印；② daemon 离线：`[!] daemon 未运行` + 数据库只读统计 + **退出码 1**；③ `--json` 输出结构 |
| `events` | ① `--since/--type/--layer/--limit` 各过滤；② daemon 离线直读 SQLite；③ 命令行超长截断到 80 字符；④ `--json` |
| `alerts` | ① `--level/--technique/--since`；② 嵌套 `rule.id/name/engine` 压平；③ 两张表都为空时的 `（无数据）` |
| `scan file` | ① daemon 在线走 ctl；② 离线本进程跑 Cascade；③ 命中样本的 verdict/score/hits 打印；④ 文件不存在时 `FileNotFoundError` + 退出码 1 |
| `scan plan` | ① `add` 全参数（`--asset/--tag/--min-criticality/--engines/--params/--cve`）；② `add` 幂等覆盖；③ `list` 表格列；④ `enable/disable` 状态未变更 → **退出码 1**；⑤ `rm` 的行数；⑥ `--params` 非法 JSON → 退出码 2 |
| `scan run` | ① 无 `--plan` 且无 `--profile` → 退出码 2；② `--plan` 走 `run_plan`；③ `--profile` 走 `run_adhoc`；④ `--ip` 不在台账 → 退出码 2；⑤ `--ip 127.0.0.1` 自动登记；⑥ 闸门拒绝的 `[拒绝]` 分支；⑦ 幂等命中 `[幂等]`；⑧ **Ctrl-C → 退出码 130**；⑨ `--dry-run`/`--check-only`/`--no-report` |
| `scan status/findings/finding` | ① 任务+快照两张表；② `finding set` 状态机六态；③ 不存在的 finding → 退出码 2；④ `（还没有扫描任务）` 占位语 |
| `scan diff` | ① 无快照 → 退出码 2 + 提示；② 仅一个快照 → 退出码 2；③ `--from/--to` 显式指定；④ 四态统计 |
| `scan coverage` | ① 默认取最近快照；② 无快照 → 退出码 2；③ D1–D6 矩阵；④ 未覆盖清单截断 40 条 |
| `scan report` | ① `--format html/json`；② `--out` 传目录；③ 无快照 → 退出码 2；④ 生成失败 → **退出码 1** |
| `scan snapshot` | ① `list --limit`；② `base` 成功 → 0；③ `base` 无效 ID → **退出码 2** |
| `scan cve` | ① `import --source nvd --file`（可重复）/`--dir`；② `import --source oval --release`；③ 缺 `--file` → 退出码 2；④ `stats` 含 `severity_dist`；⑤ `map/exclude` 省略 `--file` 用配置默认路径；⑥ 排除项 CSV 的空行计入 `skipped` |
| `scan retry/cancel` | ① 不存在的 run → 输出 `requeued:0` / `aborted:0` 且退出码 0；② `--reason` 缺省为 `人工取消` |
| `asset` | ① `add` 全参数 + `--ports "80,443;8080"` 混用分隔符；② 重复 IP → `[错误]` + 退出码 2；③ `show` 支持 ID 或 IP；④ `enable/disable` 未变更 → 退出码 1；⑤ `list` 表格 8 列 |
| `mem` | ① 无 daemon → `[错误] mem scan 需要 daemon 运行` + 退出码 2（scan/verify 各一条）；② 有 daemon 的 JSON 透传 |
| `rules` | ① `reload` 无 daemon → 退出码 2；② `list` 在线走 status；③ 离线数文件（`.yar`/`.rules`/`.json`/`.yml`） |
| `intel` | ① `import`/`build` 无 daemon → 退出码 2；② `list --type/--limit`；③ 离线 `ioc_list` |
| `case` | ① `create` 无 daemon → 退出码 2；② `show` 不存在 → `[错误] 工单不存在` + 退出码 2；③ `list --status/--limit`；④ 标题截断 50 字符 |
| `respond` | ① 无 daemon → 退出码 2；② `--mode` 三选一（默认 observe）；③ `--playbook` 默认 PB-001 |
| `verify` | ① 非 root 走 `verify.run`；② root 且非 `--remote` 走本进程（`mem.scan` 就地）；③ `--no-execute`；④ `--json`；⑤ 用例表 + TP/TN/FP/FN 汇总行 |
| `audit` | ① 在线 `audit.verify`；② 离线本地重算哈希链；③ 完整 → 0 / 断链 → **1** + `审计链断链于 seq=` |
| `forensics` | ① 无 daemon → 退出码 2；② `collect --compress` / `analyze --image` / `compare --malfind --since` 三个方法名正确 |
| `lab` | ① 组件缺失 → 退出码 2；② `index --force`；③ `list --type/--status/--limit`；④ `up/down/isolate` 以 `ok` 决定 0/1；⑤ `status` 单环境 vs 全局两个分支；⑥ `logs --tail` 尾部截断 20000 字符 |
| `vuln` | ① `record add` 校验失败 → 退出码 1 且**不写库**；② `--dry-run`；③ `record sync`；④ `show` 不存在 → 退出码 2；⑤ `match` 恒 JSON；⑥ `report --out` 传目录补 `vuln-report-<ts>.<fmt>` |
| `auth` | ① 缺 argon2：**退出码 1** + traceback（与重构前一致，已实测）；② `KeyMaterialError` → `SystemExit(2)`；③ 全部 13 个二级子命令 help 不变；④ 表格列宽上限 48 |
| `export` | ① 在线走 ctl；② 离线写 JSONL 到 `raw_dir`；③ `--out` 指定目录；④ `--format md` 在离线路径下仍写 JSONL（历史行为） |
| `prune` | ① 在线走 ctl；② 离线直调 `store.prune(days)`；③ `--days` 默认 30 |
| 全局 | ① `--version`；② 无子命令 → usage + 退出码 2；③ `badcmd` → 退出码 2；④ `scan /path` 旧写法自动补 `file`；⑤ `scan --deep /path` 补在正确位置；⑥ `-c/--config` 与 `--socket`/`--timeout` 生效 |

### 9.2 本轮实机验证记录（Ubuntu 26.04 / Python 3.14.4）

| 验证 | 方法 | 结果 |
|---|---|---|
| 命令树一致 | `tools/cli_surface.py` 前后各导出一次 | **0 行差异**（119 节点） |
| 行为一致 | 75 条命令的 stdout/stderr/退出码，归一化后 diff | **0 行差异**（退出码分布 0×30 / 1×12 / 2×33） |
| 归一化可信度 | 人为把一条 `EXIT: 0` 改成 `1`，确认能检出 | 检出（diff 非空） |
| 缺可选依赖 | 伪造 `yara.py`/`argon2.py` 抛 ImportError，对比 12 条命令 | 退出码 **12/12 一致** |
| 单元测试 | `unittest discover` | **559 项通过**（skip 3） |
| 架构约束 | `tools/check_cli_layout.py` | **全部通过** |

### 9.3 本轮未能覆盖的场景（需在已部署 daemon 环境补测）

采集机没有 daemon、没有 `/var/lib/hornwork`、用户非 root，因此以下路径实机无法构造：

- daemon 在线时的全部成功路径：`status` 实时分支、`events`/`alerts`/`case`/`intel`
  的 ctl 分支、`rules reload`、`intel import/build`、`respond`、`mem scan/verify`、
  `forensics collect/analyze/compare`、`audit verify` 在线分支、`prune` 在线分支；
- 真实扫描全流程（`scan run` 端到端、`scan file` 命中真实样本）；
- 真实靶场编排（`lab up/down/logs/isolate` 的成功态）；
- `auth` 三因子登录、TOTP、生物识别的成功路径；
- 所有需要 root 的用例（`verify run` 的 TC-03/04/05/06/10）。

建议在部署环境按 9.1 清单补跑一轮，尤其是 `--json` 的 ctl 分支，形成完整证据链。

## 10. 重构中发现并已修复的两个既有缺陷

这两个问题在重构前就存在。按「行为零变化」红线，重构阶段**刻意未修**以保留
逐字兼容的证明；随后应要求**单独修复**，并各自配了回归测试。

### 10.1 `scan run --profile ... --check-only` 的 `--check-only` 被静默丢弃

- **现象**：`scan run --profile quick --check-only` 本应"只做闸门与目标选择"，
  实际却**真的执行了扫描**。风险：以为在演练，结果动了生产目标。
- **根因**：`scan/runner.py::run_adhoc` 的签名里没有 `check_only`；CLI 的 adhoc
  分支也没有透传。只有 `run_plan` 实现了该分支。
- **修复**：
  - `run_adhoc(..., check_only: bool = False)`，在闸门通过后、**建任务之前**返回
    `would_scan` 计划；
  - `commands/scan/run.py::_execute` 在 adhoc 分支透传 `check_only=bool(args.check_only)`。
- **行为变化**（有意）：带 `--check-only` 的临时扫描不再创建任务与快照。
- **回归测试**：`tests/test_scan_regressions.py::RunAdhocCheckOnlyTest`
  （断言 `run_adhoc` 接受该参数、`check_only=True` 时任务表与快照表均为空）。

### 10.2 全新数据目录上扫描只读命令抛 `no such table`

- **现象**：空库上 `scan status` / `scan findings` / `scan finding set` /
  `scan plan list` 直接抛 `sqlite3.OperationalError: no such table`，退出码 1 +
  traceback。原因是只有写路径（`upsert_plan` 等）会调 `init_schema`。
- **修复**：在数据访问层新增 :func:`hornwork.scan.store.ensure_schema` ——
  幂等且**每个 `Store` 实例只真正执行一次**（实例上打标记），并接入 30 个
  会触碰 `scan_*` 表的入口函数。
- **为什么不下沉到 CLI**：修在数据访问层，CLI、Web 只读查询、daemon 三条调用
  路径同时受益，也不需要 30 个读函数各加一行。
- **行为变化**（有意）：空库上这些命令现在返回 `（无数据）` / `（没有 finding）`
  且退出码 0；`scan finding set --id NO-SUCH` 现在正确给出
  `[错误] finding 不存在：NO-SUCH` + 退出码 2。
- **回归测试**：`tests/test_scan_regressions.py::EmptyDatabaseReadTest`。

### 10.3 这两处修复对兼容性基线的影响

63 条命令的行为快照里**只有 4 条**发生变化，全部是上述两个缺陷的修复：

| 命令 | 修复前 | 修复后 |
|---|---|---|
| `scan status` | 退出码 1 + `no such table: scan_task` | 退出码 0 + 计数行 + 两张空表占位语 |
| `scan findings --limit 3` | 退出码 1 + `no such table: scan_finding` | 退出码 0 + `（没有 finding）` |
| `scan finding set --id NO-SUCH --status confirmed` | 退出码 1 + `no such table: scan_finding` | 退出码 **2** + `[错误] finding 不存在：NO-SUCH` |
| `scan plan list` | 退出码 1 + `no such table: scan_plan` | 退出码 0 + `（无数据）` |

其余 **59 条命令的输出与退出码仍逐字一致**，`--help`/参数树 **119 节点 0 行差异**。

> 基线采集以 `git archive HEAD` 导出的纯净原版为对照（`/tmp/orig-repo`），
> 而不是工作区副本 —— 后者还包含他人未提交的业务改动，会污染对比结果。
> 归一化规则已覆盖并排除这些非 CLI 因素（如 `verify/runner.py` 里 `run_id`
> 的 uuid 后缀，属仓库既有实现差异）。

## 11. 与既有入口的兼容

| 既有用法 | 状态 |
|---|---|
| `hornworkctl`（`pyproject.toml` 的 `hornwork.cli:main`） | 不变 |
| `python -m hornwork.cli` | 不变 |
| `make rules`（`from hornwork.cli import main`） | 不变 |
| `scripts/*.sh` 里的 `-m hornwork.cli ...` | 不变 |
| `hornworkctl scan <path>` 旧写法 | 不变（`_normalize_argv` 补 `file`） |
