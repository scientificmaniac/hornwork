# 开发者指南（development）

> 面向要改代码、加规则、加引擎、写 playbook 或跑测试的贡献者。命令与路径均与仓库当前
> 实现一致（`Makefile`、`pyproject.toml`、`scripts/`、`tests/`）；部署与运维细节见
> `docs/runbook.md`，架构见 `docs/architecture.md`。

## 1. 运行环境

| 项 | 要求 | 说明 |
|---|---|---|
| 目标运行环境 | Linux（Ubuntu 24.04/26.04） | 采集/抓包/inotify/内存扫描/控制面 socket 都依赖 Linux |
| Python | **3.11+** | `pyproject.toml` 的 `requires-python = ">=3.11"`；`scripts/setup.sh` 按发行版准备 3.12+ |
| 三方依赖 | `yara-python==4.5.4`、`PyYAML==6.0.3` | 只有这两个；其余全部标准库 |
| 外部二进制（可选） | `nmap`、`dpkg-query`、`lynis`、`testssl.sh`、`nuclei`、`clamd`、`auditd`、`avml`、`vol` | 缺失时对应能力降级/跳过，不影响主流程 |
| 开发机 | Windows / macOS 也可 | 只能跑纯逻辑单测；Linux 专属用例自动跳过（见 §3.3） |

`Makefile` 的关键变量（可在命令行覆盖）：

```makefile
PY      ?= python3
VENV    ?= /opt/hornwork-venv
PYTHON  := $(VENV)/bin/python
HORNWORK_HOME ?= /opt/hornwork
CONFIG  ?= $(HORNWORK_HOME)/config.toml
```

## 2. 目录结构

```text
hornwork/
├── hornwork/                  # 平台代码（Python 包，入口 hornworkctl = hornwork.cli:main）
│   ├── daemon.py              # 装配：采集器/引擎/总线/存储/控制面/Web，全部线程与协程都在这里启动
│   ├── cli.py                 # hornworkctl 全部子命令（argparse）
│   ├── bus.py                 # 进程内事件总线（asyncio.Queue、背压、DLQ 回调）
│   ├── schema.py              # CanonicalEvent / DetectionAlert / 校验 / 时间与序列化
│   ├── store.py               # SQLite(WAL) 访问层与核心 DDL
│   ├── config.py              # tomllib 配置 + DEFAULTS 深合并 + cfg_get()
│   ├── log.py                 # JSONL 结构化日志（stderr + 滚动文件）
│   ├── ctl.py / client.py     # Unix socket JSON-RPC 服务端与客户端
│   ├── collectors/            # auditd / proc / fim / authlog / netcap / netdecode / persist / memscan
│   ├── engines/               # sigdb / yara / clamd / cascade / hostrules / sigma / netflow / tracker / netrules
│   ├── intel/                 # IOC 库 / feeds / intel2rule / STIX 子集
│   ├── respond/              # 工单 / playbook / 动作 / 审批门 / 审计哈希链
│   ├── verify/                # runner / judge / metrics / forensics + simulate/（脚本契约）
│   ├── web/                   # 标准库 HTTP 控制台 + 静态单页（index.html / platform.html）
│   ├── scan/                  # 定期漏洞扫描：资产/计划/任务/闸门/引擎/CVE 匹配/diff/覆盖率/报告
│   ├── lab/                   # Vulhub 靶场编排（索引/compose/端口/守卫/状态）
│   ├── vuln/                  # 漏洞档案模型 / CVSS 3.1 / 版本区间匹配 / 报告
│   ├── auth/                  # 认证子系统：Argon2id、TOTP、生物模板保护、风险、会话、审计
│   ├── harden/                # 加固编排：items.yaml、计划、幂等执行与回滚、验证、报告
│   └── tools/                 # inject_demo.c（PTRACE 注入演示）、lab_repro.py（复现取证）
├── rules/                     # 规则与情报（YARA / 网络 DSL / 主机 JSON / Sigma / sigdb / IOC / playbooks）
├── deploy/                    # systemd 单元、auditd 规则、clamd 片段、logrotate、versions.lock
├── scripts/                   # setup.sh / check.sh / demo.sh 及各子系统 setup_*.sh
├── tests/                     # unittest（16 个 test_*.py 模块）
├── tools/                     # 一次性工具：scan_accuracy.py / tune_verify.sh / 证据处理脚本
├── docs/                      # 本目录文档
├── config.toml                # 全量配置（与 hornwork/config.py 的 DEFAULTS 对应）
├── pyproject.toml             # 包元数据、依赖、hornworkctl 入口
└── Makefile                   # 常用开发命令
```

## 3. 环境搭建

### 3.1 目标主机（部署形态，推荐）

```bash
# 1) 克隆仓库后，在仓库根目录执行一键安装（需 root；幂等，可重复执行）
sudo bash scripts/setup.sh          # 等价于 make setup

# 2) 自检（逐项输出 OK/FAIL，退出码 0/1）
sudo bash scripts/check.sh          # 等价于 make check

# 3) 前台运行 daemon（看日志、调试）
make run
# 等价于：
#   /opt/hornwork-venv/bin/python -m hornwork.daemon --config /opt/hornwork/config.toml

# 4) 后台运行
sudo systemctl enable --now hornwork
```

`scripts/setup.sh` 的主要动作：apt 依赖 → 创建 `hornwork` 用户与目录 → 建 venv
（`/opt/hornwork-venv`）并安装离线轮子/PyPI 依赖 → 拷贝代码到 `/opt/hornwork` →
安装 auditd 规则与 clamd 片段 → 生成 Web token（`/etc/hornwork/env`，systemd drop-in 注入）
→ 安装 systemd 单元、`/usr/local/bin/hornworkctl`、logrotate → 启动服务。

### 3.2 本机开发（Linux 或 Windows 均可用）

```bash
# 建虚拟环境并安装依赖（只装 hornwork + 两个三方库）
python -m venv .venv
. .venv/bin/activate                 # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e .                     # 装 yara-python / PyYAML 并注册 hornworkctl 命令

# 验证 import（Windows 上不应因 Linux 调用报错）
python -c "import hornwork, hornwork.daemon, hornwork.cli; print(hornwork.__version__)"
```

> `make setup` / `make check` / `make test` 里默认使用 `/opt/hornwork-venv` 的
> `$(VENV)/bin/python`，在 Windows 上请直接敲等价的 `python -m ...` 命令，或用
> `make test VENV=...` 指向一个含 `bin/python` 的环境。

### 3.3 配置与常用环境变量

- 配置加载顺序：`-c/--config` 指定 → 否则 `/opt/hornwork/config.toml`（若存在）
  → 否则 `./config.toml`；再与 `hornwork/config.py` 的 `DEFAULTS` 深合并。
- 常用环境变量（`load_config()` 会覆盖对应配置项）：

| 变量 | 覆盖的配置项 | 用途 |
|---|---|---|
| `HORNWORK_DATA_DIR` | `general.data_dir` | 把 SQLite 放到临时目录跑 |
| `HORNWORK_RAW_DIR` | `general.raw_dir` | 证据/快照目录 |
| `HORNWORK_RULE_DIR` | `general.rule_dir` | 规则目录 |
| `HORNWORK_LOG` | `general.app_log` | 日志文件 |
| `HORNWORK_TOKEN` | `web.token` | Web 静态 Bearer token |
| `HORNWORK_APPROVED=1` | —（`respond/approve.py` 直接读环境） | 审批 `enforce` 响应动作 |

## 4. 跑测试

```bash
# 全量单测（仓库根目录执行即可；Linux 专属用例在非 Linux 上自动 skip）
python -m unittest discover -s tests -v
make test                      # 等价，用 /opt/hornwork-venv/bin/python

# 只跑某个模块
python -m unittest tests.test_core -v
python -m unittest tests.test_rules -v          # 规则结构校验（yara 未装时相关用例 skip）
python -m unittest tests.test_verify_web -v     # 验证层 + Web

# 只跑某个用例
python -m unittest tests.test_core.SchemaTest.test_new_event_and_validate -v

# 语法检查（不产生字节码之外的产物）
python -m compileall -q hornwork
make lint
```

约定：

- 测试全部用 `unittest`，没有 pytest 依赖；在**仓库根目录**运行
  `python -m unittest discover -s tests`，当前工作目录会自动进入 `sys.path`。
- `tests/` 下 16 个模块覆盖：核心 schema/store/bus、采集器、规则、引擎、扫描、
  CVE/CVSS、情报/响应、验证/Web、lab、auth、harden、版本号。
- 需要 root/yara/外部二进制的用例用 `unittest.skipUnless` 自动跳过，跳过不是失败。
- 改了接口（函数签名、数据结构、表结构）时，先改 `docs/CONTRACT.md` 再改实现，
  并同步更新 `docs/interfaces.md`。

## 5. 代码风格与约定

- **语言**：代码标识符、配置键、CLI 参数用英文；注释、文档字符串、日志消息、报告文案用中文。
- **类型**：公开函数尽量写类型标注；跨模块数据统一用 `dict`（事件/告警/Hit），
  由 `schema.validate_*` 与 `engines.base.make_hit` 保证结构。
- **时间**：一律 `schema.utc_now()` / `schema.to_utc()`，字符串 UTC ISO8601（毫秒 + `Z`），
  存储与比较都用 UTC；展示层再转本地时区。
- **序列化**：JSON 一律 `schema.dumps()`（禁止 NaN/Infinity）；单条事件/告警 ≤ 1 MB。
- **异常隔离**：单文件/单事件/单规则/单采集器失败必须 `try/except` + `log.warn`，不得中断
  主循环；需要重试的落 `dlq` 表。
- **平台隔离**：`os.fork`、`socket.AF_PACKET`、`ctypes` inotify、`/proc`、`/proc/pid/mem`
  等 Linux 专属调用只能出现在函数体内部，不得在模块导入期执行（Windows 单测依赖此约定）。
- **配置读取**：统一 `cfg_get(cfg, "dotted.key", default)`；不要新建第二套配置加载。
- **日志**：`from hornwork.log import get_logger; log = get_logger("模块名")`，
  用 `log.info("msg", key=value)` 携带结构化字段；禁止把 token/口令/密钥写日志。
- **依赖方向**：核心层（`schema/store/bus/config/log`）不依赖能力层；能力层不 import
  `daemon`；入口层（`daemon.py`、`cli.py`）负责装配。
- **文件编码**：源码、规则、文档统一 UTF-8（无 BOM）；规则/配置的改动要与
  `config.toml`、`docs/rules.md` 同步。

## 6. 如何新增检测规则

规则目录与格式详见 `docs/rules.md`。四类规则的改动方式：

### 6.1 YARA 规则（`rules/yara/*.yar`）

```yara
rule my_detection
{
    meta:
        description = "说明"
        attack = "T1105"          // 必填：ATT&CK 技术号
        severity = 70             // 必填：0–100 整数（用作 score）
        source = "hornwork-self"  // 必填
    strings:
        $a = "suspicious" ascii
    condition:
        filesize < 2MB and $a
}
```

- 文件名 stem 必须唯一（`yara_bridge` 用 stem 作 namespace）；
- 改完跑 `python -m unittest tests.test_rules -v`，再 `hornworkctl rules reload` 热加载。

### 6.2 主机行为规则（`rules/host/*.json`）

- `id / name / level(1–10) / mitre[] / event_types[] / condition`；条件树支持
  `all / any / not`，叶子为 `{"field","op","value"}`，`op ∈ eq/neq/in/nin/prefix/suffix/
  contains/regex/gt/lt/exists`；
- `event_types` 必须来自 `schema.EVENT_TYPES`（空数组表示对所有事件求值）；
- 新增后 `hornworkctl rules reload`，用 `hornworkctl alerts --technique Txxxx` 观察命中。

### 6.3 网络规则 DSL（`rules/net/*.rules`）

- 语法与字段见 `docs/rules.md` §2；单包匹配 + 行为窗口（`FlowTable`/`Tracker`）+ 去重；
- 新规则 ID 建议从 `N-02xx` 起，避免与 `intel-<bundle>` 生成规则冲突；
- 解析自检：

  ```bash
  python - <<'PY'
  from pathlib import Path
  from hornwork.engines.netrules import parse_rules
  text = Path("rules/net/hornwork-net.rules").read_text(encoding="utf-8")
  rules, errors = parse_rules(text)
  print(len(rules), errors)
  PY
  ```

### 6.4 Sigma 规则（`rules/sigma/**/*.yml`）

- 保持上游结构与内容，不本地改写检测逻辑；支持的 `logsource.category` 与字段子集见
  `docs/rules.md` §4；
- `status: test` 是否参与匹配由 `[engines.sigma].include_status_test` 决定（默认
  `config.toml` 为 `true`，`hornwork/config.py` 的 DEFAULTS 为 `false`）；
- 加载统计可在 `hornworkctl status` 的 `Sigma:` 行或 `ctl sigma.stats` 看到。

### 6.5 规则改动的验证清单

```bash
python -m unittest tests.test_rules -v
hornworkctl rules reload                # 看返回里各引擎的 {ok, rules, errors}
hornworkctl alerts --since 5m           # 观察新规则是否按预期命中
```

## 7. 如何新增检测引擎

引擎协议定义在 `hornwork/engines/base.py`，分两类：

```python
# 文件/样本扫描引擎（被 Cascade 调度）
class MyEngine(BaseScanEngine):
    name = "myengine"      # 出现在 scan_result / engine_stat / status().engines
    version = "1.0"
    cost = "fast"          # fast | medium | slow（slow 只在 deep 扫描参与）
    def available(self) -> bool: ...
    def supports(self, ctx) -> bool: ...
    def scan(self, path: str, ctx) -> list[dict]: ...   # 用 make_hit() 构造

# 事件检测引擎（被 daemon 的 detectors 调度）
class MyDetector(BaseEventEngine):
    name = "mydetector"
    def on_event(self, event: dict) -> list[dict]: ...
```

接入步骤：

1. 新建 `hornwork/engines/myengine.py`，只依赖 `engines/base.py` + `log` + `config`，
   不要 import `daemon`/`collectors`；
2. 扫描引擎：在 `hornwork/daemon.py` 的 `_build_components()` 里加入 `Cascade` 的引擎列表
   （当前是 `[self.sigdb, self.yara, self.clamav]`），并在 `[engines]` 增加开关/路径配置；
3. 事件引擎：加入 `self.detectors = [self.hostrules, self.sigma, mydetector]`，
   在 `reload_rules()` 里补 `reload()`（若支持热加载）；
4. 指标：扫描引擎在 `scan()` 内自行 `store.engine_stat_add(...)`（或由 Cascade 统一记账），
   保证 `engine.stats` 与报告里的贡献度可见；
5. 测试：在 `tests/test_engines.py` 增加协议/命中/降级用例（缺失二进制、异常、超时）；
6. 文档：更新 `docs/architecture.md` 的引擎清单与 `docs/interfaces.md` 的 Hit 说明。

## 8. 如何新增响应 playbook

playbook 是 JSON 编排（`hornwork/respond/playbook.py`），校验规则在 `validate_playbook()`：

```json
{
  "id": "PB-006",
  "name": "示例处置",
  "version": "1.0",
  "steps": [
    {"id": "s1", "action": "block_ip", "mode": "enforce",
     "params": {"ip": "${ip}"}, "timeout": 30},
    {"id": "s2", "action": "collect_forensics", "mode": "observe"},
    {"id": "s3", "action": "update_case", "params": {"status": "contained"}}
  ],
  "rollback": [{"action": "restore_file", "when": "verdict == benign"}]
}
```

约束（与代码一致）：

- 步骤 `action` 取值：6 类处置动作 `quarantine_file / kill_process / block_ip /
  isolate_host / disable_account / collect_forensics`，加回滚别名 `restore_file`，
  加工单/通知类 `open_case / update_case / close_case / notify`；
- `params` 支持 `${path}`、`${pid}`、`${ip}`、`${src_ip}`、`${dst_ip}`、`${user}`、
  `${case_id}`、`${host_id}` 占位符（上下文来自告警/工单，解析不到的键会被丢弃）；
- 步骤 `mode` 会被调用方 `run(mode=...)` **向下封顶**（总开关 observe 时，步骤写
  `enforce` 也不会真执行）；`mode ∈ observe / dry-run / enforce`；
- 失败即停：任一步失败后不再执行后续步骤，结果里保留已完成步骤明细；
- `rollback` 目前只做结构校验与声明，`PlaybookRunner` 不会自动执行；`ActionExecutor`
  可调度的回滚动作只有 `restore_file`，其余（`unblock_ip`/`enable_account`/
  `unisolate_host`）是语义占位，需要人工或上层编排处理。

使用方式：

```bash
# 内置 playbook（DEFAULT_PLAYBOOKS：PB-001…PB-005）
hornworkctl respond --case CASE-XXXX --playbook PB-001 --mode dry-run

# 自定义文件（--playbook 传路径时由 load_playbook 读取并校验）
sudo hornworkctl respond --case CASE-XXXX --playbook /opt/hornwork/rules/playbooks/PB-006.json --mode observe
```

> `respond` 需要 daemon 在线；`enforce` 还需要审批（见 `docs/runbook.md` 与
> `hornwork/respond/approve.py` 的 `HORNWORK_APPROVED`）。

## 9. 提交与 PR 流程

仓库没有绑定特定托管平台，以下流程按"本地可复现"设计：

1. **建分支**：从主分支拉 `feat/<主题>`、`fix/<主题>` 或 `docs/<主题>`；
2. **先改契约**：动接口/数据结构/表结构前先改 `docs/CONTRACT.md`（接口唯一依据），
   再改实现与 `docs/interfaces.md`；动规则改 `docs/rules.md`；动验证用例改
   `docs/verification.md` 与 `hornwork/verify/simulate/README.md`；
3. **本地验证**（PR 前必须全绿）：

   ```bash
   python -m compileall -q hornwork
   python -m unittest discover -s tests -v
   bash scripts/check.sh          # 在目标主机上；无 root 可跳过
   ```

4. **写清变更说明**：动机、影响面（哪些模块/表/接口）、验证方式（命令与结果）、
   兼容性（配置/数据库/规则是否需要迁移）；
5. **提交信息**：一行摘要 + 空行 + 正文；建议前缀 `feat:` / `fix:` / `docs:` /
   `test:` / `refactor:` / `chore:`，正文说明"为什么"而不只是"改了什么"；
6. **PR 自查清单**：
   - [ ] 单测全绿；新增逻辑有对应用例
   - [ ] 接口/表/规则/配置变更已同步文档（CONTRACT 优先）
   - [ ] 没有把 Linux 专属调用放到导入期
   - [ ] 没有把 token/口令/密钥/真实恶意样本提交进仓库
   - [ ] 日志/告警/报告文案为中文且无敏感信息
   - [ ] 若改规则：`tests.test_rules` 通过、`rules reload` 无错误

> 仓库当前没有 CI 配置文件，因此"本地跑通 + PR 描述里贴命令与结果"就是验收依据。

## 10. 调试技巧

```bash
# 1) 前台跑 daemon，日志直接进 stderr（JSONL）
make run
#    或指定配置/临时数据目录，不污染系统目录：
HORNWORK_DATA_DIR=/tmp/hw-data python -m hornwork.daemon -c config.toml

# 2) 看运行状态（含采集器、总线 dropped/errors、Sigma 统计、ctl/web 状态）
hornworkctl status
hornworkctl --json status | python -m json.tool

# 3) 按时间/类型查事件与告警
hornworkctl events --type process_create --since 10m --limit 50
hornworkctl alerts --level 9 --since 1h --limit 20
hornworkctl events --layer net --since 5m

# 4) 离线扫描单文件（无需 daemon）；--deep 才启用 ClamAV
hornworkctl scan file /tmp/sample.bin --deep

# 5) 规则热加载并核对结果
hornworkctl rules reload

# 6) 直接查库（只读排查）
sqlite3 /var/lib/hornwork/hornwork.db \
  "select count(*) from event; select count(*) from alert; select count(*) from dlq;"
sqlite3 /var/lib/hornwork/hornwork.db \
  "select ts,topic,substr(error,1,80) from dlq order by id desc limit 5;"

# 7) 只读打开控制面（手工发一条 JSON-RPC）
printf '%s\n' '{"id":1,"method":"status","params":{}}' | socat - UNIX-CONNECT:/run/hornwork/ctl.sock

# 8) 单测定位（配合 -v 与 unittest 的失败堆栈）
python -m unittest tests.test_collectors -v
```

排查思路：

- **采集不到数据**：先看 `status` 里对应采集器 `running`/`errors`/`stats`，再看
  `journalctl -u hornwork -f` 与 `/var/log/hornwork/app.jsonl`，最后确认 auditd 规则、
  inotify 权限、`CAP_NET_RAW`/`CAP_SYS_PTRACE` 是否就位。
- **告警被"吞"**：`alert` 表有 `(dedup_key, 分钟)` 唯一索引；确认不是同一分钟去重，
  必要时用 `--json alerts` 看完整 `dedup_key` 与 `_row`。
- **总线丢消息**：`status` 的 `bus.metrics.dropped` / `pending`；调大
  `[bus].event_queue_max` 或检查消费端是否被慢操作阻塞。
- **配置不生效**：确认实际加载的配置文件（`status.config` 字段），注意
  `load_config()` 会用 `DEFAULTS` 深合并，缺项不会报错。
- **Windows 上跑不了**：控制面 socket、`AF_PACKET`、inotify、`/proc/pid/mem` 都不可用；
  只能用 `--no-execute` 验证路径与纯逻辑单测。
- **报告/导出写不进去**：`ProtectSystem=strict` 下只有 `ReadWritePaths` 白名单可写，
  修改 `deploy/hornwork.service` 或把输出目录指到白名单内（见 `docs/runbook.md`）。
