# Hornwork 接口与数据模型（interfaces）

> 对应 `docs/CONTRACT.md` 的可读版说明。**契约文件是唯一接口依据**；本文档用于说明当前
> 实现（`hornwork/` 包、`config.toml`、CLI、控制面 socket、Web API）的字段与方法。
> 时间统一 UTC ISO8601（毫秒 + `Z`）；中文注释/文档字符串，代码标识符英文。

## 0. 总体架构与数据流

```text
采集层 collectors/ ──emit_event──▶ Bus("events.<layer>") ──▶ 主机检测 hostrules / sigma
        │                                                     │
        └─emit_alert─▶ Bus("alerts.raw") ──▶ daemon 落库/去重/工单联动
静态扫描 engines/ (sigdb→yara→clamav 级联) ──scan_result──▶ store
网络层 netcap → netdecode → FlowTable/Tracker → NetRuleSet ──hit──▶ alert
控制面 ctl.sock (JSON-RPC) ◀── hornworkctl CLI ──▶ daemon
Web 控制台 ──进程内 store──▶ SQLite
```

- 事件总线 topic：`events.<source_layer>`，`source_layer ∈ {host, net, memory, static, scan}`；
- 告警总线 topic：`alerts.raw`；
- 落库：`event` 表 + `alert` 表 + `scan_result` / `case_` / `action_audit` 等；
- Web 与 daemon 同进程，直接持有 `Store`（不经过控制面 socket）。

## 1. CanonicalEvent（schema v1.0）

必填：`schema_version / event_id / ts / source_layer / source_product / event_type / host.host_id`。

| 字段 | 类型 | 说明 |
|---|---|---|
| `event_id` | string(UUIDv4) | 事件唯一 ID，消费方按此幂等 |
| `ts` | string | UTC ISO8601，如 `2026-10-26T12:00:00.123Z` |
| `source_layer` | enum | `host / net / memory / static / scan` |
| `source_product` | string | 采集器名，如 `hornwork-auditd`、`hornwork-fim` |
| `event_type` | enum | 见下表 |
| `host` | object | `host_id / hostname / os` |
| `process` | object | `pid / ppid / image / cmdline / sha256 / uid / parent_image` |
| `file` | object | `path / sha256 / size / action / mode_exec` |
| `network` | object | `src_ip / src_port / dst_ip / dst_port / proto / domain / direction` |
| `user` | object | `name / uid / gid / src_ip / action` |
| `rule` | object | `id / name / engine / version / level / mitre[]` |
| `raw` | object | 采集器私有字段（`collector / audit_id / snapshot_seq` 等） |

`event_type` 取值（`hornwork.schema.EVENT_TYPES`）：

```text
process_create  process_exit  file_create  file_modify  file_delete
net_connect     dns_query     logon        logon_fail   account_create
persist_item    memory_scan   scan_result  alert        net_flow
lab_action      vuln_finding
scan_task       scan_finding  scan_window
```

> 子系统的扩展事件（`lab_action` / `vuln_finding` / `scan_task` / `scan_finding` /
> `scan_window`）复用同一事件模型与同一条总线，不另建消息通道。

## 2. DetectionAlert（schema v1.0）

在事件基础上扩展：`alert_id / rule{id,name,engine,version,level} / confidence /
mitre{tactics,techniques} / entity{host_id,src_ip,dst_ip,...} / dedup_key /
evidence[] / intel{} / contrib{first_hit,also,cost_ms} / status`。

- `level`：1–15，`schema.severity_label()` 映射为 `critical/high/medium/low/info`；
- `dedup_key = sha256(rule_id|host_id|src_ip|dst_ip|dst_port|scheme|pid|extra)[:32]`；
- `status`：`open / ack / closed`（告警侧）；工单状态机见 §8；
- 告警由 `schema.new_alert(rule, event=..., evidence=...)` 构造，规则来源可以是
  `netrules / hostrules / sigma / sigdb / yara / clamav / intel / memscan / authlog`。

示例：

```json
{
  "alert_id": "8c1e...",
  "ts": "2026-10-26T10:00:05.120Z",
  "rule": {"id": "H-0001", "name": "临时目录出现可执行文件落地", "engine": "hostrules",
           "version": "1.0", "level": 9, "mitre": ["T1105"]},
  "level": 9,
  "technique": "T1105",
  "entity": {"host_id": "lab-host", "src_ip": null, "dst_ip": null},
  "dedup_key": "…",
  "evidence": [{"file.path": "/tmp/hornwork-demo-eicar.com"}],
  "status": "open"
}
```

## 3. 规则命中 Hit

引擎统一返回 `list[dict]`，由 `hornwork.engines.base.make_hit()` 构造：

```python
make_hit(engine, rule_id, name, score, meta=None, evidence=None) -> dict
```

| 字段 | 说明 |
|---|---|
| `engine` | `sigdb / yara / clamav / hostrules / sigma / netrules / intel / memscan` |
| `rule_id` | 规则 ID（YARA 规则名、N-xxxx、H-xxxx、Sigma uuid、哈希名…） |
| `name` | 人类可读规则名 |
| `score` | 0–100，`cascade` 用其判定 verdict（≥80 malicious，≥50 suspicious） |
| `meta` | 规则元数据（`attack/severity/msg/evidence` 等） |
| `evidence` | 命中证据（offset、路径、`matched`、窗口计数等） |

分值约定（文档 §4.1.2）：hash 100 / hex 80 / 结构 70 / regex 60 / 熵 40；
YARA 取 `meta.severity`（整数）；网络规则 `severity*10`；主机规则 `min(level*10,100)`。

## 4. 存储层 `hornwork.store.Store`

SQLite WAL，单写多读。主要方法（完整见 `docs/CONTRACT.md` §1）：

| 分组 | 方法 |
|---|---|
| 事件 | `insert_event` / `query_events` / `count_events` |
| 告警 | `insert_alert` / `query_alerts` / `alerts_in_window` / `count_alerts` / `set_alert_status` |
| 扫描 | `insert_scan_result` / `scan_by_sha` / `recent_scans` / `get_hash_cache` / `set_hash_cache` |
| 引擎 | `engine_contribution` / `engine_stat_add` / `engine_stats` |
| Sigma | `sigma_stat_inc` / `sigma_stat_hit` / `sigma_stats` |
| 情报 | `ioc_upsert` / `ioc_list` / `ioc_values` / `ioc_set_status` / `ioc_aging` |
| 基线 | `baseline_upsert` / `baseline_get` / `baseline_all` |
| 工单 | `insert_case` / `update_case` / `get_case` / `list_cases` |
| 审计链 | `audit_append` / `audit_last` / `audit_rows` |
| 验证 | `insert_validation` / `validation_rows` / `latest_run_id` |
| 内存 | `insert_mem_hits` / `query_mem_hits` / `insert_mem_scan` |
| 运维 | `counts` / `prune` / `db_size_bytes` / `dlq_add` / `dlq_count` / `set_meta` / `get_meta` |

常用表：`event / alert / scan_result / hash_cache / engine_stat / ioc / baseline /
case_ / action_audit / validation / mem_hits / mem_scan / meta / dlq / sigma_stat`。

> 同一数据库还承载扫描子系统（`asset / scan_plan / scan_task / scan_finding` 等，见
> `hornwork/scan/store.py`）与认证子系统（`auth_user / auth_credential / auth_session /
> bio_template / auth_audit / auth_policy / trusted_device`，见 `hornwork/auth/db.py`）的表。

## 5. 控制面（Unix socket JSON-RPC）

- 路径：`/run/hornwork/ctl.sock`（0660 hornwork:adm），一行 JSON 请求、一行 JSON 响应；
- 客户端：`hornwork.client.CtlClient`；daemon 持有的常驻能力（查询/扫描/内存/规则/情报/
  工单/响应/验证/取证/运维）经此调用，daemon 未运行时只读命令回退直读 SQLite；
- `scan`（定期漏洞扫描）、`asset`、`lab`、`vuln`、`auth` 等子系统的命令**不经过控制面**，
  在 CLI 进程内直接读写同一个 `hornwork.db`。

| method | 参数 | 返回 |
|---|---|---|
| `status` | — | 版本/pid/主机/事件告警计数/采集器状态/总线/Web/Sigma |
| `events.query` | `{type,since,limit,layer}` | `{events:[...]}` |
| `alerts.query` | `{level,technique,since,limit}` | `{alerts:[...]}` |
| `scan.file` | `{path,deep}` | 级联扫描结果 |
| `mem.scan` | `{pid,snapshot}` | 内存扫描结果 |
| `mem.verify` | `{snapshot}` | 快照复核结果 |
| `rules.reload` | — | 各引擎/规则源重载结果 |
| `intel.import` | `{path}` | 导入条数统计 |
| `intel.build` | `{bundle}` | 生成规则包路径与统计 |
| `intel.list` | `{type,limit}` | IOC 列表 |
| `case.create` | `{alert_id}` | 新工单 |
| `case.list` | `{status,limit}` | 工单列表 |
| `case.update` | `{case_id,status,verdict}` | 工单更新结果 |
| `respond.run` | `{case_id,playbook,mode}` | playbook 执行结果 |
| `verify.run` | `{suite,execute}` | 验证报告 dict（含 metrics） |
| `audit.verify` | — | `{ok,rows,broken_seq}` |
| `forensics.collect/analyze/compare` | `{...}` | 路线 B 结果 |
| `export` | `{format,out,limit}` | 导出文件路径 |
| `prune` | `{days}` | 清理行数 |
| `engine.stats` | `{days}` | 引擎贡献统计 |
| `sigma.stats` | — | Sigma 加载/支持/命中统计 |
| `scan.window_refresh` | — | 立即刷新扫描窗口缓存（扫描器发 `scan_window` 事件后调用） |

错误体（文档 C7）：`{"code","message","retryable","detail"}`。

## 6. CLI `hornworkctl`

安装：`scripts/setup.sh` 生成 `/usr/local/bin/hornworkctl`（venv 启动器，无需 pip install -e）。

| 命令 | 说明 |
|---|---|
| `hornworkctl status` | 运行状态（daemon 未运行则打印 DB 只读统计） |
| `hornworkctl events [--type T] [--layer L] [--since 10m] [--limit 20]` | 事件查询 |
| `hornworkctl alerts [--level N] [--technique T] [--since 24h] [--limit 20]` | 告警查询 |
| `hornworkctl scan file <path> [--deep]` | 文件级联扫描（daemon 不在线时离线扫描；旧写法 `scan <path>` 自动补 `file`） |
| `hornworkctl mem scan --pid N [--snapshot]` | 在线内存扫描 |
| `hornworkctl mem verify --snapshot DIR` | 快照复核 |
| `hornworkctl rules reload` / `rules list` | 热加载 / 展示规则数量 |
| `hornworkctl intel import <path>` / `intel build --bundle ID` / `intel list` | 情报导入/生成规则包/列表 |
| `hornworkctl case list [--status S]` / `case show ID` / `case create --alert ID` | 工单 |
| `hornworkctl respond --case ID [--playbook PB-001] [--mode observe\|dry-run\|enforce]` | 响应编排 |
| `hornworkctl verify run [--suite baseline] [--no-execute]` | 验证套件 |
| `hornworkctl audit verify` | 审计链完整性 |
| `hornworkctl forensics collect\|analyze\|compare` | 整机内存取证（路线 B） |
| `hornworkctl export [--format md\|jsonl] [--out DIR] [--limit N]` | 导出报告 |
| `hornworkctl prune [--days 30]` | 数据清理 |
| `hornworkctl scan plan\|run\|status\|findings\|finding set\|diff\|coverage\|report\|snapshot\|cve\|retry\|cancel` | 定期漏洞扫描子系统 |
| `hornworkctl asset add\|list\|show\|enable\|disable` | 资产台账 |
| `hornworkctl lab index\|list\|up\|down\|status\|logs\|isolate` | 靶场编排 |
| `hornworkctl vuln record add\|sync`、`vuln list\|show\|match\|report` | 漏洞档案库 |
| `hornworkctl auth …` | 认证子系统（依赖安装后可用；子命令见 `hornwork/auth/cli.py`） |

全局参数：`-c/--config`、`--socket`、`--json`、`--timeout`、`--version`。

## 7. Web API（127.0.0.1:8787，Bearer token）

- 鉴权：`Authorization: Bearer <token>`；token 取 `config.toml [web].token` 或环境变量
  `HORNWORK_TOKEN`（`/etc/hornwork/env`，由 setup.sh 生成）；
- `/healthz` 与静态页面不需要 token；`/api/*`、`/metrics` 需要（token 为空时只允许本机）。

| 路由 | 方法 | 用途 |
|---|---|---|
| `/healthz` | GET | 健康检查（版本/uptime/采集器/鉴权开关） |
| `/metrics` | GET | Prometheus 文本指标 |
| `/api/overview` | GET | 概览计数 |
| `/api/events` | GET | `type/since/limit` 过滤 |
| `/api/alerts` | GET | `level/technique/since/limit` 过滤 |
| `/api/rules` | GET/POST | 规则列表 / 记录热加载请求（实际重载用 `hornworkctl rules reload`） |
| `/api/intel` | GET/POST | IOC 列表 / 导入 |
| `/api/cases` | GET/POST | 工单列表 / 创建 |
| `/api/validate` | GET | 最近验证报告 |
| `/api/engine-stats` | GET | 引擎贡献统计 |
| `/api/export` | GET | 导出 JSONL/Markdown |

> 路由全集见 `hornwork/web/server.py`，还包括 `/api/lab/envs`、`/api/vuln/records`、
> `/api/harden/status`、`/api/scan/{overview,plans,tasks,findings,snapshots,diff,coverage,cve,reports}`、
> `/api/auth/{users,sessions,audit,policy}` 以及 POST `/api/auth/login|step-up|logout`；
> 静态页为 `GET /` 与 `GET /platform`（`web/static/platform.html`）、`GET /index.html`
> （`web/static/index.html`）。

## 8. 情报/响应/验证层接口

```python
# hornwork/intel/iocstore.py
IocStore(store, cfg).import_records(records) -> {"imported","skipped","total"}
IocStore.values(kind) -> set[str]          # kind: ip/domain/hash/url
IocStore.provider(kind) -> callable        # 传给 NetRuleSet(ioc_provider=...)

# hornwork/intel/intel2rule.py
build(store, cfg, bundle_id="bundle-1") -> dict   # 产物写 rules/yara|net|intel
validate_files(paths) -> dict                     # YARA 试编译 + NetRuleSet 试解析

# hornwork/respond/case.py
CaseManager(store, cfg).create_from_alert(alert, title=None) -> dict
CaseManager.update(case_id, status=None, verdict=None) -> bool
# 状态机：open → investigating → contained → closed；verdict ∈ tp/fp/benign/unknown

# hornwork/respond/actions.py
ActionExecutor(store, cfg).execute(action, params, mode="observe") -> dict
verify_chain(rows) -> (ok, broken_seq)
# 动作：quarantine_file / kill_process / block_ip / isolate_host /
#       disable_account / collect_forensics / restore_file
# mode：observe（只记录）/ dry-run（打印命令）/ enforce（真执行，仅 Linux）

# hornwork/respond/playbook.py
load_playbook(path) -> dict；validate_playbook(pb) -> list[str]
PlaybookRunner(store, actions).run(case_id, playbook, mode="observe") -> dict

# hornwork/verify/runner.py
VerifyRunner(store, cfg, ctl_call=None).run(suite="baseline", window_sec=None, execute=True) -> dict
# 报告含 cases[]（TP/TN/FP/FN/inconclusive、mttd_sec）+ metrics + report_path
```

## 9. 配置项要点（`config.toml`）

| 段 | 关键键 | 说明 |
|---|---|---|
| `[general]` | `host_id/hostname/os/timezone/data_dir/raw_dir/rule_dir` | 路径与主机标识 |
| `[collect.auditd]` | `log_path/keys/assemble_window_ms` | audit.log 跟随与拼装窗口 |
| `[collect.fim]` | `dirs/debounce_ms/baseline` | inotify 监控目录 |
| `[engines]` | `*_rule_dir` / `max_size_mb` | 规则目录与大小阈值 |
| `[engines.sigdb]` | `hash_file/hex_file/regex_file` | 自研签名文件 |
| `[net]` | `home_net/ioc_domain_set/ioc_ip_set/dedup_sec` | 网络规则与 IOC 集合名 |
| `[host]` | `persist_paths/baseline_path` | 后门检查范围 |
| `[intel]` | `feed_dir/bundle_dir/min_confidence_*` | 情报目录与阈值 |
| `[respond]` | `default_mode/quarantine_dir/playbook_dir` | 响应模式与 playbook 目录 |
| `[verify]` | `suite/window_sec/report_dir` | 验证套件与报告目录 |
| `[web]` | `bind/port/token_env` | 仅回环 + Bearer token |
| `[ctl]` | `socket/mode/group` | 控制面 socket 权限 |

## 10. 认证子系统接口（IF-25～IF-28）

| ID | 提供方 → 消费方 | 机制 | 载荷 | 失败处理 |
|---|---|---|---|---|
| IF-25 | `hornwork.auth` → `store` | 进程内 SQLite（同库 WAL） | `auth_user` / `auth_credential` / `auth_session` / `bio_template` / `auth_audit` / `auth_policy` / `trusted_device` | 事务回滚；锁等待由 Store `busy_timeout=15 s` 兜底 |
| IF-26 | `auth.biometric` → 人脸嵌入 | 可插拔：JSON 向量 / 轻量图像描述子 /（预留）`127.0.0.1:8930` HTTP | 512 维 float32 | 失败 → 降级 LOA2 + `degraded` 事件 |
| IF-27 | `auth.audit` → `event` | 进程内 `store.insert_event` | `CanonicalEvent{logon\|logon_fail, source_layer=host, source_product=hornwork-auth, user{name,id,action}, raw.auth{loa,factors,risk,degraded,latency_ms}}` | 写库/序列化失败 → `dlq` 兜底 |
| IF-28 | `web`/CLI → `auth` | 进程内 `AuthEngine.require_action(token, action)` | `allow` / `stepup_required` / `deny` + LOA | 令牌无效/过期 → deny；LOA 不足 → stepup_required |

认证子系统新增配置段：

| 段 | 关键键 | 说明 |
|---|---|---|
| `[auth]` | `key_path/pepper_path/key_id/db_path/challenge_ttl_sec/strong_auth_window_sec` | 密钥与 pepper 分离存储（0600，属主 hornwork）；`db_path` 空 = 共用 `data_dir/hornwork.db` |

`AuthEngine` 主要方法（中间件/PAM 复用入口）：

```python
engine.login(username, password, ip, device_token, totp_code, embedding) -> dict
engine.start_login(...) / engine.advance(challenge_id, totp_code, embedding)
engine.step_up(token, totp_code, embedding)
engine.require_action(token, action)  # allow | stepup_required | deny
engine.session_info(token) / engine.logout(token)
```

## 11. 约定与限制

- 单文件/单事件/单规则失败必须 `try/except` 隔离并 `log.warn`，不得中断采集循环；
- 所有 Linux 专属调用（`os.fork`、`AF_PACKET`、`ctypes` inotify、`/proc`）只在函数体内执行，
  保证 Windows 开发机 `import` 不报错；
- `raw/` 0700、DB 0600；敏感内容只存哈希与路径；
- Web 只绑定 `127.0.0.1`，非回环绑定必须有 token（实现会拒绝无 token 的非回环配置）；
- 认证子系统密钥/pepper 只放 `/var/lib/hornwork/auth/`（0700，属主 hornwork），
  TOTP 密钥与人脸模板只以 AEAD 密文入 `auth_credential` / `bio_template`。
