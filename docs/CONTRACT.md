  Hornwork 内部接口契约（所有模块必须严格遵守）

> 本文件是并行开发的**唯一接口依据**。修改接口必须先改本文件并通知 Lead。
> 目标运行环境：Ubuntu 24.04+/26.04，Python 3.12+（实测 3.14），仅标准库 + `yara-python` + `PyYAML`。
> 开发机（Windows）上必须能 `python -m py_compile` 且 `import` 不报错——所有 Linux 专属调用
> （`os.fork`、`socket.AF_PACKET`、`ctypes` inotify、`/proc`）只能出现在**函数体内部**，不得在模块导入期执行。

   0. 通用约定

- 时间：统一用 `hornwork.schema.utc_now()` / `to_utc()`，字符串形如 `2026-10-26T12:00:00.123Z`；
- 事件：用 `hornwork.schema.new_event(...)` 构造，`emit(event)` 的入参必须是**完整** CanonicalEvent；
- 告警：用 `hornwork.schema.new_alert(rule, ...)` 构造，`emit_alert(alert)` 同理；
- 规则命中：返回 `list[dict]`，元素由 `hornwork.engines.base.make_hit()` 生成；
- 异常：单个文件/单个事件/单条规则失败必须 `try/except` 隔离，记录 `log.warn`，不得中断采集循环；
- 日志：`from ..log import get_logger; log = get_logger("xxx")`，`log.info("msg", key=value)`；
- 中文注释/文档字符串，代码标识符英文；类型标注尽量完整。

   1. 核心（Lead 维护，只读）

```python
  hornwork/schema.py
utc_now() -> str
to_utc(ts) -> str
new_event(event_type, source_layer, source_product, cfg=None, *, ts=None,
          process=None, file=None, network=None, user=None, rule=None,
          raw=None, host=None) -> dict
validate_event(ev) -> list[str]
normalize_event(raw, cfg=None) -> dict
dedup_key(*parts) -> str            sha256 前 32 位 hex
make_rule(rule_id, name, engine, level=5, mitre=None, version="1.0") -> dict
new_alert(rule, *, level=None, event=None, entity=None, evidence=None,
          intel=None, contrib=None, confidence=60, ts=None, scheme=None,
          dedup_extra=None) -> dict
severity_label(level) -> str
sha256_file(path) -> str

  hornwork/store.py
parse_since(spec) -> str            "5m"/"2h"/ISO → ISO
class Store:
    insert_event(ev, engine=None) -> bool
    query_events(event_type=None, since=None, limit=100, source_layer=None) -> list[dict]
    count_events(since=None) -> int
    insert_alert(alert) -> bool
    query_alerts(since=None, level_min=None, technique=None, rule_ids=None, limit=100) -> list[dict]
    alerts_in_window(t0, t1=None, rule_ids=None, technique=None) -> list[dict]
    count_alerts(since=None, level_min=None) -> int
    set_alert_status(alert_id, status)
    insert_scan_result(rec) -> int
    scan_by_sha(sha256) -> dict | None
    recent_scans(since=None, limit=50) -> list[dict]
    engine_contribution(days=7) -> list[dict]
    get_hash_cache(sha)/set_hash_cache(sha, verdict)
    engine_stat_add(engine, files=0, hits=0, malicious=0, cost_ms=0, errors=0)
    engine_stats(days=7) -> list[dict]
    sigma_stat_inc(rule_id, supported); sigma_stat_hit(rule_id); sigma_stats() -> dict
    ioc_upsert(rec) -> bool; ioc_list(kind=None, limit=500, status=None) -> list[dict]
    ioc_values(kind) -> list[str]; ioc_set_status(ioc_id, status); ioc_aging(ttl_days) -> int
    baseline_upsert(rec); baseline_get(path); baseline_all() -> list[dict]
    insert_case(rec) -> str; update_case(case_id, **fields) -> bool; get_case(case_id); list_cases(status=None, limit=100)
    audit_last() -> dict|None; audit_append(rec) -> int; audit_rows() -> list[dict]
    insert_validation(rec); validation_rows(run_id=None, limit=500); latest_run_id()
    insert_mem_hits(ts, hits) -> int; query_mem_hits(since=None, pid=None) -> list[dict]
    insert_mem_scan(rec)
    set_meta(k, v); get_meta(k, default=None)
    dlq_add(topic, payload, error); dlq_count()
    counts() -> dict; prune(days=30, scan_days=7) -> dict; db_size_bytes() -> int
    execute(sql, args) ; query(sql, args) ; query_one(sql, args)
open_store(cfg) -> Store

  hornwork/bus.py
class Bus:
    bind_loop(loop); set_dlq(fn)
    subscribe(pattern) -> asyncio.Queue         pattern 支持 "events.*"
    attach(pattern, handler, name="") -> asyncio.Queue     自动起消费协程
    publish(topic, item)     线程安全
    status() -> dict; async drain(timeout=5); async stop()

  hornwork/engines/base.py
make_hit(engine, rule_id, name, score, meta=None, evidence=None) -> dict
normalize_hit(hit, default_engine="unknown") -> dict
hit_to_alert_fields(hit) -> {"rule":..., "evidence":[...], "confidence":int}
merge_hits(hits) -> list[dict]
class BaseScanEngine: name/version/cost, available()/supports(ctx)/scan(path, ctx)
class BaseEventEngine: name/version, on_event(event) -> list[dict]
```

   2. 采集层 `hornwork/collectors/`（负责人：collectors-dev）

约定：构造函数 `(cfg, emit, store=None, emit_alert=None, **kw)`；`start()` 启动**daemon 线程**后立即返回；
`stop()` 必须在 3 s 内退出线程；`status() -> dict` 返回 `{"name","running","stats":{...},"errors":n}`。
`emit(event)` / `emit_alert(alert)` 由 daemon 注入，采集层不得直接 import daemon。

```python
  auditd.py
class AuditdCollector:
    def __init__(self, cfg, emit, store=None, emit_alert=None)
    def start(self); def stop(self); def status(self) -> dict
    @staticmethod parse_line(line: str) -> dict | None
          {"type","ts","id","fields":{...}}；audit 时间戳转 UTC ISO
    @staticmethod assemble(records: list[dict]) -> dict | None
          同 audit_id 的多行拼装，返回 dict（含 event_type/process/file/rule.raw 字段）
  线程内：tail 文件 + inode 轮转检测 + 2s 拼装窗口 + EXECVE/PROCTITLE hex 解码
  映射：syscall=59 → process_create；key=hornwork_identity → file_modify；
        key=hornwork_persist → persist_item；其余按 key 归到 raw

  proc.py
class ProcCollector:    轮询 /proc 差分 + 连接表
    def __init__(self, cfg, emit, store=None, emit_alert=None)
    def start(self); def stop(self); def status(self)
def snapshot_procs() -> dict[int, dict]
      {pid: {"pid","ppid","uid","threads","image","cmdline","starttime","state"}}
def diff_procs(prev, cur) -> tuple[list[dict], list[dict], list[dict]]    created, exited, changed
def read_connections() -> list[dict]
      [{"proto","local_ip","local_port","remote_ip","remote_port","state","inode"}]
def socket_inode_owners() -> dict[str, list[int]]    inode → [pid]

  fim.py  递归 inotify（ctypes libc，函数内 import/初始化）
class FimCollector:
    def __init__(self, cfg, emit, store=None, emit_alert=None)
    def start(self); def stop(self); def status(self)
    def build_baseline(self) -> int        stat+sha256 写 baseline 表
    def diff_baseline(self) -> list[dict]    与 baseline 比对（供定时校验）
  事件：file_create/file_modify/file_delete；同路径 300ms 去抖；新目录动态加 watch

  authlog.py
class AuthLogCollector:
    def __init__(self, cfg, emit, store=None, emit_alert=None)
    def start(self); def stop(self); def status(self)
def parse_line(line: str) -> dict | None
      {"kind":"failed|accepted|account","user","src_ip","ts","raw"}
class BruteForceTracker:
    def add(self, ip: str, ts: str, success: bool) -> dict | None     触发返回告警信息
  触发：300s 内同 IP 失败 ≥5 且随后成功 → 用 schema.new_alert 生成 level=12 T1110 告警

  persist.py  7 类后门检查
class PersistenceChecker:
    def __init__(self, cfg, store, emit, emit_alert=None)
    def build_baseline(self) -> dict       记录 SUID/内核模块/持久化路径基线到 meta 表
    def run_checks(self) -> list[dict]
          [{"check":"hidden_process|fileless|ld_preload|kernel_module|persist_item|account_anomaly|suid_new",
            "findings":[{...}], "errors":[]}]
    def status(self) -> dict
  发现项同时 emit(persist_item/...) + emit_alert(level 见实现)

  netdecode.py  纯函数、可单测
def decode(frame: bytes, ts=None) -> dict | None
      {"ts","l2":"eth","ethertype","src_ip","dst_ip","proto","src_port","dst_port",
       "ip_len","flags":int,"icmp_type","icmp_code","payload_len","malformed":bool,"raw_len"}
def parse_flags(flags: int) -> set[str]       {"syn","ack",...}
FLAG_FIN/FLAG_SYN/FLAG_RST/FLAG_PSH/FLAG_ACK/FLAG_URG: int

  netcap.py  抓包 + flow + tracker + 规则一体化流水线
class NetPipeline:
    def __init__(self, cfg, emit_event, emit_alert, ioc_provider=None, store=None)
    def start(self); def stop(self); def status(self)
  抓包线程：AF_PACKET SOCK_RAW；处理线程：decode → FlowTable.update →
  NetRuleSet.evaluate(pkt, flow, tracker) → 命中转告警（schema.new_alert）→ emit_alert
  新 flow 可按配置 emit net_connect 事件（限频）；畸形包直接触发 N-0107

  memscan.py
class MemoryScanner:
    def __init__(self, cfg, store=None, emit_alert=None, emit_event=None)
    def scan_pid(self, pid: int, snapshot: bool=False) -> dict
          {"pid","regions":[...],"hits":[...],"verdict","score","snapshot_dir"?}
    def snapshot(self, pid: int) -> str        返回目录，写 maps.txt/hits.json/regions/
    def verify(self, snapshot_dir: str) -> dict
    def sweep(self) -> list[dict]              扫描全部可读进程的可疑段（限时限量）
    def status(self) -> dict
def parse_maps(pid: int) -> list[dict]         {start,end,perms,offset,dev,inode,pathname}
def parse_maps_text(text: str) -> list[dict]
  注入判定：条件 A（匿名 RWX/memfd/可执行） + 条件 B（10s 内新连接/线程+5）→ level 10+
```

   3. 检测引擎 `hornwork/engines/`（负责人：engines-dev）

```python
  sigdb.py
class SigDbEngine(BaseScanEngine):
    name="sigdb"; version="1.0"; cost="fast"
    def __init__(self, cfg, store=None)
    def available(self); def supports(self, ctx); def scan(self, path, ctx) -> list[dict]
    def reload(self) -> dict       {"hashes":n,"hex":n,"regex":n,"errors":[]}
    def compute_entropy(self, path) -> float
    def structural_hits(self, path) -> list[dict]     ELF/PE 结构异常
  规则文件：hash 行 "sha256 hex"、hex 行 "hexpattern | name | score"、regex 行 "regex | name | score"
  命中分值：hash 100 / hex 80 / regex 60 / entropy 40 / 结构 70；证据含 offset/matched

  yara_bridge.py
class YaraEngine(BaseScanEngine):
    name="yara"; version=yara.__version__; cost="medium"
    def __init__(self, cfg)
    def reload(self) -> dict       {"ok":bool,"rules":n,"error":str|None}
    def scan(self, path, ctx) -> list[dict]
      filepaths 编译（stem 做 namespace），externals: filename/filetype/filesize
      timeout 取 cfg engines.timeout_ms.yara；编译失败保留旧规则并返回错误行号

  clamd_client.py
class ClamavEngine(BaseScanEngine):
    name="clamav"; version="clamd"; cost="slow"
    def __init__(self, cfg)
    def available(self) -> bool        socket 存在 + PING 探活；失败熔断 60s
    def supports(self, ctx)            只对 deep 扫描或 ≤max_size 的文件
    def scan(self, path, ctx) -> list[dict]
    def ping(self) -> bool
def scan_stream(sock_path, path, timeout=30, chunk=1<<20) -> list[dict]
def ping(sock_path, timeout=2) -> bool

  cascade.py
class Cascade:
    def __init__(self, cfg, engines: list, store=None)
    def scan(self, path, deep=False, ctx=None, budget_ms=None) -> dict
          {"path","sha256","size","verdict","score","hits","engines_used","first_hit",
           "cost_ms","partial":bool,"cached":bool,"error":str|None}
      verdict: malicious(score>=80) / suspicious(>=50) / clean / error
      哈希缓存命中直接返回 cached=True；deep=False 跳过 cost=="slow"
      每引擎 try/except，engine_stat_add 记录 files/hits/cost/errors

  contribution.py
class ContributionTracker:
    def __init__(self, store)
    def record(self, scan_result: dict) -> None
    def top(self, days=7) -> list[dict]
    def engine_table(self, days=7) -> list[dict]

  hostrules.py  主机行为规则 JSON DSL
class HostRuleEngine(BaseEventEngine):
    name="hostrules"; version="1.0"
    def __init__(self, cfg, store=None)
    def on_event(self, event) -> list[dict]
    def reload(self) -> dict
  规则文件 rules/host/*.json：
  {"id":"H-0001","name":"...","level":8,"mitre":["T1105"],"event_types":["file_create"],
   "condition":{"all":[{"field":"file.path","op":"prefix","value":"/tmp/"}, ...]},
   "description":"..."}
  op: eq/neq/in/nin/prefix/suffix/contains/regex/gt/lt/exists；条件树 all/any/not

  sigma_matcher.py  Sigma 子集
class SigmaMatcher(BaseEventEngine):
    name="sigma"; version="1.0"
    def __init__(self, cfg, store=None)
    def on_event(self, event) -> list[dict]
    def reload(self) -> dict          {"ok","loaded","supported","skipped","error"}
    def stats(self) -> dict
  加载 rules/sigma/**/*.yml（PyYAML）；logsource.category ∈
  process_creation/file_event/network_connection；修饰符 contains/startswith/endswith/re/all
  条件 selection / and / or / not / 1 of selection* / all of them；字段映射见文档 §4.2.6

  netflow.py
class FlowTable:
    def __init__(self, max_flows=200000, timeout=120)
    def key(self, pkt) -> tuple
    def update(self, pkt) -> dict
    def evict(self, ratio=0.1) -> int
    def age(self, now=None) -> int
    def __len__(self)

  tracker.py
class Tracker:
    def __init__(self, window=5.0, shards=5)
    def add(self, ts, src, dst, dport) -> None
    def distinct_ports(self, now, src, dst) -> int
    def distinct_dsts(self, now, src, key) -> int
    def last_packet_ts(self, src, dst) -> float | None

  netrules.py  网络规则 DSL
class NetRuleSet:
    def __init__(self, cfg, ioc_provider=None, store=None)
    def load(self) -> dict            {"ok","rules":n,"errors":[...]}
    def rules(self) -> list[dict]
    def evaluate(self, pkt, flow=None, tracker=None, now=None) -> list[dict]
          单包匹配 + 行为窗口触发 + 60s 去重，返回 Hit（engine="netrules"）
    def stats(self) -> dict
  规则语法见文档 §3.7(b) + §4.3.6；支持字段：
  proto/flags/not_flags/flags_any_of/src_cidr/dst_cidr/dst_port/dst_port_in/icmp_type/
  malformed/direction/dst_domain_in/dst_ip_in/window/group_by/count_distinct/count/
  sum_bytes/avg_interval_between/severity/technique/msg
  ioc_provider(kind) -> set[str]（kind: "domains"/"ips"）
  evaluate 返回 hit.meta={"severity","technique","msg","rule_name","evidence"}
```

   4. 情报层 `hornwork/intel/`（负责人：intel-respond-dev）

```python
  feeds.py
def load_feed(path) -> list[dict]            自动识别 jsonl/csv
def parse_jsonl(path) -> list[dict]
def parse_csv(path, mapping=None) -> list[dict]
  记录规范：{"type","value","confidence","source","tlp"}
  type ∈ ip/domain/url/hash/filename；导入前过滤内网/回环/保留地址

  iocstore.py
class IocStore:
    def __init__(self, store, cfg)
    def import_records(self, records: list[dict]) -> dict     {"imported","skipped","total"}
    def values(self, kind: str) -> set[str]                    kind: "ip"/"domain"/"hash"/"url"
    def provider(self, kind: str): ...                         返回可调用对象，供 netrules ioc_provider
    def aging(self) -> int
    def stats(self) -> dict
    def export_stix(self, path) -> int
    def import_stix(self, path) -> dict

  intel2rule.py
def build(store, cfg, bundle_id="bundle-1") -> dict
      {"bundle_id","dir","files":[...],"counts":{...},"validated":bool,"errors":[]}
      产物：rules/yara/intel-<bundle>.yar（hash 字符串）、rules/net/intel-<bundle>.rules
            （dst_domain_in / dst_ip_in）、rules/intel/bundle.json
def validate_files(paths) -> dict          YARA 试编译 + NetRuleSet 试解析

  stix.py
def export_bundle(iocs: list[dict], identity: str = "hornwork") -> dict
def parse_bundle(bundle: dict) -> list[dict]
def write_bundle(path, iocs) -> int
def read_bundle(path) -> list[dict]
```

   5. 响应层 `hornwork/respond/`（负责人：intel-respond-dev）

```python
  case.py
class CaseManager:
    def __init__(self, store, cfg=None)
    def create_from_alert(self, alert: dict, title=None) -> dict     返回 case 行
    def create(self, title, severity="P3", dedup_key=None, verdict=None) -> dict
    def update(self, case_id, status=None, verdict=None) -> bool
    def get(self, case_id) -> dict | None
    def list(self, status=None, limit=100) -> list[dict]
  状态机：open → investigating → contained → closed（closed 写 closed_at）

  actions.py
class ActionExecutor:
    def __init__(self, store, cfg)
    def execute(self, action: str, params: dict, mode="observe") -> dict
          {"action","mode","ok","detail","target","rollback":{...},"action_id"}
    def quarantine_file(self, path, mode)
    def kill_process(self, pid, mode)
    def block_ip(self, ip, direction="outbound", mode="observe")
    def isolate_host(self, mode)
    def disable_account(self, user, mode)
    def collect_forensics(self, params, mode)
    def undo(self, rollback: dict, mode="observe") -> dict
def verify_chain(rows: list[dict]) -> tuple[bool, int | None]     (ok, 断链 seq)
  mode=observe: 只记录；dry-run: 打印将执行命令；enforce: 真执行（仅 Linux，函数内调用）
  每次执行写 action_audit（hash = sha256(prev_hash + 规范化字段)）

  playbook.py
def load_playbook(path) -> dict
def validate_playbook(pb: dict) -> list[str]
class PlaybookRunner:
    def __init__(self, store, actions)
    def run(self, case_id, playbook, mode="observe") -> dict
          {"case_id","playbook","mode","steps":[{...}],"ok":bool}

  approve.py
class ModeGuard:
    def __init__(self, cfg)
    def resolve(self, requested: str | None = None) -> str
    def allowed(self, mode: str) -> bool
    def require_approval(self, action: dict, mode: str) -> bool
```

   6. 验证层 `hornwork/verify/`（负责人：verify-web-dev）

```python
  judge.py
def judge_case(store, case: dict, t0: str, window_sec: int) -> dict
      {"case_id","expected","observed","verdict":"TP|TN|FP|FN|inconclusive",
       "mttd_sec":int|None,"alerts":[...]}
  case 结构：{"case_id","name","technique","expected":"alert_present|no_alert",
             "rule_ids":[...],"script":"T1105.sh"}

  metrics.py
def compute_metrics(rows: list[dict]) -> dict
      {"TP","TN","FP","FN","inconclusive","tpr","fpr","mttd_sec","coverage","techniques":[...]}

  runner.py
class VerifyRunner:
    def __init__(self, store, cfg, ctl_call=None)     ctl_call(method,params) 可空
    def run(self, suite="baseline", window_sec=None, execute=True) -> dict
          依次跑 simulate 脚本（execute=False 只做 DB 侧判定），每例前后取时间窗，
          调 judge + metrics，写 JSON + Markdown 报告到 verify.report_dir，返回报告 dict
    def suites(self) -> dict
  内置 baseline 套件 = 文档 §4.8.1 的 TC-01..TC-10 + TC-N1
  脚本随仓库分发在 hornwork/verify/simulate/（用例矩阵与规范见该目录 README.md）

  forensics.py  路线 B
class Forensics:
    def __init__(self, store, cfg)
    def collect(self, compress=False, out_dir=None) -> dict       调 avml，记录 meta/哈希
    def analyze(self, image, symbol_dir=None, plugins=None) -> dict    调 vol3 6 个插件
    def compare(self, offline_malfind=None, since=None) -> dict   在线 mem_hits vs malfind → CSV
    def status(self) -> dict
def parse_malfind(text: str) -> list[dict]
def parse_pslist(text: str) -> list[dict]
  外部命令一律 subprocess.run([...], timeout=..., check=False)，缺失二进制返回 {"ok":False,"error":...}

  verify/simulate/*.sh  10 条攻击模拟 + 1 条阴性（用例矩阵见 verify/simulate/README.md）
  规范：set -euo pipefail；trap 清理；支持 --dry-run；只做无害动作；每脚本第一行打印
        "TC-xx <technique> start" 便于日志对齐
```

   7. Web 控制台 `hornwork/web/`（负责人：verify-web-dev）

```python
class WebServer:
    def __init__(self, cfg, store)
    def start(self); def stop(self); def status(self) -> dict
  标准库 http.server.ThreadingHTTPServer + BaseHTTPRequestHandler，线程方式运行
  Bearer token 鉴权（web.token / web.token_env），仅绑定 127.0.0.1
  路由见文档 §3.8；/api/export 支持 format=jsonl|md
  static/index.html：原生 JS 单页（概览/事件/告警/规则/情报/工单/验证/引擎贡献）
```

   8. 规则与部署（负责人：rules-deploy-dev）

- `rules/yara/*.yar`：13 条，`meta` 必带 `attack/severity/source`（含 `eicar_test_file`；
  `rules/sigdb/hashes.txt` 的哈希签名同样覆盖该测试串）；
- `rules/net/*.rules`：文档 §4.3.6 的 8 条，语法必须能被 `NetRuleSet` 解析；
- `rules/host/*.json`：8 条，符合 §4.2.7 的 JSON DSL；
- `rules/sigma/**/*.yml`：从上游 SigmaHQ 仓库的 `rules/linux/` 稀疏取 Linux 规则 50～80 条（保持原目录结构与内容）；
- `rules/ioc/sample-*.jsonl|csv`：演示情报；
- `rules/sigdb/{hashes,hex,regex}.txt`：演示签名（含 EICAR 的 sha256）；
- `deploy/`：systemd 单元、auditd 规则、clamd 片段；
- `scripts/`：setup.sh / demo.sh / check.sh；
- `docs/`：interfaces.md / rules.md / runbook.md（说明文档，不是本契约）。

   9. 集成方式（daemon 伪代码，Lead 维护）

```python
cfg = load_config("config.toml"); store = open_store(cfg)
bus = Bus(cfg_get(cfg,"bus.event_queue_max",100000))
engines = [SigDbEngine(cfg,store), YaraEngine(cfg), ClamavEngine(cfg)]
cascade = Cascade(cfg, engines, store)
detectors = [HostRuleEngine(cfg,store), SigmaMatcher(cfg,store)]
collectors = [AuditdCollector(cfg, bus.publish_events, store), ProcCollector(...), ...]
netpipe = NetPipeline(cfg, emit_event, emit_alert, ioc_provider=ioc.values)
```
`emit_event(ev)` = `bus.publish("events."+layer, ev)`；`emit_alert(alert)` = `bus.publish("alerts.raw", alert)`；
daemon 订阅 `events.*` 跑 detectors，订阅 `alerts.raw` 做落库/去重/工单联动。
