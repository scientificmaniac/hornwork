# Hornwork 规则库说明（rules）

> 规则目录：`rules/`（部署后为 `/opt/hornwork/rules/`，属主 `hornwork:hornwork`，0755）。
> 所有规则文件 UTF-8 无 BOM；新增/修改规则后执行 `hornworkctl rules reload` 热加载，
> 并运行 `python -m unittest discover -s tests -v`（Windows 开发机同样适用）。

## 0. 规则库总览

| 目录 | 内容 | 数量 | 加载方 |
|---|---|---|---|
| `rules/yara/*.yar` | 自研 YARA 规则 | **12** | `hornwork/engines/yara_bridge.py`（`yara.compile(filepaths=…)`） |
| `rules/net/*.rules` | 网络规则 DSL | **8** 条（N-0101～N-0108） | `hornwork/engines/netrules.py`（`NetRuleSet`） |
| `rules/host/*.json` | 主机行为规则 JSON DSL | **8** 条（H-0001～H-0008） | `hornwork/engines/hostrules.py`（`HostRuleEngine`） |
| `rules/sigma/**/*.yml` | SigmaHQ Linux 规则子集 | **66** 条 | `hornwork/engines/sigma_matcher.py`（`SigmaMatcher`） |
| `rules/sigdb/*.txt` | 自研签名（哈希/hex/正则） | 4 + 6 + 8 行 | `hornwork/engines/sigdb.py` |
| `rules/ioc/sample-*` | 演示情报 | 6 域名 + 7 IP + 4 哈希 + CSV 4 行 | `hornwork/intel/feeds.py` / `iocstore.py` |
| `rules/playbooks/PB-001.json` | 响应剧本 | 1 | `hornwork/respond/playbook.py` |

演示数据只使用 **EICAR 无害测试串**、**RFC 5737 TEST-NET**（192.0.2.0/24、198.51.100.0/24、
203.0.113.0/24）与 **保留域名**（`.example`、`example.com/net/org`，以及私网地址用于演示导入过滤），
不含任何真实恶意样本或真实 IOC。

## 1. YARA 规则（`rules/yara/*.yar`）

### 1.1 格式要求

```yara
rule <unique_name>
{
    meta:
        description = "…"        // 必填：说明
        attack = "T1105"         // 必填：ATT&CK 技术号
        severity = 70            // 必填：整数 0–100（yara_bridge 用作 score）
        source = "hornwork-self" // 必填：来源
        author = "hornwork rules-deploy-dev"
        date = "2026-10-26"
    strings:
        $a = "literal" ascii
        $b = { 4D 5A ?? 00 }
        $c = /regex\/with\/escape/
    condition:
        filesize < 2MB and any of them
}
```

- 每个 `.yar` 文件的 **文件名 stem 必须唯一**（`yara_bridge` 以 stem 作 namespace 调用
  `yara.compile(filepaths={stem: path})`，且 `rule_id=m.rule`）；
- 未声明 `filename/filetype/filesize` 等 external 的规则在 `yara_bridge` 中自动回退为无 externals 匹配；
- 编译失败时 `YaraEngine.reload()` 保留旧规则并返回错误行号，不影响 daemon 运行。

### 1.2 规则清单（12 条）

| 文件 | rule | ATT&CK | severity | 覆盖场景 |
|---|---|---|---|---|
| `reverse_shell_cmdline.yar` | `reverse_shell_cmdline` | T1059.004 | 80 | `/dev/tcp`、`nc -e`、`socat exec`、python pty 反弹 shell |
| `webshell_pattern.yar` | `webshell_pattern` | T1505.003 | 85 | PHP/JSP/ASP 一句话木马危险函数组合 |
| `crypto_miner.yar` | `crypto_miner` | T1496 | 85 | 矿池协议、xmrig/minerd/cryptonight/randomx |
| `persistence_cron.yar` | `persistence_cron` | T1053.003 | 80 | cron 持久化路径 + 下载/执行组合 |
| `persistence_systemd.yar` | `persistence_systemd` | T1543.002 | 80 | systemd unit 指向 /tmp、/dev/shm |
| `persistence_ld_preload.yar` | `persistence_ld_preload` | T1574.006 | 85 | `LD_PRELOAD=`、`/etc/ld.so.preload` 内容劫持 |
| `elf_suspicious_section.yar` | `elf_suspicious_section` | T1027.009 | 75 | ELF 魔数 + 异常节名/UPX 加壳标记 |
| `base64_encoded_command.yar` | `base64_encoded_command` | T1140 | 70 | base64 解码后管道执行、`eval(base64_decode(...))` |
| `tmp_exec_drop.yar` | `tmp_exec_drop` | T1105 | 70 | `/tmp`、`/dev/shm`、`/var/tmp` 落盘并执行 |
| `suspicious_downloader.yar` | `suspicious_downloader` | T1105 | 70 | wget/curl/certutil 下载 + 落地/管道执行 |
| `fileless_memfd.yar` | `fileless_memfd` | T1620 | 75 | `memfd_create` / `fexecve` / `/proc/<pid>/fd` |
| `credential_access_shadow.yar` | `credential_access_shadow` | T1003.008 | 80 | `/etc/shadow` 复制/编码/外传或 unshadow/john/hashcat |

自查方式：`python -m unittest tests.test_rules -v` 校验规则结构；装好 `yara-python` 后按 §8
的脚本试编译（13 条应全部通过）；EICAR 测试串由 `eicar_test_file.yar` 的 hex/ASCII
双条件与 `sigdb/hashes.txt` 的哈希签名共同覆盖（见 §5）。

## 2. 网络规则 DSL（`rules/net/*.rules`）

### 2.1 语法

```text
rule N-0101 syn_scan {
  proto: tcp
  flags: syn
  not_flags: ack
  window: 5s
  group_by: src_ip, dst_ip
  count_distinct: dst_port >= 20
  severity: 8
  technique: T1046
  msg: "SYN 端口扫描"
}
```

- 一个文件可含多条 `rule NAME { ... }`；`#` 与 `//` 为注释；字符串用双引号；
- 支持字段：`proto / flags / not_flags / flags_any_of / src_cidr / dst_cidr / dst_port /
  dst_port_in / icmp_type / malformed / direction / dst_domain_in / dst_ip_in / window /
  group_by / count_distinct / count / sum_bytes / avg_interval_between / threshold /
  severity / technique / msg`；
- 列表写法 `[445, 139]`；比较符 `>= <= > < == !=`；时长 `5s / 60s / 600s / 1m / 1h`；
- `dst_domain_in` / `dst_ip_in` 的值是 IOC 集合名，与 `config.toml` 的
  `[net] ioc_domain_set="ioc_domains"`、`ioc_ip_set="ioc_ips"` 对应；
- 匹配分两步：单包匹配 → 行为窗口（`FlowTable`/`Tracker` 聚合），同一
  `(rule_id, src_ip, dst_ip, dst_port)` 在 `[net].dedup_sec`（默认 60 s）内去重。

### 2.2 起步 8 条（基线来自文档 §4.3.6，N-0103 有一处落地适配）

| rule_id | name | 关键条件 | severity | technique |
|---|---|---|---|---|
| N-0101 | `syn_scan` | tcp、SYN 非 ACK，5 s 内 dst_port 去重 ≥20 | 8 | T1046 |
| N-0102 | `xmas_null_scan` | tcp，flags_any_of FIN/URG 且无 ACK（见下） | 7 | T1046 |
| N-0103 | `ioc_outbound` | 目标域名 ∈ `ioc_domains`（`proto: any`，见下） | 10 | T1071.001 |
| N-0104 | `icmp_sweep` | icmp type 8，5 s 内 dst_ip 去重 ≥10 | 6 | T1018 |
| N-0105 | `lateral_smb` | tcp 445/139，192.168.56.0/24 内部，60 s ≥3 目标 | 9 | T1021.002 |
| N-0106 | `c2_heartbeat` | tcp，600 s ≥10 包且平均间隔 30–90 s | 6 | T1071 |
| N-0107 | `malformed_packet` | proto any，`malformed: true` | 4 | — |
| N-0108 | `large_upload` | tcp outbound，60 s 外发 ≥52 428 800 字节 | 6 | T1041 |

> **N-0102 落地适配**：文档原文 `flags_any_of: [fin, psh, urg]` 会把正常 TCP 的 PSH
> 也当成 XMAS 扫描（回环/正常业务上大量误报）。落地改为 `flags_any_of: [fin, urg]` +
> `not_flags: ack`：保留"异常标志位扫描"语义（XMAS 的 FIN/URG、无 ACK 的裸 FIN），
> 同时避免把普通 PSH+ACK 数据包当成攻击。
>
> **N-0103 落地适配**：文档 §4.3.6 原文为 `proto: tcp`，但文档 §0.3 明确"不做 HTTP/TLS
> 应用层解析（只解析 DNS 查询名）"，因此按 TCP 载荷匹配域名在本实现中不可达。落地时把
> `proto` 改为 `any`，由 `netdecode` 解析 DNS 查询名（UDP/TCP 53 端口）后填入
> `packet["domain"]`，N-0103 对 DNS 查询命中的 IOC 域名告警。规则 id、severity、
> technique、msg 与设计口径保持一致；该差异已记录在实现说明中。
>
> 注意：N-0105 的 `192.168.56.0/24` 与 config 的 `[net].home_net` 是测试网段，演示时按
> 实际网段调整（规则文本本身与设计口径一致，不做改写）。

## 3. 主机规则 JSON DSL（`rules/host/*.json`）

### 3.1 Schema

```json
{
  "id": "H-0001",
  "name": "临时目录出现可执行文件落地",
  "level": 9,
  "mitre": ["T1105"],
  "event_types": ["file_create", "file_modify"],
  "condition": {
    "all": [
      {"any": [
        {"field": "file.path", "op": "prefix", "value": "/tmp/"},
        {"field": "file.path", "op": "prefix", "value": "/dev/shm/"}
      ]},
      {"not": [{"field": "file.path", "op": "suffix", "value": ".log"}]}
    ]
  },
  "description": "…"
}
```

- `rules/host/*.json` 可以是单个对象，也可以是对象数组（引擎两者都兼容）；
- 必填：`id / name / condition`；`level` 1–10（score = min(level×10, 100)）；
- `event_types` 为空数组表示对所有事件求值；取值必须属于 `schema.EVENT_TYPES`；
- 条件树键：`all`（数组，全部为真）、`any`（数组，任一为真）、`not`（数组，全部为假 → 整体为真）；
- 叶子：`{"field": "点路径", "op": "…", "value": …}`；
- op：`eq / neq / in / nin / prefix / suffix / contains / regex / gt / lt / exists`；
- 字段白名单示例：`event_type`、`process.cmdline`、`process.image`、`file.path`、`network.dst_port`、
  `user.name` 等（点路径取事件字典，不做通配）。

### 3.2 规则清单（8 条）

| id | 名称 | level | event_types | 关键条件 |
|---|---|---|---|---|
| H-0001 | 临时目录出现可执行文件落地 | 9 | file_create/file_modify | path 前缀 /tmp、/dev/shm、/var/tmp，排除 `.log` |
| H-0002 | 敏感凭据文件访问（shadow/gshadow） | 10 | process_create/file_create/file_modify | path ∈ `/etc/shadow`,`/etc/gshadow` 或 cmdline 含之 |
| H-0003 | 可疑持久化项写入 | 10 | file_create/file_modify | cron/systemd/rc.local/profile.d/authorized_keys/.bashrc/ld.so.preload，白名单 hornwork-test |
| H-0004 | LD_PRELOAD / ld.so.preload 劫持 | 10 | process_create/file_create/file_modify | path 为 `/etc/ld.so.preload` 或 cmdline 含 `LD_PRELOAD=` |
| H-0005 | 可疑账号操作 | 8 | account_create/process_create | account_create 事件，或 useradd/usermod/groupadd/userdel/passwd 等 |
| H-0006 | 反弹 shell 命令行 | 10 | process_create | cmdline 含 `/dev/tcp/`、`nc -e`、`socat exec:`、`bash -i` 等 |
| H-0007 | SUID 权限变更 | 9 | process_create | chmod 且参数含 `u+s`/`g+s`/4xxx 模式 |
| H-0008 | 可疑下载工具外联 | 6 | process_create | image 为 wget/curl/nc/ncat/socat/scp… 且 cmdline 含 URL 或临时目录 |

## 4. Sigma 规则子集（`rules/sigma/`）

- 来源：SigmaHQ 官方仓库 `rules/linux/`（DRL 1.1，详见 `rules/sigma/NOTICE.md`）；
- 数量：**66 条**（process_creation 57 / file_event 7 / network_connection 2），保持上游目录结构；
- 大小写/字段名与上游一致，未修改任何规则内容；
- 加载策略（文档 §4.2.6）：`yaml.safe_load` → 校验 `title/id/logsource.category/detection` →
  `status ∈ {test, deprecated}` 按 `[engines.sigma].include_status_test` 决定是否参与匹配；
  字段/修饰符/条件不在子集内跳过并计入 `sigma_stat`；
- 实测（本仓库 `config.toml` 当前 `include_status_test = true`，演示口径）：
  `loaded=66, supported=65, skipped=1, error=0`（唯一跳过：`DestinationHostname` 字段不支持）；
- 严格口径（`include_status_test = false`，文档默认）：`loaded=66, supported=20, skipped=46`，
  其中 45 条是 `status: test`、1 条字段不支持；两种口径都 **0 error**；
- 支持子集：category 三类；字段 `Image/CommandLine/ParentImage/User/TargetFilename/
  DestinationIp/DestinationPort/QueryName`；修饰符 `contains/startswith/endswith/re/all`；
  条件 `selection`、`and/or/not`、`1 of selection*`、`all of them`。

新增 Sigma 规则时，建议先本地验证：

```bash
python - <<'PY'
import yaml, pathlib
for p in pathlib.Path("rules/sigma").rglob("*.yml"):
    yaml.safe_load(p.read_text(encoding="utf-8"))
print("yaml ok")
PY
```

## 5. 自研签名库（`rules/sigdb/`）

| 文件 | 行格式 | 说明 |
|---|---|---|
| `hashes.txt` | `sha256` 或 `sha256 名称` | 64 位 sha256（也兼容 32 位 md5）；`#` 注释；**第一行是 EICAR** `275a021bfb…` |
| `hex.txt` | `模式 \| 名称 \| 分值` | 模式为十六进制半字节 + `??` 通配（空格忽略），分值缺省 80 |
| `regex.txt` | `正则 \| 名称 \| 分值` | Python `re`，对 latin-1 文本匹配以保留 byte offset；长度 ≤2048，分值缺省 60 |

命中分值：hash 100 / hex 80 / regex 60 / 熵 40 / 结构 70（与设计口径 §4.1.2 一致）。
`hashes.txt` 中的 EICAR sha256：

```text
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f eicar-standard-test-file
```

## 6. 情报文件（`rules/ioc/`）

### 6.1 JSONL（`sample-domains.jsonl`、`sample-ips.jsonl`、`sample-hashes.jsonl`）

```json
{"type": "domain", "value": "ioc.example", "confidence": 90, "source": "hornwork-demo-seed", "tlp": "white"}
```

- `type ∈ ip / domain / url / hash / filename`；
- 导入时按 `sha256(type|value)` 去重，并过滤内网/回环/保留地址（所以
  `sample-ips.jsonl` 里故意放了 `192.168.234.5`、`10.0.0.5`、`127.0.0.9` 用于演示"被跳过"）；
- 关联 `intel2rule`：hash → YARA/hash_cache；domain/url → 网络 `dst_domain_in`；
  ip → 网络 `dst_ip_in`；filename → 主机 `file.path` 条件。

### 6.2 abuse.ch 风格 CSV（`sample-abusech.csv`）

```csv
first_seen_utc,dst_ip,dst_port,c2_status,last_online_utc,malware,confidence
"2026-01-05 08:00:00",203.0.113.9,4444,online,"2026-10-20 12:00:00",DemoLoader,80
```

字段映射可由 `[intel]` 配置/导入器参数指定；示例全部为 TEST-NET 地址。

## 7. 响应 Playbook（`rules/playbooks/PB-001.json`）

```json
{
  "id": "PB-001",
  "name": "可疑样本处置",
  "version": "1.0",
  "steps": [
    {"id": "s1", "action": "quarantine_file", "mode": "enforce", "timeout": 30},
    {"id": "s2", "action": "collect_forensics", "mode": "observe", "params": {"include": ["process", "network", "file"]}},
    {"id": "s3", "action": "open_case", "params": {"severity": "P2"}}
  ],
  "rollback": [
    {"action": "restore_file", "when": "verdict == benign"}
  ]
}
```

- 动作名与 `ActionExecutor` 一致：`quarantine_file / collect_forensics / open_case / restore_file`；
- `mode ∈ observe / dry-run / enforce`，默认取 `[respond].default_mode="observe"`；
- 每次执行写 `action_audit`，`hash = sha256(prev_hash + 规范化字段)`，`hornworkctl audit verify` 校验链。

## 8. 规则校验与热加载

```bash
# 1) 全部规则结构校验（Windows 开发机可跑；yara 未安装时该用例自动 skip）
python -m unittest tests.test_rules -v

# 2) 试编译 YARA（Linux/开发机装 yara-python 后）
python - <<'PY'
import glob, yara
rules = yara.compile(filepaths={p.rsplit("/",1)[-1][:-4]: p for p in glob.glob("rules/yara/*.yar")})
print("yara compile ok")
PY

# 3) 网络规则试解析
python - <<'PY'
from hornwork.engines.netrules import parse_rules
rules, errors = parse_rules(open("rules/net/hornwork-net.rules", encoding="utf-8").read())
print(len(rules), errors)
PY

# 4) 部署后热加载
hornworkctl rules reload
```

## 9. 规则新增约定

1. 只使用无害演示样本/保留地址，禁止真实 IOC 与恶意样本；
2. YARA `meta` 必须含 `attack/severity/source`，文件名 stem 唯一；
3. 网络规则按 §2.1 语法，新增 rule_id 建议 `N-02xx` 起，避免与 `intel-<bundle>` 冲突；
4. 主机规则 level 1–10，`event_types` 必须来自 `schema.EVENT_TYPES`；
5. Sigma 规则只保留上游原样（含 `status`），本地不改检测逻辑；
6. 改完跑 `tests/test_rules.py` 与 `bash -n scripts/*.sh`，再 `hornworkctl rules reload` 验证。
