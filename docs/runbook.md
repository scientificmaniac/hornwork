# Hornwork 运维手册（runbook）

> 适用环境：Ubuntu 24.04/26.04 Server，Python 3.12+（实测 3.14），主机名 `lab-host`；
> 代码 `/opt/hornwork`，venv `/opt/hornwork-venv`。开发机为 Windows，仅用于编写与
> `python -m unittest`、`py_compile` 等离线检查。

## 1. 目录与权限

| 路径 | 用途 | 权限/属主 |
|---|---|---|
| `/opt/hornwork` | 代码与规则 | 0755 `hornwork:hornwork` |
| `/opt/hornwork/rules` | 规则目录 | 0755，仅 hornwork 可写 |
| `/opt/hornwork/raw` | 原始证据 | 0700 `hornwork`（按天分子目录） |
| `/var/lib/hornwork` | SQLite、quarantine、baseline | 0750 `hornwork:hornwork` |
| `/var/log/hornwork` | `app.jsonl` 应用日志 | 0750 `hornwork:adm` |
| `/run/hornwork/ctl.sock` | 控制面 socket | 0660 `hornwork:adm` |
| `/etc/hornwork/env` | Web token（`HORNWORK_TOKEN=`） | 0600 `root:root` |
| `/etc/audit/rules.d/hornwork.rules` | auditd 规则 | 0640 root |
| `/etc/systemd/system/hornwork.service` | systemd 单元 | 0644 root |
| `/etc/systemd/system/hornwork.service.d/token.conf` | setup.sh 生成的 drop-in：EnvironmentFile + 报告/取证目录可写 | 0644 root |

> `deploy/hornwork.service` 是部署基准；`setup.sh` 通过 drop-in 追加
> `EnvironmentFile=/etc/hornwork/env` 与 `ReadWritePaths=/opt/hornwork/reports`、
> `ReadWritePaths=-/data/forensics`，避免 `ProtectSystem=strict` 阻止验证报告与取证产物写入。

## 2. 安装

### 2.1 前置条件

- 已安装系统的全新 Ubuntu，网络可访问 apt 源（或已准备离线包/轮子）；
- 主机名已设置成与 `config.toml [general].host_id` 一致的值（示例用 `lab-host`）：
  `sudo hostnamectl set-hostname <主机名>`，并同步修改配置里的 `host_id/hostname`；
- 服务器时间同步：`sudo timedatectl set-ntp true`，`timedatectl` 显示 `System clock synchronized: yes`。

### 2.2 一键安装

```bash
sudo bash scripts/setup.sh
# 离线/演示环境可跳过约 300 MB 病毒库更新：
sudo SKIP_CLAMAV=1 bash scripts/setup.sh
```

脚本步骤（幂等，可重复执行）：

1. `apt-get update/install`：python3/venv/pip、build-essential、sqlite3、iptables、e2fsprogs、
   attr、clamav/clamav-daemon、auditd、libyara-dev、libpcre2-dev、chrony、curl；
2. 创建系统用户 `hornwork`、目录与权限；
3. 建 venv，优先 `--no-index --find-links <wheels>` 离线安装
   `yara-python==4.5.4`、`PyYAML==6.0.3`，失败回退 PyPI；
4. 拷贝代码到 `/opt/hornwork`（排除 `.git/__pycache__`）；
5. 安装 auditd 规则并 `augenrules --load`（若 `/etc/rc.local` 不存在会先创建空文件）；
6. 把 `deploy/clamd-hornwork.conf` 追加到 `/etc/clamav/clamd.conf`（重复执行先删旧块）；
7. 生成 Web token 到 `/etc/hornwork/env`，通过 systemd drop-in `EnvironmentFile` 注入；
8. 安装 systemd 单元、`/usr/local/bin/hornworkctl` 启动器、logrotate；
9. `systemctl daemon-reload && systemctl enable --now hornwork`。

离线轮子查找顺序：`$HORNWORK_WHEELS` → `$HORNWORK_HOME/wheels`。
可把轮子放到 `/opt/hornwork/wheels` 后重跑。

### 2.3 安装后自检

```bash
sudo bash /opt/hornwork/scripts/check.sh     # 每项输出 OK / FAIL，退出码 0/1
hornworkctl status
```

`check.sh` 检查项：hornworkctl status、systemd 服务、yara/PyYAML 版本、clamdscan 与 clamd socket、
auditd 规则、NTP 同步、hostnamectl、磁盘使用率 <90%、`ctl.sock`、SQLite、Web `/healthz`。

## 3. 启停与状态

```bash
sudo systemctl start hornwork
sudo systemctl stop hornwork
sudo systemctl restart hornwork
sudo systemctl status hornwork
sudo journalctl -u hornwork -f                      # 实时日志（结构化 JSONL）
sudo journalctl -u hornwork --since "10 min ago"    # 最近 10 分钟
hornworkctl status                                  # CLI 汇总
```

配置变更（`config.toml`、systemd 单元）后：

```bash
sudo systemctl daemon-reload && sudo systemctl restart hornwork
```

规则变更后（无需重启）：

```bash
hornworkctl rules reload
```

## 4. 演示流程

```bash
sudo bash /opt/hornwork/scripts/demo.sh
```

脚本依次执行：`rules reload` → 本地 `127.0.0.1:18080` 提供 EICAR → wget/curl 下载到
`/tmp/hornwork-demo-eicar.com` → `scan --deep` → 等待 5 s → `alerts --since 5m` →
`case list` → `verify run --suite baseline` → `export --format md`，最后打印报告路径和
关键证据摘要（告警数、规则/级别分布、EICAR/sigdb/yara/T1105 命中明细）。

- 端口冲突：`HORNWORK_DEMO_PORT=18081 sudo -E bash scripts/demo.sh`；
- 下载文件保留作为证据，可 `rm -f /tmp/hornwork-demo-eicar.com`；
- 演示前建议回滚到干净的虚拟机快照。

## 5. 配置文件要点（`/opt/hornwork/config.toml`）

- `[general]`：`host_id`、`data_dir=/var/lib/hornwork`、`raw_dir`、`rule_dir`；
- `[collect.*]`：auditd/fim/proc/authlog/net 采集开关与路径；
- `[engines]`：`yara_rule_dir`、`net_rule_dir`、`host_rule_dir`、`sigma_rule_dir`、
  `max_size_mb`、`timeout_ms`；
- `[net].home_net`：判定 `direction: outbound` 的本网段（默认 `192.168.234.0/24`，按实际网卡修改）；
- `[respond].default_mode`：默认 `observe`，演示回滚时不要直接改 `enforce`；
- `[web] bind=127.0.0.1 port=8787 token_env=HORNWORK_TOKEN`；
- `[ctl].socket/mode/group`：控制面 socket。

改 `home_net` 后重启服务；改规则目录后 `rules reload`。

## 6. 日志位置

| 日志 | 位置 | 查看方式 |
|---|---|---|
| 应用结构化日志 | `/var/log/hornwork/app.jsonl` | `tail -f`、`jq`；logrotate 50 MB×5 |
| systemd 标准输出 | journald | `journalctl -u hornwork -f` |
| auditd 原始日志 | `/var/log/audit/audit.log` | `sudo ausearch -k hornwork_exec`、`aureport` |
| ClamAV | `/var/log/clamav/` | `journalctl -u clamav-daemon` |
| 验证报告 | `/opt/hornwork/reports/` | `hornworkctl export --format md` |
| 取证产物 | `[forensics].work_dir`（默认 `/data/forensics`） | 采集/分析命令输出 |

## 7. 常见故障排查

### 7.1 `hornworkctl status` 报 daemon 未运行

```bash
sudo systemctl status hornwork -l
sudo journalctl -u hornwork -n 100 --no-pager
ls -l /run/hornwork/ctl.sock        # 是否存在、权限 0660 hornwork:adm
sudo -u hornwork /opt/hornwork-venv/bin/python -m hornwork.daemon \
  --config /opt/hornwork/config.toml      # 前台跑，直接看报错
```

常见原因：`config.toml` 语法错误（tomllib 报行号）、规则目录权限不对、Web 端口被占用、
socket 目录不存在（`install -d /run/hornwork` 由 setup.sh 完成）。

### 7.2 YARA 规则编译失败

`rules reload` 返回 `{"ok": false, "error": "line N: ..."}` 时：

- 用 `yara-python` 单独试编译该文件（见 `docs/rules.md` §8）；
- 常见错误：string 未转义、`meta.severity` 写成非整数、两个 `.yar` 文件 stem 相同；
- 编译失败会保留旧规则，服务不会崩；修好后再次 `rules reload`。

### 7.3 auditd 规则加载失败

```bash
sudo augenrules --load
sudo auditctl -l | grep hornwork      # 应有 hornwork_exec/identity/persist 等
sudo ausearch -k hornwork_exec -i | tail
```

- Ubuntu 默认无 `/etc/rc.local`，`setup.sh` 会补空文件；手工安装时先
  `sudo install -m 0755 /dev/null /etc/rc.local`；
- `-f 1` 表示审计失败记录但不阻断（演示环境更安全）；
- 改了 `/etc/audit/rules.d/` 必须 `augenrules --load` 或重启 auditd。

### 7.4 ClamAV/clamd 不可用

```bash
sudo systemctl status clamav-daemon
sudo clamdscan --version
ls -l /var/run/clamav/clamd.ctl
sudo freshclam                         # 病毒库（约 300 MB，离线可跳过）
sudo systemctl restart clamav-daemon
```

`check.sh` 中 clamd socket 或版本 FAIL 时，先看 `journalctl -u clamav-daemon`；
ClamAV 不可用时级联会跳过 slow 引擎并熔断 60 s，不影响 sigdb/yara 检测。

### 7.5 Web 401/无法访问

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/healthz     # 200
TOKEN=$(sudo grep '^HORNWORK_TOKEN=' /etc/hornwork/env | cut -d= -f2-)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/api/overview | head
```

- token 存在 `/etc/hornwork/env`（0600），systemd drop-in 注入；
- 空 token 时只允许本机来源，且服务只绑定 127.0.0.1（不要改成 0.0.0.0）；
- 401 先确认 `Authorization: Bearer` 前缀与大小写，再确认 token 未被换行截断。

### 7.6 `inject_demo` 注入失败（TC-09）

```bash
sudo sysctl kernel.yama.ptrace_scope      # Ubuntu 默认 1
gcc -O2 -Wall -Wextra -o /tmp/inject_demo /opt/hornwork/hornwork/tools/inject_demo.c
sudo /tmp/inject_demo --pid <目标pid>
sudo /tmp/inject_demo --pid <目标pid> --restore
```

- 只允许 **同 uid** 目标进程；`sudo` 运行可操作 root 进程；
- 默认改 attach 时 RIP 处首字节为 `0x90`(NOP)；`--byte cc` 写 `0xCC`(INT3)，目标会收 SIGTRAP；
- 状态文件 `/tmp/inject_demo-<pid>.state`（0600）记录原始指令字，`--restore` 回写并删除；
- `ptrace_scope=1` 时非父进程 attach 可能被拒：演示机可临时
  `sudo sysctl kernel.yama.ptrace_scope=0`（仅测试环境，结束后恢复为 1）。

### 7.7 时间不一致 / 告警窗口对不上

```bash
timedatectl
sudo chronyc tracking
sudo systemctl restart chrony
```

全链路用 UTC 存储，展示层转 +08:00；`verify` 的 MTTD 依赖时间同步（`[verify].clock_skew_max_sec`）。

### 7.8 磁盘占用快速增长

```bash
df -h /var/lib/hornwork
sudo du -sh /var/lib/hornwork/* /opt/hornwork/raw /opt/hornwork/reports 2>/dev/null | sort -h
hornworkctl prune --days 30          # 事件保留 30 天、扫描结果 7 天、raw 14 天
```

`app.jsonl` 由 logrotate 每日/50 MB 轮转保留 5 份；`raw/` 与 `reports/` 按需手工清理。

## 8. 备份与恢复

### 8.1 备份

```bash
BACKUP=/backup/hornwork-$(date +%F)
sudo install -d -m 0700 "$BACKUP"
sudo sqlite3 /var/lib/hornwork/hornwork.db ".backup '$BACKUP/hornwork.db'"
sudo tar -C /opt/hornwork -czf "$BACKUP/rules.tar.gz" rules
sudo cp /var/lib/hornwork/baseline.json "$BACKUP/" 2>/dev/null || true
sudo cp /etc/hornwork/env "$BACKUP/env" && sudo chmod 600 "$BACKUP/env"
sudo cp /etc/audit/rules.d/hornwork.rules /etc/systemd/system/hornwork.service "$BACKUP/"
```

### 8.2 恢复

```bash
sudo systemctl stop hornwork
sudo sqlite3 /var/lib/hornwork/hornwork.db ".restore '$BACKUP/hornwork.db'"   # 或直接覆盖文件
sudo tar -C /opt/hornwork -xzf "$BACKUP/rules.tar.gz"
sudo chown -R hornwork:hornwork /opt/hornwork/rules
sudo cp "$BACKUP/baseline.json" /var/lib/hornwork/ 2>/dev/null || true
sudo systemctl start hornwork
hornworkctl status && hornworkctl audit verify
```

恢复后确认 `rules reload` 正常、`audit verify` 链完整；若更换主机名，同步修改
`config.toml [general].host_id/hostname`。

## 9. 数据清理与保留

| 数据 | 保留策略 | 操作 |
|---|---|---|
| 事件 `event` | 30 天 | `hornworkctl prune --days 30` |
| 扫描结果 `scan_result` | 7 天 | 同上（prune 内置） |
| `raw/` 原始证据 | 14 天 | 手工/定时清理 |
| 告警、工单、审计链 | 长期保留 | 不随 prune 删除 |
| 应用日志 | 50 MB×5 | logrotate 自动 |

## 10. 安全注意事项

- 服务进程以 `hornwork` 非 root 运行，仅保留 `CAP_NET_RAW/CAP_NET_ADMIN/CAP_SYS_PTRACE`；
  `ProtectSystem=strict` + `ReadWritePaths` 白名单；`NoNewPrivileges=yes`；
- Web 只绑定回环 + Bearer token；token 0600，新增轮换：改 `/etc/hornwork/env` 后
  `systemctl restart hornwork`；
- 响应动作默认 `observe`，`enforce` 只用于测试环境；每次动作写审计链，演示前确认工单/告警状态；
- `inject_demo` 仅用于同 uid 目标、单字节 NOP/INT3，禁止用于真实进程破坏；
- 演示样本仅 EICAR 与合成脚本，禁止放入真实恶意样本。

## 11. 卸载

```bash
sudo systemctl disable --now hornwork
sudo rm -f /etc/systemd/system/hornwork.service
sudo rm -rf /etc/systemd/system/hornwork.service.d
sudo rm -f /usr/local/bin/hornworkctl /etc/logrotate.d/hornwork
sudo rm -f /etc/audit/rules.d/hornwork.rules && sudo augenrules --load
sudo rm -f /opt/hornwork-venv -r          # 谨慎
sudo rm -rf /opt/hornwork /var/lib/hornwork /var/log/hornwork /run/hornwork /etc/hornwork
# 需要保留取证证据时，先备份 /var/lib/hornwork 与 /opt/hornwork/raw
```
