# 行为模拟脚本（内置 baseline 套件：10 条攻击模拟 + 1 条阴性用例）

本目录是验证层的内置 `baseline` 套件脚本，随仓库分发，由
`hornwork.verify.runner.VerifyRunner` 按顺序调用：

```bash
bash hornwork/verify/simulate/T1059.004.sh --run   # runner 的真实执行方式（工作目录为仓库根）
bash hornwork/verify/simulate/T1046.sh --dry-run   # 只打印将执行的动作，无副作用
```

## 用例矩阵

| 用例 | 脚本 | 动作 | ATT&CK | 主要验证点 |
|---|---|---|---|---|
| TC-01 | `T1059.004.sh` | `env /bin/sh -c 'id; uname -a'`（等价 `sh -c 'id; uname -a'`） | T1059.004 | auditd execve / 主机规则 |
| TC-02 | `T1105.sh` | 本地 HTTP 下载 68 字节 EICAR 测试串到临时目录 | T1105 | FIM + 静态扫描 + 告警 |
| TC-03 | `T1543.002.sh` | 创建 `/etc/systemd/system/hornwork-tc03.service` 单元并删除 | T1543.002 | 持久化检查 / FIM |
| TC-04 | `T1053.003.sh` | 写入用户 cron 测试任务并恢复 | T1053.003 | 持久化检查 / 主机规则 |
| TC-05 | `T1136.001.sh` | `useradd` 测试账号并删除 | T1136.001 | 账号异常检查 |
| TC-06 | `T1003.008.sh` | 复制 `/etc/shadow` 到临时文件并删除 | T1003.008 | 敏感文件访问规则 |
| TC-07 | `T1071.001.sh` | 发 3 个 DNS 查询（IOC 域名）+ 本地 8080 心跳 10 次 | T1071.001 | N-0103 情报域名 / N-0106 心跳（任一命中即 TP） |
| TC-08 | `T1046.sh` | 扫 `127.0.0.1` 1-100 端口 | T1046 | N-0101 SYN 扫描告警 |
| TC-09 | `T1055.008.sh` | `inject_demo` 注入 1 字节 NOP 后回滚 | T1055.008 | memscan 注入告警（A+B 判定） |
| TC-10 | `T1574.006.sh` | 写 `/etc/ld.so.preload`（空内容）并恢复 | T1574.006 | LD_PRELOAD 后门检查 |
| TC-N1 | `N-baseline.sh` | `ls` / `date` / `cat` 等本地只读命令 | — | 阴性样本（FPR） |

## 脚本规范（所有脚本一致）

- 首行 `#!/usr/bin/env bash`，`set -euo pipefail`；开头打印 `TC-xx <technique> start`，结尾打印 `TC-xx done`
  （TC-N1 无技术编号，打印 `TC-N1 baseline start`）；
- 支持 `--dry-run`（只打印计划动作，不产生副作用）与 `--run`（runner 传入，等价默认执行）；
  未知参数报错并 `exit 2`；
- 全部使用 `trap cleanup EXIT` 清理；危险动作（TC-03/05/06/10）前置检查 root/免密 sudo 与可写性；
- 需要 root 但拿不到 `sudo -n` 时输出 `TC-xx SKIP: ...` 并 `exit 0`，runner 记为 `inconclusive`；
- 只做无害动作，不访问外部网络、不落真实恶意样本：
  - TC-01/07/08/N1 无持久化产物；
  - TC-02 的 EICAR 是公开杀毒软件测试串（68 字节，非恶意代码），下载物保留供静态扫描复核，
    下次运行开始时自动清理上一次的样本；
  - TC-03/04/05/06/10 退出时精确恢复（删单元/还 cron/删账号/删副本/还原 `ld.so.preload`）。

## 环境变量（可选，便于在不同主机复现/调整）

| 变量 | 默认 | 用途 |
|---|---|---|
| `HORNWORK_TC02_PORT` | `18080` | TC-02 本地 HTTP 下载端口 |
| `HORNWORK_TC05_USER` | `hornwork_tc05` | TC-05 测试账号名 |
| `HORNWORK_TC07_TARGET/PORT` | `127.0.0.1:8080` | TC-07 心跳目标 |
| `HORNWORK_PYTHON` | `python3` | TC-02/07/08/09 用的 Python 解释器（本地 HTTP、DNS、扫描、监听） |
| `HORNWORK_TC07_DNS_SERVER/PORT` | `127.0.0.1:53` | TC-07 DNS 查询目标（无需服务响应） |
| `HORNWORK_TC07_DOMAINS` | `ioc.example c2.example.com ioc.example` | TC-07 查询的 IOC 域名（来自 `rules/ioc/sample-domains.jsonl`） |
| `HORNWORK_TC07_DOMAIN` | 空 | 兼容旧用法：非空时追加为首个查询域名 |
| `HORNWORK_TC07_COUNT` | `10` | TC-07 心跳次数 |
| `HORNWORK_TC08_TARGET/START/END` | `127.0.0.1` / `1` / `100` | TC-08 扫描目标与端口范围 |
| `HORNWORK_TMP` | `/tmp` | 临时文件目录（TC-09 pid 文件 `hornwork-tc09.pid`） |
| `HORNWORK_TC09_KEEP` | `0` | 置 `1` 时脚本不杀目标进程，把 pid 交给 runner 做双次 `mem.scan` 后再清理（runner 自动设置） |
| `HORNWORK_TC09_HOLD_SEC` | `2` | 注入后脚本自身保持的秒数 |
| `HORNWORK_TC09_TARGET_SEC` | `20` | 自建目标进程的存活秒数（含持有 TCP 连接） |
| `HORNWORK_TC09_PORT` | `8080` | 目标连接用的本地监听端口（被占用时 listener 自动改用空闲端口） |

## TC-09 的 `inject_demo` 编译与内存扫描联动

TC-09 依赖仓库内 `hornwork/tools/inject_demo.c`（PTRACE 注入演示，无害），
脚本会自动编译并运行；缺少源码/`gcc`/`python3` 或注入失败时按规范 `SKIP`：

```bash
# 手动等价命令（runner 内部就是这样做的；工作目录为仓库根）
gcc -O2 -o /tmp/inject_demo hornwork/tools/inject_demo.c

# 脚本会先用 heredoc 写 C 源码并 gcc 出无害目标程序（$HORNWORK_TMP/hornwork-tc09.XXXXXX/target）：
#   mmap 128KB 的 PROT_READ|PROT_WRITE|PROT_EXEC 匿名内存 + NOP 填充（memscan 条件 A）；
#   目标进程通过 PR_SET_PTRACER 显式允许同 uid 进程 attach（非 root 也能演示注入）；
#   连接脚本用 python 起在 127.0.0.1:$HORNWORK_TC09_PORT 的监听并保持（条件 B 的“新连接”）；
/tmp/inject_demo --pid <目标 pid> --addr <目标输出的 ADDR> --byte nop   # 优先注入 RWX 段
/tmp/inject_demo --pid <目标 pid> --restore                             # 注入后回滚原始字节

# 限制：仅同 uid 或 root 可 attach；Yama ptrace_scope=1 时由目标进程的 PR_SET_PTRACER 放行同 uid 注入；
#       仅注入脚本自己启动的无害目标进程；只写 0x90(nop)，不落真实 payload。
```

runner 侧联动（`VerifyRunner.run(execute=True)` 且注入了 `ctl_call` 时）：

1. 以 `HORNWORK_TC09_KEEP=1` 运行脚本：脚本注入成功后保留目标进程与 pid 文件（监听进程由脚本 `trap` 清理，
   目标仍持有 socket，CLOSE_WAIT 状态同样能被 memscan 观察到）；
2. runner 读 `$HORNWORK_TMP/hornwork-tc09.pid`，**连续两次** `ctl_call("mem.scan", ...)`：
   第一次 `{"pid":pid}` 建连接/线程行为基线，`sleep 1s` 后第二次 `{"pid":pid,"snapshot":true}`
   触发条件 B（10s 内新连接）→ `MemoryScanner` A+B 判定为 `injected` 并产生 T1055 告警；
3. 第二次扫描结果写入报告 `cases[].post_ctl`（同时保留 `baseline` 供排查），随后 runner 结束目标进程、
   删除 pid 文件，再等待 `settle_sec` 做告警判定（judge 父子技术互认 T1055 ↔ T1055.008）。

`ctl_call` 为空（离线/无 daemon）时跳过 `mem.scan`，脚本按默认 `KEEP=0` 自行 `trap` 清理。

## 在 Windows 开发机上

脚本只能在 Linux（如 Ubuntu）上执行；`VerifyRunner.run(execute=False)` 不跑脚本、
只用数据库现有告警判定，便于无 root 演示与单测。只做语法检查时可用 `bash -n <script>`，
用 `bash <script> --dry-run` 查看计划动作。
