# 变更日志（Changelog）

本文件格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Planned

- 补充跨发行版的安装与回滚演练脚本；
- 扩展检测规则覆盖率与误报基线；
- 完善 Web 控制台的访问审计与多用户权限模型。

## [0.1.0] - 2026-11-03

首个开源版本。Hornwork 是一个单进程的轻量主机/网络纵深防御平台：
采集 → 归一 → 检测 → 告警 → 工单与响应 → 审计链 → 验证与指标，
全部基于 Python 标准库 + libyara + 外部独立进程（ClamAV / nmap / Lynis 等）。

### Added

- **检测流水线**：异步事件总线（背压、丢弃计数、死信队列）、CanonicalEvent /
  DetectionAlert 规范化模型、SQLite(WAL) 存储层与统一规则加载。
- **静态扫描级联**：自研签名库（哈希 / hex / 正则 / 熵 / 结构）+ YARA 引擎 +
  ClamAV 客户端级联，哈希缓存命中短路，单引擎异常隔离并计入统计。
- **主机检测**：auditd 事件解析与拼装、`/proc` 进程差分、inotify 文件完整性监控、
  认证日志暴力破解跟踪、持久化项检查（隐藏进程 / 无文件 / LD_PRELOAD / 内核模块 /
  cron / systemd / 账号 / SUID）、主机行为规则 JSON DSL、Sigma 子集匹配器。
- **网络检测**：AF_PACKET 抓包 → 协议解码 → 流表与行为跟踪 → 网络规则 DSL
  （SYN 扫描、XMAS/FIN 扫描、ICMP 扫段、SMB 横移、C2 心跳、畸形包、大流量外发、
  IOC 外联）。
- **内存检测**：在线 `maps`/`mem` 扫描与注入判定，离线 AVML → Volatility 3
  互证流程（`malfind`/`pslist` 解析、CSV 互证与降级说明）。
- **情报能力**：IOC 生命周期管理、JSONL / abuse.ch 风格 CSV 导入、去重与保留地址
  过滤、`intel2rule` 自动生成检测规则、STIX 2.1 子集导出/导入。
- **响应与审计链**：工单、playbook 编排（`PB-001`）、动作执行器（隔离文件 /
  取证采集 / 开单 / 恢复 / 结束进程 / 封禁 IP / 隔离主机 / 禁用账号）、
  审批与 `observe`/`dry-run`/`enforce` 三模式、sha256 哈希链审计与校验命令。
- **定期漏洞扫描**：资产台账与计划槽位、时间窗/白名单/并发/磁盘闸门、nmap 端口与
  服务识别、包清单与 CPE/版本归一、NVD/OVAL 离线导入、Debian 与 semver 版本区间
  匹配（CPE + 发行版修正 + 置信度）、快照四态 diff、加权覆盖率、自包含 HTML 报告、
  扫描窗口自扰治理。
- **靶场编排与漏洞档案**：Vulhub 索引与本地/SSH 双后端、compose 补丁与端口规划、
  目录守卫与白名单、TTL 回收与清理、漏洞档案 YAML 模型、CVSS 3.1 计算器、
  档案同步与匹配、复现与证据包采集（`lab_repro`）。
- **认证子系统**：Argon2id（pepper 预变换）口令、自研 RFC 4226/6238 TOTP、
  会话令牌与 step-up、人脸模板可撤销正交变换 + AES-256-GCM 保护、风险评估与
  限流锁定、审计哈希链、`logon`/`logon_fail` 事件接入。
- **加固编排**：`items.yaml` 基线（六类 24 项，唯一事实来源）、资产画像与计划
  （批次/排除理由/sha256/Ed25519 签名）、三段式幂等执行（check → 备份 → apply →
  verify，失败隔离、高危项 systemd-run 定时回滚保险）、回滚、前后客观测量与
  Markdown/JSON 报告；密码学落地：TLS 1.2/1.3 仅 AEAD、自建 CA（ECDSA P-256）、
  Ed25519 签名验签、LUKS2（Argon2id KDF + 双密钥槽）。
- **验证框架**：10 条 ATT&CK 攻击模拟 + 1 条阴性用例、判定器（TP/TN/FP/FN /
  TPR/FPR/MTTD / 覆盖率）、取证文本解析与降级路径、eBPF 缺失时的安全回退。
- **Web 控制台**：标准库 HTTP 单页控制台（默认仅回环 + token 鉴权），提供事件、
  告警、工单、审计链、规则、扫描、靶场、漏洞档案、认证等只读/受控 API。
- **CLI**：`hornworkctl` 覆盖状态、事件、告警、扫描、情报、响应、审计、
  漏洞扫描、靶场、认证等子命令；加固子系统提供独立入口 `hardenctl`。
- **交付工件**：systemd 单元 / timer、auditd 规则、clamd 配置片段、logrotate、
  systemd 模板服务、部署版本锁、安装与自检脚本。
- **测试**：515 个单元测试（unittest），覆盖上述全部子系统；root/auditd/clamd/
  yara 等环境相关用例按条件跳过，跨平台用例在本地开发环境同样可跑。

### Security

- 响应动作默认 `observe`，`enforce` 需显式审批并全程写入审计哈希链；
- Web 控制台默认绑定 `127.0.0.1` 并要求 token，未授权请求返回 401；
- 口令存储使用 Argon2id + pepper，TOTP 明文不落库；
- 外部命令调用使用参数数组，避免 shell 拼接注入；
- 扫描/靶场默认限制在自有资产与回环端口，越界目标在闸门层拒绝。

### Known Limitations

- 部分验证与取证用例需要 root 手工执行，daemon 不主动提权；
- 未安装的第三方引擎（如 testssl.sh / nuclei / lynis）按 `available()=False`
  降级，任务标记 `partial` 并计入未覆盖，不伪造覆盖；
- CVE 数据为离线快照，匹配结果提供置信度而非最终结论；
- 安全漏洞与行为准则举报通过 GitHub Security Advisories 的私密入口提交。
