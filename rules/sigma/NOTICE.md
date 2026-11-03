# Sigma 规则来源与许可说明

## 来源

本目录下的 `linux/**/*.yml` 全部来自 **SigmaHQ / sigma** 官方仓库的 Linux 规则集：

- 上游仓库：<https://github.com/SigmaHQ/sigma>
- 本地参考副本：`参考资源/开发依赖仓库/src/sigma`（稀疏克隆，仅含 `rules/linux/`）
- 上游路径：`rules/linux/{process_creation,file_event,network_connection}/`

复制时**保持上游相对目录结构与文件内容不变**（未修改任何检测逻辑、字段名或
`logsource`），仅做筛选，便于与 Hornwork 的 Sigma 子集匹配器（§4.2.6）对齐。

## 许可证

上游规则按 **Detection Rule License (DRL) 1.1**（检测规则许可）发布，
Sigma 规范与 Logo 为公有领域：

- DRL 1.1: <https://github.com/SigmaHQ/Detection-Rule-License>
- 上游 LICENSE 文件：`参考资源/开发依赖仓库/src/sigma/LICENSE`

Hornwork 仅将这些规则用于测试环境的本地检测验证，不对外分发、不用于商业用途。
若需二次分发，请遵守 DRL 1.1（保留版权声明、修改需注明、不得暗示背书）。

## 选取范围（共 66 条）

| 类别 | 条数 | 说明 |
|---|---|---|
| `process_creation` | 57 | 进程创建：反弹 shell、curl/wget 下载、base64 解码执行、cron/systemd 持久化、凭据文件操作、挖矿、权限变更等 |
| `file_event` | 7 | 文件事件：cron 文件创建、profile.d shell 脚本、临时目录 wget 落地、rootkit 持久化等 |
| `network_connection` | 2 | 网络连接：bash 反连 shell、矿池连接 |
| 合计 | **66** | 落在约定的 50～80 条区间 |

## 与 Hornwork Sigma 子集匹配器的兼容性

`hornwork/engines/sigma_matcher.py` 只支持：

- `logsource.category ∈ {process_creation, file_event, network_connection}`
- 字段：`Image / CommandLine / ParentImage / User / TargetFilename / DestinationIp / DestinationPort / QueryName`
- 修饰符：`contains / startswith / endswith / re / all`
- 条件：`selection`、`and/or/not`、`1 of selection*`、`all of them`

此外按文档 §4.2.6，`status ∈ {test, deprecated}` 的规则默认跳过（计入
`sigma_stat(supported=0)`）。SigmaHQ Linux 规则集大量是 `status: test`：本目录 66 条中
`stable 7 / experimental 14 / test 45`。为兼顾"文档严格口径"与"实验覆盖率"，部署配置
提供了开关 `[engines.sigma].include_status_test`：

- `false`（严格复现文档口径）：loaded=66，supported=20，skipped=46（45 条 test + 1 条字段不支持）；
- `true`（本仓库 `config.toml` 当前取值，实验演示用）：loaded=66，supported=65，skipped=1，
  唯一跳过的是 `net_connection_lnx_crypto_mining_indicators`（上游使用 `DestinationHostname`，
  不在 §4.2.6 字段白名单内）。

两种口径下都 **0 error**：按支持子集编写的规则 100% 解析成功。带
`detection.timeframe`、`|count()` 聚合、`base64offset/cidr/windash` 修饰符的规则
**未纳入**本目录，以保证解析器不报错。

## 上游版本

参考副本的提交时间以 `参考资源/开发依赖仓库/src/sigma` 的 git HEAD 为准；
规则作者、`id`、`date`、`references`、`level` 等字段均保留在各自 YAML 文件头中，
未做任何改写。
