# 贡献指南（Contributing to Hornwork）

感谢你愿意参与 Hornwork！本文档说明开发环境、代码风格、规则编写、提交流程与
评审约定。开始之前请先阅读：

- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)：社区行为准则；
- [SECURITY.md](SECURITY.md)：漏洞报告与安全边界（**安全问题不要开公开 Issue**）；
- [README.md](README.md)：项目能力与快速开始；
- [docs/](docs/)：接口契约、规则格式、运行手册。

## 1. 开发环境

### 基本要求

| 项 | 要求 |
|---|---|
| 操作系统 | Linux（Ubuntu 22.04+ 推荐）；本地开发也可在 macOS/Windows 上跑跨平台用例 |
| Python | **3.11+**（CI 覆盖 3.11 / 3.12 / 3.13） |
| 第三方 Python 库 | `yara-python`、`PyYAML`；修改认证子系统时另需 `argon2-cffi`、`cryptography` |

> 说明：`pyproject.toml` 当前只声明了 `yara-python` 与 `PyYAML`。认证子系统
> （`hornwork.auth`）与部分加固用例额外依赖 `argon2-cffi`、`cryptography`，
> 需要手动安装（见下）。这两项尚未写入项目依赖，属于已知待办。

### 创建虚拟环境并安装

```bash
git clone <你的 fork 地址> hornwork
cd hornwork

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install argon2-cffi cryptography   # 认证/加固用例所需
```

### 系统级依赖（可选，跑完整功能时需要）

在 Ubuntu 上安装 systemd/auditd/clamav 等依赖并初始化目录需要 root。**只做代码
开发与单元测试时不需要执行这一步**：

```bash
sudo bash scripts/setup.sh          # 幂等；安装系统依赖、创建用户/目录、auditd 规则、systemd 单元
bash scripts/check.sh               # 环境自检
```

常用 Make 目标：

```bash
make setup    # 同 sudo bash scripts/setup.sh（需要 root）
make test     # python -m unittest discover -s tests -v
make check    # bash scripts/check.sh
make lint     # python -m compileall -q hornwork
make clean    # 清理 __pycache__ / build / dist
```

## 2. 目录速览

| 路径 | 内容 |
|---|---|
| `hornwork/` | 平台代码（daemon、总线、存储、采集器、引擎、响应、认证、加固、Web、CLI） |
| `tests/` | `unittest` 单元测试，测试产物写入 `tests/_tmp/`（已忽略） |
| `rules/` | YARA / 网络 DSL / 主机 JSON / Sigma / sigdb / IOC / playbook |
| `deploy/` | systemd 单元、auditd 规则、clamd 配置片段、版本锁 |
| `docs/` | 接口契约（`interfaces.md`）、规则格式（`rules.md`）、运行手册（`runbook.md`） |
| `scripts/` | 安装、自检、演示、各子系统初始化脚本（bash） |
| `data/` | 档案模板、漏洞档案 YAML、证据样例等随仓库分发的数据 |

## 3. 运行测试

```bash
# 全量（推荐）
python -m unittest discover -s tests -v

# 单个模块
python -m unittest tests.test_rules -v
python -m unittest tests.test_engines -v
```

约定与注意事项：

- Linux 专属用例（真实 `/proc`、inotify、clamd socket、`dpkg` 对拍等）使用
  `skipUnless` / `skipIf` 条件跳过，**不要为了让测试通过而删除或改写测试**；
- 依赖外部二进制的用例（`openssl`、`dpkg`、`nmap`、`lynis`）在缺依赖时会动态
  判定可用性或跳过；
- 需要 root 的端到端验证不在单元测试中执行，手工运行：
  `sudo hornworkctl verify run`；
- 测试必须自包含：不得访问真实网络、不得写系统临时目录、不得依赖本机状态；
- 提交前至少保证 `python -m compileall -q hornwork` 与全量单测通过。

## 4. 代码风格

- 遵循 **PEP 8**，4 空格缩进，单行建议不超过 100 列（见 `.editorconfig`）；
- 所有新代码使用 **类型注解**，文件头使用 `from __future__ import annotations`；
- 公共函数/类写 docstring，说明输入、输出、失败路径与安全边界；
- 注释语言可中文可英文，但**同一文件内保持一致**；对外文档以中文为主；
- 优先使用标准库，新增第三方依赖需在 PR 中说明理由、许可证与替代方案；
- 外部命令一律使用参数数组（`subprocess.run([...])`），禁止 `shell=True` 拼接；
- 异常处理要带上下文，禁止裸 `except:`；失败要计入状态或日志，不静默吞掉；
- 不要提交调试代码、真实凭据、个人数据或可执行恶意样本。

可选的自查（不强制，允许提示性失败）：

```bash
python -m pip install ruff
ruff check .
```

## 5. 新增检测规则

规则目录、格式与校验方式详见 [docs/rules.md](docs/rules.md)。新增规则后请运行
`python -m unittest tests.test_rules -v`，必要时执行 `hornworkctl rules reload`。

### 5.1 YARA 规则（`rules/yara/*.yar`）

- 文件名 stem 必须唯一（用作 namespace）；每个文件建议只放一条规则；
- `meta` 必填 `description`、`attack`（ATT&CK 技术号）、`severity`（0–100 整数）、
  `source`；
- 只使用无害测试样本或保留地址，禁止真实 IOC；
- 示例：

```yara
rule example_downloader
{
    meta:
        description = "示例：下载器命令行特征"
        attack = "T1105"
        severity = 70
        source = "hornwork-self"
        author = "hornwork contributors"
        date = "2026-11-03"
    strings:
        $a = "wget http" ascii nocase
        $b = "curl -s" ascii nocase
    condition:
        filesize < 2MB and any of them
}
```

### 5.2 网络规则（`rules/net/*.rules`）

- 使用 `docs/rules.md` 描述的 DSL；新增 `rule_id` 建议从 `N-02xx` 起，避免与 IOC 自动
  生成的规则冲突；
- 必须声明 `severity`、`technique`、`msg`；涉及窗口聚合的规则说明时间窗与去重语义。

### 5.3 主机规则（`rules/host/*.json`）

- 必填 `id / name / condition`；`level` 取 1–10；
- `event_types` 的取值必须来自 `hornwork/schema.py` 的 `EVENT_TYPES`（空数组表示全事件）；
- 常见误报场景请加白名单条件并在 `description` 中说明。

### 5.4 Sigma 规则（`rules/sigma/`）

- 只收录 SigmaHQ 上游规则，**保持目录结构与文件内容原样**，不修改检测逻辑；
- 来源、版本与 DRL 1.1 许可说明见 `rules/sigma/NOTICE.md`；
- 仅支持文档约定的字段/修饰符/条件子集，超出子集的规则会被跳过并计入统计。

### 5.5 自研签名（`rules/sigdb/`）与响应剧本（`rules/playbooks/`）

- `hashes.txt` / `hex.txt` / `regex.txt` 的行格式见 `docs/rules.md`；
- Playbook 的动作名必须与动作执行器一致，`mode ∈ observe / dry-run / enforce`，
  回滚步骤与前置步骤的对应关系需在 `description` 中写清。

## 6. 文档与测试同步

- 新增/修改对外行为时，同步更新 `docs/` 对应文档与 `README.md` 中的命令示例；
- 新增 CLI 子命令、配置项、规则字段时，补对应单元测试；
- 安全模型相关改动（权限、审批、默认模式）必须在 PR 中显式说明。

## 7. 提交信息规范（Conventional Commits）

格式：`<type>(<scope>): <subject>`

- `type`：`feat` / `fix` / `docs` / `test` / `refactor` / `perf` / `build` /
  `ci` / `chore` / `security`；
- `scope`：模块或目录名，例如 `engines`、`collectors`、`scan`、`auth`、`harden`、
  `web`、`rules`、`docs`、`ci`；
- `subject` 用祈使句、简短明确，不以句号结尾；
- 破坏性变更在正文写 `BREAKING CHANGE:` 并说明迁移方式。

示例：

```
feat(engines): add entropy-based static scanning fallback
fix(scan): avoid duplicated CVE rows when package appears twice
docs(rules): document N-0102 landing adaptation
test(auth): cover TOTP replay rejection
```

## 8. PR 流程

1. Fork 仓库，从 `main` 拉出特性分支：
   `git checkout -b feat/short-description`；
2. 提交前跑通全量单测与 `python -m compileall -q hornwork`；
3. 推送分支并在仓库发起 Pull Request，填写 PR 模板（变更说明、关联 Issue、
   测试情况、安全影响、检查清单）；
4. 保持 PR 聚焦：一个 PR 只做一件事；大改动请先开 Issue 讨论；
5. 评审通过后由维护者合并（默认 squash merge，保留 Conventional Commit 标题）；
6. 合并后删除特性分支。

仓库分支约定：

- `main`：始终可发布，CI 必须通过；
- `feat/*` / `fix/*` / `docs/*` / `chore/*`：特性分支；
- 安全修复走私下流程（见 [SECURITY.md](SECURITY.md)），不直接开公开 PR。

## 9. 开发者原创声明（DCO）

本项目采用简化的 DCO：在提交时加上签署行即表示你确认：

1. 该贡献由你原创，或你有权按本项目许可证提交；
2. 你同意该贡献按 **Apache-2.0**（入站=出站）许可分发；
3. 你理解贡献会公开记录在仓库历史中。

签署方式：

```bash
git commit -s -m "feat(scope): subject"
```

提交信息末尾会追加：

```
Signed-off-by: Your Name <you@example.com>
```

> 请使用可联系的邮箱；不要在提交信息中填写与贡献无关的个人身份信息。

## 10. 安全与合规

- 发现安全漏洞请按 [SECURITY.md](SECURITY.md) 私密报告，**不要**在公开 Issue/PR
  中贴 PoC 或利用细节；
- 贡献的规则与样本必须无害：只使用 EICAR 测试串、RFC 5737 保留地址、
  RFC 2606 保留域名等；
- 不得提交真实凭据、密钥、个人数据或来自未授权系统的日志；
- 新增外部命令调用需说明权限需求与失败降级路径。

## 11. 沟通渠道

- 功能建议与缺陷：GitHub Issues（使用仓库的 Issue 模板）；
- 使用问题：GitHub Discussions；
- 安全漏洞：请勿公开提交，走 [SECURITY.md](SECURITY.md) 的私密渠道（GitHub Security Advisories）；
- 行为准则举报：通过 GitHub Security Advisories 私密报告，或私信维护者。

再次感谢你的贡献！
