# Pull Request

## 变更说明

<!-- 这个 PR 做了什么？为什么需要？请聚焦单一主题。 -->

## 关联 Issue

<!-- 例如：Closes #123 / Refs #456；无关联请写“无”。 -->

## 测试情况

<!-- 说明你跑了什么、结果如何；贴关键输出或截图。 -->

- [ ] `python -m compileall -q hornwork` 通过
- [ ] `python -m unittest discover -s tests -v` 通过（或说明跳过的环境相关用例及原因）
- [ ] 手工验证步骤（如有）：
  ```bash
  # 复现/验证命令
  ```

## 安全影响

<!-- 涉及权限、审批、默认模式、外部命令、依赖、数据写入的改动必须说明。 -->

- 是否改变响应默认模式（observe / dry-run / enforce）？
- 是否新增外部命令调用或系统权限（capability / root）？
- 是否新增第三方依赖（名称、许可证、替代方案）？
- 是否影响 Web 控制台鉴权、审计链或数据留存？
- 其他安全影响：

## 检查清单

- [ ] 提交使用 Conventional Commits 格式，并已 `git commit -s` 签署 DCO
- [ ] 未提交真实凭据、密钥、个人数据、真实 IOC 或可执行恶意样本
- [ ] 新增/修改的行为有对应单元测试；测试自包含（不访问真实网络、不依赖本机状态）
- [ ] 文档（`README.md` / `docs/`）与 `CHANGELOG.md` 已同步更新（如适用）
- [ ] 规则改动已通过 `python -m unittest tests.test_rules -v`，必要时已 `hornworkctl rules reload`
- [ ] 跨平台/跨 Python 版本（3.11–3.13）兼容性已考虑
- [ ] 若是安全漏洞修复，已按 SECURITY.md 走私密流程（未在公开 PR 中披露利用细节）
