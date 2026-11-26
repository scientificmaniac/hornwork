# Web 控制台访问审计与多用户模型 —— 方案（联动等价性测试同步设计）

> 状态：总体方案已确认（Q1–Q5 已决议）；**施工级细节见 [console-audit-multiusr-spec.md](console-audit-multiusr-spec.md)**　日期：2026-11-22
> 关联代码：`hornwork/auth/{engine,session,policy,audit,db}.py`、`hornwork/web/{server,routing,context}.py`、`hornwork/web/api/auth.py`、`frontend/src/{api,stores}/*`
> 关联文档：`docs/authentication.md`（IF-25~28）、`docs/architecture.md` §10、`docs/interfaces.md` §10

---

## 0. 一句话结论

现状里三处能力**各自存在但从没真正联动**：状态机有 `require_action()`，但 Web 中间件从不调用；会话只登记 `ua_hash` 却从不写入/校验；审计链只记录登录类事件，对"控制台每次访问"一无所知；`admin` 标志只影响建号时的口令强度，没有持久化成角色，也没有任何 RBAC。因此本方案不是"加一个新模块"，而是把**认证状态机 → 会话 → 审计链**这条线在 Web 控制台入口处接通，并给每个环节配一条**等价性不变式测试**，让"实现变更"与"契约测试"同步演进。

---

## 1. 现状盘点（基于代码事实）

| 环节 | 已实现 | 缺口（本方案要补的） |
|---|---|---|
| 认证状态机 | `AuthEngine.start_login/advance/login/login_password_only/step_up/require_action`；风险决定 LOA；degrade 显式；120 s challenge | `require_action(token, action)` 只在 `tests/test_auth.py` 里被调用；Web `_authorized()`（`server.py:243`）只做"票据有效"判定，不调用它，也没有任何请求→action 的映射 |
| 会话 | HMAC `s1.` 令牌、服务端 `sha256(token)` 登记、idle/absolute 双过期、`ua_hash` 列、`device_id`、`strong_auth_ts`、step-up `upgrade()` | `ua_hash` 签发时传的永远是 `None`（`engine.py:363,452`），verify 也不核对；无 IP 漂移检测（`risk.weights.session_ip_drift=25` 已定义但无人消费）；`session.issue()` 在登录成功时**没有先撤销旧令牌**，会议固定防护只在"登录"层，改密时靠 `revoke_user` |
| 审计链 | `auth_audit` SHA-256 哈希链、独立链头、篡改检测、`logon/logon_fail/stepup/...`、emit 到 `event` 表 | 审计链只覆盖**身份事件**，不覆盖**访问事件**（谁、用哪个会话、在什么 LOA 下、访问了什么、结果如何）；`emit_event` 有 DLQ 兜底但 `auth_audit.append` 没有 |
| 多用户/RBAC | `auth_user` 多账号、`loa_max` 上限、`admin` 建号参数 | `admin` 不落库（`engine.py:70` 只写 `detail` 审计文本），`list_users()` 查不出；`docs/architecture.md:616` 明确写"不做多用户 RBAC"；`/api/auth/users|sessions|audit|policy` 四个管理接口对任何有效会话开放，无角色门槛 |
| 等价性测试 | `test_scan_cve.py` 有前缀等价概念；全仓无"状态机/会话/审计三处联动的等价性"测试 | 缺一个"同一行为走不同路径/不同实现，结果必须等价"的测试套件，尤其缺 Web 层与 auth 层的对偶测试 |

---

## 2. 目标与非目标

**目标**
1. 每次控制台请求在中间件完成"票据有效 → action 判定 → 审计落链"的闭环；决策由认证状态机单一权威给出，Web 层不重复实现策略。
2. 会话绑定设备/UA/IP，异常触发风险重算或 step-up，而不是只验签。
3. 引入最小可用的多用户模型：账号 → 角色（admin/operator/viewer）→ action 权限，管理接口按角色门禁。
4. 审计链覆盖访问事件，且保持 append-only + 哈希链 + DLQ 兜底；与检测模块 `action_audit` 链互不干扰。
5. **同步**建立等价性测试：以上每一条联动都同时有一条"两条路径结果必须一致"的断言，代码与测试同一个 PR 合入。

**非目标（明确边界，沿用认证子系统口径）**
- 不做完整 RBAC 管理 UI、不做用户自助注册/找回；角色由 CLI/管理员维护。
- 不引入 JWT、OAuth、WebAuthn、PAM；不改登录页的因子编排。
- 不在 Web 层缓存鉴权结果（当前 `TtlCache` 只用于只读 GET 数据，鉴权必须每请求实时判定）。
- 不改 `event`/`alert` 结构；新增审计表列需向后兼容（见 §7 迁移）。

---

## 3. 三处联动的总体设计

```
HTTP 请求
  │
  ▼
[Web 中间件 _authorize()]
  1. 提取票据（Bearer s1. 会话 / 静态 token）
  2. ──状态机──► eng.require_action(token, action)   # 唯一权威决策
  3. 会话绑定校验：ua_hash 一致 / IP 漂移检测 → 必要时 deny 或要求 step-up
  4. ──审计链──► audit.append(event="console_access", result=decision,
                              user/session/loa/action/ip/device/path)
                  + emit_event("console_access"?) → 看 §4.3
  5. allow → 继续；stepup_required → 403 + 提示前端拉起 step-up；deny → 401/403
```

关键原则：**决策（状态机）与记录（审计）用同一份上下文**（同一个 `session_row`、同一 `action`、同一 `decision`），避免"判的是 A、记的是 B"。

---

## 4. 分环节改造点

### 4.1 认证状态机：请求 → action 映射 + 单一决策入口

- 新增 `hornwork/web/authz.py`（或在 `routing.py` 的 `Route` 上加 `action: str` 字段），把每个路由映射到 `ACTION_MIN_LOA` 中已有的 action 词表（`read/write/admin/sensitive/ssh/sudo`）。
  - 读写映射示例：
    - `GET /api/overview|/api/events|...` → `read`（LOA2）
    - `POST /api/rules|/api/intel|/api/cases` → `write`（LOA3 + 强认证窗口）
    - `GET/POST /api/auth/users|sessions|audit|policy` → `admin`（LOA3 + 角色=admin）
  - `auth_post`、`auth_get`（登录/会话/step-up/logout）保持 `needs_auth=False`，不参与 action 门禁，但要单独审计（见 §4.3）。
- `_Handler._dispatch()`：把现有的 `if route.needs_auth and not self._authorized()` 改成 `self._authorize(route)`，返回 `(decision, ctx)`；`allow` 放行，`stepup_required` → 403（带 `code=STEP_UP_REQUIRED`），`deny` → 401/403（C7 结构）。
- 静态 Bearer token 入口：它是**运维/脚本**通道，不属于任何用户会话。策略：给它一个明确的伪 action（`ops`）/固定 LOA3、且审计里 `username="__token__", session_id="-"`，**不**与用户会话混为一谈；或者显式规定"静态 token 只用于回环运维，不进入多用户模型"（需评审二选一，见 §9 开放问题 Q1）。

### 4.2 会话：绑定与漂移

- 签发时把 `ua_hash` 真正写入：`session.issue(..., ua_hash=sha256(User-Agent))`（`engine.py:363,452` 两处），`device_id` 继续来自可信设备。
- `session.verify()` 增加可选 `ua_hash`/`ip` 校验参数：
  - UA 不一致 → `SessionError("ua_mismatch")`（直接 deny，因为这是最廉价的会话窃取信号）；
  - IP 漂移 → 不立即 deny（NAT/移动网络误伤），而是把 `risk.weights.session_ip_drift` 纳入风险评分，达到阈值则 `require_action` 返回 `stepup_required`。
- `login_password_only` / `login` 成功后撤销该用户的**其他**仍有效会话（可选，防止旧设备留存），或至少在审计里标注"并发会话数"；与 `set_password` 的 `revoke_user` 行为对齐。
- step-up 后 `session.upgrade` 已刷新 `strong_auth_ts` 与 TTL，本方案不改其语义，只确保中间件每次都通过 `require_action` 消费它。

### 4.3 审计链：覆盖访问事件

- 新增事件类型 `console_access`（身份类仍用 `logon/logon_fail/stepup/logout`；访问类用 `console_access`），字段复用 `auth_audit` 现有列：
  - `event="console_access"`, `result ∈ {ok, stepup_required, deny, rate_limited}`,
  - `factor` 复用为 `action`（read/write/admin…），`loa`=会话 LOA，`ip`/`device_id` 来自会话上下文，
  - `detail` 存 `path`、`method`、`session_id`、`decision.reason`、`ua_hash` 摘要（JSON 字符串）。
  - `prev_hash/row_hash` 继续走 `audit.append`，链头不变，独立链语义不变。
- **不滥用 `emit_event`**：`audit.emit_event` 当前 schema 只允许 `logon/logon_fail`（`audit.py:140` 注释 IF-27）；控制台访问事件默认**只写 `auth_audit`**，是否镜像到 `event` 表作为独立决策点（Q2）。若要做，须走 schema 校验器确认不新增枚举值，否则会破坏 `docs/CONTRACT.md` 的事件契约。
- 写入可靠性：`auth_audit.append` 目前失败会抛异常并中断请求；改为与 `emit_event` 一致的"失败写 DLQ、不阻断"策略（但**必须先决策再审计**，审计失败不能放行未记录的访问——采用"审计失败 → 500 + DLQ"，等评审定 Q3）。

---

## 5. 多用户模型（最小可用）

### 5.1 角色与权限

- `auth_user` 增列 `role TEXT NOT NULL DEFAULT 'viewer'`（迁移：现有账号默认 `viewer`，但需一个引导命令把首个账号设为 `admin`，避免升级后全员锁死）。
  - 角色集合：`admin` / `operator` / `viewer`。
  - 权限口径：`viewer` → 只读（action `read`）；`operator` → 写 + 响应类（`read/write/sensitive/ssh/sudo`，仍需 LOA3 + 强认证）；`admin` → 全部 + 用户/审计/策略管理（`admin` action）。
  - 角色**不提升 LOA**，只做 action 白名单：admin 也要 LOA3 才能写，viewer 就算 LOA3 也不能写。两者是 AND 关系。
- 持久化 `create_user(..., admin=...)` 的 `admin` 参数：改为写 `role='admin' if admin else 'viewer'`（此前只出现在审计 detail 里）。`list_users` 增加 `role` 列。CLI `hornworkctl auth user add --admin` 据此生效。
- 在 `AuthEngine` 增加 `role_allows(role, action) -> bool`（与 `policy.min_loa` 平行的纯函数），`require_action` 在 LOA 判定通过后追加角色门禁；返回 `decision=deny, reason=role_denied`。

### 5.2 管理接口门禁

- `/api/auth/users|sessions|audit|policy` 四个 GET 在路由表标 `action="admin"`，由中间件统一拦截，无需在每个 handler 里手写检查（避免遗漏）。
- 前端 `AuthView.vue` / `AppHeader` 按 `session.info.user.role` 隐藏管理页签；但**前端隐藏只是 UX，后端门禁才是边界**。
- 会话隔离：`/api/auth/sessions` 当前返回全库 50 条；viewer/operator 只能看自己的会话（按 `session_row.user_id` 过滤），admin 看全部；审计 tail 同理（非 admin 只能看自己的 username）。

### 5.3 文档同步

- `docs/architecture.md` §10 的"不做多用户 RBAC"改为"最小角色模型：admin/operator/viewer，action 白名单 + LOA 双门"。
- `docs/interfaces.md` §10 增加 IF-29：`web → auth.console_authorize(request_ctx) → decision+ctx`；明确静态 token 的定位（Q1）。
- `docs/authentication.md` §6/§9 增加角色与访问审计的边界说明。

---

## 6. 等价性测试（与实现同步设计，同一 PR 合入）

> 核心思想："等价性"= 同一安全语义，经不同实现路径/不同入口/不同配置，必须产生**可比对的一致结果**。每个联动点至少一条对偶测试。

### 6.1 状态机等价性

| 编号 | 断言 | 对偶路径 |
|---|---|---|
| E1 | 同一 token+action，`AuthEngine.require_action()` 与 Web 中间件 `_authorize()` 的 `decision/reason/loa` 完全一致 | 直接调引擎 vs. 经 HTTP `_dispatch` |
| E2 | 三因子 `login()`（CLI/兼容路径）与 `login_password_only()`（平台路径）在相同风险/因子输入下，签发的会话 LOA、审计 `logon` 行的 `loa/factor/result` 等价 | 两条登录路径对同一用户、同一 IP/向量 |
| E3 | `step_up()` 成功后，`require_action(token,"write")` 从 `stepup_required` 变 `allow`，与直接读会话 `strong_auth_ts` 的计算结果一致 | 状态机决策 vs. `policy.step_up_required` 纯函数 |

### 6.2 会话等价性

| 编号 | 断言 | 对偶路径 |
|---|---|---|
| E4 | `session.issue()` 写入的 `ua_hash` 与 `session.verify(ua_hash=...)` 的校验口径一致；篡改 UA 后两条路径都 deny | 签发—校验成对测试 |
| E5 | 会话过期/撤销后，`session.verify()` 抛错、`require_action()` 返回 `deny`、`_authorize()` 返回 401，三者 reason 对齐 | 底层/引擎/HTTP 三层 |
| E6 | IP 漂移时，Web 层重算的风险分与直接 `risk.score(..., session_ip_drift)` 一致，step-up 判定等价 | 中间件 vs. 风险模块单测 |

### 6.3 审计链等价性

| 编号 | 断言 | 对偶路径 |
|---|---|---|
| E7 | 每次 `console_access` 审计行的 `prev_hash/row_hash` 满足 `verify_chain(ok=True)`；链上任意一行被改，Web `/api/auth/audit` 的 `chain.ok` 变 False | 写入端 vs. 校验端 |
| E8 | 同一次请求，Web 审计行的 `user/session/loa/action/decision` 与引擎 `require_action` 返回的上下文逐字段相等 | 记录 vs. 决策同源 |
| E9 | 审计写入失败（模拟 DB 锁/异常）时，DLQ 有记录且请求按 Q3 策略处理；与 `emit_event` 的 DLQ 行为等价 | 访问审计 vs. 身份事件审计 |
| E10 | 并发 N 条 `console_access` 写入后链完整（`BUG-03` 式回归，见 `tests/test_intel_respond.py:531`） | 并发写 vs. 串行写 |

### 6.4 多用户等价性

| 编号 | 断言 | 对偶路径 |
|---|---|---|
| E11 | 三个角色对同一 action 矩阵，`role_allows` 纯函数、引擎 `require_action`、HTTP 门禁三者结论一致 | 纯函数/引擎/HTTP |
| E12 | 同用户两个会话：A 登出只吊销 A，B 仍可用；改密吊销全部；三处审计行一一对应 | CLI/HTTP 交叉 |
| E13 | 非 admin 访问 `/api/auth/*` 管理接口 → 403；admin → 200；前端隐藏字段与后端权限一致（后端为准） | HTTP 层角色门禁 |

### 6.5 测试工程约定

- 新增 `tests/test_console_access.py`，复用 `test_verify_web.py` 的 `WebServerTestCase` 夹具（临时目录、随机端口、`_post/_get`），与 `test_auth.py` 的 `AuthTestBase` 共用了 `make_user/_vec`。
- 所有测试产物写 `tests/_tmp/`（DSH 沙箱约束），Windows 全绿是硬门槛（沿用现有测试口径）。
- 等价性对照用例统一写成"同一 fixture 跑两条路径，断言可比对字段相等"，禁止复制粘贴期望值。
- 加一条 CI 检查：`grep -c "console_access" tests/test_console_access.py` 与实现中的事件常量保持一致，防止实现改了测试没跟（轻量守卫）。

---

## 7. 迁移与兼容性

- 数据库：`auth_user` 加 `role` 列（`ALTER TABLE ... DEFAULT 'viewer'`），幂等；schema_version 升到 `2`，`init_schema` 里做 `PRAGMA table_info` 检查后补列。
- 角色引导：升级后若无任何 admin，提供 `hornworkctl auth user set-role <username> admin`（或首个 CLI 建号强制 admin），否则管理接口无人可达。
- 审计表**不加列**（用现有 `factor/loa/detail` 语义复用），避免破坏 `verify_chain` 的字段集合；若必须加列，须同步改 `_canonical` 字段白名单并升 schema_version。
- 静态 token 入口保持向后兼容（脚本/运维不受影响），但必须在审计和文档里标注它是"非用户通道"。

---

## 8. 实施步骤（建议顺序）

1. **契约先行**：落 `docs/interfaces.md` IF-29、更新 §3 的路由→action 映射表（纯文档 PR 或本 PR 第一部分）。
2. **等价性测试骨架**：写 `tests/test_console_access.py` 全部 E1~E13（先红），定义比对字段与夹具。
3. **状态机 + 会话改造**：`role_allows`、`require_action` 角色门禁、`ua_hash` 写入/校验、IP 漂移风险。
4. **Web 中间件改造**：`Route.action`、`_authorize()`、403/401 C7 语义、`console_access` 审计。
5. **多用户门禁**：角色持久化、管理接口过滤、前端按角色隐藏（UX）。
6. **文档同步**：architecture §10、interfaces §10、authentication §6/§9、CHANGELOG。
7. **全量验证**：`python -m unittest tests.test_auth tests.test_verify_web tests.test_console_access -v`，再跑全仓 `make test`（521+ 基线不回退）。

---

## 9. 开放问题 —— 已全部决议（2026-11-22）

| 编号 | 问题 | 决议 |
|---|---|---|
| Q1 | 静态 Bearer token 定位 | **非用户运维通道**，不进角色模型；审计固定身份 `__token__` |
| Q2 | `console_access` 是否镜像 event 表 | **否**，只写 `auth_audit`（schema 封闭枚举 + 避免污染 `risk.last_logon`） |
| Q3 | 审计写失败处置 | **500 拒绝 + DLQ**（安全优先） |
| Q4 | 登录后是否踢旧会话 | **保留旧会话**，仅记录并发会话数 |
| Q5 | 升级后首个 admin | **CLI 显式授权**；升级迁移时提升 id 最小账号为引导 admin 并在日志标注 |

决议后的工程级展开（含新发现的并发断链前置修复、路由 action 全表、403/401 映射、E1–E16 测试矩阵、改动文件清单）见 **[console-audit-multiusr-spec.md](console-audit-multiusr-spec.md)**。
