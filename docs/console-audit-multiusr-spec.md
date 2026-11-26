# Web 控制台访问审计与多用户模型 —— 详细实施规格

> 状态：待评审的施工规格　日期：2026-11-22
> 前置：[console-audit-multiusr-plan.md](console-audit-multiusr-plan.md)（总体方案）
> 开放问题 Q1–Q5 已由需求方确认，按方案建议执行。

---

## 0. 已决议事项（Q1–Q5 固化）

| 编号 | 决议 | 落地口径 |
|---|---|---|
| Q1 | 静态 Bearer token = **非用户运维通道** | 不进角色模型；审计固定 `username="__token__"`、`session_id="-"`、`user_id=NULL`；放行条件不变（回环或已配置 token）。避免把运维密钥提升成超级用户 |
| Q2 | `console_access` **只写 `auth_audit`，不镜像到 `event` 表** | 见 §1.2：`schema.EVENT_TYPES` 是封闭枚举，且 `risk.last_logon()` 依赖 `event='logon'`，污染会直接破坏风险评分 |
| Q3 | 审计写失败 → **500 拒绝 + DLQ** | 安全优先：没有审计记录的访问不放行；`detail` 带 `audit_dlq_id` |
| Q4 | 登录后**保留旧会话**，只记录并发会话数 | 不改 `session.issue()` 的防固定语义；在 `logon` 审计 detail 追加 `active_sessions=N` |
| Q5 | 角色升级走 **CLI 显式授权** | 新增 `hornworkctl auth user set-role`，且禁止撤销最后一个 admin（防锁死） |

---

## 1. 核查新发现（这些约束改变了实现方案）

### 1.1 `auth_audit` 链有 BUG-03 同款并发断链风险 —— 必须先修实现

`tests/test_intel_respond.py:530-609` 已为 `action_audit` 建立了并发写保护（`Store.audit_append_atomic`，`store.py:656`），但 **`auth_audit.append()`（`auth/audit.py:37-64`）没有同等保护**：

```
chain_head()   → query_one(最后一行) + get_meta()      # 各自拿/放 store._lock
_hash_row()    → 纯计算
store.execute(INSERT ...)                              # 自动 commit
store.set_meta(CHAIN_HEAD_KEY, row_hash)               # 又一次 commit
```

三步之间锁已释放，多线程（Web 是 `ThreadingHTTPServer`）或多进程（CLI）并发时，两个写者会读到同一 `prev_hash`，产生重复的 prev_hash → `verify_chain` 断链。

**结论**：`console_access` 会把审计写频率从"登录级"抬到"每请求级"，并发概率呈数量级上升，**必须先给 auth_audit 加原子追加，再接 Web**。这不是可选项，是前置条件。

### 1.2 `console_access` 绝不能写成 `event='logon'`

- `schema.new_event()` 对未知 `event_type` **直接抛 ValueError**（`schema.py:142-143`），封闭枚举不支持新类型；
- 更关键：`risk.last_logon()`（`risk.py:37-43`）查询 `auth_audit WHERE event='logon' AND result='ok'`，`ip_change` 信号（`risk.py:118-121`）完全依赖它。若把访问审计写成 `logon`，用户每刷一次页面都会"重置上次登录 IP"，**风险模型被静默破坏**。

**结论**：访问审计用独立 `event='console_access'`（auth_audit 的 event 列是自由文本，无枚举约束），只用 `auth_audit.append()`，不调用 `emit_event()`。

### 1.3 错误三态契约已有框架但未接线

`web/errors.py` 声明了 `C7/SOFT/AUTH_STATE` 三态，注释写明"由 Route 声明"，但 `routing.py:28-35` 的 `Route` **没有 `error_mode` 字段**，实际分派全走 C7。同时 `errors.py:8` 要求"三态改变必须同步 `frontend/tests/api.spec.ts` 的三态用例"，而该文件当前**没有三态用例**（只有 ApiError/compactParams 等）。

**结论**：本次不重构三态框架，但必须遵守其**行为约定**：
- 中间件 401 → 前端 `client.ts:148` 会清 session 并跳登录（用于令牌失效）；
- 中间件 **403** → 不能带 401，否则 `stepup_required` / `role_denied` 会被误判为掉登录；
- 新增的前端错误分支必须同步补 `frontend/tests/api.spec.ts` 用例（见 §6.4）。

### 1.4 `login_password_only` 路径的用户默认没有 TOTP —— 写角色会被永久锁死

平台统一登录（`engine.py:408-468`）**不校验 TOTP**。而 `step_up()`（`engine.py:483-518`）第一步就 `totp.verify_user()`，无激活凭证时返回"TOTP 未激活"失败。

**结论**：角色提权必须与因子注册绑定——`operator`/`admin` 角色**必须同时注册 TOTP + 人脸模板**，否则其写/管理 action 恒被 `stepup_required` 卡死。在 `set-role` CLI 里校验并在 `require_action` 里给出可诊断的 `reason`（见 §4.3）。

### 1.5 `session.issue()` 的 `ua_hash` 列从未被写入

`auth_session.ua_hash`（`db.py:63`）存在，但 `engine.py:363` 与 `engine.py:452` 两处调用都不传；`session.verify()` 也不核对。Web 层 `_session_token()` 只读 header，没有把 UA 传给引擎。

**结论**：需要扩展引擎授权入口签名（新增 `authorize()`，见 §4.1），在 Web 中间件计算 `ua_hash = sha256(User-Agent)` 后传入，形成"签发—校验"对偶。

### 1.6 迁移机制缺失

`db.init_schema()`（`db.py:178-182`）只执行 `CREATE TABLE IF NOT EXISTS`，没有 `ALTER TABLE` 路径；`auth.schema_version` 存在 meta 里但从不校验。

**结论**：新增 `role` 列必须有显式幂等迁移函数 + 版本升到 `2`；同库共用的平台 `Store.init_schema()` 不感知 auth 版本，迁移只能在 `open_auth_store()` 里做。

---

## 2. 数据模型与迁移

### 2.1 DDL / 迁移

```python
# hornwork/auth/db.py
AUTH_SCHEMA_VERSION = "2"

ROLE_VALUES = ("viewer", "operator", "admin")
ROLE_DEFAULT = "viewer"

def migrate_schema(store: Store) -> None:
    """幂等迁移：在 init_schema 之后调用，按 version 分支，不重复 ALTER。"""
    ver = int(str(store.get_meta("auth.schema_version") or "1"))
    cols = {r["name"] for r in store.query("PRAGMA table_info(auth_user)")}
    if "role" not in cols:
        store.execute(
            "ALTER TABLE auth_user ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer'")
        store.execute(
            "UPDATE auth_user SET role='admin' WHERE username IN "
            "(SELECT username FROM auth_user ORDER BY id LIMIT 1)")   # 见下方说明
    # 角色合法性兜底（人工改库的情况）
    store.execute(
        "UPDATE auth_user SET role='viewer' WHERE role NOT IN ('viewer','operator','admin')")
    store.set_meta("auth.schema_version", AUTH_SCHEMA_VERSION)
```

> **首个 admin 的兼容处理**：升级时把 `id` 最小的既有账号提升为 admin（Q5 的"CLI 显式授权"指的是**新装**从零开始时的口径；**升级**场景必须有且仅有一个引导 admin，否则管理接口无人可达）。该行为写入 CHANGELOG，并在迁移日志里明确打印被提升的用户名。若希望纯 CLI 授权，可把这段改为 `role='viewer'` 并在启动日志输出告警"无 admin，请执行 `hornworkctl auth user set-role <user> admin`"。

```python
def open_auth_store(cfg, db_path=None) -> Store:
    store = Store(...)
    init_schema(store)      # CREATE IF NOT EXISTS
    migrate_schema(store)   # 新增
    seed_policy(store)
    return store
```

### 2.2 角色权限矩阵（纯函数）

```python
# hornwork/auth/policy.py
ROLE_ACTIONS = {
    "viewer":   {"read"},
    "operator": {"read", "write", "sensitive", "ssh", "sudo"},
    "admin":    {"read", "write", "sensitive", "ssh", "sudo", "admin"},
}

def role_allows(role: str, action: str) -> bool:
    return str(action or "read") in ROLE_ACTIONS.get(str(role or ""), set())
```

**角色与 LOA 是 AND 关系**：`role_allows` 过 ≠ 放行，仍要过 `min_loa` + `step_up_required`。admin 也要 LOA3 才能写；viewer 就算 LOA3 也不能写。

### 2.3 会话列语义补全

| 列 | 现状 | 本方案 |
|---|---|---|
| `ua_hash` | 从不写 | 签发时写 `sha256(User-Agent)[:32]`（`session.issue` 新增可选参数 `ua_hash`）；校验时不一致 → `deny(ua_mismatch)` |
| `ip` | 登录 IP | 保留；请求 IP 与会话 IP `/24` 不同 → 追加 `session_ip_drift` 权重重算风险，按结果决定是否 step-up（不直接 deny，避免 NAT 误伤） |
| `strong_auth_ts` | step-up 刷新 | 不变，`require_action` 继续消费 |

---

## 3. 路由 → action 全表（`routing.py`）

在 `Route` 增加两个字段：`action: str = "read"`、`audit: bool = True`。`needs_auth=False` 的路由不参与 action 门禁，但仍可通过 `audit` 单独记录。

| 路由 | 方法 | needs_auth | action | 说明 |
|---|---|---|---|---|
| `/`, `/index.html`, `/platform`, `/platform.html` | GET/HEAD | 否 | — | 静态页，不审计（避免噪声） |
| `/healthz`, `/favicon.ico` | GET/HEAD | 否 | — | 健康检查，不审计 |
| `/assets/*` | GET/HEAD | 否 | — | 静态资源，不审计 |
| `/api/auth/login` | POST | 否 | — | 身份事件已有审计 |
| `/api/auth/step-up` | POST | 否 | — | 身份事件已有审计 |
| `/api/auth/logout` | POST | 否 | — | 身份事件已有审计 |
| `/api/auth/session` | GET/HEAD | 否 | — | 会话自查询，不重复审计 |
| `/api/overview` | GET | 是 | `read` | |
| `/api/events`, `/api/alerts`, `/api/rules`(GET) | GET | 是 | `read` | |
| `/api/intel`(GET), `/api/cases`(GET), `/api/validate` | GET | 是 | `read` | |
| `/api/engine-stats`, `/api/lab/envs`, `/api/vuln/records` | GET | 是 | `read` | |
| `/api/export`, `/api/integration/status` | GET | 是 | `read`（导出含敏感数据，可视作 `sensitive`） | 建议 `sensitive`，待确认 |
| `/api/platform/security`, `/api/events/recent`, `/api/events/types` | GET | 是 | `read` | |
| `/api/harden/status`, `/api/scan/*`(各 GET), `/api/report`, `/metrics` | GET | 是 | `read` | |
| `/api/rules`(POST), `/api/intel`(POST), `/api/cases`(POST) | POST | 是 | `write` | 需要 LOA3 + 强认证窗口 |
| `/api/auth/users`, `/api/auth/sessions`, `/api/auth/audit`, `/api/auth/policy` | GET | 是 | `admin` | 管理接口，仅 admin 角色 |

> `/api/export` 与 `/api/report` 会导出原始告警/报告，建议归 `sensitive`（仍需 LOA3）。这会让"只读运维"也需要强认证，属预期收紧行为，需在 CHANGELOG 标注。

---

## 4. 核心改造伪码

### 4.1 统一授权入口 `AuthEngine.authorize()`

`require_action()` 保留为纯引擎口径（供 CLI/测试直接调用），新增带请求上下文的 `authorize()` 供 Web 中间件调用，**二者共用同一决策核心** `decide()`：

```python
# hornwork/auth/engine.py
def decide(self, row: dict, action: str, role: str, *,
           request_ip: str | None = None, ua_hash: str | None = None) -> dict:
    """唯一决策核心。返回 {decision, reason, loa, action, ...ctx}"""
    # 1) 会话绑定：UA 不符直接 deny（最廉价的会话窃取信号）
    if ua_hash and row.get("ua_hash") and not const_compare(row["ua_hash"], ua_hash):
        return _deny("ua_mismatch", row, action)
    # 2) IP 漂移：不直接 deny，重算风险后交给 3/4
    risk_ctx = None
    if request_ip and row.get("ip") and ip_prefix(request_ip) != ip_prefix(row["ip"]):
        user = self.user_by_id(int(row["user_id"]))
        risk_ctx = risk.score(self.store, user, ip=request_ip,
                              device_id=row.get("device_id"),
                              weights=self._section("risk.weights"))
    # 3) 角色白名单（先于 LOA，给出更精确的可诊断 reason）
    if not policy.role_allows(role, action):
        return _deny("role_denied", row, action,
                     required_role=min(k for k, v in ROLE_ACTIONS.items() if action in v))
    # 4) LOA + 强认证窗口（原有口径）
    if int(row["loa"]) < policy.min_loa(action):
        return _stepup("loa_too_low", row, action, risk_ctx)
    if policy.step_up_required(row, action):
        return _stepup("strong_auth_expired", row, action, risk_ctx)
    # 5) 漂移风险达 loa3 阈值但当前会话仅 LOA2，且动作需要强认证
    if risk_ctx and risk_ctx["action"] in ("loa3", "loa3_warn", "lockout") \
            and int(row["loa"]) < 3 and policy.min_loa(action) >= 3:
        return _stepup("session_ip_drift", row, action, risk_ctx)
    return {"decision": "allow", "reason": "ok", "loa": int(row["loa"]),
            "action": action, "session": row, "risk": risk_ctx}

def authorize(self, token: str, action: str, *,
              role: str, request_ip: str | None,
              ua_hash: str | None) -> dict:
    try:
        row = self.session_row(token)        # verify + touch
    except session.SessionError as exc:
        return {"decision": "deny", "reason": exc.reason, ...}
    return self.decide(row, action, role, request_ip=request_ip, ua_hash=ua_hash)

def require_action(self, token: str, action: str = "read") -> dict:
    """兼容既有调用：role 从会话用户解析，无请求 IP/UA。"""
    row = self.session_row(token)  # 原逻辑
    user = self.user_by_id(int(row["user_id"])) or {}
    return self.decide(row, action, str(user.get("role") or "viewer"))
```

> `session_row()` 内部会 `session.verify(..., touch=True)`，每次请求刷新 idle 窗口，与现状一致。UA 校验用 `crypto.const_compare`。

### 4.2 Web 中间件 `_authorize()`

```python
# hornwork/web/server.py
def _authorize(self, route) -> dict:
    # Q1：静态 token 通道——非用户、非角色，单独审计
    if self._is_static_token():
        ctx = {"decision": "allow", "reason": "ops_token", "loa": 3,
               "action": route.action, "username": "__token__",
               "session_id": "-", "user_id": None}
    else:
        token = self._session_token()
        if not token:
            ctx = {"decision": "deny", "reason": "missing_token", "action": route.action}
        else:
            eng = self._auth_engine()
            srow = self._session_row_cached(token)   # 一次 verify，复用给 session_info
            user = eng.user_by_id(int(srow["user_id"]))
            ctx = eng.authorize(token, route.action,
                                role=str(user["role"]),
                                request_ip=self.client_address[0],
                                ua_hash=self._ua_hash())
    # 审计（Q3：失败即 500）
    if route.audit:
        try:
            self._append_console_access(route, ctx)
        except Exception as exc:
            self.app.note_error()
            dlq_id = store.dlq_add("auth.access_audit", {...}, repr(exc))
            raise _HttpError(500, "审计写入失败，请求已被拒绝",
                             retryable=True, detail=f"audit_dlq_id={dlq_id}")
    return ctx
```

### 4.3 错误映射表（关键：403 vs 401）

| decision.reason | HTTP | C7 `code` | `message` | `detail` | 前端行为 |
|---|---|---|---|---|---|
| `missing_token` / `unknown` / `bad_mac` / `revoked` / `expired` / `idle_expired` / `ua_mismatch` | **401** | 401 | 未授权：会话无效 | `reason`, `action` | 清 session → 跳登录（现有拦截器） |
| `stepup_required` / `loa_too_low` / `strong_auth_expired` / `session_ip_drift` | **403** | 403 | 需要提升认证等级 | `reason`, `loa`, `action`, `required_loa` | **不跳登录**，拉起 step-up 对话框 |
| `role_denied` | **403** | 403 | 当前角色无权执行该操作 | `reason`, `role`, `required_role`, `action` | **不跳登录**，提示无权限 |
| `too_many_requests` | 429 | 429 | 请求过于频繁 | `retry_after` | 退避重试 |
| 审计写失败 | 500 | 500 | 审计写入失败，请求已被拒绝 | `audit_dlq_id` | 可重试 |

> **绝不能让 step-up / 角色不足返回 401**：`client.ts:148` 的拦截器会清掉 session 并把用户踢回登录页，而 step-up 场景下会话是有效的。

### 4.4 审计原子追加（前置修复）

```python
# hornwork/store.py —— 新增专用原子方法
def auth_audit_append_atomic(self, build_fields) -> int:
    """读链头→算哈希→INSERT→更新 meta 全在同一 SQLite 写事务内。
    BEGIN IMMEDIATE 同时挡住进程内线程与跨进程写者（配合 busy_timeout=15s）。
    """
    with self._lock:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            last = self.conn.execute(
                "SELECT row_hash FROM auth_audit ORDER BY id DESC LIMIT 1").fetchone()
            head = str(last["row_hash"]) if last else str(self._meta_get("auth.audit_head") or GENESIS)
            fields = build_fields(head)          # 纯计算 canonical + hash
            cur = self.conn.execute(INSERT_SQL, tuple(fields.values()))
            self._meta_set("auth.audit_head", fields["row_hash"])  # 同一连接，不另 commit
            self.conn.commit()
            return int(cur.lastrowid or 0)
        except Exception:
            self.conn.rollback()
            raise
```

```python
# hornwork/auth/audit.py
def append(store, *, event, result, ..., atomic: bool = False) -> int:
    if atomic or event.startswith("console_"):
        return append_atomic(store, ...)   # 走上面的事务方法
    return _append_legacy(store, ...)      # 身份事件保持原行为，降低回归面
```

> 只让 `console_access` 走新的原子路径，身份事件先保持原实现，缩小回归范围；后续再把身份事件迁移到原子路径（单独 PR）。

### 4.5 审计字段映射（不新增列，复用 `factor`/`detail`）

| auth_audit 列 | 值 |
|---|---|
| `event` | `console_access` |
| `result` | `ok` / `stepup_required` / `deny` / `rate_limited` |
| `factor` | `action`（read/write/admin/sensitive…） |
| `loa` | 会话 LOA（NULL 表示未认证） |
| `username` / `user_id` | 会话用户；静态 token 为 `__token__` / NULL |
| `ip` / `device_id` | 会话上下文 |
| `detail` | JSON：`{"path":..., "method":..., "session_id":..., "reason":..., "role":..., "ua_hash":..., "decision":...}` |
| `prev_hash` / `row_hash` | 走原子追加 |

> `verify_chain()` 的字段白名单不含 `detail` 以外的可变结构，复用现有列**无需改 `_canonical`**，兼容性安全。

---

## 5. CLI 改动

```bash
hornworkctl auth user add alice --password-stdin            # 默认 viewer
hornworkctl auth user add ops --admin --password-stdin      # admin（保留既有 --admin 语义）
hornworkctl auth user set-role alice operator               # 新增
hornworkctl auth user set-role alice viewer                 # 降级
hornworkctl auth user list                                  # 增加 role 列
```

`set-role` 保护规则：
1. 目标用户必须存在；角色值必须在 `ROLE_VALUES`；
2. 提升为 `operator`/`admin` 时校验 `totp.active_credential()` 与 `biometric.has_template()`，缺任一则拒绝并提示先注册因子（§1.4）；
3. 禁止把**最后一个 admin** 降级（查询 `COUNT(*) WHERE role='admin' AND status='active'`）；
4. 每次成功写 `audit.append(event="role_change", detail="old→new")`。

---

## 6. 等价性测试详细规格

### 6.1 夹具（新增 `tests/test_console_access.py`）

复用 `test_verify_web.py` 的 `WebServerTestCase`（随机端口、`_get/_post`）与 `test_auth.py` 的 `AuthTestBase.make_user/_vec`。新增：

```python
def make_role_user(eng, name, role, *, with_bio=True):
    user, secret = make_user(name, with_totp=True, with_bio=with_bio)
    eng.store.execute("UPDATE auth_user SET role=? WHERE id=?", (role, user["id"]))
    return user, secret
```

**三角色固定夹具**：`viewer_alice` / `operator_bob` / `admin_carol`，全部注册 TOTP + 人脸。

### 6.2 状态机等价性

| 编号 | 步骤 | 断言 |
|---|---|---|
| E1 | 同一 token+action 分别调 `eng.require_action()` 与经 HTTP `GET /api/overview` | 两者 `decision/reason/loa/action` 逐字段相等；审计行 `detail.decision` 等于该 decision |
| E2 | 同一用户/IP/向量分别走 `login()` 与 `login_password_only()` | 两者签发会话 LOA、`logon` 审计行 `loa/factor/result` 等价（注意 TOTP 路径 factors 含 totp，平台路径不含——比对 LOA 与 result，factors 比对为"含 pw"） |
| E3 | `step_up()` 前后分别调 `require_action(token,"write")` 与 `policy.step_up_required(session_row,"write")` | step-up 前两者都要求 step-up；step-up 后两者都 allow |

### 6.3 会话等价性

| 编号 | 步骤 | 断言 |
|---|---|---|
| E4 | 签发带 `ua_hash` 的会话，分别用正确/错误 UA 走 `session.verify(ua_hash=...)` 与 HTTP 请求 | 正确 UA 两路径都通过；错误 UA 两路径都 `deny(ua_mismatch)`，HTTP 为 401 |
| E5 | 撤销/过期会话后分别调 `verify` / `require_action` / HTTP | 三者 reason 对齐（`revoked`/`expired`/`idle_expired`），HTTP 401 |
| E6 | 模拟会话 IP 与请求 IP 不同网段 | 中间件重算的 `risk_ctx.score` 与直接 `risk.score(..., session_ip_drift)` 相等；写动作返回 `stepup_required(reason=session_ip_drift)`；读动作仍 allow |

### 6.4 审计链等价性

| 编号 | 步骤 | 断言 |
|---|---|---|
| E7 | 连续 20 次 HTTP 请求后调 `audit.verify_chain()` 与 `GET /api/auth/audit` | 两者 `ok=True` 且 `checked` 相等；篡改一行后两者都 `ok=False` |
| E8 | 单次请求 | 审计行 `factor==route.action`、`detail.decision==ctx.decision`、`detail.session_id` 与 `X-Hornwork-Session` 对应 |
| E9 | monkeypatch `auth_audit_append_atomic` 抛异常 | HTTP 500 + DLQ 有记录；与 `emit_event` 的 DLQ 行为等价（都能查到 topic 记录） |
| E10 | 8 线程 × 25 次并发 HTTP 请求（对齐 `test_intel_respond.py:575`） | 200 条 `console_access`，`verify_chain(ok=True)`，prev_hash 无重复 |
| E14（新） | 2 个子进程各写 30 条 `console_access`（跨进程） | 链完整，无重复 prev_hash（验证 `BEGIN IMMEDIATE` 的跨进程保护） |

### 6.5 多用户等价性

| 编号 | 步骤 | 断言 |
|---|---|---|
| E11 | 三角色 × 六 action 矩阵 | `policy.role_allows`、`eng.decide`、HTTP 门禁三者结论一致（管理员接口用 admin 角色测） |
| E12 | 同用户两会话 A/B：A 登出、改密 | A 失效 B 可用；改密后全失效；三处审计行一一对应 |
| E13 | 非 admin 访问 `/api/auth/*` 管理接口 | 403（**不是 401**），detail 含 `role_denied`；admin 200 |
| E15（新） | 在 `risk.last_logon()` 触发场景下产生 10 条 `console_access` | `last_logon()` 返回的仍是真实 `logon` 行，`ip_change` 信号不被访问审计污染 |
| E16（新） | step-up / role_denied / 令牌失效三类响应 | HTTP 分别为 403/403/401；前端 `onUnauthorized` 回调只在前两类**不触发**（通过 vitest 模拟拦截器验证） |

### 6.6 前端测试（`frontend/tests/api.spec.ts` 同步补充）

- 三态用例：C7（有 `message` → ApiError）、SOFT（`{items,error}` → softErrorOf）、AUTH_STATE（401 body 保留为 LoginResult）；
- 新增：`ApiError` 增加 `isStepUp`/`isRoleDenied` getter，从 `detail.reason` 解析；
- 新增：403 不触发 `unauthorizedHandler`，401 触发（用 `resetHttpForTest()` + mock axios adapter）。

### 6.7 测试工程约定

- 所有产物写 `tests/_tmp/<uuid>`，Windows 全绿；
- 等价性用例必须"同一 fixture 跑两条路径，断言可比对字段相等"，禁止复制期望值；
- CI 轻量守卫：`grep -q 'console_access' hornwork/auth/audit.py && grep -q 'console_access' tests/test_console_access.py`。

---

## 7. 分文件改动清单（精确到函数）

| 文件 | 改动 |
|---|---|
| `hornwork/auth/db.py` | `AUTH_SCHEMA_VERSION=2`；新增 `ROLE_VALUES/ROLE_DEFAULT/migrate_schema()`；`open_auth_store` 调用迁移 |
| `hornwork/auth/policy.py` | 新增 `ROLE_ACTIONS/role_allows()` |
| `hornwork/auth/audit.py` | 新增 `append_atomic()`；`append()` 按 event 分流；`SUMMARY` 支持 console_access 统计（可选） |
| `hornwork/auth/session.py` | `issue()` 增 `ua_hash` 参数并落库；`verify()` 增 `ua_hash`/`request_ip` 校验参数 |
| `hornwork/auth/engine.py` | `decide()/authorize()`；`require_action()` 委托 `decide()`；两处 `session.issue` 传 ua_hash；`create_user` 落 role；`login` 审计 detail 追加 active_sessions |
| `hornwork/auth/cli.py` | `user set-role` 子命令；`user list` 增加 role 列；因子注册校验与"最后 admin"保护 |
| `hornwork/web/routing.py` | `Route` 增 `action`/`audit` 字段；全表填 action（§3） |
| `hornwork/web/server.py` | `_authorize()` 替换 `_authorized()` 调用；`_ua_hash()`；错误映射（§4.3）；审计调用 |
| `hornwork/store.py` | 新增 `auth_audit_append_atomic()`（§4.4） |
| `frontend/src/types/auth.ts` | `UserRow.role`；`SessionInfo.user.role`；`LoginResult`/`ApiError.detail` 结构 |
| `frontend/src/stores/auth.ts` | `role` computed；`ensureLoa(action)`（403 时拉起 step-up） |
| `frontend/src/api/client.ts` | `ApiError.isStepUp/isRoleDenied`；401 拦截保持不变，403 不清理 session |
| `frontend/src/router/index.ts` | 按 `role` 过滤 admin 路由（`/auth` 管理页） |
| `frontend/src/components/layout/AppSidebar.vue` | 按角色隐藏菜单项（UX，非安全边界） |
| `docs/architecture.md` §10 | 更新"不做多用户 RBAC"口径 |
| `docs/interfaces.md` §10 | 新增 IF-29；补充角色与访问审计 |
| `docs/authentication.md` §6/§9 | 角色边界与访问审计说明 |
| `CHANGELOG.md` | 迁移说明、首个 admin 提升、导出接口收紧为 sensitive |

---

## 8. 实施顺序（依赖驱动）

```
[0] 修 auth_audit 并发原子性（§4.4）           ← 前置，独立 PR 可先合
       ↓
[1] 数据迁移 + role 纯函数 + CLI set-role（§2/§5）
       ↓
[2] 等价性测试骨架 E1–E16 全部先红（§6）
       ↓
[3] 引擎 decide/authorize + session 绑定（§4.1/§2.3）
       ↓
[4] Web 路由 action + 中间件 + 错误映射 + console_access 审计（§3/§4.2/§4.3/§4.5）
       ↓
[5] 前端角色/403 分支 + vitest 用例（§6.6）
       ↓
[6] 文档同步 + 全量验证
```

### 验收命令

```bash
python -m unittest tests.test_auth tests.test_verify_web tests.test_console_access -v
python -m unittest tests.test_intel_respond -v        # BUG-03 回归不回退
# 全量基线：521 passed / 3 skipped 不回退
cd frontend && npx vitest run                          # 含新增三态/403 用例
```

### 回滚方案

- 新增列 `role` 不删除（SQLite 不支持 DROP COLUMN 的低版本兼容），回滚时代码忽略该列即可；
- `console_access` 审计行保留（append-only），回滚只停写；
- 前端按需回退静态产物（`frontend/dist` → `hornwork/web/static/app`），后端接口保持向后兼容（C7 结构不变）。

---

## 9. 残留风险

| 风险 | 缓解 |
|---|---|
| `BEGIN IMMEDIATE` 与 `Store.execute()` 自动 commit 混用可能提前结束事务 | 原子方法内**全部直接操作 `self.conn`**，不调用 `execute()/set_meta()` 封装；单测 E10/E14 覆盖 |
| 静态 token 无审计身份区分 | `__token__` 固定身份 + `detail` 记录来源 IP；文档中明确非用户通道 |
| `/api/export` 收紧为 sensitive 影响现有脚本 | CHANGELOG 标注 + 静态 token 仍可访问（Q1 通道不受角色限制） |
| 跨进程 BEGIN IMMEDIATE 在高并发下等待 | `busy_timeout=15s` 已配置；E14 子进程测试覆盖；超时应返回 500+DLQ 而非静默丢审计 |
