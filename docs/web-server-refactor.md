# Web 控制台服务重构设计（Server 重构说明）

> 对象：`hornwork/web/server.py`，重构前 **1522 行**，单个 `_Handler` 类约 1250 行，
> 承载 HTTP 传输、鉴权、38 个业务接口、静态文件、规则扫描、导出、Prometheus、
> 扫描模块代理等全部职责。
>
> 目标：**运行更高效**（消灭全站性开销与重复重查询）+ **可维护性更强**（按域拆分、
> 静态路由表、统一错误处理），并且 **对外接口无感迁移**：
> `WebServer(cfg, store)` 与 `start()`/`stop()`/`status()`/`request_reload()`/
> `reload_state()` 签名、路由行为、C7 错误结构、前端“200 + error”软错误契约全部保持。
>
> 本文为设计方案；**步骤 1–3 及按域拆分（步骤 4–8 的 handler 搬迁）已在 Ubuntu
> 26.04 虚拟机实机完成并验证**，实施结果见文末第 12 节。

## 1. 结论速览

| 维度 | 现状 | 重构目标 |
|---|---|---|
| `server.py` 行数 | 1522 | ≤ 180（只做生命周期 + HTTP server 装配） |
| `_Handler` 职责数 | 10+ 类挤在一个类 | 按域拆到 `api/*.py`，每文件 ≤ 250 行 |
| 路由表 | 每请求重建，`getattr` 隐式挂载 8 条 | 启动时构建一次静态表，显式注册 |
| 连接 | 强制 `Connection: close`，无复用 | HTTP/1.1 keep-alive + 超时兜底 |
| 重型接口 | 近 20 次串行 SQL / 最长约 13s 阻塞 | 合并查询 + TTL 缓存 + 并行探测 |
| 错误处理 | 散落 `try/except`，错误当 200 返回 | 统一 `error_mode` 策略（C7 / soft / auth-state） |
| 测试基线 | 单测 14 个 handler + e2e 2 个 | 新增架构自检 + 缓存/路由/错误契约测试 |

**三个全站性热点**（作用于每个请求或每次页面加载，优先级最高）：
1. 每个响应强制关闭连接（放弃 HTTP/1.1 复用，Vue 分块逐个握手）；
2. 每个请求重建整套路由表并做 8 次 `getattr`；
3. 会话型请求每个都执行 `session_info` 数据库查询。

## 2. 现状诊断（重构前基线，行号基于 1522 版）

### 2.1 性能问题

| 编号 | 严重度 | 位置 | 问题与影响 |
|---|---|---|---|
| P1 | 高 | L119/L799/L808 | 声明 HTTP/1.1 却每响应发 `Connection: close` 并置 `close_connection=True`，全站无连接复用 |
| P2 | 高 | L206–263 | `get_routes`/`post_routes` 与 8 路 `getattr` 在 `_dispatch` 内每请求重建 |
| P3 | 高 | L339–444 | `_h_integration_status` 单请求约 18 次串行 `COUNT(*)` + meta/latest 查询 + 审计链 + 文件遍历 |
| P4 | 高 | L446–499 | `_h_platform_security` 同步 TLS 探测(3s) + 两次 systemctl(5s×2)，单请求最长阻塞约 13s |
| P5 | 中高 | L918–942/L1316–1364/L1220–1233 | overview/metrics/engine-stats 重复 `counts()`/`latest_run_id()`/`validation_rows()`+`compute_metrics()`，无缓存；`/metrics` 被高频抓取 |
| P6 | 中 | L861–902 | 静态页与 assets 每次 `read_bytes()`，无内存缓存（哈希资源本可只加载一次） |
| P7 | 中 | L267–275/L819–839 | auth engine 惰性构造无锁竞态；每个会话请求一次 `session_info` DB 查询 |
| P8 | 中 | L1367–1372/L1464 | ThreadingHTTPServer 无并发上限，慢接口叠加导致线程膨胀 |
| P9 | 中 | 全文件 20+ 处 | 惰性 import 散落；`os`(L20/L448)、`time`(L23/L610) 重复导入 |
| P10 | 中 | L984–1060 | `/api/rules` 每次递归扫描 4 类规则目录并逐文件读取解析，无缓存 |
| P11 | 中 | L682/L710/L751/L770 | 扫描代理在请求热路径反复调用 `scan_store.init_schema()` |
| P12 | 低 | L811–813 | 所有响应 `json.dumps(default=str)` 全量序列化（必要开销，无流式） |

### 2.2 可维护性问题

| 编号 | 严重度 | 位置 | 问题与影响 |
|---|---|---|---|
| M1 | 高 | L115–1364 | 单类/单文件职责严重超标，任何改动都要理解整份文件，多人并行冲突概率高 |
| M2 | 高 | L687–786 等 | 8 个扫描代理几乎逐字复制 `except → 200 + error`，错误无法被监控/重试识别，与文件头 C7 约定自相矛盾 |
| M3 | 中高 | L231–245 | `getattr` 按需挂载让路由集合随分支合并状态漂移，IDE/静态分析无法发现死路由 |
| M4 | 中高 | 全文 5+ 处 | 路由以裸字符串散落在 if/字典/元组/docstring，文档头 L4–7 已明显落后于实际路由 |
| M5 | 中 | 40+ 处 | 大量裸 `except Exception` 吞异常且无日志，静默降级为 0/空，排障困难 |
| M6 | 中 | L459/L460/L474–475/L492/L612/L622 | HTTPS 端口 8443、主机名、目录、服务名、报告根路径全部硬编码，跨环境失效 |
| M7 | 低 | L16–35 vs 函数内 | 导入风格不一致、重复导入 |

### 2.3 必须保留的既有契约（来自调查，不可破坏）

- **公开接口**（`hornwork/web/__init__.py` + `docs/CONTRACT.md` §7）：
  `WebServer(cfg, store)`、`start()`/`stop()`/`status()`，以及被测试与前端实际依赖的
  `request_reload(note)`/`reload_state()`。
- **实现载体**：`ThreadingHTTPServer` + `BaseHTTPRequestHandler`，线程方式（`docs/CONTRACT.md` L410）。
- **鉴权**：Bearer token（web.token / web.token_env），静态页与 `/healthz` 免 token，
  无 token 时仅绑定回环（`docs/interfaces.md` L195–205、README L212–219）。
- **错误契约三态**（`frontend/src/api/client.ts`）：
  1. 通用接口：C7 `{code,message,retryable,detail}`，非 2xx（`ApiError.from`，L70–107）；
  2. 扫描类接口：**HTTP 200 + `{items:[], error:"..."}` 软错误**，由 `softErrorOf` 解读
     （`frontend/tests/api.spec.ts` L59–65、`client.ts` L8）；
  3. 认证类接口：401 时返回**状态机**而非 C7（`status`/`reason`/`degraded`，`client.ts` L51–53/L77–88）。
- **测试基线**：`tests/test_verify_web.py::WebServerTestCase`（L486–730）是回归金标准；
  e2e `frontend/tests/e2e/{serve_backend,cdp_e2e}.py` 覆盖登录与 session 路由。

> 重要：M2 的“错误当 200”在扫描类接口上是**前端明确依赖的契约**，不能简单全改成非 2xx。
> 重构做法是把它**显式化、收敛到一处**（见第 5 节 `error_mode`），而不是取消它。

## 3. 目标架构目录

```text
hornwork/web/
├── __init__.py              # 对外仍只导出 WebServer（签名不变）
├── server.py                # 入口：WebServer 生命周期 + HTTP server 装配（≤180 行）
├── context.py               # WebContext：cfg/store/token/统计/auth engine/缓存 的集中持有者
├── errors.py                # HttpError + C7 payload + error_mode 常量（从 server.py 抽出）
├── transport.py             # _Handler：只做传输层（解析/鉴权/分派/发送），不含业务逻辑
├── auth.py                  # 鉴权实现：_session_token / _authorized / auth engine 加锁构造
├── static_files.py          # 静态页与 assets（含内存缓存 + 路径穿越防护）
├── routing.py               # Route 定义 + 静态路由表注册中心
├── api/                     # 业务 handler：一个域一个模块，统一签名
│   ├── __init__.py          # all_routes()：汇总各域 Route 列表
│   ├── overview.py          # overview / engine-stats
│   ├── events.py            # events / events/recent / events/types
│   ├── alerts.py            # alerts
│   ├── rules.py             # rules GET/POST + 规则目录扫描（带缓存）
│   ├── intel.py             # intel GET/POST
│   ├── cases.py             # cases GET/POST
│   ├── validate.py          # validate
│   ├── export.py            # export + markdown 渲染
│   ├── metrics.py           # /metrics Prometheus 渲染
│   ├── auth.py              # auth login/step-up/logout/session/users/sessions/audit/policy
│   ├── integration.py       # integration/status + platform/security（重型诊断）
│   ├── harden.py            # harden/status
│   ├── lab.py               # lab/envs + vuln/records
│   ├── scan.py              # 8 个扫描代理 handler（统一走 soft error）
│   └── report.py            # scan/reports + report 文件服务
└── static/                  # 不变（index.html / platform.html / app/）
```

新增两个**可执行约束**文件（借鉴 CLI 重构先例）：
- `tools/check_web_layout.py`：依赖方向、路由表唯一性、单文件行数、handler 签名检查；
- `tests/test_web_layout.py`：把约束写成单测，CI 强制。

## 4. 静态路由表方案（替换 P2/M3/M4）

### 4.1 Route 数据结构

`routing.py` 定义不可变路由条目，把“路径 / 方法 / 是否鉴权 / 错误模式 / 缓存策略”
收拢到**唯一来源**，消灭散落的魔法字符串：

```python
# hornwork/web/routing.py
from dataclasses import dataclass
from typing import Callable

# 错误模式三态：与前端 client.ts 的三态契约一一对应
C7 = "c7"            # 异常 → 非 2xx + C7 JSON（默认）
SOFT = "soft"        # 异常 → 200 + {"items": [], "error": ...}（扫描类接口）
AUTH_STATE = "auth"  # 认证状态机：异常/拒绝仍返回完整 body，不强制 C7

@dataclass(frozen=True)
class Route:
    path: str
    methods: frozenset[str]
    handler: Callable          # handler(ctx: WebContext, query: dict) -> object
    auth: bool = True          # False = 免 token（静态页/healthz/auth 入口）
    error_mode: str = C7
    cache_ttl: float = 0.0     # >0 表示响应参与 TTL 缓存

    def allows(self, method: str) -> bool:
        return method in self.methods
```

### 4.2 注册表构建（启动时一次）

`get_routes()` 由各域模块的 `all_routes()` 汇总，`transport._Handler` 启动时取一次快照：

```python
# hornwork/web/routing.py
def build_router(ctx: WebContext) -> dict[str, Route]:
    router: dict[str, Route] = {}
    for module in (
        auth, overview, events, alerts, rules, intel, cases,
        validate, export, metrics, integration, harden, lab, scan, report,
    ):
        for route in module.all_routes():
            if route.path in router:
                raise RuntimeError(f"重复注册路由：{route.path}")
            router[route.path] = route
    return router
```

- 静态页/healthz/favicon 也注册进表（`auth=False`），消除 `_dispatch` 里的 if 链；
- 405 的处理统一为“路径存在但方法不允许”：查表后 `route.allows(method)` 判断；
- **扫路由不再用 `getattr` 隐式挂载**：模块存在即注册，模块缺失是明确的部署错误，
  在 `build_router()` 阶段暴露，而不是运行时静默 404（修 M3）。

### 4.3 分派器（传输层瘦化）

```python
# hornwork/web/transport.py
def _dispatch(self, method: str) -> None:
    parsed = urlparse(self.path)
    path = parsed.path or "/"
    query = _query_dict(parsed.query)
    route = self.app.router.get(path)

    if route is None:
        raise HttpError(404, f"未知路由：{path}")
    if not route.allows(method):
        raise HttpError(405, f"{path} 只支持 {'/'.join(sorted(route.methods))}")

    if route.auth and not self._authorized():
        raise HttpError(401, "未授权：缺少或错误的 Bearer token")

    payload = self.app.cache.get(route, query)          # TTL 缓存命中直接返回
    if payload is None:
        payload = route.handler(self.app.context, query)
        self.app.cache.put(route, query, payload)
    self._send_json(200, payload)
```

异常统一在 `_handle` 出口按 `route.error_mode` 转换（见第 5 节）。

## 5. 统一错误处理（保三态、消样板）

### 5.1 出口集中转换

```python
# hornwork/web/transport.py
def _handle(self, method: str) -> None:
    self._sent = False
    self.app.note_request()
    route = None
    try:
        self._dispatch(method)
    except HttpError as exc:
        self._send_error(route, exc.status, exc.payload)
    except Exception as exc:
        self.app.note_error()
        log.exception("web 请求处理异常", path=self.path, error=str(exc))
        self._send_error(route, 500, _error_payload(500, "服务内部错误", True, exc))

def _send_error(self, route, status, payload):
    mode = route.error_mode if route else C7
    if mode == SOFT:
        # 扫描类接口：保持前端 softErrorOf 依赖的 200 + error 契约
        self._send_json(200, {"items": [], "total": 0, "error": payload["message"]})
    elif mode == AUTH_STATE:
        # 认证类接口：保留状态机 body（client.ts 依赖 401 原文）
        self._send_json(status, payload.get("body") or payload)
    else:
        self._send_json(status, payload)
```

### 5.2 handler 变纯：只返回数据，不自己发送

现状 handler 内部 `self._send_json(...)` 与 `try/except → 200+error` 混杂（M2/M5）。
重构后统一签名 `handler(ctx, query) -> dict`，**不发送响应、不吞异常**：

```python
# hornwork/web/api/scan.py —— 8 个代理共用一套骨架
def _proxy(name, call):
    def handler(ctx, query):
        try:
            return call(ctx.store)
        except Exception as exc:
            log.warn(f"scan.{name} 查询失败", error=str(exc))   # 不再静默
            raise                                              # 交给出口按 SOFT 处理
    return handler

def all_routes():
    return [
        Route("/api/scan/overview", GET, _proxy("overview", lambda s: scan_api.overview(s)),
              error_mode=SOFT, cache_ttl=2.0),
        # ... 其余 7 条同构，不再逐字复制 try/except
    ]
```

收益：错误模式由路由表一处声明；handler 可直接单测（传 ctx/query，断言返回 dict），
不必起 HTTP server。

## 6. 性能改造清单

### 6.1 P1 连接复用（收益最大，改动最小）

- 删除 `_send` 里的 `send_header("Connection", "close")` 与 `self.close_connection = True`；
- 保留 `protocol_version = "HTTP/1.1"` 与已设置的 `Content-Length`；
- `_read_json` 已按 `Content-Length` 精确读取请求体，不会污染下个请求，keep-alive 安全；
- **配套防线程膨胀**（应对 P8）：给 `_ThreadingServer` 设置 `timeout = 30`（秒），
  空闲连接到时自动关闭；并在 `WebServer` 里保留并发上限的开关（默认不限制，
  云环境可配置），避免慢请求把线程打满。

### 6.2 P5/P6/P10 缓存层（`context.py` 内的轻量 TTL 缓存）

```python
# hornwork/web/context.py
class TtlCache:
    def __init__(self):
        self._data: dict[tuple, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, route, query):
        if route.cache_ttl <= 0:
            return None
        key = (route.path, tuple(sorted(query.items())), route.handler)
        with self._lock:
            hit = self._data.get(key)
            if hit and time.monotonic() - hit[0] < route.cache_ttl:
                return hit[1]
        return None

    def put(self, route, query, payload):
        if route.cache_ttl <= 0:
            return
        key = (route.path, tuple(sorted(query.items())), route.handler)
        with self._lock:
            self._data[key] = (time.monotonic(), payload)
```

按接口设定 TTL（数据新鲜度 vs 负载的平衡）：

| 接口 | TTL | 理由 |
|---|---|---|
| `/metrics`、integration/status、platform/security | 5–10s | 诊断/监控数据，被高频抓取；阻塞探测必须缓存 |
| overview、engine-stats | 2s | 前端有轮询（`usePolling`），2s 内数据足够新鲜 |
| `/api/rules`（目录扫描 P10） | 10s | 规则目录极少变动；POST reload 时主动失效 |
| assets（P6） | 永久（按 mtime 失效） | 哈希文件名不可变，可常驻内存 |

- `request_reload()` 时主动清 `/api/rules` 缓存键，保证热加载标记立即生效；
- 缓存只用于**只读 GET**；所有 POST 与 auth 接口一律不缓存。

### 6.3 P3/P4 重型诊断接口专项

- `_h_integration_status`（P3）：把 18 条 `COUNT(*)` 合并为**一次**带子查询的 SQL
  （`SELECT (SELECT COUNT(*) FROM event) AS events, ... FROM (SELECT 1)`），
  连同 meta/latest/审计链结果一起纳入 10s TTL 缓存；
- `_h_platform_security`（P4）：
  - TLS 探测与两次 systemctl **并发执行**（`concurrent.futures.ThreadPoolExecutor`，
    超时 3s），总耗时从约 13s 降到约 3s；
  - 硬编码项（端口 8443、主机名、目录、`hornwork.service`、报告根 `/opt/hornwork/reports`）
    改走 `cfg_get`（修 M6），保留默认值兼容；
  - 结果 10s TTL 缓存；探测失败写 debug 日志而非静默（修 M5）。

### 6.4 P7 auth engine 竞态与每请求查询

- auth engine 构造纳入 `WebContext` 的**双检锁**（`with ctx.lock` 二次判空再构造），
  消除多线程重复构造；
- 会话型请求的 `session_info` 查询：加一个**短 TTL（如 5s）的 session 校验缓存**
  （key 为 session token 的哈希，value 为是否有效），降低每请求 DB 查询；
  token 一旦 logout 或过期，由 `logout()` 主动清缓存，避免缓存了已吊销会话。

### 6.5 P9/P11 杂项快赢

- 函数内的 `os`/`time` 重复导入删除，可选依赖（auth/scan/intel/respond 等）保留函数内惰性导入
  （避免循环依赖与缺依赖时全站不可用，与 CLI 重构一致）；
- `scan_store.init_schema()` 从 4 个请求路径移到 `WebServer.start()` 一次性调用
  （用 try/except 容忍模块未就绪），请求热路径不再做 DDL。

## 7. 依赖方向

```text
server.py (入口, ≤180 行)
   │  装配 WebContext + build_router + HTTP server，只依赖 context/routing/transport
   ▼
transport.py ──► routing.py ──► context.py ──► errors.py
   │                                │
   │ 分派                            │ 提供 cfg/store/统计/缓存/auth engine
   ▼                                ▼
api/*.py (业务 handler) ──► hornwork.{store,config,schema,auth,scan,...}（函数内惰性导入）
   │
   ▼
static_files.py / auth.py（被 transport 调用的横切设施）
```

三条禁令：
1. `api/*` 之间零互相 import；
2. `api/*` 不 import `transport`（不碰响应发送），只依赖 `context` 与 `errors`；
3. 入口 `server.py` 不含任何业务查询逻辑。

## 8. 分阶段迁移顺序（低风险优先，每步可独立验证/回滚）

| 步骤 | 内容 | 风险 | 验证手段 |
|---|---|---|---|
| 0 | 建立基线：`tests/test_verify_web.py` 全绿；记录全部路由→状态码→响应结构快照 | 无（只读） | 快照落盘 |
| 1 | 抽 `errors.py`（HttpError/C7/error_mode）、`context.py`（WebContext/TtlCache），server.py 只改引用 | 极低 | 单测全绿，行为 diff 为 0 |
| 2 | **性能快赢**：P1 连接复用 + timeout、P9 重复 import、P7 auth 双检锁，不动路由结构 | 低 | 单测 + keep-alive 手工验证（同一连接两次请求） |
| 3 | 建 `routing.py` 静态表 + `transport.py`，把现有 handler 挂到 Route（`auth`/`error_mode` 三态就位），行为逐步对齐 | 中 | 路由快照 diff 为 0；三态错误契约用例 |
| 4 | 抽 `static_files.py` + assets 内存缓存（P6），路径穿越防护测试保持 | 低 | 静态资源与穿越防护用例 |
| 5 | 按域迁移只读 handler：overview/events/alerts/intel/cases/validate/export/metrics | 中 | 每域迁移后跑对应单测 |
| 6 | 迁移规则域（rules + 目录扫描缓存 P10），接 reload 缓存失效 | 中 | reload 标记用例 + 缓存失效用例 |
| 7 | 迁移 auth 域（保留状态机 401 契约），session 校验缓存（P7） | 中 | e2e 登录/session + 401 跳转用例 |
| 8 | 迁移扫描域（8 个代理统一 SOFT 骨架，init_schema 移到 start，P11） | 中 | `softErrorOf` 契约用例 + 扫描接口快照 |
| 9 | 迁移重型诊断（integration/platform，P3/P4：合并 SQL + 并发探测 + 走配置） | 中高 |TTL 命中用例 + 硬编码项可配置用例 |
| 10 | 重写 `server.py` 为 ≤180 行入口，删除旧 `_Handler` | 中 | 全量回归 |
| 11 | 加 `tools/check_web_layout.py` + `tests/test_web_layout.py` 锁结构 | 无 | CI 全绿 |

**为什么这个顺序**：步骤 1–2 先把公共层与零风险性能收益落地（此时路由结构未变，回滚范围极小）；
步骤 3 建立新的分派骨架但保持行为；步骤 5–9 是把 handler 机械搬运到各域，一次一个域；
入口最后重写（步骤 10），结构约束最后锁定（步骤 11）。任何一步出问题，回滚范围都只有当前一步。

## 9. 回归测试清单

### 9.1 必须保持通过的既有测试（行为基线）
- `tests/test_verify_web.py::WebServerTestCase` 全部 9 个用例：
  healthz/overview/events/alerts/metrics/静态页、规则 reload 标记、401 C7 结构、
  engine-stats/intel/cases/export(jsonl+md)/validate、stop 释放端口、
  Vue 产物与 assets MIME/缓存、路径穿越防护。
- e2e：`frontend/tests/e2e/cdp_e2e.py` 登录 → session → 清 token 跳登录流程。
- 前端单测：`frontend/tests/api.spec.ts`（ApiError/C7、softErrorOf 三态）。

### 9.2 新增测试（本轮重构引入）
1. **架构自检**（`tests/test_web_layout.py`）：依赖方向、路由表唯一性、单文件 ≤250 行、
   入口 ≤180 行、所有 handler 签名一致。
2. **静态表测试**：`build_router()` 路由数 == 预期；重复注册抛错；405 方法判断正确；
   不再有 `getattr` 式隐式挂载。
3. **错误三态测试**：同一异常在 C7 模式返回非 2xx + C7；SOFT 模式返回 200 + error；
   AUTH_STATE 模式返回状态机 body —— 锁定前端三态契约不被破坏。
4. **缓存测试**：TTL 内命中（store 查询计数不增加）；过期后刷新；
   `request_reload()` 后 rules 缓存失效；logout 后 session 缓存失效。
5. **连接复用测试**：同一 TCP 连接连续两次请求成功（验证 keep-alive），
   空闲连接 timeout 后关闭（验证不泄漏线程）。
6. **诊断接口测试**：integration 的 SQL 合并后计数与合并前一致；
   platform 探测并发总耗时显著低于串行；硬编码项可按 cfg 覆盖。

### 9.3 本轮难以自动覆盖、需部署环境补测
- 真实 TLS 反代（nginx 8443）探测与 systemctl 沙箱字段（Windows 开发机必然走异常分支）；
- 高频 Prometheus 抓取下的缓存命中率与线程数稳定（需稳定运行 daemon 观察）。

## 10. 风险与兼容

| 风险 | 缓解 |
|---|---|
| 错误处理收敛时误伤前端三态契约 | 第 5 节按 `error_mode` 分派；9.2-3 用例锁定；前端 `api.spec.ts` 保持 |
| keep-alive 导致线程 prolonged 占用 | 配套 `timeout=30` 与可选并发上限（6.1）；压测观察线程数 |
| TTL 缓存让数据陈旧 | 只缓存只读接口且 TTL ≤10s；写操作与 reload/logout 主动失效 |
| 拆分中循环导入 | 与 CLI 重构一致：handler 顶层只 import context/errors/标准库，业务子系统函数内惰性导入 |
| 扫描模块并行开发冲突 | 静态表显式注册（步骤 3/8），缺失模块在启动时明确报错，不再静默 404 |
| 会话缓存缓存了已吊销会话 | logout 主动清缓存 + TTL ≤5s 兜底 |

**公开接口不变承诺**：`hornwork.web.WebServer` 的构造与五个公开方法签名、
`__all__ = ["WebServer"]`、全部路由路径与响应结构、`docs/CONTRACT.md` §7 与
`docs/interfaces.md` 约定，均在重构后保持；`renderer`/前端无需改动。

## 11. 待确认事项

1. 是否接受 `/metrics` 与诊断接口引入 **5–10s TTL 缓存**（数据最多延迟 10s）？
2. keep-alive 是否设置 `timeout=30` 与并发上限（默认开放，云环境可配）？
3. 步骤顺序是否按第 8 节执行，还是希望先只做步骤 1–2（公共层 + 性能快赢）验证效果后再继续？

## 12. 实施结果（Ubuntu 26.04 / Python 3.14.4 实机验证）

### 12.1 已落地内容

| 步骤 | 内容 | 状态 |
|---|---|---|
| 1 | 抽公共层 `errors.py`（HttpError/C7/error_mode 三态）、`context.py`（WebContext/TtlCache） | 完成 |
| 2 | keep-alive（GET/HEAD 复用）+ `_Handler.setup()` 设 TCP_NODELAY + `_ThreadingServer.timeout=30`；auth engine 双检锁 | 完成 |
| 3 | `routing.py` 静态路由表（44 条，启动构建一次）+ `transport` 查表分派；扫描 8 条显式注册 | 完成 |
| 4–8 | 按域拆分：`api/` 下 14 个 mixin（auth/integration/events/harden/report/lab/scan/overview/rules/intel/cases/validate/export/metrics），`_Handler` 多继承装配；方法体原样搬迁 | 完成 |
| 11 | `tests/test_web_layout.py` 架构自检（21 项） | 完成 |

公共工具另抽 `common.py`（iso_now/query_dict/q_int/MIME 规则/log），供 server 与 mixin 共用，
避免反向依赖入口造成循环导入。

### 12.2 代码体量

| 指标 | 重构前 | 重构后 |
|---|---|---|
| `hornwork/web/server.py` | 1522 行 | **530 行**（-65%） |
| 业务 handler 文件数 | 1 | **14**（`api/*.py`，单文件最大 137 行） |
| 单类职责 | `_Handler` 约 1250 行 | 传输层 ~380 行 + 14 个域 mixin |

### 12.3 性能实测（300 次 GET /healthz，复用连接）

| 版本 | 吞吐 | 平均延迟 |
|---|---|---|
| 原始（每请求 `Connection: close`） | 671 req/s | 1.49 ms |
| 仅 keep-alive（未设 TCP_NODELAY） | 24 req/s | 40.9 ms（Nagle + delayed-ACK 陷阱） |
| keep-alive + TCP_NODELAY | 1955 req/s | 0.51 ms |
| + 静态路由表 | 2099 req/s | 0.48 ms |
| + 按域拆分 mixin（最终） | 1844 req/s | 0.54 ms |

**净收益约 2.7×**（671 → 1844 req/s）。关键教训：keep-alive 必须与 TCP_NODELAY 同时启用，
否则响应头/体分两次写会触发 40ms delayed-ACK，反而比短连接慢 28 倍。

### 12.4 测试结论

- Web 专项：`tests/test_verify_web.py` + `tests/test_web_layout.py` = **60 passed**（38 原有 + 22 新增）。
- 全项目：`596 passed, 3 skipped`（另有 573 subtests）。
- 唯一失败 `tests/test_auth.py::EngineLoginTest::test_session_step_up_and_action_guard`
  经**完全还原原始代码后仍稳定失败**，属生物识别策略既有的环境问题，与本次重构无关。

### 12.5 未实施（保留为后续可选优化）

- 设计文档第 6.2/6.3 节的 TTL 缓存（`/metrics`、integration、platform 的 5–10s 缓存）、
  platform 探测并发化（3s+5s+5s → 3s）、integration 的 18 条 COUNT 合并为单条 SQL：
  这些属于「新的性能热点优化」，与已完成的「全站性开销消除」正交，可在确认数据新鲜度要求后再做。
- `error_mode` 三态的统一出口收敛：现状扫描类接口的 200+error、C7、认证状态机三态
  已在 `errors.py` 定义常量，但 handler 出口尚未统一改造（行为已保持，风险低）。
