# 前端工程（Hornwork 控制台）

Vue 3 + TypeScript + Vite 实现的 Hornwork 控制台，替换 `hornwork/web/static/platform.html`
与 `index.html` 两套原生 JS 单页。架构依据见 [`docs/frontend-vue-architecture.md`](../docs/frontend-vue-architecture.md)。

## 与后端的约定

- **路由用 hash**（`#/scan/findings`）：后端没有 SPA fallback 也能直接托管，浏览器只请求根文档。
- **构建产物放 `hornwork/web/static/app/`**：后端 `hornwork/web/server.py` 负责
  `GET /`（入口 HTML）与 `GET /assets/*`（哈希分块），产物缺失时自动回退旧版单页。
- **鉴权**：平台会话（`s1.` 前缀）存 `sessionStorage`，经 `Authorization: Bearer` 下发；
  `/api/auth/login|step-up|logout` 免 token。401 统一清会话并跳登录。
- **形状归一**：后端列表返回 `items` / `records` / `envs` / `runs` 多种形状，统一在
  `src/api/modules/*` 归一为 `{ items, total }`；扫描类接口的 `200 + error`
  降级约定由各模块提取为软错误，页面按提示条展示而不是当作空数据。

## 目录结构

```
src/
├── api/
│   ├── client.ts            # 唯一 axios 实例：token 注入、401 拦截、C7 → ApiError
│   └── modules/             # 按后端域拆分：auth / detection / scan / platform
├── components/
│   ├── base/                # StatCard、ToneBadge（语义徽章）
│   ├── charts/EChart.vue    # ECharts 按需注册 + 生命周期封装
│   └── layout/              # AppLayout / AppSidebar / AppHeader
├── composables/
│   ├── useAsync.ts          # 加载/失败/软降级四态，且丢弃过期并发响应
│   ├── usePolling.ts        # 可见性感知轮询，终态自停、卸载即清
│   └── useReport.ts         # 报告预览与导出（必须带 Authorization，走 blob）
├── router/                  # 路由表 + 登录守卫 + nav.ts 单一菜单来源
├── stores/                  # Pinia：auth（会话/LOA）、app（主题/侧栏）
├── styles/                  # tokens.css（两套主题变量）+ index.css（EP 变量桥接）
├── types/                   # 与后端 schema 一一对应的 TS 类型
├── utils/                   # format / badge / charts / options / embedding / browser
└── views/                   # 按域分目录，共 19 个页面
tests/                       # Vitest 单测；tests/e2e 为真实浏览器脚本
```

## 本地开发

```bash
npm install
npm run dev        # http://localhost:5173，/api 与 /healthz 代理到 127.0.0.1:8787
npm run typecheck
npm run lint
npm run test
```

后端地址可用 `HORNWORK_WEB=http://host:port npm run dev` 覆盖。

## 构建与集成

```bash
npm run build                       # 产物 dist/
cp -r dist/* ../hornwork/web/static/app/   # 或使用仓库根目录的 make frontend
```

产物约 2 MB（gzip 后 ~560 KB），由后端直接托管：`/` 返回 index.html（`no-cache`），
`/assets/*` 带内容哈希（`immutable` 长缓存）。重启服务即可生效；回退只需删除
`hornwork/web/static/app/`，后端会自动回到旧版 `platform.html`。

## 测试

### 单元测试（Vitest）

```bash
npm run test
```

覆盖纯逻辑：时间/数值格式化、徽章映射（严重级/状态/四态）、C7 错误解析、
人脸向量规范化、图表 option 构造。

### 端到端（真实浏览器）

`tests/e2e/cdp_e2e.py` 只用 Python 标准库：手写 WebSocket 实现 Chrome DevTools
Protocol 客户端，驱动真实 Chrome 完成登录、17 个路由渲染、主题切换、会话失效跳转，
并逐页截图。

```bash
# 1) 起后端（真实 SQLite + 会话鉴权）
python ../tools/serve_backend_e2e.py          # 打印 {"port": 18787, ...}

# 2) 建测试账号（首次）
hornworkctl --config /tmp/hw-test/config.toml auth db init
printf 'YourPassword\n' | hornworkctl --config /tmp/hw-test/config.toml \
    auth user add e2e-admin --admin --password-stdin

# 3) 跑 E2E（需要 google-chrome；截图输出到 /tmp/hw-e2e-shots）
python3 tests/e2e/cdp_e2e.py http://127.0.0.1:18787 e2e-admin 'YourPassword'
```

脚本对每个失败项打印 `[FAIL]` 并以非 0 退出，可直接接入 CI。
