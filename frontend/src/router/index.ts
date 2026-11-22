/**
 * 路由表。
 *
 * 使用 hash 历史：后端没有通用 SPA fallback（见 docs/frontend-vue-architecture.md §5.5），
 * hash 让浏览器只请求根文档，部署时无需任何额外改造；产物同时被后端静态路由托管，
 * 未来切 history 只需补齐 fallback 并替换 `createWebHashHistory`。
 */

import { createRouter, createWebHashHistory } from 'vue-router';

import { onUnauthorized } from '@/api/client';
import { useAuthStore } from '@/stores/auth';
import AppLayout from '@/components/layout/AppLayout.vue';

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
      meta: { public: true, title: '登录' },
    },
    {
      path: '/',
      component: AppLayout,
      redirect: '/overview',
      children: [
        {
          path: 'overview',
          name: 'overview',
          component: () => import('@/views/OverviewView.vue'),
          meta: { title: '总览' },
        },
        {
          path: 'detection',
          redirect: '/detection/events',
          children: [
            {
              path: 'events',
              name: 'detection-events',
              component: () => import('@/views/detection/EventsView.vue'),
              meta: { title: '事件流' },
            },
            {
              path: 'alerts',
              name: 'detection-alerts',
              component: () => import('@/views/detection/AlertsView.vue'),
              meta: { title: '告警' },
            },
            {
              path: 'rules',
              name: 'detection-rules',
              component: () => import('@/views/detection/RulesView.vue'),
              meta: { title: '规则' },
            },
            {
              path: 'intel',
              name: 'detection-intel',
              component: () => import('@/views/detection/IntelView.vue'),
              meta: { title: '情报' },
            },
            {
              path: 'cases',
              name: 'detection-cases',
              component: () => import('@/views/detection/CasesView.vue'),
              meta: { title: '工单' },
            },
            {
              path: 'validation',
              name: 'detection-validation',
              component: () => import('@/views/detection/ValidationView.vue'),
              meta: { title: '验证' },
            },
            {
              path: 'engines',
              name: 'detection-engines',
              component: () => import('@/views/detection/EnginesView.vue'),
              meta: { title: '引擎贡献' },
            },
          ],
        },
        {
          path: 'vuln',
          name: 'vuln',
          component: () => import('@/views/VulnView.vue'),
          meta: { title: '漏洞档案' },
        },
        {
          path: 'scan',
          redirect: '/scan/overview',
          children: [
            {
              path: 'overview',
              name: 'scan-overview',
              component: () => import('@/views/scan/ScanOverviewView.vue'),
              meta: { title: '扫描总览' },
            },
            {
              path: 'findings',
              name: 'scan-findings',
              component: () => import('@/views/scan/FindingsView.vue'),
              meta: { title: '问题清单' },
            },
            {
              path: 'diff',
              name: 'scan-diff',
              component: () => import('@/views/scan/DiffView.vue'),
              meta: { title: '快照对比' },
            },
            {
              path: 'coverage',
              name: 'scan-coverage',
              component: () => import('@/views/scan/CoverageView.vue'),
              meta: { title: '覆盖率' },
            },
            {
              path: 'cve',
              name: 'scan-cve',
              component: () => import('@/views/scan/CveView.vue'),
              meta: { title: 'CVE 库' },
            },
            {
              path: 'reports',
              name: 'scan-reports',
              component: () => import('@/views/scan/ReportsView.vue'),
              meta: { title: '报告' },
            },
          ],
        },
        {
          path: 'auth',
          name: 'auth',
          component: () => import('@/views/AuthView.vue'),
          meta: { title: '身份认证' },
        },
        {
          path: 'harden',
          name: 'harden',
          component: () => import('@/views/HardenView.vue'),
          meta: { title: '安全加固' },
        },
        {
          path: 'security',
          name: 'security',
          component: () => import('@/views/SecurityView.vue'),
          meta: { title: '平台安全' },
        },
      ],
    },
    // 未知路径统一回总览，避免刷新旧 URL 后白屏
    { path: '/:pathMatch(.*)*', redirect: '/overview' },
  ],
});

router.beforeEach(async (to) => {
  const auth = useAuthStore();
  if (to.meta.public) return true;

  if (!auth.session) {
    return { name: 'login', query: to.fullPath === '/' ? {} : { redirect: to.fullPath } };
  }
  // 首次进入或刷新后补齐身份信息（LOA 展示依赖它）
  if (!auth.info) await auth.refresh();
  return true;
});

// 会话在运行期失效（401）时，统一回到登录页并保留来源路径
onUnauthorized(() => {
  const current = router.currentRoute.value;
  if (current.name === 'login') return;
  void router.replace({ name: 'login', query: { redirect: current.fullPath } });
});
