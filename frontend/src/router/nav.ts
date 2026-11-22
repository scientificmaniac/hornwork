/** 导航配置：侧边栏与路由共用同一份声明，避免两处维护两份菜单。 */

import type { RouteRecordRaw } from 'vue-router';

export interface NavItem {
  path: string;
  title: string;
  /** 侧栏分组标题（一级域）。 */
  children?: NavItem[];
}

/** 一级域的结构（不含组件），供侧栏渲染；路由表据此生成。 */
export const NAV: NavItem[] = [
  { path: '/overview', title: '总览' },
  {
    path: '/detection',
    title: '检测',
    children: [
      { path: '/detection/events', title: '事件流' },
      { path: '/detection/alerts', title: '告警' },
      { path: '/detection/rules', title: '规则' },
      { path: '/detection/intel', title: '情报' },
      { path: '/detection/cases', title: '工单' },
      { path: '/detection/validation', title: '验证' },
      { path: '/detection/engines', title: '引擎贡献' },
    ],
  },
  { path: '/vuln', title: '漏洞档案' },
  {
    path: '/scan',
    title: '定期扫描',
    children: [
      { path: '/scan/overview', title: '扫描总览' },
      { path: '/scan/findings', title: '问题清单' },
      { path: '/scan/diff', title: '快照对比' },
      { path: '/scan/coverage', title: '覆盖率' },
      { path: '/scan/cve', title: 'CVE 库' },
      { path: '/scan/reports', title: '报告' },
    ],
  },
  { path: '/auth', title: '身份认证' },
  { path: '/harden', title: '安全加固' },
  { path: '/security', title: '平台安全' },
];

/** 扁平化：路径 → 标题，供顶栏标题与面包屑使用。 */
export const NAV_TITLES: Record<string, string> = (() => {
  const map: Record<string, string> = {};
  for (const item of NAV) {
    map[item.path] = item.title;
    for (const child of item.children ?? []) map[child.path] = child.title;
  }
  return map;
})();

export type AppRoute = RouteRecordRaw;
