/** 业务枚举选项：下拉框与图表共用，集中一处避免各页面写死文案。 */

import type { Severity } from '@/types/scan';

export interface Option {
  label: string;
  value: string;
}

export const SEVERITY_OPTIONS: { label: string; value: Severity }[] = [
  { label: '严重', value: '严重' },
  { label: '高', value: '高' },
  { label: '中', value: '中' },
  { label: '低', value: '低' },
  { label: '无', value: '无' },
];

export const FINDING_KIND_OPTIONS: Option[] = [
  { label: '端口服务（事实）', value: 'port' },
  { label: '应用组件（事实）', value: 'component' },
  { label: 'CVE（问题）', value: 'cve' },
  { label: '配置基线（问题）', value: 'config' },
  { label: 'TLS（问题）', value: 'tls' },
  { label: 'Web PoC（问题）', value: 'web' },
];

export const FINDING_STATUS_OPTIONS: Option[] = [
  { label: '新增', value: 'new' },
  { label: '已观测', value: 'observed' },
  { label: '已确认', value: 'confirmed' },
  { label: '误报', value: 'false_positive' },
  { label: '已修复', value: 'fixed' },
  { label: '重新打开', value: 'reopened' },
];

export const TASK_STATUS_OPTIONS: Option[] = [
  { label: '排队中', value: 'queued' },
  { label: '运行中', value: 'running' },
  { label: '已完成', value: 'done' },
  { label: '部分完成', value: 'partial' },
  { label: '失败', value: 'failed' },
  { label: '已中断', value: 'aborted' },
];

export const CASE_STATUS_OPTIONS: Option[] = [
  { label: '打开', value: 'open' },
  { label: '调查中', value: 'investigating' },
  { label: '已遏制', value: 'contained' },
  { label: '已关闭', value: 'closed' },
];

export const CASE_SEVERITY_OPTIONS: Option[] = [
  { label: 'P1（最高）', value: 'P1' },
  { label: 'P2', value: 'P2' },
  { label: 'P3', value: 'P3' },
];

export const VERDICT_OPTIONS: Option[] = [
  { label: '真阳 TP', value: 'tp' },
  { label: '假阳 FP', value: 'fp' },
  { label: '无害 benign', value: 'benign' },
  { label: '未知 unknown', value: 'unknown' },
];

export const IOC_TYPE_OPTIONS: Option[] = [
  { label: 'IP', value: 'ip' },
  { label: '域名', value: 'domain' },
  { label: 'URL', value: 'url' },
  { label: '哈希', value: 'hash' },
  { label: '文件名', value: 'filename' },
];

export const IOC_STATUS_OPTIONS: Option[] = [
  { label: '候选', value: 'candidate' },
  { label: '生效', value: 'active' },
  { label: '老化', value: 'aging' },
  { label: '已过期', value: 'expired' },
];

export const SOURCE_LAYER_OPTIONS: Option[] = [
  { label: 'host（主机）', value: 'host' },
  { label: 'net（网络）', value: 'net' },
  { label: 'memory（内存）', value: 'memory' },
  { label: 'static（静态）', value: 'static' },
  { label: 'scan（扫描）', value: 'scan' },
];

/** 时间范围：`since` 直接透传给后端（`store.parse_since` 支持 `24h` / `7d` 等写法）。 */
export const SINCE_OPTIONS: Option[] = [
  { label: '最近 1 小时', value: '1h' },
  { label: '最近 24 小时', value: '24h' },
  { label: '最近 7 天', value: '7d' },
  { label: '最近 30 天', value: '30d' },
];

/** 告警级别下限（1–15）。 */
export const LEVEL_OPTIONS: Option[] = [
  { label: 'L3 及以上', value: '3' },
  { label: 'L6 及以上（中）', value: '6' },
  { label: 'L9 及以上（高）', value: '9' },
  { label: 'L12 及以上（严重）', value: '12' },
];
