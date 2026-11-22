/** 检测域类型：事件、告警、规则、情报、工单、验证、引擎贡献。 */

import type { ChainInfo } from './common';

/** 事件类型（20 个，与 `hornwork/schema.py::EVENT_TYPES` 一致）。 */
export const EVENT_TYPES = [
  'process_create',
  'process_exit',
  'file_create',
  'file_modify',
  'file_delete',
  'net_connect',
  'dns_query',
  'logon',
  'logon_fail',
  'account_create',
  'persist_item',
  'memory_scan',
  'scan_result',
  'alert',
  'net_flow',
  'lab_action',
  'vuln_finding',
  'scan_task',
  'scan_finding',
  'scan_window',
] as const;

/** 来源层。 */
export const SOURCE_LAYERS = ['host', 'net', 'memory', 'static', 'scan'] as const;

/**
 * 统一事件（CanonicalEvent）。
 *
 * 后端返回的是 payload 展开后的对象，字段随事件类型变化，
 * 因此只固化跨类型必有的字段，其余按未知处理（渲染时才取用）。
 */
export interface CanonicalEvent {
  event_id?: string;
  ts: string;
  event_type: string;
  source_layer?: string;
  host?: { host_id?: string; hostname?: string; os?: string };
  process?: { pid?: number; name?: string; cmdline?: string; exe?: string; ppid?: number };
  file?: { path?: string; sha256?: string; size?: number; mode?: string };
  network?: { src_ip?: string; dst_ip?: string; dst_port?: number; proto?: string; domain?: string };
  user?: { name?: string; id?: number | string; action?: string };
  raw?: Record<string, unknown>;
  _row?: { engine?: string | null; created_at?: string };
  [key: string]: unknown;
}

export interface Alert {
  alert_id?: string;
  ts: string;
  rule?: { id?: string; name?: string; version?: string; engine?: string };
  rule_id?: string;
  level?: number;
  technique?: string | null;
  confidence?: number;
  status?: string;
  dedup_key?: string;
  evidence?: Record<string, unknown>[];
  contrib?: unknown;
  intel?: unknown;
  host?: { host_id?: string };
  _row?: { alert_id?: string; engine?: string; level?: number; status?: string };
  [key: string]: unknown;
}

export interface RuleItem {
  source: string;
  id: string;
  name: string;
  path: string;
  size: number;
  mtime: string;
  level?: string | number | null;
  technique?: string | null;
  rule_count?: number | null;
  rules?: string[];
  event_types?: string[];
  description?: string;
  error?: string;
}

export interface RulesPayload {
  items: RuleItem[];
  sources: Record<string, string>;
  missing: string[];
  sigma: { total: number; supported: number; hits: number };
  reload: { requested_at?: string | null; count?: number; note?: string };
}

export interface IocRecord {
  ioc_id?: string;
  type: string;
  value: string;
  confidence?: number;
  tlp?: string;
  source?: string | null;
  status?: string;
  first_seen?: string | null;
  last_seen?: string | null;
  expires_at?: string | null;
  whitelisted?: number;
}

export interface IntelPayload {
  items: IocRecord[];
  by_type: Record<string, number>;
}

export interface CaseRecord {
  case_id: string;
  title?: string | null;
  severity?: string | null;
  status?: string | null;
  verdict?: string | null;
  dedup_key?: string | null;
  created_at?: string | null;
  closed_at?: string | null;
}

export interface CreateCaseRequest {
  title: string;
  severity?: string;
  verdict?: string;
  dedup_key?: string;
}

export interface ValidationRow {
  case_id: string;
  technique?: string | null;
  expected?: string | null;
  observed?: string | null;
  verdict?: string | null;
  mttd_sec?: number | null;
  name?: string | null;
  error?: string | null;
}

export interface ValidationMetrics {
  TP: number;
  TN: number;
  FP: number;
  FN: number;
  inconclusive: number;
  tpr?: number | null;
  fpr?: number | null;
  coverage?: number | null;
  mttd_sec?: number | null;
}

export interface ValidationPayload {
  run_id: string | null;
  rows: ValidationRow[];
  case_count?: number;
  metrics: ValidationMetrics | null;
  report_path?: string | null;
  md_path?: string | null;
}

export interface EngineStatRow {
  engine: string;
  day: string;
  files: number;
  hits: number;
  malicious: number;
  cost_ms: number;
  errors: number;
}

export interface ContributionRow {
  first_hit?: string | null;
  n: number;
}

export interface ScanResultRow {
  ts: string;
  path?: string;
  sha256?: string;
  verdict?: string;
  score?: number;
  first_hit?: string | null;
  cost_ms?: number;
  hits?: unknown[];
}

export interface EngineStatsPayload {
  days: number;
  engine_stats: EngineStatRow[];
  contribution: ContributionRow[];
  sigma: { total: number; supported: number; hits: number };
  recent_scans: ScanResultRow[];
}

/** 总览聚合：counts 为扁平计数，engine_stats 供趋势图。 */
export interface OverviewPayload {
  ts: string;
  counts: Record<string, number>;
  engine_stats: EngineStatRow[];
  sigma: { total: number; supported: number; hits: number };
  recent_scans: ScanResultRow[];
  validation: { run_id: string; case_count: number; metrics: ValidationMetrics } | null;
  web: WebStatus;
}

export interface WebStatus {
  enabled: boolean;
  bind: string;
  port: number;
  auth: boolean;
  running: boolean;
  url: string;
  requests?: number;
  errors?: number;
  uptime_sec?: number;
}

export interface IntegrationModule {
  [key: string]: unknown;
}

export interface IntegrationPayload {
  ts: string;
  host?: string | null;
  modules: {
    detection?: IntegrationModule;
    vuln?: IntegrationModule;
    scan?: IntegrationModule;
    auth?: { users?: number; sessions?: number; audit_rows?: number; chain?: ChainInfo };
    harden?: IntegrationModule;
  };
}
