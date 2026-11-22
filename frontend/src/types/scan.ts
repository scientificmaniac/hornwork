/** 定期扫描域类型：资产、计划、任务、finding、快照、diff、覆盖率、CVE、报告。 */

export type Severity = '严重' | '高' | '中' | '低' | '无';

export const SEVERITIES: Severity[] = ['严重', '高', '中', '低', '无'];

export const FINDING_KINDS = ['port', 'component', 'cve', 'config', 'tls', 'web'] as const;

export const FINDING_STATUSES = [
  'new',
  'observed',
  'confirmed',
  'false_positive',
  'fixed',
  'reopened',
] as const;

export interface ScanCounts {
  asset: number;
  plan: number;
  task: number;
  snapshot: number;
  finding: number;
  cve: number;
}

export interface ScanOverview {
  counts: ScanCounts;
  tasks: { total: number; by_status: Record<string, number> };
  findings: {
    total: number;
    by_status: Record<string, number>;
    by_kind: Record<string, number>;
  };
  cve: { total: number };
  recent_tasks: ScanTask[];
  last_task: ScanTask | null;
  last_snapshot: Snapshot | null;
  error?: string;
}

export interface ScanPlan {
  plan_id: string;
  name?: string | null;
  kind?: string | null;
  profile?: string | null;
  selector?: Record<string, unknown>;
  engines?: unknown;
  window_start?: string | null;
  window_end?: string | null;
  rate_limit?: number | null;
  max_hosts?: number | null;
  enabled: boolean;
  last_run?: string | null;
  next_run?: string | null;
  created_at?: string | null;
}

export interface ScanTask {
  task_id: string;
  run_id?: string | null;
  plan_id?: string | null;
  asset_id?: string | null;
  status: string;
  stage?: string | null;
  progress?: number | null;
  snapshot_id?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  cost_ms?: number | null;
  error?: string | null;
  checkpoint?: Record<string, unknown>;
  asset_ip?: string | null;
  asset_hostname?: string | null;
}

export interface Finding {
  finding_id: string;
  task_id?: string | null;
  asset_id?: string | null;
  asset_ip?: string | null;
  asset_hostname?: string | null;
  snapshot_id?: string | null;
  kind?: string | null;
  check_id?: string | null;
  title?: string | null;
  severity?: string | null;
  cvss?: number | null;
  cvss_source?: string | null;
  confidence?: number | null;
  status?: string | null;
  target?: string | null;
  evidence?: Record<string, unknown>;
  vuln_ref?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface Snapshot {
  snapshot_id: string;
  plan_id?: string | null;
  run_id?: string | null;
  ts?: string | null;
  kind?: string | null;
  label?: string | null;
  is_base?: boolean;
  task_count?: number | null;
  finding_count?: number | null;
  stats?: Record<string, number>;
}

export type DeltaState = 'new' | 'fixed' | 'persisting' | 'regressed';

export interface DiffItem {
  finding_key: string;
  asset_id: string;
  kind?: string | null;
  check_id?: string | null;
  severity?: string | null;
  cvss?: number | null;
  title?: string | null;
  target?: string | null;
  prev_status?: string | null;
  cur_status?: string | null;
  delta: DeltaState;
}

export interface DiffStats {
  new: number;
  fixed: number;
  persisting: number;
  regressed: number;
  total: number;
}

export interface DiffPayload {
  cur?: string | null;
  prev?: string | null;
  ts?: string;
  items: DiffItem[];
  stats: Partial<DiffStats>;
  by_severity?: Record<string, Partial<DiffStats>>;
  error?: string;
}

export interface CoverageDomain {
  name: string;
  weight: number;
  applicable: number;
  done: number;
  partial: number;
  missing: number;
  avg: number;
}

export interface CoverageAssetRow {
  asset_id: string;
  ip?: string | null;
  hostname?: string | null;
  role?: string | null;
  domains: Record<string, number>;
  score: number;
  notes?: Record<string, string>;
  status?: string | null;
}

export interface CoverageUncovered {
  asset_id: string;
  ip?: string | null;
  domain: string;
  name: string;
  reason: string;
  status?: string;
  covered: number;
}

export interface CoveragePayload {
  snapshot_id?: string;
  ts?: string;
  assets?: number;
  coverage: number;
  by_domain: Record<string, CoverageDomain>;
  matrix: CoverageAssetRow[];
  uncovered: CoverageUncovered[];
  weights?: Record<string, number>;
  error?: string;
}

export interface CveStats {
  total: number;
  by_severity: Record<string, number>;
  by_source: Record<string, number>;
  by_year: Record<string, number>;
  last_modified?: string | null;
  oval_fixes?: number;
  component_map?: number;
  error?: string;
}

export interface ReportItem {
  name: string;
  rel: string;
  size: number;
  mtime: string;
}

export interface VulnRecord {
  id: string;
  cve?: string | null;
  title?: string | null;
  component?: string | null;
  cwe?: string | null;
  cvss_vector?: string | null;
  cvss_score?: number | null;
  severity?: string | null;
  kind?: string | null;
  status?: string | null;
  yaml_path?: string | null;
  updated_at?: string | null;
}

export interface LabEnv {
  env_id: string;
  state?: string | null;
  running?: number | boolean | null;
  ports?: unknown;
  host_ports?: unknown;
  expires_at?: string | null;
  target?: string | null;
  cve?: string | null;
  profile?: string | null;
}

export interface LabRun {
  run_id: string;
  env_id?: string | null;
  action?: string | null;
  result?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  elapsed_ms?: number | null;
  detail?: string | null;
}

export interface LabPayload {
  envs: LabEnv[];
  runs: LabRun[];
}
