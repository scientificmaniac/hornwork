/** 加固域与平台安全域类型（数据全部来自文件状态与 systemd 实测）。 */

export interface BaselineItem {
  id: string;
  category?: string | null;
  title?: string | null;
  risk?: string | null;
  scope_A?: boolean;
}

export interface HardenPlan {
  plan_id?: string | null;
  role?: string | null;
  asset?: string | null;
  items?: number;
  /** 后端读的是 `created_at`，实际字段是 `generated_at`，展示时兜底。 */
  created_at?: string | null;
  generated_at?: string | null;
}

export interface HardenRun {
  run_id?: string | null;
  plan_id?: string | null;
  mode?: string | null;
  status?: string | null;
  started_at?: string | null;
  counts?: Record<string, number>;
  items?: number;
}

export interface HardenReport {
  name: string;
  size: number;
}

export interface HardenStatus {
  ts: string;
  items: BaselineItem[];
  plans: HardenPlan[];
  runs: HardenRun[];
  reports: HardenReport[];
}

export interface PlatformPathInfo {
  mode?: string;
  uid?: number;
  gid?: number;
  exists: boolean;
}

export interface PlatformSecurity {
  ts: string;
  https: { ok?: boolean; protocol?: string; cipher?: string; error?: string };
  lockout: Record<string, unknown>;
  paths: Record<string, PlatformPathInfo>;
  service: { unit?: string; user?: string; sandbox?: string[]; error?: string };
  bind?: {
    host?: string;
    port?: number;
    token_auth?: boolean;
    tls_ingress?: boolean;
  };
}
