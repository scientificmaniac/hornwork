/** 定期扫描 / 漏洞档案 / 靶场 API：`/api/scan/*`、`/api/vuln/*`、`/api/lab/*`、`/api/report`。 */

import { getBlob, getJson } from '@/api/client';
import type { ListPayload, QueryParams } from '@/types/common';
import type {
  CoveragePayload,
  CveStats,
  DiffPayload,
  Finding,
  LabPayload,
  ReportItem,
  ScanOverview,
  ScanPlan,
  ScanTask,
  Snapshot,
  VulnRecord,
} from '@/types/scan';

type RawList<T> = { items?: T[]; count?: number; total?: number; error?: string };

function toList<T>(data: RawList<T>): ListPayload<T> {
  const items = data.items ?? [];
  const total = Number(data.total ?? data.count ?? items.length);
  return data.error ? { items, total, error: String(data.error) } : { items, total };
}

/**
 * 扫描类接口的降级处理：后端在异常时返回 `200 + 空结构 + error`。
 * 这里把 `error` 提取成软错误随数据返回，页面据此展示降级条而不是白屏。
 */
export const scanApi = {
  async overview(): Promise<ScanOverview> {
    const data = await getJson<Partial<ScanOverview>>('/api/scan/overview');
    return {
      counts: data.counts ?? { asset: 0, plan: 0, task: 0, snapshot: 0, finding: 0, cve: 0 },
      tasks: data.tasks ?? { total: 0, by_status: {} },
      findings: data.findings ?? { total: 0, by_status: {}, by_kind: {} },
      cve: data.cve ?? { total: 0 },
      recent_tasks: data.recent_tasks ?? [],
      last_task: data.last_task ?? null,
      last_snapshot: data.last_snapshot ?? null,
      ...(data.error ? { error: data.error } : {}),
    };
  },

  async plans(): Promise<ListPayload<ScanPlan>> {
    return toList(await getJson<RawList<ScanPlan>>('/api/scan/plans'));
  },

  async tasks(params: QueryParams = {}): Promise<ListPayload<ScanTask>> {
    return toList(await getJson<RawList<ScanTask>>('/api/scan/tasks', params));
  },

  async findings(params: QueryParams = {}): Promise<ListPayload<Finding>> {
    return toList(await getJson<RawList<Finding>>('/api/scan/findings', params));
  },

  async snapshots(limit = 20): Promise<ListPayload<Snapshot>> {
    return toList(await getJson<RawList<Snapshot>>('/api/scan/snapshots', { limit }));
  },

  /** 注意后端语义：`from` 是本次（新）快照，`to` 是上次（旧）快照。 */
  async diff(from?: string, to?: string): Promise<DiffPayload> {
    const data = await getJson<Partial<DiffPayload>>('/api/scan/diff', { from, to });
    return {
      cur: data.cur ?? null,
      prev: data.prev ?? null,
      ts: data.ts,
      items: data.items ?? [],
      stats: data.stats ?? {},
      by_severity: data.by_severity ?? {},
      ...(data.error ? { error: data.error } : {}),
    };
  },

  async coverage(snapshot?: string): Promise<CoveragePayload> {
    const data = await getJson<Partial<CoveragePayload>>('/api/scan/coverage', { snapshot });
    return {
      snapshot_id: data.snapshot_id,
      ts: data.ts,
      assets: data.assets ?? 0,
      coverage: Number(data.coverage ?? 0),
      by_domain: data.by_domain ?? {},
      matrix: data.matrix ?? [],
      uncovered: data.uncovered ?? [],
      weights: data.weights,
      ...(data.error ? { error: data.error } : {}),
    };
  },

  async cve(): Promise<CveStats> {
    const data = await getJson<Partial<CveStats>>('/api/scan/cve');
    return {
      total: Number(data.total ?? 0),
      by_severity: data.by_severity ?? {},
      by_source: data.by_source ?? {},
      by_year: data.by_year ?? {},
      last_modified: data.last_modified ?? null,
      oval_fixes: data.oval_fixes ?? 0,
      component_map: data.component_map ?? 0,
      ...(data.error ? { error: data.error } : {}),
    };
  },

  async reports(): Promise<ReportItem[]> {
    const data = await getJson<{ items?: ReportItem[]; error?: string }>('/api/scan/reports');
    return data.items ?? [];
  },

  async vulnRecords(params: QueryParams = {}): Promise<VulnRecord[]> {
    const data = await getJson<{ records?: VulnRecord[] }>('/api/vuln/records', params);
    return data.records ?? [];
  },

  async labEnvs(limit = 20): Promise<LabPayload> {
    const data = await getJson<{ envs?: LabPayload['envs']; runs?: LabPayload['runs'] }>(
      '/api/lab/envs',
      { limit },
    );
    return { envs: data.envs ?? [], runs: data.runs ?? [] };
  },

  /**
   * 报告预览：`/api/report?file=<rel>` 返回 HTML 或纯文本（后端已拦截路径穿越）。
   * 用 Blob 取回后在新标签打开，避免把 token 拼进 URL。
   */
  async report(rel: string): Promise<{ blob: Blob; contentType: string }> {
    const { blob, headers } = await getBlob('/api/report', { file: rel });
    return { blob, contentType: headers['content-type'] ?? 'text/plain; charset=utf-8' };
  },
};
