/** 检测域 API：事件、告警、规则、情报、工单、验证、引擎贡献、导出。 */

import { getBlob, getJson, postJson } from '@/api/client';
import type { ListPayload, QueryParams } from '@/types/common';
import type {
  Alert,
  CanonicalEvent,
  CaseRecord,
  CreateCaseRequest,
  EngineStatsPayload,
  IntegrationPayload,
  IntelPayload,
  IocRecord,
  OverviewPayload,
  RulesPayload,
  ValidationPayload,
} from '@/types/detection';

type RawList<T> = { items?: T[]; count?: number; total?: number; error?: string };

/**
 * 列表形状归一化。
 *
 * 后端列表接口存在 `{items,count}` / `{items,total}` 两种形状，`count` 是
 * “本次返回条数”而非真实总数（无 offset 分页），因此 `total` 只作展示参考。
 * 扫描类接口会在 200 响应里带 `error` 字段，这里一并透出，由页面决定降级提示。
 */
function toList<T>(data: RawList<T>): ListPayload<T> {
  const items = data.items ?? [];
  const total = Number(data.total ?? data.count ?? items.length);
  return data.error ? { items, total, error: String(data.error) } : { items, total };
}

export const detectionApi = {
  overview(days = 7): Promise<OverviewPayload> {
    return getJson<OverviewPayload>('/api/overview', { days });
  },

  integration(): Promise<IntegrationPayload> {
    return getJson<IntegrationPayload>('/api/integration/status');
  },

  async events(params: QueryParams = {}): Promise<ListPayload<CanonicalEvent>> {
    return toList(await getJson<RawList<CanonicalEvent>>('/api/events', params));
  },

  async recentEvents(limit = 20): Promise<ListPayload<CanonicalEvent>> {
    return toList(await getJson<RawList<CanonicalEvent>>('/api/events/recent', { limit }));
  },

  async eventTypes(): Promise<{ type: string; n: number }[]> {
    const data = await getJson<{ items?: { type: string; n: number }[] }>('/api/events/types');
    return data.items ?? [];
  },

  async alerts(params: QueryParams = {}): Promise<ListPayload<Alert>> {
    return toList(await getJson<RawList<Alert>>('/api/alerts', params));
  },

  async rules(): Promise<RulesPayload> {
    const data = await getJson<Partial<RulesPayload>>('/api/rules');
    return {
      items: data.items ?? [],
      sources: data.sources ?? {},
      missing: data.missing ?? [],
      sigma: data.sigma ?? { total: 0, supported: 0, hits: 0 },
      reload: data.reload ?? {},
    };
  },

  reloadRules(note = ''): Promise<{ ok: boolean; count?: number; requested_at?: string }> {
    return postJson('/api/rules', { action: 'reload', note });
  },

  async intel(params: QueryParams = {}): Promise<IntelPayload> {
    const data = await getJson<{
      items?: IocRecord[];
      by_type?: Record<string, number>;
      error?: string;
    }>('/api/intel', params);
    return { items: data.items ?? [], by_type: data.by_type ?? {} };
  },

  importIntel(
    records: IocRecord[],
  ): Promise<{ ok: boolean; imported?: number; skipped?: number; total?: number }> {
    return postJson('/api/intel', { records });
  },

  async cases(params: QueryParams = {}): Promise<ListPayload<CaseRecord>> {
    return toList(await getJson<RawList<CaseRecord>>('/api/cases', params));
  },

  createCase(
    payload: CreateCaseRequest,
  ): Promise<{ ok: boolean; case_id: string; case?: CaseRecord }> {
    return postJson('/api/cases', payload);
  },

  validate(params: QueryParams = {}): Promise<ValidationPayload> {
    return getJson<ValidationPayload>('/api/validate', params);
  },

  engineStats(days = 7, limit = 20): Promise<EngineStatsPayload> {
    return getJson<EngineStatsPayload>('/api/engine-stats', { days, limit });
  },

  /**
   * 导出下载。
   *
   * 后端要求 `Authorization` 头，所以不能用 `window.location`；
   * 文件名从 `Content-Disposition` 解析，缺失时按约定拼一个。
   */
  async exportFile(
    kind: 'alerts' | 'events' | 'validation',
    format: 'jsonl' | 'md',
    since = '24h',
  ): Promise<{ blob: Blob; filename: string }> {
    const { blob, headers } = await getBlob('/api/export', { kind, format, since });
    const disposition = headers['content-disposition'] ?? '';
    const match = /filename="?([^";]+)"?/.exec(disposition);
    const fallback = `hornwork-${kind}.${format === 'md' ? 'md' : 'jsonl'}`;
    return { blob, filename: match?.[1] ?? fallback };
  },
};
