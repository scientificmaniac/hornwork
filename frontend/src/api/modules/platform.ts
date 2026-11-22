/** 加固域与平台安全域 API：`/api/harden/status`、`/api/platform/security`、`/healthz`。 */

import { getJson } from '@/api/client';
import type { HardenStatus, PlatformSecurity } from '@/types/harden';

export interface HealthPayload {
  ok: boolean;
  service: string;
  version: string;
  ts: string;
  auth: boolean;
  web: { bind: string; port: number; running: boolean; url: string; uptime_sec?: number };
}

export const platformApi = {
  health(): Promise<HealthPayload> {
    return getJson<HealthPayload>('/healthz');
  },

  async harden(): Promise<HardenStatus> {
    const data = await getJson<Partial<HardenStatus>>('/api/harden/status');
    return {
      ts: data.ts ?? '',
      items: data.items ?? [],
      plans: data.plans ?? [],
      runs: data.runs ?? [],
      reports: data.reports ?? [],
    };
  },

  async security(): Promise<PlatformSecurity> {
    const data = await getJson<Partial<PlatformSecurity>>('/api/platform/security');
    return {
      ts: data.ts ?? '',
      https: data.https ?? {},
      lockout: data.lockout ?? {},
      paths: data.paths ?? {},
      service: data.service ?? {},
      bind: data.bind,
    };
  },
};
