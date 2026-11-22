/** 认证模块 API：`/api/auth/*`（登录、step-up、会话、用户、审计、策略）。 */

import { ApiError, getJson, postJson } from '@/api/client';
import type {
  AuditPayload,
  LoginRequest,
  LoginResult,
  PolicyMap,
  SessionInfo,
  StepUpRequest,
  UserRow,
} from '@/types/auth';

/**
 * 登录类接口的 401 不是错误而是状态机的一步（`totp_required` / `fail` / `rate_limited`），
 * 因此把原始响应体当作正常返回值，其它错误继续抛 `ApiError`。
 */
async function postAuth(url: string, body: unknown): Promise<LoginResult> {
  try {
    return await postJson<LoginResult>(url, body);
  } catch (error) {
    if (error instanceof ApiError && error.body && typeof error.body === 'object') {
      return error.body as LoginResult;
    }
    throw error;
  }
}

export const authApi = {
  login(payload: LoginRequest): Promise<LoginResult> {
    return postAuth('/api/auth/login', payload);
  },

  stepUp(payload: StepUpRequest): Promise<LoginResult> {
    return postAuth('/api/auth/step-up', payload);
  },

  logout(): Promise<void> {
    return postJson<void>('/api/auth/logout', {}).then(() => undefined);
  },

  session(): Promise<SessionInfo> {
    return getJson<SessionInfo>('/api/auth/session');
  },

  async users(): Promise<UserRow[]> {
    const data = await getJson<{ items?: UserRow[] }>('/api/auth/users');
    return data.items ?? [];
  },

  async sessions(): Promise<SessionInfo['session'][]> {
    const data = await getJson<{ items?: SessionInfo['session'][] }>('/api/auth/sessions');
    return data.items ?? [];
  },

  async audit(limit = 30): Promise<AuditPayload> {
    const data = await getJson<Partial<AuditPayload>>('/api/auth/audit', { limit });
    return {
      items: data.items ?? [],
      chain: data.chain ?? { ok: false, error: '审计链状态缺失' },
    };
  },

  async policy(): Promise<PolicyMap> {
    const data = await getJson<{ policy?: PolicyMap }>('/api/auth/policy');
    return data.policy ?? {};
  },
};
