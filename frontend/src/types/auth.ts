/** 认证域类型：登录状态机、会话、用户、审计、策略。 */

import type { ChainInfo } from './common';

/** LOA 0–3：0 未认证 / 1 口令 / 2 口令+动态码 / 3 口令+动态码+人脸。 */
export type Loa = 0 | 1 | 2 | 3;

/** 角色：viewer 只读 / operator 可写 / admin 额外管理用户与审计。 */
export type Role = 'viewer' | 'operator' | 'admin';

export interface LoginRequest {
  username: string;
  password: string;
  /** 平台统一登录的客户端 IP（写入风险评分与审计）。 */
  ip?: string;
  /** 三因子路径的动态码；提供时后端走 challenge 状态机。 */
  totp?: string;
  /** 人脸向量必须是纯 number[]（512 维），不能是 { vector: [...] }。 */
  embedding?: number[];
  device_token?: string;
}

export interface StepUpRequest {
  totp: string;
  embedding?: number[];
  token?: string;
}

/** 登录/step-up 响应；成功以 `ok` 判定，`degraded` 表示降级认证而非失败。 */
export interface LoginResult {
  ok: boolean;
  status: string;
  token?: string;
  loa?: number;
  loa_name?: string;
  factors?: string[];
  degraded?: boolean;
  degrade_reason?: string | null;
  reason?: string;
  similarity?: number | null;
  latency_ms?: number;
  challenge_id?: string | null;
  required_loa?: number;
  expires_in?: number;
  ts?: string;
  message?: string;
  detail?: string;
}

export interface SessionRow {
  session_id: string;
  user_id: number;
  loa: number;
  ip?: string | null;
  device_id?: string | null;
  created_ts?: string | null;
  last_seen_ts?: string | null;
  idle_expires_ts?: string | null;
  expires_ts?: string | null;
  strong_auth_ts?: string | null;
  revoked?: number;
  revoke_reason?: string | null;
}

export interface SessionInfo {
  ok: boolean;
  ts?: string;
  session: SessionRow;
  user: { id: number; username: string; role?: Role };
  loa: number;
  loa_name: string;
}

export interface UserRow {
  id: number;
  username: string;
  role?: Role;
  display_name?: string | null;
  status: string;
  loa_max: number;
  failed_count?: number;
  locked_until?: string | null;
  last_login_ts?: string | null;
  /** 后端字段名是 `mfa_enabled`，旧页面读的是 `totp_active`。 */
  mfa_enabled?: number | boolean;
  password_algo?: string | null;
}

export interface AuditRow {
  id: number;
  ts: string;
  username?: string | null;
  event: string;
  factor?: string | null;
  result: string;
  loa?: number | null;
  risk_score?: number | null;
  risk_why?: string | null;
  ip?: string | null;
  latency_ms?: number | null;
  detail?: string | null;
  row_hash?: string;
}

export interface AuditPayload {
  items: AuditRow[];
  chain: ChainInfo;
}

export type PolicyMap = Record<string, unknown>;
