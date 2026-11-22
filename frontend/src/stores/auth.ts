/** 认证状态（Pinia）：会话、当前用户、LOA、登录 / step-up / 登出。 */

import { computed, ref } from 'vue';
import { defineStore } from 'pinia';

import { authApi } from '@/api/modules/auth';
import { readSession, writeSession } from '@/api/client';
import type { LoginRequest, LoginResult, SessionInfo } from '@/types/auth';

/** 登录态判定：后端以 `ok` 为准，`degraded=true` 仍算成功（只是 LOA 受限）。 */
export function isLoginSuccess(result: LoginResult): boolean {
  return result.ok === true && Boolean(result.token);
}

export const useAuthStore = defineStore('auth', () => {
  const session = ref(readSession());
  const info = ref<SessionInfo | null>(null);
  /** 最近一次登录的降级原因（bio_mismatch / loa_capped / risk_high）。 */
  const degradedReason = ref<string | null>(null);
  const loading = ref(false);

  const loggedIn = computed(() => Boolean(session.value));
  const loa = computed(() => info.value?.loa ?? 0);
  const username = computed(() => info.value?.user.username ?? '');
  const displayLoa = computed(() => info.value?.loa_name ?? (loa.value ? `LOA${loa.value}` : '-'));

  function clear(): void {
    session.value = '';
    info.value = null;
    degradedReason.value = null;
    writeSession('');
  }

  /** 用已有会话拉取身份信息；失败即视为会话失效（拦截器负责跳登录）。 */
  async function refresh(): Promise<SessionInfo | null> {
    if (!session.value) return null;
    try {
      info.value = await authApi.session();
      return info.value;
    } catch {
      clear();
      return null;
    }
  }

  async function login(payload: LoginRequest): Promise<LoginResult> {
    loading.value = true;
    try {
      const result = await authApi.login(payload);
      if (!isLoginSuccess(result)) return result;

      session.value = result.token ?? '';
      writeSession(session.value);
      degradedReason.value = result.degraded ? (result.degrade_reason ?? 'unknown') : null;
      await refresh();
      return result;
    } finally {
      loading.value = false;
    }
  }

  async function stepUp(totp: string, embedding?: number[]): Promise<LoginResult> {
    const result = await authApi.stepUp({ totp, embedding });
    if (result.status === 'ok') await refresh();
    return result;
  }

  async function logout(): Promise<void> {
    try {
      if (session.value) await authApi.logout();
    } finally {
      clear();
    }
  }

  /** 表单输入用：切换账号时清掉上一次的降级提示。 */
  function clearDegraded(): void {
    degradedReason.value = null;
  }

  return {
    session,
    info,
    loading,
    degradedReason,
    loggedIn,
    loa,
    username,
    displayLoa,
    login,
    stepUp,
    logout,
    refresh,
    clear,
    clearDegraded,
  };
});
