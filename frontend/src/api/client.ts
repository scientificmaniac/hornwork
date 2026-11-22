/**
 * 统一 HTTP 层：唯一的 axios 实例。
 *
 * 约定（见 docs/frontend-vue-architecture.md §5.4 / §8.3）：
 * - token 双轨：平台会话（`s1.` 前缀，sessionStorage）与静态 Bearer 均经 `Authorization` 下发；
 * - 401 统一清理会话并跳登录（登录类接口除外）；
 * - 后端 C7 错误结构原样抛成 `ApiError`，调用方按 `retryable` 决定是否重试；
 * - 后端“200 + error 字段”的降级约定由各 API 模块解读，不在这里吞掉。
 */

import axios, { type AxiosError, type AxiosInstance } from 'axios';

import type { C7Payload } from '@/types/common';

/** 免鉴权路径：不注入 token，也不触发 401 跳转。 */
const PUBLIC_PATHS = ['/api/auth/login', '/api/auth/step-up', '/api/auth/logout'];

const SESSION_KEY = 'hornwork.session';

let http: AxiosInstance | null = null;
let unauthorizedHandler: (() => void) | null = null;

/** 会话令牌读取（唯一入口，避免各模块各自读 storage）。 */
export function readSession(): string {
  try {
    return sessionStorage.getItem(SESSION_KEY) ?? '';
  } catch {
    return '';
  }
}

export function writeSession(token: string): void {
  try {
    if (token) {
      sessionStorage.setItem(SESSION_KEY, token);
    } else {
      sessionStorage.removeItem(SESSION_KEY);
    }
  } catch {
    /* 隐私模式下 storage 不可用：仅内存态生效，不阻断操作 */
  }
}

/** 注册 401 回调（由 router 装配，避免 client 直接依赖路由）。 */
export function onUnauthorized(handler: () => void): void {
  unauthorizedHandler = handler;
}

/**
 * 结构化 API 错误：承载 C7 四字段，供 toast 与重试逻辑使用。
 *
 * `body` 保留后端原始响应体——认证类接口在 401 时仍返回完整状态机
 * （`status` / `reason` / `degraded`），调用方需要它来决定下一步交互。
 */
export class ApiError extends Error {
  readonly code: number;
  readonly retryable: boolean;
  readonly detail: string | null;
  readonly body: unknown;

  constructor(payload: C7Payload, body: unknown = null) {
    super(payload.message || `请求失败（HTTP ${payload.code}）`);
    this.name = 'ApiError';
    this.code = payload.code;
    this.retryable = payload.retryable;
    this.detail = payload.detail;
    this.body = body;
  }

  static from(error: unknown): ApiError {
    if (error instanceof ApiError) return error;
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<Partial<C7Payload>>;
      const status = axiosError.response?.status ?? 0;
      const data = axiosError.response?.data;
      if (data && typeof data === 'object') {
        // 认证类接口 401 时返回的是状态机而非 C7，同样保留原始响应体
        if (typeof data.message === 'string') {
          return new ApiError(
            {
              code: Number(data.code ?? status),
              message: data.message,
              retryable: Boolean(data.retryable),
              detail: (data.detail as string | null) ?? null,
            },
            data,
          );
        }
        return new ApiError(
          { code: status, message: `请求被拒绝（HTTP ${status}）`, retryable: false, detail: null },
          data,
        );
      }
      return new ApiError({
        code: status,
        message: axiosError.message || '网络请求失败',
        retryable: !axiosError.response,
        detail: null,
      });
    }
    return new ApiError({
      code: 0,
      message: error instanceof Error ? error.message : String(error),
      retryable: false,
      detail: null,
    });
  }
}

function isPublicPath(url: string): boolean {
  return PUBLIC_PATHS.some((path) => url.startsWith(path));
}

function getHttp(): AxiosInstance {
  if (http) return http;

  http = axios.create({
    baseURL: '/',
    timeout: 30_000,
    responseType: 'json',
    // 后端只接受对象型 JSON 体，这里统一序列化，避免各调用点重复处理
    transformRequest: [
      (data, headers) => {
        if (data === undefined || data === null) return undefined;
        if (typeof data === 'string' || data instanceof FormData || data instanceof Blob) return data;
        (headers as Record<string, string>)['Content-Type'] = 'application/json';
        return JSON.stringify(data);
      },
    ],
  });

  http.interceptors.request.use((config) => {
    const url = config.url ?? '';
    if (!isPublicPath(url)) {
      const token = readSession();
      if (token) config.headers.set('Authorization', `Bearer ${token}`);
    }
    // 禁用浏览器缓存：后端所有响应都带 Cache-Control: no-store，前端保持一致语义
    config.headers.set('Cache-Control', 'no-store');
    return config;
  });

  http.interceptors.response.use(
    (response) => response,
    (error: AxiosError) => {
      const status = error.response?.status;
      const url = error.config?.url ?? '';
      if (status === 401 && !isPublicPath(url)) {
        writeSession('');
        unauthorizedHandler?.();
      }
      return Promise.reject(ApiError.from(error));
    },
  );

  return http;
}

/** GET：`params` 中的 null/undefined/空串会被丢弃，避免后端收到 `?severity=`。 */
export async function getJson<T>(url: string, params?: Record<string, unknown>): Promise<T> {
  const response = await getHttp().get<T>(url, { params: compactParams(params) });
  return response.data;
}

/** POST：返回后端原始 JSON。 */
export async function postJson<T>(url: string, body?: unknown): Promise<T> {
  const response = await getHttp().post<T>(url, body ?? {});
  return response.data;
}

/** 下载二进制/文本产物：返回 Blob 与响应头（文件名在 `Content-Disposition`）。 */
export async function getBlob(
  url: string,
  params?: Record<string, unknown>,
): Promise<{ blob: Blob; headers: Record<string, string> }> {
  const response = await getHttp().get<Blob>(url, {
    params: compactParams(params),
    responseType: 'blob',
    // 产物可能是 HTML/JSONL：保持原始字节，不让 axios 尝试解析
    transformResponse: [(value: unknown) => value],
  });
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(response.headers ?? {})) {
    if (typeof value === 'string') headers[key.toLowerCase()] = value;
  }
  return { blob: response.data, headers };
}

/** 丢掉空值参数：后端 `_q_int` 会把空串当默认值，但保留空串会产生无谓噪声。 */
export function compactParams(params?: Record<string, unknown>): Record<string, string> | undefined {
  if (!params) return undefined;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    out[key] = String(value);
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** 供测试注入：重置单例。 */
export function resetHttpForTest(): void {
  http = null;
  unauthorizedHandler = null;
}
