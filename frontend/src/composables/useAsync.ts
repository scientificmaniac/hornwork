/**
 * 异步数据容器：把「加载 / 成功 / 失败 / 软降级」四态收在一处。
 *
 * 页面通用形态是「一组请求 → 渲染」。逐个页面手写 loading/error/data 三支会让代码
 * 迅速膨胀并各自长出不同的错误处理；这里只做一件事：稳定暴露状态，并在并发请求
 * 交叠时丢弃过期结果（避免慢请求覆盖新数据）。
 */

import { ref, type Ref, shallowRef, type ShallowRef } from 'vue';

import { ApiError } from '@/api/client';

/** 把任意异常转成中文可读文案（C7 的 detail 一并带出，便于定位）。 */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    const detail = error.detail ? `：${error.detail}` : '';
    return `${error.message}${detail}`;
  }
  return error instanceof Error ? error.message : String(error);
}

/** 从「带 error 字段的数据」里取软错误（扫描类接口的 200+error 降级约定）。 */
export function softErrorOf(data: unknown): string {
  if (data && typeof data === 'object' && 'error' in data) {
    const value = (data as { error?: unknown }).error;
    if (value) return String(value);
  }
  return '';
}

export interface AsyncRunner<T> {
  data: ShallowRef<T>;
  loading: Ref<boolean>;
  error: Ref<string>;
  softError: Ref<string>;
  run: (loader: () => Promise<T>, options?: { softError?: boolean }) => Promise<T | null>;
  clearError: () => void;
}

export function useAsync<T>(initial: T): AsyncRunner<T> {
  const data = shallowRef(initial) as ShallowRef<T>;
  const loading = ref(false);
  const error = ref('');
  const softError = ref('');

  /** 并发代次：只接受最后一次请求的结果。 */
  let generation = 0;

  async function run(
    loader: () => Promise<T>,
    options: { softError?: boolean } = {},
  ): Promise<T | null> {
    const current = ++generation;
    loading.value = true;
    error.value = '';
    try {
      const result = await loader();
      if (current !== generation) return null;
      data.value = result;
      softError.value = options.softError === false ? '' : softErrorOf(result);
      return result;
    } catch (cause) {
      if (current !== generation) return null;
      error.value = describeError(cause);
      return null;
    } finally {
      if (current === generation) loading.value = false;
    }
  }

  function clearError(): void {
    error.value = '';
    softError.value = '';
  }

  return { data, loading, error, softError, run, clearError };
}
