/**
 * 轮询：仅在页面可见时运行，卸载或不可见时暂停。
 *
 * 后端没有 SSE / WebSocket，长时任务（扫描任务、靶场启动）只能定时拉取；
 * 关键约束是「离开页面必须停」——否则多标签页会持续打库。
 */

import { onScopeDispose, ref } from 'vue';

export interface PollingOptions {
  /** 轮询间隔（毫秒）。 */
  interval: number;
  /** 返回 true 停止轮询（终态判定）。 */
  shouldStop?: () => boolean;
  /** 页面不可见时暂停（默认 true）。 */
  pauseWhenHidden?: boolean;
  /** 是否立即执行一次（默认 true）。 */
  immediate?: boolean;
}

export function usePolling(task: () => unknown, options: PollingOptions) {
  const { interval, shouldStop, pauseWhenHidden = true, immediate = true } = options;
  const active = ref(false);
  const lastError = ref<string>('');

  let timer: ReturnType<typeof setTimeout> | null = null;
  let running = false;
  let disposed = false;

  function clearTimer(): void {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
  }

  function schedule(): void {
    clearTimer();
    if (!active.value || disposed) return;
    timer = setTimeout(tick, interval);
  }

  async function tick(): Promise<void> {
    if (!active.value || disposed || running) return;
    if (pauseWhenHidden && document.visibilityState === 'hidden') {
      schedule();
      return;
    }
    running = true;
    try {
      await task();
      lastError.value = '';
    } catch (error) {
      lastError.value = error instanceof Error ? error.message : String(error);
    } finally {
      running = false;
    }
    if (shouldStop?.()) {
      stop();
      return;
    }
    schedule();
  }

  function start(): void {
    if (active.value || disposed) return;
    active.value = true;
    if (immediate) {
      void tick();
    } else {
      schedule();
    }
  }

  function stop(): void {
    active.value = false;
    clearTimer();
  }

  /** 立即执行一次但不改变轮询状态（“刷新”按钮复用同一条请求路径）。 */
  async function refreshNow(): Promise<void> {
    await tick();
  }

  function handleVisibility(): void {
    if (!active.value) return;
    if (document.visibilityState === 'visible') {
      // 回到前台时补一次，避免错过窗口期的状态变化
      if (timer === null) void tick();
    }
  }

  document.addEventListener('visibilitychange', handleVisibility);

  onScopeDispose(() => {
    disposed = true;
    stop();
    document.removeEventListener('visibilitychange', handleVisibility);
  });

  return { active, lastError, start, stop, refreshNow };
}
