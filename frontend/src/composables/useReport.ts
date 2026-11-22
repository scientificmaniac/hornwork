/**
 * 报告与导出：把“取二进制 → 打开/下载”的能力收在一处。
 *
 * 两者都必须带 `Authorization` 头，因此不能用 `window.location` 或 `<a href>`，
 * 统一走 API 层的 blob 通道；页面只关心 `rel` / `kind`。
 */

import { ref } from 'vue';

import { detectionApi } from '@/api/modules/detection';
import { scanApi } from '@/api/modules/scan';
import { downloadBlob, openBlobInNewTab } from '@/utils/browser';
import { describeError } from '@/composables/useAsync';

export function useReport() {
  const busy = ref(false);
  const error = ref('');

  /** 打开 `/api/report?file=<rel>`：`rel` 形如 `scan/xxx.html`、`reports/xxx.md`。 */
  async function openReport(rel: string): Promise<boolean> {
    if (!rel) {
      error.value = '缺少报告路径';
      return false;
    }
    busy.value = true;
    error.value = '';
    try {
      const { blob } = await scanApi.report(rel);
      const ok = openBlobInNewTab(blob);
      if (!ok) error.value = '浏览器拦截了新标签页，请允许弹出窗口后重试';
      return ok;
    } catch (cause) {
      error.value = describeError(cause);
      return false;
    } finally {
      busy.value = false;
    }
  }

  /** 导出告警 / 事件 / 验证结果为 jsonl 或 markdown。 */
  async function exportAs(
    kind: 'alerts' | 'events' | 'validation',
    format: 'jsonl' | 'md',
    since = '24h',
  ): Promise<boolean> {
    busy.value = true;
    error.value = '';
    try {
      const { blob, filename } = await detectionApi.exportFile(kind, format, since);
      downloadBlob(blob, filename);
      return true;
    } catch (cause) {
      error.value = describeError(cause);
      return false;
    } finally {
      busy.value = false;
    }
  }

  return { busy, error, openReport, exportAs };
}
