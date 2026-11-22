/** 浏览器侧副作用：文件下载、新标签预览。与业务无关，集中在此避免各页面重复。 */

/** 触发浏览器下载（Blob 已带内容类型时优先使用后端声明的文件名）。 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // 立即 revoke 会让部分浏览器取消下载，延后释放
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/**
 * 在新标签打开后端产物（HTML 报告 / Markdown）。
 *
 * 产物来自本地服务、属于可信内容，但仍用 `noopener` 与新窗口隔离，
 * 避免报告内脚本拿到控制台的 `window` 引用。
 */
export function openBlobInNewTab(blob: Blob): boolean {
  const url = URL.createObjectURL(blob);
  const opened = window.open(url, '_blank', 'noopener,noreferrer');
  if (!opened) {
    URL.revokeObjectURL(url);
    return false;
  }
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return true;
}

/** 读取本地文件为文本（登录页载入人脸向量 JSON）。 */
export function readFileText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(reader.error ?? new Error('文件读取失败'));
    reader.readAsText(file);
  });
}
