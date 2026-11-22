/** 可读化工具：时间、数值、字节、JSON、CVSS、HTTP 协议等。全部为纯函数，便于单测。 */

/** 后端时间统一 UTC ISO8601（毫秒 + Z）；空值统一显示 `-`。 */
const PLACEHOLDER = '-';

/** 本地时间字符串（`YYYY-MM-DD HH:mm:ss`）。非法值原样返回，避免静默丢信息。 */
export function formatTime(value: unknown): string {
  if (value === null || value === undefined || value === '') return PLACEHOLDER;
  const text = String(value);
  // 扫描报告的 mtime 已是本地时间字符串（`YYYY-MM-DD HH:MM:SS`），不做二次转换
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(text)) return text.slice(0, 19);
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return text;
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  );
}

/** 只保留到分钟：列表里看时间足够，减少噪声。 */
export function formatTimeShort(value: unknown): string {
  const text = formatTime(value);
  return text === PLACEHOLDER ? text : text.slice(0, 16);
}

/** 相对时间（“3 分钟前”），用于“最近更新”类提示。 */
export function formatRelative(value: unknown, now: number = Date.now()): string {
  if (value === null || value === undefined || value === '') return PLACEHOLDER;
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  const seconds = Math.round((now - date.getTime()) / 1000);
  if (seconds < 60) return '刚刚';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  return `${Math.round(hours / 24)} 天前`;
}

/** 千分位数字；空值返回 `-`。 */
export function formatNumber(value: unknown): string {
  if (value === null || value === undefined || value === '') return PLACEHOLDER;
  const num = Number(value);
  if (!Number.isFinite(num)) return String(value);
  return num.toLocaleString('zh-CN');
}

/** 浮点数保留位数（默认 2 位），用于 CVSS 与比率。 */
export function formatFloat(value: unknown, digits = 2): string {
  if (value === null || value === undefined || value === '') return PLACEHOLDER;
  const num = Number(value);
  return Number.isFinite(num) ? num.toFixed(digits) : String(value);
}

/** 0–1 比率 → 百分比。 */
export function formatPercent(value: unknown, digits = 1): string {
  if (value === null || value === undefined || value === '') return PLACEHOLDER;
  const num = Number(value);
  return Number.isFinite(num) ? `${(num * 100).toFixed(digits)}%` : String(value);
}

/** 字节数 → 带单位字符串。 */
export function formatBytes(value: unknown): string {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return PLACEHOLDER;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = num;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size >= 100 || index === 0 ? Math.round(size) : size.toFixed(1)} ${units[index]}`;
}

/** 毫秒耗时 → 可读时长。 */
export function formatDuration(ms: unknown): string {
  const num = Number(ms);
  if (!Number.isFinite(num) || num < 0) return PLACEHOLDER;
  if (num < 1000) return `${Math.round(num)} ms`;
  if (num < 60_000) return `${(num / 1000).toFixed(1)} s`;
  const minutes = Math.floor(num / 60_000);
  const seconds = Math.round((num % 60_000) / 1000);
  return `${minutes} 分 ${seconds} 秒`;
}

/** 对象 → 缩进 JSON（详情抽屉里展示原始数据）。循环引用与非法值安全降级。 */
export function formatJson(value: unknown): string {
  if (value === null || value === undefined) return '';
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

/** 一行摘要：把嵌套结构压成单行文本，供表格单元格使用。 */
export function summarize(value: unknown, maxLength = 120): string {
  if (value === null || value === undefined) return PLACEHOLDER;
  if (typeof value !== 'object') return truncate(String(value), maxLength);
  const parts: string[] = [];
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (item === null || item === undefined || item === '') continue;
    const text = typeof item === 'object' ? JSON.stringify(item) : String(item);
    parts.push(`${key}=${text}`);
    if (parts.join(' ').length > maxLength) break;
  }
  return truncate(parts.join(' ') || PLACEHOLDER, maxLength);
}

/** 截断字符串（保留尾部省略号）。 */
export function truncate(text: string, maxLength: number): string {
  return text.length > maxLength ? `${text.slice(0, Math.max(0, maxLength - 1))}…` : text;
}

/** 布尔 → 中文。 */
export function formatBool(value: unknown): string {
  if (value === null || value === undefined || value === '') return PLACEHOLDER;
  return value === true || value === 1 || value === '1' || value === 'true' ? '是' : '否';
}
