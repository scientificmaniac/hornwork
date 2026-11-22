/**
 * 徽章映射：严重级 / 状态 / 四态 diff / 告警级别 → 语义色。
 *
 * 旧页面用正则散落在各处判断（`sevBadge` / `statusBadge`），这里集中一处维护：
 * 后端新增枚举值时只需改本文件，不会出现同一个值在不同页面颜色不一致。
 */

import type { Tone } from '@/types/common';

/** 命中集合里的任一关键字即返回对应语义色（大小写不敏感）。 */
function matchTone(value: string, table: [RegExp, Tone][], fallback: Tone = 'neutral'): Tone {
  const text = value.trim().toLowerCase();
  for (const [pattern, tone] of table) {
    if (pattern.test(text)) return tone;
  }
  return fallback;
}

/**
 * 严重级：支持告警数值级别（1–15）与中文五档、P1–P3、CVSS 分数。
 * 告警级别口径：≥12 critical / ≥9 high / ≥6 medium / ≥3 low / 其余 info。
 */
export function severityTone(value: unknown): Tone {
  if (value === null || value === undefined || value === '') return 'neutral';
  if (typeof value === 'number') return levelTone(value);
  const text = String(value).trim();
  if (/^\d+(\.\d+)?$/.test(text)) {
    const num = Number(text);
    // CVSS 3.1 分数与告警 level 都用数值，按 0–10 判定；>10 视为告警 level
    return num > 10 ? levelTone(num) : cvssTone(num);
  }
  return matchTone(
    text,
    [
      [/^(严重|极高|critical|crit|p1|high|高)$/, 'danger'],
      [/^(中|medium|moderate|p2|warning|mid)$/, 'warning'],
      [/^(低|low|p3|info|无|none)$/, 'success'],
    ],
    'neutral',
  );
}

/** CVSS 分数 → 语义色（3.1 分级：≥9 严重 / ≥7 高 / ≥4 中 / 其余低）。 */
export function cvssTone(score: number): Tone {
  if (!Number.isFinite(score)) return 'neutral';
  if (score >= 9) return 'danger';
  if (score >= 7) return 'danger';
  if (score >= 4) return 'warning';
  if (score > 0) return 'success';
  return 'neutral';
}

/** 告警数值级别 1–15 → 语义色。 */
export function levelTone(level: number): Tone {
  if (!Number.isFinite(level)) return 'neutral';
  if (level >= 12) return 'danger';
  if (level >= 9) return 'danger';
  if (level >= 6) return 'warning';
  if (level >= 3) return 'success';
  return 'info';
}

/** CVSS 3.1 分数 → 分级文案（与 `cvssTone` 的阈值保持一致）。 */
export function cvssBand(score: unknown): string {
  const value = Number(score);
  if (!Number.isFinite(value)) return '-';
  if (value >= 9) return '严重';
  if (value >= 7) return '高';
  if (value >= 4) return '中';
  if (value > 0) return '低';
  return '无';
}

/** 状态：任务 / finding / 会话 / 加固运行 / 靶场等共用一套关键字。 */
export function statusTone(value: unknown): Tone {
  if (value === null || value === undefined || value === '') return 'neutral';
  const text = String(value);
  return matchTone(text, [
    [/^(ok|done|success|succeeded|verified|active|healthy|open|passed|通过)$/, 'success'],
    [/^(running|queued|starting|pending|observed|would_apply|partial|partially_completed|in_progress)$/, 'info'],
    [/^(new|reopened|regressed|degraded|warn|warning|manual|skipped_unconfirmed|not_executed|ack)$/, 'warning'],
    [/^(fail|failed|error|critical|aborted|false_positive|verify_failed|partially_failed|revoked|locked)$/, 'danger'],
    [/^(closed|stopped|down|expired|fixed|already_ok|inconclusive|unknown)$/, 'neutral'],
  ]);
}

/** 快照 diff 四态。 */
export function deltaTone(value: unknown): Tone {
  switch (String(value ?? '')) {
    case 'regressed':
      return 'danger';
    case 'new':
      return 'warning';
    case 'persisting':
      return 'info';
    case 'fixed':
      return 'success';
    default:
      return 'neutral';
  }
}

/** 四态中文标签：与后端 `scan.diff.DELTA_LABELS` 保持一致。 */
export const DELTA_LABELS: Record<string, string> = {
  new: '新增',
  fixed: '已修复',
  persisting: '仍存在',
  regressed: '回归',
};

export function deltaLabel(value: unknown): string {
  const key = String(value ?? '');
  return DELTA_LABELS[key] ?? (key || '-');
}

/** 常用枚举的中文标签；未收录时原样返回，避免吞掉后端新增值。 */
const LABELS: Record<string, string> = {
  // 任务 / 阶段
  queued: '排队中',
  running: '运行中',
  done: '已完成',
  partial: '部分完成',
  failed: '失败',
  aborted: '已中断',
  claimed: '已认领',
  finished: '已结束',
  retry: '重试',
  recovered: '已恢复',
  cancelled: '已取消',
  // finding
  new: '新增',
  observed: '已观测',
  confirmed: '已确认',
  false_positive: '误报',
  fixed: '已修复',
  reopened: '重新打开',
  // 工单
  open: '打开',
  investigating: '调查中',
  contained: '已遏制',
  closed: '已关闭',
  // 情报
  candidate: '候选',
  active: '生效',
  aging: '老化',
  expired: '已过期',
  // 验证
  TP: '真阳',
  TN: '真阴',
  FP: '假阳',
  FN: '假阴',
  inconclusive: '未定',
  alert_present: '有告警',
  no_alert: '无告警',
  unknown: '未知',
  // 靶场 / 加固
  down: '未启动',
  starting: '启动中',
  healthy: '健康',
  error: '错误',
  stopped: '已停止',
  succeeded: '成功',
  partially_completed: '部分完成',
  not_executed: '未执行',
  partially_failed: '部分失败',
  rolled_back: '已回滚',
  pending: '待处理',
  manual: '需人工',
  already_ok: '已合规',
  would_apply: '试运行',
  skipped_unconfirmed: '未确认跳过',
  verify_failed: '复测失败',
  verified: '已验证',
  // 日志/认证
  ok: '成功',
  fail: '失败',
  degraded: '降级',
  revoked: '已吊销',
  logon: '登录',
  logon_fail: '登录失败',
  stepup: '会话升级',
  logout: '登出',
  lockout: '锁定',
  unlock: '解锁',
  // 加固风险
  low: '低',
  mid: '中',
  high: '高',
  // 引擎
  malicious: '恶意',
  clean: '干净',
  unknown_verdict: '未知',
};

export function statusLabel(value: unknown): string {
  if (value === null || value === undefined || value === '') return '-';
  const text = String(value);
  return LABELS[text] ?? text;
}
