import { describe, expect, it } from 'vitest';

import {
  cvssBand,
  deltaLabel,
  deltaTone,
  levelTone,
  severityTone,
  statusLabel,
  statusTone,
} from '@/utils/badge';

describe('severityTone', () => {
  it('告警数值级别按 12/9/6/3 分档', () => {
    expect(severityTone(13)).toBe('danger');
    expect(severityTone(12)).toBe('danger');
    expect(severityTone(9)).toBe('danger');
    expect(severityTone(6)).toBe('warning');
    expect(severityTone(3)).toBe('success');
    expect(severityTone(1)).toBe('info');
  });

  it('CVSS 分数按 9/7/4 分档', () => {
    expect(severityTone('9.8')).toBe('danger');
    expect(severityTone('7.5')).toBe('danger');
    expect(severityTone('5.0')).toBe('warning');
    expect(severityTone('2.0')).toBe('success');
  });

  it('中文与英文枚举', () => {
    expect(severityTone('严重')).toBe('danger');
    expect(severityTone('高')).toBe('danger');
    expect(severityTone('中')).toBe('warning');
    expect(severityTone('低')).toBe('success');
    expect(severityTone('无')).toBe('success');
    expect(severityTone('critical')).toBe('danger');
    expect(severityTone('P1')).toBe('danger');
    expect(severityTone('P2')).toBe('warning');
  });

  it('未知值回落到中性', () => {
    expect(severityTone('something')).toBe('neutral');
    expect(severityTone(null)).toBe('neutral');
  });
});

describe('statusTone', () => {
  it('成功类状态', () => {
    for (const value of ['ok', 'done', 'verified', 'healthy', 'succeeded']) {
      expect(statusTone(value)).toBe('success');
    }
  });

  it('结束态是中性色，不与“成功”混用', () => {
    for (const value of ['closed', 'stopped', 'expired', 'fixed']) {
      expect(statusTone(value)).toBe('neutral');
    }
  });

  it('进行中类状态', () => {
    for (const value of ['running', 'queued', 'starting', 'partial', 'in_progress']) {
      expect(statusTone(value)).toBe('info');
    }
  });

  it('失败类状态', () => {
    for (const value of ['failed', 'error', 'aborted', 'revoked', 'partially_failed']) {
      expect(statusTone(value)).toBe('danger');
    }
  });

  it('警告类状态', () => {
    for (const value of ['new', 'reopened', 'degraded', 'manual', 'not_executed']) {
      expect(statusTone(value)).toBe('warning');
    }
  });
});

describe('statusLabel', () => {
  it('已知枚举转中文', () => {
    expect(statusLabel('reopened')).toBe('重新打开');
    expect(statusLabel('verify_failed')).toBe('复测失败');
  });

  it('未知值原样返回，不吞掉后端新增枚举', () => {
    expect(statusLabel('brand_new_state')).toBe('brand_new_state');
    expect(statusLabel(null)).toBe('-');
  });
});

describe('diff 四态', () => {
  it('标签与状态一致', () => {
    expect(deltaLabel('regressed')).toBe('回归');
    expect(deltaLabel('new')).toBe('新增');
    expect(deltaLabel(undefined)).toBe('-');
  });

  it('配色：回归最刺眼、修复最轻', () => {
    expect(deltaTone('regressed')).toBe('danger');
    expect(deltaTone('new')).toBe('warning');
    expect(deltaTone('persisting')).toBe('info');
    expect(deltaTone('fixed')).toBe('success');
  });
});

describe('CVSS 分档与 levelTone', () => {
  it('cvssBand 与阈值一致', () => {
    expect(cvssBand(9.8)).toBe('严重');
    expect(cvssBand(7.1)).toBe('高');
    expect(cvssBand(4.0)).toBe('中');
    expect(cvssBand(0.1)).toBe('低');
    expect(cvssBand('x')).toBe('-');
  });

  it('levelTone 与 severityTone 数值分支一致', () => {
    expect(levelTone(12)).toBe(severityTone(12));
    expect(levelTone(9)).toBe(severityTone(9));
    expect(levelTone(6)).toBe(severityTone(6));
  });
});
