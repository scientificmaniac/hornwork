import { describe, expect, it } from 'vitest';

import {
  formatBool,
  formatBytes,
  formatDuration,
  formatFloat,
  formatJson,
  formatNumber,
  formatPercent,
  formatTime,
  formatTimeShort,
  summarize,
  truncate,
} from '@/utils/format';

describe('formatTime', () => {
  it('把 UTC ISO 转成本地时间字符串', () => {
    const text = formatTime('2026-11-21T12:34:56.789Z');
    expect(text).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  it('已是本地时间格式的字符串原样截断', () => {
    expect(formatTime('2026-11-21 12:34:56')).toBe('2026-11-21 12:34:56');
  });

  it('空值与非法值安全降级', () => {
    expect(formatTime(null)).toBe('-');
    expect(formatTime('')).toBe('-');
    expect(formatTime('not-a-date')).toBe('not-a-date');
  });

  it('formatTimeShort 只保留到分钟', () => {
    expect(formatTimeShort('2026-11-21 12:34:56')).toBe('2026-11-21 12:34');
  });
});

describe('数值格式化', () => {
  it('formatNumber 千分位与空值', () => {
    expect(formatNumber(1234567)).toBe('1,234,567');
    expect(formatNumber(null)).toBe('-');
    expect(formatNumber('abc')).toBe('abc');
  });

  it('formatFloat 固定小数位', () => {
    expect(formatFloat(7.126)).toBe('7.13');
    expect(formatFloat(null)).toBe('-');
  });

  it('formatPercent 转百分比', () => {
    expect(formatPercent(0.4567)).toBe('45.7%');
    expect(formatPercent(undefined)).toBe('-');
  });

  it('formatBytes 单位换算', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KB');
    expect(formatBytes(0)).toBe('-');
  });

  it('formatDuration 按量级切换单位', () => {
    expect(formatDuration(320)).toBe('320 ms');
    expect(formatDuration(1500)).toBe('1.5 s');
    expect(formatDuration(125000)).toBe('2 分 5 秒');
  });

  it('formatBool 识别常见真值', () => {
    expect(formatBool(true)).toBe('是');
    expect(formatBool(1)).toBe('是');
    expect(formatBool(false)).toBe('否');
    expect(formatBool(null)).toBe('-');
  });
});

describe('文本工具', () => {
  it('truncate 超长截断并加省略号', () => {
    expect(truncate('abcdef', 4)).toBe('abc…');
    expect(truncate('abc', 4)).toBe('abc');
  });

  it('summarize 把对象压成一行', () => {
    expect(summarize({ a: 1, b: 'x' })).toBe('a=1 b=x');
    expect(summarize(null)).toBe('-');
  });

  it('summarize 保留截断长度上限', () => {
    const long = { key: 'x'.repeat(200) };
    expect(summarize(long, 20).length).toBeLessThanOrEqual(20);
  });

  it('formatJson 缩进序列化', () => {
    expect(formatJson({ a: 1 })).toContain('"a": 1');
    expect(formatJson(null)).toBe('');
  });

  it('formatJson 处理循环引用', () => {
    const loop: Record<string, unknown> = {};
    loop.self = loop;
    expect(() => formatJson(loop)).not.toThrow();
  });
});
