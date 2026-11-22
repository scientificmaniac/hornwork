import { describe, expect, it } from 'vitest';

import { ApiError, compactParams } from '@/api/client';
import { describeError, softErrorOf } from '@/composables/useAsync';
import { extractVector, parseEmbedding, EmbeddingError } from '@/utils/embedding';

describe('compactParams', () => {
  it('丢弃空值并保留 0 与 false', () => {
    expect(compactParams({ a: 1, b: '', c: null, d: undefined, e: 0, f: false })).toEqual({
      a: '1',
      e: '0',
      f: 'false',
    });
  });

  it('全空时返回 undefined，避免拼出空查询串', () => {
    expect(compactParams({ a: '' })).toBeUndefined();
    expect(compactParams(undefined)).toBeUndefined();
  });
});

describe('ApiError', () => {
  it('从 C7 结构构造', () => {
    const error = new ApiError({ code: 500, message: '服务内部错误', retryable: true, detail: 'x' });
    expect(error.message).toBe('服务内部错误');
    expect(error.retryable).toBe(true);
    expect(error.detail).toBe('x');
  });

  it('普通异常转成 code=0 且不可重试', () => {
    const error = ApiError.from(new Error('boom'));
    expect(error.code).toBe(0);
    expect(error.retryable).toBe(false);
  });

  it('已是 ApiError 时原样返回', () => {
    const original = new ApiError({ code: 401, message: '未授权', retryable: false, detail: null });
    expect(ApiError.from(original)).toBe(original);
  });
});

describe('describeError', () => {
  it('拼上 C7 detail 便于定位', () => {
    const error = new ApiError({ code: 400, message: '参数错误', retryable: false, detail: 'k=v' });
    expect(describeError(error)).toBe('参数错误：k=v');
  });

  it('无 detail 时不追加冒号', () => {
    const error = new ApiError({ code: 400, message: '参数错误', retryable: false, detail: null });
    expect(describeError(error)).toBe('参数错误');
  });

  it('普通异常取 message', () => {
    expect(describeError(new Error('x'))).toBe('x');
    expect(describeError('y')).toBe('y');
  });
});

describe('softErrorOf', () => {
  it('读取扫描类接口的 200+error 软错误', () => {
    expect(softErrorOf({ items: [], error: '库未初始化' })).toBe('库未初始化');
    expect(softErrorOf({ items: [] })).toBe('');
    expect(softErrorOf(null)).toBe('');
  });
});

describe('parseEmbedding', () => {
  const vector = Array.from({ length: 512 }, (_, index) => index / 512);

  it('接受纯数组', () => {
    expect(parseEmbedding(JSON.stringify(vector))).toHaveLength(512);
  });

  it('兼容 {vector:[...]} 与 {embedding:[...]} 包装', () => {
    expect(parseEmbedding(JSON.stringify({ vector }))).toHaveLength(512);
    expect(parseEmbedding(JSON.stringify({ embedding: vector }))).toHaveLength(512);
  });

  it('维度不符即报错（否则后端会静默忽略人脸因子）', () => {
    expect(() => parseEmbedding(JSON.stringify([1, 2, 3]))).toThrow(EmbeddingError);
  });

  it('非 JSON 与空值报错', () => {
    expect(() => parseEmbedding('')).toThrow(EmbeddingError);
    expect(() => parseEmbedding('not json')).toThrow(EmbeddingError);
  });

  it('数组元素必须是数值', () => {
    const bad = Array.from({ length: 512 }, () => 'x');
    expect(() => parseEmbedding(JSON.stringify(bad))).toThrow(EmbeddingError);
  });

  it('extractVector 支持多种字段名', () => {
    expect(extractVector({ features: [1, 2] })).toEqual([1, 2]);
    expect(() => extractVector({ other: 1 })).toThrow(EmbeddingError);
  });
});
