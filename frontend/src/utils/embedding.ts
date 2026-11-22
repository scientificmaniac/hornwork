/**
 * 人脸向量的规范化解析。
 *
 * 后端 `_h_auth_post` 只接受 `isinstance(embedding, list)`，传对象会被静默忽略
 * （人脸因子直接丢失，登录降级且不报错）。因此这里把常见的几种载体
 * （纯数组 / `{vector:[...]}` / `{embedding:[...]}`）统一成 `number[]`，
 * 并对维度与值域做前置校验，尽早给出可读错误。
 */

/** 后端 `[auth.bio].dim` 默认 512。 */
export const EXPECTED_DIMENSION = 512;

export class EmbeddingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EmbeddingError';
  }
}

/** 从任意 JSON 值里提取向量数组。 */
export function extractVector(raw: unknown): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (raw && typeof raw === 'object') {
    const record = raw as Record<string, unknown>;
    for (const key of ['vector', 'embedding', 'features', 'data']) {
      if (Array.isArray(record[key])) return record[key] as unknown[];
    }
  }
  throw new EmbeddingError('未找到向量数组：应为 [0.1, 0.2, ...] 或 {"vector": [...]}');
}

/** 解析并校验向量；返回值一定是纯 `number[]`。 */
export function parseEmbedding(text: string): number[] {
  const trimmed = text.trim();
  if (!trimmed) throw new EmbeddingError('人脸向量为空');

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new EmbeddingError('人脸向量不是合法 JSON');
  }

  const values = extractVector(parsed);
  if (values.length !== EXPECTED_DIMENSION) {
    throw new EmbeddingError(
      `人脸向量维度应为 ${EXPECTED_DIMENSION}，实际 ${values.length}`,
    );
  }
  return values.map((value) => {
    const num = Number(value);
    if (!Number.isFinite(num)) throw new EmbeddingError('人脸向量包含非数值元素');
    return num;
  });
}
