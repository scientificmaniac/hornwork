/** 全局通用类型：与后端 C7 错误结构、列表响应形状一一对应。 */

/** 后端统一错误结构（契约 C7），`code` 即 HTTP 状态码。 */
export interface C7Payload {
  code: number;
  message: string;
  retryable: boolean;
  detail: string | null;
}

/** 语义色：徽章与面板共用，避免各页面自行拼 className。 */
export type Tone = 'danger' | 'warning' | 'success' | 'info' | 'neutral';

/** 认证审计链校验结果。 */
export interface ChainInfo {
  ok: boolean;
  checked?: number;
  head?: string;
  bad_id?: number;
  reason?: string;
  error?: string;
}

/**
 * 归一化后的列表结果。
 *
 * 后端列表形状不统一（`items` / `records` / `envs` / `runs`），
 * 各 API 模块在出口处统一成本结构；`error` 是后端“200 + 降级”约定的软错误。
 */
export interface ListPayload<T> {
  items: T[];
  total: number;
  error?: string;
}

export type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue>;

/**
 * 单元格渲染方式：
 * - `severity` / `status` / `delta` / `level` 渲染为徽章；
 * - 其余为文本格式化，`sum` 是“压缩成一行”的摘要。
 */
export type CellKind =
  | 'text'
  | 'sum'
  | 'mono'
  | 'time'
  | 'number'
  | 'float'
  | 'percent'
  | 'bytes'
  | 'duration'
  | 'bool'
  | 'json'
  | 'severity'
  | 'status'
  | 'delta'
  | 'level';

/** 表格列定义：声明式描述一列如何取值与渲染。 */
export interface Column<T> {
  key: string;
  label: string;
  width?: number | string;
  minWidth?: number;
  align?: 'left' | 'center' | 'right';
  kind?: CellKind;
  /** 自定义取值；省略时读 `row[key]`。 */
  value?: (row: T) => unknown;
}
