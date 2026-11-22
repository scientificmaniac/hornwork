/**
 * ECharts 配置构造：把「后端数据 → option」的重复劳动集中一处。
 *
 * 只做通用图形（折线 / 环形 / 柱状），特殊图形由页面自行组装 option。
 * 颜色取自设计变量，避免图表与页面主题脱节。
 */

import type { EChartsOption } from 'echarts';

/** 语义色（与 tokens.css 的浅色主题取值一致；图表用固定色，跟随主题变化代价过高）。 */
export const CHART_COLORS = {
  primary: '#1f5fbf',
  success: '#1b6e2a',
  warning: '#a15c00',
  danger: '#b00020',
  info: '#3a7bd5',
  neutral: '#8a94a3',
} as const;

/** 多系列折线图（时间轴按分类轴处理，避免时区问题）。 */
export function lineOption(params: {
  categories: string[];
  series: { name: string; data: number[]; color?: string }[];
  yName?: string;
}): EChartsOption {
  return {
    color: params.series.map((item) => item.color ?? CHART_COLORS.primary),
    tooltip: { trigger: 'axis' },
    legend: { top: 0, type: 'scroll' },
    grid: { left: 12, right: 16, top: 34, bottom: 6, containLabel: true },
    xAxis: {
      type: 'category',
      data: params.categories,
      axisLine: { lineStyle: { color: '#c3ccd8' } },
      axisLabel: { color: '#5b6878', fontSize: 11 },
    },
    yAxis: {
      type: 'value',
      name: params.yName,
      nameTextStyle: { color: '#8a94a3', fontSize: 11 },
      splitLine: { lineStyle: { color: '#eef1f6' } },
      axisLabel: { color: '#5b6878', fontSize: 11 },
    },
    series: params.series.map((item) => ({
      name: item.name,
      type: 'line',
      smooth: true,
      showSymbol: params.categories.length <= 12,
      data: item.data,
    })),
  };
}

/** 环形图：`entries` 为 `[名称, 数值]`，值为 0 的项自动过滤。 */
export function doughnutOption(
  entries: [string, number][],
  colors: string[] = [
    CHART_COLORS.danger,
    CHART_COLORS.warning,
    CHART_COLORS.info,
    CHART_COLORS.success,
    CHART_COLORS.neutral,
  ],
): EChartsOption {
  const data = entries.filter(([, value]) => value > 0).map(([name, value]) => ({ name, value }));
  return {
    color: colors,
    tooltip: { trigger: 'item', formatter: '{b}: {c}（{d}%）' },
    legend: { bottom: 0, type: 'scroll' },
    series: [
      {
        type: 'pie',
        radius: ['46%', '68%'],
        center: ['50%', '44%'],
        avoidLabelOverlap: true,
        itemStyle: { borderColor: '#fff', borderWidth: 1 },
        label: { show: false },
        data,
      },
    ],
  };
}

/** 竖向柱状图（CVE 年份分布等）。 */
export function barOption(
  categories: string[],
  values: number[],
  color: string = CHART_COLORS.primary,
): EChartsOption {
  return {
    color: [color],
    tooltip: { trigger: 'axis' },
    grid: { left: 12, right: 16, top: 20, bottom: 6, containLabel: true },
    xAxis: {
      type: 'category',
      data: categories,
      axisLabel: { color: '#5b6878', fontSize: 11 },
      axisLine: { lineStyle: { color: '#c3ccd8' } },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: '#eef1f6' } },
      axisLabel: { color: '#5b6878', fontSize: 11 },
    },
    series: [{ type: 'bar', data: values, barMaxWidth: 28 }],
  };
}

/** 横向柱状图（事件类型 TopN：类目名较长，横排更易读）。 */
export function hBarOption(entries: [string, number][], color: string = CHART_COLORS.info): EChartsOption {
  const sorted = [...entries].sort((a, b) => a[1] - b[1]);
  return {
    color: [color],
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 12, right: 24, top: 10, bottom: 6, containLabel: true },
    xAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: '#eef1f6' } },
      axisLabel: { color: '#5b6878', fontSize: 11 },
    },
    yAxis: {
      type: 'category',
      data: sorted.map(([name]) => name),
      axisLabel: { color: '#5b6878', fontSize: 11 },
      axisLine: { lineStyle: { color: '#c3ccd8' } },
    },
    series: [{ type: 'bar', data: sorted.map(([, value]) => value), barMaxWidth: 18 }],
  };
}

/** 对象计数 → `[名称, 数值]` 数组（按数值降序）。 */
export function countEntries(map: Record<string, number>): [string, number][] {
  return Object.entries(map).sort((a, b) => b[1] - a[1]);
}
