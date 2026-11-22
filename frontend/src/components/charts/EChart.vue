<script setup lang="ts">
/**
 * ECharts 轻量封装。
 *
 * 按需注册（只引入用到的图表与组件）以控制体积；`option` 由调用方传入，
 * 组件只负责生命周期（初始化 / 尺寸变化 / 销毁），避免每个页面重复样板。
 */
import { onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue';

import { BarChart, LineChart, PieChart } from 'echarts/charts';
import {
  DatasetComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from 'echarts/components';
import * as echarts from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import type { EChartsOption } from 'echarts';

echarts.use([
  BarChart,
  LineChart,
  PieChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  DatasetComponent,
  CanvasRenderer,
]);

const props = withDefaults(
  defineProps<{
    option: EChartsOption;
    height?: string;
    /** 无数据时展示的文案（覆盖图表默认的空白画布）。 */
    emptyText?: string;
    empty?: boolean;
  }>(),
  { height: '260px', emptyText: '暂无数据', empty: false },
);

const container = ref<HTMLDivElement | null>(null);
const chart = shallowRef<echarts.ECharts | null>(null);
// 主题切换需要重新 init：浅色/深色下坐标轴文字颜色不同
let observer: ResizeObserver | null = null;

function render(): void {
  if (!container.value) return;
  if (!chart.value) chart.value = echarts.init(container.value, undefined, { renderer: 'canvas' });
  chart.value.setOption(props.option, true);
}

onMounted(() => {
  render();
  if (container.value && typeof ResizeObserver !== 'undefined') {
    observer = new ResizeObserver(() => chart.value?.resize());
    observer.observe(container.value);
  }
});

watch(
  () => props.option,
  () => {
    if (props.empty) return;
    render();
  },
  { deep: true },
);

watch(
  () => props.empty,
  (empty) => {
    if (!empty) render();
  },
);

onBeforeUnmount(() => {
  observer?.disconnect();
  observer = null;
  chart.value?.dispose();
  chart.value = null;
});
</script>

<template>
  <div class="chart">
    <div v-show="!empty" ref="container" class="chart__canvas" :style="{ height }" />
    <div v-if="empty" class="chart__empty" :style="{ height }">{{ emptyText }}</div>
  </div>
</template>

<style scoped>
.chart {
  width: 100%;
  min-width: 0;
}
.chart__canvas {
  width: 100%;
}
.chart__empty {
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-faint);
  font-size: 12px;
}
</style>
