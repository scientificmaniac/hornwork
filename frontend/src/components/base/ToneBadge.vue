<script setup lang="ts">
import { computed } from 'vue';

import type { Tone } from '@/types/common';
import { deltaLabel, deltaTone, severityTone, statusLabel, statusTone } from '@/utils/badge';

/**
 * 语义徽章：严重级 / 状态 / 四态 diff 的统一渲染。
 *
 * 这里只做「值 → 语义 → Element Plus 类型」的映射，
 * 旧的 `sevBadge()` / `statusBadge()` 正则判断集中到了 `utils/badge.ts`。
 */
const props = withDefaults(
  defineProps<{
    value: unknown;
    kind?: 'severity' | 'status' | 'delta';
    /** 覆盖展示文本（如把 level 数字显示成 `L12`）。 */
    label?: string;
    size?: 'large' | 'default' | 'small';
  }>(),
  { kind: 'status', label: '', size: 'small' },
);

const EL_TYPES: Record<Tone, 'danger' | 'warning' | 'success' | 'info' | ''> = {
  danger: 'danger',
  warning: 'warning',
  success: 'success',
  info: 'info',
  neutral: '',
};

const tone = computed<Tone>(() => {
  if (props.kind === 'severity') return severityTone(props.value);
  if (props.kind === 'delta') return deltaTone(props.value);
  return statusTone(props.value);
});

const text = computed(() => {
  if (props.label) return props.label;
  if (props.kind === 'delta') return deltaLabel(props.value);
  if (props.kind === 'severity') {
    return props.value === null || props.value === undefined || props.value === ''
      ? '-'
      : String(props.value);
  }
  return statusLabel(props.value);
});
</script>

<template>
  <el-tag :type="EL_TYPES[tone]" :size="size" disable-transitions>{{ text }}</el-tag>
</template>
