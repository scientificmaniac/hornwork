<script setup lang="ts">
import { computed } from 'vue';

import type { Tone } from '@/types/common';

const props = withDefaults(
  defineProps<{
    label: string;
    value: string | number;
    hint?: string;
    tone?: Tone;
  }>(),
  { hint: '', tone: 'neutral' },
);

const hintText = computed(() => props.hint ?? '');
</script>

<template>
  <div class="stat-card" :data-tone="props.tone">
    <div class="stat-card__label">{{ props.label }}</div>
    <div class="stat-card__value">{{ props.value }}</div>
    <div v-if="hintText" class="stat-card__hint">{{ hintText }}</div>
  </div>
</template>

<style scoped>
.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--border-strong);
  border-radius: 6px;
  padding: 11px 13px;
  min-width: 0;
}
.stat-card[data-tone='danger'] {
  border-left-color: var(--tone-danger);
}
.stat-card[data-tone='warning'] {
  border-left-color: var(--tone-warning);
}
.stat-card[data-tone='success'] {
  border-left-color: var(--tone-success);
}
.stat-card[data-tone='info'] {
  border-left-color: var(--tone-info);
}
.stat-card__label {
  font-size: 12px;
  color: var(--text-muted);
}
.stat-card__value {
  margin-top: 4px;
  font-size: 21px;
  font-weight: 600;
  color: var(--text-strong);
  font-family: var(--font-mono);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.stat-card__hint {
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-faint);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
