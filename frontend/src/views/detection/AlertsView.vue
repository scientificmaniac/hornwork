<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';

import ToneBadge from '@/components/base/ToneBadge.vue';
import { detectionApi } from '@/api/modules/detection';
import { useAsync } from '@/composables/useAsync';
import { usePolling } from '@/composables/usePolling';
import { useReport } from '@/composables/useReport';
import type { ListPayload } from '@/types/common';
import type { Alert } from '@/types/detection';
import { formatJson, formatNumber, formatTime, summarize } from '@/utils/format';
import { LEVEL_OPTIONS, SINCE_OPTIONS } from '@/utils/options';

const list = useAsync<ListPayload<Alert>>({ items: [], total: 0 });
const filter = reactive({ since: '24h', levelMin: '', technique: '', ruleId: '', limit: 100 });

const detail = ref<Alert | null>(null);
const drawerVisible = ref(false);
const exporter = useReport();
/** 实时流：默认关闭，避免用户没意识到时持续打库。 */
const live = ref(false);

function load(): Promise<ListPayload<Alert> | null> {
  return list.run(() =>
    detectionApi.alerts({
      since: filter.since || undefined,
      level_min: filter.levelMin || undefined,
      technique: filter.technique.trim() || undefined,
      rule_id: filter.ruleId.trim() || undefined,
      limit: filter.limit,
    }),
  );
}

const poller = usePolling(load, { interval: 10_000, immediate: false });

function toggleLive(): void {
  if (live.value) {
    poller.start();
  } else {
    poller.stop();
  }
}

function resetFilter(): void {
  filter.since = '24h';
  filter.levelMin = '';
  filter.technique = '';
  filter.ruleId = '';
  filter.limit = 100;
  void load();
}

function openDetail(row: Alert): void {
  detail.value = row;
  drawerVisible.value = true;
}

/** 证据链分组：告警的价值在“为什么响”，这里把它单独拎出来。 */
const evidence = computed(() => {
  const row = detail.value;
  if (!row) return [];
  const blocks: { title: string; data: unknown }[] = [
    { title: '规则', data: row.rule ?? {} },
    { title: '证据链 evidence', data: row.evidence ?? [] },
    { title: '引擎贡献 contrib', data: row.contrib ?? {} },
    { title: '情报命中 intel', data: row.intel ?? {} },
    { title: '主机', data: row.host ?? {} },
  ];
  return blocks.filter((block) => {
    const value = block.data;
    if (Array.isArray(value)) return value.length > 0;
    if (value && typeof value === 'object') return Object.keys(value).length > 0;
    return Boolean(value);
  });
});

const levelCounts = computed(() => {
  const buckets: Record<string, number> = { 严重: 0, 高: 0, 中: 0, 低: 0, 信息: 0 };
  for (const alert of list.data.value.items) {
    const level = Number(alert.level ?? 0);
    if (level >= 12) buckets['严重'] += 1;
    else if (level >= 9) buckets['高'] += 1;
    else if (level >= 6) buckets['中'] += 1;
    else if (level >= 3) buckets['低'] += 1;
    else buckets['信息'] += 1;
  }
  return buckets;
});

onMounted(load);
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>
        告警
        <span class="head-note">按级别与 ATT&CK 技术筛选；点击行查看证据链</span>
      </template>

      <div class="toolbar">
        <el-select v-model="filter.since" class="is-wide" @change="load">
          <el-option v-for="option in SINCE_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
        </el-select>
        <el-select v-model="filter.levelMin" placeholder="级别下限" clearable @change="load">
          <el-option v-for="option in LEVEL_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
        </el-select>
        <el-input v-model="filter.technique" placeholder="ATT&CK（T1059）" clearable @keyup.enter="load" />
        <el-input v-model="filter.ruleId" placeholder="规则 ID" clearable @keyup.enter="load" />
        <el-select v-model="filter.limit" class="is-wide" @change="load">
          <el-option :value="100" label="每页 100 条" />
          <el-option :value="500" label="每页 500 条" />
          <el-option :value="1000" label="每页 1000 条" />
        </el-select>
        <el-button :loading="list.loading.value" @click="load">刷新</el-button>
        <el-button text @click="resetFilter">重置</el-button>
        <span class="spacer" />
        <el-switch v-model="live" active-text="实时（10s）" @change="toggleLive" />
        <el-button :loading="exporter.busy.value" @click="exporter.exportAs('alerts', 'jsonl', filter.since)">
          导出
        </el-button>
      </div>

      <div class="level-summary">
        <span v-for="(count, label) in levelCounts" :key="label" class="level-item">
          <ToneBadge :value="label" kind="severity" :label="label" />
          <span class="mono">{{ formatNumber(count) }}</span>
        </span>
      </div>

      <el-alert v-if="list.error.value" :title="list.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="list.softError.value" :title="list.softError.value" type="warning" :closable="false" show-icon />
      <el-alert v-if="poller.lastError.value" :title="`实时刷新失败：${poller.lastError.value}`" type="warning" :closable="false" show-icon />
      <el-alert v-if="exporter.error.value" :title="exporter.error.value" type="error" :closable="false" show-icon />

      <el-table
        v-loading="list.loading.value"
        :data="list.data.value.items"
        size="small"
        empty-text="所选条件下没有告警"
        @row-click="openDetail"
      >
        <el-table-column label="时间" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.ts) }}</span></template>
        </el-table-column>
        <el-table-column label="级别" width="88">
          <template #default="{ row }">
            <ToneBadge :value="row.level" kind="severity" :label="`L${row.level ?? 0}`" />
          </template>
        </el-table-column>
        <el-table-column label="规则" min-width="180" show-overflow-tooltip>
          <template #default="{ row }">{{ row.rule?.name ?? row.rule?.id ?? row.rule_id ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="技术" width="120">
          <template #default="{ row }"><span class="mono">{{ row.technique ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column label="主机" width="130" show-overflow-tooltip>
          <template #default="{ row }">{{ row.host?.host_id ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="92">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="证据摘要" min-width="220">
          <template #default="{ row }">
            <span class="muted">{{ summarize(row.evidence?.[0] ?? row.raw, 110) }}</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-drawer v-model="drawerVisible" title="告警详情" size="640px">
      <template v-if="detail">
        <div class="row detail-head">
          <ToneBadge :value="detail.level" kind="severity" :label="`L${detail.level ?? 0}`" />
          <ToneBadge :value="detail.status" />
          <span class="mono muted">{{ detail.alert_id ?? '-' }}</span>
        </div>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="规则">{{ detail.rule?.name ?? detail.rule?.id ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="技术">{{ detail.technique ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="置信度">{{ detail.confidence ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="去重键">
            <span class="mono">{{ detail.dedup_key ?? '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="时间">{{ formatTime(detail.ts) }}</el-descriptions-item>
          <el-descriptions-item label="引擎">{{ detail._row?.engine ?? detail.rule?.engine ?? '-' }}</el-descriptions-item>
        </el-descriptions>

        <el-divider content-position="left">证据链</el-divider>
        <el-collapse>
          <el-collapse-item v-for="block in evidence" :key="block.title" :title="block.title" :name="block.title">
            <pre class="json-block">{{ formatJson(block.data) }}</pre>
          </el-collapse-item>
        </el-collapse>
        <el-divider content-position="left">完整告警</el-divider>
        <pre class="json-block">{{ formatJson(detail) }}</pre>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.head-note {
  margin-left: 10px;
  font-size: 11px;
  font-weight: 400;
  color: var(--text-faint);
}
.level-summary {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  margin-bottom: 10px;
  font-size: 12px;
}
.level-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.detail-head {
  margin-bottom: 10px;
}
.json-block {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text-muted);
  background: var(--surface-alt);
  border-radius: 4px;
  padding: 8px 10px;
}
</style>
