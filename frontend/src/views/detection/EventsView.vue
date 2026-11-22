<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';

import { detectionApi } from '@/api/modules/detection';
import { useAsync } from '@/composables/useAsync';
import { useReport } from '@/composables/useReport';
import type { ListPayload } from '@/types/common';
import type { CanonicalEvent } from '@/types/detection';
import { EVENT_TYPES } from '@/types/detection';
import { formatJson, formatTime, summarize } from '@/utils/format';
import { SINCE_OPTIONS, SOURCE_LAYER_OPTIONS } from '@/utils/options';

const list = useAsync<ListPayload<CanonicalEvent>>({ items: [], total: 0 });
const types = ref<{ type: string; n: number }[]>([]);

const filter = reactive({
  type: '',
  layer: '',
  since: '24h',
  limit: 100,
});

const detail = ref<CanonicalEvent | null>(null);
const drawerVisible = ref(false);

const exporter = useReport();

/** 类型下拉：合并后端实际出现过的类型（带计数）与常量表，保证不丢未知值。 */
const typeOptions = computed<{ label: string; value: string }[]>(() => {
  const seen = new Map(types.value.map((item) => [item.type, item.n]));
  const known = EVENT_TYPES.map((type) => ({
    label: seen.has(type) ? `${type}（${seen.get(type)}）` : type,
    value: type,
  }));
  const extra = types.value
    .filter((item) => !EVENT_TYPES.includes(item.type as (typeof EVENT_TYPES)[number]))
    .map((item) => ({ label: `${item.type}（${item.n}）`, value: item.type }));
  return [...known, ...extra];
});

function load(): Promise<ListPayload<CanonicalEvent> | null> {
  return list.run(() =>
    detectionApi.events({
      type: filter.type || undefined,
      layer: filter.layer || undefined,
      since: filter.since || undefined,
      limit: filter.limit,
    }),
  );
}

function openDetail(row: CanonicalEvent): void {
  detail.value = row;
  drawerVisible.value = true;
}

function resetFilter(): void {
  filter.type = '';
  filter.layer = '';
  filter.since = '24h';
  filter.limit = 100;
  void load();
}

/** 事件详情按语义分组展示，避免把整个 payload 平铺成一坨 JSON。 */
const detailGroups = computed(() => {
  const row = detail.value;
  if (!row) return [];
  const groups: { title: string; data: Record<string, unknown> }[] = [
    {
      title: '标识',
      data: {
        event_id: row.event_id,
        ts: row.ts,
        event_type: row.event_type,
        source_layer: row.source_layer,
        source_product: row.source_product,
      },
    },
  ];
  for (const [title, key] of [
    ['主机', 'host'],
    ['进程', 'process'],
    ['文件', 'file'],
    ['网络', 'network'],
    ['用户', 'user'],
    ['原始载荷', 'raw'],
  ] as const) {
    const value = row[key];
    if (value && typeof value === 'object') {
      groups.push({ title, data: value as Record<string, unknown> });
    }
  }
  return groups.filter((group) => Object.keys(group.data).length > 0);
});

onMounted(async () => {
  await load();
  types.value = await detectionApi.eventTypes().catch(() => []);
});
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>事件流</template>

      <div class="toolbar">
        <el-select v-model="filter.type" placeholder="事件类型" clearable filterable @change="load">
          <el-option
            v-for="option in typeOptions"
            :key="option.value"
            :label="option.label"
            :value="option.value"
          />
        </el-select>
        <el-select v-model="filter.layer" placeholder="来源层" clearable @change="load">
          <el-option
            v-for="option in SOURCE_LAYER_OPTIONS"
            :key="option.value"
            :label="option.label"
            :value="option.value"
          />
        </el-select>
        <el-select v-model="filter.since" class="is-wide" @change="load">
          <el-option
            v-for="option in SINCE_OPTIONS"
            :key="option.value"
            :label="option.label"
            :value="option.value"
          />
        </el-select>
        <el-select v-model="filter.limit" class="is-wide" @change="load">
          <el-option :value="100" label="每页 100 条" />
          <el-option :value="300" label="每页 300 条" />
          <el-option :value="1000" label="每页 1000 条（上限）" />
        </el-select>
        <el-button :loading="list.loading.value" @click="load">刷新</el-button>
        <el-button text @click="resetFilter">重置</el-button>
        <span class="spacer" />
        <el-button :loading="exporter.busy.value" @click="exporter.exportAs('events', 'jsonl', filter.since)">
          导出 JSONL
        </el-button>
        <el-button :loading="exporter.busy.value" @click="exporter.exportAs('events', 'md', filter.since)">
          导出 Markdown
        </el-button>
      </div>

      <el-alert v-if="list.error.value" :title="list.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="list.softError.value" :title="list.softError.value" type="warning" :closable="false" show-icon />
      <el-alert v-if="exporter.error.value" :title="exporter.error.value" type="error" :closable="false" show-icon />

      <el-table
        v-loading="list.loading.value"
        :data="list.data.value.items"
        size="small"
        empty-text="所选条件下没有事件"
        @row-click="openDetail"
      >
        <el-table-column label="时间" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.ts) }}</span></template>
        </el-table-column>
        <el-table-column label="类型" width="150">
          <template #default="{ row }">
            <el-tag size="small" type="info" disable-transitions>{{ row.event_type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="来源层" width="92">
          <template #default="{ row }">{{ row.source_layer ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="来源组件" width="130" show-overflow-tooltip>
          <template #default="{ row }">{{ row.source_product ?? row._row?.engine ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="主机" width="130" show-overflow-tooltip>
          <template #default="{ row }">{{ row.host?.host_id ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="摘要" min-width="260">
          <template #default="{ row }">
            <span class="muted">{{ summarize(row.process ?? row.file ?? row.network ?? row.raw, 140) }}</span>
          </template>
        </el-table-column>
      </el-table>

      <p class="muted footer-note">
        共 {{ list.data.value.items.length }} 条；后端只支持 limit 截断（无 offset 分页），
        需要更早数据请提高条数或放宽时间范围。
      </p>
    </el-card>

    <el-drawer v-model="drawerVisible" title="事件详情" size="620px">
      <template v-if="detail">
        <div class="row detail-head">
          <el-tag size="small" disable-transitions>{{ detail.event_type }}</el-tag>
          <span class="mono muted">{{ detail.event_id ?? '-' }}</span>
        </div>
        <el-collapse>
          <el-collapse-item
            v-for="group in detailGroups"
            :key="group.title"
            :title="group.title"
            :name="group.title"
          >
            <pre class="json-block">{{ formatJson(group.data) }}</pre>
          </el-collapse-item>
        </el-collapse>
        <el-divider content-position="left">完整事件</el-divider>
        <pre class="json-block">{{ formatJson(detail) }}</pre>
      </template>
    </el-drawer>
  </div>
</template>

<style scoped>
.detail-head {
  margin-bottom: 10px;
}
.footer-note {
  margin: 8px 0 0;
  font-size: 11px;
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
