<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';

import ToneBadge from '@/components/base/ToneBadge.vue';
import EChart from '@/components/charts/EChart.vue';
import { detectionApi } from '@/api/modules/detection';
import { useAsync } from '@/composables/useAsync';
import type { IntelPayload, IocRecord } from '@/types/detection';
import { formatNumber, formatTime } from '@/utils/format';
import { doughnutOption, countEntries } from '@/utils/charts';
import { IOC_STATUS_OPTIONS, IOC_TYPE_OPTIONS } from '@/utils/options';

const intel = useAsync<IntelPayload>({ items: [], by_type: {} });
const filter = reactive({ kind: '', status: '', limit: 500 });

const importVisible = ref(false);
const importText = ref('');
const importing = ref(false);

/** 后端限制请求体 2MB，贴入大量 records 时先在本地拦一下。 */
const IMPORT_LIMIT_BYTES = 2 * 1024 * 1024;
const IMPORT_PLACEHOLDER =
  '[{"type":"domain","value":"evil.example.com","confidence":80,"source":"manual"}]';

const importSize = computed(() => new Blob([importText.value]).size);
const importTooLarge = computed(() => importSize.value > IMPORT_LIMIT_BYTES);

function load(): Promise<IntelPayload | null> {
  return intel.run(() =>
    detectionApi.intel({
      kind: filter.kind || undefined,
      status: filter.status || undefined,
      limit: filter.limit,
    }),
  );
}

const typeChart = computed(() =>
  doughnutOption(countEntries(intel.data.value.by_type), [
    '#1f5fbf',
    '#b00020',
    '#a15c00',
    '#1b6e2a',
    '#8a94a3',
  ]),
);

function openImport(): void {
  importText.value = '';
  importVisible.value = true;
}

/** 解析并校验贴入的 records（数组，或带 records 字段的对象）。 */
function parseRecords(): IocRecord[] {
  const parsed: unknown = JSON.parse(importText.value);
  const list = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === 'object' && Array.isArray((parsed as { records?: unknown }).records)
      ? (parsed as { records: unknown[] }).records
      : null;
  if (!list) throw new Error('应为 records 数组，或形如 {"records": [...]} 的对象');
  if (list.length === 0) throw new Error('records 为空');
  return list as IocRecord[];
}

async function submitImport(): Promise<void> {
  if (importTooLarge.value) return;
  importing.value = true;
  try {
    const records = parseRecords();
    const result = await detectionApi.importIntel(records);
    ElMessage.success(
      `导入完成：新增 ${result.imported ?? 0} 条，跳过 ${result.skipped ?? 0} 条，共 ${result.total ?? records.length} 条`,
    );
    importVisible.value = false;
    importText.value = '';
    await load();
  } catch (cause) {
    ElMessage.error(cause instanceof Error ? cause.message : String(cause));
  } finally {
    importing.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>
        情报（IOC）
        <span class="head-note">导入只接受 records 数组；服务端路径导入请用 hornworkctl intel</span>
      </template>

      <div class="toolbar">
        <el-select v-model="filter.kind" placeholder="类型" clearable @change="load">
          <el-option v-for="option in IOC_TYPE_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
        </el-select>
        <el-select v-model="filter.status" placeholder="状态" clearable @change="load">
          <el-option v-for="option in IOC_STATUS_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
        </el-select>
        <el-select v-model="filter.limit" class="is-wide" @change="load">
          <el-option :value="500" label="每页 500 条" />
          <el-option :value="2000" label="每页 2000 条" />
          <el-option :value="5000" label="每页 5000 条" />
        </el-select>
        <el-button :loading="intel.loading.value" @click="load">刷新</el-button>
        <span class="spacer" />
        <el-button type="primary" @click="openImport">导入 IOC</el-button>
      </div>

      <el-alert v-if="intel.error.value" :title="intel.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="intel.softError.value" :title="intel.softError.value" type="warning" :closable="false" show-icon />

      <div class="chart-wrap">
        <EChart
          :option="typeChart"
          height="200px"
          :empty="Object.keys(intel.data.value.by_type).length === 0"
          empty-text="暂无 IOC 分布"
        />
      </div>

      <el-table v-loading="intel.loading.value" :data="intel.data.value.items" size="small" empty-text="暂无情报记录">
        <el-table-column label="值" min-width="220" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.value }}</span></template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="96" />
        <el-table-column label="置信度" width="90">
          <template #default="{ row }"><span class="mono">{{ row.confidence ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column prop="tlp" label="TLP" width="80" />
        <el-table-column label="来源" width="140" show-overflow-tooltip>
          <template #default="{ row }">{{ row.source ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="首次出现" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.first_seen) }}</span></template>
        </el-table-column>
        <el-table-column label="过期时间" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.expires_at) }}</span></template>
        </el-table-column>
      </el-table>

      <p class="muted footer-note">共 {{ formatNumber(intel.data.value.items.length) }} 条</p>
    </el-card>

    <el-dialog v-model="importVisible" title="导入 IOC records" width="640px">
      <el-alert
        title="支持贴入 JSON 数组（每项含 type / value，可选 confidence / tlp / source / expires_at）；单次请求上限 2MB。"
        type="info"
        :closable="false"
        show-icon
      />
      <el-input
        v-model="importText"
        type="textarea"
        :rows="12"
        :placeholder="IMPORT_PLACEHOLDER"
        class="import-input"
      />
      <div class="import-meta">
        <span :class="{ 'error-text': importTooLarge }">
          {{ formatNumber(importSize) }} / 2097152 字节
        </span>
      </div>
      <template #footer>
        <el-button @click="importVisible = false">取消</el-button>
        <el-button
          type="primary"
          :loading="importing"
          :disabled="!importText.trim() || importTooLarge"
          @click="submitImport"
        >
          提交导入
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.head-note {
  margin-left: 10px;
  font-size: 11px;
  font-weight: 400;
  color: var(--text-faint);
}
.chart-wrap {
  max-width: 420px;
  margin-bottom: 12px;
}
.import-input {
  margin-top: 10px;
  font-family: var(--font-mono);
}
.import-meta {
  margin-top: 6px;
  font-size: 11px;
  color: var(--text-faint);
}
.error-text {
  color: var(--tone-danger);
}
.footer-note {
  margin: 8px 0 0;
  font-size: 11px;
}
</style>
