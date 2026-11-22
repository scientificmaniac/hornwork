<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';

import StatCard from '@/components/base/StatCard.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import { scanApi } from '@/api/modules/scan';
import { useAsync } from '@/composables/useAsync';
import type { Finding } from '@/types/scan';
import { formatFloat, formatNumber, formatTime, summarize } from '@/utils/format';
import { FINDING_KIND_OPTIONS, FINDING_STATUS_OPTIONS, SEVERITY_OPTIONS } from '@/utils/options';

/** 事实类 kind 不可处置，问题类才可能转工单（当前写能力仅 CLI）。 */
const FACT_KINDS = new Set(['port', 'component']);

const findings = useAsync<{ items: Finding[]; total: number }>({ items: [], total: 0 });
const filter = reactive({ severity: '', status: '', kind: '', asset: '', limit: 200 });

const detail = ref<Finding | null>(null);
const drawerVisible = ref(false);

function load(): Promise<{ items: Finding[]; total: number } | null> {
  return findings.run(() =>
    scanApi.findings({
      severity: filter.severity || undefined,
      status: filter.status || undefined,
      kind: filter.kind || undefined,
      asset: filter.asset.trim() || undefined,
      limit: filter.limit,
    }),
  );
}

function resetFilter(): void {
  filter.severity = '';
  filter.status = '';
  filter.kind = '';
  filter.asset = '';
  filter.limit = 200;
  void load();
}

function openDetail(row: Finding): void {
  detail.value = row;
  drawerVisible.value = true;
}

/** 按严重级统计（当前结果集，用于顶部卡）。 */
const severityCounts = computed(() => {
  const counts: Record<string, number> = {};
  for (const item of findings.data.value.items) {
    const key = String(item.severity ?? '无');
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
});

const issueCount = computed(
  () => findings.data.value.items.filter((item) => !FACT_KINDS.has(String(item.kind))).length,
);

function isFact(row: Finding): boolean {
  return FACT_KINDS.has(String(row.kind));
}

const evidence = computed(() => detail.value?.evidence ?? {});

onMounted(load);
</script>

<template>
  <div class="stack">
    <div class="grid-cards">
      <StatCard label="问题项" :value="formatNumber(findings.data.value.total)" hint="按当前筛选" tone="warning" />
      <StatCard label="其中问题类" :value="formatNumber(issueCount)" hint="可确认 / 转工单（需 CLI）" tone="danger" />
      <StatCard label="严重" :value="formatNumber(severityCounts['严重'] ?? 0)" tone="danger" />
      <StatCard label="高" :value="formatNumber(severityCounts['高'] ?? 0)" tone="warning" />
      <StatCard label="中" :value="formatNumber(severityCounts['中'] ?? 0)" tone="info" />
      <StatCard label="低 / 无" :value="formatNumber((severityCounts['低'] ?? 0) + (severityCounts['无'] ?? 0))" tone="success" />
    </div>

    <el-card shadow="never">
      <template #header>
        问题清单
        <span class="head-note">port / component 是资产事实，不可处置；cve / config / tls / web 是问题，需 CLI 确认</span>
      </template>

      <div class="toolbar">
        <el-select v-model="filter.severity" placeholder="严重级" clearable @change="load">
          <el-option v-for="option in SEVERITY_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
        </el-select>
        <el-select v-model="filter.status" placeholder="状态" clearable @change="load">
          <el-option v-for="option in FINDING_STATUS_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
        </el-select>
        <el-select v-model="filter.kind" class="is-wide" placeholder="类型" clearable @change="load">
          <el-option v-for="option in FINDING_KIND_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
        </el-select>
        <el-input v-model="filter.asset" placeholder="资产 ID" clearable @keyup.enter="load" />
        <el-select v-model="filter.limit" class="is-wide" @change="load">
          <el-option :value="200" label="每页 200 条" />
          <el-option :value="500" label="每页 500 条" />
          <el-option :value="2000" label="每页 2000 条" />
        </el-select>
        <el-button :loading="findings.loading.value" @click="load">刷新</el-button>
        <el-button text @click="resetFilter">重置</el-button>
      </div>

      <el-alert v-if="findings.error.value" :title="findings.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="findings.softError.value" :title="findings.softError.value" type="warning" :closable="false" show-icon />

      <el-table
        v-loading="findings.loading.value"
        :data="findings.data.value.items"
        size="small"
        empty-text="所选条件下没有问题项"
        @row-click="openDetail"
      >
        <el-table-column prop="finding_id" label="finding" width="170" show-overflow-tooltip />
        <el-table-column label="资产" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">{{ row.asset_hostname || row.asset_ip || row.asset_id || '-' }}</template>
        </el-table-column>
        <el-table-column label="类型" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="isFact(row) ? 'info' : 'warning'" disable-transitions>
              {{ row.kind ?? '-' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="check_id" label="检查项" width="150" show-overflow-tooltip />
        <el-table-column prop="title" label="标题" min-width="200" show-overflow-tooltip />
        <el-table-column label="严重级" width="92">
          <template #default="{ row }"><ToneBadge :value="row.severity" kind="severity" /></template>
        </el-table-column>
        <el-table-column label="CVSS" width="80">
          <template #default="{ row }"><span class="mono">{{ formatFloat(row.cvss) }}</span></template>
        </el-table-column>
        <el-table-column label="置信度" width="88">
          <template #default="{ row }"><span class="mono">{{ formatFloat(row.confidence) }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="最近发现" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.last_seen) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-drawer v-model="drawerVisible" title="问题项详情" size="620px">
      <template v-if="detail">
        <div class="row detail-head">
          <ToneBadge :value="detail.severity" kind="severity" />
          <ToneBadge :value="detail.status" />
          <el-tag size="small" type="info" disable-transitions>{{ detail.kind }}</el-tag>
        </div>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="finding">{{ detail.finding_id }}</el-descriptions-item>
          <el-descriptions-item label="检查项">{{ detail.check_id ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="资产">{{ detail.asset_id ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="目标">{{ detail.target ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="CVSS">{{ formatFloat(detail.cvss) }}（{{ detail.cvss_source ?? '-' }}）</el-descriptions-item>
          <el-descriptions-item label="置信度">{{ formatFloat(detail.confidence) }}</el-descriptions-item>
          <el-descriptions-item label="漏洞引用">{{ detail.vuln_ref ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="快照">{{ detail.snapshot_id ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="首次发现">{{ formatTime(detail.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="最近发现">{{ formatTime(detail.last_seen) }}</el-descriptions-item>
        </el-descriptions>

        <el-divider content-position="left">证据链</el-divider>
        <pre v-if="Object.keys(evidence).length > 0" class="json-block">{{ summarize(evidence, 4000) }}</pre>
        <p v-else class="muted">没有 evidence 字段（该 finding 由列字段直接得出）</p>

        <p v-if="!isFact(detail)" class="hint">
          确认 / 标记误报 / 转工单请执行：<code>hornworkctl scan finding confirm {{ detail.finding_id }}</code>
        </p>
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
.hint {
  margin-top: 14px;
  font-size: 11px;
  color: var(--text-faint);
}
.hint code {
  font-family: var(--font-mono);
  background: var(--surface-alt);
  padding: 1px 5px;
  border-radius: 3px;
}
</style>
