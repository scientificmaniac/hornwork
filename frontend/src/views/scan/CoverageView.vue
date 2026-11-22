<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';

import ToneBadge from '@/components/base/ToneBadge.vue';
import { scanApi } from '@/api/modules/scan';
import { useAsync } from '@/composables/useAsync';
import type { CoveragePayload, Snapshot } from '@/types/scan';
import { formatNumber, formatPercent, formatTime } from '@/utils/format';

const coverage = useAsync<CoveragePayload>({
  coverage: 0,
  by_domain: {},
  matrix: [],
  uncovered: [],
});
const snapshots = ref<Snapshot[]>([]);
const snapshotId = ref('');

function load(): Promise<CoveragePayload | null> {
  return coverage.run(() => scanApi.coverage(snapshotId.value || undefined));
}

/** 单格 covered 值 → 展示与配色（1 绿 / 0.5 黄 / 0 红 / 不适用灰）。 */
function cellOf(row: { domains: Record<string, number> }, domain: string): number | null {
  const value = row.domains?.[domain];
  return typeof value === 'number' ? value : null;
}

function cellText(row: { domains: Record<string, number> }, domain: string): string {
  const value = cellOf(row, domain);
  if (value === null) return '—';
  return value >= 1 ? '✓' : value > 0 ? '半' : '×';
}

function cellClass(row: { domains: Record<string, number> }, domain: string): string {
  const value = cellOf(row, domain);
  if (value === null) return 'cell--na';
  if (value >= 1) return 'cell--done';
  if (value > 0) return 'cell--partial';
  return 'cell--missing';
}

const domains = computed(() => Object.keys(coverage.data.value.by_domain).sort());
const domainRows = computed(() =>
  Object.entries(coverage.data.value.by_domain).map(([code, bucket]) => ({ code, ...bucket })),
);

/** 顶部环形图用 el-progress 表达即可，无需引入额外图表类型。 */
const coveragePercent = computed(() => Math.round(coverage.data.value.coverage * 100));

const uncoveredRows = computed(() => coverage.data.value.uncovered.slice(0, 200));

onMounted(async () => {
  const result = await scanApi.snapshots(20).catch(() => ({ items: [], total: 0 }));
  snapshots.value = result.items;
  if (result.items.length > 0) snapshotId.value = result.items[0].snapshot_id;
  await load();
});
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>
        覆盖率
        <span class="head-note">
          按“资产 × 检查域”逐格判定：done=1 / partial=0.5 / 缺失=0；不适用域不计入分母
        </span>
      </template>

      <div class="toolbar">
        <el-select v-model="snapshotId" class="is-wide" placeholder="快照（留空取最新）" clearable filterable @change="load">
          <el-option
            v-for="snapshot in snapshots"
            :key="snapshot.snapshot_id"
            :label="`${snapshot.snapshot_id}（${formatTime(snapshot.ts)}）`"
            :value="snapshot.snapshot_id"
          />
        </el-select>
        <el-button :loading="coverage.loading.value" @click="load">刷新</el-button>
        <span class="spacer" />
        <span class="muted">台账资产 {{ formatNumber(coverage.data.value.assets) }} 个</span>
      </div>

      <el-alert v-if="coverage.error.value" :title="coverage.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="coverage.data.value.error" :title="coverage.data.value.error" type="warning" :closable="false" show-icon />

      <div class="coverage-head">
        <el-progress
          type="dashboard"
          :percentage="coveragePercent"
          :width="140"
          :stroke-width="12"
          :color="coveragePercent >= 80 ? '#1b6e2a' : coveragePercent >= 50 ? '#a15c00' : '#b00020'"
        >
          <template #default>
            <div class="coverage-head__value mono">{{ formatPercent(coverage.data.value.coverage) }}</div>
            <div class="coverage-head__label">加权覆盖率</div>
          </template>
        </el-progress>
        <div class="domain-cards">
          <div v-for="row in domainRows" :key="row.code" class="domain-card">
            <div class="domain-card__title">
              {{ row.code }} · {{ row.name }}
              <span class="muted">（权重 {{ formatPercent(row.weight, 0) }}）</span>
            </div>
            <div class="domain-card__value mono">{{ formatPercent(row.avg) }}</div>
            <div class="domain-card__meta muted">
              适用 {{ formatNumber(row.applicable) }} · 完成 {{ formatNumber(row.done) }} ·
              部分 {{ formatNumber(row.partial) }} · 缺失 {{ formatNumber(row.missing) }}
            </div>
          </div>
        </div>
      </div>
    </el-card>

    <el-card shadow="never">
      <template #header>
        资产 × 检查域矩阵
        <span class="head-note">D1 端口服务 / D2 系统补丁 / D3 应用组件 / D4 主机配置 / D5 TLS / D6 Web PoC</span>
      </template>
      <el-table :data="coverage.data.value.matrix" size="small" empty-text="没有可计算的资产（台账为空）">
        <el-table-column label="资产" min-width="170" show-overflow-tooltip>
          <template #default="{ row }">
            <div>{{ row.hostname || row.ip || row.asset_id }}</div>
            <div class="muted mono small">{{ row.asset_id }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="role" label="角色" width="100" />
        <el-table-column v-for="domain in domains" :key="domain" :label="domain" width="64" align="center">
          <template #default="{ row }">
            <span class="cell" :class="cellClass(row, domain)" :title="row.notes?.[domain] ?? ''">
              {{ cellText(row, domain) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="资产得分" width="110" align="right">
          <template #default="{ row }"><span class="mono">{{ formatPercent(row.score) }}</span></template>
        </el-table-column>
        <el-table-column label="任务状态" width="100">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>
        未覆盖清单
        <span class="head-note">前 200 条；完整清单见扫描报告</span>
      </template>
      <el-table :data="uncoveredRows" size="small" empty-text="没有未覆盖单元格">
        <el-table-column label="资产" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">{{ row.ip || row.asset_id }}</template>
        </el-table-column>
        <el-table-column prop="domain" label="域" width="70" />
        <el-table-column prop="name" label="名称" width="150" />
        <el-table-column prop="reason" label="原因" min-width="220" show-overflow-tooltip />
        <el-table-column label="状态" width="100">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="覆盖值" width="90" align="right">
          <template #default="{ row }"><span class="mono">{{ formatPercent(row.covered, 0) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<style scoped>
.head-note {
  margin-left: 10px;
  font-size: 11px;
  font-weight: 400;
  color: var(--text-faint);
}
.coverage-head {
  display: flex;
  align-items: center;
  gap: 24px;
  flex-wrap: wrap;
  margin-bottom: 6px;
}
.coverage-head__value {
  font-size: 20px;
  font-weight: 600;
  color: var(--text-strong);
}
.coverage-head__label {
  font-size: 11px;
  color: var(--text-faint);
}
.domain-cards {
  flex: 1;
  min-width: 260px;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
  gap: 8px;
}
.domain-card {
  border: 1px solid var(--border-soft);
  border-radius: 5px;
  padding: 7px 10px;
  background: var(--surface-alt);
}
.domain-card__title {
  font-size: 12px;
  color: var(--text-strong);
}
.domain-card__value {
  font-size: 17px;
  font-weight: 600;
  color: var(--text-strong);
}
.domain-card__meta {
  font-size: 11px;
}
.cell {
  display: inline-flex;
  width: 24px;
  height: 24px;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}
.cell--done {
  background: var(--badge-success-bg);
  color: var(--badge-success-fg);
}
.cell--partial {
  background: var(--badge-warning-bg);
  color: var(--badge-warning-fg);
}
.cell--missing {
  background: var(--badge-danger-bg);
  color: var(--badge-danger-fg);
}
.cell--na {
  background: var(--badge-neutral-bg);
  color: var(--badge-neutral-fg);
}
.small {
  font-size: 11px;
}
</style>
