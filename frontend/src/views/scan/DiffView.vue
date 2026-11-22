<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';

import StatCard from '@/components/base/StatCard.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import EChart from '@/components/charts/EChart.vue';
import { scanApi } from '@/api/modules/scan';
import { useAsync } from '@/composables/useAsync';
import type { DeltaState, DiffPayload, Snapshot } from '@/types/scan';
import { SEVERITIES } from '@/types/scan';
import { formatNumber, formatTime } from '@/utils/format';
import { barOption } from '@/utils/charts';

/**
 * 后端语义：`from` 是本次（新）快照，`to` 是上次（旧）快照。
 * 变量名统一用 cur / prev，避免读代码时把方向搞反。
 */
const diff = useAsync<DiffPayload>({ items: [], stats: {}, by_severity: {} });
const snapshots = ref<Snapshot[]>([]);
const selection = ref<{ cur: string; prev: string }>({ cur: '', prev: '' });
const deltaFilter = ref<DeltaState | ''>('');

async function loadSnapshots(): Promise<void> {
  const result = await scanApi.snapshots(20);
  snapshots.value = result.items;
  if (result.items.length >= 2) {
    // 快照按 ts 倒序：第一个是最新（cur），第二个是上一次（prev）
    selection.value = { cur: result.items[0].snapshot_id, prev: result.items[1].snapshot_id };
  } else if (result.items.length === 1) {
    selection.value = { cur: result.items[0].snapshot_id, prev: '' };
  }
}

function load(): Promise<DiffPayload | null> {
  return diff.run(() =>
    scanApi.diff(selection.value.cur || undefined, selection.value.prev || undefined),
  );
}

const stats = computed(() => ({
  new: diff.data.value.stats.new ?? 0,
  fixed: diff.data.value.stats.fixed ?? 0,
  persisting: diff.data.value.stats.persisting ?? 0,
  regressed: diff.data.value.stats.regressed ?? 0,
  total: diff.data.value.stats.total ?? diff.data.value.items.length,
}));

const DELTA_ORDER: DeltaState[] = ['regressed', 'new', 'persisting', 'fixed'];

/** 四态堆叠柱：一眼看出“变好还是变坏”。 */
const statsChart = computed(() =>
  barOption(['回归', '新增', '仍存在', '已修复'], [
    stats.value.regressed,
    stats.value.new,
    stats.value.persisting,
    stats.value.fixed,
  ]),
);

/** 按严重级 × 四态的矩阵表。 */
const severityRows = computed(() =>
  SEVERITIES.map((severity) => {
    const bucket = diff.data.value.by_severity?.[severity] ?? {};
    return {
      severity,
      new: bucket.new ?? 0,
      fixed: bucket.fixed ?? 0,
      persisting: bucket.persisting ?? 0,
      regressed: bucket.regressed ?? 0,
      total: bucket.total ?? 0,
    };
  }).filter((row) => row.total > 0),
);

const rows = computed(() => {
  const items = diff.data.value.items;
  if (!deltaFilter.value) return items;
  return items.filter((item) => item.delta === deltaFilter.value);
});

function countOf(delta: DeltaState): number {
  return diff.data.value.items.filter((item) => item.delta === delta).length;
}

async function applySelection(): Promise<void> {
  await load();
}

onMounted(async () => {
  await loadSnapshots();
  await load();
});
</script>

<template>
  <div class="stack">
    <div class="grid-cards">
      <StatCard label="回归" :value="formatNumber(stats.regressed)" hint="修好又出现" tone="danger" />
      <StatCard label="新增" :value="formatNumber(stats.new)" hint="本次新发现" tone="warning" />
      <StatCard label="仍存在" :value="formatNumber(stats.persisting)" tone="info" />
      <StatCard label="已修复" :value="formatNumber(stats.fixed)" tone="success" />
      <StatCard label="差异总数" :value="formatNumber(stats.total)" />
    </div>

    <el-card shadow="never">
      <template #header>
        快照对比
        <span class="head-note">
          后端语义：<b>本次（新）</b> 对比 <b>上次（旧）</b>；首次扫描没有上一次时无法对比
        </span>
      </template>

      <div class="toolbar">
        <el-select v-model="selection.cur" class="is-wide" placeholder="本次快照（新）" filterable>
          <el-option
            v-for="snapshot in snapshots"
            :key="snapshot.snapshot_id"
            :label="`${snapshot.snapshot_id}（${formatTime(snapshot.ts)}）`"
            :value="snapshot.snapshot_id"
          />
        </el-select>
        <span class="muted">对比</span>
        <el-select v-model="selection.prev" class="is-wide" placeholder="上次快照（旧）" clearable filterable>
          <el-option
            v-for="snapshot in snapshots"
            :key="snapshot.snapshot_id"
            :label="`${snapshot.snapshot_id}（${formatTime(snapshot.ts)}）`"
            :value="snapshot.snapshot_id"
          />
        </el-select>
        <el-button type="primary" :loading="diff.loading.value" :disabled="!selection.cur || !selection.prev" @click="applySelection">
          对比
        </el-button>
        <el-button :loading="diff.loading.value" @click="load">刷新</el-button>
        <span class="spacer" />
        <el-radio-group v-model="deltaFilter" size="small">
          <el-radio-button value="">全部</el-radio-button>
          <el-radio-button v-for="delta in DELTA_ORDER" :key="delta" :value="delta">
            {{ delta === 'regressed' ? '回归' : delta === 'new' ? '新增' : delta === 'persisting' ? '仍存在' : '已修复' }}
            ({{ countOf(delta) }})
          </el-radio-button>
        </el-radio-group>
      </div>

      <el-alert v-if="diff.error.value" :title="diff.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="diff.data.value.error" :title="diff.data.value.error" type="warning" :closable="false" show-icon />

      <p v-if="diff.data.value.cur" class="muted selection-note">
        本次 <span class="mono">{{ diff.data.value.cur }}</span>
        · 上次 <span class="mono">{{ diff.data.value.prev || '（无）' }}</span>
        · 生成于 {{ formatTime(diff.data.value.ts) }}
      </p>
    </el-card>

    <el-row :gutter="14">
      <el-col :xs="24" :md="10">
        <el-card shadow="never">
          <template #header>四态分布</template>
          <EChart
            :option="statsChart"
            height="220px"
            :empty="diff.data.value.items.length === 0"
            empty-text="没有可对比的差异"
          />
        </el-card>
      </el-col>
      <el-col :xs="24" :md="14">
        <el-card shadow="never">
          <template #header>按严重级</template>
          <el-table :data="severityRows" size="small" empty-text="没有差异">
            <el-table-column label="严重级" width="100">
              <template #default="{ row }"><ToneBadge :value="row.severity" kind="severity" /></template>
            </el-table-column>
            <el-table-column label="回归" width="80">
              <template #default="{ row }"><span class="mono">{{ formatNumber(row.regressed) }}</span></template>
            </el-table-column>
            <el-table-column label="新增" width="80">
              <template #default="{ row }"><span class="mono">{{ formatNumber(row.new) }}</span></template>
            </el-table-column>
            <el-table-column label="仍存在" width="90">
              <template #default="{ row }"><span class="mono">{{ formatNumber(row.persisting) }}</span></template>
            </el-table-column>
            <el-table-column label="已修复" width="90">
              <template #default="{ row }"><span class="mono">{{ formatNumber(row.fixed) }}</span></template>
            </el-table-column>
            <el-table-column label="合计">
              <template #default="{ row }"><span class="mono">{{ formatNumber(row.total) }}</span></template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <template #header>差异明细</template>
      <el-table
        v-loading="diff.loading.value"
        :data="rows"
        size="small"
        empty-text="没有符合条件的差异"
      >
        <el-table-column label="状态" width="96">
          <template #default="{ row }"><ToneBadge :value="row.delta" kind="delta" /></template>
        </el-table-column>
        <el-table-column label="资产" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">{{ row.asset_id }}</template>
        </el-table-column>
        <el-table-column prop="kind" label="类型" width="100" />
        <el-table-column prop="check_id" label="检查项" width="150" show-overflow-tooltip />
        <el-table-column prop="title" label="标题" min-width="200" show-overflow-tooltip />
        <el-table-column label="严重级" width="92">
          <template #default="{ row }"><ToneBadge :value="row.severity" kind="severity" /></template>
        </el-table-column>
        <el-table-column label="上次状态" width="110">
          <template #default="{ row }"><ToneBadge :value="row.prev_status" /></template>
        </el-table-column>
        <el-table-column label="本次状态" width="110">
          <template #default="{ row }"><ToneBadge :value="row.cur_status" /></template>
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
.selection-note {
  margin: 8px 0 0;
  font-size: 11px;
}
</style>
