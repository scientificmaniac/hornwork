<script setup lang="ts">
import { computed, onMounted, reactive } from 'vue';

import EChart from '@/components/charts/EChart.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import { detectionApi } from '@/api/modules/detection';
import { useAsync } from '@/composables/useAsync';
import type { EngineStatsPayload } from '@/types/detection';
import { formatDuration, formatNumber, formatPercent, formatTime } from '@/utils/format';
import { lineOption, doughnutOption } from '@/utils/charts';

const stats = useAsync<EngineStatsPayload>({
  days: 7,
  engine_stats: [],
  contribution: [],
  sigma: { total: 0, supported: 0, hits: 0 },
  recent_scans: [],
});
const filter = reactive({ days: 7, limit: 20 });

function load(): Promise<EngineStatsPayload | null> {
  return stats.run(() => detectionApi.engineStats(filter.days, filter.limit), { softError: false });
}

/** 按天聚合各引擎的恶意命中，缺测的引擎当天补 0（不插值，避免读出虚假趋势）。 */
const trendOption = computed(() => {
  const rows = stats.data.value.engine_stats;
  if (rows.length === 0) return null;
  const days = [...new Set(rows.map((row) => row.day))].sort();
  const engines = [...new Set(rows.map((row) => row.engine))];
  return lineOption({
    categories: days,
    yName: '命中数',
    series: engines.map((engine) => ({
      name: engine,
      data: days.map(
        (day) => rows.find((row) => row.day === day && row.engine === engine)?.malicious ?? 0,
      ),
    })),
  });
});

/** 首杀贡献：谁先发现恶意样本。 */
const contributionOption = computed(() =>
  doughnutOption(
    stats.data.value.contribution.map((row) => [
      row.first_hit || '未知引擎',
      Number(row.n ?? 0),
    ]),
  ),
);

/** 引擎明细：把按天行按引擎聚合，避免表格被日期切碎。 */
const engineRows = computed(() => {
  const map = new Map<
    string,
    { engine: string; files: number; hits: number; malicious: number; costMs: number; errors: number; days: number }
  >();
  for (const row of stats.data.value.engine_stats) {
    const item = map.get(row.engine) ?? {
      engine: row.engine,
      files: 0,
      hits: 0,
      malicious: 0,
      costMs: 0,
      errors: 0,
      days: 0,
    };
    item.files += Number(row.files ?? 0);
    item.hits += Number(row.hits ?? 0);
    item.malicious += Number(row.malicious ?? 0);
    item.costMs += Number(row.cost_ms ?? 0);
    item.errors += Number(row.errors ?? 0);
    item.days += 1;
    map.set(row.engine, item);
  }
  return [...map.values()].sort((a, b) => b.malicious - a.malicious);
});

function hitRate(row: { files: number; hits: number }): number {
  return row.files > 0 ? row.hits / row.files : 0;
}

function maliciousRate(row: { files: number; malicious: number }): number {
  return row.files > 0 ? row.malicious / row.files : 0;
}

function avgCost(row: { costMs: number; days: number }): number {
  return row.days > 0 ? row.costMs / row.days : 0;
}

onMounted(load);
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>
        引擎贡献
        <span class="head-note">级联引擎的命中率与首杀分布：说明“谁先发现恶意样本”</span>
      </template>

      <div class="toolbar">
        <el-select v-model="filter.days" @change="load">
          <el-option :value="1" label="最近 1 天" />
          <el-option :value="7" label="最近 7 天" />
          <el-option :value="30" label="最近 30 天" />
          <el-option :value="90" label="最近 90 天" />
        </el-select>
        <el-select v-model="filter.limit" class="is-wide" @change="load">
          <el-option :value="20" label="最近扫描 20 条" />
          <el-option :value="100" label="最近扫描 100 条" />
          <el-option :value="200" label="最近扫描 200 条" />
        </el-select>
        <el-button :loading="stats.loading.value" @click="load">刷新</el-button>
      </div>

      <el-alert v-if="stats.error.value" :title="stats.error.value" type="error" :closable="false" show-icon />
    </el-card>

    <el-row :gutter="14">
      <el-col :xs="24" :md="14">
        <el-card shadow="never">
          <template #header>引擎恶意命中趋势</template>
          <EChart
            v-if="trendOption"
            :option="trendOption"
            height="260px"
            :empty="stats.data.value.engine_stats.length === 0"
            empty-text="所选区间没有引擎统计"
          />
          <el-empty v-else description="所选区间没有引擎统计" :image-size="60" />
        </el-card>
      </el-col>
      <el-col :xs="24" :md="10">
        <el-card shadow="never">
          <template #header>首杀贡献</template>
          <EChart
            :option="contributionOption"
            height="260px"
            :empty="stats.data.value.contribution.length === 0"
            empty-text="所选区间没有恶意命中"
          />
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <template #header>引擎明细（按天聚合）</template>
      <el-table :data="engineRows" size="small" empty-text="暂无引擎统计">
        <el-table-column prop="engine" label="引擎" width="140" />
        <el-table-column label="扫描文件" width="110">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.files) }}</span></template>
        </el-table-column>
        <el-table-column label="命中" width="100">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.hits) }}</span></template>
        </el-table-column>
        <el-table-column label="恶意" width="100">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.malicious) }}</span></template>
        </el-table-column>
        <el-table-column label="命中率" width="110">
          <template #default="{ row }"><span class="mono">{{ formatPercent(hitRate(row)) }}</span></template>
        </el-table-column>
        <el-table-column label="恶意率" width="110">
          <template #default="{ row }"><span class="mono">{{ formatPercent(maliciousRate(row)) }}</span></template>
        </el-table-column>
        <el-table-column label="日均耗时" width="120">
          <template #default="{ row }"><span class="mono">{{ formatDuration(avgCost(row)) }}</span></template>
        </el-table-column>
        <el-table-column label="错误" width="90">
          <template #default="{ row }">
            <span class="mono" :class="{ 'error-text': row.errors > 0 }">{{ formatNumber(row.errors) }}</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>
        Sigma 与最近扫描
        <span class="head-note">
          Sigma 规则 {{ formatNumber(stats.data.value.sigma.total) }} 条，
          命中 {{ formatNumber(stats.data.value.sigma.hits) }} 次
        </span>
      </template>
      <el-table :data="stats.data.value.recent_scans" size="small" empty-text="暂无扫描记录">
        <el-table-column label="时间" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.ts) }}</span></template>
        </el-table-column>
        <el-table-column label="文件" min-width="240" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.path ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column label="判定" width="100">
          <template #default="{ row }"><ToneBadge :value="row.verdict" /></template>
        </el-table-column>
        <el-table-column label="首杀引擎" width="140">
          <template #default="{ row }">{{ row.first_hit ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="耗时" width="110">
          <template #default="{ row }"><span class="mono">{{ formatDuration(row.cost_ms) }}</span></template>
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
.error-text {
  color: var(--tone-danger);
}
</style>
