<script setup lang="ts">
import { computed, onMounted } from 'vue';

import StatCard from '@/components/base/StatCard.vue';
import EChart from '@/components/charts/EChart.vue';
import { scanApi } from '@/api/modules/scan';
import { useAsync } from '@/composables/useAsync';
import type { CveStats } from '@/types/scan';
import { formatNumber, formatTime } from '@/utils/format';
import { barOption, countEntries, doughnutOption } from '@/utils/charts';

const cve = useAsync<CveStats>({
  total: 0,
  by_severity: {},
  by_source: {},
  by_year: {},
  oval_fixes: 0,
  component_map: 0,
});

function load(): Promise<CveStats | null> {
  return cve.run(() => scanApi.cve());
}

const severityChart = computed(() => doughnutOption(countEntries(cve.data.value.by_severity)));
const sourceChart = computed(() => doughnutOption(countEntries(cve.data.value.by_source)));

/** 年份分布：按年份升序，去掉空年份。 */
const yearChart = computed(() => {
  const entries = Object.entries(cve.data.value.by_year)
    .filter(([year]) => year && year !== '')
    .sort(([a], [b]) => a.localeCompare(b));
  return barOption(
    entries.map(([year]) => year),
    entries.map(([, count]) => count),
  );
});

onMounted(load);
</script>

<template>
  <div class="stack">
    <div class="grid-cards">
      <StatCard label="CVE 总数" :value="formatNumber(cve.data.value.total)" :hint="`最后更新 ${formatTime(cve.data.value.last_modified)}`" />
      <StatCard label="OVAL 修复映射" :value="formatNumber(cve.data.value.oval_fixes)" hint="发行版补丁来源" />
      <StatCard label="组件映射" :value="formatNumber(cve.data.value.component_map)" hint="CPE ↔ 包名" />
    </div>

    <el-card shadow="never">
      <template #header>
        CVE 库
        <span class="head-note">
          匹配口径是“版本是否落入影响区间”，不代表“是否可利用”；利用验证请看问题清单与靶场
        </span>
      </template>
      <div class="toolbar">
        <el-button :loading="cve.loading.value" @click="load">刷新</el-button>
      </div>
      <el-alert v-if="cve.error.value" :title="cve.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="cve.data.value.error" :title="cve.data.value.error" type="warning" :closable="false" show-icon />
    </el-card>

    <el-row :gutter="14">
      <el-col :xs="24" :md="8">
        <el-card shadow="never">
          <template #header>按严重级</template>
          <EChart
            :option="severityChart"
            height="240px"
            :empty="Object.keys(cve.data.value.by_severity).length === 0"
            empty-text="CVE 缓存为空"
          />
        </el-card>
      </el-col>
      <el-col :xs="24" :md="8">
        <el-card shadow="never">
          <template #header>按来源</template>
          <EChart
            :option="sourceChart"
            height="240px"
            :empty="Object.keys(cve.data.value.by_source).length === 0"
            empty-text="CVE 缓存为空"
          />
        </el-card>
      </el-col>
      <el-col :xs="24" :md="8">
        <el-card shadow="never">
          <template #header>按年份</template>
          <EChart
            :option="yearChart"
            height="240px"
            :empty="Object.keys(cve.data.value.by_year).length === 0"
            empty-text="CVE 缓存为空"
          />
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <template #header>分档明细</template>
      <el-table
        :data="
          Object.entries(cve.data.value.by_severity).map(([label, count]) => ({ label, count }))
        "
        size="small"
        empty-text="CVE 缓存为空"
      >
        <el-table-column prop="label" label="严重级" width="140" />
        <el-table-column label="条数" width="140">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.count) }}</span></template>
        </el-table-column>
        <el-table-column label="占比">
          <template #default="{ row }">
            <el-progress
              :percentage="cve.data.value.total > 0 ? Math.round((row.count / cve.data.value.total) * 100) : 0"
              :stroke-width="6"
            />
          </template>
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
</style>
