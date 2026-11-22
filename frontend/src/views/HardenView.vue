<script setup lang="ts">
import { computed, onMounted } from 'vue';

import StatCard from '@/components/base/StatCard.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import { platformApi } from '@/api/modules/platform';
import { useReport } from '@/composables/useReport';
import { useAsync } from '@/composables/useAsync';
import type { HardenStatus } from '@/types/harden';
import { formatBytes, formatNumber, formatTime } from '@/utils/format';

const harden = useAsync<HardenStatus>({ ts: '', items: [], plans: [], runs: [], reports: [] });
const report = useReport();

function load(): Promise<HardenStatus | null> {
  return harden.run(() => platformApi.harden(), { softError: false });
}

/** 基线项统计：H- 开头为通用基线，H-PL- 开头为平台登录面。 */
const baseline = computed(() => harden.data.value.items.filter((item) => item.id.startsWith('H-')));
const platformItems = computed(() => harden.data.value.items.filter((item) => item.id.startsWith('H-PL-')));
const applicable = computed(() => harden.data.value.items.filter((item) => item.scope_A).length);

/** 计划时间字段兼容：后端读 `created_at`，实际文件字段是 `generated_at`。 */
function planTime(plan: { created_at?: string | null; generated_at?: string | null }): string {
  return plan.created_at ?? plan.generated_at ?? '';
}

/** 运行结果计数 → 可读文本（counts 是 `{status: n}`）。 */
function countsText(counts: Record<string, number> | undefined): string {
  if (!counts) return '-';
  return Object.entries(counts)
    .map(([status, count]) => `${status}×${count}`)
    .join('，');
}

function openReport(name: string): void {
  void report.openReport(`reports/${name}`);
}

onMounted(load);
</script>

<template>
  <div class="stack">
    <div class="grid-cards">
      <StatCard label="基线项" :value="formatNumber(baseline.length)" :hint="`A 机适用 ${formatNumber(applicable)} 项`" />
      <StatCard label="平台登录项" :value="formatNumber(platformItems.length)" hint="H-PL-01 ~ 04" tone="info" />
      <StatCard label="加固计划" :value="formatNumber(harden.data.value.plans.length)" />
      <StatCard label="加固运行" :value="formatNumber(harden.data.value.runs.length)" />
    </div>

    <el-card shadow="never">
      <template #header>
        安全加固
        <span class="head-note">计划生成与执行只能通过 hornworkctl harden 完成；本页只读</span>
      </template>
      <div class="toolbar">
        <el-button :loading="harden.loading.value" @click="load">刷新</el-button>
        <span class="spacer" />
        <span class="muted">状态目录：/etc/hornwork/harden</span>
      </div>
      <el-alert v-if="harden.error.value" :title="harden.error.value" type="error" :closable="false" show-icon />
    </el-card>

    <el-card shadow="never">
      <template #header>基线项</template>
      <el-table :data="harden.data.value.items" size="small" empty-text="暂无基线项">
        <el-table-column prop="id" label="编号" width="130" />
        <el-table-column prop="category" label="类别" width="120" />
        <el-table-column prop="title" label="标题" min-width="260" show-overflow-tooltip />
        <el-table-column label="风险" width="96">
          <template #default="{ row }"><ToneBadge :value="row.risk" kind="severity" /></template>
        </el-table-column>
        <el-table-column label="A 机适用" width="100">
          <template #default="{ row }">
            <ToneBadge :value="row.scope_A ? 'ok' : 'stopped'" :label="row.scope_A ? '适用' : '不适用'" />
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>加固计划</template>
      <el-table :data="harden.data.value.plans" size="small" empty-text="暂无加固计划">
        <el-table-column prop="plan_id" label="计划" width="200" show-overflow-tooltip />
        <el-table-column prop="role" label="角色" width="120" />
        <el-table-column prop="asset" label="资产" width="150" show-overflow-tooltip />
        <el-table-column label="项数" width="90">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.items) }}</span></template>
        </el-table-column>
        <el-table-column label="生成时间" width="180">
          <template #default="{ row }"><span class="mono">{{ formatTime(planTime(row)) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>运行结果</template>
      <el-table :data="harden.data.value.runs" size="small" empty-text="暂无运行记录">
        <el-table-column prop="run_id" label="运行" width="200" show-overflow-tooltip />
        <el-table-column prop="plan_id" label="计划" width="180" show-overflow-tooltip />
        <el-table-column prop="mode" label="模式" width="100" />
        <el-table-column label="状态" width="130">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="项数" width="90">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.items) }}</span></template>
        </el-table-column>
        <el-table-column label="结果分布" min-width="240" show-overflow-tooltip>
          <template #default="{ row }">
            <span class="muted">{{ countsText(row.counts) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="开始时间" width="180">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.started_at) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>加固报告</template>
      <el-alert v-if="report.error.value" :title="report.error.value" type="error" :closable="false" show-icon />
      <el-table :data="harden.data.value.reports" size="small" empty-text="暂无报告">
        <el-table-column prop="name" label="报告" min-width="280" show-overflow-tooltip />
        <el-table-column label="大小" width="110">
          <template #default="{ row }"><span class="mono">{{ formatBytes(row.size) }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="110" align="right">
          <template #default="{ row }">
            <el-button size="small" :loading="report.busy.value" @click="openReport(row.name)">查看</el-button>
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
