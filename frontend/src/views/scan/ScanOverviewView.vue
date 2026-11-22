<script setup lang="ts">
import { computed, onMounted } from 'vue';

import StatCard from '@/components/base/StatCard.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import { scanApi } from '@/api/modules/scan';
import { useAsync } from '@/composables/useAsync';
import { usePolling } from '@/composables/usePolling';
import type { ScanOverview, ScanPlan, ScanTask } from '@/types/scan';
import { formatDuration, formatNumber, formatPercent, formatTime } from '@/utils/format';

interface ScanBundle {
  overview: ScanOverview;
  plans: ScanPlan[];
  tasks: ScanTask[];
  errors: string[];
}

const bundle = useAsync<ScanBundle | null>(null);

function load(): Promise<ScanBundle | null> {
  return bundle.run(async () => {
    const [overview, plans, tasks] = await Promise.all([
      scanApi.overview(),
      scanApi.plans(),
      scanApi.tasks({ limit: 50 }),
    ]);
    return {
      overview,
      plans: plans.items,
      tasks: tasks.items,
      errors: [overview.error, plans.error, tasks.error].filter((item): item is string => Boolean(item)),
    };
  }, { softError: false });
}

/** 有运行中任务时才轮询：任务终态后自动停，避免空转。 */
const hasRunning = computed(() =>
  (bundle.data.value?.tasks ?? []).some((task) => task.status === 'running' || task.status === 'queued'),
);

const poller = usePolling(load, {
  interval: 4000,
  immediate: false,
  shouldStop: () => !hasRunning.value,
});

const counts = computed(
  () => bundle.data.value?.overview.counts ?? { asset: 0, plan: 0, task: 0, snapshot: 0, finding: 0, cve: 0 },
);

/** 计划的时间窗：后端存的是 `HH:MM` 字符串，空值表示全天。 */
function windowText(plan: ScanPlan): string {
  if (!plan.window_start && !plan.window_end) return '全天';
  return `${plan.window_start ?? '-'} ~ ${plan.window_end ?? '-'}`;
}

function selectorText(plan: ScanPlan): string {
  const selector = plan.selector ?? {};
  const entries = Object.entries(selector)
    .filter(([, value]) => value !== null && value !== undefined && value !== '')
    .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join('|') : String(value)}`);
  return entries.length > 0 ? entries.join(', ') : '全部启用资产';
}

function progressOf(task: ScanTask): number {
  const value = Number(task.progress ?? 0);
  if (!Number.isFinite(value)) return 0;
  // 后端 progress 是 0–1 比率；兼容误存 0–100 的情况
  return value > 1 ? Math.min(1, value / 100) : Math.max(0, value);
}

onMounted(async () => {
  await load();
  if (hasRunning.value) poller.start();
});
</script>

<template>
  <div class="stack">
    <div class="grid-cards">
      <StatCard label="资产" :value="formatNumber(counts.asset)" hint="台账启用数" />
      <StatCard label="扫描计划" :value="formatNumber(counts.plan)" />
      <StatCard label="扫描任务" :value="formatNumber(counts.task)" :hint="hasRunning ? '存在运行中任务' : '无运行中任务'" :tone="hasRunning ? 'info' : 'neutral'" />
      <StatCard label="快照" :value="formatNumber(counts.snapshot)" />
      <StatCard label="问题项" :value="formatNumber(counts.finding)" tone="warning" />
      <StatCard label="CVE 缓存" :value="formatNumber(counts.cve)" />
    </div>

    <el-card shadow="never">
      <template #header>
        扫描总览
        <span class="head-note">计划配置与任务触发只能通过 hornworkctl scan 执行</span>
      </template>
      <div class="toolbar">
        <el-button :loading="bundle.loading.value" @click="load">刷新</el-button>
        <el-switch
          :model-value="poller.active.value"
          active-text="自动刷新（4s）"
          :disabled="!hasRunning"
          @change="(value: boolean) => (value ? poller.start() : poller.stop())"
        />
        <span class="spacer" />
        <span v-if="bundle.data.value?.overview.last_snapshot" class="muted">
          最近快照 {{ bundle.data.value.overview.last_snapshot.snapshot_id }} ·
          {{ formatTime(bundle.data.value.overview.last_snapshot.ts) }}
        </span>
      </div>

      <el-alert v-if="bundle.error.value" :title="bundle.error.value" type="error" :closable="false" show-icon />
      <el-alert
        v-for="message in bundle.data.value?.errors ?? []"
        :key="message"
        :title="`扫描模块降级：${message}`"
        type="warning"
        :closable="false"
        show-icon
      />
    </el-card>

    <el-card shadow="never">
      <template #header>扫描计划</template>
      <el-table :data="bundle.data.value?.plans ?? []" size="small" empty-text="暂无扫描计划">
        <el-table-column prop="plan_id" label="计划" width="160" show-overflow-tooltip />
        <el-table-column prop="name" label="名称" min-width="160" show-overflow-tooltip />
        <el-table-column label="类型" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.kind === 'periodic' ? 'success' : 'info'" disable-transitions>
              {{ row.kind === 'periodic' ? '周期型' : (row.kind ?? '事件型') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="profile" label="profile" width="120" show-overflow-tooltip />
        <el-table-column label="选择器" min-width="180" show-overflow-tooltip>
          <template #default="{ row }"><span class="muted">{{ selectorText(row) }}</span></template>
        </el-table-column>
        <el-table-column label="时间窗" width="140">
          <template #default="{ row }"><span class="mono">{{ windowText(row) }}</span></template>
        </el-table-column>
        <el-table-column label="启用" width="80">
          <template #default="{ row }">
            <ToneBadge :value="row.enabled ? 'ok' : 'stopped'" :label="row.enabled ? '启用' : '停用'" />
          </template>
        </el-table-column>
        <el-table-column label="上次运行" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.last_run) }}</span></template>
        </el-table-column>
        <el-table-column label="下次运行" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.next_run) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>扫描任务</template>
      <el-table v-loading="bundle.loading.value" :data="bundle.data.value?.tasks ?? []" size="small" empty-text="暂无扫描任务">
        <el-table-column prop="task_id" label="任务" width="160" show-overflow-tooltip />
        <el-table-column label="资产" min-width="150" show-overflow-tooltip>
          <template #default="{ row }">{{ row.asset_hostname || row.asset_ip || row.asset_id || '-' }}</template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="阶段" width="100">
          <template #default="{ row }"><ToneBadge :value="row.stage" /></template>
        </el-table-column>
        <el-table-column label="进度" width="150">
          <template #default="{ row }">
            <el-progress :percentage="Math.round(progressOf(row) * 100)" :stroke-width="6" />
          </template>
        </el-table-column>
        <el-table-column label="耗时" width="100">
          <template #default="{ row }"><span class="mono">{{ formatDuration(row.cost_ms) }}</span></template>
        </el-table-column>
        <el-table-column label="开始" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.started_at) }}</span></template>
        </el-table-column>
        <el-table-column label="错误" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.error" class="error-text">{{ row.error }}</span>
            <span v-else class="muted">-</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-row :gutter="14">
      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>任务状态分布</template>
          <el-empty
            v-if="Object.keys(bundle.data.value?.overview.tasks.by_status ?? {}).length === 0"
            description="暂无任务"
            :image-size="60"
          />
          <div v-else class="chip-grid">
            <span
              v-for="[status, count] in Object.entries(bundle.data.value?.overview.tasks.by_status ?? {})"
              :key="status"
              class="chip"
            >
              <ToneBadge :value="status" />
              <span class="mono">{{ formatNumber(count) }}</span>
            </span>
          </div>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>问题项状态分布</template>
          <el-empty
            v-if="Object.keys(bundle.data.value?.overview.findings.by_status ?? {}).length === 0"
            description="暂无问题项"
            :image-size="60"
          />
          <div v-else class="chip-grid">
            <span
              v-for="[status, count] in Object.entries(bundle.data.value?.overview.findings.by_status ?? {})"
              :key="status"
              class="chip"
            >
              <ToneBadge :value="status" />
              <span class="mono">{{ formatNumber(count) }}</span>
            </span>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card v-if="bundle.data.value?.overview.last_snapshot" shadow="never">
      <template #header>最近快照</template>
      <p class="mono muted">
        {{ bundle.data.value.overview.last_snapshot.snapshot_id }} ·
        {{ formatTime(bundle.data.value.overview.last_snapshot.ts) }} ·
        任务 {{ formatNumber(bundle.data.value.overview.last_snapshot.task_count) }} ·
        问题 {{ formatNumber(bundle.data.value.overview.last_snapshot.finding_count) }} ·
        基线 {{ formatPercent(bundle.data.value.overview.last_snapshot.is_base ? 1 : 0, 0) }}
      </p>
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
.chip-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 8px;
}
.chip {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  border: 1px solid var(--border-soft);
  border-radius: 5px;
  padding: 6px 9px;
  font-size: 12px;
}
</style>
