<script setup lang="ts">
import { computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';

import StatCard from '@/components/base/StatCard.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import EChart from '@/components/charts/EChart.vue';
import { detectionApi } from '@/api/modules/detection';
import { scanApi } from '@/api/modules/scan';
import { useAsync } from '@/composables/useAsync';
import { usePolling } from '@/composables/usePolling';
import type { Alert, IntegrationPayload, OverviewPayload } from '@/types/detection';
import { formatNumber, formatRelative, formatTime } from '@/utils/format';
import { lineOption } from '@/utils/charts';

const router = useRouter();

interface OverviewBundle {
  overview: OverviewPayload | null;
  integration: IntegrationPayload | null;
  alerts: Alert[];
  scan: Awaited<ReturnType<typeof scanApi.overview>> | null;
  scanError?: string;
}

const bundle = useAsync<OverviewBundle>({
  overview: null,
  integration: null,
  alerts: [],
  scan: null,
});

async function load(): Promise<void> {
  await bundle.run(async () => {
    const [overview, integration, alerts, scan] = await Promise.all([
      detectionApi.overview(7),
      detectionApi.integration(),
      detectionApi.alerts({ since: '24h', limit: 8 }),
      scanApi.overview(),
    ]);
    return {
      overview,
      integration,
      alerts: alerts.items,
      scan,
      scanError: scan.error ?? alerts.error,
    };
  }, { softError: false });
}

onMounted(load);

// 看板用低频轮询：15 秒一次，离开页面自动停
const poller = usePolling(load, { interval: 15_000, immediate: false });
poller.start();

const counts = computed(() => bundle.data.value.overview?.counts ?? {});
const modules = computed(() => bundle.data.value.integration?.modules ?? {});

/** 五大功能域摘要卡：点击直接进入对应域。 */
const domainCards = computed(() => {
  const mod = modules.value;
  return [
    {
      title: '检测',
      path: '/detection',
      value: formatNumber(mod.detection?.events ?? 0),
      hint: `告警 ${formatNumber(mod.detection?.alerts ?? 0)} · 工单 ${formatNumber(mod.detection?.cases ?? 0)}`,
    },
    {
      title: '漏洞档案',
      path: '/vuln',
      value: formatNumber(mod.vuln?.records ?? 0),
      hint: `已验证 ${formatNumber(mod.vuln?.verified ?? 0)} · 靶场 ${formatNumber(mod.vuln?.lab_envs ?? 0)}`,
    },
    {
      title: '定期扫描',
      path: '/scan',
      value: formatNumber(mod.scan?.findings ?? 0),
      hint: `任务 ${formatNumber(mod.scan?.tasks ?? 0)} · 快照 ${formatNumber(mod.scan?.snapshots ?? 0)}`,
    },
    {
      title: '身份认证',
      path: '/auth',
      value: formatNumber(mod.auth?.users ?? 0),
      hint: `审计 ${formatNumber(mod.auth?.audit_rows ?? 0)} 条`,
    },
    {
      title: '安全加固',
      path: '/harden',
      value: formatNumber(mod.harden?.items ?? 0),
      hint: mod.harden?.latest_run ? `最近运行 ${String(mod.harden.latest_run)}` : '暂无运行记录',
    },
  ];
});

/** 审计链状态：`ok=false` 时首页就要显眼。 */
const chainOk = computed(() => modules.value.auth?.chain?.ok ?? true);
const chainChecked = computed(() => modules.value.auth?.chain?.checked ?? 0);

/** 引擎命中趋势：按天聚合，缺失的天补 0，避免折线误导性地跨天连线。 */
const trend = computed(() => {
  const stats = bundle.data.value.overview?.engine_stats ?? [];
  if (stats.length === 0) return null;

  const days = [...new Set(stats.map((row) => row.day))].sort();
  const engines = [...new Set(stats.map((row) => row.engine))];
  const series = engines.map((engine) => ({
    name: engine,
    data: days.map((day) => {
      const hit = stats.find((row) => row.day === day && row.engine === engine);
      return hit ? Number(hit.malicious) : 0;
    }),
  }));
  return lineOption({ categories: days, series, yName: '恶意命中' });
});

const scanTaskStats = computed(() => {
  const byStatus = bundle.data.value.scan?.tasks.by_status ?? {};
  return Object.entries(byStatus);
});

function go(path: string): void {
  void router.push(path);
}
</script>

<template>
  <div class="stack">
    <el-alert
      v-if="bundle.error.value"
      :title="`加载总览失败：${bundle.error.value}`"
      type="error"
      :closable="false"
      show-icon
    />
    <el-alert
      v-if="bundle.data.value.scanError"
      :title="`扫描模块降级：${bundle.data.value.scanError}`"
      type="warning"
      :closable="false"
      show-icon
    />
    <el-alert
      v-if="!chainOk"
      :title="`认证审计链校验未通过（已校验 ${chainChecked} 条），请尽快排查`"
      type="error"
      :closable="false"
      show-icon
    />

    <div class="grid-cards">
      <StatCard label="近 24h 事件" :value="formatNumber(counts.events_24h)" :hint="`累计 ${formatNumber(counts.events_total)}`" tone="info" />
      <StatCard label="近 24h 告警" :value="formatNumber(counts.alerts_24h)" :hint="`未处置 ${formatNumber(counts.alerts_open)}`" tone="danger" />
      <StatCard label="开放工单" :value="formatNumber(counts.cases_open)" :hint="`累计 ${formatNumber(counts.cases_total)}`" tone="warning" />
      <StatCard label="扫描问题项" :value="formatNumber(bundle.data.value.scan?.findings.total ?? 0)" :hint="`快照 ${formatNumber(bundle.data.value.scan?.counts.snapshot ?? 0)} 个`" />
      <StatCard label="IOC 条数" :value="formatNumber(counts.iocs)" :hint="`死信 ${formatNumber(counts.dlq)}`" />
      <StatCard label="审计链" :value="chainOk ? '正常' : '异常'" :hint="`已校验 ${formatNumber(chainChecked)} 条`" :tone="chainOk ? 'success' : 'danger'" />
    </div>

    <el-row :gutter="14">
      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>功能域入口</template>
          <div class="domain-list">
            <button
              v-for="card in domainCards"
              :key="card.path"
              type="button"
              class="domain-item"
              @click="go(card.path)"
            >
              <span class="domain-item__title">{{ card.title }}</span>
              <span class="domain-item__value mono">{{ card.value }}</span>
              <span class="domain-item__hint">{{ card.hint }}</span>
            </button>
          </div>
        </el-card>
      </el-col>

      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>
            近 24h 告警
            <el-link type="primary" class="card-link" @click="go('/detection/alerts')">全部</el-link>
          </template>
          <el-empty
            v-if="bundle.data.value.alerts.length === 0"
            description="近 24h 无告警"
            :image-size="60"
          />
          <ul v-else class="alert-list">
            <li v-for="(alert, index) in bundle.data.value.alerts" :key="alert.alert_id ?? index">
              <ToneBadge :value="alert.level" kind="severity" :label="`L${alert.level ?? 0}`" />
              <span class="alert-list__rule">{{ alert.rule?.name ?? alert.rule?.id ?? alert.rule_id ?? '未知规则' }}</span>
              <span class="alert-list__time muted">{{ formatTime(alert.ts) }}</span>
            </li>
          </ul>
        </el-card>
      </el-col>
    </el-row>

    <el-card shadow="never">
      <template #header>引擎恶意命中趋势（按天）</template>
      <EChart
        v-if="trend"
        :option="trend"
        height="260px"
        :empty="(bundle.data.value.overview?.engine_stats?.length ?? 0) === 0"
        empty-text="暂无引擎统计"
      />
      <el-empty v-else description="暂无引擎统计" :image-size="60" />
    </el-card>

    <el-row :gutter="14">
      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>最近扫描任务</template>
          <el-table
            :data="bundle.data.value.scan?.recent_tasks ?? []"
            size="small"
            empty-text="暂无扫描任务"
          >
            <el-table-column prop="task_id" label="任务" min-width="140" show-overflow-tooltip />
            <el-table-column label="资产" min-width="130">
              <template #default="{ row }">
                {{ row.asset_hostname || row.asset_ip || row.asset_id || '-' }}
              </template>
            </el-table-column>
            <el-table-column label="状态" width="96">
              <template #default="{ row }"><ToneBadge :value="row.status" /></template>
            </el-table-column>
            <el-table-column label="开始时间" width="150">
              <template #default="{ row }">
                <span class="muted">{{ formatRelative(row.started_at) }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </el-col>

      <el-col :xs="24" :md="12">
        <el-card shadow="never">
          <template #header>任务状态分布</template>
          <div v-if="scanTaskStats.length === 0" class="muted">暂无任务</div>
          <div v-else class="status-grid">
            <div v-for="[status, count] in scanTaskStats" :key="status" class="status-cell">
              <ToneBadge :value="status" />
              <span class="mono">{{ formatNumber(count) }}</span>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <p class="muted note">
      平台监听 {{ bundle.data.value.overview?.web.bind ?? '-' }}:{{ bundle.data.value.overview?.web.port ?? '-' }}
      · 主机 {{ bundle.data.value.integration?.host ?? '-' }}
      · 数据更新时间 {{ formatTime(bundle.data.value.overview?.ts) }}
    </p>
  </div>
</template>

<style scoped>
.domain-list {
  display: grid;
  gap: 8px;
}
.domain-item {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 2px 10px;
  text-align: left;
  border: 1px solid var(--border);
  background: var(--surface);
  border-radius: 5px;
  padding: 8px 11px;
  cursor: pointer;
  font-family: inherit;
}
.domain-item:hover {
  border-color: var(--tone-info);
  background: var(--surface-hover);
}
.domain-item__title {
  font-size: 13px;
  color: var(--text-strong);
  font-weight: 600;
}
.domain-item__value {
  font-size: 16px;
  color: var(--text-strong);
  text-align: right;
}
.domain-item__hint {
  grid-column: 1 / -1;
  font-size: 11px;
  color: var(--text-faint);
}
.alert-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 6px;
}
.alert-list li {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}
.alert-list__rule {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.alert-list__time {
  font-size: 11px;
  white-space: nowrap;
}
.status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
  gap: 8px;
}
.status-cell {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  border: 1px solid var(--border-soft);
  border-radius: 5px;
  padding: 6px 9px;
  font-size: 12px;
}
.card-link {
  margin-left: auto;
  font-size: 12px;
}
.note {
  font-size: 11px;
  margin: 0;
}
</style>
