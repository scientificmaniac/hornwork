<script setup lang="ts">
import { computed, onMounted, reactive, watch } from 'vue';

import StatCard from '@/components/base/StatCard.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import { scanApi } from '@/api/modules/scan';
import { useAsync } from '@/composables/useAsync';
import { usePolling } from '@/composables/usePolling';
import type { LabEnv, LabRun, VulnRecord } from '@/types/scan';
import { formatDuration, formatFloat, formatNumber, formatTime } from '@/utils/format';
import { cvssBand } from '@/utils/badge';

interface VulnBundle {
  records: VulnRecord[];
  envs: LabEnv[];
  runs: LabRun[];
}

const bundle = useAsync<VulnBundle>({ records: [], envs: [], runs: [] });
const filter = reactive({ severity: '', cwe: '', limit: 200 });

function load(): Promise<VulnBundle | null> {
  return bundle.run(async () => {
    const [records, lab] = await Promise.all([
      scanApi.vulnRecords({
        severity: filter.severity || undefined,
        cwe: filter.cwe.trim() || undefined,
        limit: filter.limit,
      }),
      scanApi.labEnvs(20),
    ]);
    return { records, envs: lab.envs, runs: lab.runs };
  }, { softError: false });
}

/** 有 `starting` 环境时轮询：靶场启动是长时操作，其它状态不轮询。 */
const hasStarting = computed(() =>
  bundle.data.value.envs.some((env) => String(env.state ?? '') === 'starting'),
);

const poller = usePolling(load, {
  interval: 3000,
  immediate: false,
  shouldStop: () => !hasStarting.value,
});

watch(hasStarting, (starting) => {
  if (starting) poller.start();
  else poller.stop();
});

const verifiedCount = computed(
  () => bundle.data.value.records.filter((item) => String(item.status) === 'verified').length,
);
const publishedCount = computed(
  () => bundle.data.value.records.filter((item) => String(item.status) === 'published').length,
);

/** 环境端口展示：后端 `host_ports` 可能是对象或数组，统一转成可读文本。 */
function portText(value: unknown): string {
  if (value === null || value === undefined || value === '') return '-';
  if (Array.isArray(value)) return value.map((item) => String(item)).join(', ');
  if (typeof value === 'object') {
    return Object.values(value as Record<string, unknown>)
      .map((item) => String(item))
      .join(', ');
  }
  return String(value);
}

onMounted(load);
</script>

<template>
  <div class="stack">
    <div class="grid-cards">
      <StatCard label="漏洞档案" :value="formatNumber(bundle.data.value.records.length)" hint="当前筛选结果" />
      <StatCard label="已验证" :value="formatNumber(verifiedCount)" tone="success" />
      <StatCard label="已发布" :value="formatNumber(publishedCount)" tone="info" />
      <StatCard label="靶场环境" :value="formatNumber(bundle.data.value.envs.length)" :hint="`运行记录 ${formatNumber(bundle.data.value.runs.length)} 条`" />
    </div>

    <el-card shadow="never">
      <template #header>
        漏洞档案
        <span class="head-note">列表接口只返回列字段；payload / 复现步骤需通过 hornworkctl vuln show 查看</span>
      </template>

      <div class="toolbar">
        <el-select v-model="filter.severity" placeholder="等级" clearable @change="load">
          <el-option label="严重" value="严重" />
          <el-option label="高" value="高" />
          <el-option label="中" value="中" />
          <el-option label="低" value="低" />
        </el-select>
        <el-input v-model="filter.cwe" placeholder="CWE（如 CWE-79）" clearable @keyup.enter="load" />
        <el-select v-model="filter.limit" class="is-wide" @change="load">
          <el-option :value="200" label="每页 200 条" />
          <el-option :value="500" label="每页 500 条" />
          <el-option :value="1000" label="每页 1000 条" />
        </el-select>
        <el-button :loading="bundle.loading.value" @click="load">刷新</el-button>
        <span class="spacer" />
        <span class="muted">CVSS 3.1 · 按分数降序</span>
      </div>

      <el-alert v-if="bundle.error.value" :title="bundle.error.value" type="error" :closable="false" show-icon />

      <el-table v-loading="bundle.loading.value" :data="bundle.data.value.records" size="small" empty-text="暂无漏洞档案">
        <el-table-column prop="id" label="档案 ID" width="170" show-overflow-tooltip />
        <el-table-column label="CVE" width="150">
          <template #default="{ row }"><span class="mono">{{ row.cve ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column prop="title" label="标题" min-width="220" show-overflow-tooltip />
        <el-table-column prop="component" label="组件" width="150" show-overflow-tooltip />
        <el-table-column label="CWE" width="100">
          <template #default="{ row }"><span class="mono">{{ row.cwe ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column label="CVSS" width="96">
          <template #default="{ row }">
            <span class="mono">{{ formatFloat(row.cvss_score) }}</span>
            <span v-if="row.cvss_score !== null && row.cvss_score !== undefined" class="muted">
              （{{ cvssBand(row.cvss_score) }}）
            </span>
          </template>
        </el-table-column>
        <el-table-column label="等级" width="92">
          <template #default="{ row }"><ToneBadge :value="row.severity" kind="severity" /></template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="更新" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.updated_at) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>
        靶场环境
        <span v-if="hasStarting" class="head-note">存在启动中的环境，每 3 秒自动刷新</span>
      </template>
      <el-table :data="bundle.data.value.envs" size="small" empty-text="暂无靶场环境">
        <el-table-column prop="env_id" label="环境" width="170" show-overflow-tooltip />
        <el-table-column label="状态" width="100">
          <template #default="{ row }"><ToneBadge :value="row.state" /></template>
        </el-table-column>
        <el-table-column label="运行中" width="86">
          <template #default="{ row }">{{ row.running ? '是' : '否' }}</template>
        </el-table-column>
        <el-table-column label="端口" min-width="150">
          <template #default="{ row }"><span class="mono">{{ portText(row.host_ports ?? row.ports) }}</span></template>
        </el-table-column>
        <el-table-column label="过期时间" width="170">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.expires_at) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>靶场运行记录</template>
      <el-table :data="bundle.data.value.runs" size="small" empty-text="暂无运行记录">
        <el-table-column prop="run_id" label="运行" width="180" show-overflow-tooltip />
        <el-table-column prop="env_id" label="环境" width="150" show-overflow-tooltip />
        <el-table-column label="动作" width="100">
          <template #default="{ row }">{{ row.action ?? '-' }}</template>
        </el-table-column>
        <el-table-column label="结果" width="110">
          <template #default="{ row }"><ToneBadge :value="row.result" /></template>
        </el-table-column>
        <el-table-column label="耗时" width="110">
          <template #default="{ row }"><span class="mono">{{ formatDuration(row.elapsed_ms) }}</span></template>
        </el-table-column>
        <el-table-column label="开始时间" width="170">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.started_at) }}</span></template>
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
