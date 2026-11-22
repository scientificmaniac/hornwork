<script setup lang="ts">
import { onMounted } from 'vue';

import { scanApi } from '@/api/modules/scan';
import { useReport } from '@/composables/useReport';
import { useAsync } from '@/composables/useAsync';
import type { ReportItem } from '@/types/scan';
import { formatBytes, formatTime } from '@/utils/format';

const reports = useAsync<ReportItem[]>([]);
const viewer = useReport();

function load(): Promise<ReportItem[] | null> {
  return reports.run(() => scanApi.reports(), { softError: false });
}

function open(item: ReportItem): void {
  void viewer.openReport(item.rel);
}

onMounted(load);
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>
        扫描报告
        <span class="head-note">报告由 daemon 生成（HTML）；控制台通过 /api/report 只读预览</span>
      </template>

      <div class="toolbar">
        <el-button :loading="reports.loading.value" @click="load">刷新</el-button>
        <span class="spacer" />
        <span class="muted">最近 20 份</span>
      </div>

      <el-alert v-if="reports.error.value" :title="reports.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="viewer.error.value" :title="viewer.error.value" type="error" :closable="false" show-icon />

      <el-table v-loading="reports.loading.value" :data="reports.data.value" size="small" empty-text="暂无扫描报告">
        <el-table-column prop="name" label="报告文件" min-width="260" show-overflow-tooltip />
        <el-table-column label="路径" min-width="200" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono muted">{{ row.rel }}</span></template>
        </el-table-column>
        <el-table-column label="大小" width="110">
          <template #default="{ row }"><span class="mono">{{ formatBytes(row.size) }}</span></template>
        </el-table-column>
        <el-table-column label="生成时间" width="170">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.mtime) }}</span></template>
        </el-table-column>
        <el-table-column label="操作" width="110" align="right">
          <template #default="{ row }">
            <el-button size="small" :loading="viewer.busy.value" @click="open(row)">查看</el-button>
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
