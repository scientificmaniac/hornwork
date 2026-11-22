<script setup lang="ts">
import { computed, onMounted, reactive } from 'vue';

import EChart from '@/components/charts/EChart.vue';
import { detectionApi } from '@/api/modules/detection';
import { useAsync } from '@/composables/useAsync';
import { useReport } from '@/composables/useReport';
import type { ValidationPayload } from '@/types/detection';
import { formatFloat, formatNumber, formatPercent } from '@/utils/format';
import { barOption } from '@/utils/charts';

const validation = useAsync<ValidationPayload>({
  run_id: null,
  rows: [],
  metrics: null,
  report_path: null,
  md_path: null,
});
const filter = reactive({ runId: '', limit: 500 });
const report = useReport();

function load(): Promise<ValidationPayload | null> {
  return validation.run(() =>
    detectionApi.validate({
      run_id: filter.runId.trim() || undefined,
      limit: filter.limit,
    }),
  );
}

const metrics = computed(() => validation.data.value.metrics);
const rows = computed(() => validation.data.value.rows);

const verdictChart = computed(() => {
  const value = metrics.value;
  if (!value) return null;
  return barOption(
    ['TP', 'TN', 'FP', 'FN', '未定'],
    [value.TP, value.TN, value.FP, value.FN, value.inconclusive],
  );
});

/** 判定结果四象限配色：TP/TN 为正常，FP/FN 为异常。 */
const VERDICT_TONE: Record<string, 'success' | 'danger' | 'info'> = {
  TP: 'success',
  TN: 'success',
  FP: 'danger',
  FN: 'danger',
  inconclusive: 'info',
};

/** 验证报告路径是服务端绝对路径，`/api/report` 只接受 reports 根目录下的相对路径。 */
function toReportRel(path: string | null | undefined): string {
  if (!path) return '';
  const marker = '/reports/';
  const index = path.lastIndexOf(marker);
  return index >= 0 ? path.slice(index + marker.length) : '';
}

const reportRel = computed(() => toReportRel(validation.data.value.report_path));
const mdRel = computed(() => toReportRel(validation.data.value.md_path));
const reportHint = computed(() => {
  if (!validation.data.value.report_path) return '';
  return reportRel.value
    ? ''
    : `报告路径不在 reports 根目录下，无法在线打开：${validation.data.value.report_path}`;
});

onMounted(load);
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>
        验证
        <span class="head-note">对最近一次验证运行做指标汇总与用例明细核对</span>
      </template>

      <div class="toolbar">
        <el-input v-model="filter.runId" class="is-wide" placeholder="run_id（留空取最近一次）" clearable @keyup.enter="load" />
        <el-select v-model="filter.limit" class="is-wide" @change="load">
          <el-option :value="500" label="每页 500 条" />
          <el-option :value="1000" label="每页 1000 条" />
          <el-option :value="2000" label="每页 2000 条" />
        </el-select>
        <el-button :loading="validation.loading.value" @click="load">加载</el-button>
        <span class="spacer" />
        <el-button :disabled="!reportRel" :loading="report.busy.value" @click="report.openReport(reportRel)">
          打开 JSON 报告
        </el-button>
        <el-button :disabled="!mdRel" :loading="report.busy.value" @click="report.openReport(mdRel)">
          打开 Markdown 报告
        </el-button>
      </div>

      <el-alert v-if="validation.error.value" :title="validation.error.value" type="error" :closable="false" show-icon />
      <el-alert v-if="reportHint" :title="reportHint" type="warning" :closable="false" show-icon />
      <el-alert v-if="report.error.value" :title="report.error.value" type="error" :closable="false" show-icon />

      <el-empty v-if="!validation.loading.value && !validation.data.value.run_id" description="尚无验证运行记录" :image-size="70" />
    </el-card>

    <template v-if="validation.data.value.run_id">
      <div class="grid-cards">
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">运行</div>
          <div class="mini-card__value mono small-value">{{ validation.data.value.run_id }}</div>
        </el-card>
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">用例数</div>
          <div class="mini-card__value mono">{{ formatNumber(validation.data.value.case_count) }}</div>
        </el-card>
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">TPR</div>
          <div class="mini-card__value mono">{{ formatPercent(metrics?.tpr) }}</div>
        </el-card>
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">FPR</div>
          <div class="mini-card__value mono">{{ formatPercent(metrics?.fpr) }}</div>
        </el-card>
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">覆盖率</div>
          <div class="mini-card__value mono">{{ formatPercent(metrics?.coverage) }}</div>
        </el-card>
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">MTTD</div>
          <div class="mini-card__value mono">{{ formatFloat(metrics?.mttd_sec, 1) }} s</div>
        </el-card>
      </div>

      <el-card shadow="never">
        <template #header>判定分布</template>
        <EChart
          v-if="verdictChart"
          :option="verdictChart"
          height="200px"
          :empty="rows.length === 0"
          empty-text="暂无判据"
        />
        <el-empty v-else description="暂无判据" :image-size="60" />
      </el-card>

      <el-card shadow="never">
        <template #header>用例明细</template>
        <el-table v-loading="validation.loading.value" :data="rows" size="small" empty-text="该运行没有用例">
          <el-table-column prop="case_id" label="用例" width="130" />
          <el-table-column label="名称" min-width="180" show-overflow-tooltip>
            <template #default="{ row }">{{ row.name ?? '-' }}</template>
          </el-table-column>
          <el-table-column label="技术" width="130">
            <template #default="{ row }"><span class="mono">{{ row.technique ?? '-' }}</span></template>
          </el-table-column>
          <el-table-column label="期望" width="110">
            <template #default="{ row }">{{ row.expected ?? '-' }}</template>
          </el-table-column>
          <el-table-column label="观测" width="110">
            <template #default="{ row }">{{ row.observed ?? '-' }}</template>
          </el-table-column>
          <el-table-column label="判定" width="96">
            <template #default="{ row }">
              <el-tag :type="VERDICT_TONE[row.verdict] ?? 'info'" size="small" disable-transitions>
                {{ row.verdict ?? '-' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="MTTD" width="92">
            <template #default="{ row }">
              <span class="mono">{{ row.mttd_sec === null || row.mttd_sec === undefined ? '-' : `${formatFloat(row.mttd_sec, 1)} s` }}</span>
            </template>
          </el-table-column>
          <el-table-column label="备注" min-width="180" show-overflow-tooltip>
            <template #default="{ row }">
              <span v-if="row.error" class="error-text">{{ row.error }}</span>
              <span v-else class="muted">-</span>
            </template>
          </el-table-column>
        </el-table>
      </el-card>

      <el-card shadow="never">
        <template #header>验证元数据</template>
        <el-descriptions :column="2" border size="small">
          <el-descriptions-item label="run_id"><span class="mono">{{ validation.data.value.run_id }}</span></el-descriptions-item>
          <el-descriptions-item label="用例数">{{ formatNumber(validation.data.value.case_count) }}</el-descriptions-item>
          <el-descriptions-item label="JSON 报告"><span class="mono">{{ validation.data.value.report_path ?? '-' }}</span></el-descriptions-item>
          <el-descriptions-item label="Markdown 报告"><span class="mono">{{ validation.data.value.md_path ?? '-' }}</span></el-descriptions-item>
        </el-descriptions>
      </el-card>
    </template>
  </div>
</template>

<style scoped>
.head-note {
  margin-left: 10px;
  font-size: 11px;
  font-weight: 400;
  color: var(--text-faint);
}
.mini-card__label {
  font-size: 12px;
  color: var(--text-muted);
}
.mini-card__value {
  font-size: 20px;
  font-weight: 600;
  color: var(--text-strong);
  margin-top: 2px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.small-value {
  font-size: 13px;
}
.error-text {
  color: var(--tone-danger);
}
</style>
