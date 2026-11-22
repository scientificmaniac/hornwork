<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';

import ToneBadge from '@/components/base/ToneBadge.vue';
import { detectionApi } from '@/api/modules/detection';
import { useAsync } from '@/composables/useAsync';
import type { ListPayload } from '@/types/common';
import type { CaseRecord } from '@/types/detection';
import { formatTime } from '@/utils/format';
import { CASE_SEVERITY_OPTIONS, CASE_STATUS_OPTIONS, VERDICT_OPTIONS } from '@/utils/options';
import { statusLabel } from '@/utils/badge';

const list = useAsync<ListPayload<CaseRecord>>({ items: [], total: 0 });
const filter = reactive({ status: '', limit: 100 });

const createVisible = ref(false);
const creating = ref(false);
const form = reactive({
  title: '',
  severity: 'P3',
  verdict: 'unknown',
  dedup_key: '',
});

/** 工单状态机：按后端 `open→investigating→contained→closed` 展示进度。 */
const STAGES = ['open', 'investigating', 'contained', 'closed'] as const;

function load(): Promise<ListPayload<CaseRecord> | null> {
  return list.run(() =>
    detectionApi.cases({ status: filter.status || undefined, limit: filter.limit }),
  );
}

/** 每种状态的数量（当前页统计，用于看板）；后端无聚合接口，只能就本页统计。 */
const statusCounts = computed(() => {
  const counts: Record<string, number> = {};
  for (const item of list.data.value.items) {
    const key = String(item.status ?? 'unknown');
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
});

function stageIndex(status: unknown): number {
  const index = STAGES.indexOf(String(status) as (typeof STAGES)[number]);
  return index < 0 ? 0 : index;
}

function openCreate(): void {
  form.title = '';
  form.severity = 'P3';
  form.verdict = 'unknown';
  form.dedup_key = '';
  createVisible.value = true;
}

async function submitCreate(): Promise<void> {
  if (!form.title.trim()) {
    ElMessage.warning('请填写工单标题');
    return;
  }
  creating.value = true;
  try {
    const result = await detectionApi.createCase({
      title: form.title.trim(),
      severity: form.severity,
      verdict: form.verdict,
      dedup_key: form.dedup_key.trim() || undefined,
    });
    ElMessage.success(`已创建工单 ${result.case_id}`);
    createVisible.value = false;
    await load();
  } catch (cause) {
    ElMessage.error(cause instanceof Error ? cause.message : String(cause));
  } finally {
    creating.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>
        工单
        <span class="head-note">处置动作与审批只能通过 hornworkctl respond 执行，本页仅做记录与建档</span>
      </template>

      <div class="toolbar">
        <el-select v-model="filter.status" placeholder="状态" clearable @change="load">
          <el-option v-for="option in CASE_STATUS_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
        </el-select>
        <el-select v-model="filter.limit" class="is-wide" @change="load">
          <el-option :value="100" label="每页 100 条" />
          <el-option :value="500" label="每页 500 条" />
          <el-option :value="1000" label="每页 1000 条" />
        </el-select>
        <el-button :loading="list.loading.value" @click="load">刷新</el-button>
        <span class="spacer" />
        <el-button type="primary" @click="openCreate">新建工单</el-button>
      </div>

      <div class="stage-bar">
        <div v-for="(stage, index) in STAGES" :key="stage" class="stage-cell">
          <span class="stage-cell__index">{{ index + 1 }}</span>
          <span class="stage-cell__label">{{ statusLabel(stage) }}</span>
          <span class="stage-cell__count mono">{{ statusCounts[stage] ?? 0 }}</span>
        </div>
      </div>

      <el-alert v-if="list.error.value" :title="list.error.value" type="error" :closable="false" show-icon />

      <el-table v-loading="list.loading.value" :data="list.data.value.items" size="small" empty-text="暂无工单">
        <el-table-column prop="case_id" label="工单号" width="180" show-overflow-tooltip />
        <el-table-column prop="title" label="标题" min-width="220" show-overflow-tooltip />
        <el-table-column label="严重级" width="96">
          <template #default="{ row }">
            <ToneBadge :value="row.severity" kind="severity" :label="row.severity ?? '-'" />
          </template>
        </el-table-column>
        <el-table-column label="状态" width="100">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="判定" width="96">
          <template #default="{ row }">
            <span class="muted">{{ row.verdict ?? '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="进度" width="180">
          <template #default="{ row }">
            <el-steps :active="stageIndex(row.status)" :space="26" simple size="small">
              <el-step v-for="stage in STAGES" :key="stage" :title="statusLabel(stage)" />
            </el-steps>
          </template>
        </el-table-column>
        <el-table-column label="创建时间" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.created_at) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="createVisible" title="新建工单" width="520px">
      <el-form label-width="88px">
        <el-form-item label="标题" required>
          <el-input v-model="form.title" maxlength="200" show-word-limit placeholder="一句话描述事件" />
        </el-form-item>
        <el-form-item label="严重级">
          <el-select v-model="form.severity">
            <el-option v-for="option in CASE_SEVERITY_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="判定">
          <el-select v-model="form.verdict">
            <el-option v-for="option in VERDICT_OPTIONS" :key="option.value" :label="option.label" :value="option.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="去重键">
          <el-input v-model="form.dedup_key" placeholder="可选，重复建单时用于归并" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="submitCreate">创建</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.head-note {
  margin-left: 10px;
  font-size: 11px;
  font-weight: 400;
  color: var(--text-faint);
}
.stage-bar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 8px;
  margin-bottom: 12px;
}
.stage-cell {
  display: flex;
  align-items: center;
  gap: 6px;
  border: 1px solid var(--border-soft);
  border-radius: 5px;
  padding: 6px 10px;
  font-size: 12px;
  background: var(--surface-alt);
}
.stage-cell__index {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--tone-info);
  color: #fff;
  font-size: 11px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.stage-cell__label {
  flex: 1;
  color: var(--text-strong);
}
.stage-cell__count {
  color: var(--text-muted);
}
</style>
