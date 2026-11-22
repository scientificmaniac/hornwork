<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { ElMessage } from 'element-plus';

import ToneBadge from '@/components/base/ToneBadge.vue';
import { detectionApi } from '@/api/modules/detection';
import { useAsync } from '@/composables/useAsync';
import type { RulesPayload } from '@/types/detection';
import { formatNumber, formatTime } from '@/utils/format';

const rules = useAsync<RulesPayload>({
  items: [],
  sources: {},
  missing: [],
  sigma: { total: 0, supported: 0, hits: 0 },
  reload: {},
});
const requesting = ref(false);

const SOURCE_LABELS: Record<string, string> = {
  yara: 'YARA',
  net: '网络规则',
  host: '主机规则',
  sigma: 'Sigma',
};

/** 按来源分组统计规则文件数与规则条数。 */
const bySource = computed(() => {
  const groups = new Map<string, { files: number; rules: number }>();
  for (const item of rules.data.value.items) {
    const bucket = groups.get(item.source) ?? { files: 0, rules: 0 };
    bucket.files += 1;
    bucket.rules += Number(item.rule_count ?? 0);
    groups.set(item.source, bucket);
  }
  return [...groups.entries()].map(([source, value]) => ({ source, ...value }));
});

function load(): Promise<RulesPayload | null> {
  return rules.run(() => detectionApi.rules(), { softError: false });
}

async function requestReload(): Promise<void> {
  requesting.value = true;
  try {
    const result = await detectionApi.reloadRules('来自控制台');
    ElMessage.success(`已记录重载请求（第 ${result.count ?? 1} 次），daemon 轮询后生效`);
    await load();
  } catch (cause) {
    ElMessage.error(cause instanceof Error ? cause.message : String(cause));
  } finally {
    requesting.value = false;
  }
}

const reloadHint = computed(() => {
  const reload = rules.data.value.reload;
  if (!reload.requested_at) return '尚未请求过热加载';
  return `最近请求：${formatTime(reload.requested_at)}（累计 ${formatNumber(reload.count ?? 0)} 次）`;
});

onMounted(load);
</script>

<template>
  <div class="stack">
    <el-card shadow="never">
      <template #header>
        规则
        <span class="head-note">只读清单：规则内容由 daemon 加载，控制台仅请求热加载标记</span>
      </template>

      <div class="toolbar">
        <el-button :loading="rules.loading.value" @click="load">刷新</el-button>
        <el-button type="primary" :loading="requesting" @click="requestReload">请求热加载</el-button>
        <span class="spacer" />
        <span class="muted">{{ reloadHint }}</span>
      </div>

      <el-alert v-if="rules.error.value" :title="rules.error.value" type="error" :closable="false" show-icon />
      <el-alert
        v-if="rules.data.value.missing.length > 0"
        :title="`以下规则目录不存在或不可读：${rules.data.value.missing.join('、')}`"
        type="warning"
        :closable="false"
        show-icon
      />

      <div class="grid-cards">
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">规则文件</div>
          <div class="mini-card__value mono">{{ formatNumber(rules.data.value.items.length) }}</div>
        </el-card>
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">Sigma 规则</div>
          <div class="mini-card__value mono">{{ formatNumber(rules.data.value.sigma.total) }}</div>
        </el-card>
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">Sigma 命中</div>
          <div class="mini-card__value mono">{{ formatNumber(rules.data.value.sigma.hits) }}</div>
        </el-card>
        <el-card shadow="never" class="mini-card">
          <div class="mini-card__label">重载请求</div>
          <div class="mini-card__value mono">{{ formatNumber(rules.data.value.reload.count ?? 0) }}</div>
        </el-card>
      </div>

      <el-descriptions title="规则来源路径" :column="2" border size="small" class="source-paths">
        <el-descriptions-item
          v-for="(path, source) in rules.data.value.sources"
          :key="source"
          :label="SOURCE_LABELS[source] ?? source"
        >
          <span class="mono">{{ path || '未配置' }}</span>
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card shadow="never">
      <template #header>来源汇总</template>
      <el-table :data="bySource" size="small" empty-text="未发现规则文件">
        <el-table-column label="来源" width="150">
          <template #default="{ row }">{{ SOURCE_LABELS[row.source] ?? row.source }}</template>
        </el-table-column>
        <el-table-column label="文件数" width="110">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.files) }}</span></template>
        </el-table-column>
        <el-table-column label="规则条数">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.rules) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>规则文件清单</template>
      <el-table
        v-loading="rules.loading.value"
        :data="rules.data.value.items"
        size="small"
        empty-text="未发现规则文件"
      >
        <el-table-column label="来源" width="110">
          <template #default="{ row }">
            <el-tag size="small" type="info" disable-transitions>{{ row.source }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="名称" min-width="180" show-overflow-tooltip />
        <el-table-column prop="id" label="标识" min-width="150" show-overflow-tooltip />
        <el-table-column label="规则数" width="90">
          <template #default="{ row }">
            <span class="mono">{{ row.rule_count ?? '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="级别" width="90">
          <template #default="{ row }">
            <ToneBadge v-if="row.level !== null && row.level !== undefined" :value="row.level" kind="severity" />
            <span v-else class="muted">-</span>
          </template>
        </el-table-column>
        <el-table-column label="技术" width="110">
          <template #default="{ row }"><span class="mono">{{ row.technique ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column label="大小" width="90">
          <template #default="{ row }"><span class="mono">{{ formatNumber(row.size) }} B</span></template>
        </el-table-column>
        <el-table-column label="更新时间" width="160">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.mtime) }}</span></template>
        </el-table-column>
        <el-table-column label="说明" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.error" class="error-text">{{ row.error }}</span>
            <span v-else class="muted">{{ row.description ?? (row.rules ?? []).slice(0, 3).join(', ') }}</span>
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
.mini-card__label {
  font-size: 12px;
  color: var(--text-muted);
}
.mini-card__value {
  font-size: 20px;
  font-weight: 600;
  color: var(--text-strong);
  margin-top: 2px;
}
.source-paths {
  margin-top: 6px;
}
.error-text {
  color: var(--tone-danger);
}
</style>
