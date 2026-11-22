<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';

import StatCard from '@/components/base/StatCard.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import { authApi } from '@/api/modules/auth';
import { useAsync } from '@/composables/useAsync';
import { useAuthStore } from '@/stores/auth';
import type { AuditPayload, PolicyMap, SessionRow, UserRow } from '@/types/auth';
import { formatJson, formatNumber, formatTime } from '@/utils/format';
import { parseEmbedding } from '@/utils/embedding';

interface AuthBundle {
  users: UserRow[];
  sessions: SessionRow[];
  policy: PolicyMap;
  audit: AuditPayload;
}

const auth = useAuthStore();
const bundle = useAsync<AuthBundle | null>(null);
const auditLimit = reactive({ value: 30 });
const stepUpVisible = ref(false);
const stepUpForm = reactive({ totp: '', embedding: '' });
const stepUpBusy = ref(false);

function load(): Promise<AuthBundle | null> {
  return bundle.run(async () => {
    const [users, sessions, policy, audit] = await Promise.all([
      authApi.users(),
      authApi.sessions(),
      authApi.policy(),
      authApi.audit(auditLimit.value),
    ]);
    return { users, sessions, policy, audit };
  }, { softError: false });
}

const users = computed(() => bundle.data.value?.users ?? []);
const sessions = computed(() => bundle.data.value?.sessions ?? []);
const policy = computed(() => bundle.data.value?.policy ?? {});
const audit = computed(() => bundle.data.value?.audit);
const chain = computed(() => audit.value?.chain ?? { ok: true });

/** 有效会话：未吊销且未过期（后端 sessions 接口已按创建时间倒序，最多 50 条）。 */
const activeSessions = computed(() => sessions.value.filter((item) => !item.revoked));

/** 锁定阈值：来自 `lockout` 策略组，用于指标卡。 */
const lockout = computed(() => {
  const value = policy.value['lockout'];
  return value && typeof value === 'object' ? (value as Record<string, number>) : {};
});

const policyGroups = computed<[string, unknown][]>(() => Object.entries(policy.value));

/** 当前会话 LOA 不足 3 时给 step-up 入口（后端 stepup 需要 TOTP + 人脸）。 */
const needsStepUp = computed(() => auth.loa < 3);

async function openStepUp(): Promise<void> {
  stepUpForm.totp = '';
  stepUpForm.embedding = '';
  stepUpVisible.value = true;
}

async function submitStepUp(): Promise<void> {
  stepUpBusy.value = true;
  try {
    const embedding = stepUpForm.embedding.trim() ? parseEmbedding(stepUpForm.embedding) : undefined;
    const result = await auth.stepUp(stepUpForm.totp.trim(), embedding);
    if (result.status === 'ok') {
      ElMessage.success(`会话已升级到 ${result.loa_name ?? 'LOA3'}`);
      stepUpVisible.value = false;
      stepUpForm.totp = '';
      stepUpForm.embedding = '';
      return;
    }
    if (result.status === 'bio_required') {
      ElMessage.info('需要人脸向量：请贴入 512 维向量 JSON 后重试');
      return;
    }
    ElMessage.error(`提升失败：${result.reason ?? result.message ?? result.status}`);
  } catch (cause) {
    ElMessage.error(cause instanceof Error ? cause.message : String(cause));
  } finally {
    stepUpBusy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="stack">
    <div class="grid-cards">
      <StatCard label="用户" :value="formatNumber(users.length)" :hint="`有效会话 ${formatNumber(activeSessions.length)}`" />
      <StatCard
        label="审计链"
        :value="chain.ok ? '正常' : '异常'"
        :hint="`已校验 ${formatNumber(chain.checked ?? 0)} 条`"
        :tone="chain.ok ? 'success' : 'danger'"
      />
      <StatCard label="账号失败阈值" :value="formatNumber(lockout.account_fail)" hint="超过即锁定" tone="warning" />
      <StatCard label="当前 LOA" :value="auth.displayLoa" :tone="needsStepUp ? 'warning' : 'success'" />
    </div>

    <el-card shadow="never">
      <template #header>
        身份认证
        <span class="head-note">三因子：口令 + TOTP + 人脸模板；风险评分驱动 LOA 与锁定</span>
      </template>
      <div class="toolbar">
        <el-button :loading="bundle.loading.value" @click="load">刷新</el-button>
        <el-select v-model="auditLimit.value" class="is-wide" @change="load">
          <el-option :value="30" label="审计 30 条" />
          <el-option :value="100" label="审计 100 条" />
          <el-option :value="200" label="审计 200 条" />
        </el-select>
        <span class="spacer" />
        <el-button v-if="needsStepUp" type="primary" @click="openStepUp">提升认证等级</el-button>
      </div>

      <el-alert v-if="bundle.error.value" :title="bundle.error.value" type="error" :closable="false" show-icon />
      <el-alert
        v-if="!chain.ok"
        :title="`审计链校验未通过：${chain.reason ?? chain.error ?? 'hash_mismatch'}（bad_id=${chain.bad_id ?? '-'}）`"
        type="error"
        :closable="false"
        show-icon
      />
    </el-card>

    <el-card shadow="never">
      <template #header>用户</template>
      <el-table :data="users" size="small" empty-text="暂无用户">
        <el-table-column prop="username" label="用户名" width="150" />
        <el-table-column prop="display_name" label="显示名" width="150" show-overflow-tooltip />
        <el-table-column label="状态" width="100">
          <template #default="{ row }"><ToneBadge :value="row.status" /></template>
        </el-table-column>
        <el-table-column label="LOA 上限" width="100">
          <template #default="{ row }"><span class="mono">LOA{{ row.loa_max }}</span></template>
        </el-table-column>
        <el-table-column label="MFA" width="90">
          <template #default="{ row }">
            <ToneBadge :value="row.mfa_enabled ? 'ok' : 'stopped'" :label="row.mfa_enabled ? '已启用' : '未启用'" />
          </template>
        </el-table-column>
        <el-table-column label="口令算法" width="130">
          <template #default="{ row }"><span class="mono">{{ row.password_algo ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column label="失败次数" width="100">
          <template #default="{ row }"><span class="mono">{{ row.failed_count ?? 0 }}</span></template>
        </el-table-column>
        <el-table-column label="锁定至" width="170">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.locked_until) }}</span></template>
        </el-table-column>
        <el-table-column label="最近登录" width="170">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.last_login_ts) }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>会话</template>
      <el-table :data="sessions" size="small" empty-text="暂无会话">
        <el-table-column label="会话 ID" width="170" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.session_id }}</span></template>
        </el-table-column>
        <el-table-column label="用户" width="80">
          <template #default="{ row }">{{ row.user_id }}</template>
        </el-table-column>
        <el-table-column label="LOA" width="80">
          <template #default="{ row }"><span class="mono">L{{ row.loa }}</span></template>
        </el-table-column>
        <el-table-column prop="ip" label="IP" width="130" />
        <el-table-column label="创建" width="170">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.created_ts) }}</span></template>
        </el-table-column>
        <el-table-column label="空闲到期" width="170">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.idle_expires_ts) }}</span></template>
        </el-table-column>
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <ToneBadge :value="row.revoked ? 'revoked' : 'active'" />
          </template>
        </el-table-column>
        <el-table-column label="吊销原因" min-width="130" show-overflow-tooltip>
          <template #default="{ row }">{{ row.revoke_reason ?? '-' }}</template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>认证策略</template>
      <el-collapse>
        <el-collapse-item v-for="[key, value] in policyGroups" :key="key" :title="key" :name="key">
          <pre class="json-block">{{ formatJson(value) }}</pre>
        </el-collapse-item>
      </el-collapse>
    </el-card>

    <el-card shadow="never">
      <template #header>
        审计
        <span class="head-note">{{ chain.ok ? '哈希链校验通过' : '哈希链校验未通过' }}</span>
      </template>
      <el-table :data="audit?.items ?? []" size="small" empty-text="暂无审计记录">
        <el-table-column label="时间" width="170">
          <template #default="{ row }"><span class="mono">{{ formatTime(row.ts) }}</span></template>
        </el-table-column>
        <el-table-column label="事件" width="120">
          <template #default="{ row }"><ToneBadge :value="row.event" /></template>
        </el-table-column>
        <el-table-column prop="username" label="用户" width="130" />
        <el-table-column prop="factor" label="因子" width="100" />
        <el-table-column label="结果" width="100">
          <template #default="{ row }"><ToneBadge :value="row.result" /></template>
        </el-table-column>
        <el-table-column label="LOA" width="76">
          <template #default="{ row }"><span class="mono">{{ row.loa ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column label="风险分" width="90">
          <template #default="{ row }"><span class="mono">{{ row.risk_score ?? '-' }}</span></template>
        </el-table-column>
        <el-table-column prop="ip" label="IP" width="130" />
        <el-table-column label="详情" min-width="200" show-overflow-tooltip>
          <template #default="{ row }"><span class="muted">{{ row.detail ?? '-' }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="stepUpVisible" title="提升认证等级（step-up）" width="560px">
      <el-alert
        title="step-up 需要 TOTP 与人脸模板：贴入 512 维向量 JSON 后才能升到 LOA3"
        type="info"
        :closable="false"
        show-icon
      />
      <el-form label-width="90px" class="stepup-form">
        <el-form-item label="动态码" required>
          <el-input v-model="stepUpForm.totp" maxlength="8" placeholder="6 位 TOTP" />
        </el-form-item>
        <el-form-item label="人脸向量">
          <el-input
            v-model="stepUpForm.embedding"
            type="textarea"
            :rows="4"
            placeholder="[0.12, -0.03, ...] 或 {&quot;vector&quot;: [...]}"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="stepUpVisible = false">取消</el-button>
        <el-button type="primary" :loading="stepUpBusy" @click="submitStepUp">提交</el-button>
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
.json-block {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text-muted);
  background: var(--surface-alt);
  border-radius: 4px;
  padding: 8px 10px;
}
.stepup-form {
  margin-top: 12px;
}
</style>
