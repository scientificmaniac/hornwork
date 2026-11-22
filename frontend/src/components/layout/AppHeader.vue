<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ElMessageBox } from 'element-plus';

import { useAppStore } from '@/stores/app';
import { useAuthStore } from '@/stores/auth';
import { useReport } from '@/composables/useReport';

const app = useAppStore();
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();
const report = useReport();

const reloading = ref(false);

const title = computed(() => String(route.meta.title ?? '控制台'));
/** 降级认证提示：`degraded=true` 时顶栏常驻告警。 */
const degradedHint = computed(() => (auth.degradedReason ? `降级认证：${auth.degradedReason}` : ''));

async function logout(): Promise<void> {
  try {
    await ElMessageBox.confirm('确认退出当前会话？', '退出登录', {
      confirmButtonText: '退出',
      cancelButtonText: '取消',
      type: 'warning',
    });
  } catch {
    return;
  }
  await auth.logout();
  await router.replace({ name: 'login' });
}

async function exportAlerts(): Promise<void> {
  reloading.value = true;
  try {
    await report.exportAs('alerts', 'jsonl', '24h');
  } finally {
    reloading.value = false;
  }
}
</script>

<template>
  <header class="header">
    <h1 class="header__title">{{ title }}</h1>
    <span v-if="degradedHint" class="header__degraded">{{ degradedHint }}</span>
    <div class="header__meta">
      <span v-if="auth.info" class="header__loa" :title="`用户 ${auth.username}`">
        {{ auth.username }} · {{ auth.displayLoa }}
      </span>
      <el-button size="small" text @click="exportAlerts">导出告警</el-button>
      <el-button size="small" text @click="app.toggleTheme()">
        {{ app.isDark ? '浅色' : '深色' }}
      </el-button>
      <el-button size="small" @click="logout">退出</el-button>
    </div>
  </header>
</template>

<style scoped>
.header {
  height: 54px;
  flex: 0 0 54px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 18px;
}
.header__title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
  color: var(--text-strong);
  white-space: nowrap;
}
.header__degraded {
  font-size: 11px;
  color: var(--badge-warning-fg);
  background: var(--badge-warning-bg);
  border-radius: 9px;
  padding: 1px 8px;
}
.header__meta {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-muted);
  font-size: 12px;
}
.header__loa {
  font-family: var(--font-mono);
  margin-right: 4px;
}
@media (max-width: 900px) {
  .header__loa {
    display: none;
  }
}
</style>
