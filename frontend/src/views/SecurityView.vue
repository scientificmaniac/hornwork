<script setup lang="ts">
import { computed, onMounted } from 'vue';

import StatCard from '@/components/base/StatCard.vue';
import ToneBadge from '@/components/base/ToneBadge.vue';
import { platformApi } from '@/api/modules/platform';
import { useAsync } from '@/composables/useAsync';
import type { PlatformSecurity } from '@/types/harden';
import { formatBool, formatNumber, formatTime } from '@/utils/format';

const security = useAsync<PlatformSecurity>({
  ts: '',
  https: {},
  lockout: {},
  paths: {},
  service: {},
});

function load(): Promise<PlatformSecurity | null> {
  return security.run(() => platformApi.security(), { softError: false });
}

const https = computed(() => security.data.value.https);
const service = computed(() => security.data.value.service);
const bind = computed(() => security.data.value.bind);

/** 检查项：把“实测值 + 结论”放在一行，便于逐项对照基线。 */
const checks = computed(() => {
  const list: { id: string; title: string; actual: string; ok: boolean | null }[] = [
    {
      id: 'H-PL-01',
      title: 'HTTPS 反代入口',
      actual: https.value.ok
        ? `${https.value.protocol ?? '-'} / ${https.value.cipher ?? '-'}`
        : (https.value.error ?? '未检测到 8443 TLS 入口'),
      ok: Boolean(https.value.ok),
    },
    {
      id: 'H-PL-02',
      title: '登录锁定策略',
      actual: Object.keys(security.data.value.lockout).length > 0
        ? `失败 ${security.data.value.lockout.account_fail ?? '-'} 次锁 ${security.data.value.lockout.lock_seconds ?? '-'} 秒`
        : '策略不可读',
      ok: Object.keys(security.data.value.lockout).length > 0,
    },
    {
      id: 'H-PL-04',
      title: '服务运行身份',
      actual: service.value.error
        ? service.value.error
        : `${service.value.user ?? '-'}（非 root 为合规）`,
      ok: service.value.error ? null : service.value.user !== 'root' && service.value.user !== '',
    },
    {
      id: 'BIND',
      title: '平台监听地址',
      actual: bind.value
        ? `${bind.value.host}:${bind.value.port}（token 鉴权 ${formatBool(bind.value.token_auth)}）`
        : '不可读',
      ok: bind.value ? bind.value.host === '127.0.0.1' || Boolean(bind.value.tls_ingress) : null,
    },
  ];
  return list;
});

/** 关键路径权限：mode 为八进制字符串；uid/gid 非 0 视为已降权。 */
const pathRows = computed(() =>
  Object.entries(security.data.value.paths).map(([path, info]) => ({
    path,
    mode: info.mode ?? '-',
    uid: info.uid ?? '-',
    gid: info.gid ?? '-',
    exists: info.exists,
    /** 世界可写属于明显问题；其它权限由加固模块的基线项判定。 */
    worldWritable: info.exists && typeof info.mode === 'string' ? /[2367]$/.test(info.mode) : false,
  })),
);

onMounted(load);
</script>

<template>
  <div class="stack">
    <div class="grid-cards">
      <StatCard
        label="HTTPS 入口"
        :value="https.ok ? '正常' : '未启用'"
        :hint="https.ok ? (https.protocol ?? '') : 'nginx 8443 反代未就绪'"
        :tone="https.ok ? 'success' : 'warning'"
      />
      <StatCard
        label="服务身份"
        :value="service.user ?? '-'"
        :hint="service.user && service.user !== 'root' ? '非 root，符合要求' : '以 root 运行，风险较高'"
        :tone="service.user && service.user !== 'root' ? 'success' : 'danger'"
      />
      <StatCard label="监听地址" :value="bind ? `${bind.host}:${bind.port}` : '-'" hint="回环或 TLS 反代均可" :tone="bind?.host === '127.0.0.1' || bind?.tls_ingress ? 'success' : 'warning'" />
      <StatCard label="Token 鉴权" :value="formatBool(bind?.token_auth)" hint="静态 Bearer 或会话令牌" />
    </div>

    <el-card shadow="never">
      <template #header>
        平台安全
        <span class="head-note">全部为实测值：TLS 握手、systemd 属性与文件权限，不做假设</span>
      </template>
      <div class="toolbar">
        <el-button :loading="security.loading.value" @click="load">刷新</el-button>
        <span class="spacer" />
        <span class="muted">采集时间 {{ formatTime(security.data.value.ts) }}</span>
      </div>
      <el-alert v-if="security.error.value" :title="security.error.value" type="error" :closable="false" show-icon />
    </el-card>

    <el-card shadow="never">
      <template #header>检查项</template>
      <el-table :data="checks" size="small">
        <el-table-column prop="id" label="编号" width="110" />
        <el-table-column prop="title" label="检查项" width="200" />
        <el-table-column prop="actual" label="实测值" min-width="280" show-overflow-tooltip />
        <el-table-column label="结论" width="110">
          <template #default="{ row }">
            <ToneBadge
              :value="row.ok === null ? 'unknown' : row.ok ? 'ok' : 'fail'"
              :label="row.ok === null ? '不可判定' : row.ok ? '通过' : '待整改'"
            />
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never">
      <template #header>服务单元</template>
      <el-descriptions :column="1" border size="small" empty-text="不可读">
        <el-descriptions-item label="单元">{{ service.unit ?? '-' }}</el-descriptions-item>
        <el-descriptions-item label="运行用户">{{ service.user ?? '-' }}</el-descriptions-item>
        <el-descriptions-item label="沙箱属性">
          <span class="mono">{{ (service.sandbox ?? []).join(' / ') || '-' }}</span>
        </el-descriptions-item>
      </el-descriptions>
    </el-card>

    <el-card shadow="never">
      <template #header>关键路径权限</template>
      <el-table :data="pathRows" size="small" empty-text="无可读路径">
        <el-table-column label="路径" min-width="260" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.path }}</span></template>
        </el-table-column>
        <el-table-column label="权限" width="110">
          <template #default="{ row }">
            <span class="mono" :class="{ 'error-text': row.worldWritable }">{{ row.mode }}</span>
          </template>
        </el-table-column>
        <el-table-column label="uid" width="90">
          <template #default="{ row }"><span class="mono">{{ row.uid }}</span></template>
        </el-table-column>
        <el-table-column label="gid" width="90">
          <template #default="{ row }"><span class="mono">{{ row.gid }}</span></template>
        </el-table-column>
        <el-table-column label="存在" width="90">
          <template #default="{ row }">
            <ToneBadge :value="row.exists ? 'ok' : 'fail'" :label="row.exists ? '是' : '否'" />
          </template>
        </el-table-column>
        <el-table-column label="风险" min-width="140">
          <template #default="{ row }">
            <span v-if="row.worldWritable" class="error-text">其他用户可写</span>
            <span v-else class="muted">-</span>
          </template>
        </el-table-column>
      </el-table>
      <p class="muted footer-note">
        权限基线由加固模块 H-PL-03 固化；此处只做只读核对，共 {{ formatNumber(pathRows.length) }} 个路径。
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
.footer-note {
  margin: 8px 0 0;
  font-size: 11px;
}
</style>
