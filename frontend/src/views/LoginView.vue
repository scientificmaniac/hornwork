<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { describeError } from '@/composables/useAsync';
import { useAuthStore } from '@/stores/auth';
import { readFileText } from '@/utils/browser';
import { EmbeddingError, parseEmbedding } from '@/utils/embedding';

const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

const form = reactive({
  username: '',
  password: '',
  ip: '127.0.0.1',
  /** 人脸向量 JSON 文本；留空表示只做口令登录（LOA2）。 */
  embeddingText: '',
});

const errorText = ref('');
const noticeText = ref('');
/** TOTP 挑战态：后端返回 `totp_required` 后进入。 */
const challenge = reactive({ active: false, id: '' as string, requiredLoa: 0, totp: '' });

const submitting = ref(false);
const canSubmit = computed(
  () => form.username.trim().length > 0 && form.password.length > 0 && !submitting.value,
);

/** 载入人脸向量文件（`.json`），只读入内存，提交后立即清空。 */
async function loadEmbeddingFile(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    errorText.value = '人脸向量文件超过 2MB（后端请求体上限）';
    input.value = '';
    return;
  }
  try {
    form.embeddingText = await readFileText(file);
    errorText.value = '';
    noticeText.value = `已载入 ${file.name}`;
  } catch (cause) {
    errorText.value = describeError(cause);
  } finally {
    input.value = '';
  }
}

function resetChallenge(): void {
  challenge.active = false;
  challenge.id = '';
  challenge.requiredLoa = 0;
  challenge.totp = '';
}

/** 登录后跳转：优先回到被拦截的来源路径。 */
async function enterConsole(): Promise<void> {
  const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/overview';
  await router.replace(redirect);
}async function submit(): Promise<void> {
  errorText.value = '';
  noticeText.value = '';
  submitting.value = true;
  try {
    let embedding: number[] | undefined;
    if (form.embeddingText.trim()) {
      try {
        embedding = parseEmbedding(form.embeddingText);
      } catch (cause) {
        errorText.value = (cause as EmbeddingError).message;
        return;
      }
    }

    const payload = {
      username: form.username.trim(),
      password: form.password,
      ip: form.ip.trim() || undefined,
      embedding,
      ...(challenge.active && challenge.totp ? { totp: challenge.totp.trim() } : {}),
    };
    const result = await auth.login(payload);

    if (result.ok && result.token) {
      // 提交成功后立即丢弃口令与人脸向量，不在内存里久留
      form.password = '';
      form.embeddingText = '';
      resetChallenge();
      await enterConsole();
      return;
    }

    switch (result.status) {
      case 'totp_required':
        challenge.active = true;
        challenge.id = String(result.challenge_id ?? '');
        challenge.requiredLoa = Number(result.required_loa ?? 0);
        noticeText.value = '请输入动态码完成第二因子';
        break;
      case 'bio_required':
        noticeText.value = '需要人脸因子：请载入人脸向量文件后重试';
        break;
      case 'enroll_required':
        errorText.value = '该账号尚未注册动态码，请联系管理员完成注册';
        break;
      case 'rate_limited':
        errorText.value = `请求过于频繁，请稍后再试（${result.reason ?? 'too_many_requests'}）`;
        break;
      default:
        errorText.value = `登录失败：${result.reason ?? result.message ?? result.status ?? '未知原因'}`;
        break;
    }
  } catch (cause) {
    errorText.value = describeError(cause);
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <div class="login">
    <div class="login__card">
      <section class="login__intro">
        <div class="login__brand">Hornwork · 纵深防御平台</div>
        <h1>Hornwork 控制台</h1>
        <p class="login__desc">
          单进程 · Python 标准库 + libyara + ClamAV<br />
          检测 / 漏洞档案 / 定期扫描 / 身份认证 / 安全加固
        </p>
        <ul>
          <li>检测：采集、检测、告警、工单与哈希链审计</li>
          <li>漏洞档案：靶场编排与 CVSS / 复现证据</li>
          <li>定期扫描：端口服务 + CVE 匹配 + 快照 diff + 覆盖率</li>
          <li>认证：口令 + 动态码 + 人脸模板与风险驱动的 LOA</li>
          <li>加固：基线编排、幂等执行、回滚与复测</li>
        </ul>
        <div class="login__foot">会话令牌仅存 sessionStorage，关闭标签页即失效</div>
      </section>

      <section class="login__form">
        <h2>登录</h2>
        <p class="login__hint">账号 + 口令；人脸为可选因子（提供向量则升 LOA3）</p>

        <el-form label-position="top" @submit.prevent="submit">
          <el-form-item label="用户名">
            <el-input v-model="form.username" autocomplete="username" placeholder="用户名" />
          </el-form-item>
          <el-form-item label="口令">
            <el-input
              v-model="form.password"
              type="password"
              show-password
              autocomplete="current-password"
              placeholder="口令"
              @keyup.enter="submit"
            />
          </el-form-item>
          <el-form-item label="动态码（可选）">
            <el-input
              v-model="challenge.totp"
              maxlength="8"
              placeholder="6 位动态码"
              :disabled="!challenge.active"
            />
          </el-form-item>
          <el-form-item label="人脸向量（可选，.json）">
            <input type="file" accept=".json,application/json" @change="loadEmbeddingFile" />
          </el-form-item>
          <el-form-item label="来源 IP（写入风险评分与审计）">
            <el-input v-model="form.ip" placeholder="127.0.0.1" />
          </el-form-item>

          <el-alert
            v-if="errorText"
            :title="errorText"
            type="error"
            :closable="false"
            show-icon
            class="login__alert"
          />
          <el-alert
            v-else-if="noticeText"
            :title="noticeText"
            type="info"
            :closable="false"
            show-icon
            class="login__alert"
          />

          <el-button
            type="primary"
            class="login__submit"
            :loading="submitting"
            :disabled="!canSubmit"
            @click="submit"
          >
            登录
          </el-button>
        </el-form>
      </section>
    </div>
  </div>
</template>

<style scoped>
.login {
  min-height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: linear-gradient(135deg, #16213c 0%, #1f3864 55%, #2a4f8a 100%);
}
.login__card {
  width: 780px;
  max-width: 100%;
  background: var(--surface);
  border-radius: 8px;
  box-shadow: 0 18px 50px rgba(0, 0, 0, 0.35);
  display: grid;
  grid-template-columns: 1fr 1fr;
  overflow: hidden;
}
.login__intro {
  background: #1f3864;
  color: #fff;
  padding: 28px 26px;
}
.login__brand {
  font-size: 12px;
  color: #9fb0cc;
}
.login__intro h1 {
  margin: 6px 0 6px;
  font-size: 20px;
  color: #fff;
  letter-spacing: 1px;
}
.login__desc {
  color: #b9c6dd;
  font-size: 12px;
  line-height: 1.7;
  margin: 0;
}
.login__intro ul {
  margin: 18px 0 0;
  padding-left: 18px;
  color: #d7e0ef;
  font-size: 12px;
  line-height: 1.9;
}
.login__foot {
  margin-top: 24px;
  font-size: 11px;
  color: #8fa0bd;
}
.login__form {
  padding: 26px 26px 22px;
}
.login__form h2 {
  margin: 0 0 4px;
  font-size: 16px;
}
.login__hint {
  margin: 0 0 14px;
  font-size: 12px;
  color: var(--text-faint);
}
.login__alert {
  margin-bottom: 12px;
}
.login__submit {
  width: 100%;
}
@media (max-width: 860px) {
  .login__card {
    grid-template-columns: 1fr;
  }
  .login__intro {
    display: none;
  }
}
</style>
