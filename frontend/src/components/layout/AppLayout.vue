<script setup lang="ts">
import { onMounted } from 'vue';

import AppHeader from '@/components/layout/AppHeader.vue';
import AppSidebar from '@/components/layout/AppSidebar.vue';
import { useAppStore } from '@/stores/app';

const app = useAppStore();

onMounted(() => {
  // 主题在挂载时落到 <html data-theme>，避免首屏闪烁（index.html 里没有内联脚本）
  app.applyTheme();
});
</script>

<template>
  <div class="layout">
    <AppSidebar />
    <div class="layout__main">
      <AppHeader />
      <main class="layout__content">
        <router-view v-slot="{ Component }">
          <component :is="Component" />
        </router-view>
      </main>
    </div>
  </div>
</template>

<style scoped>
.layout {
  display: flex;
  height: 100%;
  overflow: hidden;
}
.layout__main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}
.layout__content {
  flex: 1;
  overflow: auto;
  padding: 16px 20px 28px;
}
</style>
