<script setup lang="ts">
import { onMounted, watch } from 'vue';
import { useRoute } from 'vue-router';

import { useAppStore } from '@/stores/app';

const app = useAppStore();
const route = useRoute();

onMounted(() => app.applyTheme());

watch(
  () => route.meta.title,
  (title) => app.setPageTitle(String(title ?? '')),
  { immediate: true },
);
</script>

<template>
  <router-view />
</template>
