<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { NAV } from '@/router/nav';
import { useAppStore } from '@/stores/app';
import { useAuthStore } from '@/stores/auth';

const app = useAppStore();
const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

/** 当前激活的一级域（子路由归到父级高亮）。 */
const activeDomain = computed(() => `/${route.path.split('/')[1] ?? ''}`);

function navigate(path: string): void {
  if (route.path !== path) void router.push(path);
}
</script>

<template>
  <aside class="sidebar" :class="{ 'is-collapsed': app.sidebarCollapsed }">
    <div class="sidebar__brand">
      <div class="sidebar__name">Hornwork</div>
      <div v-show="!app.sidebarCollapsed" class="sidebar__sub">纵深防御控制台</div>
    </div>

    <nav class="sidebar__nav" aria-label="主导航">
      <template v-for="item in NAV" :key="item.path">
        <template v-if="!item.children">
          <button
            type="button"
            class="sidebar__item"
            :class="{ 'is-active': activeDomain === item.path }"
            :title="item.title"
            @click="navigate(item.path)"
          >
            <span class="sidebar__item-text">{{ app.sidebarCollapsed ? item.title.slice(0, 1) : item.title }}</span>
          </button>
        </template>
        <template v-else>
          <div v-show="!app.sidebarCollapsed" class="sidebar__group">{{ item.title }}</div>
          <button
            v-for="child in item.children"
            :key="child.path"
            type="button"
            class="sidebar__item sidebar__item--child"
            :class="{ 'is-active': route.path === child.path }"
            :title="`${item.title} / ${child.title}`"
            @click="navigate(child.path)"
          >
            <span class="sidebar__item-text">{{ child.title }}</span>
          </button>
        </template>
      </template>
    </nav>

    <div class="sidebar__foot">
      <div v-show="!app.sidebarCollapsed" class="sidebar__user">
        <span class="sidebar__user-name">{{ auth.username || '未登录' }}</span>
        <span class="sidebar__user-loa">{{ auth.displayLoa }}</span>
      </div>
      <button type="button" class="sidebar__collapse" @click="app.toggleSidebar()">
        {{ app.sidebarCollapsed ? '»' : '« 收起' }}
      </button>
    </div>
  </aside>
</template>

<style scoped>
.sidebar {
  width: 210px;
  flex: 0 0 210px;
  background: var(--frame-bg);
  color: var(--frame-text);
  display: flex;
  flex-direction: column;
  transition: width 0.15s ease, flex-basis 0.15s ease;
}
.sidebar.is-collapsed {
  width: 64px;
  flex-basis: 64px;
}
.sidebar__brand {
  padding: 15px 16px 11px;
  border-bottom: 1px solid var(--frame-border);
  overflow: hidden;
}
.sidebar__name {
  font-size: 15px;
  font-weight: 600;
  color: #fff;
  letter-spacing: 0.5px;
  white-space: nowrap;
}
.sidebar__sub {
  font-size: 11px;
  color: var(--frame-text-dim);
  margin-top: 3px;
  white-space: nowrap;
}
.sidebar__nav {
  flex: 1;
  overflow-y: auto;
  padding: 10px 8px;
}
.sidebar__group {
  font-size: 11px;
  color: var(--frame-text-dim);
  padding: 10px 10px 4px;
}
.sidebar__item {
  display: block;
  width: 100%;
  text-align: left;
  border: 0;
  background: transparent;
  color: var(--frame-text);
  padding: 7px 11px;
  border-radius: 5px;
  font-size: 13px;
  font-family: inherit;
  cursor: pointer;
  margin-bottom: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.sidebar__item:hover {
  background: var(--frame-bg-soft);
  color: #fff;
}
.sidebar__item.is-active {
  background: var(--frame-active);
  color: #fff;
}
.sidebar__item--child {
  padding-left: 20px;
  font-size: 12.5px;
}
.is-collapsed .sidebar__item--child {
  padding-left: 11px;
}
.sidebar__foot {
  border-top: 1px solid var(--frame-border);
  padding: 9px 12px 11px;
}
.sidebar__user {
  display: flex;
  flex-direction: column;
  gap: 2px;
  margin-bottom: 6px;
  overflow: hidden;
}
.sidebar__user-name {
  font-size: 12px;
  color: #fff;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.sidebar__user-loa {
  font-size: 11px;
  color: var(--frame-text-dim);
}
.sidebar__collapse {
  border: 1px solid var(--frame-border);
  background: transparent;
  color: var(--frame-text-dim);
  border-radius: 4px;
  padding: 3px 8px;
  font-size: 11px;
  cursor: pointer;
  width: 100%;
}
.sidebar__collapse:hover {
  color: #fff;
  background: var(--frame-bg-soft);
}
@media (prefers-reduced-motion: reduce) {
  .sidebar {
    transition: none;
  }
}
</style>
