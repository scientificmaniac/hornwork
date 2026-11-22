/** 全局 UI 状态：侧栏折叠、主题、页面标题，与后端无关。 */

import { computed, ref } from 'vue';
import { defineStore } from 'pinia';

export type ThemeName = 'light' | 'dark';

const THEME_KEY = 'hornwork.theme';
const SIDEBAR_KEY = 'hornwork.sidebarCollapsed';

function readStored(key: string): string {
  try {
    return localStorage.getItem(key) ?? '';
  } catch {
    return '';
  }
}

function writeStored(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* 隐私模式：主题偏好只在本次会话生效 */
  }
}

export const useAppStore = defineStore('app', () => {
  const theme = ref<ThemeName>(readStored(THEME_KEY) === 'dark' ? 'dark' : 'light');
  const sidebarCollapsed = ref(readStored(SIDEBAR_KEY) === '1');
  const pageTitle = ref('总览');

  const isDark = computed(() => theme.value === 'dark');

  function applyTheme(): void {
    document.documentElement.dataset.theme = theme.value;
    writeStored(THEME_KEY, theme.value);
  }

  function setTheme(next: ThemeName): void {
    theme.value = next;
    applyTheme();
  }

  function toggleTheme(): void {
    setTheme(isDark.value ? 'light' : 'dark');
  }

  function toggleSidebar(): void {
    sidebarCollapsed.value = !sidebarCollapsed.value;
    writeStored(SIDEBAR_KEY, sidebarCollapsed.value ? '1' : '0');
  }

  function setPageTitle(title: string): void {
    pageTitle.value = title;
    document.title = title ? `${title} · Hornwork` : 'Hornwork 控制台';
  }

  return {
    theme,
    isDark,
    sidebarCollapsed,
    pageTitle,
    applyTheme,
    setTheme,
    toggleTheme,
    toggleSidebar,
    setPageTitle,
  };
});
