import { createApp } from 'vue';
import { createPinia } from 'pinia';
import ElementPlus from 'element-plus';
import zhCn from 'element-plus/es/locale/lang/zh-cn';

import App from './App.vue';
import { router } from './router';
import { useAppStore } from './stores/app';

import 'element-plus/dist/index.css';
import './styles/index.css';

const pinia = createPinia();
const app = createApp(App);

app.use(pinia);
app.use(router);
app.use(ElementPlus, { locale: zhCn });

/**
 * 全局兜底：未捕获的异常与未处理的 Promise 拒绝统一落 console。
 * 控制台里看不到的报错最难排查，宁可多一行日志也不要静默失败。
 */
app.config.errorHandler = (error, _instance, info) => {
  console.error('[hornwork] 组件异常', info, error);
};

window.addEventListener('unhandledrejection', (event) => {
  console.error('[hornwork] 未处理的 Promise 拒绝', event.reason);
});

// 主题必须在首次渲染前落到 <html data-theme>，否则会出现一帧浅色闪烁
useAppStore(pinia).applyTheme();

app.mount('#app');
