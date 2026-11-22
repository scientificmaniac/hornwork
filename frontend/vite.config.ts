import { fileURLToPath, URL } from 'node:url';

import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

/**
 * 后端地址：dev 模式下把 /api 与 /healthz 代理到真实 Hornwork Web 服务。
 * 生产构建由 `hornwork.web.server` 从 `hornwork/web/static/app/` 托管，
 * 因此 base 保持 `/`（产物引用 `/assets/*`，与后端静态路由一一对应）。
 */
const backend = process.env.HORNWORK_WEB ?? 'http://127.0.0.1:8787';

export default defineConfig({
  base: '/',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: backend, changeOrigin: false },
      '/healthz': { target: backend, changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
    rollupOptions: {
      output: {
        // 三个大依赖各自成块：改动业务代码时浏览器仍能命中依赖缓存。
        manualChunks: {
          echarts: ['echarts/core', 'echarts/charts', 'echarts/components', 'echarts/renderers'],
          element: ['element-plus'],
          vue: ['vue', 'vue-router', 'pinia'],
        },
      },
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.spec.ts'],
  },
});
