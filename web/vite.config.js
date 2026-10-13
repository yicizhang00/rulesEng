import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 8080,
    // 端口被占用时直接报错，避免静默回落到 8081 与后端 BIND_ADDR 冲突
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8081',
      '/parse': 'http://127.0.0.1:8081',
      '/verify': 'http://127.0.0.1:8081',
    },
  },
  test: {
    environment: 'jsdom',
  },
})
