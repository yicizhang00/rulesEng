import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 8080,
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
