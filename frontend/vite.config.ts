/// <reference types="vitest" />
import { defineConfig, type ProxyOptions } from 'vite'
import react from '@vitejs/plugin-react'

// The browser only ever talks to one origin: the backend exposes everything
// under /api, so dev proxies it (nginx does the same in production).
const proxy: Record<string, string | ProxyOptions> = {
  '/api': {
    target: process.env.VITE_PROXY_TARGET || 'http://localhost:8000',
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./tests/setup.ts'],
    include: ['tests/**/*.test.{ts,tsx}'],
  },
})
