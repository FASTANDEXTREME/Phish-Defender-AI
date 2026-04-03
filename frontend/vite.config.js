import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Backend URL — configurable via VITE_API_URL env var, defaults to local dev server
const API_TARGET = process.env.VITE_API_URL || 'http://127.0.0.1:8080'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/server_info': {
        target: API_TARGET,
        changeOrigin: true,
      },
      '/analyze': {
        target: API_TARGET,
        changeOrigin: true,
      }
    }
  }
})
