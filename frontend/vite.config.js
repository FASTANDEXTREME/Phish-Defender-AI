import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import process from 'process'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const API_TARGET = env.VITE_API_URL || 'http://127.0.0.1:8080'

  return {
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
  }
})
