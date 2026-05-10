import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Local dev: http://localhost:8000
// Docker:    http://backend:8000  (set VITE_API_HOST env var)
const apiHost = process.env.VITE_API_HOST ?? 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: apiHost,
        changeOrigin: true,
      },
    },
  },
})
