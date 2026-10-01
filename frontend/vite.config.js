import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.API_TARGET || 'http://localhost:8001',
        changeOrigin: true,
        headers: { 'X-API-Key': process.env.BACKEND_API_KEY || 'devkey' }
      }
    }
  }
})
