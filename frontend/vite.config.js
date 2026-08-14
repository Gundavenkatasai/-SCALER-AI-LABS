import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    // Proxy /api requests to the local FastAPI server during development.
    // On Vercel this isn't needed — Vercel routes /api/* to Python serverless.
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      }
    }
  }
})
