import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    proxy: {
      '/upload': 'http://localhost:3000',
      '/jet': 'http://localhost:3000',
      '/player': 'http://localhost:3000'
    },
    fs: {
      allow: ['../player']
    }
  }
})
