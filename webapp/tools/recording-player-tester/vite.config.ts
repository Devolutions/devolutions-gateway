import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  server: {
    proxy: {
      '/upload': 'http://localhost:3000',
      '/jet': 'http://localhost:3000',
    },
  },
  plugins: [react(),tailwindcss()],
});
