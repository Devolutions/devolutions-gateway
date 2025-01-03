import { defineConfig } from 'vite';

export default defineConfig(({ mode }) => {
  return {
    base: '',
    build: {
      outDir: '../player',
      emptyOutDir: true,
      sourcemap: mode === 'development',
    },
  };
});
