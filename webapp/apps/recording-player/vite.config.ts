import { defineConfig } from 'vite';

export default defineConfig(({ mode }) => {
  return {
    base: './',
    build: {
      outDir: '../../dist/recording-player',
      emptyOutDir: true,
      sourcemap: mode === 'development',
    },
  };
});
