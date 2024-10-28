import path from 'node:path';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/main.ts'),
      name: 'MyComponentLibrary',
      fileName: (format) => `webm-stream-player.${format}.js`,
    },
    rollupOptions: {
      // Ensure external dependencies are not bundled into the library
      external: [],
      output: {
        globals: {},
      },
    },
  },

  plugins: [
    dts({
      insertTypesEntry: true,
    }),
  ],
});
