import path from 'node:path';
import {defineConfig} from 'vite';
import dts from 'vite-plugin-dts';
import {viteStaticCopy} from 'vite-plugin-static-copy';

const staticCopyPlugin = viteStaticCopy({
  targets: [
    {
      src: './package.dist.json',
      dest: './',
      rename: 'package.json',
    },
  ],
});

export default defineConfig({
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/index.ts'),
      name: 'WebRecorder',
      fileName: 'index',
      formats: ['es'],
    },
    rollupOptions: {
      // rxjs is a peer dependency provided by the consuming app; do not bundle it.
      external: ['rxjs'],
      output: {
        globals: {},
      },
    },
  },
  plugins: [dts({tsconfigPath: './tsconfig.declaration.json'}), staticCopyPlugin],
});
