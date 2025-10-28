import path from 'node:path';
import { UserConfig, defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

// Simple deep merge function
function deepMerge<T extends object>(target: Partial<T>, source: T): T {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      target[key] = deepMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target as T;
}

const DefaultConfig: UserConfig = {
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/main.ts'),
      name: 'WebmStreamPlayer',
      fileName: () => 'webm-stream-player.js',
      formats: ['es'],
    },
    rollupOptions: {
      // Ensure external dependencies are not bundled into the library
      external: [],
      output: {
        globals: {},
      },
    },
  },
};

const OutDir = {
  debug: 'dist',
  release: 'dist',
};

const Plugins = {
  debug: [
    dts({
      insertTypesEntry: true,
    }),
  ],
  release: [
    dts({
      insertTypesEntry: true,
    }),
  ],
};

export default defineConfig(({ mode }) => {
  const isDebug = mode === 'debug';
  console.log(`Building in mode ${mode}`);

  const config: UserConfig = deepMerge({}, DefaultConfig);
  config.build = {
    ...config.build,
    outDir: isDebug ? OutDir.debug : OutDir.release,
  };
  config.plugins = isDebug ? Plugins.debug : Plugins.release;

  return config;
});
