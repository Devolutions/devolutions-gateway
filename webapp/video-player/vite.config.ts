import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import { viteStaticCopy } from 'vite-plugin-static-copy';

export default defineConfig(({ mode }) => {
  const plugins = [
    dts({
      rollupTypes: true,
    }),
    // Copy video.js fonts to output directory
    viteStaticCopy({
      targets: [
        {
          src: './node_modules/video.js/dist/font/**/*',
          dest: './fonts',
        },
      ],
    }),
  ];

  // Used for testing, it will avoid loading node_modules
  // and completely use the built files using index.html as entry
  if (mode === 'test') {
    return {
      build: {
        outDir: './example/video-player',
        sourcemap: true,
      },
      plugins,
    };
  }

  // Regular build configuration
  return {
    build: {
      lib: {
        entry: 'src/index.ts',
        name: 'MultiVideoPlayer',
        fileName: 'multi-video-player',
        formats: ['es' as const],
      },
    },
    plugins,
  };
});
