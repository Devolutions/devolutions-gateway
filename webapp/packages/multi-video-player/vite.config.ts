import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';
import { viteStaticCopy } from 'vite-plugin-static-copy';

export default defineConfig(({ mode }) => {
  const plugins = [
    dts({
      rollupTypes: true,
    }),
    // Copy video.js fonts to output directory and package.json for publishing
    viteStaticCopy({
      targets: [
        {
          src: './node_modules/video.js/dist/font/**/*',
          dest: './fonts',
        },
        {
          src: './package.dist.json',
          dest: './',
          rename: 'package.json',
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
        fileName: 'index',
        formats: ['es' as const],
      },
      rollupOptions: {
        external: ['video.js', '@devolutions/shadow-player'],
      },
    },
    plugins,
  };
});
