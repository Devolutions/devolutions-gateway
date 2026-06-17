import {defineConfig} from 'vite';

// The tester talks directly to the dev token server (:8080) and the Gateway (:7171),
// exactly like the recording-player-tester. Both must allow CORS for the dev origin.
export default defineConfig({
  server: {
    port: 5273,
  },
});
