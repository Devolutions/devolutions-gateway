import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  timeout: 60_000,
  retries: 0,
  use: {
    baseURL: 'http://localhost:4200',
    headless: false,
    screenshot: 'only-on-failure',
  },
});
