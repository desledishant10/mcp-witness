// @ts-check
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: '**/*.spec.js',
  timeout: 60000,
  use: {
    headless: true,
    ignoreHTTPSErrors: true,
    bypassCSP: true,
    // Important: don't reuse browser context — clean DNS cache between runs
    contextOptions: {},
  },
  reporter: [['list']],
});
