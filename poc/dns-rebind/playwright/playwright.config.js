// @ts-check
const { defineConfig } = require('@playwright/test');

// Each mode runs exactly one test file. They cannot run in the same
// process because the rebind DNS server's state is per-query-counter
// and any test's HTTP traffic burns through the rebind window — running
// both back-to-back leaves the second test with a DNS server that
// always returns the victim, breaking the page-load step of test.spec.js.
const escalation = process.env.ESCALATION_DEMO === '1';

module.exports = defineConfig({
  testDir: '.',
  testMatch: escalation ? '**/escalation.spec.js' : '**/test.spec.js',
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
