# DNS-rebind PoC harness

Reproduces the attack chain disclosed in [`findings/2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md`](../../findings/2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md) end-to-end. Single command spins up everything, runs the attack, reports SUCCESS/FAIL.

## What it demonstrates

When an HTTP-transport MCP server binds to localhost without `Origin` / `Host` header validation, a browser tab the operator visits can issue same-origin requests against the server via DNS rebinding — invoking whatever tool the server exposes from a completely unrelated web origin.

This is the inbound counterpart to outbound SSRF: the server is the attack surface, the browser is the attack vector, and the operator visiting a webpage is the entire trigger.

## Run

```bash
# From this directory:
make demo
```

That runs:

1. **`make demo-quick`** (no Docker) — direct HTTP probe demonstrating the vulnerability shape (server accepts request with mismatched Origin / Host headers). Useful first because it works without containers, in <5 seconds.
2. **`make demo-full`** (Docker compose) — the realistic attack: containerized victim running `mcp-streamablehttp-proxy` v0.2.0 wrapping `mcp-server-time`, attacker web server, custom rebind DNS server, and a Playwright-driven browser that loads the attacker page and pivots to the victim's MCP endpoint via DNS rebind.

If you only want the quick proof:

```bash
make demo-quick     # ~5 sec, no Docker
```

If you want the full reproduction:

```bash
make demo-full      # ~60 sec including container startup
```

## Architecture

```
                          ┌──────────────────────────┐
                          │  rebind DNS server (dns) │
                          │  resolves evil.example:  │
                          │    first lookup → attacker
                          │    next lookups → victim │
                          └──────────────┬───────────┘
                                         │ DNS
                  ┌──────────────────────┴────────────────────┐
                  │                                            │
                  ▼                                            ▼
        ┌──────────────────┐   step 1: page load     ┌─────────────────┐
        │ Playwright       │ ────────────────────►   │ attacker (nginx)│
        │ (browser, in     │                          │  serves HTML +  │
        │  container)      │ ◄────────────────────    │  rebind.js on   │
        │                  │   step 2: rebind.js     │  evil.example:  │
        │                  │            executes      │  3000           │
        └──────────────────┘                          └─────────────────┘
                  │
                  │ step 3: fetch('http://evil.example:3000/mcp', {…})
                  │           DNS now returns victim IP
                  ▼
        ┌──────────────────────────────────────────┐
        │ victim (mcp-streamablehttp-proxy v0.2.0) │
        │   binds 0.0.0.0:3000 (no auth, no Origin │
        │   check), wraps `mcp-server-time` over   │
        │   stdio. /mcp endpoint accepts the       │
        │   POST regardless of Origin / Host.      │
        └──────────────────────────────────────────┘
                  │ step 4: returns get_current_time result
                  │           to the browser as same-origin response
                  ▼
        Playwright asserts the response shape matches MCP — full
        proof that the attacker page from an unrelated origin
        invoked a tool on a localhost-bound MCP server.
```

## File layout

| Path | Purpose |
|---|---|
| `Makefile` | `make demo`, `make demo-quick`, `make demo-full`, `make clean` |
| `docker-compose.yml` | Orchestrates dns + attacker + victim + playwright |
| `quick_probe.py` | Standalone Python script for `make demo-quick` (no Docker) |
| `dns/Dockerfile`, `dns/rebind_server.py` | Custom DNS server with first-lookup-then-flip behavior |
| `attacker/Dockerfile`, `attacker/html/`, `attacker/nginx.conf` | Nginx + the malicious page + rebind.js |
| `victim/Dockerfile`, `victim/start.sh` | Pinned vulnerable `mcp-streamablehttp-proxy` + `mcp-server-time` (benign demo) |
| `victim/Dockerfile.escalation`, `victim/start.escalation.sh` | Variant wrapping `mcp-server-shell` for the `demo-rce` escalation profile |
| `compose.escalation.yml` | Compose override that swaps the victim to the escalation variant + sets `ESCALATION_DEMO=1` |
| `playwright/Dockerfile`, `playwright/test.spec.js` | Headless Chromium executing the base attack |
| `playwright/escalation.spec.js` | Additional test that drives `tools/call execute_command` post-rebind; auto-skipped unless `ESCALATION_DEMO=1` |

## What to look for in the output

`make demo-quick`:

```
[+] starting victim container (mcp-streamablehttp-proxy v0.2.0)
[+] waiting for victim to bind localhost:3000
[+] probe 1: legitimate request from same origin       → 200 OK (initialize handshake)
[+] probe 2: request with Origin: http://evil.example  → 200 OK   ← VULNERABILITY
[+] probe 3: request with Host: evil.example           → 200 OK   ← VULNERABILITY
[+] cleanup
RESULT: VULNERABLE (server accepted requests from attacker-controlled headers)
```

`make demo-full` adds the browser-pivot leg:

```
[+] all 4 containers up
[+] playwright: navigate to http://evil.example:3000/        (DNS resolves to attacker)
[+] playwright: page loaded, rebind.js executing
[+] rebind.js: TTL flip in progress (1s wait)
[+] playwright: fetch http://evil.example:3000/mcp           (DNS now resolves to victim)
[+] playwright: response shape matches MCP initialize        ← REBIND SUCCESS
[+] playwright: tool_call get_current_time returned …
RESULT: VULNERABLE (browser-pivot via DNS rebind succeeded)
```

## Escalation demo (`make demo-rce`) — educational use only

The base `demo-full` proves that the attacker-origin request is *accepted* — the JSON-RPC `initialize` handshake completes. That's the vulnerability in its primitive form. The escalation demo adds the second half: **the attacker, post-rebind, drives an actual tool call and reads back its output.** This is the "universal escalation" property documented in the [disclosure](../../disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md) — the proxy's vulnerability inherits the toolset of whatever stdio MCP sits behind it.

The escalation variant:

- Swaps the wrapped stdio MCP from `mcp-server-time` (one read-only tool: `get_current_time`) to `mcp-server-shell` (one RCE-shaped tool: `execute_command(command: str)`).
- Sets `ESCALATION_DEMO=1` so `playwright/escalation.spec.js` enables itself (the file `test.skip(...)`s otherwise — the base demo never runs the RCE leg, even if you accidentally invoke Playwright directly).
- Drives `execute_command` with `echo "RCE-PROOF: $(whoami)@$(hostname)"` and asserts the marker appears in the MCP response. Distinctive enough to be unambiguous; harmless enough that no system state is altered.

```bash
make demo-rce
```

### Why this is safe to run locally

- The shell runs **inside the throwaway victim container**, not on your host. The victim image has no volume mounts; the only network it can reach is the lab compose network (dns + attacker + playwright). It cannot read your filesystem, see your processes, or reach any other service.
- `make clean` removes the container and the built images. No state persists.
- The payload is `echo`. No destructive command runs even within the container.
- The `compose.escalation.yml` override is the only way to trigger the RCE leg. The base `docker-compose.yml`, `make demo`, `make demo-quick`, and `make demo-full` cannot reach this state.

### What this is NOT

- It is **not** a tool for attacking real `mcp-streamablehttp-proxy` deployments. Do not adapt the attacker page or the Playwright test to point at any proxy you don't own. Coordinated-disclosure embargo still applies through 2026-08-10.
- It is **not** wired into CI. The [`dns-rebind-poc` GitHub Actions workflow](../../.github/workflows/dns-rebind-poc.yml) is manual-dispatch only and runs `demo-quick` / `demo-full` — never `demo-rce`. Escalation runs are operator-initiated on a local machine, witnessed visibly, never automated.
- It is **not** the public exploit. The blog post that lifts the embargo will reference this harness from the public-facing [`examples/04-dns-rebind-poc/`](../../examples/04-dns-rebind-poc/) pointer; the escalation profile stays internal to the audit record.

## Embargo + responsibility

The vulnerable package (`mcp-streamablehttp-proxy` v0.2.0) is under coordinated disclosure with the embargo expiring 2026-08-10. This harness is in the repo as defense documentation — anyone running it can verify the vulnerability they're protecting against. It does NOT contain a zero-day; the underlying vulnerability is documented in the linked finding and disclosure record.

After the 2026-08-10 embargo lift, this harness becomes part of the public reproduction record alongside the blog post.

## Cleanup

```bash
make clean              # tears down all containers + removes images
docker compose down -v  # alternative; doesn't remove images
```

## Adapting to other targets

To run the harness against a different vulnerable target (e.g. `mcp-fetch-streamablehttp-server`, `fastmcp-http`):

1. Edit `victim/Dockerfile` to pin + launch the alternative package
2. Edit `victim/start.sh` if the launch command differs
3. Re-run `make demo-full`

Each of the 4 disclosed DNS-rebind targets can be reproduced with a one-line `victim/` swap.

## CI

`.github/workflows/dns-rebind-poc.yml` runs the harness on manual dispatch (Actions tab → `dns-rebind-poc` → Run workflow). Choose `demo-quick` (fast) or `demo-full` (full Docker stack). `demo-rce` is deliberately excluded — see §"Escalation demo" above. The workflow becomes a regression check: the day `mcp-streamablehttp-proxy` ships an Origin validation fix, `demo-full` starts failing — which is the signal you want.
