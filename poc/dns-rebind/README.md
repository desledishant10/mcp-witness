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
| `victim/Dockerfile`, `victim/start.sh` | Pinned vulnerable `mcp-streamablehttp-proxy` + `mcp-server-time` |
| `playwright/Dockerfile`, `playwright/test.spec.js` | Headless Chromium executing the attack |

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
