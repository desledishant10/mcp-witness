# Example 04 — DNS-rebind PoC, end-to-end

A runnable reproduction of the inbound DNS-rebind attack disclosed against `mcp-streamablehttp-proxy` v0.2.0 (see [`findings/2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md`](../../findings/2026-05-12-MCP-S-014-streamablehttp-proxy-dns-rebinding.md)). The harness itself lives at [`poc/dns-rebind/`](../../poc/dns-rebind/) — this example is just the pointer + the high-level walkthrough.

## What the harness does

Two demos, both single-command:

| Demo | Effort | What it proves |
|---|---|---|
| `make demo-quick` | ~5 sec, Python only | Server accepts MCP JSON-RPC requests with arbitrary `Origin` and `Host` headers. The vulnerability shape, no Docker needed. |
| `make demo-full` | ~60 sec, Docker compose | Full attack chain: custom DNS server with TTL-flip behavior + attacker web server hosting the rebind page + vulnerable victim container + Playwright-driven headless browser. Mirrors the real-world attack a browser tab on an operator's machine would execute. |

## Run

```bash
cd poc/dns-rebind
make demo
```

`demo` runs the quick probe first (proves the vulnerability shape) and then the full Docker-orchestrated end-to-end (proves the attack actually works from a real browser).

## Architecture

```
                          ┌─────────────────────────────┐
                          │  rebind DNS server          │
                          │  evil.example: 1st lookup → │
                          │     attacker, then victim   │
                          └──────────────┬──────────────┘
                                         │ DNS (TTL: 1s)
                  ┌──────────────────────┴────────────────────┐
                  │                                            │
                  ▼                                            ▼
        ┌──────────────────┐   1. load page           ┌─────────────────┐
        │ Playwright       │ ─────────────────►       │ attacker (nginx)│
        │ (browser)        │ ◄─────────────────       │ serves rebind.js│
        │                  │   2. rebind.js runs      │  on             │
        │                  │                          │  evil.example:  │
        │                  │                          │  3000           │
        └──────────────────┘                          └─────────────────┘
                  │
                  │ 3. fetch http://evil.example:3000/mcp
                  │    (DNS now returns victim IP — same-origin to browser)
                  ▼
        ┌──────────────────────────────────────────┐
        │ victim: mcp-streamablehttp-proxy v0.2.0  │
        │   binds 0.0.0.0:3000, no Origin check    │
        │   wraps mcp-server-time over stdio       │
        └──────────────────────────────────────────┘
                  │ 4. returns initialize / get_current_time
                  ▼
              proof: browser tab from one origin
              just invoked a tool on a different
              server because there was no header
              validation in the middle.
```

## What you'll see

`make demo-quick`:

```
[+] probe 1: legitimate request (Origin: http://localhost:3000)
    → status=200, body shape: MCP initialize response
[+] probe 2: request with hostile Origin: http://evil.example
    → status=200, body shape: MCP initialize response (UNAUTHORIZED ACCEPTED)
[+] probe 3: request with hostile Host: evil.example
    → status=200, body shape: MCP initialize response (UNAUTHORIZED ACCEPTED)
─────────────────────────────────────────────────────────────────
VERDICT: VULNERABLE
```

`make demo-full` adds a containerized run that ends with a Playwright assertion:

```
  [browser/log]  [t=2.5s] attempt 1: POST http://evil.example:3000/mcp
  [browser/log]  [t=2.7s] REBIND SUCCESS — MCP initialize response received
[playwright] verdict: PoC: VULNERABLE
```

## Why this matters

The exploit doesn't require:

- Network position (the attacker is just a web page the operator visits)
- Authentication
- Prompt injection (this is the *server* failing to authenticate the *browser*, not the agent failing to authenticate the *prompt*)
- IPv6, exotic DNS records, anything fancy

It does require:

- The operator visiting an attacker-controlled web page in any browser tab while a vulnerable MCP server is running on `localhost`. That's the entire trigger.

## What the fix looks like

In `victim/start.sh`, change the launch command to wrap the proxy behind something that does Origin/Host validation. For ASGI servers (Starlette / FastAPI), one line:

```python
from starlette.middleware.trustedhost import TrustedHostMiddleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1:3000", "localhost:3000"],
)
```

If the fix is in place, the harness's `make demo-quick` would have `probe 2` and `probe 3` return non-MCP responses, and `make demo-full` would have Playwright timeout waiting for the rebind to succeed.

## Adapting to the other three DNS-rebind-class targets

Edit `poc/dns-rebind/victim/Dockerfile` + `victim/start.sh` to install + launch one of:

- [`mcp-fetch-streamablehttp-server`](../../findings/2026-05-12-MCP-S-014-fetch-streamablehttp-server-dns-rebinding.md)
- [`fastmcp-http`](../../findings/2026-05-12-MCP-S-014-fastmcp-http-dns-rebinding.md)
- [`mcp-server-fetch-sse`](../../findings/2026-06-02-MCP-S-014-mcp-server-fetch-sse-dns-rebinding.md)

The DNS-rebind primitive is independent of the wrapped server. Each swap is a one-file change.

## Cleanup

```bash
make clean              # tear down containers + remove images
docker compose down -v  # alternative
```

## Embargo

The vulnerable package (`mcp-streamablehttp-proxy` v0.2.0) is under coordinated disclosure with embargo expiring **2026-08-10**. This harness is published in the repo as defense documentation — the vulnerability it reproduces is documented in the linked finding, and the disclosure timeline is documented in [`disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md`](../../disclosures/2026-05-12-mcp-oauth-gateway-dns-rebinding.md).
