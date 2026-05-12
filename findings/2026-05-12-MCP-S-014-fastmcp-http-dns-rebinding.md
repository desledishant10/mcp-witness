# MCP-S-014 vs fastmcp-http — DNS-rebinding via Flask dev server bound to 0.0.0.0

**Date:** 2026-05-12
**Target:** `fastmcp-http` v0.1.4 (PyPI; [ARadRareness/mcp-registry](https://github.com/ARadRareness/mcp-registry))
**Tested by:** MCP-S-014 (static; W2 keyword-suppression — file contains no "origin" reference, but the detector missed it because the bind shape uses `self.flask_app.run(host=host)` with `host` as a function parameter, not `ast.Constant`; pure W1 false-negative) + manual source review
**Agent driver:** n/a (transport-layer finding)
**Outcome:** **VULNERABILITY (source-confirmed)** — Flask dev server bound to `0.0.0.0` with no middleware, no auth, and zero Origin/Host validation anywhere in the package. Disclosure pending (GitHub-only contact). Embargo target: 2026-08-10.

## Result

`fastmcp-http` exposes MCP tools over HTTP using Flask's built-in development server. In its default configuration:

1. Binds to `0.0.0.0` (every network interface).
2. Uses `flask.Flask.run(host=host, port=port)` — i.e. the Werkzeug development server, not a production WSGI server. Flask's own docs warn against using `app.run()` for anything but local development.
3. Has **no** Origin/Host validation, **no** auth, **no** CORS middleware, **no** before-request hook anywhere in the package. A repo-wide grep for `origin|allowed_hosts|trustedhost|host\s*header|cors|before_request` returns zero matches.

Result: the package's documented use case (run locally, register tools, let agents call them) is exploitable from any network the host is reachable on, and from any browser tab via DNS rebinding.

## Source-level evidence

`fastmcp_http/server.py` lines 115–128:

```python
def run(
    self,
    host: str = "0.0.0.0",
    register_server: bool = True,
    port: int = 5000,
) -> None:
    """Run the FastMCP HTTP server.

    Args:
        host: Host to bind to (default: "0.0.0.0")
        port: Port to listen on (default: 5000)
        register_server: Whether to register the server with the registry (default: True)
    """
    if register_server:
        port = self.register_server()
    self.flask_app.run(host=host, port=port)
```

Three signals stacked:

- `host: str = "0.0.0.0"` — default is all-interfaces. The docstring explicitly documents this default.
- `self.flask_app.run(host=host, port=port)` — Werkzeug dev server. Not intended for any deployment scenario beyond local development.
- No middleware registration anywhere in the file. `Flask(__name__)` is constructed plainly, no `@app.before_request` hooks, no `app.after_request` post-processing, no auth decorator on any route.

The `register_server: bool = True` path implies a registry-of-MCP-servers pattern — multiple `fastmcp-http` instances coordinate via a central registry. Per repo organization (`ARadRareness/mcp-registry`), this is the intended architecture. Every node in that architecture is independently exploitable.

## Reproduction (source-level)

```bash
pip install fastmcp-http==0.1.4
python -c "
from fastmcp_http import FastMCPHTTP  # or whatever the package exposes
srv = FastMCPHTTP('demo')
@srv.tool()
def echo(text: str) -> str: return text
srv.run(register_server=False)
"
# binds 0.0.0.0:5000

# Any host on the network (or DNS-rebind via any browser tab):
curl -X POST http://<victim-ip>:5000/<mcp-endpoint> \
    -H "Content-Type: application/json" \
    -d '{"method":"echo","params":{"text":"poc"}}'
```

Expected: 200 OK with the echo response, no Origin header rejected, no auth required.

The exact endpoint path depends on the package's route layout (need to verify against installed source). The vulnerability is invariant of the route — there's no authentication or Origin check on any route.

## Impact

**Severity: High in production-shaped deployments, Medium in pure-local-dev.**

- The package is named `fastmcp-http` (suggesting general HTTP transport) and its `register_server` mode implies a multi-node deployment. Anyone running it on a workstation that's network-reachable from other devices on the same LAN/VPC is exposing their MCP tools to those devices.
- Whatever tools are registered via the `@srv.tool()` decorator are reachable. Generic exposure to the toolset; no fine-grained vulnerability statement is possible without knowing the deployed toolset, but every registered tool is a callable endpoint.
- DNS-rebind path is the same as the other two findings — every browser tab the operator opens becomes a potential attacker.

Lower-blast-radius than the `atrawog/mcp-oauth-gateway` findings because `fastmcp-http` doesn't have the same "wraps an arbitrary stdio MCP" universal-escalation property, but mechanically the same root cause.

## Interpretation

**This is the simplest of the three findings to fix** — the package is small, the architecture isn't built around an external CORS-handling layer (unlike the `atrawog` packages), and a single `app.before_request` hook would close the gap. The Flask dev server choice is a separate issue and would normally call for "use a real WSGI server" guidance, but for the threat model in scope here (Origin validation), an in-process check is sufficient.

The package is also smaller-footprint than the `atrawog` packages — disclosure tone can be more direct, and the fix is a 5-line patch.

## Mitigations

1. **Default `host` to `127.0.0.1`**.
2. **Add a `@self.flask_app.before_request`** hook that inspects `request.headers.get("Host")` and `request.headers.get("Origin")` and rejects requests whose Host header isn't in `{127.0.0.1:<port>, localhost:<port>}` or whose Origin (if present) isn't in an allowlist.
3. **Replace `self.flask_app.run(...)` with a recommendation to use a production WSGI server** (`gunicorn` or `waitress`) when deploying anywhere other than purely local dev. Flask's own warning text could be lifted verbatim.

## Caveats

- **GitHub-only contact channel.** The PyPI metadata lists only a GitHub-noreply email (`38016746+ARadRareness@users.noreply.github.com`), which is not deliverable. Disclosure has to go through a GitHub Security Advisory (if the maintainer has enabled the Security tab) or a public issue (which prematurely discloses).
- **Smaller user base than the `atrawog` packages.** PyPI publish history is recent and the project's GitHub footprint is modest. Disclosure is still the right call, but expectations on response time should be calibrated — a polite Day +14 ping is appropriate, but Day +60 escalation channels are narrower (no security@ contact, no monorepo organization to escalate within).

## Suggested follow-up

1. **Check whether `ARadRareness/mcp-registry` has the GitHub Security tab enabled.** If yes, file an advisory; if no, fall back to a public issue (the disclosure timeline justifies it after good-faith private contact attempts).
2. **DNS-rebind PoC harness** — same harness covers all three findings.
3. **Patch S-014 W1** in MCP-Scan v0.3 — the `self.flask_app.run(host=host, port=port)` pattern with a parameter-default of `"0.0.0.0"` is exactly the W1 case. Resolution: when `host=` is non-constant, follow the surrounding function's default-arg value (`ast.FunctionDef.args.defaults`). After W1 patches, this finding would fire automatically.

## Disclosure

Separate from the `atrawog/mcp-oauth-gateway` advisory — different maintainer, different repo. Disclosure draft pending until GitHub Security tab availability is verified.

Embargo target: 2026-08-10, aligning with the other two findings so the public writeup can frame the whole DNS-rebind class together.
