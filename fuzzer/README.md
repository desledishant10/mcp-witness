# fuzzer

An automated dynamic fuzzer for MCP servers. It captures a server's
`tools/list`, generates capability-aware adversarial arguments for each tool,
sends them to a locally-run server, and classifies each response with an oracle
that flags crashes, hangs, information leaks, and real vulnerability signals.

This is the "find new bugs" half of the toolkit. Where the [analyzer](../analyzer/)
reads a tool definition statically and the [harness](../harness/) runs curated
scenarios, the fuzzer generates payloads at scale and lets the server tell you
where it breaks.

## Capability-aware payloads

The fuzzer does not spray random bytes. It runs each tool through the
[classifier](../classifier/) to label every parameter with a role, then aims
the payload family that actually exercises that role's bug class:

| Parameter role | Payloads | Looks for |
|---|---|---|
| `url`, `host` | IMDS / loopback / `file://` / `gopher://` | SSRF, cloud-credential read |
| `path` | `../` traversal, absolute paths, null byte, URL-encoded | path traversal, arbitrary read |
| `command` | `; id`, `$(id)`, backticks, pipes, newlines | command injection |
| `query` | SQL/`--`/`UNION` | injection, raw DB errors |
| `content` | format strings, huge input, control bytes | crashes, format-string bugs |

On top of the role payloads, every parameter gets **type-confusion** (wrong
JSON type, null, nested object) and **boundary** mutations (empty, 100k chars,
unicode tricks), and each tool gets **protocol** malformations (no arguments,
an extra unknown argument).

## The oracle

Each response is classified: `crash`, `hang`, `sensitive-read` (e.g.
`/etc/passwd` content came back), `ssrf-hit` (cloud-metadata content),
`command-injection` (shell output reflected), `error-leak` (a stack trace in
the response), `sql-error` (raw database error), `rejected` (clean validation,
**not** a finding), or `ok`. Findings are deduplicated by (tool, category,
outcome).

## Use it

```bash
# Fuzz a locally-run server (installs/launches it yourself first if needed).
mcp-witness-fuzz -- python -m some_mcp_server

# See what would be sent without sending anything.
mcp-witness-fuzz --dry-run -- python -m some_mcp_server

# JSON output, tighter budget.
mcp-witness-fuzz --json --max-per-tool 32 -- python server.py
```

Exit code is 1 when there are findings, 0 otherwise. `make demo` runs the
engine against an in-process vulnerable server with no network needed.

## How it is built

```
payloads.py    capability-aware payload generation (uses the classifier)
oracle.py      response -> outcome + severity (pure)
engine.py      run_campaign: drive payloads through an injectable call_fn
transport.py   live stdio MCP transport (async client bridged to the engine)
report.py      text / JSON reporting
cli.py         mcp-witness-fuzz
```

The payloads, oracle, and engine are pure and fully unit-tested against an
in-process vulnerable server that exhibits each bug class, proving the fuzzer
actually finds traversal, SSRF, command injection, a crash, and an
information leak while leaving a well-behaved tool alone.

## Scope and honesty

Fuzz MCP servers **you run yourself** and disclose responsibly. A finding is a
candidate signal, not a confirmed vulnerability: the oracle can be fooled (a
tool that legitimately echoes its input could reflect a payload marker), so
every finding needs manual confirmation before it goes into a report or a CVE
request. Absence of findings is not proof of safety.
