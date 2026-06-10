# Examples

Worked examples showing mcpsentry in real use. Each is self-contained — the input data lives in the example directory, the commands run against it, and the expected output is checked in for comparison.

| # | Example | What it shows |
|---|---|---|
| [01](01-audit-mcp-server-fetch/) | Audit `mcp-server-fetch` from a captured `tools/list` | The end-to-end of the SSRF discovery (#4143). Two analyzer findings surfacing from one captured JSON, with commentary on what each means and how they composed into the disclosed vulnerability. |
| [02](02-ssrf-class-survey/) | Surface the SSRF class across two packages | How a single static rule (MCP-S-009) found *both* disclosed SSRF servers from captured `tools/list` files alone — no source-code inspection required. The "class issue, not single package" framing in code. |
| [03](03-detector-evolution-s014/) | The W1–W4 patches for MCP-S-014 | How four real-world DNS-rebind targets each motivated one of the four S-014 detector patches. Side-by-side: v0.1 detector misses → v0.3 detector catches. |

Each example is meant to be readable in 5 minutes, runnable in 30 seconds, and re-usable as a template for auditing your own servers.

## Running these

You'll need mcpsentry installed (`pip install -e .` from the repo root, or eventually `pip install mcpsentry` once published). All input files live next to each example's README; the commands are concrete (no `<placeholder>` substitutions needed).
