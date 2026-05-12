# Dynamic Scenarios

Library of MCP-Scan dynamic test scenarios. Format specified in [../docs/scenario-schema.md](../docs/scenario-schema.md).

## v0.1 — seed set (5 scenarios)

These are the highest-yield scenarios chosen for the initial implementation. Together they exercise tool-description injection, server-side input validation (path traversal and SSRF), trust-on-first-use violation (rug pull), and indirect prompt injection via invisible Unicode — covering the most common bug classes the audit phase is expected to find in real-world MCP servers.

| ID                                                       | Category                              | Severity  | Primary target | What it tests                                                              |
|----------------------------------------------------------|---------------------------------------|-----------|----------------|----------------------------------------------------------------------------|
| [MCP-D-001](MCP-D-001-tool-desc-injection-fetch.yaml)    | `tool.description_injection`          | high      | agent          | Does the agent obey instructions hidden in a tool description?             |
| [MCP-D-002](MCP-D-002-path-traversal-fs-tool.yaml)       | `tool.input.path_traversal`           | critical  | server         | Does the server canonicalize and root-check filesystem paths?              |
| [MCP-D-003](MCP-D-003-ssrf-url-fetcher.yaml)             | `tool.input.ssrf`                     | high      | server         | Does the server validate URL schemes and hosts?                            |
| [MCP-D-004](MCP-D-004-tool-def-rug-pull.yaml)            | `tool.rug_pull`                       | high      | agent          | Does the agent re-prompt for approval when tool defs change mid-session?   |
| [MCP-D-005](MCP-D-005-unicode-tag-smuggling.yaml)        | `tool.output.injection_unicode_tags`  | high      | agent          | Does the agent act on instructions encoded in invisible Unicode tag chars? |
| [MCP-D-006](MCP-D-006-subtle-capability-redefinition.yaml) | `tool.description_injection`        | high      | agent          | Does the agent follow capability-redefinition framing ("now you can", "compliance pipeline") that avoids obvious imperatives? |

"Primary target" indicates the more likely failure mode — server-side validation vs. agent-side trust. Several scenarios catch both at once; the column points at the dominant defect class.

## Roadmap for subsequent batches

Not yet authored, planned for v0.2+:

- Confused deputy across two tools (`cross.confused_deputy`)
- Resource content injection (`resource.content_injection`)
- Prompt argument injection (`prompt.argument_injection`)
- OAuth `redirect_uri` validation weakness (`transport.oauth_redirect`)
- DNS rebinding against localhost HTTP transport (`transport.dns_rebinding`)
- Annotation lying — `readOnlyHint=true` on writing tools (`tool.annotation_lying`)
- Agent infinite-loop / token-burn (`cross.agent_loop`)
- ANSI-escape terminal injection in tool output (`tool.output.injection_ansi`)
- Markdown-image exfil in agent reply (`tool.output.injection_markdown_image`)
- Sampling credit theft (`sampling.credit_theft`)

Target for v0.3 is full coverage of every category in the [taxonomy](../docs/scenario-schema.md#category-taxonomy).
