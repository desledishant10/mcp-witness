# Findings

Audit-trail record for MCP-Scan runs against real targets. Every meaningful invocation against a third-party MCP server — whether a dynamic-harness scenario, a static-analyzer scan, or a classifier evaluation — that produces a recordable observation lives here.

Two outcome classes:

- **Vulnerability** — a scenario's oracle fired (`passed: false` with non-empty `oracle_evidence`), or the analyzer surfaced a high-severity finding. Documented with reproduction steps, attribution-ready writeup, and a suggested disclosure timeline.
- **Defense** — a scenario's oracle did *not* fire (`passed: true`), or the analyzer returned no findings on a tool the auditor expected to fail. Documented because "frontier model X resisted attack class Y against server Z on date D" is itself a publishable claim and a useful baseline for future regression checks.

Both classes matter for the audit-phase deliverable.

## File naming

`YYYY-MM-DD-<scenario-or-rule>-<target>-<agent-or-mode>-<outcome>.md`

Examples:
- `2026-05-11-MCP-D-001-fetch-opus47-defense.md`
- `2026-05-12-MCP-S-001-server-foo-static-vuln.md`

## Entry template

```markdown
# <Scenario-or-Rule ID> vs <target>

**Date:** YYYY-MM-DD
**Target:** <package name + version>
**Tested by:** <scenario file or analyzer rule>
**Agent driver:** <stub | anthropic | n/a>
**Model:** <claude-opus-4-7 | etc. | n/a>
**Outcome:** **VULNERABILITY** | **DEFENSE** | **INFO**

## Result
<one-line summary>

## Reproduction
\`\`\`bash
<exact command>
\`\`\`

## Raw output
\`\`\`json
<RunResult or analyzer JSON>
\`\`\`

## Interpretation
<what this means; what we tested and what we didn't>

## Caveats
- <single-run results are not a statistical claim>
- <model versions and server versions matter>
- <anything else worth flagging>

## Disclosure
<for vuln: contact info + timeline; for defense: not applicable>
```

## Versioning the corpus of findings

Findings are append-only. If a re-test produces a different result (e.g., a model update closes a vulnerability), the new finding goes in as a separate entry referencing the prior one. The original is never edited.

This matters for the audit-phase writeup: the value isn't the latest result, it's the *time series* of "we tested X against Y on date Z; this is what we found."
