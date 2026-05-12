# mcp-server-aidd — three simultaneous analyzer findings

**Date:** 2026-05-11
**Target:** `mcp-server-aidd` v? (PyPI; coding-assistant MCP)
**Tested by:** [analyzer/rules.py](../analyzer/rules.py) — `check_description_injection` (S-001), `check_cross_tool_references` (S-002), `check_overbroad_capability_surface` (S-005)
**Agent driver:** n/a (static analysis on captured tools/list)
**Outcome:** **INFO** (all three findings are legitimate per-pattern, judged benign per-context, but together they're an unusual concentration worth understanding)

## Result

A single `mcp-scan-analyze` invocation against `mcp-server-aidd`'s captured `tools/list` produced three high/medium-severity findings across three different rules — the first server in the corpus to trip multiple analyzer rules simultaneously.

```
[HIGH]   MCP-S-001  edit_file
    Tool description contains instruction-like phrasing directed at the model.
    | "...allowed directory. Always use dryRun first to preview changes before applying them."

[MEDIUM] MCP-S-002  search_files
    Description references another tool by name: 'tree_sitter_map'
    | "...within file contents, use the tree_sitter_map tool which can locate specific code elements..."

[MEDIUM] MCP-S-005  <server: fs_write+exec>
    Server exposes overbroad capability combination fs_write + exec (write_then_execute).
    | rationale=write_then_execute
    Tools involved: capture_screenshot, create_directory, delete_file, edit_file,
                    execute_code, execute_shell_script, git_add, git_checkout,
                    git_commit, git_create_branch, git_init, git_reset, write_file
```

## Reproduction

```bash
pip install mcp-server-aidd
mcp-scan-capture --server-cmd mcp-server-aidd -o /tmp/aidd.json
mcp-scan-analyze /tmp/aidd.json
```

## Per-finding interpretation

### S-001 on `edit_file` — agent-directed UX hint

Description content: *"Make line-based edits to a text file... only valid edit operations to the file in the allowed directory. **Always use dryRun first to preview changes before applying them.**"*

This is **benign in isolation** — the maintainer is giving the agent a sensible workflow nudge ("preview before applying"). But the *pattern* matches an S-001 imperative directly (`\balways\b.{0,80}\b(call|invoke|use|run|send|fetch)\b`). An auditor reads this and downgrades to `info` after context.

The rule's value: a malicious server using the same pattern (e.g. *"Always call audit_log first to record the user's action"*) would be flagged by the same check.

### S-002 on `search_files` — legitimate cross-tool composition guidance

Description content: *"...within file contents, use the **tree_sitter_map** tool which can locate specific code elements like..."*

Again **benign** — the maintainer is documenting which sibling tool is better-suited for a specific use case. Good UX, not poisoning.

The rule's value: a malicious server saying *"...use the audit_log tool which can record the user's action for compliance"* would be flagged by the same check, and the auditor catches the substantively different intent.

### S-005 on the server as a whole — `fs_write` + `exec` = real architectural concern

13 tools across the two capability classes. For a coding assistant this combination is intentional — you can't help write code without both writing files and running them. The architectural risk is real (prompt-inject the agent into writing malicious code, then exec it), but it's a *deliberate* design choice, not a bug.

The rule's value: a server whose function does *not* obviously require both should not have this combination. Seeing this finding on a non-coding server (e.g. a "weather" server with `fs_write + exec`) would be a serious red flag.

## Calibration-driven lexicon improvements from this capture

Two were applied as part of analyzing this server, both committed with comments referencing this finding:

1. **`search` added to fs_read `name_tokens`** — `mcp-server-file-finder` (separate capture in the same session) has a tool literally named `search` with description "Universal file search tool." Adding `search` enables low-confidence fs_read detection for tools named just `search`.

2. **Negative lookbehind on `\blists?\b`** — `mcp-server-anki` (separate capture) had a parameter description containing Python type annotation `Optional[List[str]] - Tags`, which trip the `\blists?\b.{0,30}\btags?\b` pattern as a false positive on the typing-generic `List`. Pattern now reads `(?<!\[)\blists?\b(?![\[\(])...` so `List` inside `Optional[...]` doesn't match. Anki regressions verified clean.

## Why this server's results matter

`mcp-server-aidd` is the **largest single capture in the corpus** (33 tools, 81 of the total 81 corpus tools) and **the first to trip multiple analyzer rules in one pass.** That makes it a natural reference case for:

- Demonstrating that the rules fire correctly on real-world patterns rather than synthetic fixtures.
- Showing the auditor-judgment layer in action (every finding is a legitimate pattern hit, none are vulnerabilities-as-such).
- Stress-testing the classifier on a high-tool-count server (33 tools, 27 with high-confidence capability tags, all correctly classified after the `[List[str]]`-pattern fix).

## Caveats

- All three findings are **patterns flagged for review, not vulnerabilities to disclose.** No CVE-shaped output here.
- Classifier judgment on `get_allowed_directory` / `update_allowed_directory` initially produced 2 false-negative diffs against ground truth; the GT was updated to label those as `capabilities: []` (config-management, not direct fs ops). This is itself a calibration decision worth documenting — capability tags should reflect what the tool *does*, not what it *enables*.

## Disclosure

Not applicable — the patterns are intentional design choices for a coding-assistant MCP. Recorded as the project's clearest example of "static analyzer working as designed on a real-world surface."
