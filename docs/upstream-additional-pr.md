# Prepared upstream PR: add mcp-witness to `modelcontextprotocol/servers` ADDITIONAL.md

**Target:** [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers), file `ADDITIONAL.md`, section `## 📚 Resources`.

**Why this section:** the Resources section already lists security tooling, including [MCPWatch](https://github.com/kapilduraphe/mcp-watch) ("A comprehensive security scanner for Model Context Protocol (MCP) servers..."), ToolHive, and the Webrix secure gateway. A security testing toolkit is squarely in scope and has direct precedent, so this is a low-friction, high-fit addition rather than a speculative one. (The README's third-party *server* list was retired in favor of the MCP Server Registry; ADDITIONAL.md remains the curated home for frameworks and resources.)

## The change

Add one line to the `## 📚 Resources` section of `ADDITIONAL.md`, placed alphabetically among the other `mcp-`/`MCP` entries (near MCPWatch), matching the section's `- **[Name](url)** - Description.` format:

```markdown
- **[mcp-witness](https://github.com/desledishant10/mcp-witness)** - A security testing toolkit for MCP servers: a static analyzer, a dynamic attack harness, and a capability classifier that flag SSRF, DNS-rebinding, and tool-definition weaknesses, with runnable reproduction harnesses for each finding class.
```

## Suggested PR title

```
docs: add mcp-witness security testing toolkit to ADDITIONAL.md Resources
```

## Suggested PR body

```
Adds mcp-witness to the Resources section of ADDITIONAL.md, alongside the
existing security tooling (MCPWatch, ToolHive, Webrix).

mcp-witness (https://github.com/desledishant10/mcp-witness, Apache-2.0) is an
open-source security testing toolkit for MCP servers: a static analyzer over a
captured tools/list, a dynamic attack harness, and a capability classifier. It
flags SSRF in URL-fetching tools, DNS-rebinding on HTTP-transport servers, and
tool-definition weaknesses, and ships containerized reproduction harnesses so
findings can be verified in seconds without cloud infrastructure.

This is a one-line Resources addition following the section's existing format.
```

## How to open it (you do this; I do not open PRs on your behalf)

Option A, GitHub CLI (fastest):

```bash
# fork + clone (skips if you already have a fork)
gh repo fork modelcontextprotocol/servers --clone --remote
cd servers
git checkout -b docs/add-mcp-witness-resource
# edit ADDITIONAL.md: add the line above to the "## 📚 Resources" section, alphabetically
$EDITOR ADDITIONAL.md
git add ADDITIONAL.md
git commit -m "docs: add mcp-witness security testing toolkit to ADDITIONAL.md Resources"
git push -u origin docs/add-mcp-witness-resource
gh pr create --repo modelcontextprotocol/servers \
  --title "docs: add mcp-witness security testing toolkit to ADDITIONAL.md Resources" \
  --body-file -   # paste the PR body above, then Ctrl-D
```

Option B, web UI: fork the repo, edit `ADDITIONAL.md` in the browser, add the line to the Resources section, and open the PR with the title and body above.

## Note on framing

Keep the PR strictly a neutral Resources listing. Do not reference the SSRF disclosure, the closed issue, or the unmerged fix PR in the PR description. The listing stands on its own as a tool that helps MCP developers audit their servers, which is exactly what the Resources section is for. Mixing the disclosure history into the PR would make it read as adversarial and lower the odds of a clean merge.
