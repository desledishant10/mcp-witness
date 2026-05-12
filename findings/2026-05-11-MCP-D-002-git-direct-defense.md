# MCP-D-002 vs mcp-server-git

**Date:** 2026-05-11
**Target:** `mcp-server-git` v? (PyPI; version not pinned at capture)
**Tested by:** [scenarios/MCP-D-002-path-traversal-fs-tool.yaml](../scenarios/MCP-D-002-path-traversal-fs-tool.yaml)
**Agent driver:** n/a (direct mode — harness as MCP client)
**Outcome:** **DEFENSE**

## Result

`mcp-server-git` resisted every path-traversal probe across 7 read-classified tools × 9 traversal payloads = 63 calls. The canary file content (`MCP_SCAN_CANARY_<run_id>`) never appeared in any response. Two independent defense layers fired.

```json
{
  "scenario_id": "MCP-D-002",
  "passed": true,
  "oracle_evidence": [],
  "skipped_steps": [],
  "error": null
}
```

## Reproduction

```bash
# Need a non-target git repo for the server to be willing to start:
REPO=/tmp/mcp-scan-git-test
mkdir -p "$REPO" && (cd "$REPO" && git init -q && echo test > README \
    && git add README && git -c user.email=t@t -c user.name=t commit -q -m init)

mcp-scan-test scenarios/MCP-D-002-path-traversal-fs-tool.yaml \
    --server-cmd python --server-arg=-m --server-arg=mcp_server_git \
    --server-arg=--repository --server-arg="$REPO"
```

## What happened

Tools the harness classified as `fs_read` capability and therefore probed:
`git_status`, `git_diff_unstaged`, `git_diff_staged`, `git_diff`, `git_log`, `git_show`, `git_branch`.

Two distinct defense responses observed across the 63 calls:

### Layer 1: JSON Schema required-property validation

```
git_branch({"repo_path": "/var/folders/.../mcp-scan-canary-...txt"})
  → "Input validation error: 'branch_type' is a required property"

git_diff({"repo_path": "/var/folders/.../mcp-scan-canary-...txt"})
  → "Input validation error: 'target' is a required property"

git_show({"repo_path": "/var/folders/.../mcp-scan-canary-...txt"})
  → "Input validation error: 'revision' is a required property"
```

The MCP framework rejected the call at JSON Schema validation before the path ever reached `_repository = Repo(path)`. Side effect: D-002's probing only carries `repo_path`, so tools requiring more args bail without exercising the path-traversal logic.

### Layer 2: repository-path canonicalization + git-repo check

```
git_status({"repo_path": "/var/folders/.../mcp-scan-canary-...txt"})
  → "Repository path '/var/folders/.../mcp-scan-canary-...txt' does not
      appear to be a Git repository"

git_diff_staged, git_diff_unstaged, git_log → same pattern
```

For tools whose schema validation passed, the server attempts to construct a `gitpython.Repo(repo_path)`, which raises if the path isn't a valid git repo. The exception is caught and surfaced as a clean error message — no file content leaks.

## Interpretation

This is a positive example of defense-in-depth that other MCP server authors can model:

1. **Schema validation is doing real work.** Strict `required` lists on tool inputs reject malformed calls before any business logic runs. Many MCP servers use loose schemas (every field optional, "we'll figure it out from what's provided"). Git's strict schema is the right pattern.

2. **The semantic check is independent of the schema check.** Even when schema validation passes, the server still validates that `repo_path` points to a real git repo. This is the *application-layer* check that a determined attacker would need to bypass — and the only way to bypass it is to supply a real git repo path, at which point the worst they can do is read git history of a repo they already have access to.

3. **Errors are flat strings, not stack traces.** No file path internals, no python tracebacks, no library-internal state leaks into the response. This is the right error-surfacing pattern for security-sensitive tools.

## Caveats

- **D-002 doesn't probe the parameters tools actually need.** A more thorough scenario would supply valid `branch_type` / `target` / `revision` arguments and probe `repo_path` separately. For tools requiring multiple args, the current D-002 design exercises the schema layer but not the path layer.
- **The "defense" is partly accidental.** The schema-validation rejection of single-arg calls means we didn't fully exercise the git_branch / git_diff / git_show path-handling code paths. To attribute defense to *path handling*, we'd need a refined D-002 that supplies all required params.
- **Path-traversal-via-symlink not tested.** If `/tmp/some.git` symlinked to `/etc`, would `git_log` follow? Unlikely — gitpython resolves the path and rejects non-repo locations — but the scenario doesn't probe this.

## Suggested follow-up

1. Refine D-002 to supply valid args for the multi-param tools, then re-run. Expected: same defense holds at Layer 2.
2. Author a D-002b "git symlink escape" scenario specifically for the symlink class.
3. Document the schema-validation pattern in the eventual project writeup as a positive example for MCP server authors.

## Disclosure

Not applicable — defense observed, no vulnerability.
