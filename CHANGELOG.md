# Changelog

All notable changes to mcp-witness. Format roughly follows [Keep a Changelog](https://keepachangelog.com/); the project is alpha so changes are not yet versioned with semver discipline. Project name history: `mcp-scan` (initial) → `mcpsentry` (renamed 2026-06-08 to avoid collision with Snyk-Invariant's mcp-scan / agent-scan) → `mcp-witness` (renamed 2026-06-09, after PyPI rejected `mcpsentry` as too similar to the existing `mcp-sentry` package). Historical CHANGELOG sections preserve the project's original name as written at release time.

## [Unreleased] — main branch

### Added

- **Calibration corpus regression test in CI** (`calibration/tests/test_corpus_regression.py`; **+6 tests, 185 → 191**). Six assertions that protect the 100/100 precision-recall asset and the corpus shape against accidental regression: (1) at least 10 labeled targets (spec stable threshold), (2) precision ≥ 0.90 on every exercised capability tag, (3) recall ≥ 0.75 on every exercised tag, (4) parameter-role accuracy ≥ 0.80, (5) the four original v0.1 tags (`exec`, `fs_read`, `fs_write`, `net_egress`) remain exercised in the corpus, (6) no tag has zero true positives despite having ground-truth positives (catches "detector entirely missing" failure mode distinct from "tuning regression"). Runs automatically as part of `pytest`, so it's already in the existing `.github/workflows/tests.yml` CI pipeline without any workflow changes. Floor values are deliberately set at the spec floor (not at current observed values) so honest corpus expansion that adds harder targets doesn't trip the test, while real regressions still get caught.
- **`mcp-witness-disclose` — coordinated-disclosure helper CLI** (new `disclose/` package; **+21 tests, 164 → 185**). Codifies the day +14 / +21 / +30 / +45 / +60 / +90 milestone cadence used to run the mcp-witness disclosure track and makes the methodology lift-able by anyone else doing coordinated security disclosure. Three v0.1 subcommands:
  - **`mcp-witness-disclose new <target>`** — scaffold a `disclosures/YYYY-MM-DD-<slug>.md` file with frontmatter prefilled (Filed, Filed by, Filed to, Affected, Embargo at +90 days, Status: drafted) plus channel-decision-audit + body + Updates section skeletons. Refuses to overwrite without `--force`.
  - **`mcp-witness-disclose status`** — table or `--json` view of every disclosure in `disclosures/`. For each: filing date, day-count vs `--today` (defaults to today), parsed status, and the next-milestone calculation (e.g. "day +45 pointer issue in 15d (2026-06-26)"). Summary line counts open / closed / due-today / overdue. Smoke-tested against the real 4 in-flight disclosures: produces the same dates the human escalation playbook landed on.
  - **`mcp-witness-disclose ping <slug>`** — render a day-appropriate message body. Day +14 / +21 templates are soft confirmations; day +30 switches to escalation language with soft-channel options (LinkedIn / Twitter / contact form / third email); day +45 generates a non-exploitative pointer-issue body for filing on the upstream repo; day +60 is the final-notice template naming the embargo publish date. Slug is fuzzy-matched (exact slug, basename, or prefix substring across `disclosures/`).
  - Implementation layers: `disclose.dates` (milestone cadence + day arithmetic, both injectable via `--today` for reproducibility), `disclose.parse` (permissive markdown frontmatter parser tolerant of multi-line `Filed to:` / `Affected:` blocks and bold-emphasis-wrapped Status lines), `disclose.templates` (safe-substitution templates rendering `<missing field>` rather than raising on unbound names), `disclose.cli` (argparse, subcommand dispatch, status-row formatting). Heuristic `is_closed()` classifies "fix verified" / "unmaintained" / "publicly disclosed" statuses as closed for the summary line; conservative — anything ambiguous stays "open."
  - Console script registered as `mcp-witness-disclose`; package added to hatch wheel targets.

### Released

- **🎉 2026-06-11 — First PyPI release: [`mcp-witness 0.2.0`](https://pypi.org/project/mcp-witness/0.2.0/).** Both wheel and sdist live on PyPI. Quickstart is now `pip install mcp-witness` (replacing the previous `git clone + pip install -e .` flow). End-to-end verified: fresh-venv install → `mcp-witness-audit mcp-server-fetch` produces 2 findings (MCP-S-001 + MCP-S-009 — the SSRF detection that led to #4143).

### Changed

- **Project renamed (second time): mcpsentry → mcp-witness.** PyPI rejected `mcpsentry` upload with `400 Bad Request: The name 'mcpsentry' is too similar to an existing project` — under PyPI's name normalization, `mcpsentry` and the existing `mcp-sentry` package (an MCP server for retrieving issues from sentry.io, v0.6.2) collide. Picked `mcp-witness` from the original backup-name list: zero PyPI collision, zero GitHub-name collision, and "witness" carries three useful connotations for the project (attestation of state, observation of behavior, formal evidence in disclosure). PyPI namespace, GitHub repo, console scripts, env vars, and prose all updated; package directories (`analyzer/`, `harness/`, `classifier/`, `calibration/`) keep their functional names; disclosures + findings + this CHANGELOG's historical sections preserve the prior names as written at the time.
- **Console scripts renamed (second time):** `mcpsentry-*` → `mcp-witness-*` (audit, capture, scaffold-gt, analyze, classify, eval-calibration, lint-scenarios, test). Reinstall after pulling: `pip uninstall mcpsentry -y && pip install -e ".[dev]"`.
- **Env vars renamed (second time):** `MCPSENTRY_*` → `MCP_WITNESS_*` (MOCK_CONFIG, AGENT_MODEL, AGENT_MAX_ITERATIONS).
- **Project renamed (first time, recorded on 2026-06-08): MCP-Scan → mcpsentry.** Avoided collision with Snyk-Invariant's well-established `mcp-scan` (now `agent-scan`, 2.5k stars). PyPI namespace, GitHub repo URL, console scripts, and project-name prose updated; package directories kept their functional names. Subsequently superseded by the second rename above when the chosen replacement also turned out to collide on PyPI's similarity heuristic.
- **Console scripts renamed (first time):** `mcp-scan-*` → `mcpsentry-*` (audit, capture, scaffold-gt, analyze, classify, eval-calibration, lint-scenarios, test).
- **README rewritten** to lead with the Anthropic SSRF disclosure narrative (EC2 IAM-credential demo + PR #4226 verified) before test counts / rule tables. The disclosure is the differentiator; test counts are table stakes.
- **GitHub Pages enabled** at `desledishant10.github.io/mcpsentry`. `_config.yml` excludes `drafts/`, `disclosures/`, `findings/`, source dirs, etc. — only the root README and `docs/` are published as Pages-served HTML.
- **Embargoed blog draft moved out of `/docs/`** to `/drafts/` to keep it out of Pages indexing pre-2026-08-10. Still in the public repo (open-auditing principle preserved), just not in the Pages-served path.
- **Embargo-day blog draft rewritten for the broader 6-package/2-class scope.** Original draft (`blog-draft-2026-08-10-mcp-ssrf-disclosure.md`, now archived as `blog-draft-2026-08-10-v1-ssrf-only-archived.md`) covered only the 2 SSRF packages; new draft (`blog-draft-2026-08-10-mcp-transport-layer-blind-spot.md`, ~3,800 words) covers both vulnerability classes — outbound SSRF (`mcp-server-fetch` + `mcp-server-http-request`) and inbound DNS rebinding (`mcp-streamablehttp-proxy`, `mcp-fetch-streamablehttp-server`, `fastmcp-http`, `mcp-server-fetch-sse`) — with a unifying "external constraint, missing in-package enforcement" frame. Adds: PR #4226 fix-verified subsection, full Class 2 (DNS rebinding) section, brand-attribution section (incl. neutral one-paragraph mention of HackerOne process friction), MCP-spec-level recommendation, and a Next section pointing at follow-up writeups (v0.3 detector patches + AST-vs-pattern methodology). Working title: *"MCP servers and the transport-layer blind spot: six Python packages, two vulnerability classes, one ecosystem norm."* Structural outline preserved alongside the draft at [`drafts/blog-outline-v2.md`](drafts/blog-outline-v2.md) for the Session 3 polish pass.

### Fixed

- **`_walk_repo_files` substring-on-absolute-path bug.** The skip-fragment check (e.g. `/site-packages/`, `/.venv/`) was matched against the absolute path, which meant *any* scan rooted under `site-packages/` returned zero files. This silently broke `mcp-scan-audit <pypi-pkg>` for the entire v0.2 lifecycle — the documented quickstart workflow. Surfaced by re-running the v0.3 detector against the original DNS-rebind survey targets and getting zero hits despite the patches being correct. The walker now checks skip fragments against the path *relative* to root, so user-pointed-at scans inside one of the skip dirs work correctly.

### Detector evolution (MCP-S-014 v0.3)

- **MCP-S-014 detector v0.3 patches.** The DNS-rebinding survey surfaced three false-negative classes in the v0.2 detector; all are now fixed, plus a fourth (W4) surfaced during the post-patch verification re-run:
  - **W1 — host=variable resolution.** The detector previously only resolved string-literal host arguments. `uvicorn.run(app, host=host, port=port)` patterns where `host` is bound to `"0.0.0.0"` earlier (via module-level assignment or function parameter default) now resolve correctly. Pre-pass `_collect_string_bindings(tree)` walks the file for `ast.Assign` and `FunctionDef.args.defaults` / `kwonlyargs` bindings; `_extract_host_value` threads the binding map through and resolves `ast.Name` arguments. File-wide flat scope (no lexical-scope precision) is a deliberate heuristic for a "review this" static rule.
  - **W2 — origin-suppression tightened.** Previously a case-insensitive `\borigin\b` substring match anywhere in the file silenced the rule. Comments like `# CORS handled by Traefik` and wildcard CORS response headers (`Access-Control-Allow-Origin: *`) both qualified. New `_file_validates_origin(tree)` walks the AST for actual request-header reads: `.headers["Origin"]` (subscript) or `.headers.get("Origin", …)` (method call), case-insensitive on the key. Comments, docstrings, and response-header string literals no longer suppress.
  - **W3 — aiohttp.web bind shapes.** `_SERVER_BIND_METHODS` extended with `run_app` (keyword-host pattern: `web.run_app(app, host="…")`) and `TCPSite` (positional-host pattern: `web.TCPSite(runner, "…", port)`). `mcp-server-fetch-sse` and similar aiohttp-based packages no longer slip through the detector.
  - **W4 — `os.getenv(..., "default")` and `os.environ.get(..., "default")` resolution.** Surfaced during the post-patch verification against `mcp-fetch-streamablehttp-server`, which uses `host = os.getenv("HOST", "0.0.0.0")` — the env-driven default pattern. `_extract_env_default` resolves the second-arg string default; `_collect_string_bindings` calls it for `Assign` nodes whose value is a `Call`. Now binds `name → "default"` for both `os.getenv` and `os.environ.get` shapes.
- **Verified end-to-end against the original DNS-rebind survey targets.** Re-ran the v0.3 detector on all four installed packages (after fixing the walker bug above). 4 of 4 now correctly fire S-014: `mcp-streamablehttp-proxy` (W1), `mcp-fetch-streamablehttp-server` (W4), `fastmcp-http` (W1), and `mcp-server-fetch-sse` (W1+W3).
- Test suite: **151 → 164** tests (13 new across W1/W2/W3/W4 positive + negative cases).

### Disclosure status

- **2026-06-02 — Three new disclosures dispatched.**
  - `fastmcp-http` v0.1.4 DNS rebinding: public-issue channel of last resort at [ARadRareness/mcp-registry#3](https://github.com/ARadRareness/mcp-registry/issues/3) after `gh api` verified GHSA disabled + maintainer profile has no contact + PyPI lists only a GitHub-noreply email. Public issue body intentionally light on PoC; embargo principle held by keeping source-line evidence in the private finding only.
  - `mcp-server-fetch-sse` v0.1.1 DNS rebinding + inherited pre-PR-#4226 SSRF: primary disclosure to maintainer-of-record `jadamson@anthropic.com`; parallel courtesy notice to Anthropic Security via `disclosure@anthropic.com` after HackerOne attempt halted at the program triage interstitial (full channel-decision audit trail in [disclosures/2026-06-02-mcp-server-fetch-sse-dns-rebinding.md](disclosures/2026-06-02-mcp-server-fetch-sse-dns-rebinding.md)). `disclosure@` returned a no-reply auto-responder routing back to HackerOne — no human review reached on the brand-attribution flag. Documented; primary technical disclosure to maintainer is the binding channel for the fix.
  - Day +21 follow-up pings sent on the two May 12 disclosures that remained silent (statespace `mcp-server-http-request`, atrawog `mcp-streamablehttp-proxy` + `mcp-fetch-streamablehttp-server`).
- **All six DNS-rebind + SSRF survey targets are now under active coordinated disclosure with the same 2026-08-10 embargo** for the class-wide public writeup.

### Disclosure status (earlier)

- **2026-05-22 — mcp-server-fetch fix PR opened AND independently verified.** PR [modelcontextprotocol/servers#4226](https://github.com/modelcontextprotocol/servers/pull/4226) by `@kgarg2468` explicitly fixes [#4143](https://github.com/modelcontextprotocol/servers/issues/4143) with scheme allowlist + reserved-range denylist + **per-redirect validation** (a defense beyond the original disclosure ask). Same demo script that retrieved IAM credentials on EC2 was re-run against the fix branch: now returns `"Fetching private or non-public IP addresses is not allowed"`. Verification comment posted on the PR. Awaiting maintainer approval.

---

## [0.2.0] — 2026-05-12

### Added

- **Static-analyzer ruleset complete: 14/14 v0.1 rules implemented.** Five new rules close out the spec:
  - **MCP-S-010** — committed secrets and `.env` files. Regex scan for named-format keys (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, Google API, PEM private keys, JWTs); flag presence of `.env*` files in source tree (excluding documented-safe `.example` / `.sample` / `.template` / `.dist` variants). Path-glob allowlist via `.mcp-scan-allowlist` at scan root.
  - **MCP-S-011** — sensitive data logged to stderr/stdout. AST scan over tool handlers for `print`, `logging.X`, `logger.X`, `sys.stderr.write`, `console.error` calls whose arguments reference a tool parameter, a sensitive-named identifier (`token`, `password`, `header`, etc.), or `os.environ`/`os.getenv`. Calls inside `if debug:` / `if verbose:` blocks suppressed as the documented opt-in shape.
  - **MCP-S-012** — `RootsCapability` referenced but `list_roots()` never called. Cross-file scan; declares a containment guarantee the server doesn't actually enforce.
  - **MCP-S-013** — prompt template interpolation without sanitization. Discovers `@<x>.prompt()` handlers, inspects `PromptMessage`/`Message`/role-typed constructors and dict-literal messages, flags parameter interpolation (f-string, `.format`, `%`-format, `+`-concat) into `system` or `assistant` roles. User-role interpolation silenced — too conventional to be useful signal.
  - **MCP-S-014** — HTTP transport missing Origin/Host validation. AST scan for `uvicorn.run` / similar server binds on `0.0.0.0` / `127.0.0.1` / `localhost`; flags when the source file contains no reference to `Origin` header validation. Also flags the CORS `allow_origins=['*']` + `allow_credentials=True` antipattern.
- **`REPO_RULES` rule shape** — new third rule registry alongside `RULES` (per-tool) and `SERVER_RULES` (per tool set). Rules in this shape receive the scan-root `Path` and walk the source tree themselves. Used by S-010, S-012, S-013, S-014. Captured-mode scans (`.json`) skip `REPO_RULES` since there's no source tree.
- `mcp-scan-audit` — one-shot CLI that pip-installs a package, captures its tools/list, runs the analyzer and classifier, and prints a human-readable report. Replaces the previous three-command quickstart in the README.
- Analyzer rule **MCP-S-004** — flags tools whose `annotations.readOnlyHint: true` or `destructiveHint: false` contradicts write-indicating verbs in the name or description.
- Analyzer rule **MCP-S-008** — heuristic SQLi detection from captured `tools/list`; flags query-typed parameters without parameterized-query mention.
- Analyzer rule **MCP-S-009** — heuristic SSRF detection from captured `tools/list`; static counterpart to the dynamic MCP-D-003 probe. Fires on `mcp-server-fetch` and `mcp-server-http-request`.
- Dynamic scenario **MCP-D-007** — cloud-metadata-exfiltration scenario with strict oracle (only fires on JSON-shape metadata field names; designed for EC2 audit verification).
- `disclosures/` directory with append-only audit-trail records of outgoing coordinated-disclosure communications. First entry covers the fetch + http-request SSRF disclosure.
- `findings/` directory entries for: D-003 SSRF on mcp-server-fetch (vulnerability, demonstrated on EC2 + disclosed as [modelcontextprotocol/servers#4143](https://github.com/modelcontextprotocol/servers/issues/4143)); D-003 SSRF on mcp-server-http-request (vulnerability, email-disclosed); D-001/D-006 defense observations against Claude Opus 4.7; D-002 defense observations against mcp-server-git and mcp-server-aidd; S-003 informational on mcp-server-time; aidd multi-rule informational.
- `docs/audit-runbook-ec2-ssrf-verification.md` — step-by-step runbook from AWS account creation through EC2 reproduction, evidence capture, and teardown.
- `docs/blog-draft-2026-08-10-mcp-ssrf-disclosure.md` — embargo-day blog draft (publication scheduled for 2026-08-10).
- `SECURITY.md` and `CONTRIBUTING.md`.
- Calibration corpus growth: 5 → 10 labeled targets, 33 → 81 tools. Stable per spec.
- Calibration-driven lexicon improvements (each commit-annotated with the corpus evidence that drove it).
- Test suite: 76 → **151** tests (45 new across the five new rules).

### Changed

- README rewritten to feature real findings + one-command quickstart instead of planning-document framing.
- Scaffolded ground-truth files now include `labeled: false` so the eval skips drafts by default.
- `_relpath` normalization (in `analyzer/rules.py`) made consistent between directory and single-file scans — REPO_RULES findings now report the same path form as per-tool findings.

### Fixed

- `\blists?\b` lexicon pattern false-positive on Python type annotations (`Optional[List[str]] - Tags`); now uses `(?<!\[)\blists?\b(?![\[\(])` to exclude generic-type contexts.
- D-002 scenario YAML had an embedded null byte (`%00` escape-sequence smuggling); replaced with literal `%00` characters.

### Security

- Coordinated disclosure filed for class-wide SSRF in `mcp-server-fetch` (Anthropic reference) and `mcp-server-http-request` (community). Embargo expires 2026-08-10.

---

## [0.1.0a0] — 2026-05-10

### Added

- Initial scaffolding for analyzer, harness, classifier, calibration, and scenarios packages.
- 6 analyzer rules (S-001, S-002, S-003, S-005, S-006, S-007).
- 6 dynamic scenarios (D-001 through D-006).
- Capability classifier with Layer 1 (lexical) detection across 8 capability tags and 8 parameter roles.
- HTTP canary server for dynamic-scenario SSRF probes.
- Proxy-mode harness with stub and Anthropic agent drivers.
- Mock MCP server for plumbing tests.
- 76 tests across analyzer, classifier, harness, and calibration packages.
- Initial calibration corpus of 5 labeled targets (3 verified by capture, 2 best-effort from public docs).
