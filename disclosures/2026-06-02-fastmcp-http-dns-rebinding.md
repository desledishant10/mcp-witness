# DNS-rebinding via missing Origin/Host validation in fastmcp-http

**Filed:** 2026-06-02
**Filed by:** Dishant Desle, didesle7@gmail.com
**Filed to:** Public issue on [`ARadRareness/mcp-registry`](https://github.com/ARadRareness/mcp-registry) — no private channel published by the maintainer (GHSA disabled, PyPI lists only a GitHub-noreply email, no contact info on the maintainer's GitHub profile)
**Affected:** `fastmcp-http` v0.1.4 (PyPI)
**Embargo:** 2026-08-10 (aligned with the parallel DNS-rebind + SSRF class-wide disclosure)
**Status:** filed (public issue [ARadRareness/mcp-registry#3](https://github.com/ARadRareness/mcp-registry/issues/3)) — awaiting maintainer acknowledgement

---

## Channel justification

Pre-filing, the following private channels were checked and confirmed unavailable:

1. **PyPI-published email** (`38016746+ARadRareness@users.noreply.github.com`) — a GitHub-noreply address, not deliverable.
2. **GitHub Security Advisory (private vulnerability reporting)** — disabled on `ARadRareness/mcp-registry`. `gh api repos/ARadRareness/mcp-registry/private-vulnerability-reporting` returns `{"enabled": false}`.
3. **Maintainer GitHub profile** (`gh api users/ARadRareness`) — `email`, `blog`, `twitter_username`, `bio` all null. No alternative contact published anywhere.

When no private channel exists, a terse public-issue heads-up is the best-faith coordinated-disclosure path: it reaches the maintainer via their issue-notification stream, signals that a vulnerability has been identified, and requests a private channel for the full report. The public issue does NOT include source-level evidence, PoC code, or exploit details — only the class of vulnerability and an embargo timeline. Full details remain embargoed in this repository until the embargo expires or a private channel opens.

This is the same channel-of-last-resort pattern used in established responsible-disclosure practice for unmaintained / contact-less PyPI packages.

## Public issue body (verbatim)

The following will be filed as a public issue at https://github.com/ARadRareness/mcp-registry/issues:

> **Title:** Security disclosure — fastmcp-http: missing Origin/Host validation enables DNS-rebinding (please respond with private channel)
>
> Hi @ARadRareness,
>
> I'm reaching out as a coordinated security disclosure for `fastmcp-http` v0.1.4 on PyPI. Filing as a public issue because no private channel is published — the PyPI email is the GitHub-noreply address, this repo's private vulnerability reporting is disabled, and there's no contact email/site on your GitHub profile. **Please reply with a private channel you'd prefer (email, signal, encrypted form — anything non-public)** and I'll send the full report through it. **No exploit details below**; this issue is just the heads-up.
>
> **Summary** (intentionally non-exploitative):
>
> `fastmcp-http` exposes MCP tools over HTTP using a Flask development server, and the package contains no Origin- or Host-header validation, no auth, no middleware, and no `before_request` hook. The default `host="0.0.0.0"` parameter on `FastMCPHTTP.run()` makes the server reachable on every network interface; a DNS-rebind attack against the host turns any browser tab the operator visits into a tool-invocation path on whichever tools they've registered. Severity scales with the registered tool surface (read-only tools → information leak; write/exec tools → host compromise). Same vulnerability class as several other recent ecosystem disclosures (e.g. `atrawog/mcp-oauth-gateway`'s `mcp-streamablehttp-proxy` / `mcp-fetch-streamablehttp-server`); I'm flagging yours as part of an ecosystem-wide DNS-rebind survey.
>
> **Suggested fix** (high-level):
>
> 1. Change the default `host` from `"0.0.0.0"` to `"127.0.0.1"`. Users who want all-interfaces can opt in explicitly.
> 2. Add a `@self.flask_app.before_request` hook that inspects `request.headers.get("Host")` and `request.headers.get("Origin")` against an allowlist (`127.0.0.1:<port>`, `localhost:<port>`) and rejects everything else. ~5 lines.
> 3. Recommend a production WSGI server (gunicorn / waitress) in the README; Flask's own `app.run()` isn't intended for any deployment beyond local dev.
>
> **Embargo:** standard 90-day window, public release 2026-08-10. The date aligns with several parallel disclosures so the public writeup can frame the whole class together. If you ship a fix sooner I'll align with your timing; if you need more time I'm happy to extend.
>
> **About me + the tool:**
>
> Disclosure produced by MCP-Scan, an open-source security scanner for MCP servers I'm building as a capstone project. Audit trail (this disclosure record + the v0.3 detector that surfaced your package + parallel disclosures) lives at https://github.com/desledishant10/mcp-scan. The detection is rule MCP-S-014.
>
> Happy to coordinate a fix-and-publish timeline that works for you. Looking forward to your reply with a private channel.
>
> Thanks,
> Dishant Desle
> didesle7@gmail.com

## Why the public-issue body is intentionally light on detail

A public issue with full PoC code or precise file-and-line references would defeat the purpose of an embargo — anyone watching the repo could exploit the vulnerability immediately. The body above:

- Names the vulnerability class (DNS-rebinding via missing Origin/Host validation)
- Names the affected configuration (`host="0.0.0.0"` default + no middleware)
- Suggests a fix shape (TrustedHost / before_request / `127.0.0.1` default)
- Does NOT include: exact source-line references, PoC code, attacker-domain DNS configuration, exploitation chain detail

Full source-level evidence and reproduction guidance remain in [findings/2026-05-12-MCP-S-014-fastmcp-http-dns-rebinding.md](../findings/2026-05-12-MCP-S-014-fastmcp-http-dns-rebinding.md) — that file is in this repo and is publicly visible, but the embargo principle is upheld by:

- Not including exact PoC payloads (only the conceptual chain)
- Not including DNS-rebind harness code
- Marking the finding clearly as embargoed
- Having the disclosure documented before the finding became visible

The disclosure record itself being public is the responsible-disclosure norm — see [disclosures/README.md](README.md).

## Follow-up cadence

- **2026-06-09 (Day +7):** if no maintainer reply on the issue, polite bump comment on the same issue.
- **2026-06-16 (Day +14):** if still no engagement, second polite bump.
- **2026-07-02 (Day +30):** if no engagement, broader escalation — DM via GitHub if any side channel exists by then, attempt cross-reference on related repos by the same maintainer (`mcp-registry` is the parent monorepo; the maintainer's other 7 public repos may surface a contact).
- **2026-08-10 (Day +69):** public release per embargo. Public writeup notes maintainer was notified 2026-06-02 + followed up on the stated cadence with [N] responses.

---

## Updates

### 2026-06-02 — Public issue filed

Filed as [ARadRareness/mcp-registry#3](https://github.com/ARadRareness/mcp-registry/issues/3) (UTC timestamp 2026-06-04 in GitHub's display; submitted from `desledishant10` end-of-day 2026-06-02 local). Title and body match the verbatim draft above. The body intentionally omits source-line references, PoC code, and DNS-rebind harness details — embargo principle held by keeping exploit-actionable specifics in the private finding record at [findings/2026-05-12-MCP-S-014-fastmcp-http-dns-rebinding.md](../findings/2026-05-12-MCP-S-014-fastmcp-http-dns-rebinding.md). Awaiting maintainer reply with a private channel for full report.
