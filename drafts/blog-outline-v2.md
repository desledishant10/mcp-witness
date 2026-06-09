# Blog outline v2 — 2026-08-10 embargo-day post

Working draft: [blog-draft-2026-08-10-mcp-transport-layer-blind-spot.md](blog-draft-2026-08-10-mcp-transport-layer-blind-spot.md)

## Scope decision

One comprehensive post covering all 6 disclosed packages across 2 vulnerability classes (outbound SSRF + inbound DNS rebinding). Both classes share the 2026-08-10 embargo and tell one coherent ecosystem-level story.

## Working title

*"MCP servers and the transport-layer blind spot: six Python packages, two vulnerability classes, one ecosystem norm"*

Alt: *"MCP at the transport layer: how the protocol's HTTP boundary leaks both ways"*

## Sections + word budget (target ~3,000)

| # | Section | Words | Status |
|---|---|---|---|
| 1 | TL;DR | 250 | rewritten — leads with 6/2/1-fix |
| 2 | What MCP is + why this surface exists | 200 | existing + framing add |
| 3 | Class 1 — Outbound SSRF | 650 | mostly existing + NEW PR #4226 subsection |
| 4 | Class 2 — Inbound DNS rebinding | 700 | NEW — full section |
| 5 | The brand-attribution problem | 250 | NEW — includes HackerOne-friction paragraph |
| 6 | Class-wide observation: ecosystem norm | 450 | expanded — both anti-patterns under one frame |
| 7 | Disclosure timeline | 150 | rewritten — actual events |
| 8 | What the ecosystem should do | 550 | expanded — adds MCP-spec recommendation |
| 9 | About the tool | 150 | updated — mcpsentry rename + current metrics |
| 10 | Next | 150 | NEW — pointers to follow-ups |
| 11 | Closing | 100 | slight rewrite |

## Key narrative arcs

1. **The discovery-to-fix loop works.** PR #4226 from external contributor within 10 days of disclosure; fix is *more* defensive than the disclosure asked for (per-redirect validation); independently verified pre-embargo.
2. **Two attack directions, one architectural anti-pattern.** SSRF is server-reaching-out; DNS rebind is browser-reaching-in. Both result from "external constraint, missing in-package enforcement" — the assumption that someone upstream handles security.
3. **The detector evolved with the survey.** W1-W4 patches reflect what the four DNS-rebind targets taught the static rule. Told honestly: original detector missed 4 of 4.
4. **The brand-attribution problem is novel material.** mcp-server-fetch-sse case study — Anthropic Author attribution on a third-party fork; disclosure-channel friction told neutrally.
5. **Ecosystem-level recommendation: spec-mandated validation.** Hook from zeweihan's comment on #4143 — propose the MCP spec mandate SSRF + Origin/Host validation patterns for HTTP-class tools.

## Things NOT in this post (deliberate exclusions)

- The v0.3 detector technical writeup — gets its own piece
- AST-vs-string-matching methodology — gets its own piece
- Calibration corpus methodology — gets its own piece
- Threat modeling for MCP at large — outside scope; this post is about two specific vulnerability classes

## Session sequence

- **Session 1 (done):** decisions + this outline
- **Session 2 (~2 hours):** write the new draft according to the outline
- **Session 3 (a few days before launch):** polish — read-aloud, TL;DR pull-quote, 280-char Twitter version, HN title + first comment

## Launch-day artifacts (Session 3 produces these)

- Blog post (this file → final-published)
- HN title: ~80 chars, no "Show HN" prefix (this isn't a tool launch, it's a disclosure)
- HN first comment: technical color the post body skipped
- Twitter thread: 5-7 tweets, lead with the EC2 IAM screenshot
- Lobsters submission with `security` + `ai` tags
- Comment on #4143 with the published URL
