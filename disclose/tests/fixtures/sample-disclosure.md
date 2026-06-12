# Sample SSRF in fake-mcp-server

**Filed:** 2026-05-12
**Filed by:** Dishant Desle, didesle7@gmail.com
**Filed to:** maintainer@example.invalid
**Affected:** `fake-mcp-server` v0.1.0 (PyPI)
**Embargo:** 2026-08-10 (90 days from filing)
**Status:** filed (awaiting acknowledgement)

---

## Channel decision audit

PyPI METADATA lists `maintainer@example.invalid`. GHSA is enabled but
the maintainer hasn't responded on prior advisories; email-first.

## Body of the filed report

Hi maintainer. Coordinated security disclosure for SSRF in
fake-mcp-server v0.1.0. Embargo runs through 2026-08-10. Suggested fix
shape: scheme allowlist + RFC-reserved-range denylist.

## Updates

<!-- newest first -->
