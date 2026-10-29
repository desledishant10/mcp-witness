.PHONY: demo demo-quick demo-full demo-fixed demo-fixed-release clean help

# The first mcp-server-fetch PyPI release that ships the SSRF fix default-on
# is 2026.10.10; 2026.10.28 is the current release. Override with e.g.
#   make demo-fixed-release FIXED_VERSION=2026.10.19
FIXED_VERSION ?= 2026.10.28

help:
	@echo "SSRF PoC harness — targets:"
	@echo ""
	@echo "  make demo-quick   Fast Python-only probe (no Docker)."
	@echo "                    Side-by-side pre-fix vs post-fix demonstration"
	@echo "                    using a threaded IMDS mock + bare urllib."
	@echo "                    No mcp-server-fetch install required."
	@echo "                    ~3 seconds."
	@echo ""
	@echo "  make demo-full    Full containerized end-to-end PoC against the"
	@echo "                    real mcp-server-fetch v2025.4.7 package."
	@echo "                    Requires Docker. ~60 seconds first run, ~5"
	@echo "                    seconds thereafter."
	@echo ""
	@echo "  make demo         Runs demo-quick, then demo-full."
	@echo ""
	@echo "  make demo-fixed-release"
	@echo "                    Same shape as demo-full but installs the fixed"
	@echo "                    PyPI release (mcp-server-fetch $(FIXED_VERSION))."
	@echo "                    The SSRF is fixed default-on upstream via #5033,"
	@echo "                    shipped 2026.10.10+. Expected outcome: FIX VERIFIED."
	@echo ""
	@echo "  make demo-fixed   Historical: installs the never-merged community"
	@echo "                    fix PR #4226 branch directly. Prefer"
	@echo "                    demo-fixed-release for the shipped fix."
	@echo "                    Expected outcome: FIX VERIFIED."
	@echo ""
	@echo "  make clean        Tear down containers + remove built images."

demo: demo-quick demo-full

demo-quick:
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " demo-quick — direct probe (no Docker)"
	@echo "═════════════════════════════════════════════════════════════════"
	python3 quick_probe.py

demo-full:
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " demo-full — containerized SSRF reproduction"
	@echo "═════════════════════════════════════════════════════════════════"
	docker compose up --build --abort-on-container-exit --exit-code-from attacker

demo-fixed-release:
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " demo-fixed-release — install the fixed PyPI release + run vs IMDS"
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " The SSRF is fixed default-on upstream via modelcontextprotocol/"
	@echo " servers#5033 (merged 2026-10-05), shipped in mcp-server-fetch"
	@echo " 2026.10.10+. Installing mcp-server-fetch==$(FIXED_VERSION) from PyPI."
	@echo " Expected outcome: FIX VERIFIED (attacker exits 1)."
	@echo ""
	MCP_FETCH_SPEC="mcp-server-fetch==$(FIXED_VERSION)" \
	MCP_FETCH_VERSION="$(FIXED_VERSION)" \
	docker compose up --build --abort-on-container-exit --exit-code-from attacker

demo-fixed:
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " demo-fixed — install the (never-merged) PR #4226 branch + run"
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " Historical check of the original community fix proposal. The"
	@echo " vulnerability was fixed upstream by maintainer PR #5033 (default-on,"
	@echo " PyPI 2026.10.10+); use 'make demo-fixed-release' for the shipped fix."
	@echo " PR #4226 was closed unmerged 2026-10-28; its branch ref may still install."
	@echo ""
	MCP_FETCH_SPEC="mcp-server-fetch @ git+https://github.com/modelcontextprotocol/servers.git@refs/pull/4226/head#subdirectory=src/fetch" \
	MCP_FETCH_VERSION="PR#4226-branch" \
	docker compose up --build --abort-on-container-exit --exit-code-from attacker

clean:
	docker compose down -v --rmi local 2>/dev/null || true
	@echo "Cleaned up containers + images."
