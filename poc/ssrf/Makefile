.PHONY: demo demo-quick demo-full demo-fixed clean help

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
	@echo "  make demo-fixed   Same shape as demo-full but installs from the"
	@echo "                    PR #4226 branch directly. No fixed PyPI release"
	@echo "                    exists yet (PR is open + unmerged as of"
	@echo "                    2026-06-20). Expected outcome: FIX VERIFIED."
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

demo-fixed:
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " demo-fixed — install from PR #4226 branch + run against IMDS"
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " No fixed PyPI release exists yet; PR #4226 is open + unmerged."
	@echo " Verified 2026-06-20: latest PyPI v2026.6.4 still vulnerable."
	@echo " Installing from the PR branch directly via pip git URL."
	@echo ""
	MCP_FETCH_SPEC="mcp-server-fetch @ git+https://github.com/modelcontextprotocol/servers.git@refs/pull/4226/head#subdirectory=src/fetch" \
	MCP_FETCH_VERSION="PR#4226-branch" \
	docker compose up --build --abort-on-container-exit --exit-code-from attacker

clean:
	docker compose down -v --rmi local 2>/dev/null || true
	@echo "Cleaned up containers + images."
