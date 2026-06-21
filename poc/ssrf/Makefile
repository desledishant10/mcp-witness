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
	@echo "  make demo-fixed   Same as demo-full but against a post-PR-#4226"
	@echo "                    release. Set MCP_FETCH_VERSION first, e.g."
	@echo "                    MCP_FETCH_VERSION=2026.5.30 make demo-fixed"
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
	@if [ -z "$$MCP_FETCH_VERSION" ]; then \
		echo "set MCP_FETCH_VERSION to a post-PR-#4226 release first."; \
		echo "  e.g.  MCP_FETCH_VERSION=2026.5.30 make demo-fixed"; \
		exit 2; \
	fi
	docker compose up --build --abort-on-container-exit --exit-code-from attacker

clean:
	docker compose down -v --rmi local 2>/dev/null || true
	@echo "Cleaned up containers + images."
