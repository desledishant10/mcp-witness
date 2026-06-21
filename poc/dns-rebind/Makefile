.PHONY: demo demo-quick demo-full demo-rce clean help

help:
	@echo "DNS-rebind PoC harness — targets:"
	@echo ""
	@echo "  make demo-quick   Fast Python-only probe demonstrating the vuln shape."
	@echo "                    No Docker required. ~5 seconds."
	@echo ""
	@echo "  make demo-full    Full containerized attack: DNS server + attacker"
	@echo "                    + victim + Playwright browser. Requires Docker."
	@echo "                    ~60 seconds including first-run image builds."
	@echo "                    Wrapped MCP is mcp-server-time (benign)."
	@echo ""
	@echo "  make demo-rce     ESCALATION DEMO — same stack but the wrapped MCP"
	@echo "                    is mcp-server-shell. Playwright drives a tools/call"
	@echo "                    execute_command post-rebind and asserts on an"
	@echo "                    RCE-PROOF marker. All shell execution is confined"
	@echo "                    to the throwaway victim container. Educational only —"
	@echo "                    do NOT run against any real proxy deployment."
	@echo ""
	@echo "  make demo         Runs demo-quick, then demo-full. (Does NOT run demo-rce.)"
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
	@echo " demo-full — full containerized DNS rebind (benign wrapped MCP)"
	@echo "═════════════════════════════════════════════════════════════════"
	docker compose up --build --abort-on-container-exit --exit-code-from playwright

demo-rce:
	@echo "═════════════════════════════════════════════════════════════════"
	@echo " demo-rce — ESCALATION DEMO (mcp-server-shell wrapped)"
	@echo ""
	@echo " Drives tools/call execute_command post-rebind to prove universal"
	@echo " escalation. Shell runs inside the throwaway victim container;"
	@echo " host is NOT exposed. Educational use only."
	@echo "═════════════════════════════════════════════════════════════════"
	docker compose -f docker-compose.yml -f compose.escalation.yml up \
	    --build --abort-on-container-exit --exit-code-from playwright

clean:
	docker compose -f docker-compose.yml -f compose.escalation.yml down -v --rmi local 2>/dev/null || true
	docker compose down -v --rmi local 2>/dev/null || true
	@echo "Cleaned up containers + images."
