.PHONY: demo demo-quick demo-full clean help

help:
	@echo "DNS-rebind PoC harness — targets:"
	@echo ""
	@echo "  make demo-quick   Fast Python-only probe demonstrating the vuln shape."
	@echo "                    No Docker required. ~5 seconds."
	@echo ""
	@echo "  make demo-full    Full containerized attack: DNS server + attacker"
	@echo "                    + victim + Playwright browser. Requires Docker."
	@echo "                    ~60 seconds including first-run image builds."
	@echo ""
	@echo "  make demo         Runs demo-quick, then demo-full."
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
	@echo " demo-full — full containerized DNS rebind"
	@echo "═════════════════════════════════════════════════════════════════"
	docker compose up --build --abort-on-container-exit --exit-code-from playwright

clean:
	docker compose down -v --rmi local 2>/dev/null || true
	@echo "Cleaned up containers + images."
