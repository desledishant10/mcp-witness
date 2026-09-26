# mcp-witness detections: validate the defender signatures.
#
#   make validate           offline: rules vs. fixtures vs. ground truth + suricata lint
#   make test               the pytest suite for this module
#   make validate-live      run the real PoC probes and match their output
#   make validate-suricata  load the Suricata rules in the engine (needs suricata)
#   make lint-suricata      structural lint of the Suricata rules only

PY ?= python
REPO_ROOT := $(shell cd ../ && pwd)

.PHONY: help validate test validate-live validate-suricata lint-suricata

help:
	@grep -E '^#   make' Makefile | sed 's/^#   /  /'

validate:
	cd $(REPO_ROOT) && $(PY) -m detections.validate

test:
	cd $(REPO_ROOT) && $(PY) -m pytest detections/tests -q

validate-live:
	cd $(REPO_ROOT) && $(PY) -m detections.validate_live

lint-suricata:
	cd $(REPO_ROOT) && $(PY) -m detections.validate --lint-suricata

validate-suricata:
	@if command -v suricata >/dev/null 2>&1; then \
		suricata -T -S suricata/mcp-witness.rules -l /tmp 2>&1 | tail -5 ; \
	else \
		echo "suricata not installed; 'make lint-suricata' runs the structural check without it." ; \
	fi
