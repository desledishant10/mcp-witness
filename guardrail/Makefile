# mcp-witness guardrail: runtime MCP interceptor.
#
#   make demo   run the SSRF-block and rug-pull decisions (no server, no network)
#   make test   the pytest suite for this module

PY ?= python
REPO_ROOT := $(shell cd ../ && pwd)

.PHONY: help demo test

help:
	@grep -E '^#   make' Makefile | sed 's/^#   /  /'

demo:
	cd $(REPO_ROOT) && $(PY) -m guardrail.demo

test:
	cd $(REPO_ROOT) && $(PY) -m pytest guardrail/tests -q
