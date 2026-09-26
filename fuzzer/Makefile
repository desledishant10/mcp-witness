# mcp-witness fuzzer.
#
#   make demo   fuzz an in-process vulnerable server and print the findings
#   make test   the pytest suite for this module

PY ?= python
REPO_ROOT := $(shell cd ../ && pwd)

.PHONY: help demo test

help:
	@grep -E '^#   make' Makefile | sed 's/^#   /  /'

demo:
	cd $(REPO_ROOT) && $(PY) -m fuzzer.demo

test:
	cd $(REPO_ROOT) && $(PY) -m pytest fuzzer/tests -q
