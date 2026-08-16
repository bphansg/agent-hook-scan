.PHONY: check test clean install help

PYTHON := $(shell command -v python3 2>/dev/null || command -v python 2>/dev/null)

help:
	@echo "agent-hook-scan Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make check    - Run tests"
	@echo "  make test     - Run tests (alias for check)"
	@echo "  make clean    - Remove temporary files"
	@echo "  make install  - Install in development mode"

check: test

test:
	@if command -v pytest >/dev/null 2>&1; then \
		$(PYTHON) -m pytest tests/ -v; \
	else \
		$(PYTHON) -m unittest discover tests/ -v; \
	fi

clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.sarif' -delete

install:
	$(PYTHON) -m pip install -e .
