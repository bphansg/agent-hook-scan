"""
agent-hook-scan: Scan AI agent configs for risky hooks and over-broad tools.

A focused linter for Cursor, Claude, and MCP configuration files.
NOT a security product, CVE scanner, or semgrep replacement.

Copyright 2026 Binh Phan
Licensed under Apache-2.0
Built with AI assistance (MoneyMaker) for Binh Phan
"""

__version__ = "0.1.0"

from .scanner import scan_directory
from .findings import Finding, Severity

__all__ = ["scan_directory", "Finding", "Severity"]
