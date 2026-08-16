"""CLI entry point for agent-hook-scan."""

import argparse
import sys
from pathlib import Path

from . import scan_directory
from .findings import Severity
from .formatters import format_markdown, format_sarif


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="agent-hook-scan",
        description="Scan AI agent configs for risky hooks and over-broad tools",
        epilog="Built with AI assistance (MoneyMaker) for Binh Phan. Apache-2.0."
    )
    
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory to scan (default: current directory)"
    )
    
    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Output SARIF JSON to FILE"
    )
    
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "info"],
        help="Exit with code 1 if any findings at or above this severity"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="agent-hook-scan 0.1.0"
    )
    
    args = parser.parse_args()
    
    # Resolve path
    scan_path = Path(args.path).resolve()
    if not scan_path.exists():
        print(f"Error: Path does not exist: {scan_path}", file=sys.stderr)
        return 1
    
    if not scan_path.is_dir():
        print(f"Error: Path is not a directory: {scan_path}", file=sys.stderr)
        return 1
    
    # Scan
    findings = scan_directory(scan_path)
    
    # Output markdown to stdout
    markdown = format_markdown(findings, scan_path)
    print(markdown)
    
    # Output SARIF if requested
    if args.sarif:
        sarif = format_sarif(findings, scan_path)
        sarif_path = Path(args.sarif)
        sarif_path.write_text(sarif)
        print(f"\nSARIF written to: {sarif_path}", file=sys.stderr)
    
    # Check fail threshold
    if args.fail_on and findings:
        threshold = Severity.from_string(args.fail_on)
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        threshold_idx = severity_order.index(threshold)
        
        for finding in findings:
            finding_idx = severity_order.index(finding.severity)
            if finding_idx >= threshold_idx:
                print(f"\nFailing due to {finding.severity.value} finding (threshold: {args.fail_on})", file=sys.stderr)
                return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
