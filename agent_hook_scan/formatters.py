"""Output formatters for scan findings."""

import json
from pathlib import Path
from typing import List

from .findings import Finding, Severity


def format_markdown(findings: List[Finding], scanned_path: Path) -> str:
    """Format findings as markdown."""
    if not findings:
        return f"# agent-hook-scan\n\nNo issues found in `{scanned_path}`.\n"
    
    lines = [
        "# agent-hook-scan",
        "",
        f"Scanned: `{scanned_path}`",
        f"Found: **{len(findings)}** issue(s)",
        "",
    ]
    
    # Group by severity
    by_severity = {s: [] for s in Severity}
    for finding in findings:
        by_severity[finding.severity].append(finding)
    
    for severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        items = by_severity[severity]
        if not items:
            continue
        
        lines.append(f"## {severity.value.upper()} ({len(items)})")
        lines.append("")
        
        for finding in items:
            lines.append(f"### {finding.title}")
            lines.append("")
            lines.append(f"- **File**: `{finding.file_path}`")
            if finding.line:
                lines.append(f"- **Line**: {finding.line}")
            lines.append(f"- **Rule**: `{finding.rule_id}`")
            if finding.description:
                lines.append(f"- **Description**: {finding.description}")
            if finding.remediation:
                lines.append(f"- **Remediation**: {finding.remediation}")
            lines.append("")
    
    return "\n".join(lines)


def format_sarif(findings: List[Finding], scanned_path: Path) -> str:
    """Format findings as SARIF JSON."""
    rules = {}
    results = []
    
    for finding in findings:
        # Register rule
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {
                    "text": finding.title
                },
                "fullDescription": {
                    "text": finding.description or finding.title
                },
                "help": {
                    "text": finding.remediation or "Review and remediate the issue"
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(finding.severity)
                }
            }
        
        # Add result
        result = {
            "ruleId": finding.rule_id,
            "level": _severity_to_sarif_level(finding.severity),
            "message": {
                "text": finding.description or finding.title
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path
                    }
                }
            }]
        }
        
        if finding.line:
            result["locations"][0]["physicalLocation"]["region"] = {
                "startLine": finding.line
            }
        
        results.append(result)
    
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agent-hook-scan",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/bphansg/agent-hook-scan",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }]
    }
    
    return json.dumps(sarif, indent=2)


def _severity_to_sarif_level(severity: Severity) -> str:
    """Convert Severity to SARIF level."""
    mapping = {
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note"
    }
    return mapping[severity]
