"""Test output formatters."""

import json
import unittest
from pathlib import Path

from agent_hook_scan.findings import Finding, Severity
from agent_hook_scan.formatters import format_markdown, format_sarif


class TestFormatters(unittest.TestCase):
    """Test output formatting."""

    def test_markdown_no_findings(self):
        """Test markdown output with no findings."""
        output = format_markdown([], Path("/test"))
        self.assertIn("No issues found", output)

    def test_markdown_with_findings(self):
        """Test markdown output with findings."""
        findings = [
            Finding(
                severity=Severity.HIGH,
                rule_id="test-1",
                title="Test Issue 1",
                file_path="file1.json",
                description="Test description",
                remediation="Fix it"
            ),
            Finding(
                severity=Severity.MEDIUM,
                rule_id="test-2",
                title="Test Issue 2",
                file_path="file2.json",
            )
        ]
        
        output = format_markdown(findings, Path("/test"))
        self.assertIn("Test Issue 1", output)
        self.assertIn("Test Issue 2", output)
        self.assertIn("HIGH", output)
        self.assertIn("MEDIUM", output)
        self.assertIn("test-1", output)
        self.assertIn("Fix it", output)

    def test_sarif_structure(self):
        """Test SARIF output structure."""
        findings = [
            Finding(
                severity=Severity.HIGH,
                rule_id="test-rule",
                title="Test Issue",
                file_path="test.json",
                line=10,
                description="Test description",
                remediation="Fix it"
            )
        ]
        
        output = format_sarif(findings, Path("/test"))
        sarif = json.loads(output)
        
        # Check SARIF structure
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(len(sarif["runs"]), 1)
        
        run = sarif["runs"][0]
        self.assertIn("tool", run)
        self.assertEqual(run["tool"]["driver"]["name"], "agent-hook-scan")
        
        # Check results
        self.assertEqual(len(run["results"]), 1)
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "test-rule")
        self.assertEqual(result["level"], "error")
        
        # Check location
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "test.json")
        self.assertEqual(location["region"]["startLine"], 10)

    def test_sarif_severity_mapping(self):
        """Test severity to SARIF level mapping."""
        findings = [
            Finding(Severity.HIGH, "r1", "T1", "f1"),
            Finding(Severity.MEDIUM, "r2", "T2", "f2"),
            Finding(Severity.LOW, "r3", "T3", "f3"),
            Finding(Severity.INFO, "r4", "T4", "f4"),
        ]
        
        output = format_sarif(findings, Path("/test"))
        sarif = json.loads(output)
        
        results = sarif["runs"][0]["results"]
        self.assertEqual(results[0]["level"], "error")    # HIGH
        self.assertEqual(results[1]["level"], "warning")  # MEDIUM
        self.assertEqual(results[2]["level"], "note")     # LOW
        self.assertEqual(results[3]["level"], "note")     # INFO


if __name__ == "__main__":
    unittest.main()
