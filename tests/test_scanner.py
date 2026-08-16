"""Test the core scanner functionality."""

import unittest
from pathlib import Path

from agent_hook_scan import scan_directory
from agent_hook_scan.findings import Severity


class TestScanner(unittest.TestCase):
    """Test scanner detection rules."""

    def setUp(self):
        """Set up test fixtures path."""
        self.testdata = Path(__file__).parent.parent / "testdata"
        self.assertTrue(self.testdata.exists(), "testdata directory not found")

    def test_clean_repo_no_findings(self):
        """Test that clean repo produces no findings."""
        findings = scan_directory(self.testdata / "clean_repo")
        self.assertEqual(len(findings), 0, "Clean repo should have no findings")

    def test_risky_mcp_shell_command(self):
        """Test detection of shell command in MCP config."""
        findings = scan_directory(self.testdata / "risky_mcp")
        
        # Should detect bash -c usage
        shell_findings = [f for f in findings if f.rule_id == "mcp-shell-command"]
        self.assertGreater(len(shell_findings), 0, "Should detect shell command execution")
        self.assertEqual(shell_findings[0].severity, Severity.HIGH)

    def test_risky_mcp_secrets(self):
        """Test detection of secrets in MCP env vars."""
        findings = scan_directory(self.testdata / "risky_mcp")
        
        # Should detect API key in env
        secret_findings = [f for f in findings if f.rule_id == "mcp-env-secret"]
        self.assertGreater(len(secret_findings), 0, "Should detect secrets in MCP env vars")
        self.assertEqual(secret_findings[0].severity, Severity.HIGH)

    def test_risky_mcp_curl_pipe_sh(self):
        """Test detection of curl | sh in MCP config."""
        findings = scan_directory(self.testdata / "risky_mcp")
        
        # Should detect curl | sh pattern
        curl_findings = [f for f in findings if f.rule_id == "mcp-curl-pipe-sh"]
        self.assertGreater(len(curl_findings), 0, "Should detect curl | sh pattern")

    def test_risky_mcp_unpinned_npx(self):
        """Test detection of unpinned npx packages."""
        findings = scan_directory(self.testdata / "risky_mcp")
        
        # Should detect unpinned npx
        npx_findings = [f for f in findings if f.rule_id == "mcp-unpinned-npx"]
        self.assertGreater(len(npx_findings), 0, "Should detect unpinned npx packages")
        self.assertEqual(npx_findings[0].severity, Severity.MEDIUM)

    def test_risky_npm_postinstall(self):
        """Test detection of curl | sh in npm lifecycle hooks."""
        findings = scan_directory(self.testdata / "risky_npm")
        
        # Should detect postinstall curl | sh
        npm_findings = [f for f in findings if f.rule_id == "npm-curl-pipe-sh"]
        self.assertGreater(len(npm_findings), 0, "Should detect npm curl | sh")
        self.assertEqual(npm_findings[0].severity, Severity.HIGH)

    def test_risky_npm_wget(self):
        """Test detection of wget in npm lifecycle hooks."""
        findings = scan_directory(self.testdata / "risky_npm")
        
        # Should detect wget usage
        wget_findings = [f for f in findings if f.rule_id == "npm-wget-exec"]
        self.assertGreater(len(wget_findings), 0, "Should detect npm wget")

    def test_risky_vscode_auto_task(self):
        """Test detection of auto-run VS Code tasks."""
        findings = scan_directory(self.testdata / "risky_vscode")
        
        # Should detect folderOpen task
        task_findings = [f for f in findings if f.rule_id == "vscode-auto-task"]
        self.assertGreater(len(task_findings), 0, "Should detect auto-run tasks")
        self.assertEqual(task_findings[0].severity, Severity.HIGH)

    def test_risky_github_actions(self):
        """Test detection of risky GitHub Actions patterns."""
        findings = scan_directory(self.testdata / "risky_github")
        
        # Should detect curl | bash
        curl_findings = [f for f in findings if f.rule_id == "gha-curl-pipe-bash"]
        self.assertGreater(len(curl_findings), 0, "Should detect GHA curl | bash")
        
        # Should detect unpinned actions
        unpinned_findings = [f for f in findings if f.rule_id == "gha-unpinned-action"]
        self.assertGreater(len(unpinned_findings), 0, "Should detect unpinned actions")

    def test_risky_cursor_rules_secret_ref(self):
        """Test detection of secret references in Cursor rules."""
        findings = scan_directory(self.testdata / "risky_cursor_rules")
        
        # Should detect .env reference in rules
        rule_findings = [f for f in findings if f.rule_id == "agent-rule-secret-ref"]
        self.assertGreater(len(rule_findings), 0, "Should detect secret references in rules")

    def test_risky_secrets_in_markdown(self):
        """Test detection of embedded secrets in AGENTS.md."""
        findings = scan_directory(self.testdata / "risky_secrets")
        
        # Should detect secret patterns
        secret_findings = [f for f in findings if "secret" in f.rule_id.lower()]
        self.assertGreater(len(secret_findings), 0, "Should detect secrets in markdown")


class TestFindingStructure(unittest.TestCase):
    """Test finding data structures."""

    def test_finding_to_dict(self):
        """Test Finding.to_dict() conversion."""
        from agent_hook_scan.findings import Finding
        
        finding = Finding(
            severity=Severity.HIGH,
            rule_id="test-rule",
            title="Test Finding",
            file_path="test.json",
            line=42,
            description="Test description",
            remediation="Fix it"
        )
        
        d = finding.to_dict()
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["rule_id"], "test-rule")
        self.assertEqual(d["title"], "Test Finding")
        self.assertEqual(d["file_path"], "test.json")
        self.assertEqual(d["line"], 42)

    def test_severity_from_string(self):
        """Test Severity.from_string() parsing."""
        self.assertEqual(Severity.from_string("high"), Severity.HIGH)
        self.assertEqual(Severity.from_string("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.from_string("medium"), Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
