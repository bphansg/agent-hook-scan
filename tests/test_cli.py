"""Test CLI functionality."""

import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from agent_hook_scan.__main__ import main


class TestCLI(unittest.TestCase):
    """Test CLI interface."""

    def setUp(self):
        """Set up test fixtures path."""
        self.testdata = Path(__file__).parent.parent / "testdata"

    def test_cli_help(self):
        """Test --help flag."""
        with patch.object(sys, "argv", ["agent-hook-scan", "--help"]):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)

    def test_cli_version(self):
        """Test --version flag."""
        with patch.object(sys, "argv", ["agent-hook-scan", "--version"]):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)

    def test_cli_clean_repo(self):
        """Test scanning clean repo."""
        with patch.object(sys, "argv", ["agent-hook-scan", str(self.testdata / "clean_repo")]):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                exit_code = main()
                output = fake_out.getvalue()
        
        self.assertEqual(exit_code, 0)
        self.assertIn("No issues found", output)

    def test_cli_risky_repo(self):
        """Test scanning risky repo."""
        with patch.object(sys, "argv", ["agent-hook-scan", str(self.testdata / "risky_mcp")]):
            with patch("sys.stdout", new=StringIO()) as fake_out:
                exit_code = main()
                output = fake_out.getvalue()
        
        self.assertEqual(exit_code, 0)
        self.assertIn("issue(s)", output)

    def test_cli_fail_on_high(self):
        """Test --fail-on high with high severity findings."""
        with patch.object(sys, "argv", [
            "agent-hook-scan",
            str(self.testdata / "risky_mcp"),
            "--fail-on", "high"
        ]):
            with patch("sys.stdout", new=StringIO()):
                exit_code = main()
        
        self.assertEqual(exit_code, 1, "Should fail on high severity findings")

    def test_cli_fail_on_no_findings(self):
        """Test --fail-on with clean repo."""
        with patch.object(sys, "argv", [
            "agent-hook-scan",
            str(self.testdata / "clean_repo"),
            "--fail-on", "high"
        ]):
            with patch("sys.stdout", new=StringIO()):
                exit_code = main()
        
        self.assertEqual(exit_code, 0, "Should not fail on clean repo")

    def test_cli_invalid_path(self):
        """Test CLI with invalid path."""
        with patch.object(sys, "argv", ["agent-hook-scan", "/nonexistent/path"]):
            with patch("sys.stderr", new=StringIO()):
                exit_code = main()
        
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
