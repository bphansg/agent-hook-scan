# agent-hook-scan

**A focused linter for AI agent configuration files.**

Scan Cursor, Claude, and MCP agent configs for risky hooks, over-broad tools, and embedded secrets.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## ⚡ 60-Second Quickstart

```bash
# Clone and enter
git clone https://github.com/bphansg/agent-hook-scan.git
cd agent-hook-scan

# Run on current directory
python -m agent_hook_scan

# Or scan a specific path
python -m agent_hook_scan /path/to/your/repo

# Output SARIF for GitHub/GitLab integration
python -m agent_hook_scan --sarif findings.sarif

# Fail CI builds on high-severity findings
python -m agent_hook_scan --fail-on high
```

**No dependencies beyond Python 3.11+ stdlib.** Just clone and run.

---

## What It Is

`agent-hook-scan` detects risky patterns in AI agent configuration files:

- **Cursor**: `.cursor/mcp.json`, `.cursor/hooks.json`, `.cursor/rules/**`, `AGENTS.md`, `.cursor/skills/**`
- **Claude**: `.claude/**`, `CLAUDE.md`, Claude MCP configs
- **MCP Servers**: Shell command execution (`bash -c`, unpinned `npx`, `curl | sh`), secrets in env vars
- **VS Code Tasks**: Auto-run tasks (`runOn: folderOpen`)
- **npm Lifecycle**: `postinstall` / `prepare` scripts with `curl | sh` or `wget` patterns
- **GitHub Actions**: Unpinned actions, `curl | bash` in workflows
- **Secret Leakage**: `.env` files referenced by agent configs, embedded API keys

---

## What It Is NOT

- ❌ Not a security product or CVE scanner
- ❌ Not a replacement for semgrep, Snyk, or dependency scanners
- ❌ Does not scan application code, only agent config files
- ❌ No telemetry, analytics, or phone-home

This is a **config linter** for AI agent setups, not a comprehensive security tool.

---

## Example Output

### Markdown (default)

```markdown
# agent-hook-scan

Scanned: `/path/to/repo`
Found: **3** issue(s)

## HIGH (2)

### MCP server 'shell-exec' uses shell command execution

- **File**: `.cursor/mcp.json`
- **Rule**: `mcp-shell-command`
- **Description**: MCP server executes arbitrary shell commands
- **Remediation**: Review the command and ensure it doesn't execute untrusted input

### package.json postinstall script uses curl | sh

- **File**: `package.json`
- **Rule**: `npm-curl-pipe-sh`
- **Description**: Lifecycle hook downloads and executes remote scripts
- **Remediation**: Remove curl | sh pattern from lifecycle scripts

## MEDIUM (1)

### MCP server 'unpinned' uses unpinned npx package

- **File**: `.cursor/mcp.json`
- **Rule**: `mcp-unpinned-npx`
- **Description**: npx without version pins can execute different code on each run
- **Remediation**: Pin package versions with @version syntax
```

### SARIF (for CI/CD)

```bash
python -m agent_hook_scan --sarif findings.sarif
# Integrates with GitHub Security tab, GitLab Security Dashboard
```

---

## Detection Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `mcp-shell-command` | HIGH | MCP server uses `bash -c` or `sh -c` |
| `mcp-curl-pipe-sh` | HIGH | MCP server args contain `curl \| sh` pattern |
| `mcp-env-secret` | HIGH | MCP env vars may contain hardcoded secrets |
| `mcp-unpinned-npx` | MEDIUM | MCP uses `npx` without `@version` pin |
| `npm-curl-pipe-sh` | HIGH | npm lifecycle script uses `curl \| sh` |
| `npm-wget-exec` | HIGH | npm lifecycle script uses `wget` with execution |
| `vscode-auto-task` | HIGH | VS Code task runs on `folderOpen` |
| `gha-curl-pipe-bash` | HIGH | GitHub Action uses `curl \| bash` |
| `gha-unpinned-action` | MEDIUM | GitHub Action uses mutable reference (e.g., `@main`) |
| `agent-rule-secret-ref` | MEDIUM | Cursor rule/skill references `.env` or credentials |
| `env-file-agent-accessible` | HIGH | `.env` file referenced in agent config |
| `secret-in-config` | HIGH | Config file contains potential secrets (regex-based) |
| `md-secret-pattern` | MEDIUM | Markdown config has embedded secret patterns |

---

## CLI Options

```
usage: agent-hook-scan [-h] [--sarif FILE] [--fail-on {high,medium,low,info}] [--version] [path]

Scan AI agent configs for risky hooks and over-broad tools

positional arguments:
  path                  Directory to scan (default: current directory)

options:
  -h, --help            show this help message and exit
  --sarif FILE          Output SARIF JSON to FILE
  --fail-on {high,medium,low,info}
                        Exit with code 1 if any findings at or above this severity
  --version             show program's version number and exit
```

---

## Installation

### As a Tool (recommended)

```bash
git clone https://github.com/bphansg/agent-hook-scan.git
cd agent-hook-scan
python -m agent_hook_scan /your/repo
```

### As a Package

```bash
pip install git+https://github.com/bphansg/agent-hook-scan.git
agent-hook-scan /your/repo
```

### Development

```bash
git clone https://github.com/bphansg/agent-hook-scan.git
cd agent-hook-scan
make install  # or: pip install -e .
make check    # Run tests
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Agent Config Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run agent-hook-scan
        run: |
          git clone https://github.com/bphansg/agent-hook-scan.git /tmp/scanner
          python -m agent_hook_scan --sarif findings.sarif --fail-on high
        working-directory: /tmp/scanner
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
```

### GitLab CI

```yaml
agent-scan:
  image: python:3.11
  script:
    - git clone https://github.com/bphansg/agent-hook-scan.git /tmp/scanner
    - cd /tmp/scanner && python -m agent_hook_scan $CI_PROJECT_DIR --sarif findings.sarif --fail-on high
  artifacts:
    reports:
      sast: findings.sarif
```

---

## Testing

```bash
# Run all tests
make check

# Or directly with pytest
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_scanner.py::TestScanner::test_risky_mcp_shell_command -v
```

---

## Contributing

This is an early v0 release. Contributions welcome:

1. **Bug reports**: Open an issue with reproduction steps
2. **New rules**: Add detection logic + test fixtures
3. **False positives**: Report with the config that triggered it

**Note**: This tool was built with AI assistance (MoneyMaker agent) for Binh Phan. All contributions must be original work, Apache-2.0 compatible, and not copied from proprietary repos.

---

## FAQ

**Q: Why not just use semgrep/Snyk/CodeQL?**  
A: Those are broad SAST tools. This is laser-focused on AI agent config files (MCP, Cursor, Claude). Different problem space.

**Q: Does it phone home or send telemetry?**  
A: No. Zero network activity. It's a local scanner using only Python stdlib.

**Q: Can I use this in production?**  
A: It's v0. Use as a linter/CI check, but don't rely on it as your only security control.

**Q: How do I add a new rule?**  
A: Edit `agent_hook_scan/scanner.py`, add detection logic, update `findings.py` if needed, add test fixtures in `testdata/`, write tests in `tests/`.

**Q: Python 3.11+ only?**  
A: Yes. Uses modern stdlib features. If you need 3.9/3.10, feel free to fork and backport.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for full text.

Copyright 2026 Binh Phan.

**Disclosure**: This tool was built with AI assistance by the MoneyMaker agent operating on behalf of Binh Phan.

---

## Acknowledgments

Built with:
- Python 3.11+ standard library
- MoneyMaker AI agent (Cursor Cloud Agent)
- Community feedback (coming soon!)

---

**Not affiliated with Cursor, Anthropic, or any AI agent vendor.**
