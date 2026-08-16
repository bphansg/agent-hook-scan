"""Core scanning logic for agent configuration files."""

import json
import re
from pathlib import Path
from typing import List

from .findings import Finding, Severity


class AgentConfigScanner:
    """Scanner for AI agent configuration files."""

    def __init__(self, root_path: Path):
        self.root = root_path.resolve()
        self.findings: List[Finding] = []

    def scan(self) -> List[Finding]:
        """Run all scans and return findings."""
        self.findings = []
        
        self._scan_cursor_configs()
        self._scan_claude_configs()
        self._scan_mcp_configs()
        self._scan_vscode_tasks()
        self._scan_package_json()
        self._scan_github_actions()
        self._scan_env_files()
        
        return self.findings

    def _scan_cursor_configs(self):
        """Scan Cursor-specific configuration files."""
        patterns = [
            ".cursor/mcp.json",
            "mcp.json",
            ".cursor/hooks.json",
            ".cursor/hooks.jsonc",
        ]
        
        for pattern in patterns:
            path = self.root / pattern
            if path.exists():
                self._check_json_file(path)
        
        # Scan .cursor/rules directory
        rules_dir = self.root / ".cursor" / "rules"
        if rules_dir.exists() and rules_dir.is_dir():
            for rule_file in rules_dir.rglob("*"):
                if rule_file.is_file():
                    self._check_agent_rule_file(rule_file)
        
        # Scan .cursor/skills directory
        skills_dir = self.root / ".cursor" / "skills"
        if skills_dir.exists() and skills_dir.is_dir():
            for skill_file in skills_dir.rglob("*"):
                if skill_file.is_file():
                    self._check_agent_rule_file(skill_file)
        
        # Check AGENTS.md
        agents_md = self.root / "AGENTS.md"
        if agents_md.exists():
            self._check_markdown_file(agents_md)

    def _scan_claude_configs(self):
        """Scan Claude-specific configuration files."""
        claude_dir = self.root / ".claude"
        if claude_dir.exists() and claude_dir.is_dir():
            for config_file in claude_dir.rglob("*"):
                if config_file.is_file():
                    self._check_json_file(config_file)
        
        claude_md = self.root / "CLAUDE.md"
        if claude_md.exists():
            self._check_markdown_file(claude_md)

    def _scan_mcp_configs(self):
        """Scan MCP server configurations."""
        mcp_paths = [
            self.root / ".cursor" / "mcp.json",
            self.root / "mcp.json",
        ]
        
        for path in mcp_paths:
            if path.exists():
                self._check_mcp_servers(path)

    def _scan_vscode_tasks(self):
        """Scan VS Code tasks.json for risky tasks."""
        tasks_path = self.root / ".vscode" / "tasks.json"
        if tasks_path.exists():
            self._check_vscode_tasks(tasks_path)

    def _scan_package_json(self):
        """Scan package.json for risky lifecycle scripts."""
        pkg_path = self.root / "package.json"
        if pkg_path.exists():
            self._check_package_json(pkg_path)

    def _scan_github_actions(self):
        """Scan GitHub Actions workflows."""
        workflows_dir = self.root / ".github" / "workflows"
        if workflows_dir.exists() and workflows_dir.is_dir():
            for workflow in workflows_dir.glob("*.yml"):
                self._check_github_workflow(workflow)
            for workflow in workflows_dir.glob("*.yaml"):
                self._check_github_workflow(workflow)

    def _scan_env_files(self):
        """Scan for .env files referenced by agent configs."""
        env_patterns = [".env", ".env.local", ".env.development", ".env.production"]
        
        for pattern in env_patterns:
            env_path = self.root / pattern
            if env_path.exists():
                self._check_env_file(env_path)

    def _check_json_file(self, path: Path):
        """Basic check for JSON config files."""
        try:
            content = path.read_text()
            data = json.loads(content)
            
            # Check for embedded secrets patterns
            if self._contains_secret_patterns(content):
                self.findings.append(Finding(
                    severity=Severity.HIGH,
                    rule_id="secret-in-config",
                    title="Potential secret in configuration file",
                    file_path=str(path.relative_to(self.root)),
                    description="Configuration file may contain embedded secrets or API keys",
                    remediation="Use environment variables instead of hardcoding secrets"
                ))
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    def _check_mcp_servers(self, path: Path):
        """Check MCP server configurations for risky patterns."""
        try:
            content = path.read_text()
            data = json.loads(content)
            
            servers = data.get("mcpServers", {})
            for server_name, config in servers.items():
                command = config.get("command", "")
                args = config.get("args", [])
                env = config.get("env", {})
                
                # Check for risky shell commands
                args_str = " ".join(str(a) for a in args)
                
                # Check for bash/sh with -c flag (arbitrary command execution)
                if command.lower() in ["bash", "sh", "zsh"]:
                    if "-c" in args or "bash -c" in command or "sh -c" in command:
                        self.findings.append(Finding(
                            severity=Severity.HIGH,
                            rule_id="mcp-shell-command",
                            title=f"MCP server '{server_name}' uses shell command execution",
                            file_path=str(path.relative_to(self.root)),
                            description="MCP server executes arbitrary shell commands",
                            remediation="Review the command and ensure it doesn't execute untrusted input"
                        ))
                
                # Check for curl | sh pattern (either in command or args)
                full_command = f"{command} {args_str}"
                if re.search(r'(curl|wget).*\|.*(sh|bash)', full_command, re.IGNORECASE):
                    self.findings.append(Finding(
                        severity=Severity.HIGH,
                        rule_id="mcp-curl-pipe-sh",
                        title=f"MCP server '{server_name}' uses curl | sh pattern",
                        file_path=str(path.relative_to(self.root)),
                        description="Downloading and executing remote scripts is dangerous",
                        remediation="Download scripts, review them, and execute separately"
                    ))
                
                # Check for npx with unpinned packages
                if "npx" in command:
                    if "@" not in args_str:
                        self.findings.append(Finding(
                            severity=Severity.MEDIUM,
                            rule_id="mcp-unpinned-npx",
                            title=f"MCP server '{server_name}' uses unpinned npx package",
                            file_path=str(path.relative_to(self.root)),
                            description="npx without version pins can execute different code on each run",
                            remediation="Pin package versions with @version syntax"
                        ))
                
                # Check for secrets in env vars
                for key, value in env.items():
                    if self._looks_like_secret(key, str(value)):
                        self.findings.append(Finding(
                            severity=Severity.HIGH,
                            rule_id="mcp-env-secret",
                            title=f"MCP server '{server_name}' may expose secrets",
                            file_path=str(path.relative_to(self.root)),
                            description=f"Environment variable '{key}' appears to contain a secret",
                            remediation="Use environment variable references instead of hardcoded values"
                        ))
                
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    def _check_vscode_tasks(self, path: Path):
        """Check VS Code tasks for auto-run commands."""
        try:
            content = path.read_text()
            data = json.loads(content)
            
            tasks = data.get("tasks", [])
            for task in tasks:
                run_options = task.get("runOptions", {})
                if run_options.get("runOn") == "folderOpen":
                    command = task.get("command", "")
                    self.findings.append(Finding(
                        severity=Severity.HIGH,
                        rule_id="vscode-auto-task",
                        title="VS Code task runs automatically on folder open",
                        file_path=str(path.relative_to(self.root)),
                        description=f"Task '{task.get('label', 'unknown')}' executes on folder open",
                        remediation="Remove runOn: folderOpen or ensure the command is safe"
                    ))
                
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    def _check_package_json(self, path: Path):
        """Check package.json for risky lifecycle scripts."""
        try:
            content = path.read_text()
            data = json.loads(content)
            
            scripts = data.get("scripts", {})
            risky_hooks = ["preinstall", "postinstall", "prepare"]
            
            for hook in risky_hooks:
                if hook in scripts:
                    script = scripts[hook]
                    
                    # Check for curl | sh pattern
                    if re.search(r'curl.*\|.*sh', script, re.IGNORECASE):
                        self.findings.append(Finding(
                            severity=Severity.HIGH,
                            rule_id="npm-curl-pipe-sh",
                            title=f"package.json {hook} script uses curl | sh",
                            file_path=str(path.relative_to(self.root)),
                            description="Lifecycle hook downloads and executes remote scripts",
                            remediation="Remove curl | sh pattern from lifecycle scripts"
                        ))
                    
                    # Check for wget pattern
                    if re.search(r'wget.*&&', script, re.IGNORECASE):
                        self.findings.append(Finding(
                            severity=Severity.HIGH,
                            rule_id="npm-wget-exec",
                            title=f"package.json {hook} script uses wget with execution",
                            file_path=str(path.relative_to(self.root)),
                            description="Lifecycle hook downloads and may execute files",
                            remediation="Review and pin downloaded resources"
                        ))
                    
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    def _check_github_workflow(self, path: Path):
        """Check GitHub Actions workflow for risky patterns."""
        try:
            content = path.read_text()
            
            # Check for curl | bash in run steps
            if re.search(r'curl.*\|.*bash', content, re.IGNORECASE):
                self.findings.append(Finding(
                    severity=Severity.HIGH,
                    rule_id="gha-curl-pipe-bash",
                    title="GitHub Action uses curl | bash pattern",
                    file_path=str(path.relative_to(self.root)),
                    description="Workflow downloads and executes remote scripts",
                    remediation="Download scripts to a file, review, and execute separately"
                ))
            
            # Check for unpinned actions (uses: without @sha256 or @v1.2.3)
            unpinned = re.findall(r'uses:\s*([^@\n]+)@([^#\n]+)', content)
            for action, ref in unpinned:
                if not re.match(r'v?\d+\.\d+\.\d+|[a-f0-9]{40}', ref):
                    self.findings.append(Finding(
                        severity=Severity.MEDIUM,
                        rule_id="gha-unpinned-action",
                        title="GitHub Action uses unpinned or mutable reference",
                        file_path=str(path.relative_to(self.root)),
                        description=f"Action '{action}' uses ref '{ref}' which may change",
                        remediation="Pin actions to specific SHAs or semantic versions"
                    ))
            
        except UnicodeDecodeError:
            pass

    def _check_agent_rule_file(self, path: Path):
        """Check agent rule/skill files for secret references."""
        try:
            content = path.read_text()
            
            # Check if file references .env or secret files
            if re.search(r'\.env|secret|credential|password|token', content, re.IGNORECASE):
                self.findings.append(Finding(
                    severity=Severity.MEDIUM,
                    rule_id="agent-rule-secret-ref",
                    title="Agent rule/skill references potential secrets",
                    file_path=str(path.relative_to(self.root)),
                    description="Rule or skill file may reference secret files or credentials",
                    remediation="Ensure secrets are not accessible to agent hooks"
                ))
            
        except UnicodeDecodeError:
            pass

    def _check_markdown_file(self, path: Path):
        """Check markdown config files for embedded secrets."""
        try:
            content = path.read_text()
            
            if self._contains_secret_patterns(content):
                self.findings.append(Finding(
                    severity=Severity.MEDIUM,
                    rule_id="md-secret-pattern",
                    title="Markdown file may contain secret patterns",
                    file_path=str(path.relative_to(self.root)),
                    description="Agent configuration markdown contains potential secrets",
                    remediation="Use environment variable references instead"
                ))
            
        except UnicodeDecodeError:
            pass

    def _check_env_file(self, path: Path):
        """Check if .env files are referenced by agent configs."""
        # Look for references in agent config files
        config_files = [
            self.root / ".cursor" / "mcp.json",
            self.root / "mcp.json",
            self.root / "AGENTS.md",
            self.root / "CLAUDE.md",
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    content = config_file.read_text()
                    if path.name in content:
                        self.findings.append(Finding(
                            severity=Severity.HIGH,
                            rule_id="env-file-agent-accessible",
                            title=f"Secret file {path.name} referenced in agent config",
                            file_path=str(path.relative_to(self.root)),
                            description=f"Agent configuration references {path.name}",
                            remediation="Ensure agent hooks cannot access secret files"
                        ))
                        break
                except UnicodeDecodeError:
                    pass

    def _contains_secret_patterns(self, content: str) -> bool:
        """Check if content contains patterns that look like secrets."""
        patterns = [
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            r'["\']?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{20,}["\']',
            r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'sk-[a-zA-Z0-9]{40,}',  # OpenAI-style keys
            r'xoxb-[0-9]{10,}',  # Slack tokens
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)

    def _looks_like_secret(self, key: str, value: str) -> bool:
        """Check if a key-value pair looks like a secret."""
        secret_keys = [
            "api_key", "apikey", "token", "password", "secret",
            "auth", "credential", "private_key", "access_key"
        ]
        
        if any(sk in key.lower() for sk in secret_keys):
            if len(value) > 10 and value not in ["${", "${"]:
                return not value.startswith("$")  # Not an env var reference
        
        return False


def scan_directory(path: Path) -> List[Finding]:
    """Scan a directory for risky agent configurations."""
    scanner = AgentConfigScanner(path)
    return scanner.scan()
