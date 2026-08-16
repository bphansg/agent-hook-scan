"""Census recoder for Cursor hooks.json command strings.

Recoder ID: hooks-census-recode-2026-08-16
Version: Published classifier for public use

This recoder is NOT agent-hook-scan and NOT the GitHub Action.
It provides a reference implementation for classifying command strings
from Cursor hooks.json files without requiring exploit writeups.

Copyright 2026 Binh Phan
Licensed under the Apache License, Version 2.0
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Union


# Classification precedence (most severe to least severe)
PRECEDENCE = ["execute-remote", "echo-the-install-warning", "local-sh", "none"]


def extract_commands(data: Any) -> List[str]:
    """Extract command strings from JSON data.
    
    Walks the JSON structure and collects string values whose key is
    one of: command, cmd, script, or run.
    
    Args:
        data: Parsed JSON data (dict, list, or primitive)
        
    Returns:
        List of command strings found in the data
    """
    commands = []
    
    def walk(obj: Any, parent_key: str = ""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in ("command", "cmd", "script", "run"):
                    if isinstance(value, str):
                        commands.append(value)
                walk(value, key)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, parent_key)
    
    walk(data)
    return commands


def classify_command(cmd: str) -> str:
    """Classify a single command string.
    
    Classification rules (in precedence order):
    1. execute-remote: curl/wget piped to sh/bash/zsh/dash (optional sudo)
    2. echo-the-install-warning: echo/printf where recipe is only printed
    3. local-sh: shell interpreter runs local path, or command is .sh path,
       including `|| sh "$HOME/..."`, with no remote fetch
    4. none: everything else
    
    Args:
        cmd: Command string to classify
        
    Returns:
        One of: "execute-remote", "echo-the-install-warning", "local-sh", "none"
    """
    if not cmd or not isinstance(cmd, str):
        return "none"
    
    # Normalize whitespace for pattern matching
    normalized = " ".join(cmd.split())
    
    # 2. echo-the-install-warning: echo/printf that only prints a recipe
    # Check this FIRST before execute-remote to avoid false positives
    # Matches commands that start with echo or printf and contain shell/pipe references
    # but don't actually execute them
    echo_pattern = r'^(echo|printf)\b'
    if re.match(echo_pattern, normalized.strip(), re.IGNORECASE):
        # Check if it's printing a recipe (contains pipe or shell indicators in quotes/as text)
        # and not actually executing anything
        if '|' in cmd or 'sh' in cmd.lower() or 'curl' in cmd.lower() or 'wget' in cmd.lower():
            return "echo-the-install-warning"
    
    # 1. execute-remote: remote fetch piped to shell
    # Matches: curl ... | sh, wget ... | bash, sudo curl ... | zsh, etc.
    remote_pipe_pattern = r'(sudo\s+)?(curl|wget)\b[^|]*\|\s*(sh|bash|zsh|dash)\b'
    if re.search(remote_pipe_pattern, normalized, re.IGNORECASE):
        return "execute-remote"
    
    # 3. local-sh: shell interpreter runs a local path
    # Matches:
    # - sh /path/to/script.sh
    # - bash "$HOME/script.sh"
    # - zsh ~/.config/setup.sh
    # - || sh "$HOME/..."
    # - ./script.sh or /path/to/script.sh
    # Must NOT contain remote fetch in the same string
    
    # First check for remote fetches - if present, it's not local-sh
    if re.search(r'\b(curl|wget)\b', normalized, re.IGNORECASE):
        return "none"
    
    # Pattern 1: shell interpreter with local path
    # sh /path, bash $HOME, zsh ~/, dash ./
    shell_local_pattern = r'\b(sh|bash|zsh|dash)\s+["\']?[~$/.]'
    if re.search(shell_local_pattern, normalized, re.IGNORECASE):
        return "local-sh"
    
    # Pattern 2: || sh "$HOME/..." or similar fallback patterns
    fallback_pattern = r'\|\|\s*(sh|bash|zsh|dash)\s+["\']?[~$/.]'
    if re.search(fallback_pattern, normalized, re.IGNORECASE):
        return "local-sh"
    
    # Pattern 3: command is itself a .sh path (starts with ./, /, ~/, or $)
    sh_file_pattern = r'^[~$/.].*\.sh\b'
    if re.search(sh_file_pattern, normalized.strip(), re.IGNORECASE):
        return "local-sh"
    
    # 4. none: everything else
    return "none"


def classify_file(filepath: Union[str, Path]) -> str:
    """Classify all commands in a JSON file and return the most severe class.
    
    Extracts all commands from the file, classifies each one, and returns
    the most severe classification according to precedence:
    execute-remote > echo-the-install-warning > local-sh > none
    
    Args:
        filepath: Path to JSON file (typically hooks.json)
        
    Returns:
        Most severe classification: "execute-remote", "echo-the-install-warning",
        "local-sh", or "none"
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
    """
    path = Path(filepath)
    
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    commands = extract_commands(data)
    
    if not commands:
        return "none"
    
    # Classify all commands
    classifications = [classify_command(cmd) for cmd in commands]
    
    # Return the most severe classification
    for severity in PRECEDENCE:
        if severity in classifications:
            return severity
    
    return "none"


def main():
    """Example usage of the census recoder."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m census.recode <path-to-hooks.json>")
        print("\nClassifies commands in a Cursor hooks.json file.")
        print("\nOutput classes (most to least severe):")
        print("  - execute-remote: curl/wget piped to shell")
        print("  - echo-the-install-warning: echo/printf printing a recipe")
        print("  - local-sh: shell interpreter with local script")
        print("  - none: no risky patterns detected")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    try:
        result = classify_file(filepath)
        print(f"Classification: {result}")
        
        # Also show individual commands
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        commands = extract_commands(data)
        
        if commands:
            print(f"\nFound {len(commands)} command(s):")
            for i, cmd in enumerate(commands, 1):
                classification = classify_command(cmd)
                print(f"  {i}. [{classification}] {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
    
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
