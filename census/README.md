# Census Recoder

**Recoder ID:** `hooks-census-recode-2026-08-16`

This recoder provides a public reference implementation for classifying Cursor `hooks.json` command strings. It is intended for researchers and developers who want to analyze hook patterns without requiring exploit writeups.

## Important Notes

- **This recoder is NOT `agent-hook-scan`** (the scanner in the parent directory)
- **This recoder is NOT the GitHub Action** (see `action.yml`)
- **v0.1.0 does NOT produce this 3-way split** — this is a separate classifier

This is a standalone tool for census and research purposes only.

## Functions

### `extract_commands(data)`

Walks JSON data and collects string values whose key is one of:
- `command`
- `cmd`
- `script`
- `run`

**Args:** Parsed JSON data (dict, list, or primitive)  
**Returns:** List of command strings

### `classify_command(cmd)`

Classifies a single command string into one of four classes.

**Args:** Command string  
**Returns:** Classification string (see below)

### `classify_file(filepath)`

Extracts all commands from a JSON file and returns the most severe classification.

**Args:** Path to JSON file  
**Returns:** Most severe classification found in the file

## Classification Classes

Commands are classified into one of four classes, in precedence order (most to least severe):

### 1. `execute-remote`

The executed command has a remote fetch (`curl` or `wget`) piped to a shell interpreter (`sh`, `bash`, `zsh`, or `dash`). Optional `sudo` is supported.

**Examples:**
- `curl http://example.com/install.sh | sh`
- `sudo wget -O- https://example.com/setup | bash`

### 2. `echo-the-install-warning`

The outer command is `echo` or `printf` AND the recipe is only printed (not executed).

**Examples:**
- `echo "Run: curl http://example.com | sh"`
- `printf "Install with: wget -O- https://example.com | bash\n"`

### 3. `local-sh`

A shell interpreter runs a local path, or the command is itself a `.sh` path. Includes patterns like `|| sh "$HOME/..."`. Must have **no remote fetch** in the same string.

**Examples:**
- `sh /usr/local/bin/setup.sh`
- `bash "$HOME/.config/install.sh"`
- `./scripts/setup.sh`
- `command || sh "$HOME/fallback.sh"`

### 4. `none`

Everything else that doesn't match the above patterns.

## Precedence

When multiple classes are present in a file, the most severe class is returned:

```
execute-remote > echo-the-install-warning > local-sh > none
```

## Usage

### As a Python Module

```python
from census.recode import classify_command, classify_file, extract_commands

# Classify a single command
result = classify_command("curl http://example.com/install.sh | sh")
print(result)  # "execute-remote"

# Classify all commands in a file
result = classify_file(".cursor/hooks.json")
print(result)  # Most severe class found

# Extract commands from JSON data
import json
with open(".cursor/hooks.json") as f:
    data = json.load(f)
commands = extract_commands(data)
```

### Command Line

```bash
python -m census.recode /path/to/hooks.json
```

This will output the overall classification and show individual command classifications.

## License

Apache License 2.0 — Copyright 2026 Binh Phan

See the `LICENSE` file in the repository root.
