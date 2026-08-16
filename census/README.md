# Census recoder

**Recoder ID:** `hooks-census-recode-2026-08-16`

This recoder is **not** `agent-hook-scan` and **not** the GitHub Action.
v0.1.0 does **not** produce this 3-way split.

Functions: `extract_commands`, `classify_command`, `classify_file`, `classify_json_text`.

Classes, most severe first: `execute-remote`, `echo-the-install-warning`, `local-sh`, `none`.

Rules live in `classify_command` in `recode.py`. This README does not include command strings.

Apache-2.0. Copyright 2026 Binh Phan.
