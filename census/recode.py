#!/usr/bin/env python3
"""hooks-census-recode-2026-08-16

Separate recoder. NOT agent-hook-scan and NOT the GitHub Action.
v0.1.0 does not produce this 3-way split.

A reader can recode by applying classify_command() to every JSON string
whose key is command, cmd, script, or run.
"""
from __future__ import annotations

import json
import re
from typing import Iterable, List

RECODER_ID = "hooks-census-recode-2026-08-16"

REMOTE_FETCH = re.compile(r"\\b(curl|wget)\\b", re.I)
PIPE_TO_SHELL = re.compile(
    r"\\|\\s*(sudo\\s+)?(sh|bash|zsh|dash)(\\s|$)", re.I
)
CURL_PIPE_SH = re.compile(
    r"\\b(curl|wget)\\b[\\s\\S]{0,200}\\|\\s*(sudo\\s+)?(sh|bash|zsh|dash)\\b",
    re.I,
)
ECHO_OUTER = re.compile(r"^\\s*(echo|printf)\\b", re.I)
SHELL_INVOKE = re.compile(
    r"(?:^|[;&\\n]|\\|\\||&&)\\s*(sudo\\s+)?(sh|bash|zsh|dash)\\b",
    re.I,
)
LOCAL_PATH = re.compile(
    r"""(\\.sh\\b|\\$HOME|\\$\\{HOME\\}|~/|\\./|\\.cursor/)""",
    re.I,
)

PRECEDENCE = {
    "execute-remote": 3,
    "echo-the-install-warning": 2,
    "local-sh": 1,
    "none": 0,
}


def extract_commands(obj) -> List[str]:
    acc: List[str] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("command", "cmd", "script", "run") and isinstance(v, str):
                    acc.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for x in node:
                walk(x)

    walk(obj)
    return acc


def classify_command(cmd: str) -> str:
    s = cmd.strip()
    if not s:
        return "none"

    has_pipe = bool(CURL_PIPE_SH.search(s) or (REMOTE_FETCH.search(s) and PIPE_TO_SHELL.search(s)))
    if has_pipe:
        if ECHO_OUTER.match(s):
            return "echo-the-install-warning"
        return "execute-remote"

    if REMOTE_FETCH.search(s):
        return "none"
    if SHELL_INVOKE.search(s) and LOCAL_PATH.search(s):
        return "local-sh"
    if LOCAL_PATH.search(s) and re.search(r"\\.sh\\b", s) and not has_pipe:
        return "local-sh"
    return "none"


def classify_file(commands: Iterable[str]) -> str:
    best = "none"
    for c in commands:
        k = classify_command(c)
        if PRECEDENCE[k] > PRECEDENCE[best]:
            best = k
    return best


def classify_json_text(text: str) -> tuple[str, int, str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "none", 0, "parse-error"
    cmds = extract_commands(data)
    return classify_file(cmds), len(cmds), "ok"
