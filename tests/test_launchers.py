import os
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DESKTOP_FILE = REPO_ROOT / "examples" / "desktop" / "portpatrol.desktop"
WRAPPER = REPO_ROOT / "portpatrol-desktop.sh"

# Characters the freedesktop desktop entry spec treats as reserved in Exec
# when they appear outside double quotes.
RESERVED = set(' \t\n"\\\'$&<>()~|;?*#`')


def desktop_key(key):
    for line in DESKTOP_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    return None


def test_desktop_file_exists():
    assert DESKTOP_FILE.is_file()


def test_desktop_file_required_keys():
    assert desktop_key("Type") == "Application"
    assert desktop_key("Terminal") == "true"
    assert desktop_key("Icon") == "utilities-system-monitor"
    assert desktop_key("Name") == "PortPatrol"
    categories = desktop_key("Categories") or ""
    assert "System" in categories


def test_desktop_exec_target_is_safe():
    exec_value = desktop_key("Exec")
    assert exec_value, "desktop file must have an Exec line"
    match = re.match(r'^"([^"]+)"|^(\S+)', exec_value)
    assert match, "Exec must start with a quoted or bare command"
    token = match.group(1) or match.group(2)
    assert not any(ch in RESERVED for ch in token), (
        "Exec command token contains an unquoted reserved character: " + token
    )
    if "/" in token:
        assert token.startswith("/"), "Exec path with a slash must be absolute"


def test_wrapper_exists_and_is_executable():
    assert WRAPPER.is_file()
    assert os.access(WRAPPER, os.X_OK), "wrapper must be executable"


def test_wrapper_content():
    text = WRAPPER.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    assert "portpatrol scan" in text
    assert "Press Enter" in text
    assert re.search(r"\bread\b", text), "wrapper must wait for Enter"
    assert re.search(r"exit\s+\$?\{?status\}?", text), (
        "wrapper must exit with the scan status"
    )
