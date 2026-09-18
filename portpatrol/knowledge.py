"""Knowledge base loading and port classification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from portpatrol.defaults import DEFAULT_ENTRIES

PACKAGE_KB = Path(__file__).resolve().parent / "knowledge_base.json"


def _load_json_entries(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    return [e for e in data if isinstance(e, dict) and isinstance(e.get("port"), int)]


def load_knowledge_base(user_path=None):
    """Resolve the knowledge base: user override, home file, package file, defaults.

    Prints a warning on stderr when falling back to defaults.
    Returns {port: entry}.
    """
    candidates = []
    if user_path is not None:
        candidates.append(Path(user_path))
    candidates.append(Path.home() / ".portpatrol" / "knowledge_base.json")
    candidates.append(PACKAGE_KB)
    for path in candidates:
        entries = _load_json_entries(path)
        if entries:
            return {e["port"]: e for e in entries}
    print("portpatrol: knowledge base not found or invalid; using built-in defaults", file=sys.stderr)
    return {e["port"]: e for e in DEFAULT_ENTRIES}


def get_entry(kb, port):
    """Return the knowledge base entry for a port, or None."""
    return kb.get(port)


def service_index(kb):
    """Map service name to entry for banner-derived classification."""
    return {e["service"]: e for e in kb.values() if e.get("service")}
