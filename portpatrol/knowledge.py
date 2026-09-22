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


def parse_port_spec(spec, top_ports):
    """Parse a port specification into a sorted, deduplicated port list.

    Accepts: "top50", "top100", "top1000" (well-known range 1-1023 plus the
    top-100 list), "all" (1-65535), and explicit specs like "80,443" or
    "8000-8100". Raises ValueError on anything invalid.
    """
    spec = spec.strip().lower()
    if spec == "all":
        return list(range(1, 65536))
    if spec in ("top50", "top100"):
        return list(top_ports[: 50 if spec == "top50" else 100])
    if spec == "top1000":
        return sorted(set(range(1, 1024)) | set(top_ports[:100]))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"invalid port spec: {spec!r}")
        if "-" in part:
            lo, _, hi = part.partition("-")
            lo, hi = int(lo), int(hi)
            if not (1 <= lo <= hi <= 65535):
                raise ValueError(f"invalid port range: {part!r}")
            ports.update(range(lo, hi + 1))
        else:
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"invalid port: {part!r}")
            ports.add(port)
    return sorted(ports)


def classify_port(kb, port, service=None):
    """Return the risk level for a port.

    A port entry wins, then a banner-derived service match, else "unknown".
    """
    entry = kb.get(port)
    if entry is not None:
        return entry["risk"]
    if service:
        matched = service_index(kb).get(service)
        if matched is not None:
            return matched["risk"]
    return "unknown"


_LOOPBACK_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "info"}


def adjust_risk_for_exposure(risk, exposure):
    """One-level downgrade for loopback-only listeners; interface/unknown unchanged."""
    if exposure == "loopback":
        return _LOOPBACK_DOWNGRADE.get(risk, risk)
    return risk
