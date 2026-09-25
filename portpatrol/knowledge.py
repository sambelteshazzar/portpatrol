"""Knowledge base loading and port classification."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from portpatrol.defaults import DEFAULT_ENTRIES
from portpatrol.notifier import RISK_ORDER

PACKAGE_KB = Path(__file__).resolve().parent / "knowledge_base.json"

VALID_RISKS = frozenset(RISK_ORDER)

RISK_REPAIRED_KEY = "_risk_repaired"


def _usable_risk(entry):
    """Return the entry's risk, or None when the risk was repaired on load.

    A risk that _normalize_risk had to downgrade to "unknown" carries no
    estimate, so it must not stand in as a port or service rule. An entry that
    genuinely rates a port "unknown" is still a valid rule.
    """
    risk = entry.get("risk")
    if risk not in VALID_RISKS or entry.get(RISK_REPAIRED_KEY):
        return None
    return risk


def _normalize_risk(entry, path):
    """Return entry with a guaranteed-valid risk, warning on stderr when fixed.

    A risk that had to be repaired is marked so classification can tell a
    downgraded entry apart from one that legitimately rates the port unknown.
    """
    if "risk" not in entry:
        print(f"portpatrol: {path}: missing 'risk' for port {entry['port']}; using 'unknown'",
              file=sys.stderr)
        entry["risk"] = "unknown"
        entry[RISK_REPAIRED_KEY] = True
    elif entry["risk"] not in VALID_RISKS:
        print(f"portpatrol: {path}: invalid risk {entry['risk']!r} for port {entry['port']}; "
              f"using 'unknown'", file=sys.stderr)
        entry["risk"] = "unknown"
        entry[RISK_REPAIRED_KEY] = True
    return entry


def _load_json_entries(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    entries = [e for e in data if isinstance(e, dict) and isinstance(e.get("port"), int)]
    return [_normalize_risk(e, path) for e in entries]


def load_knowledge_base_with_source(user_path=None):
    """Resolve the knowledge base and report which file supplied it.

    Resolution order is an explicit user path, the home file, the package
    file, then the built-in defaults. Returns ({port: entry}, metadata) where
    metadata is {"source", "path", "entries", "repaired"}.
    """
    candidates = []
    if user_path is not None:
        candidates.append((Path(user_path), "user"))
    candidates.append((Path.home() / ".portpatrol" / "knowledge_base.json", "user"))
    candidates.append((PACKAGE_KB, "package"))
    for path, source in candidates:
        entries = _load_json_entries(path)
        if entries:
            return ({e["port"]: e for e in entries}, {
                "source": source,
                "path": str(path),
                "entries": len(entries),
                "repaired": sum(1 for e in entries if e.get(RISK_REPAIRED_KEY)),
            })
    print("portpatrol: knowledge base not found or invalid; using built-in defaults", file=sys.stderr)
    return ({e["port"]: e for e in DEFAULT_ENTRIES}, {
        "source": "defaults",
        "path": None,
        "entries": len(DEFAULT_ENTRIES),
        "repaired": 0,
    })


def load_knowledge_base(user_path=None):
    """Return the knowledge base entries as {port: entry}."""
    entries, _ = load_knowledge_base_with_source(user_path)
    return entries


def get_entry(kb, port):
    """Return the knowledge base entry for a port, or None."""
    return kb.get(port)


def service_index(kb):
    """Map service name to entry for banner-derived classification."""
    return {e["service"]: e for e in kb.values()
            if e.get("service") and _usable_risk(e) is not None}


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


def classify_port_with_source(kb, port, service=None, svc_index=None):
    """Return the risk, source, and confidence for a port."""
    entry = kb.get(port)
    if entry is not None:
        risk = _usable_risk(entry)
        if risk is not None:
            return risk, "port_rule", "high"
    if service:
        index = service_index(kb) if svc_index is None else svc_index
        matched = index.get(service)
        if matched is not None:
            risk = _usable_risk(matched)
            if risk is not None:
                return risk, "service_rule", "high"
    return "unknown", "fallback", "low"


def classify_port(kb, port, service=None, svc_index=None):
    """Return the risk level for a port.

    A port entry wins, then a banner-derived service match, else "unknown".
    Risk values outside the five known levels, and entries whose risk was
    repaired on load, do not stand in as rules. Pass a prebuilt
    service_index(kb) in svc_index to avoid rebuilding it per call.
    """
    return classify_port_with_source(kb, port, service, svc_index)[0]


_LOOPBACK_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "info"}


def adjust_risk_for_exposure(risk, exposure):
    """One-level downgrade for loopback-only listeners; interface/unknown unchanged."""
    if exposure == "loopback":
        return _LOOPBACK_DOWNGRADE.get(risk, risk)
    return risk
