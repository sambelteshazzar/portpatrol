"""Stateful scan diffing: last-scan snapshot, allowlist, change computation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

_SLIM_KEYS = ("port", "service", "version", "risk")


def load_state(path):
    """Return the persisted last-scan state, or None when missing or invalid."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("open"), list):
        return None
    return data


def save_state(path, findings):
    """Persist a slim snapshot of the current findings (port/service/version/risk only)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "version": 1,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "open": [{k: f.get(k) for k in _SLIM_KEYS} for f in findings],
    }
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def load_allowlist(path):
    """Return the set of expected port numbers. Missing or invalid file yields set()."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if not isinstance(data, list):
        return set()
    return {int(p) for p in data if isinstance(p, int) and 1 <= p <= 65535}


def compute_changes(prev, curr, allowlist):
    """Diff two finding lists: new (minus allowlist), removed, changed service/version."""
    prev_by_port = {f["port"]: f for f in prev}
    curr_by_port = {f["port"]: f for f in curr}
    new = [f for p, f in curr_by_port.items()
           if p not in prev_by_port and p not in allowlist]
    removed = [f for p, f in prev_by_port.items() if p not in curr_by_port]
    changed = []
    for port in sorted(set(prev_by_port) & set(curr_by_port)):
        before, after = prev_by_port[port], curr_by_port[port]
        if (before.get("service"), before.get("version")) != (after.get("service"), after.get("version")):
            changed.append({
                "port": port,
                "from": {"service": before.get("service"), "version": before.get("version")},
                "to": {"service": after.get("service"), "version": after.get("version")},
            })
    return {"new": new, "removed": removed, "changed": changed}


def has_changes(changes):
    """True when any category holds an entry."""
    return bool(changes["new"] or changes["removed"] or changes["changed"])


def changes_message(changes):
    """One-line toast text for a diff. 🆕-led, 🚨 when any new port is critical."""
    parts = []
    if changes["new"]:
        labels = ", ".join(f"{f['port']} ({f['risk']})" for f in changes["new"])
        parts.append(f"{len(changes['new'])} new: {labels}")
    if changes["removed"]:
        labels = ", ".join(str(f["port"]) for f in changes["removed"])
        parts.append(f"{len(changes['removed'])} removed: {labels}")
    if changes["changed"]:
        labels = ", ".join(str(c["port"]) for c in changes["changed"])
        parts.append(f"{len(changes['changed'])} changed: {labels}")
    if not parts:
        return "✅ PortPatrol: no changes since last scan"
    lead = "🚨" if any(f.get("risk") == "critical" for f in changes["new"]) else "🆕"
    return f"{lead} PortPatrol changes — " + "; ".join(parts)
