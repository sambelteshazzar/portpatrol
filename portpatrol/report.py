"""Console table, JSON output, and scan history persistence."""

from __future__ import annotations

import json
from pathlib import Path

from portpatrol.notifier import EMOJI, RISK_ORDER


def console_table(findings):
    """Render findings as a risk-sorted console table with emoji per row."""
    if not findings:
        return "✅ No open ports found."
    ordered = sorted(findings, key=lambda f: RISK_ORDER.index(f["risk"]))
    lines = [f"{'PORT':>6}  {'RISK':<8} {'EXPOSURE':<9} {'SERVICE':<16} "
             f"{'VERSION':<14} {'PROCESS':<14} CVES"]
    for f in ordered:
        cves = ", ".join(f.get("cves", []))
        exposure = f.get("exposure") or "-"
        process = f.get("process") or "-"
        lines.append(
            f"{f['port']:>6}  {EMOJI[f['risk']]} {f['risk']:<7} "
            f"{exposure:<9} {f.get('service') or 'unknown':<16} "
            f"{(f.get('version') or '-'):<14} {process:<14} {cves}"
        )
    return "\n".join(lines)


def to_json(result):
    return json.dumps(result, indent=2)


def append_history(result, history_path):
    """Append a result record to the history file, creating parents on demand."""
    history_path = Path(history_path)
    history_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        history = json.loads(history_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        history = []
    if not isinstance(history, list):
        history = []
    history.append(result)
    history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
