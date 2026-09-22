# PortPatrol Stateful Diff (`--diff`) Implementation Plan

> **For agentic workers:** Implement one task at a time, in order, with TDD (write the failing test, watch it fail, implement, watch it pass, commit). Steps use checkbox (`- [ ]`) syntax for tracking. Run tests from the repo root: `python3 -m pytest tests/ -v`.

**Goal:** Make scheduled PortPatrol runs alert only when open ports change — new, removed, or re-identified — instead of toasting the same summary daily.

**Architecture:** A new `portpatrol/diff.py` module persists a slim snapshot of the last scan to `~/.portpatrol/state.json` and computes `{new, removed, changed}` against it, with an optional `~/.portpatrol/allowlist.json` suppressing expected ports from `new`. `cli.py` gains a `--diff` flag: first run establishes the baseline; later runs skip the summary toast entirely when nothing changed and otherwise toast a change message (🚨-led when any new port is critical, with the existing per-critical detail toasts for new criticals only). Exit codes stay findings-based (`0/1/2`); the shipped systemd user unit uses `SuccessExitStatus=1`.

**Tech Stack:** Python 3.8+ stdlib only (json, pathlib, argparse), pytest for tests, systemd user timer for scheduling.

## Global Constraints

- Python 3.8+ standard library only. Zero pip dependencies.
- Platforms: any Linux distribution; Windows 10/11.
- Target: `127.0.0.1` only. No other hosts.
- Connect scans only. Timeouts: 0.5s sweep, 1.0s probes. One probe per open port per scan.
- No telemetry. Network egress only the user-triggered `--kev` fetch from cisa.gov.
- Exit codes: 0 clean, 1 findings, 2 error. `--diff` does not change exit semantics.
- Data dir `~/.portpatrol/` (`history.json`, `kev.json`, `state.json`, `allowlist.json`, optional `knowledge_base.json` override).
- Emoji map: 🚨 critical, ⚠️ high, 🟡 medium, 🔵 info, ❓ unknown, ✅ all clear; `--diff` adds 🆕 as the change-message lead (🚨 replaces it when a new port is critical).
- Defensive only: no exploitation, no credential attempts, no packet crafting.

---

### Task 1: Diff engine (state, allowlist, change computation)

**Files:**
- Create: `portpatrol/diff.py`
- Test: `tests/test_diff.py`

**Interfaces:**
- Consumes: finding dicts shaped `{"port": int, "service": str, "version": str | None, "risk": str, ...}` (produced by `cmd_scan`).
- Produces: `load_state(path) -> dict | None`, `save_state(path, findings) -> None`, `load_allowlist(path) -> set[int]`, `compute_changes(prev: list[dict], curr: list[dict], allowlist: set[int]) -> dict` with shape `{"new": list[dict], "removed": list[dict], "changed": list[dict]}` (changed items are `{"port": int, "from": {"service", "version"}, "to": {"service", "version"}}`), `has_changes(changes) -> bool`, `changes_message(changes) -> str`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_diff.py
from portpatrol import diff


def _finding(port, service="ssh", version=None, risk="info"):
    return {"port": port, "service": service, "version": version, "risk": risk}


def test_load_state_missing_returns_none(tmp_path):
    assert diff.load_state(tmp_path / "state.json") is None


def test_load_state_invalid_returns_none(tmp_path):
    p = tmp_path / "state.json"
    p.write_text("{not json", encoding="utf-8")
    assert diff.load_state(p) is None


def test_save_load_roundtrip(tmp_path):
    p = tmp_path / "state.json"
    diff.save_state(p, [_finding(22)])
    state = diff.load_state(p)
    assert state["open"] == [{"port": 22, "service": "ssh", "version": None, "risk": "info"}]
    assert state["version"] == 1


def test_save_state_slims_extra_keys(tmp_path):
    p = tmp_path / "state.json"
    diff.save_state(p, [{"port": 443, "service": "https", "version": "1.2", "risk": "info",
                         "cves": ["CVE-1"], "product": "nginx"}])
    stored = diff.load_state(p)["open"][0]
    assert set(stored) == {"port", "service", "version", "risk"}


def test_load_allowlist_missing_returns_empty_set(tmp_path):
    assert diff.load_allowlist(tmp_path / "allowlist.json") == set()


def test_load_allowlist_parses_int_list(tmp_path):
    p = tmp_path / "allowlist.json"
    p.write_text("[22, 631]", encoding="utf-8")
    assert diff.load_allowlist(p) == {22, 631}


def test_compute_changes_identical_is_empty():
    curr = [_finding(22)]
    changes = diff.compute_changes([_finding(22)], curr, set())
    assert changes == {"new": [], "removed": [], "changed": []}


def test_compute_changes_detects_new_port():
    changes = diff.compute_changes([], [_finding(8080, service="http-proxy", risk="medium")], set())
    assert [f["port"] for f in changes["new"]] == [8080]
    assert changes["new"][0]["risk"] == "medium"


def test_compute_changes_allowlist_suppresses_new():
    changes = diff.compute_changes([], [_finding(631)], {631})
    assert changes["new"] == []


def test_compute_changes_detects_removed_port():
    changes = diff.compute_changes([_finding(22), _finding(80)], [_finding(22)], set())
    assert [f["port"] for f in changes["removed"]] == [80]


def test_compute_changes_detects_service_or_version_change():
    prev = [_finding(22, service="ssh", version="OpenSSH_8.9")]
    curr = [_finding(22, service="ssh", version="OpenSSH_9.6")]
    changes = diff.compute_changes(prev, curr, set())
    assert changes["changed"] == [
        {"port": 22,
         "from": {"service": "ssh", "version": "OpenSSH_8.9"},
         "to": {"service": "ssh", "version": "OpenSSH_9.6"}}
    ]


def test_compute_changes_allowlist_does_not_hide_removals():
    changes = diff.compute_changes([_finding(631)], [], {631})
    assert [f["port"] for f in changes["removed"]] == [631]


def test_has_changes():
    empty = {"new": [], "removed": [], "changed": []}
    assert diff.has_changes(empty) is False
    assert diff.has_changes({"new": [_finding(80)], "removed": [], "changed": []}) is True


def test_changes_message_lists_new_with_risk():
    msg = diff.changes_message({"new": [_finding(8080, risk="medium")],
                                "removed": [], "changed": []})
    assert msg.startswith("🆕")
    assert "8080" in msg
    assert "medium" in msg


def test_changes_message_critical_new_leads_with_siren():
    msg = diff.changes_message({"new": [_finding(6379, service="redis", risk="critical")],
                                "removed": [], "changed": []})
    assert msg.startswith("🚨")


def test_changes_message_includes_removed_and_changed():
    msg = diff.changes_message({"new": [],
                                "removed": [_finding(80)],
                                "changed": [{"port": 22,
                                             "from": {"service": "ssh", "version": "8.9"},
                                             "to": {"service": "ssh", "version": "9.6"}}]})
    assert "1 removed" in msg
    assert "80" in msg
    assert "1 changed" in msg
    assert "22" in msg


def test_changes_message_empty_is_all_clear():
    msg = diff.changes_message({"new": [], "removed": [], "changed": []})
    assert msg.startswith("✅")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_diff.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'portpatrol.diff'` (collection error)

- [ ] **Step 3: Implement the diff engine**

```python
# portpatrol/diff.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_diff.py -v`
Expected: PASS (all 17 tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/diff.py tests/test_diff.py
git commit -m "feat: stateful scan diff engine with allowlist"
```

---

### Task 2: `--diff` CLI integration

**Files:**
- Modify: `portpatrol/cli.py` (import, paths, flag, diff block, notify logic)
- Test: `tests/test_cli.py` (append tests)

**Interfaces:**
- Consumes: `load_state`, `save_state`, `load_allowlist`, `compute_changes`, `has_changes`, `changes_message` from Task 1; `HISTORY_PATH` pattern already in `cli.py`.
- Produces: module-level `STATE_PATH = Path.home() / ".portpatrol" / "state.json"`, `ALLOWLIST_PATH = Path.home() / ".portpatrol" / "allowlist.json"` (both monkeypatchable); `scan --diff` flag; result dict gains `"changes"` and `"baseline"` keys when `--diff` is set.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
def test_diff_flag_exists():
    args = cli.build_parser().parse_args(["scan", "--diff"])
    assert args.diff is True
    args = cli.build_parser().parse_args(["scan"])
    assert args.diff is False


def _patch_scan(monkeypatch, tmp_path, open_ports, identify_service="ssh"):
    monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
    monkeypatch.setattr(cli, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr("portpatrol.scanner.sweep", lambda ports, **kw: open_ports)
    monkeypatch.setattr("portpatrol.scanner.identify",
                        lambda p, e, i, **kw: {"port": p, "service": identify_service,
                                               "version": None})
    monkeypatch.setattr("portpatrol.scanner.enrich_with_nmap", lambda ports, **kw: {})


def test_diff_first_run_establishes_baseline(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [])
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    assert cli.main(["scan", "--diff", "--ports", "80"]) == 0
    assert len(calls) == 1
    assert "all clear" in calls[0][1]
    assert (tmp_path / "state.json").exists()


def test_diff_unchanged_second_run_is_silent(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [22])
    import json as _json
    (tmp_path / "state.json").write_text(_json.dumps(
        {"version": 1, "open": [{"port": 22, "service": "ssh", "version": None, "risk": "info"}]}
    ), encoding="utf-8")
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    assert cli.main(["scan", "--diff", "--ports", "22"]) == 1
    assert calls == []


def test_diff_new_port_toasts_changes(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [8080], identify_service="http-proxy")
    import json as _json
    (tmp_path / "state.json").write_text(
        _json.dumps({"version": 1, "open": []}), encoding="utf-8")
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    assert cli.main(["scan", "--diff", "--ports", "8080"]) == 1
    assert len(calls) == 1
    assert calls[0][1].startswith("🆕")
    assert "8080" in calls[0][1]


def test_diff_json_includes_changes(monkeypatch, tmp_path, capsys):
    _patch_scan(monkeypatch, tmp_path, [22])
    import json as _json
    (tmp_path / "state.json").write_text(
        _json.dumps({"version": 1, "open": []}), encoding="utf-8")
    cli.main(["scan", "--diff", "--json", "--no-notify", "--ports", "22"])
    out = _json.loads(capsys.readouterr().out)
    assert out["baseline"] is False
    assert [f["port"] for f in out["changes"]["new"]] == [22]


def test_non_diff_runs_do_not_touch_state(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [])
    cli.main(["scan", "--no-notify", "--ports", "80"])
    assert not (tmp_path / "state.json").exists()


def test_diff_new_critical_gets_detail_toast(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [6379], identify_service="redis")
    import json as _json
    (tmp_path / "state.json").write_text(
        _json.dumps({"version": 1, "open": []}), encoding="utf-8")
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    cli.main(["scan", "--diff", "--ports", "6379"])
    assert calls[0][1].startswith("🚨")
    assert calls[1][0].startswith("🚨 Port 6379")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_cli.py -v`
Expected: NEW tests FAIL with `AttributeError: 'Namespace' object has no attribute 'diff'` (and related failures); existing CLI tests still PASS.

- [ ] **Step 3: Implement the CLI wiring**

Edits to `portpatrol/cli.py`:

1. Add import after the existing `from portpatrol import knowledge, scanner`:

```python
from portpatrol import diff, knowledge, scanner
```

2. Add paths after `HISTORY_PATH`:

```python
STATE_PATH = Path.home() / ".portpatrol" / "state.json"
ALLOWLIST_PATH = Path.home() / ".portpatrol" / "allowlist.json"
```

3. In `build_parser()`, after the `--verbose` argument of the scan subparser:

```python
    scan.add_argument("--diff", action="store_true",
                      help="compare with the last scan; alert only on changes")
```

4. In `cmd_scan`, insert the diff block after the `if args.kev:` block and before `result = {`:

```python
    changes = None
    baseline = False
    if args.diff:
        prev_state = diff.load_state(STATE_PATH)
        baseline = prev_state is None
        allow = diff.load_allowlist(ALLOWLIST_PATH)
        changes = diff.compute_changes(
            [] if prev_state is None else prev_state["open"], findings, allow)
        diff.save_state(STATE_PATH, findings)
```

5. Extend the `result` dict (still inside `cmd_scan`):

```python
    result = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": "127.0.0.1",
        "scanned": len(ports),
        "open": findings,
    }
    if args.diff:
        result["changes"] = changes
        result["baseline"] = baseline
```

6. Replace the existing `if not args.no_notify:` block with:

```python
    if not args.no_notify:
        if args.diff:
            if baseline:
                notify("PortPatrol", summary_message(findings))
            elif diff.has_changes(changes):
                notify("PortPatrol", diff.changes_message(changes))
                for f in changes["new"]:
                    if f["risk"] != "critical":
                        continue
                    detail = f.get("service") or "unknown service"
                    notify(
                        f"🚨 Port {f['port']} {detail}",
                        f"Critical: newly open. Run 'portpatrol explain {f['port']}'.",
                    )
        else:
            notify("PortPatrol", summary_message(findings))
            for f in findings:
                if f["risk"] != "critical":
                    continue
                detail = f.get("service") or "unknown service"
                cves = ", ".join(f.get("cves", []))
                suffix = f" ({cves})" if cves else ""
                notify(
                    f"🚨 Port {f['port']} {detail}",
                    f"Critical: open and exploitable{suffix}. Run 'portpatrol explain {f['port']}'.",
                )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/ -v`
Expected: PASS (all tests across all files; Task 1's 17 + prior suites + the 7 new CLI tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/cli.py tests/test_cli.py
git commit -m "feat: scan --diff with baseline, silent unchanged runs, change toasts"
```

---

### Task 3: Daily timer wiring and end-to-end verification

**Files:**
- Modify: `~/.config/systemd/user/portpatrol-daily.service` (add `--diff` to ExecStart)
- Create: `examples/systemd/user/portpatrol-daily.service`
- Create: `examples/systemd/user/portpatrol-daily.timer`
- Test: manual verification only; full suite must stay green

**Interfaces:**
- Consumes: `scan --diff` from Task 2; the already-enabled `portpatrol-daily.timer` (fires 09:00 daily, `SuccessExitStatus=1`).
- Produces: reproducible example units in-repo; a verified silent-when-stable daily pipeline.

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -v`
Expected: PASS (all tests)

- [ ] **Step 2: Establish the baseline via the installed unit**

Edit `~/.config/systemd/user/portpatrol-daily.service` so ExecStart reads:

```ini
ExecStart=/home/belteshazzarkijin/portpatrol/bin/portpatrol scan --ports top1000 --kev --diff
```

Then:

```bash
systemctl --user daemon-reload
systemctl --user start portpatrol-daily.service
systemctl --user show portpatrol-daily.service -p Result
```

Expected: `Result=success`; `~/.portpatrol/state.json` now exists with the current open ports (baseline).

- [ ] **Step 3: Verify a change produces a toast and silence otherwise**

```bash
# Unchanged run: expect no notification and Result=success
systemctl --user start portpatrol-daily.service && echo "second run ok"

# Induce a change: open a listener, scan with --diff, expect 🆕 toast
python3 -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1 &
sleep 1
portpatrol scan --diff --ports 18081
kill %1
```

Expected: second unit run is silent (no toast); the listener scan toasts `🆕 PortPatrol changes — 1 new: 18081 (…)` and exits 1. Note: that subset scan overwrites state with only port 18081 (single-snapshot semantics — state always reflects the last `--diff` scan regardless of `--ports`). Restore the full baseline silently once the listener is down:

```bash
portpatrol scan --diff --ports top1000 --no-notify
```

- [ ] **Step 4: Ship example units**

Create `examples/systemd/user/portpatrol-daily.service`:

```ini
# Install:
#   mkdir -p ~/.config/systemd/user
#   cp portpatrol-daily.* ~/.config/systemd/user/
#   systemctl --user daemon-reload && systemctl --user enable --now portpatrol-daily.timer

[Unit]
Description=PortPatrol daily open-port scan

[Service]
Type=oneshot
ExecStart=%h/portpatrol/bin/portpatrol scan --ports top1000 --kev --diff
SuccessExitStatus=1
```

Create `examples/systemd/user/portpatrol-daily.timer`:

```ini
# Paired with portpatrol-daily.service; see that file for install steps.

[Unit]
Description=Run PortPatrol daily at 09:00 local time

[Timer]
OnCalendar=*-*-* 09:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 5: Final suite run and commit**

Run: `python3 -m pytest tests/ -v`
Expected: PASS (all tests)

```bash
git add examples/systemd/user/portpatrol-daily.service examples/systemd/user/portpatrol-daily.timer
git commit -m "feat: example systemd user units for daily --diff scans"
git status --short
# If verification produced code fixes:
# git add -A && git commit -m "fix: corrections from --diff end-to-end verification"
```
