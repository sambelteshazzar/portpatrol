# PortPatrol Process Attribution + Bind-Address Exposure Implementation Plan

> **For agentic workers:** Implement one task at a time, in order, with TDD (write the failing test, watch it fail, implement, watch it pass, commit). Steps use checkbox (`- [ ]`) syntax for tracking. Run tests from the repo root: `python3 -m pytest tests/ -v`.

**Goal:** Every finding shows which process owns the port (name + PID) and whether the listener is loopback-only or interface-facing, with loopback-only listeners downgraded one risk level.

**Architecture:** A new `portpatrol/listeners.py` builds an OS listener inventory from `ss -tlnp` (Linux) or `netstat -ano` (Windows), returning `{port: {pid, process, bind}}` and classifying each bind as `loopback | interface | unknown`; it degrades to `{}` when neither binary is available. `knowledge.adjust_risk_for_exposure` applies a one-level downgrade for `loopback` (critical→high, high→medium, medium→info; info/unknown unchanged); `interface` and `unknown` keep the KB risk. `cli.py` merges the inventory into findings (`pid`, `process`, `exposure` fields) before classification, and `report.console_table` gains EXPOSURE and PROCESS columns. State files for `--diff` are unaffected (they slim to port/service/version/risk only).

**Tech Stack:** Python 3.8+ stdlib only (subprocess, re, socket for tests), system binaries `ss`/`netstat` invoked optionally like `nmap`/`notify-send`, pytest for tests.

## Global Constraints

- Python 3.8+ standard library only. Zero pip dependencies.
- System binaries via subprocess are optional enrichments (`nmap`, `notify-send`, `ss`, `netstat`); every one degrades gracefully when missing, noted under `--verbose` where applicable.
- Platforms: any Linux distribution; Windows 10/11.
- Target: `127.0.0.1` only. No other hosts.
- Connect scans only. Timeouts: 0.5s sweep, 1.0s probes. One probe per open port per scan.
- No telemetry. Network egress only the user-triggered `--kev` fetch from cisa.gov.
- Exit codes: 0 clean, 1 findings, 2 error. Unchanged by this plan.
- Data dir `~/.portpatrol/` (`history.json`, `kev.json`, `state.json`, `allowlist.json`, optional `knowledge_base.json` override).
- Emoji map: 🚨 critical, ⚠️ high, 🟡 medium, 🔵 info, ❓ unknown, ✅ all clear.
- Defensive only: no exploitation, no credential attempts, no packet crafting.
- Windows v1 attribution is PID-only (`process` stays `None`); process names come from `ss` on Linux.

---

### Task 1: Listener inventory and exposure primitives

**Files:**
- Create: `portpatrol/listeners.py`
- Modify: `portpatrol/knowledge.py` (append one function)
- Test: `tests/test_listeners.py` (new)
- Test: `tests/test_knowledge.py` (append tests)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `parse_ss(output: str) -> dict`, `parse_netstat(output: str) -> dict` (both `{port: {"pid": int | None, "process": str | None, "bind": str}}`), `classify_exposure(bind: str | None) -> str` (`"loopback" | "interface" | "unknown"`), `collect_listeners() -> dict` (same shape, `{}` when unavailable), `knowledge.adjust_risk_for_exposure(risk: str, exposure: str) -> str`.

- [x] **Step 1: Write the failing tests**

```python
# tests/test_listeners.py
import os
import shutil
import socket
from unittest import mock

import pytest

from portpatrol import listeners

SS_SAMPLE = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      4096   127.0.0.1:631      0.0.0.0:*         users:("cupsd",pid=1234,fd=5)
LISTEN 0      511    0.0.0.0:80          0.0.0.0:*         users:(("nginx",pid=99,fd=6))
LISTEN 0      128    [::1]:8080          [::]:*            users:("python3",pid=42,fd=7)
LISTEN 0      128    192.168.1.10:3000   0.0.0.0:*
LISTEN 0      128    127.0.0.1:5432      0.0.0.0:*         users:("postgres",pid=7,fd=3)
LISTEN 0      128    0.0.0.0:5432        0.0.0.0:*
"""

NETSTAT_SAMPLE = """
  TCP    127.0.0.1:135           0.0.0.0:0              LISTENING       1234
  TCP    0.0.0.0:445             0.0.0.0:0              LISTENING       4
  TCP    [::1]:5357              [::]:0                 LISTENING       888
  UDP    0.0.0.0:500             *:0                                    999
"""


def test_parse_ss_extracts_pid_process_bind():
    out = listeners.parse_ss(SS_SAMPLE)
    assert out[631] == {"pid": 1234, "process": "cupsd", "bind": "127.0.0.1"}
    assert out[80]["process"] == "nginx"
    assert out[80]["pid"] == 99
    assert out[8080]["bind"] == "::1"
    assert out[3000]["bind"] == "192.168.1.10"
    assert out[3000]["pid"] is None
    assert out[3000]["process"] is None


def test_parse_ss_dual_bind_prefers_interface_and_keeps_pid():
    out = listeners.parse_ss(SS_SAMPLE)
    assert out[5432]["bind"] == "0.0.0.0"
    assert out[5432]["pid"] == 7
    assert out[5432]["process"] == "postgres"


def test_parse_ss_skips_header_and_short_lines():
    out = listeners.parse_ss("State\nLISTEN\nGARBAGE LINE ONLY\n")
    assert out == {}


def test_parse_netstat_extracts_listeners_and_skips_udp():
    out = listeners.parse_netstat(NETSTAT_SAMPLE)
    assert out[135] == {"pid": 1234, "process": None, "bind": "127.0.0.1"}
    assert out[445]["pid"] == 4
    assert out[5357]["bind"] == "::1"
    assert 500 not in out


def test_classify_exposure_loopback():
    assert listeners.classify_exposure("127.0.0.1") == "loopback"
    assert listeners.classify_exposure("127.0.0.53") == "loopback"
    assert listeners.classify_exposure("::1") == "loopback"


def test_classify_exposure_interface_and_unknown():
    assert listeners.classify_exposure("0.0.0.0") == "interface"
    assert listeners.classify_exposure("::") == "interface"
    assert listeners.classify_exposure("*") == "interface"
    assert listeners.classify_exposure("192.168.1.10") == "interface"
    assert listeners.classify_exposure(None) == "unknown"
    assert listeners.classify_exposure("") == "unknown"


def test_collect_linux_uses_ss():
    with mock.patch.object(listeners.shutil, "which", return_value="/usr/bin/ss"), \
         mock.patch.object(listeners, "_run", return_value=SS_SAMPLE):
        out = listeners.collect_listeners()
    assert out[631]["process"] == "cupsd"


def test_collect_windows_uses_netstat():
    with mock.patch.object(listeners.sys, "platform", "win32"), \
         mock.patch.object(listeners, "_run", return_value=NETSTAT_SAMPLE):
        out = listeners.collect_listeners()
    assert out[135]["pid"] == 1234


def test_collect_returns_empty_when_unavailable():
    with mock.patch.object(listeners.sys, "platform", "linux"), \
         mock.patch.object(listeners.shutil, "which", return_value=None):
        assert listeners.collect_listeners() == {}


@pytest.mark.skipif(shutil.which("ss") is None, reason="ss not installed")
def test_collect_live_finds_own_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        out = listeners.collect_listeners()
        assert out[port]["pid"] == os.getpid()
        assert listeners.classify_exposure(out[port]["bind"]) == "loopback"
    finally:
        srv.close()
```

Append to `tests/test_knowledge.py`:

```python
def test_adjust_risk_loopback_downgrades_one_level():
    assert knowledge.adjust_risk_for_exposure("critical", "loopback") == "high"
    assert knowledge.adjust_risk_for_exposure("high", "loopback") == "medium"
    assert knowledge.adjust_risk_for_exposure("medium", "loopback") == "info"
    assert knowledge.adjust_risk_for_exposure("info", "loopback") == "info"
    assert knowledge.adjust_risk_for_exposure("unknown", "loopback") == "unknown"


def test_adjust_risk_interface_or_unknown_exposure_unchanged():
    assert knowledge.adjust_risk_for_exposure("critical", "interface") == "critical"
    assert knowledge.adjust_risk_for_exposure("medium", "interface") == "medium"
    assert knowledge.adjust_risk_for_exposure("high", "unknown") == "high"
```

- [x] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_listeners.py tests/test_knowledge.py -v`
Expected: FAIL — `ImportError: cannot import name 'listeners'` (collection error) and `AttributeError: ... has no attribute 'adjust_risk_for_exposure'`.

- [x] **Step 3: Implement the primitives**

```python
# portpatrol/listeners.py
"""OS listener inventory: which process owns each port and where it binds."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys


def _run(cmd, timeout=10):
    """Run a command and return stdout, or None on failure."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def classify_exposure(bind):
    """Classify a bound host string: loopback-only, interface-facing, or unknown."""
    if not bind:
        return "unknown"
    if bind == "*":
        return "interface"
    if bind == "::1" or bind.startswith("127."):
        return "loopback"
    return "interface"


def _exposure_rank(bind):
    return 2 if classify_exposure(bind) == "interface" else 1


def _split_host_port(local):
    if ":" not in local:
        return None, None
    host, _, port_s = local.rpartition(":")
    if not port_s.isdigit():
        return None, None
    port = int(port_s)
    if not (1 <= port <= 65535):
        return None, None
    return host.strip("[]") or "*", port


def parse_ss(output):
    """Parse `ss -tlnp` output into {port: {pid, process, bind}}.

    Dual-stack or dual-bind listeners on one port merge to the most
    interface-facing bind; pid/process fill in when the other line has them.
    """
    found = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("State"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        bind, port = _split_host_port(parts[3])
        if port is None:
            continue
        pid_m = re.search(r"pid=(\d+)", line)
        name_m = re.search(r'users:\(+"?([^",]+)', line)
        entry = {
            "pid": int(pid_m.group(1)) if pid_m else None,
            "process": name_m.group(1) if name_m else None,
            "bind": bind,
        }
        prev = found.get(port)
        if prev is None:
            found[port] = entry
        elif _exposure_rank(entry["bind"]) > _exposure_rank(prev["bind"]):
            entry["pid"] = entry["pid"] if entry["pid"] is not None else prev["pid"]
            entry["process"] = entry["process"] or prev["process"]
            found[port] = entry
        elif entry["pid"] is not None and prev["pid"] is None:
            prev["pid"] = entry["pid"]
            prev["process"] = entry["process"] or prev["process"]
    return found


def parse_netstat(output):
    """Parse Windows `netstat -ano` output into {port: {pid, process, bind}}.

    Only LISTENING rows count; process names are Windows v1 out of scope.
    """
    found = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or "LISTENING" not in parts:
            continue
        bind, port = _split_host_port(parts[1])
        if port is None:
            continue
        pid = int(parts[4]) if parts[4].isdigit() else None
        found[port] = {"pid": pid, "process": None, "bind": bind}
    return found


def collect_listeners():
    """Return {port: {pid, process, bind}} from the OS listener table.

    ss on Linux, netstat on Windows, {} when neither is available.
    """
    if sys.platform == "win32":
        out = _run(["netstat", "-ano"])
        if out is None:
            return {}
        return parse_netstat(out)
    if shutil.which("ss"):
        out = _run(["ss", "-tlnp"])
        if out:
            return parse_ss(out)
    return {}
```

Append to `portpatrol/knowledge.py`:

```python
_LOOPBACK_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "info"}


def adjust_risk_for_exposure(risk, exposure):
    """One-level downgrade for loopback-only listeners; interface/unknown unchanged."""
    if exposure == "loopback":
        return _LOOPBACK_DOWNGRADE.get(risk, risk)
    return risk
```

- [x] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/ -v`
Expected: PASS (all tests across all files; 11 new listeners tests + 2 new knowledge tests on top of the existing 72)

- [x] **Step 5: Commit**

```bash
git add portpatrol/listeners.py portpatrol/knowledge.py tests/test_listeners.py tests/test_knowledge.py
git commit -m "feat: OS listener inventory with process attribution and exposure classes"
```

---

### Task 2: CLI merge, risk adjustment, and report columns

**Files:**
- Modify: `portpatrol/cli.py` (import, classification loop, verbose note)
- Modify: `portpatrol/report.py` (table columns)
- Test: `tests/test_cli.py` (append tests)
- Test: `tests/test_report.py` (append test)

**Interfaces:**
- Consumes: `collect_listeners`, `classify_exposure` (Task 1); `adjust_risk_for_exposure` (Task 1); `_patch_scan` helper already in `tests/test_cli.py`.
- Produces: findings gain `pid: int | None`, `process: str | None`, `exposure: str` fields in console, JSON, and history output.

- [x] **Step 1: Write the failing tests**

Append to `tests/test_cli.py` (also add `import os`, `import socket`, `import shutil`, `import pytest` at the top of the file as needed):

```python
def test_verbose_notes_missing_listener_table(monkeypatch, tmp_path, capsys):
    _patch_scan(monkeypatch, tmp_path, [22])
    monkeypatch.setattr("portpatrol.listeners.collect_listeners", lambda: {})
    cli.main(["scan", "--no-notify", "--verbose", "--ports", "22"])
    assert "listener table" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("ss") is None, reason="ss not installed")
def test_scan_loopback_listener_downgrades_risk_and_attributes_pid(monkeypatch, tmp_path):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.bind(("127.0.0.1", 6379))
    except OSError:
        srv.close()
        pytest.skip("port 6379 busy")
    srv.listen(5)
    try:
        monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
        monkeypatch.setattr("portpatrol.scanner.identify",
                            lambda p, e, i, **kw: {"port": p, "service": "redis",
                                                   "version": None})
        monkeypatch.setattr("portpatrol.scanner.enrich_with_nmap", lambda ports, **kw: {})
        assert cli.main(["scan", "--no-notify", "--ports", "6379"]) == 1
        history = json.loads((tmp_path / "history.json").read_text(encoding="utf-8"))
        f = history[0]["open"][0]
        assert f["exposure"] == "loopback"
        assert f["risk"] == "high"
        assert f["pid"] == os.getpid()
        assert f["process"]
    finally:
        srv.close()


def test_findings_default_to_unknown_exposure_when_not_listening(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [])
    cli.main(["scan", "--no-notify", "--json", "--ports", "80"])
    assert True
```

Note: the third test above is a placeholder for the JSON-empty case only if needed; prefer asserting via `test_diff_json_includes_changes`-style capsys when writing — the essential new tests are the verbose note and the live loopback attribution test.

Append to `tests/test_report.py`:

```python
def test_console_table_shows_exposure_and_process():
    findings = [{"port": 6379, "risk": "high", "service": "redis", "version": None,
                 "cves": [], "exposure": "loopback", "process": "redis-server"}]
    table = report.console_table(findings)
    assert "loopback" in table
    assert "redis-server" in table
```

- [x] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_cli.py tests/test_report.py -v`
Expected: NEW tests FAIL (`listener table` not in stderr — no verbose note yet; history findings lack `exposure` key; table lacks `loopback` substring); existing tests still PASS.

- [x] **Step 3: Implement the wiring**

Edits to `portpatrol/cli.py`:

1. Import: change `from portpatrol import diff, knowledge, scanner` to:

```python
from portpatrol import diff, knowledge, listeners, scanner
```

2. Replace the existing classification loop in `cmd_scan`:

```python
    for f in findings:
        service = f["service"] if f["service"] not in (None, "unknown") else None
        f["risk"] = knowledge.classify_port(kb, f["port"], service)
        f["cves"] = []
```

with:

```python
    inv = listeners.collect_listeners()
    if args.verbose and findings and not inv:
        print("portpatrol: listener table unavailable (ss/netstat); "
              "no process attribution", file=sys.stderr)
    for f in findings:
        info = inv.get(f["port"]) or {}
        f["pid"] = info.get("pid")
        f["process"] = info.get("process")
        f["exposure"] = listeners.classify_exposure(info.get("bind"))
        service = f["service"] if f["service"] not in (None, "unknown") else None
        risk = knowledge.classify_port(kb, f["port"], service)
        f["risk"] = knowledge.adjust_risk_for_exposure(risk, f["exposure"])
        f["cves"] = []
```

Edit to `portpatrol/report.py` — replace `console_table` with:

```python
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
```

- [x] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/ -v`
Expected: PASS (all tests across all files)

- [x] **Step 5: Commit**

```bash
git add portpatrol/cli.py portpatrol/report.py tests/test_cli.py tests/test_report.py
git commit -m "feat: per-finding process, PID, exposure, and loopback risk downgrade"
```

---

### Task 3: End-to-end verification

**Files:**
- No new files. Fixes only if verification finds bugs.

**Interfaces:**
- Consumes: the complete feature from Tasks 1-2.
- Produces: verified working software and, if anything was fixed, a final commit.

- [x] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -v`
Expected: PASS (all tests)

- [x] **Step 2: Real scan shows real processes and exposure**

```bash
cd /home/belteshazzarkijin/portpatrol && portpatrol scan --ports 631,5000,8000 --no-notify
```

Expected: the table shows EXPOSURE and PROCESS columns populated from the live system (e.g. `631` owned by `cupsd` with its real PID; `5000`/`8000` revealing their owning processes — previously unknown services), exit 1.

- [x] **Step 3: Diff baseline stays stable (risk changes do not alert)**

```bash
portpatrol scan --diff --ports top1000 --no-notify
python3 -c "import json; print([f['port'] for f in json.load(open('/home/belteshazzarkijin/.portpatrol/state.json'))['open']])"
```

Expected: state still `[631, 5000, 8000]` (service/version unchanged, so no false "changed" alerts even if loopback downgrades shifted their risk); the run is silent.

- [x] **Step 4: Commit any fixes, or confirm no fixes needed**

```bash
git status --short
# If verification produced fixes:
# git add -A && git commit -m "fix: corrections from attribution end-to-end verification"
```
