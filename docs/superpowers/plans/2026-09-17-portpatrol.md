# PortPatrol Implementation Plan

> **Note for agentic workers:** Implement one task at a time, in order, with TDD (write the failing test, watch it fail, implement, watch it pass, commit). Steps use checkbox (`- [ ]`) syntax for tracking. Run tests from the repo root: `python3 -m pytest tests/ -v`.

**Goal:** Build PortPatrol, a local open-port scanner that classifies risk against an nmap-derived knowledge base and alerts via native desktop notifications.

**Architecture:** A Bash launcher execs a stdlib-only Python CLI. `scanner.py` sweeps localhost with connect scans, identifies services via banner grabs and probes, and optionally enriches with nmap and the CISA KEV feed. `knowledge.py` classifies, `notifier.py` alerts, `report.py` renders and persists, `cli.py` wires them together.

**Tech Stack:** Python 3.8+ stdlib only (socket, concurrent.futures, json, re, ctypes, urllib, xml.etree, argparse), Bash launcher, pytest for tests.

## Global Constraints

- Python 3.8+ standard library only. Zero pip dependencies.
- Platforms: any Linux distribution; Windows 10/11.
- Target: `127.0.0.1` only. No other hosts in v1.
- Connect scans only. Timeouts: 0.5s sweep, 1.0s probes. One probe per open port per scan.
- No telemetry. Network egress only the user-triggered `--kev` fetch from cisa.gov.
- Exit codes: 0 clean, 1 findings, 2 error.
- Data dir `~/.portpatrol/` (`history.json`, `kev.json`, optional `knowledge_base.json` override).
- Emoji map: 🚨 critical, ⚠️ high, 🟡 medium, 🔵 info, ❓ unknown, ✅ all clear.
- Defensive only: no exploitation, no credential attempts, no packet crafting.

---

### Task 1: Package scaffold, knowledge data, and loader

**Files:**
- Create: `portpatrol/__init__.py`
- Create: `portpatrol/defaults.py`
- Create: `portpatrol/data/top_ports.json`
- Create: `portpatrol/knowledge.py`
- Create (generated): `portpatrol/knowledge_base.json`
- Test: `tests/test_knowledge.py`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `DEFAULT_ENTRIES: list[dict]`, `TOP_PORTS: list[int]`, `load_knowledge_base(user_path=None) -> dict[int, dict]`, `get_entry(kb, port) -> dict | None`, `service_index(kb) -> dict[str, dict]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_knowledge.py
import json

from portpatrol import knowledge
from portpatrol.defaults import DEFAULT_ENTRIES, TOP_PORTS

REQUIRED_KEYS = {"port", "protocol", "service", "risk", "banner_first", "probe", "match", "advice", "kev_hints"}
RISKS = {"critical", "high", "medium", "info", "unknown"}


def test_default_entries_validate_against_schema():
    assert len(DEFAULT_ENTRIES) >= 40
    for entry in DEFAULT_ENTRIES:
        assert REQUIRED_KEYS <= set(entry), entry["port"]
        assert entry["protocol"] == "tcp"
        assert entry["risk"] in RISKS, entry["port"]
        assert isinstance(entry["port"], int) and 1 <= entry["port"] <= 65535
        assert isinstance(entry["match"], list)
        assert isinstance(entry["kev_hints"], list)
        assert isinstance(entry["advice"], str) and entry["advice"]


def test_top_ports_list_has_100_unique_ports():
    assert len(TOP_PORTS) == 100
    assert len(set(TOP_PORTS)) == 100
    for known in (80, 443, 22, 3306, 3389, 5900, 6379, 27017):
        assert known in TOP_PORTS


def test_load_knowledge_base_uses_user_override(tmp_path):
    user_kb = tmp_path / "knowledge_base.json"
    user_kb.write_text(json.dumps([
        {"port": 9999, "protocol": "tcp", "service": "testsvc", "risk": "high",
         "banner_first": False, "probe": None, "match": [], "advice": "test advice",
         "kev_hints": []}
    ]), encoding="utf-8")
    kb = knowledge.load_knowledge_base(user_path=user_kb)
    assert kb[9999]["risk"] == "high"


def test_load_knowledge_base_invalid_json_falls_back(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    kb = knowledge.load_knowledge_base(user_path=bad)
    assert 22 in kb


def test_service_index_maps_names_to_entries():
    kb = knowledge.load_knowledge_base()
    idx = knowledge.service_index(kb)
    assert idx["ssh"]["port"] == 22
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_knowledge.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'portpatrol'`

- [ ] **Step 3: Write the package scaffold and data files**

```python
# portpatrol/__init__.py
"""PortPatrol: local open-port scanner with risk classification and desktop alerts."""

__version__ = "0.1.0"
```

```python
# portpatrol/defaults.py
"""Built-in knowledge base entries and the curated top-ports list.

knowledge_base.json overrides these when present. One source of truth: the
JSON file is generated from this module, never hand-maintained twice.
"""

from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"


def _entry(port, service, risk, advice, banner_first=False, probe=None, match=None, kev_hints=None):
    return {
        "port": port,
        "protocol": "tcp",
        "service": service,
        "risk": risk,
        "banner_first": banner_first,
        "probe": probe,
        "match": match or [],
        "advice": advice,
        "kev_hints": kev_hints or [],
    }


DEFAULT_ENTRIES = [
    _entry(7, "echo", "info", "Echo service is obsolete and amplifies reflection attacks. Disable it."),
    _entry(21, "ftp", "high", "FTP sends credentials in cleartext and has a long exploit history. Use SFTP or close the port.",
           banner_first=True, match=[r"^220"], kev_hints=["ftp"]),
    _entry(22, "ssh", "info", "SSH is acceptable when hardened. Disable password auth and root login, keep OpenSSH patched.",
           banner_first=True, match=[r"^SSH-[\d.]+-(OpenSSH[\w.p\-]+)"], kev_hints=["openssh"]),
    _entry(23, "telnet", "critical", "Telnet transmits everything in cleartext and was the Mirai botnet's entry point. No modern use; close it."),
    _entry(25, "smtp", "medium", "An exposed mail relay gets abused for spam and phishing within hours. Restrict to trusted hosts.",
           banner_first=True, match=[r"^220"], kev_hints=["exim"]),
    _entry(53, "domain", "medium", "An open resolver participates in DNS amplification DDoS. Bind to localhost or your LAN only."),
    _entry(110, "pop3", "medium", "POP3 sends credentials in cleartext. Use POP3S or close the port.",
           banner_first=True, match=[r"^\+OK"]),
    _entry(111, "rpcbind", "high", "rpcbind exposes the RPC service map attackers use for recon. Firewall it from untrusted networks."),
    _entry(113, "auth", "info", "Ident service leaks username info to remote hosts. Close it unless something depends on it."),
    _entry(135, "msrpc", "high", "The RPC endpoint mapper is the first stop for Windows recon and lateral movement. Firewall it."),
    _entry(139, "netbios-ssn", "high", "NetBIOS session service leaks host info and predates modern Windows networking. Close it."),
    _entry(143, "imap", "medium", "IMAP sends credentials in cleartext. Use IMAPS or close the port.",
           banner_first=True, match=[r"^\* OK"]),
    _entry(389, "ldap", "medium", "Anonymous LDAP queries leak directory data. Require authentication and bind to trusted networks."),
    _entry(443, "https", "info", "HTTPS is expected. Keep the TLS stack and certificates current.",
           probe="HEAD / HTTP/1.0\r\n\r\n", match=[r"^HTTP/[\d.]+", r"Server:\s*([^\r\n]+)"], kev_hints=["openssl"]),
    _entry(445, "microsoft-ds", "high", "Exposed SMB is the WannaCry/EternalBlue path (CVE-2017-0145). Firewall it from untrusted networks and keep patches current.",
           kev_hints=["ms17-010", "samba"]),
    _entry(465, "smtps", "medium", "SMTPS is acceptable. Keep the TLS stack current."),
    _entry(513, "login", "high", "rlogin trusts the client host and predates modern auth. Close it."),
    _entry(514, "shell", "critical", "rsh executes commands with no real authentication. Close it."),
    _entry(515, "printer", "medium", "LPD printing is a legacy service with buffer-overflow history. Close it if unused."),
    _entry(548, "afp", "medium", "AFP file sharing is legacy Apple networking. Prefer SMB with signing or close it."),
    _entry(554, "rtsp", "info", "RTSP streams leak media server details and has default-credential issues. Bind to trusted networks."),
    _entry(5555, "adb", "critical", "ADB over the network gives full device control and is a Mirai infection vector. Disable it."),
    _entry(587, "submission", "medium", "Submission is acceptable when it requires authentication. Keep it patched.",
           banner_first=True, match=[r"^220"]),
    _entry(631, "ipp", "medium", "CUPS printing has a history of RCE bugs. Keep it patched or close if unused."),
    _entry(873, "rsync", "high", "An exposed rsync daemon allows anonymous module listing and file pull. Require auth or close it.",
           banner_first=True, match=[r"^@RSYNCD:"]),
    _entry(1080, "socks", "medium", "An open SOCKS proxy relays attacker traffic anonymously. Require auth or close it."),
    _entry(1433, "ms-sql-s", "medium", "Exposed SQL Server is brute-forced and ransomware-staged. Restrict to app subnets."),
    _entry(1723, "pptp", "medium", "PPTP VPN is cryptographically broken. Replace with WireGuard or close it."),
    _entry(2049, "nfs", "high", "An exported NFS share without root squashing gives effective root access. Firewall to trusted hosts."),
    _entry(3128, "squid", "medium", "An open proxy relays attacker traffic. Restrict to your LAN."),
    _entry(3306, "mysql", "medium", "Exposed databases are brute-forced and dumped within hours of discovery. Bind to app subnets, require strong auth.",
           kev_hints=["mysql", "mariadb"]),
    _entry(3389, "ms-wbt-server", "high", "Exposed RDP is brute-forced around the clock and was the BlueKeep path (CVE-2019-0708). Put it behind a VPN and keep patches current.",
           kev_hints=["bluekeep", "remote desktop"]),
    _entry(3690, "svn", "info", "An exposed SVN server leaks source code history. Require auth or close it."),
    _entry(5000, "upnp", "medium", "UPnP and alt HTTP services often expose admin interfaces. Verify what listens here."),
    _entry(5060, "sip", "medium", "Exposed SIP gets scanned for toll fraud. Restrict to your SIP provider."),
    _entry(5432, "postgresql", "medium", "Exposed databases are brute-forced and dumped within hours of discovery. Bind to app subnets, require strong auth.",
           kev_hints=["postgresql"]),
    _entry(5900, "vnc", "medium", "VNC has weak auth and a history of unauthenticated access bugs. Tunnel over SSH or close it.",
           banner_first=True, match=[r"^RFB"]),
    _entry(5985, "winrm", "high", "WinRM over HTTP is a remote shell for attackers once credentials leak. Require HTTPS and firewall it.",
           probe="HEAD / HTTP/1.0\r\n\r\n", match=[r"^HTTP"]),
    _entry(6379, "redis", "critical", "Unauthenticated Redis is a root-install path (cron and SSH key writes). Require auth, bind to localhost, and keep patched.",
           probe="PING\r\n", match=[r"^\+PONG", r"^-ERR", r"^\$\d"], kev_hints=["redis"]),
    _entry(8000, "http-alt", "medium", "Dev and alt HTTP ports often expose admin panels and debug endpoints. Verify what listens here.",
           probe="HEAD / HTTP/1.0\r\n\r\n", match=[r"^HTTP"]),
    _entry(8080, "http-proxy", "medium", "Alt HTTP ports often expose admin panels, proxies, and debug endpoints. Verify what listens here.",
           probe="HEAD / HTTP/1.0\r\n\r\n", match=[r"^HTTP", r"Server:\s*([^\r\n]+)"]),
    _entry(8443, "https-alt", "medium", "Alt HTTPS ports often expose admin panels and management consoles. Verify what listens here."),
    _entry(9200, "elasticsearch", "high", "Exposed Elasticsearch clusters get indexed and ransomed. Bind to localhost and require auth.",
           probe="HEAD / HTTP/1.0\r\n\r\n", match=[r"^HTTP"], kev_hints=["elasticsearch"]),
    _entry(11211, "memcached", "medium", "Exposed memcached is the reflection-amplification DDoS record holder (5 Tbps, 2018). Bind to localhost.",
           probe="version\r\n", match=[r"^VERSION "], kev_hints=["memcached"]),
    _entry(27017, "mongod", "critical", "Unauthenticated MongoDB triggered the 2017 ransomware wave. Require auth, bind to localhost.",
           kev_hints=["mongodb"]),
]


def _load_top_ports():
    try:
        ports = json.loads((DATA_DIR / "top_ports.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [int(p) for p in ports]


TOP_PORTS = _load_top_ports()
```

```json
// portpatrol/data/top_ports.json
// Curated top-100 TCP ports in frequency order, drawn from nmap's top-ports
// knowledge. JSON has no comments; remove these two lines when writing the file.
[80, 443, 22, 21, 23, 25, 3389, 135, 139, 445,
 3306, 143, 110, 995, 993, 587, 111, 53, 5900, 631,
 873, 389, 1723, 1433, 2049, 5432, 548, 113, 179, 199,
 427, 465, 513, 514, 515, 554, 7, 9, 13, 19,
 37, 79, 81, 88, 106, 119, 144, 5555, 646, 783,
 1080, 3128, 3000, 5000, 5001, 5060, 5901, 5902, 5903, 5985,
 5986, 6379, 6667, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
 9000, 9001, 9090, 9200, 9300, 11211, 15672, 27017, 28017, 50000,
 10000, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 2000,
 2121, 3690, 4444, 1900, 2123, 3260, 5666, 6000, 888, 880]
```

Write `portpatrol/data/top_ports.json` with the list only, no comment lines (JSON does not allow comments).

- [ ] **Step 4: Write the knowledge loader**

```python
# portpatrol/knowledge.py
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_knowledge.py -v`
Expected: PASS (all 5 tests)

- [ ] **Step 6: Generate knowledge_base.json from the defaults**

```bash
cd /home/belteshazzarkijin/portpatrol && python3 -c "
import json
from pathlib import Path
from portpatrol.defaults import DEFAULT_ENTRIES
Path('portpatrol/knowledge_base.json').write_text(json.dumps(DEFAULT_ENTRIES, indent=2), encoding='utf-8')
"
```

Verify: `python3 -c "import json; print(len(json.load(open('portpatrol/knowledge_base.json'))))"` prints `45`.

- [ ] **Step 7: Commit**

```bash
git add portpatrol/ tests/test_knowledge.py
git commit -m "feat: knowledge base with 45 seed entries and loader"
```

---

### Task 2: Port spec parser and risk classifier

**Files:**
- Modify: `portpatrol/knowledge.py` (append two functions)
- Test: `tests/test_knowledge.py` (append tests)

**Interfaces:**
- Consumes: `TOP_PORTS` from Task 1.
- Produces: `parse_port_spec(spec, top_ports) -> list[int]`, `classify_port(kb, port, service=None) -> str` (returns one of `critical|high|medium|info|unknown`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_knowledge.py`:

```python
import pytest


def test_parse_port_spec_list():
    assert knowledge.parse_port_spec("80,443", TOP_PORTS) == [80, 443]


def test_parse_port_spec_range():
    assert knowledge.parse_port_spec("8000-8003", TOP_PORTS) == [8000, 8001, 8002, 8003]


def test_parse_port_spec_mixed_dedup_sorted():
    assert knowledge.parse_port_spec("443,80,8000-8001,80", TOP_PORTS) == [80, 443, 8000, 8001]


def test_parse_port_spec_top50():
    assert knowledge.parse_port_spec("top50", TOP_PORTS) == TOP_PORTS[:50]


def test_parse_port_spec_top1000_covers_well_known():
    ports = knowledge.parse_port_spec("top1000", TOP_PORTS)
    for known in (22, 6379, 27017):
        assert known in ports
    assert max(ports) >= 27017


def test_parse_port_spec_all_length():
    assert len(knowledge.parse_port_spec("all", TOP_PORTS)) == 65535


def test_parse_port_spec_invalid():
    with pytest.raises(ValueError):
        knowledge.parse_port_spec("0", TOP_PORTS)
    with pytest.raises(ValueError):
        knowledge.parse_port_spec("80-", TOP_PORTS)


def test_classify_port_by_port_entry():
    kb = knowledge.load_knowledge_base()
    assert knowledge.classify_port(kb, 23) == "critical"
    assert knowledge.classify_port(kb, 22) == "info"


def test_classify_port_by_service_match():
    kb = knowledge.load_knowledge_base()
    assert knowledge.classify_port(kb, 12345, service="redis") == "critical"


def test_classify_port_unknown():
    kb = knowledge.load_knowledge_base()
    assert knowledge.classify_port(kb, 40000, service="notaservice") == "unknown"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_knowledge.py -v`
Expected: FAIL with `AttributeError: module 'portpatrol.knowledge' has no attribute 'parse_port_spec'`

- [ ] **Step 3: Implement the parser and classifier**

Append to `portpatrol/knowledge.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_knowledge.py -v`
Expected: PASS (all 15 tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/knowledge.py tests/test_knowledge.py
git commit -m "feat: port spec parser and risk classifier"
```

---

### Task 3: Socket sweep

**Files:**
- Create: `portpatrol/scanner.py`
- Create: `tests/test_scanner.py` (defines the socket helpers Tasks 3 and 4 share)

**Interfaces:**
- Consumes: nothing.
- Produces: `sweep(ports, target="127.0.0.1", timeout=0.5, workers=100) -> list[int]` (sorted open ports). Test helpers `_listener() -> (socket, int)`, `_serve_once(payload) -> (socket, thread, port)`, `_serve_respond(reply, expect=b"PING\r\n") -> (socket, thread, port)`.

- [ ] **Step 1: Write the failing tests and shared helpers**

```python
# tests/test_scanner.py
import socket
import threading

from portpatrol import scanner


def _listener():
    """A TCP listener on a free ephemeral port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    return srv, srv.getsockname()[1]


def _serve_once(payload):
    """A server that accepts one connection, sends payload, closes the connection."""
    srv, port = _listener()

    def run():
        conn, _ = srv.accept()
        conn.sendall(payload)
        conn.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, t, port


def _serve_respond(reply, expect=b"PING\r\n"):
    """A server that accepts one connection, reads a probe, sends reply."""
    srv, port = _listener()

    def run():
        conn, _ = srv.accept()
        conn.recv(256)
        conn.sendall(reply)
        conn.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return srv, t, port


def test_sweep_finds_open_port():
    srv, port = _listener()
    try:
        assert scanner.sweep([port]) == [port]
    finally:
        srv.close()


def test_sweep_misses_closed_port():
    srv, port = _listener()
    srv.close()
    assert scanner.sweep([port]) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_scanner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'portpatrol.scanner'` (create an empty `portpatrol/scanner.py` if pytest reports import error instead of collection error)

- [ ] **Step 3: Implement the sweep**

```python
# portpatrol/scanner.py
"""Port scanning: socket sweep, banner grabs, service probes, enrichment.

All imports are stdlib. Later tasks extend this module with service probes,
nmap enrichment, and KEV enrichment.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def _connect(target, port, timeout):
    """Open a TCP connection or return None on refusal, timeout, or denial."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        return sock
    except OSError:
        sock.close()
        return None


def sweep(ports, target="127.0.0.1", timeout=0.5, workers=100):
    """TCP connect scan. Returns the sorted list of open ports."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_connect, target, p, timeout): p for p in ports}
        for future in as_completed(futures):
            sock = future.result()
            if sock is not None:
                open_ports.append(futures[future])
                sock.close()
    return sorted(open_ports)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_scanner.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/scanner.py tests/test_scanner.py
git commit -m "feat: threaded TCP connect sweep"
```

---

### Task 4: Banner grab, probe, and service identification

**Files:**
- Modify: `portpatrol/scanner.py` (append three functions)
- Test: `tests/test_scanner.py` (append tests)

**Interfaces:**
- Consumes: `_connect`, `_listener`, `_serve_once`, `_serve_respond` from Task 3.
- Produces: `grab_banner(port, target="127.0.0.1", timeout=1.0, recv_bytes=256) -> bytes | None`, `send_probe(port, probe, target="127.0.0.1", timeout=1.0, recv_bytes=256) -> bytes | None`, `identify(port, entry, svc_index, target="127.0.0.1", timeout=1.0) -> dict` shaped `{"port": int, "service": str | None, "version": str | None}` where `service` is `"unknown"` when nothing matches.

**Caution:** Python source strings like `"PING\r\n"` carry real CR/LF bytes; `\\r\\n` would send literal backslash characters. Regex patterns in Python source use `r"^\\+PONG"` form; the same pattern in JSON is written `"^\\+PONG"` and parses identically.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_scanner.py`:

```python
def test_grab_banner_reads_greeting():
    srv, t, port = _serve_once(b"SSH-2.0-Test_1.0\r\n")
    try:
        assert scanner.grab_banner(port) == b"SSH-2.0-Test_1.0\r\n"
    finally:
        srv.close()
    t.join(timeout=2)


def test_grab_banner_none_when_silent():
    srv, t, port = _serve_once(b"")
    try:
        assert scanner.grab_banner(port) == b""
    finally:
        srv.close()
    t.join(timeout=2)


def test_send_probe_gets_response():
    srv, t, port = _serve_respond(b"+PONG\r\n")
    try:
        assert scanner.send_probe(port, b"PING\r\n") == b"+PONG\r\n"
    finally:
        srv.close()
    t.join(timeout=2)


def test_identify_uses_probe_and_match():
    srv, t, port = _serve_respond(b"+PONG\r\n")
    entry = {"port": port, "protocol": "tcp", "service": "redis", "risk": "critical",
             "banner_first": False, "probe": "PING\r\n", "match": [r"^\+PONG"],
             "advice": "x", "kev_hints": []}
    try:
        result = scanner.identify(port, entry, {})
        assert result == {"port": port, "service": "redis", "version": None}
    finally:
        srv.close()
    t.join(timeout=2)


def test_identify_banner_first_extracts_version():
    srv, t, port = _serve_once(b"SSH-2.0-OpenSSH_9.6p1\r\n")
    entry = {"port": port, "protocol": "tcp", "service": "ssh", "risk": "info",
             "banner_first": True, "probe": None,
             "match": [r"^SSH-[\d.]+-(OpenSSH[\w.p\-]+)"],
             "advice": "x", "kev_hints": []}
    try:
        result = scanner.identify(port, entry, {})
        assert result["service"] == "ssh"
        assert result["version"] == "OpenSSH_9.6p1"
    finally:
        srv.close()
    t.join(timeout=2)


def test_identify_fallback_to_service_index():
    srv, t, port = _serve_once(b"SSH-2.0-OpenSSH_9.6p1\r\n")
    svc_index = {"ssh": {"port": 22, "protocol": "tcp", "service": "ssh", "risk": "info",
                         "banner_first": True, "probe": None,
                         "match": [r"^SSH-[\d.]+-(OpenSSH[\w.p\-]+)"],
                         "advice": "x", "kev_hints": []}}
    try:
        result = scanner.identify(port, None, svc_index)
        assert result["service"] == "ssh"
        assert result["version"] == "OpenSSH_9.6p1"
    finally:
        srv.close()
    t.join(timeout=2)


def test_identify_unknown_when_nothing_matches():
    srv, t, port = _serve_once(b"")
    try:
        result = scanner.identify(port, None, {})
        assert result["service"] == "unknown"
    finally:
        srv.close()
    t.join(timeout=2)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_scanner.py -v`
Expected: FAIL with `AttributeError: module 'portpatrol.scanner' has no attribute 'grab_banner'`

- [ ] **Step 3: Implement banner grab, probe, and identification**

Append to `portpatrol/scanner.py`:

```python
def grab_banner(port, target="127.0.0.1", timeout=1.0, recv_bytes=256):
    """Connect and read the first bytes a service sends. b"" when silent, None on failure."""
    sock = _connect(target, port, timeout)
    if sock is None:
        return None
    try:
        return sock.recv(recv_bytes)
    except OSError:
        return None
    finally:
        sock.close()


def send_probe(port, probe, target="127.0.0.1", timeout=1.0, recv_bytes=256):
    """Connect, send a probe, read the response. None on any failure."""
    sock = _connect(target, port, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(probe)
        return sock.recv(recv_bytes)
    except OSError:
        return None
    finally:
        sock.close()


def _match_response(service, patterns, response):
    """Apply match patterns to response bytes.

    Returns {"service": str | None, "version": str | None}. The service is
    named when any pattern matches; the first capturing group of the first
    group-matching pattern becomes the version.
    """
    text = response.decode("latin-1", errors="replace")
    out = {"service": None, "version": None}
    for pattern in patterns:
        m = re.search(pattern, text)
        if m is None:
            continue
        if out["service"] is None:
            out["service"] = service
        if m.groups() and m.group(1):
            out["version"] = m.group(1)
            break
    return out


def identify(port, entry, svc_index, target="127.0.0.1", timeout=1.0):
    """Identify the service on an open port.

    Uses the entry's probe/match rules when present. Falls back to a banner
    grab matched against the knowledge base service index. Returns
    {"port": int, "service": str, "version": str | None} with service
    "unknown" when nothing matches.
    """
    if entry is not None:
        response = None
        if entry.get("probe"):
            response = send_probe(port, entry["probe"].encode("latin-1"), target, timeout)
        elif entry.get("banner_first"):
            response = grab_banner(port, target, timeout)
        if response:
            matched = _match_response(entry["service"], entry.get("match", []), response)
            if matched["service"] is not None:
                return {"port": port, "service": matched["service"], "version": matched["version"]}

    banner = grab_banner(port, target, timeout)
    if banner:
        for name, candidate in svc_index.items():
            matched = _match_response(name, candidate.get("match", []), banner)
            if matched["service"] is not None:
                return {"port": port, "service": matched["service"], "version": matched["version"]}

    return {"port": port, "service": "unknown", "version": None}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_scanner.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/scanner.py tests/test_scanner.py
git commit -m "feat: banner grab, service probes, and identification"
```

---

### Task 5: nmap enrichment

**Files:**
- Modify: `portpatrol/scanner.py` (append one function)
- Test: `tests/test_scanner.py` (append tests)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `NMAP_XML_SAMPLE: str` (test fixture), `enrich_with_nmap(open_ports, target="127.0.0.1") -> dict[int, dict]` shaped `{port: {"service": str | None, "product": str | None, "version": str | None}}`, empty dict when nmap is missing or fails.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_scanner.py`:

```python
from unittest import mock


def test_enrich_with_nmap_parses_xml():
    with mock.patch("portpatrol.scanner.shutil.which", return_value="/usr/bin/nmap"), \
         mock.patch("portpatrol.scanner.subprocess.run") as run:
        run.return_value = mock.Mock(returncode=0, stdout=scanner.NMAP_XML_SAMPLE)
        services = scanner.enrich_with_nmap([22, 6379])
    assert services[22]["service"] == "ssh"
    assert services[22]["product"] == "OpenSSH"
    assert services[6379]["version"] == "7.2.4"


def test_enrich_with_nmap_skips_when_missing():
    with mock.patch("portpatrol.scanner.shutil.which", return_value=None):
        assert scanner.enrich_with_nmap([22]) == {}


def test_enrich_with_nmap_empty_without_open_ports():
    with mock.patch("portpatrol.scanner.shutil.which", return_value="/usr/bin/nmap"):
        assert scanner.enrich_with_nmap([]) == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_scanner.py -v`
Expected: FAIL with `AttributeError: module 'portpatrol.scanner' has no attribute 'NMAP_XML_SAMPLE'`

- [ ] **Step 3: Implement nmap enrichment**

Append to `portpatrol/scanner.py`:

```python
NMAP_XML_SAMPLE = """<?xml version="1.0"?>
<nmaprun>
<host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1"/></port>
<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis" version="7.2.4"/></port>
</ports></host>
</nmaprun>
"""


def enrich_with_nmap(open_ports, target="127.0.0.1"):
    """Run nmap -sV on the open ports and parse its XML output.

    Returns {port: {"service": ..., "product": ..., "version": ...}}. Empty
    dict when nmap is not installed, no ports are open, or the scan fails.
    """
    if not open_ports or shutil.which("nmap") is None:
        return {}
    port_spec = ",".join(str(p) for p in open_ports)
    cmd = ["nmap", "-sV", "--version-light", "-p", port_spec, "-oX", "-", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            return {}
        root = ET.fromstring(proc.stdout)
    except (OSError, subprocess.TimeoutExpired, ET.ParseError):
        return {}
    services = {}
    for port_el in root.iter("port"):
        svc = port_el.find("service")
        if svc is None:
            continue
        services[int(port_el.get("portid"))] = {
            "service": svc.get("name"),
            "product": svc.get("product"),
            "version": svc.get("version"),
        }
    return services
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_scanner.py -v`
Expected: PASS (12 tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/scanner.py tests/test_scanner.py
git commit -m "feat: optional nmap -sV enrichment with XML parsing"
```

---

### Task 6: KEV enrichment

**Files:**
- Modify: `portpatrol/scanner.py` (append two functions)
- Test: `tests/test_scanner.py` (append tests)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `KEV_URL: str`, `KEV_MAX_AGE: int` (86400), `fetch_kev(cache_path, url=KEV_URL) -> list[dict]`, `enrich_with_kev(findings, kb, cache_path) -> list[dict]` which mutates each finding in place, adding `"cves": list[str]`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_scanner.py`:

```python
import json
import time


KEV_FIXTURE = {
    "_fetched_at": time.time(),
    "vulnerabilities": [
        {"cve": "CVE-2017-0145", "vendorProject": "Microsoft",
         "product": "Windows SMB", "description": "Windows SMB Remote Code Execution Vulnerability, known as EternalBlue or ms17-010."},
        {"cve": "CVE-2021-44228", "vendorProject": "Apache",
         "product": "Log4j2", "description": "Apache Log4j2 remote code execution."},
    ],
}


def test_enrich_with_kev_matches_hints(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(KEV_FIXTURE), encoding="utf-8")
    kb = {445: {"port": 445, "kev_hints": ["ms17-010", "smb"]}}
    findings = [{"port": 445, "service": "microsoft-ds", "product": None}]
    result = scanner.enrich_with_kev(findings, kb, cache)
    assert result[0]["cves"] == ["CVE-2017-0145"]


def test_enrich_with_kev_no_match_gives_empty_cves(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(KEV_FIXTURE), encoding="utf-8")
    kb = {}
    findings = [{"port": 40000, "service": "unknown", "product": None}]
    result = scanner.enrich_with_kev(findings, kb, cache)
    assert result[0]["cves"] == []


def test_fetch_kev_uses_cache(tmp_path):
    cache = tmp_path / "kev.json"
    cache.write_text(json.dumps(KEV_FIXTURE), encoding="utf-8")
    with mock.patch("portpatrol.scanner.urllib.request.urlopen") as urlopen:
        records = scanner.fetch_kev(cache)
    urlopen.assert_not_called()
    assert len(records) == 2


def test_fetch_kev_skips_offline_without_cache(tmp_path):
    with mock.patch("portpatrol.scanner.urllib.request.urlopen", side_effect=OSError):
        assert scanner.fetch_kev(tmp_path / "kev.json") == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_scanner.py -v`
Expected: FAIL with `AttributeError: module 'portpatrol.scanner' has no attribute 'KEV_URL'`

- [ ] **Step 3: Implement KEV fetch and enrichment**

Append to `portpatrol/scanner.py`:

```python
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_AGE = 24 * 3600


def _load_kev_cache(cache_path):
    try:
        data = json.loads(Path(cache_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or "_fetched_at" not in data:
        return None
    if time.time() - data["_fetched_at"] > KEV_MAX_AGE:
        return None
    return data.get("vulnerabilities", [])


def fetch_kev(cache_path, url=KEV_URL):
    """Return KEV vulnerability records, cached for 24 hours at cache_path.

    Returns [] when the fetch fails and no fresh cache exists.
    """
    cached = _load_kev_cache(cache_path)
    if cached is not None:
        return cached
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError):
        return []
    records = data.get("vulnerabilities", [])
    payload = {"_fetched_at": time.time(), "vulnerabilities": records}
    try:
        cache_path = Path(cache_path)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(payload), encoding="utf-8")
    except OSError:
        pass
    return records


def enrich_with_kev(findings, kb, cache_path):
    """Add "cves" to each finding using kev_hints and product names.

    Matches the entry's kev_hints keywords and the nmap-derived product name
    against the feed's vendorProject, product, and description fields.
    Mutates and returns findings.
    """
    records = fetch_kev(cache_path)
    hints_by_port = {}
    for f in findings:
        hints = set()
        entry = kb.get(f["port"])
        if entry:
            hints.update(h.lower() for h in entry.get("kev_hints", []))
        if f.get("product"):
            hints.add(f["product"].lower())
        hints_by_port[f["port"]] = hints
    for f in findings:
        cves = set()
        for rec in records:
            blob = (f"{rec.get('vendorProject', '')} {rec.get('product', '')} "
                    f"{rec.get('description', '')}").lower()
            if any(h in blob for h in hints_by_port[f["port"]]):
                cves.add(rec.get("cve"))
        f["cves"] = sorted(c for c in cves if c)
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_scanner.py -v`
Expected: PASS (16 tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/scanner.py tests/test_scanner.py
git commit -m "feat: CISA KEV enrichment with 24h cache"
```

---

### Task 7: Notifications

**Files:**
- Create: `portpatrol/notifier.py`
- Test: `tests/test_notifier.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `EMOJI: dict[str, str]` (critical 🚨, high ⚠️, medium 🟡, info 🔵, unknown ❓, clear ✅), `RISK_ORDER: list[str]`, `summary_message(findings) -> str`, `notify(title, body) -> bool` (True when a channel delivered), `_linux_command(title, body) -> list[str]`, `_windows_powershell_script(title, body) -> str`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_notifier.py
from unittest import mock

from portpatrol import notifier


def test_summary_message_clear():
    assert notifier.summary_message([]).startswith("✅ PortPatrol: all clear")


def test_summary_message_counts_and_emoji():
    findings = [
        {"port": 22, "risk": "info"},
        {"port": 445, "risk": "high"},
        {"port": 23, "risk": "critical"},
    ]
    msg = notifier.summary_message(findings)
    assert msg.startswith("🚨 PortPatrol: 3 open ports")
    assert "1 critical" in msg
    assert "1 high" in msg
    assert "1 info" in msg


def test_summary_message_unknown_only():
    msg = notifier.summary_message([{"port": 40000, "risk": "unknown"}])
    assert msg.startswith("❓ PortPatrol: 1 open ports")


def test_notify_linux_uses_notify_send():
    with mock.patch("portpatrol.notifier.shutil.which", return_value="/usr/bin/notify-send"), \
         mock.patch("portpatrol.notifier.subprocess.run") as run:
        assert notifier.notify("t", "b") is True
    assert run.call_args[0][0][0] == "notify-send"


def test_notify_linux_fallback_when_missing():
    with mock.patch("portpatrol.notifier.shutil.which", return_value=None):
        assert notifier.notify("t", "b") is False


def test_windows_powershell_script_contains_text():
    script = notifier._windows_powershell_script("title", "body")
    assert "ToastNotificationManager" in script
    assert "'title'" in script
    assert "'body'" in script
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_notifier.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'portpatrol.notifier'`

- [ ] **Step 3: Implement the notifier**

```python
# portpatrol/notifier.py
"""Cross-platform desktop notifications with emoji risk indicators."""

from __future__ import annotations

import shutil
import subprocess
import sys

EMOJI = {
    "critical": "🚨",
    "high": "⚠️",
    "medium": "🟡",
    "info": "🔵",
    "unknown": "❓",
    "clear": "✅",
}

RISK_ORDER = ["critical", "high", "medium", "info", "unknown"]


def summary_message(findings):
    """Build the summary toast text, e.g. "🚨 PortPatrol: 3 open ports — 1 critical, 1 high, 1 info"."""
    if not findings:
        return "✅ PortPatrol: all clear — no open ports found"
    counts = {}
    for f in findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
    top = next(r for r in RISK_ORDER if r in counts)
    parts = [f"{counts[r]} {r}" for r in RISK_ORDER if r in counts]
    return f"{EMOJI[top]} PortPatrol: {len(findings)} open ports — {', '.join(parts)}"


def _linux_command(title, body):
    return ["notify-send", title, body]


def _windows_powershell_script(title, body):
    esc_title = title.replace("'", "''")
    esc_body = body.replace("'", "''")
    return (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
        "ContentType = WindowsRuntime] | Out-Null; "
        "$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
        "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
        f"$t.GetElementsByTagName('text').Item(0).AppendChild($t.CreateTextNode('{esc_title}')) | Out-Null; "
        f"$t.GetElementsByTagName('text').Item(1).AppendChild($t.CreateTextNode('{esc_body}')) | Out-Null; "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($t); "
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('PortPatrol').Show($toast)"
    )


def notify(title, body):
    """Send a desktop notification. Returns True when a channel delivered it."""
    if sys.platform == "win32":
        return _notify_windows(title, body)
    return _notify_linux(title, body)


def _notify_linux(title, body):
    if shutil.which("notify-send") is None:
        return False
    try:
        subprocess.run(_linux_command(title, body), timeout=10, check=False)
        return True
    except OSError:
        return False


def _notify_windows(title, body):
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             _windows_powershell_script(title, body)],
            capture_output=True, timeout=15, check=False,
        )
        if proc.returncode == 0:
            return True
    except OSError:
        pass
    return _notify_windows_fallback(title, body)


def _notify_windows_fallback(title, body):
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, body, title, 0x40)
        return True
    except (OSError, AttributeError, ImportError):
        return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_notifier.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/notifier.py tests/test_notifier.py
git commit -m "feat: cross-platform desktop notifications with emoji indicators"
```

---

### Task 8: Console report and history

**Files:**
- Create: `portpatrol/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `EMOJI`, `RISK_ORDER` from Task 7.
- Produces: `console_table(findings) -> str`, `to_json(result) -> str`, `append_history(result, history_path) -> None`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_report.py
import json

from portpatrol import report


def test_console_table_sorts_by_risk():
    findings = [
        {"port": 22, "risk": "info", "service": "ssh", "version": "OpenSSH_9.6p1", "cves": []},
        {"port": 23, "risk": "critical", "service": "telnet", "version": None, "cves": ["CVE-1"]},
    ]
    table = report.console_table(findings)
    assert table.index("23") < table.index("22")
    assert "🚨" in table
    assert "CVE-1" in table


def test_console_table_empty():
    assert report.console_table([]).startswith("✅")


def test_to_json_shape():
    result = {"timestamp": "2026-09-17T14:03:22Z", "target": "127.0.0.1",
              "scanned": 1000, "open": []}
    assert json.loads(report.to_json(result))["target"] == "127.0.0.1"


def test_append_history_creates_and_appends(tmp_path):
    path = tmp_path / "history.json"
    report.append_history({"timestamp": "t1", "open": []}, path)
    report.append_history({"timestamp": "t2", "open": []}, path)
    history = json.loads(path.read_text(encoding="utf-8"))
    assert [h["timestamp"] for h in history] == ["t1", "t2"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_report.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'portpatrol.report'`

- [ ] **Step 3: Implement the report module**

```python
# portpatrol/report.py
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
    lines = [f"{'PORT':>6}  {'RISK':<8} {'SERVICE':<16} {'VERSION':<20} CVES"]
    for f in ordered:
        cves = ", ".join(f.get("cves", []))
        lines.append(
            f"{f['port']:>6}  {EMOJI[f['risk']]} {f['risk']:<7} "
            f"{f.get('service') or 'unknown':<16} {(f.get('version') or '-'):<20} {cves}"
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_report.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/report.py tests/test_report.py
git commit -m "feat: console report and scan history"
```

---

### Task 9: CLI wiring, exit codes, and Bash launcher

**Files:**
- Create: `portpatrol/__main__.py`
- Create: `portpatrol/cli.py`
- Create: `bin/portpatrol`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `parse_port_spec`, `load_knowledge_base`, `get_entry`, `service_index`, `classify_port` (Task 1-2); `sweep`, `identify`, `enrich_with_nmap`, `enrich_with_kev` (Task 3-6); `notify`, `summary_message` (Task 7); `console_table`, `to_json`, `append_history` (Task 8).
- Produces: `build_parser() -> argparse.ArgumentParser`, `cmd_scan(args) -> int`, `cmd_explain(args) -> int`, `main(argv=None) -> int`. `bin/portpatrol` runs on Linux.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cli.py
import json

from portpatrol import cli


def test_parser_defaults():
    args = cli.build_parser().parse_args(["scan"])
    assert args.ports == "top1000"
    assert args.json is False
    assert args.kev is False
    assert args.no_notify is False


def test_main_scan_clean_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
    monkeypatch.setattr("portpatrol.scanner.sweep", lambda ports, **kw: [])
    assert cli.main(["scan", "--no-notify", "--ports", "80,443"]) == 0
    assert (tmp_path / "history.json").exists()


def test_main_scan_findings_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
    monkeypatch.setattr("portpatrol.scanner.sweep", lambda ports, **kw: [22])
    monkeypatch.setattr("portpatrol.scanner.identify",
                        lambda p, e, i, **kw: {"port": p, "service": "ssh", "version": None})
    monkeypatch.setattr("portpatrol.scanner.enrich_with_nmap", lambda ports, **kw: {})
    assert cli.main(["scan", "--no-notify", "--ports", "22"]) == 1
    history = json.loads((tmp_path / "history.json").read_text(encoding="utf-8"))
    assert history[0]["open"][0]["port"] == 22
    assert history[0]["open"][0]["risk"] == "info"


def test_main_scan_invalid_ports_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
    assert cli.main(["scan", "--no-notify", "--ports", "0"]) == 2


def test_main_scan_notifies_by_default(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
    monkeypatch.setattr("portpatrol.scanner.sweep", lambda ports, **kw: [])
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    cli.main(["scan", "--ports", "80"])
    assert len(calls) == 1
    assert calls[0][0] == "PortPatrol"


def test_main_explain(capsys):
    assert cli.main(["explain", "23"]) == 0
    out = capsys.readouterr().out
    assert "telnet" in out
    assert "critical" in out


def test_main_explain_unknown_port(capsys):
    assert cli.main(["explain", "40000"]) == 0
    out = capsys.readouterr().out
    assert "unknown" in out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'portpatrol.cli'`

- [ ] **Step 3: Implement the CLI**

```python
# portpatrol/__main__.py
"""Allow `python -m portpatrol`."""

import sys

from portpatrol.cli import main

if __name__ == "__main__":
    sys.exit(main())
```

```python
# portpatrol/cli.py
"""Command line interface: scan and explain commands."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from portpatrol import knowledge, scanner
from portpatrol.defaults import TOP_PORTS
from portpatrol.notifier import notify, summary_message
from portpatrol.report import append_history, console_table, to_json

HISTORY_PATH = Path.home() / ".portpatrol" / "history.json"


def build_parser():
    parser = argparse.ArgumentParser(
        prog="portpatrol",
        description="Scan this machine for open ports and classify the risk.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan localhost and report open ports")
    scan.add_argument("--ports", default="top1000",
                      help="top50 | top100 | top1000 | all | 80,443 | 8000-8100")
    scan.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    scan.add_argument("--kev", action="store_true", help="cross-reference CISA KEV catalog")
    scan.add_argument("--no-notify", action="store_true", help="suppress desktop notifications")
    scan.add_argument("--verbose", action="store_true", help="log skipped enrichments and probe failures")
    scan.set_defaults(func=cmd_scan)

    explain = sub.add_parser("explain", help="print the knowledge base entry for a port")
    explain.add_argument("port", type=int)
    explain.set_defaults(func=cmd_explain)
    return parser


def cmd_scan(args):
    try:
        ports = knowledge.parse_port_spec(args.ports, TOP_PORTS)
    except ValueError as exc:
        print(f"portpatrol: {exc}", file=sys.stderr)
        return 2

    kb = knowledge.load_knowledge_base()
    svc_index = knowledge.service_index(kb)

    open_ports = scanner.sweep(ports)
    if args.verbose:
        print(f"portpatrol: {len(open_ports)} open of {len(ports)} scanned", file=sys.stderr)

    findings = [scanner.identify(p, knowledge.get_entry(kb, p), svc_index) for p in open_ports]

    services = scanner.enrich_with_nmap(open_ports)
    if args.verbose and open_ports and not services:
        print("portpatrol: nmap not found; socket probes only", file=sys.stderr)
    for f in findings:
        extra = services.get(f["port"]) or {}
        if f["service"] in (None, "unknown") and extra.get("service"):
            f["service"] = extra["service"]
        if extra.get("version") and not f["version"]:
            f["version"] = extra["version"]
        if extra.get("product"):
            f["product"] = extra["product"]

    for f in findings:
        service = f["service"] if f["service"] not in (None, "unknown") else None
        f["risk"] = knowledge.classify_port(kb, f["port"], service)
        f["cves"] = []

    if args.kev:
        scanner.enrich_with_kev(findings, kb, Path.home() / ".portpatrol" / "kev.json")

    result = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": "127.0.0.1",
        "scanned": len(ports),
        "open": findings,
    }

    if args.json:
        print(to_json(result))
    else:
        print(console_table(findings))

    if not args.no_notify:
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

    append_history(result, HISTORY_PATH)
    return 1 if findings else 0


def cmd_explain(args):
    kb = knowledge.load_knowledge_base()
    entry = knowledge.get_entry(kb, args.port)
    if entry is None:
        print(f"No knowledge base entry for port {args.port}.")
        print("Risk: unknown — not a well-known port. Verify manually what listens on it.")
        return 0
    print(f"Port {entry['port']}/tcp — {entry['service']} — risk: {entry['risk']}")
    print(f"Advice: {entry['advice']}")
    if entry.get("kev_hints"):
        print("KEV hints: " + ", ".join(entry["kev_hints"]))
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 2
```

```bash
# bin/portpatrol
#!/usr/bin/env bash
# PortPatrol launcher: runs the CLI from a source checkout or an installed package.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_PARENT="$(dirname "$SCRIPT_DIR")"

export PYTHONPATH="${PACKAGE_PARENT}${PYTHONPATH:+:$PYTHONPATH}"

exec python3 -m portpatrol "$@"
```

Make the launcher executable: `chmod +x bin/portpatrol`

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/ -v`
Expected: PASS (all tests across all files)

- [ ] **Step 5: Commit**

```bash
git add portpatrol/ bin/portpatrol tests/test_cli.py
git commit -m "feat: CLI with scan and explain commands, exit codes, Bash launcher"
```

---

### Task 10: End-to-end manual verification

**Files:**
- No new files. Fixes only if verification finds bugs.

**Interfaces:**
- Consumes: the complete tool from Tasks 1-9.
- Produces: verified working software and, if anything was fixed, a final commit.

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -v`
Expected: PASS (all tests)

- [ ] **Step 2: Verify a real scan finds a real listener**

```bash
cd /home/belteshazzarkijin/portpatrol && python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
sleep 1 && bin/portpatrol scan --ports 18080 --no-notify
kill %1
```

Expected: the table shows `18080` open with service `http` and a version extracted from the `Server:` header (SimpleHTTP). Exit code 1.

- [ ] **Step 3: Verify notifications and history**

```bash
cd /home/belteshazzarkijin/portpatrol && python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 &
sleep 1 && bin/portpatrol scan --ports 18080
kill %1
tail -n 12 ~/.portpatrol/history.json
```

Expected: a desktop toast appears (this machine runs KDE Plasma with notify-send), and the history file contains a record for the run.

- [ ] **Step 4: Verify explain and clean exit**

```bash
bin/portpatrol explain 445 && bin/portpatrol explain 40000
bin/portpatrol scan --ports 18080 --no-notify
```

Expected: `explain 445` prints the SMB entry with WannaCry advice; `explain 40000` prints the unknown-port fallback. The final scan exits 0 with the all-clear line once the listener is down.

- [ ] **Step 5: Commit any fixes, or confirm no fixes needed**

```bash
git status --short
# If verification produced fixes:
git add -A && git commit -m "fix: corrections from end-to-end verification"
```

---

## Windows Verification (manual, user-run)

On a Windows 10/11 machine with Python installed:

```powershell
python -m portpatrol scan --no-notify --ports top100
python -m portpatrol scan --ports top100
```

Expected: console table renders; the second run fires a PowerShell toast (or a MessageBox fallback on systems where the toast API is unavailable). `%USERPROFILE%\.portpatrol\history.json` records both runs.


