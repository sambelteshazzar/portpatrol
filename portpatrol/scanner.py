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
