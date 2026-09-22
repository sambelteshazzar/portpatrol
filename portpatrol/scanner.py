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
