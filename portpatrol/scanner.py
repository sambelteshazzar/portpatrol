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
