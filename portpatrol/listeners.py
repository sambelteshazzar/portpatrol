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
