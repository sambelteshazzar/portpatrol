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
