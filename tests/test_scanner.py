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
