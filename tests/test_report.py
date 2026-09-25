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


def test_console_table_shows_risk_source():
    findings = [{"port": 22, "risk": "info", "service": "ssh", "version": None,
                 "cves": [], "exposure": "loopback", "process": "sshd",
                 "risk_source": "port_rule"}]
    table = report.console_table(findings)
    assert "SOURCE" in table
    assert "port_rule" in table


def test_console_table_source_falls_back_to_dash():
    findings = [{"port": 23, "risk": "critical", "service": "telnet", "version": None,
                 "cves": []}]
    table = report.console_table(findings)
    assert "SOURCE" in table
    assert "-" in table
    assert "port_rule" not in table


def test_raw_lines_omits_risk_fields():
    findings = [{"port": 18083, "service": "unknown", "version": None,
                 "product": None, "exposure": "loopback", "pid": 42,
                 "process": "test-server", "risk": "unknown",
                 "risk_source": "fallback", "confidence": "low", "cves": []}]
    raw = report.raw_lines(findings)
    assert "port=18083" in raw
    assert "exposure=loopback" in raw
    assert "pid=42" in raw
    assert "process=test-server" in raw
    assert "risk=" not in raw
    assert "confidence=" not in raw
    assert "cves=" not in raw


def test_raw_lines_uses_dash_for_missing_values():
    findings = [{"port": 18084}]
    raw = report.raw_lines(findings)
    assert raw == ("port=18084 service=unknown version=- product=- "
                   "exposure=- pid=- process=-")


def test_raw_lines_empty():
    assert report.raw_lines([]) == "No open ports found."


def test_raw_lines_one_line_per_finding():
    findings = [{"port": 1}, {"port": 2}, {"port": 3}]
    assert len(report.raw_lines(findings).splitlines()) == 3


def test_console_table_shows_exposure_and_process():
    findings = [{"port": 6379, "risk": "high", "service": "redis", "version": None,
                 "cves": [], "exposure": "loopback", "process": "redis-server"}]
    table = report.console_table(findings)
    assert "loopback" in table
    assert "redis-server" in table
