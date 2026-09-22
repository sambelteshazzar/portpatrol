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


def test_console_table_shows_exposure_and_process():
    findings = [{"port": 6379, "risk": "high", "service": "redis", "version": None,
                 "cves": [], "exposure": "loopback", "process": "redis-server"}]
    table = report.console_table(findings)
    assert "loopback" in table
    assert "redis-server" in table
