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
