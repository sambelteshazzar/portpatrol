import json
import os
import shutil
import socket

import pytest

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


def test_diff_flag_exists():
    args = cli.build_parser().parse_args(["scan", "--diff"])
    assert args.diff is True
    args = cli.build_parser().parse_args(["scan"])
    assert args.diff is False


def _patch_scan(monkeypatch, tmp_path, open_ports, identify_service="ssh"):
    monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
    monkeypatch.setattr(cli, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr("portpatrol.scanner.sweep", lambda ports, **kw: open_ports)
    monkeypatch.setattr("portpatrol.scanner.identify",
                        lambda p, e, i, **kw: {"port": p, "service": identify_service,
                                               "version": None})
    monkeypatch.setattr("portpatrol.scanner.enrich_with_nmap", lambda ports, **kw: {})


def test_diff_first_run_establishes_baseline(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [])
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    assert cli.main(["scan", "--diff", "--ports", "80"]) == 0
    assert len(calls) == 1
    assert "all clear" in calls[0][1]
    assert (tmp_path / "state.json").exists()


def test_diff_unchanged_second_run_is_silent(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [22])
    import json as _json
    (tmp_path / "state.json").write_text(_json.dumps(
        {"version": 1, "open": [{"port": 22, "service": "ssh", "version": None, "risk": "info"}]}
    ), encoding="utf-8")
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    assert cli.main(["scan", "--diff", "--ports", "22"]) == 1
    assert calls == []


def test_diff_new_port_toasts_changes(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [8080], identify_service="http-proxy")
    import json as _json
    (tmp_path / "state.json").write_text(
        _json.dumps({"version": 1, "open": []}), encoding="utf-8")
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    assert cli.main(["scan", "--diff", "--ports", "8080"]) == 1
    assert len(calls) == 1
    assert calls[0][1].startswith("🆕")
    assert "8080" in calls[0][1]


def test_diff_json_includes_changes(monkeypatch, tmp_path, capsys):
    _patch_scan(monkeypatch, tmp_path, [22])
    import json as _json
    (tmp_path / "state.json").write_text(
        _json.dumps({"version": 1, "open": []}), encoding="utf-8")
    cli.main(["scan", "--diff", "--json", "--no-notify", "--ports", "22"])
    out = _json.loads(capsys.readouterr().out)
    assert out["baseline"] is False
    assert [f["port"] for f in out["changes"]["new"]] == [22]


def test_non_diff_runs_do_not_touch_state(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [])
    cli.main(["scan", "--no-notify", "--ports", "80"])
    assert not (tmp_path / "state.json").exists()


def test_diff_new_critical_gets_detail_toast(monkeypatch, tmp_path):
    _patch_scan(monkeypatch, tmp_path, [6379], identify_service="redis")
    import json as _json
    (tmp_path / "state.json").write_text(
        _json.dumps({"version": 1, "open": []}), encoding="utf-8")
    calls = []
    monkeypatch.setattr(cli, "notify", lambda t, b: calls.append((t, b)) or True)
    cli.main(["scan", "--diff", "--ports", "6379"])
    assert calls[0][1].startswith("🚨")
    assert calls[1][0].startswith("🚨 Port 6379")


def test_verbose_notes_missing_listener_table(monkeypatch, tmp_path, capsys):
    _patch_scan(monkeypatch, tmp_path, [22])
    monkeypatch.setattr("portpatrol.listeners.collect_listeners", lambda: {})
    cli.main(["scan", "--no-notify", "--verbose", "--ports", "22"])
    assert "listener table" in capsys.readouterr().err


@pytest.mark.skipif(shutil.which("ss") is None, reason="ss not installed")
def test_scan_loopback_listener_downgrades_risk_and_attributes_pid(monkeypatch, tmp_path):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.bind(("127.0.0.1", 6379))
    except OSError:
        srv.close()
        pytest.skip("port 6379 busy")
    srv.listen(5)
    try:
        monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
        monkeypatch.setattr("portpatrol.scanner.identify",
                            lambda p, e, i, **kw: {"port": p, "service": "redis",
                                                   "version": None})
        monkeypatch.setattr("portpatrol.scanner.enrich_with_nmap", lambda ports, **kw: {})
        assert cli.main(["scan", "--no-notify", "--ports", "6379"]) == 1
        history = json.loads((tmp_path / "history.json").read_text(encoding="utf-8"))
        f = history[0]["open"][0]
        assert f["exposure"] == "loopback"
        assert f["risk"] == "high"
        assert f["pid"] == os.getpid()
        assert f["process"]
    finally:
        srv.close()


def test_findings_json_include_exposure_fields(monkeypatch, tmp_path, capsys):
    _patch_scan(monkeypatch, tmp_path, [22])
    monkeypatch.setattr("portpatrol.listeners.collect_listeners",
                        lambda: {22: {"pid": 1, "process": "sshd", "bind": "0.0.0.0"}})
    cli.main(["scan", "--no-notify", "--json", "--ports", "22"])
    out = json.loads(capsys.readouterr().out)
    f = out["open"][0]
    assert f["exposure"] == "interface"
    assert f["pid"] == 1
    assert f["process"] == "sshd"
    assert f["risk"] == "info"
