import json
import shutil
import socket
import sys

import pytest

from portpatrol import cli, listeners


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("ss") is None,
    reason="loopback listener inventory requires ss",
)
def test_real_loopback_listener_is_reported(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
    monkeypatch.setattr("portpatrol.scanner.enrich_with_nmap", lambda ports, **kw: {})

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        if port not in listeners.collect_listeners():
            pytest.skip("host listener inventory does not expose the test listener")

        result = cli.main([
            "scan", "--no-notify", "--json", "--ports", str(port)
        ])

    assert result == 1
    finding = json.loads(capsys.readouterr().out)["open"][0]
    assert finding["port"] == port
    assert finding["exposure"] == "loopback"
