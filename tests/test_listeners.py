import os
import shutil
import socket
from unittest import mock

import pytest

from portpatrol import listeners

SS_SAMPLE = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      4096   127.0.0.1:631      0.0.0.0:*         users:("cupsd",pid=1234,fd=5)
LISTEN 0      511    0.0.0.0:80          0.0.0.0:*         users:(("nginx",pid=99,fd=6))
LISTEN 0      128    [::1]:8080          [::]:*            users:("python3",pid=42,fd=7)
LISTEN 0      128    192.168.1.10:3000   0.0.0.0:*
LISTEN 0      128    127.0.0.1:5432      0.0.0.0:*         users:("postgres",pid=7,fd=3)
LISTEN 0      128    0.0.0.0:5432        0.0.0.0:*
"""

NETSTAT_SAMPLE = """
  TCP    127.0.0.1:135           0.0.0.0:0              LISTENING       1234
  TCP    0.0.0.0:445             0.0.0.0:0              LISTENING       4
  TCP    [::1]:5357              [::]:0                 LISTENING       888
  UDP    0.0.0.0:500             *:0                                    999
"""


def test_parse_ss_extracts_pid_process_bind():
    out = listeners.parse_ss(SS_SAMPLE)
    assert out[631] == {"pid": 1234, "process": "cupsd", "bind": "127.0.0.1"}
    assert out[80]["process"] == "nginx"
    assert out[80]["pid"] == 99
    assert out[8080]["bind"] == "::1"
    assert out[3000]["bind"] == "192.168.1.10"
    assert out[3000]["pid"] is None
    assert out[3000]["process"] is None


def test_parse_ss_dual_bind_prefers_interface_and_keeps_pid():
    out = listeners.parse_ss(SS_SAMPLE)
    assert out[5432]["bind"] == "0.0.0.0"
    assert out[5432]["pid"] == 7
    assert out[5432]["process"] == "postgres"


def test_parse_ss_skips_header_and_short_lines():
    out = listeners.parse_ss("State\nLISTEN\nGARBAGE LINE ONLY\n")
    assert out == {}


def test_parse_netstat_extracts_listeners_and_skips_udp():
    out = listeners.parse_netstat(NETSTAT_SAMPLE)
    assert out[135] == {"pid": 1234, "process": None, "bind": "127.0.0.1"}
    assert out[445]["pid"] == 4
    assert out[5357]["bind"] == "::1"
    assert 500 not in out


def test_classify_exposure_loopback():
    assert listeners.classify_exposure("127.0.0.1") == "loopback"
    assert listeners.classify_exposure("127.0.0.53") == "loopback"
    assert listeners.classify_exposure("::1") == "loopback"


def test_classify_exposure_interface_and_unknown():
    assert listeners.classify_exposure("0.0.0.0") == "interface"
    assert listeners.classify_exposure("::") == "interface"
    assert listeners.classify_exposure("*") == "interface"
    assert listeners.classify_exposure("192.168.1.10") == "interface"
    assert listeners.classify_exposure(None) == "unknown"
    assert listeners.classify_exposure("") == "unknown"


def test_collect_linux_uses_ss():
    with mock.patch.object(listeners.shutil, "which", return_value="/usr/bin/ss"), \
         mock.patch.object(listeners, "_run", return_value=SS_SAMPLE):
        out = listeners.collect_listeners()
    assert out[631]["process"] == "cupsd"


def test_collect_windows_uses_netstat():
    with mock.patch.object(listeners.sys, "platform", "win32"), \
         mock.patch.object(listeners, "_run", return_value=NETSTAT_SAMPLE):
        out = listeners.collect_listeners()
    assert out[135]["pid"] == 1234


def test_collect_returns_empty_when_unavailable():
    with mock.patch.object(listeners.sys, "platform", "linux"), \
         mock.patch.object(listeners.shutil, "which", return_value=None):
        assert listeners.collect_listeners() == {}


@pytest.mark.skipif(shutil.which("ss") is None, reason="ss not installed")
def test_collect_live_finds_own_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        out = listeners.collect_listeners()
        assert out[port]["pid"] == os.getpid()
        assert listeners.classify_exposure(out[port]["bind"]) == "loopback"
    finally:
        srv.close()
