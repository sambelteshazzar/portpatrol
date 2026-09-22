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
