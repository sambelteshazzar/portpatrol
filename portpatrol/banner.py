"""ASCII wordmark printed on bare invocation."""

from __future__ import annotations

BANNER = "\n".join((
    " ____            _   ____       _             _",
    "|  _ \\ ___  _ __| |_|  _ \\ __ _| |_ _ __ ___ | |",
    "| |_) / _ \\| '__| __| |_) / _` | __| '__/ _ \\| |",
    "|  __/ (_) | |  | |_|  __/ (_| | |_| | | (_) | |",
    "|_|   \\___/|_|   \\__|_|   \\__,_|\\__|_|  \\___/|_|",
))


def print_banner(stream):
    """Write the wordmark and a blank line to stream, best-effort."""
    try:
        stream.write(BANNER + "\n\n")
    except OSError:
        pass
