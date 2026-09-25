import io

from portpatrol import banner


def test_banner_art_properties():
    rows = banner.BANNER.splitlines()
    assert len(rows) == 5
    assert all(row.isascii() for row in rows)
    assert all(row for row in rows), "banner must have no empty rows"
    assert all(row == row.rstrip() for row in rows), "no trailing whitespace"
    assert max(len(row) for row in rows) <= 48
    assert "\x1b" not in banner.BANNER, "no ANSI escapes"


def test_print_banner_writes_art_and_blank_line():
    stream = io.StringIO()
    banner.print_banner(stream)
    assert stream.getvalue() == banner.BANNER + "\n\n"


def test_print_banner_ignores_oserror():
    class BrokenStream:
        def write(self, text):
            raise OSError("stream is gone")

    banner.print_banner(BrokenStream())
