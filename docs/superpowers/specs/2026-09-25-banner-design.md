# PortPatrol Terminal Banner Design

**Date:** 2026-09-25
**Status:** approved for implementation planning

## Goal

A bare `portpatrol` run greets the user with an ASCII wordmark above the scan result, so the first thing a new user sees identifies the tool. Every explicit subcommand keeps the output it has today.

## Requirements

- The banner prints only when the user gives no subcommand (`args.command is None`). `scan`, `watch`, and `explain` print nothing new.
- The banner goes to stderr, followed by one blank line. stdout stays byte-identical to what `portpatrol scan` produces now, so pipes, `grep`, and `--json` consumers see no change.
- The art is pure ASCII with no ANSI escape codes. It renders the same in a pipe, under `NO_COLOR`, in the legacy Windows console, and through a screen reader.
- The art is the figlet `standard` font spelling `PortPatrol`, trailing blank rows and trailing spaces removed: 5 rows, 48 columns at the widest row.
- The art lives in a new module, `portpatrol/banner.py`, as a `BANNER` string constant plus a `print_banner(stream)` helper.
- No runtime dependency is added. pyfiglet generated the art once, in a throwaway virtual environment outside the repository.

## Art

```
 ____            _   ____       _             _
|  _ \ ___  _ __| |_|  _ \ __ _| |_ _ __ ___ | |
| |_) / _ \| '__| __| |_) / _` | __| '__/ _ \| |
|  __/ (_) | |  | |_|  __/ (_| | |_| | | (_) | |
|_|   \___/|_|   \__|_|   \__,_|\__|_|  \___/|_|
```

Trailing whitespace is stripped from every row; the block is left-aligned with no indentation.

## Architecture

`main()` already distinguishes bare runs through `args.command`. After `apply_bare_defaults` fills the scan defaults, `main()` calls `print_banner(sys.stderr)` when `args.command is None`, then dispatches to `args.func(args)` as it does today. `apply_bare_defaults` stays a pure parse-time helper.

`print_banner` writes `BANNER`, a newline, and one blank line to the given stream. The scan pipeline, parser defaults, and exit codes are untouched.

## Error handling

Printing is best-effort. An `OSError` while writing to stderr is caught and ignored; the scan still runs and the exit code still comes from the scan alone.

## Testing strategy

- Bare `main([])` puts the first banner row on stderr and leaves the banner out of stdout.
- `main(["scan", ...])` prints no banner on stderr.
- `BANNER` is ASCII-only, every row is at most 80 columns wide, no row ends in whitespace, and the block has no empty rows.
- `print_banner` writes to the stream it is given (test with `io.StringIO`), leaving stdout alone.
- A stream that raises `OSError` does not propagate; the scan continues.
- The current suite stays green; the banner tests are added on top.

## Out of scope (YAGNI)

- Color, gradients, or animation of any kind. The research on terminal banners shows these need opt-in flags and accessibility handling; this design uses none of it.
- A banner on `--help`, on `version`, or on any subcommand.
- A tagline or version line under the wordmark.
- Rendering figlet fonts at runtime; the art is a constant.
- A `banner` subcommand.

## Compatibility

- Python 3.8+ stdlib only.
- Exit codes and stdout of every existing command stay unchanged.
- Pure ASCII keeps the banner safe in the legacy Windows console, where box-drawing characters misrender.
