# PortPatrol Usability Design

**Date:** 2026-09-25
**Status:** approved for implementation planning

## Goal

Make PortPatrol runnable by people who do not live in a terminal: a bare `portpatrol` command that scans, an installer per operating system, and a double-click launcher on each desktop.

## Requirements

### 1. Bare invocation runs a scan

- `portpatrol` with no subcommand behaves exactly like `portpatrol scan`: same defaults (`--ports top1000`, notifications on, no `--json`, no `--diff`), same output, same exit codes (0 clean, 1 findings, 2 error).
- `portpatrol --help` still lists `scan`, `watch`, and `explain`.
- Unknown top-level arguments still fail with argparse's message and exit `2`.
- Implementation: `add_subparsers(dest="command", required=False)` plus parser-level `set_defaults` carrying every attribute `cmd_scan` reads (`func`, `ports`, `json`, `kev`, `no_notify`, `verbose`, `diff`).

### 2. install.sh (Linux)

- Preflight, in order, each failure printed on its own line and exit `2`:
  1. `python3` exists; version is 3.8 or newer; otherwise point at python.org.
  2. `python3 -m venv` succeeds. Debian and Ubuntu ship venv creation broken until `python3-venv` is installed, so a failure prints `sudo apt install python3-venv` (or the `dnf`/`pacman` equivalent when detected) instead of Python's raw traceback.
  3. `pip install` of the checkout succeeds. The first install downloads the build backend (setuptools), so a pip failure prints that an internet connection is needed the first time.
- Steps: create `~/.portpatrol/venv`, `pip install <checkout>`, symlink `~/.local/bin/portpatrol` to the venv entry point, copy the desktop file with `Exec` rewritten to the absolute venv path.
- Warn when `~/.local/bin` is not on `PATH`, printing the exact `export` line to fix it.
- Idempotent: a second run upgrades the same venv and rewrites the symlink.
- Must take every path from `$HOME` so tests can redirect it with a scratch home directory.

### 3. install.ps1 (Windows)

- Python discovery: `py -3` first, then `python`; version must be 3.8 or newer.
- Venv at `%USERPROFILE%\.portpatrol\venv`, `pip install` the checkout, shim at `%USERPROFILE%\.portpatrol\bin\portpatrol.bat`.
- User `PATH`: read the unexpanded user-scope value from the registry, append the bin directory only when absent, write it back as `ExpandString` so `%VAR%` references survive, broadcast the environment change so new terminals see it, and update the current session. Never use `setx` (it truncates at 1024 characters and rewrites the value as a plain string).
- Start Menu shortcut via the WScript.Shell COM object, targeting the double-click launcher.
- README documents invocation as `powershell -ExecutionPolicy Bypass -File install.ps1` because the default policy blocks downloaded scripts.

### 4. Double-click launchers

- Linux: `portpatrol-desktop.sh` wrapper that runs a scan and then waits for Enter so the window does not close on the result. `examples/desktop/portpatrol.desktop` carries `Type=Application`, `Terminal=true`, `Icon=utilities-system-monitor`, and `Exec=` pointing at the wrapper's absolute path. Paths with spaces are quoted per the freedesktop desktop entry spec (double quotes, no field codes inside quotes).
- Windows: `portpatrol.bat` runs a scan, then `pause`. Resolution order: installed shim, then `py -3 -m portpatrol` with `PYTHONPATH` set to the checkout, then `python -m portpatrol`.
- Both files work standalone for people who copy them by hand; the installers place them.

## Error handling

- Every installer failure names the problem and the fix in one sentence, exits `2`, and never dumps a traceback.
- A pre-existing `portpatrol` on `PATH` is replaced by the installer; the checkout keeps its own `bin/portpatrol` launcher for developers.
- Uninstalled desktop file or missing wrapper degrades to "double-click does nothing": the README's manual copy path still works.

## Testing strategy

- Bare invocation: unit tests on `main([])` for clean exit, findings exit, and help text still listing subcommands.
- `install.sh`: automated test running the script with `HOME` pointed at `tmp_path`, asserting the venv, symlink, and desktop file land inside the scratch home, the installed command answers `explain 22`, and a second run succeeds (idempotency).
- `.desktop` and `.bat`: content assertions (required keys, absolute `Exec`, `pause` present) so the files cannot rot silently.
- `install.ps1`: cannot execute in the Linux development environment; reviewed by hand, and the README says so.

## Out of scope (YAGNI)

- GUI, tray app, or system service (v1 non-goals in the original design).
- Plain-language rewrite of the console table (`explain` already carries the advice).
- Uninstall command; removal is `rm -rf ~/.portpatrol` plus deleting the symlink.
- Publishing to PyPI, auto-update, shell completions.
- macOS: the scripts are POSIX and likely work, but no macOS run happened, so the README makes no macOS claim.

## Compatibility

- Python 3.8+ stdlib only; installers add no runtime dependency.
- Exit codes and existing flags unchanged; bare invocation is additive.
- `bin/portpatrol` stays for source checkouts; developers keep working exactly as before.
