# PortPatrol Usability Implementation Plan

> **For agentic workers:** Implement one task at a time, in order, with TDD (write the failing test, watch it fail, implement, watch it pass, commit). Steps use checkbox (`- [ ]`) syntax for tracking. Run tests from the repo root: `python3 -m pytest tests/ -v`.

**Goal:** a bare `portpatrol` invocation scans, `install.sh`/`install.ps1` set everything up, and double-click launchers exist for both desktops.

**Architecture:** parser-level defaults make `main([])` route to `cmd_scan`; installers build a venv under `~/.portpatrol/` and put a shim on `PATH`; launchers are a desktop-file wrapper on Linux and a `pause`-ending `.bat` on Windows.

**Tech Stack:** Python 3.8+ stdlib only for the app; POSIX shell for `install.sh`; PowerShell 5.1+ for `install.ps1`; pytest.

## Global Constraints

- Exit codes unchanged: `scan` 0/1/2; bare invocation identical to `scan`.
- Every path in `install.sh` derives from `$HOME` so tests can redirect it.
- Installers never print Python tracebacks; each failure is one sentence naming the fix.
- `install.ps1` preserves the registry `PATH` type and broadcasts the change; no `setx`.
- Windows files are reviewed, not executed, in this environment; the README states that.
- Spec: `docs/superpowers/specs/2026-09-25-usability-design.md`.

---

### Task 1: Bare invocation runs a scan

**Files:** `portpatrol/cli.py`, `tests/test_cli.py`

- [x] **Step 1: Write the failing tests**
  - `main([])` with a clean sweep returns `0` and prints the all-clear line.
  - `main([])` with a finding returns `1`.
  - `build_parser().format_help()` still lists `scan`, `watch`, `explain`.
  - `parse_args([])` carries scan defaults (`ports == "top1000"`, `json/kev/no_notify/verbose/diff` all `False`, `func` is `cmd_scan`).
- [x] **Step 2: Run the tests to verify they fail**
- [x] **Step 3: Implement**: `add_subparsers(dest="command")` without `required=True`, plus `apply_bare_defaults` filling scan defaults after parse (parser-level `set_defaults` leaked `json`/`diff` onto the watch namespace, which an existing test forbids).
- [x] **Step 4: Run the tests to verify they pass**, full suite green.
- [x] **Step 5: Commit** `feat: bare portpatrol invocation runs a default scan`

### Task 2: Desktop launcher files

**Files:** `portpatrol-desktop.sh`, `examples/desktop/portpatrol.desktop`, `tests/test_launchers.py`

- [x] **Step 1: Write the failing tests**: desktop file has `Type=Application`, `Terminal=true`, an `Exec` line whose first token is absolute-path-safe per the spec's reserved-character rules, `Icon`, `Categories`; the shell wrapper ends with a `read` so the terminal stays open and calls `portpatrol scan`.
- [x] **Step 2: Run the tests to verify they fail**
- [x] **Step 3: Implement** the wrapper and desktop file (bare-name `Exec`, resolved via `PATH`; the installer rewrites it to an absolute path).
- [x] **Step 4: Run the tests to verify they pass**
- [x] **Step 5: Commit** `feat: desktop launcher and terminal wrapper`

### Task 3: install.sh

**Files:** `install.sh`, `tests/test_installers.py`

- [x] **Step 1: Write the failing tests**: run `bash install.sh` with `HOME` set to `tmp_path` and `PATH` containing the real `python3`; assert `~/.portpatrol/venv` exists, `~/.local/bin/portpatrol` is a symlink into the venv, `~/.local/share/applications/portpatrol.desktop` has an absolute `Exec`, the installed command answers `explain 22` with `ssh`, and a second run exits `0`.
- [x] **Step 2: Run the tests to verify they fail**
- [x] **Step 3: Implement** `install.sh`: preflight (python3, version, venv, pip), venv build, install, symlink, desktop copy with `Exec` rewrite, `PATH` warning, plain-language failures. Manually re-verified under `/bin/sh` (not just bash) with a scratch home.
- [x] **Step 4: Run the tests to verify they pass**
- [x] **Step 5: Commit** `feat: install.sh for Linux`

### Task 4: install.ps1 and portpatrol.bat

**Files:** `install.ps1`, `portpatrol.bat`, additions to `tests/test_launchers.py`

- [x] **Step 1: Write the failing tests**: content assertions: `.bat` ends with `exit /b` after `pause`, prefers the installed venv entry point, falls back to `py -3 -m portpatrol` with `PYTHONPATH`; `install.ps1` contains the registry-preserving PATH helper, the `ExpandString` write, the `WM_SETTINGCHANGE` broadcast, and no `setx`.
- [x] **Step 2: Run the tests to verify they fail**
- [x] **Step 3: Implement** both files per the spec (Python discovery, venv, shim, PATH, shortcut). The double-click `.bat` prefers the installed venv executable; the installer writes a separate no-pause shim so interactive commands stay interactive.
- [x] **Step 4: Run the tests to verify they pass**
- [x] **Step 5: Commit** `feat: install.ps1 and Windows double-click launcher`

### Task 5: README

**Files:** `README.md`

- [x] **Step 1: Rewrite Install** around `./install.sh` and `install.ps1`, keep the source-checkout paths, document bare `portpatrol`, add launcher instructions, state plainly that Windows files were not executed here.
- [x] **Step 2: Slop pass**: no em dashes in prose, sentence-case headings, no bold-label lists, no claim that was not verified in this environment.
- [x] **Step 3: Commit** `docs: installer and bare-invocation instructions`

### Task 6: Verification

- [x] **Step 1:** `python3 -m pytest` green (122 passed, exit 0, run fresh after all feature commits).
- [x] **Step 2:** bare `portpatrol` runs a real scan from the repo checkout (`./bin/portpatrol` printed the table, exit 1 for present findings).
- [x] **Step 3:** scratch-home `install.sh` run works end to end: install exit 0, installed `explain 22` exit 0, installed bare command exit 1 with findings, unknown top-level flag exit 2, absolute `Exec` in the installed desktop file.
- [ ] **Step 4:** push.
