# PortPatrol Watch Mode Design

**Date:** 2026-09-22
**Status:** approved for implementation planning

## Goal

`portpatrol watch` continuously re-scans localhost on a fixed interval and reports only when open-port findings change — near-real-time complement to the daily systemd timer.

## Requirements

- Command: `portpatrol watch [--interval SECONDS] [--ports SPEC] [--kev] [--no-notify] [--verbose]`
- `--interval`: seconds between scans; default `60`; minimum `1`; non-integer or `< 1` exits `2` before the loop starts.
- `--ports`: same spec grammar as `scan` (`top50|top100|top1000|all|80,443|8000-8100`); invalid spec exits `2` before the loop starts.
- No `--json` flag: an infinite loop has no single JSON document to emit.
- Terminal output is silent while findings are unchanged. On change, print the same change summary used for toasts (`diff.changes_message`) to stdout.
- Desktop notifications: same behavior as `scan --diff` — baseline/first-cycle all-clear toast once, change toast on each change cycle, per-critical detail toasts for newly open critical ports. `--no-notify` suppresses all of them.
- `--verbose` logs one line per cycle to stderr (cycle number, open count, change count); stdout stays silent on quiet cycles.
- Ctrl+C exits `0`. Pre-loop validation errors exit `2`.
- Exit code of a completed cycle does not terminate the loop (watch always returns to sleep).

## State and history

- Watch reads and writes the shared baseline `~/.portpatrol/state.json` via the existing diff engine — identical semantics to `scan --diff` (single snapshot; service/version comparison; allowlist suppresses only `new`).
- A running watch keeps the daily systemd timer's baseline fresh.
- `history.json` is appended only on cycles where `diff.has_changes(changes)` is true (prevents unbounded growth at one entry per interval).
- Baseline establishment (first cycle with no prior state) does not append history. Only real new/changed/gone transitions append.

## Architecture

Approach A: extract a shared scan pipeline.

1. **`run_scan(args) -> ScanOutcome`** (namedtuple or simple class) extracted from `cmd_scan`:
   - parses `--ports`; on invalid spec prints `portpatrol: {exc}` to stderr (same message `scan` emits today) and returns `exit_code=2` with `result=None` (callers return `2` without printing/notifying/history),
   - sweeps, identifies, enriches (nmap), classifies risk + exposure,
   - optional KEV enrichment,
   - when diff is enabled: load state → `compute_changes` → `save_state`,
   - builds the result document (`timestamp`, `target`, `scanned`, `open`, optional `changes`/`baseline`),
   - performs **no** printing, notifying, or history append.
   - Fields: `exit_code: int`, `result: dict`, `changes: dict | None`, `baseline: bool`.
2. **`cmd_scan`** becomes a thin wrapper: call `run_scan`, print table/JSON, notify, `append_history`, return `exit_code`. Behavior must remain identical (existing test suite is the contract).
3. **`cmd_watch`**:
   - validate interval (and ports via `run_scan`'s first call — ports are validated once before entering the loop, using `knowledge.parse_port_spec` directly so a bad spec never starts the loop),
   - loop forever: force `diff=True` on args → `run_scan` → on `has_changes(changes)`: print change message, notify, `append_history(result)` → optional verbose stderr line → `sleep(interval)`,
   - first cycle with no prior state establishes the baseline (all-clear toast unless `--no-notify`; no history append),
   - `KeyboardInterrupt` → return `0`.

## Error handling

- Invalid `--ports` or `--interval` before loop: message on stderr, exit `2`.
- Missing `ss`/`netstat`: existing behavior — findings get `exposure=unknown`, verbose note; the loop continues.
- Unexpected exception inside a cycle propagates: message on stderr, exit `2` (do not silently swallow scan failures forever).

## Testing strategy

- Existing 88 tests must stay green after the `cmd_scan` extraction (they define `cmd_scan`'s contract).
- New unit tests for `run_scan`: returns findings/changes/baseline without printing or notifying; invalid ports surfaces as exit-code-2 path.
- New unit tests for `cmd_watch` with monkeypatched `time.sleep` that raises `KeyboardInterrupt` after N iterations, fake `run_scan` results:
  - quiet cycles: no stdout, no notify, no history append,
  - change cycle: stdout contains change message, notify called, history appended once,
  - baseline-first cycle: all-clear notify, no history append,
  - `--verbose`: stderr line per cycle.
- Interval validation: `0`, `-1`, `abc` → exit `2`, loop never entered (assert `sleep` not called).

## Out of scope (YAGNI)

- Event-driven/netlink detection, hybrid modes.
- JSON streaming output.
- Separate watch state file (state is shared by design).
- Config file for interval/ports (flags only).
- Graceful per-cycle retry/backoff on transient errors — a cycle error exits `2` so the daily timer/user sees the failure.

## Compatibility

- Python 3.8+ stdlib only.
- Exit codes unchanged for `scan`: 0 clean, 1 findings, 2 error.
- Daily systemd timer and example units unchanged (`scan --diff` remains the cron entry point; watch is an interactive/session tool).
