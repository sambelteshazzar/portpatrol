# Finding provenance and raw output implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show how each risk value was selected and provide a raw observation view that does not apply PortPatrol's risk model.

**Architecture:** Keep the current scan pipeline, then attach provenance metadata during risk classification. Add a report renderer for the existing table and a separate raw renderer. `--raw` uses the same collection pipeline with diff, notification, and history side effects disabled, so a raw report cannot overwrite the normal watch/scan baseline.

**Tech Stack:** Python 3.8+, standard library, pytest, `ss` on Linux when available.

## Global Constraints

- Preserve the current risk values, exit codes, notification behavior, history format compatibility, and diff semantics when `--raw` is absent.
- `risk_source` is one of `port_rule`, `service_rule`, `exposure_adjusted`, or `fallback`.
- `confidence` is one of `high`, `medium`, or `low`.
- Raw output contains observed/collected fields only: port, service, version, product, exposure, PID, and process.
- Raw output does not write history or a diff baseline and does not notify.
- Do not add third-party dependencies.
- Use existing project style and no source-code comments.

---

### Task 1: Classify findings with provenance

**Files:**
- Modify: `portpatrol/knowledge.py:103-120`
- Modify: `portpatrol/cli.py:90-102`
- Test: `tests/test_knowledge.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Produces `knowledge.classify_port_with_source(kb, port, service=None, svc_index=None) -> tuple[str, str, str]`.
- The tuple is `(risk, risk_source, confidence)` before exposure adjustment.
- Existing `classify_port(...) -> str` remains available and delegates to the new function.

- [ ] **Step 1: Write failing tests for the classification paths**

Add tests to `tests/test_knowledge.py` for a direct port entry, a service match when the port is absent, and an unmatched port. Assert the exact tuple for each path:

```python
def test_classify_port_with_source_uses_port_rule():
    kb = {22: {"port": 22, "service": "ssh", "risk": "info"}}
    assert knowledge.classify_port_with_source(kb, 22) == ("info", "port_rule", "high")


def test_classify_port_with_source_uses_service_rule():
    kb = {22: {"port": 22, "service": "ssh", "risk": "info"}}
    assert knowledge.classify_port_with_source(kb, 2222, "ssh") == (
        "info", "service_rule", "high"
    )


def test_classify_port_with_source_falls_back():
    assert knowledge.classify_port_with_source({}, 40000) == (
        "unknown", "fallback", "low"
    )
```

- [ ] **Step 2: Run the new tests and verify they fail**

Run: `python3 -m pytest tests/test_knowledge.py -k 'classify_port_with_source' -q`

Expected: FAIL because `classify_port_with_source` does not exist.

- [ ] **Step 3: Implement the classification helper**

Add the helper before the existing `classify_port` function. A port entry takes precedence. If no port entry exists, a detected service is looked up in the supplied service index. Invalid or missing risks return `unknown` with `fallback` and `low`. `classify_port` returns only the first tuple element.

```python
def classify_port_with_source(kb, port, service=None, svc_index=None):
    entry = kb.get(port)
    if entry is not None:
        risk = entry.get("risk")
        if risk in VALID_RISKS:
            return risk, "port_rule", "high"
    if service:
        index = service_index(kb) if svc_index is None else svc_index
        matched = index.get(service)
        if matched is not None:
            risk = matched.get("risk")
            if risk in VALID_RISKS:
                return risk, "service_rule", "high"
    return "unknown", "fallback", "low"
```

- [ ] **Step 4: Add pipeline tests for exposure-adjusted and fallback fields**

Extend the existing `_patch_scan` test helper only as needed. Add assertions to a scan test for a loopback port rule that the result has `risk_source == "exposure_adjusted"` and `confidence == "medium"`, and a test for an unknown port with `risk_source == "fallback"` and `confidence == "low"`.

- [ ] **Step 5: Wire provenance into `run_scan`**

Replace the separate `classify_port` and exposure adjustment block with:

```python
risk, risk_source, confidence = knowledge.classify_port_with_source(
    kb, f["port"], service, svc_index
)
f["risk"] = knowledge.adjust_risk_for_exposure(risk, f["exposure"])
if f["risk"] != risk:
    risk_source = "exposure_adjusted"
    confidence = "medium"
f["risk_source"] = risk_source
f["confidence"] = confidence
```

This preserves the existing risk value and marks only a real exposure downgrade as adjusted.

- [ ] **Step 6: Run focused and full tests**

Run: `python3 -m pytest tests/test_knowledge.py tests/test_cli.py -q`

Expected: PASS with existing tests and the new provenance tests.

- [ ] **Step 7: Commit**

```bash
git add portpatrol/knowledge.py portpatrol/cli.py tests/test_knowledge.py tests/test_cli.py
git commit -m "feat: expose risk provenance"
```

### Task 2: Add source to reports and raw rendering

**Files:**
- Modify: `portpatrol/report.py:11-28`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes findings with optional `risk_source`.
- Produces `report.raw_lines(findings) -> str`, one raw line per finding.
- `console_table(findings)` includes a `SOURCE` column and uses `-` for older fixtures without provenance.

- [ ] **Step 1: Write failing report tests**

Add tests for a source column and raw rendering:

```python
def test_console_table_shows_risk_source():
    findings = [{"port": 22, "risk": "info", "service": "ssh", "version": None,
                 "cves": [], "exposure": "loopback", "process": "sshd",
                 "risk_source": "port_rule"}]
    table = report.console_table(findings)
    assert "SOURCE" in table
    assert "port_rule" in table


def test_raw_lines_omits_risk_fields():
    findings = [{"port": 18083, "service": "unknown", "version": None,
                 "product": None, "exposure": "loopback", "pid": 42,
                 "process": "test-server", "risk": "unknown",
                 "risk_source": "fallback", "confidence": "low", "cves": []}]
    raw = report.raw_lines(findings)
    assert "port=18083" in raw
    assert "exposure=loopback" in raw
    assert "pid=42" in raw
    assert "process=test-server" in raw
    assert "risk=" not in raw
    assert "confidence=" not in raw
    assert "cves=" not in raw
```

- [ ] **Step 2: Run the report tests and verify they fail**

Run: `python3 -m pytest tests/test_report.py -k 'source or raw' -q`

Expected: FAIL because the source column and `raw_lines` do not exist.

- [ ] **Step 3: Implement the report changes**

Add `SOURCE` to the header and each row using `f.get("risk_source", "-")`. Keep the existing width and sorting behavior. Add:

```python
def raw_lines(findings):
    if not findings:
        return "No open ports found."
    lines = []
    for f in findings:
        lines.append(
            f"port={f['port']} service={f.get('service') or 'unknown'} "
            f"version={f.get('version') or '-'} product={f.get('product') or '-'} "
            f"exposure={f.get('exposure') or '-'} pid={f.get('pid') or '-'} "
            f"process={f.get('process') or '-'}"
        )
    return "\n".join(lines)
```

- [ ] **Step 4: Run report tests and verify they pass**

Run: `python3 -m pytest tests/test_report.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add portpatrol/report.py tests/test_report.py
git commit -m "feat: add raw finding report"
```

### Task 3: Add `scan --raw` without side effects

**Files:**
- Modify: `portpatrol/cli.py:31-53, 129-168, 236-247`
- Test: `tests/test_cli.py`

**Interfaces:**
- Adds parser attribute `raw=False` for `scan`.
- `cmd_scan` prints raw lines when `args.raw` is true and returns the existing scan exit code.
- Raw mode forces `args.diff = False`, suppresses notifications, and does not append history.

- [ ] **Step 1: Write failing CLI tests**

Add parser and behavior tests. Patch scan dependencies with `_patch_scan`, patch `HISTORY_PATH` and `STATE_PATH`, and set `--no-notify` so the test isolates output and files:

```python
def test_scan_raw_parser_flag():
    assert cli.build_parser().parse_args(["scan", "--raw"]).raw is True


def test_scan_raw_prints_evidence_without_writing_state(monkeypatch, tmp_path, capsys):
    _patch_scan(monkeypatch, tmp_path, [18083], identify_service="unknown")
    monkeypatch.setattr(cli, "STATE_PATH", tmp_path / "state.json")
    result = cli.main(["scan", "--raw", "--ports", "18083"])
    assert result == 1
    out = capsys.readouterr().out
    assert "port=18083" in out
    assert "risk=" not in out
    assert not (tmp_path / "state.json").exists()
    assert not (tmp_path / "history.json").exists()
```

Add a test that passes `--raw --diff` and confirms no state file is created. Add a bare-invocation assertion that `args.raw is False` after `apply_bare_defaults`.

- [ ] **Step 2: Run the new CLI tests and verify they fail**

Run: `python3 -m pytest tests/test_cli.py -k 'raw or bare_invocation' -q`

Expected: FAIL because `--raw` is unknown and bare defaults do not set `raw`.

- [ ] **Step 3: Add the parser and bare default**

Add `scan.add_argument("--raw", action="store_true", help="print observed port evidence without risk interpretation")` and set `args.raw = False` in `apply_bare_defaults`.

- [ ] **Step 4: Add the raw command branch**

At the start of `cmd_scan`, preserve the original diff choice and disable it for raw mode:

```python
if args.raw:
    args.diff = False
outcome = run_scan(args)
if outcome.result is None:
    return outcome.exit_code
if args.raw:
    print(report.raw_lines(outcome.result["open"]))
    return outcome.exit_code
```

Import the renderer explicitly: change the existing report import to `from portpatrol.report import append_history, console_table, raw_lines, to_json` and call `raw_lines(...)`. Do not call notification or history code on this branch.

- [ ] **Step 5: Run CLI tests and verify they pass**

Run: `python3 -m pytest tests/test_cli.py -q`

Expected: PASS, including the existing watch, diff, notification, and history tests.

- [ ] **Step 6: Commit**

```bash
git add portpatrol/cli.py tests/test_cli.py
git commit -m "feat: add raw scan output"
```

### Task 4: Add real-host integration coverage and update user documentation

**Files:**
- Create: `tests/test_integration.py`
- Modify: `README.md:101-117, 165-189`

**Interfaces:**
- Consumes the public `cli.main` and real loopback socket/listener discovery.
- Produces one platform-aware integration test that skips only when the host lacks the required OS listener command.

- [ ] **Step 1: Write the integration test**

Create a real ephemeral listener in a context manager or `try/finally`. Run `cli.main(["scan", "--no-notify", "--json", "--ports", str(port)])`, parse stdout, and assert the returned port is present. If `shutil.which("ss")` is available on Linux, assert `exposure == "loopback"`. Use `pytest.mark.skipif` only for the platform/tool condition, and do not mock the socket or listener parser.

```python
@pytest.mark.skipif(sys.platform == "win32" or shutil.which("ss") is None,
                    reason="loopback listener inventory requires ss")
def test_real_loopback_listener_is_reported(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "HISTORY_PATH", tmp_path / "history.json")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        result = cli.main(["scan", "--no-notify", "--json", "--ports", str(port)])
    assert result == 1
    finding = json.loads(capsys.readouterr().out)["open"][0]
    assert finding["port"] == port
    assert finding["exposure"] == "loopback"
```

Patch nmap enrichment to `{}` only if the test must remain focused on listener inventory; otherwise allow the normal optional path and keep the test bounded to the selected port.

- [ ] **Step 2: Run the integration test**

Run: `python3 -m pytest tests/test_integration.py -q` (or the exact file if the existing test layout places it in `test_cli.py`).

Expected: PASS on this Linux host, or a single clear skip when `ss` is unavailable.

- [ ] **Step 3: Update README behavior and examples**

Document the `SOURCE` column, the four `risk_source` values, confidence values, and the fact that risk is a knowledge-base estimate. Add the raw command and example output. State that raw mode does not update `state.json` or `history.json`, and that integration coverage is host-dependent.

Use the existing README voice. Do not describe the result as a complete vulnerability assessment or call the risk value a verified vulnerability.

- [ ] **Step 4: Run the complete test suite and static checks**

Run: `python3 -m pytest -q`

Expected: all tests pass.

Run: `python3 -m compileall -q portpatrol tests`

Expected: exit 0.

Run the repository's configured linter if present. `ruff` is installed in this checkout; use `ruff check portpatrol tests` and distinguish pre-existing findings from findings in changed lines.

- [ ] **Step 5: Commit**

```bash
git add tests/test_cli.py tests/test_integration.py README.md
git commit -m "test: cover real loopback findings"
```

## Final verification

- [ ] `git status --short` shows only intended changes.
- [ ] `git diff --check` passes.
- [ ] The full pytest suite passes.
- [ ] The integration test runs or reports a documented platform skip.
- [ ] README examples match the implemented raw format and provenance values.
