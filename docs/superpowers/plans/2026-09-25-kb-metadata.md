# Knowledge-base source metadata implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Report which knowledge base supplied each scan's ratings, including the file path and any repaired risk values.

**Architecture:** Add a metadata-aware loader in `knowledge.py` and keep the existing loader as a dictionary-returning wrapper. `run_scan` embeds four top-level metadata fields in normal results, while `cmd_explain` prints the source and path. Diff state stays slim and unchanged.

**Tech Stack:** Python 3.8+, standard library, pytest.

## Global Constraints

- Keep `load_knowledge_base(user_path=None) -> dict` backward compatible.
- Add `load_knowledge_base_with_source(user_path=None) -> (dict, dict)`.
- Source values are exactly `user`, `package`, or `defaults`.
- Metadata keys are `source`, `path`, `entries`, and `repaired` internally; scan JSON keys are `knowledge_base_source`, `knowledge_base_path`, `knowledge_base_entries`, and `knowledge_base_repaired`.
- Do not change risk values, diff state keys, notifications, exit codes, raw rendering, or watch behavior.
- Do not add third-party dependencies or source-code comments.

---

### Task 1: Add metadata-aware knowledge-base loading

**Files:**
- Modify: `portpatrol/knowledge.py:32-79`
- Test: `tests/test_knowledge.py`

**Interfaces:**
- Produces `knowledge.load_knowledge_base_with_source(user_path=None) -> (dict, dict)`.
- Metadata shape: `{"source": str, "path": str | None, "entries": int, "repaired": int}`.
- Existing `load_knowledge_base(user_path=None) -> dict` delegates to the new function.

- [ ] **Step 1: Write failing tests for source metadata**

Add a helper for a valid temporary entry and tests for an explicit user file, a missing user file falling back to the package, and an invalid package path falling back to defaults. Assert exact metadata:

```python
def _write_kb(path, port=22, risk="info"):
    entry = {"port": port, "protocol": "tcp", "service": "ssh",
             "risk": risk, "banner_first": False, "probe": None,
             "match": [], "advice": "test advice", "kev_hints": []}
    path.write_text(json.dumps([entry]), encoding="utf-8")
    return path


def test_load_with_source_reports_user_file(tmp_path):
    path = _write_kb(tmp_path / "kb.json", 22, "info")
    entries, meta = knowledge.load_knowledge_base_with_source(user_path=path)
    assert list(entries) == [22]
    assert meta == {"source": "user", "path": str(path), "entries": 1, "repaired": 0}


def test_load_with_source_reports_package(monkeypatch, tmp_path):
    monkeypatch.setattr(knowledge.Path, "home", lambda: tmp_path)
    entries, meta = knowledge.load_knowledge_base_with_source()
    assert meta["source"] == "package"
    assert meta["path"] == str(knowledge.PACKAGE_KB)
    assert meta["entries"] == len(entries)
    assert meta["repaired"] == 0
```

Use `monkeypatch.setattr(knowledge, "PACKAGE_KB", tmp_path / "missing.json")` for the defaults case, and assert the exact `{"source": "defaults", "path": None, ...}` shape. Add `assert isinstance(knowledge.load_knowledge_base(...), dict)` for the compatibility wrapper.

- [ ] **Step 2: Run the tests and verify they fail**

Run: `python3 -m pytest tests/test_knowledge.py -k 'with_source or repaired' -q`

Expected: FAIL because `load_knowledge_base_with_source` does not exist.

- [ ] **Step 3: Implement the loader and repaired count**

Refactor the candidate loop into one helper that returns the selected path, source label, entries list, and repaired count. Count an entry when `_normalize_risk` sets `RISK_REPAIRED_KEY`. Preserve the existing stderr warning and resolution order. Return metadata with `entries` set to the number of selected entries.

```python
def load_knowledge_base_with_source(user_path=None):
    candidates = []
    if user_path is not None:
        candidates.append((Path(user_path), "user"))
    candidates.append((Path.home() / ".portpatrol" / "knowledge_base.json", "user"))
    candidates.append((PACKAGE_KB, "package"))
    for path, source in candidates:
        entries = _load_json_entries(path)
        if entries:
            return ({e["port"]: e for e in entries}, {
                "source": source,
                "path": str(path),
                "entries": len(entries),
                "repaired": sum(e.get(RISK_REPAIRED_KEY, False) for e in entries),
            })
    print("portpatrol: knowledge base not found or invalid; using built-in defaults", file=sys.stderr)
    return ({e["port"]: e for e in DEFAULT_ENTRIES}, {
        "source": "defaults",
        "path": None,
        "entries": len(DEFAULT_ENTRIES),
        "repaired": 0,
    })


def load_knowledge_base(user_path=None):
    entries, _ = load_knowledge_base_with_source(user_path)
    return entries
```

- [ ] **Step 4: Add repaired-count tests**

Use a temporary file with one invalid risk and one missing risk. Assert `repaired == 2`, both entries are still loaded, and the existing warnings still reach stderr. Keep the explicit-`unknown` test from the provenance work.

- [ ] **Step 5: Run knowledge tests and verify they pass**

Run: `python3 -m pytest tests/test_knowledge.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add portpatrol/knowledge.py tests/test_knowledge.py
git commit -m "feat: report knowledge-base source metadata"
```

### Task 2: Embed metadata in scan and explain output

**Files:**
- Modify: `portpatrol/cli.py:71-135, 238-249`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes `knowledge.load_knowledge_base_with_source()`.
- Normal JSON result gains the four `knowledge_base_*` top-level fields.
- `explain` prints `Knowledge base: <source> (<path>)` for file sources and `Knowledge base: defaults` for built-in entries.

- [ ] **Step 1: Write failing CLI tests**

Add a JSON scan test that patches the metadata loader and asserts the four fields. Add explain tests for a user source with a known port and a source line for an unknown port:

```python
def test_scan_json_includes_knowledge_base_metadata(monkeypatch, tmp_path, capsys):
    _patch_scan(monkeypatch, tmp_path, [22])
    cli.main(["scan", "--no-notify", "--json", "--ports", "22"])
    out = json.loads(capsys.readouterr().out)
    assert out["knowledge_base_source"] == "package"
    assert out["knowledge_base_path"] == str(knowledge.PACKAGE_KB)
    assert out["knowledge_base_entries"] > 0
    assert out["knowledge_base_repaired"] == 0


def test_explain_reports_knowledge_base_source(monkeypatch, capsys, tmp_path):
    path = _write_user_kb(tmp_path, 22, "info")
    monkeypatch.setattr("portpatrol.cli.knowledge.load_knowledge_base_with_source",
                        lambda user_path=None: ({22: _entry(22, "info")},
                        {"source": "user", "path": str(path), "entries": 1, "repaired": 0}))
    assert cli.main(["explain", "22"]) == 0
    out = capsys.readouterr().out
    assert f"Knowledge base: user ({path})" in out
```

Use a minimal entry helper with the keys required by `cmd_explain`.

- [ ] **Step 2: Run the new tests and verify they fail**

Run: `python3 -m pytest tests/test_cli.py -k 'knowledge_base_metadata or explain_reports' -q`

Expected: FAIL because `run_scan` and `cmd_explain` do not yet use the metadata loader or print the source.

- [ ] **Step 3: Wire metadata into `run_scan`**

Replace the single loader call with:

```python
kb, kb_meta = knowledge.load_knowledge_base_with_source()
svc_index = knowledge.service_index(kb)
```

Add these keys to `result` before returning `ScanOutcome`:

```python
"knowledge_base_source": kb_meta["source"],
"knowledge_base_path": kb_meta["path"],
"knowledge_base_entries": kb_meta["entries"],
"knowledge_base_repaired": kb_meta["repaired"],
```

Keep raw mode's renderer unchanged. The fields may exist in its internal result document; the raw renderer must not print them.

- [ ] **Step 4: Wire metadata into `cmd_explain`**

Use the metadata-aware loader there as well. Print the source line before the port result:

```python
kb, kb_meta = knowledge.load_knowledge_base_with_source()
source = kb_meta["source"]
path = kb_meta["path"]
if path:
    print(f"Knowledge base: {source} ({path})")
else:
    print(f"Knowledge base: {source}")
```

Keep the existing no-entry, advice, and KEV-hint output and exit code.

- [ ] **Step 5: Run CLI tests and verify they pass**

Run: `python3 -m pytest tests/test_cli.py -q`

Expected: PASS with existing scan, watch, diff, raw, and explain tests unchanged apart from the new source line assertions.

- [ ] **Step 6: Commit**

```bash
git add portpatrol/cli.py tests/test_cli.py
git commit -m "feat: show knowledge-base source in output"
```

### Task 3: Document and verify metadata

**Files:**
- Modify: `README.md:165-220`
- Test: `tests/test_knowledge.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Documents the four JSON metadata fields, source values, and `explain` output.
- Confirms the metadata is not written to the diff baseline.

- [ ] **Step 1: Add a baseline regression test**

Assert that `run_scan(... --diff)` writes a state file whose `open` entry keys remain exactly `{"port", "service", "version", "risk"}`. This protects the metadata from leaking into the slim baseline.

- [ ] **Step 2: Run the baseline test and verify it passes or fails for the expected missing behavior**

Run: `python3 -m pytest tests/test_cli.py -k 'diff_state' -q`

Expected: PASS after the loader wiring; if it fails, fix the state key construction before documentation.

- [ ] **Step 3: Update README**

Add the four fields to the JSON example and explain that `user` means the home override, `package` means the shipped file, and `defaults` means the built-in fallback. Add the `explain` source line and state that the count of repaired entries is a data-quality warning, not a vulnerability result.

- [ ] **Step 4: Run complete verification**

Run: `python3 -m pytest -q`

Run: `python3 -m compileall -q portpatrol tests`

Run: `if command -v mypy >/dev/null 2>&1; then mypy portpatrol; else python3 -m mypy portpatrol; fi`

Run: `git diff --check`

Expected: all tests pass, compile and typecheck succeed, and the diff has no whitespace errors.

- [ ] **Step 5: Commit**

```bash
git add README.md tests/test_knowledge.py tests/test_cli.py
git commit -m "docs: describe knowledge-base metadata"
```

## Final verification

- [ ] `git status --short` is clean after the final commit.
- [ ] Normal JSON output contains all four metadata fields.
- [ ] `explain` names the source for known and unknown ports.
- [ ] Existing loader callers still receive a dictionary.
- [ ] Diff state keys are unchanged.
