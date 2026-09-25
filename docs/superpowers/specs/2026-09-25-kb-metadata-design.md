# Knowledge-base source metadata

**Date:** 2026-09-25
**Status:** approved for implementation

## Goal

Make it clear which knowledge base supplied a rating. A user override, the packaged file, and the built-in fallback have different levels of authority, and a report should say which one was used.

This is metadata about PortPatrol's own data. It does not claim that a rating is verified, current, or complete.

## Behavior

Add a second loader that returns both entries and metadata:

```python
load_knowledge_base_with_source(user_path=None) -> (dict, dict)
```

Keep `load_knowledge_base(user_path=None) -> dict` as the compatibility wrapper. Internal callers that need metadata use the new function, so the knowledge base is read once per command.

The metadata contains:

- `source`: `user`, `package`, or `defaults`.
- `path`: the selected file path for `user` and `package`, or `None` for built-in defaults.
- `entries`: the number of loaded entries.
- `repaired`: the number of entries whose missing or invalid risk value was changed to `unknown`.

The metadata is embedded at the top level of normal JSON scan results as:

- `knowledge_base_source`
- `knowledge_base_path`
- `knowledge_base_entries`
- `knowledge_base_repaired`

`scan --raw` does not print risk interpretation, so it does not print these fields. The result object may still contain them for internal consistency, but the raw renderer will ignore them.

`portpatrol explain PORT` prints the source and path on a dedicated line. When the port has no entry, the source line is still printed so the user knows which data set was searched.

## Source resolution

Resolution keeps the existing order and fallback behavior:

1. explicit `user_path`, used by tests and callers that provide a file;
2. `~/.portpatrol/knowledge_base.json`;
3. the packaged `portpatrol/knowledge_base.json`;
4. `DEFAULT_ENTRIES` from `defaults.py`.

A file that parses but contains no usable entries does not win resolution. A valid file with one repaired entry still wins; the repaired count records that problem instead of silently treating the file as authoritative.

The default fallback prints the existing warning to stderr. No new warning is added for a normal user or package source.

## Implementation boundaries

- `knowledge.py` owns resolution, metadata, and the compatibility wrapper.
- `cli.py` calls the metadata-aware loader and adds the four top-level fields to the result document.
- `cmd_explain` calls the metadata-aware loader and prints the source line.
- `diff.save_state` continues storing only its existing slim fields. The new metadata belongs to the full result and history document, not the change baseline.
- The console table and raw renderer do not change.

## Tests

Add unit tests for:

- each source type and its path;
- the existing `load_knowledge_base` return type;
- repaired-entry counts for missing and invalid risk values;
- metadata in a normal JSON scan result;
- source output from `explain` for known and unknown ports;
- no regression in diff state keys or existing result fields.

The tests will use temporary user files and `capsys`; they will not depend on the developer's home directory.

## Acceptance criteria

- A normal JSON scan states which knowledge base supplied its ratings.
- `explain` identifies that source and path.
- Repaired user data is visible through the `knowledge_base_repaired` count.
- Existing callers that expect a dictionary from `load_knowledge_base` continue to work.
- Raw output, diff baselines, notifications, and exit codes keep their current behavior.
- The README describes the metadata without presenting it as independent threat intelligence.
