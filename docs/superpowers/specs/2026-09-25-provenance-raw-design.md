# Finding provenance and raw output

**Date:** 2026-09-25
**Status:** approved for implementation

## Goal

Make the gap between observed port state and risk interpretation visible. A scan should tell the user which ports are open, how the service was identified, and why a risk label was assigned. The report must remain useful when the knowledge base has no matching entry.

The design follows the distinction used by Nmap between port state and service-version enrichment. PortPatrol will keep the observed finding as the base data and attach interpretation metadata to it.

## Scope

This pass adds two capabilities:

- Finding provenance: each interpreted finding records the source of its risk and a confidence label.
- Raw output: `scan --raw` prints observed evidence without applying the risk model.

The pass also adds real-host integration coverage for a loopback listener and the operating-system listener table when available. It does not add remote scanning, exploit checks, automatic vulnerability scanning, or a new risk database.

## Result schema

Each finding gains these fields:

- `risk_source`: `port_rule`, `service_rule`, `exposure_adjusted`, or `fallback`.
- `confidence`: `high`, `medium`, or `low`.

`risk_source` identifies the rule path used for the final risk. `port_rule` means the port had a knowledge-base entry. `service_rule` means the port had no entry but the detected service matched a known service. `exposure_adjusted` means the rule matched and the loopback downgrade changed the final value. `fallback` means no rule matched and the final risk is `unknown`.

Confidence is deliberately simple:

- `high`: port rule or service rule, before exposure adjustment.
- `medium`: a rule was adjusted for loopback exposure.
- `low`: no matching rule was found.

The fields are part of JSON output and persisted history. The normal console table gets a compact `SOURCE` column. This preserves the existing columns while making the interpretation visible in the primary report.

## Raw output

Add `scan --raw`. Raw output uses the same scan pipeline and writes one line per open port, for example:

```text
port=18083 service=unknown version=- product=- exposure=loopback pid=123 process=test-server
```

The raw report contains only observed and collected fields:

- port
- detected service and version
- nmap product, when available
- listener exposure
- process and PID, when the OS exposes them

It omits risk, confidence, risk source, CVEs, and the knowledge-base recommendation. `scan --raw` does not write a diff baseline or history record, because it is an observation view rather than a normal scan result. The command exits with the existing convention: `0` for no open ports, `1` for findings, and `2` for an error.

`watch` does not gain a raw mode. Its output is already change-oriented, and a raw line on every cycle would make the alert stream noisy.

## Data flow

`run_scan` continues to build the interpreted finding list. After service and listener enrichment, it calls a small classification helper that returns the risk, source, and confidence together. Exposure adjustment is applied inside that helper so the source and confidence describe the final result.

JSON and history receive the augmented findings. `console_table` reads `risk_source` with a safe fallback for old test fixtures and hand-built findings. `cmd_scan --raw` renders the observed fields before normal table or JSON output, and skips history/diff side effects for that invocation.

The knowledge-base loading behavior remains unchanged. A user override can still replace the packaged data, which is why the source fields are needed: a result no longer looks authoritative without showing which rule path was used.

## Error handling

Missing `nmap` or listener data does not make raw output fail. Missing enrichment fields are printed as `-`, while the open-port observation remains available. A malformed knowledge-base entry keeps the existing `unknown` fallback. Raw output follows the existing scan exception and exit-code paths.

## Tests

Unit tests will cover:

- port-rule provenance and high confidence;
- service-rule provenance for a port absent from the knowledge base;
- exposure-adjusted provenance and medium confidence;
- low-confidence fallback;
- raw rendering with and without listener/nmap data;
- raw output side-effect behavior;
- console-table source display and compatibility with older hand-built findings.

Integration tests will bind a real ephemeral loopback listener, run the scan pipeline, and assert that the port appears with loopback exposure when `ss` is available. Tests skip only when the host cannot provide the relevant OS command. The existing mocked subprocess and filesystem tests remain the fast contract for the rest of the suite.

## Acceptance criteria

- A normal scan identifies the source of every risk value in JSON and the table.
- A finding with no matching rule says so through `fallback`, `unknown`, and `low` confidence.
- `scan --raw` shows collected evidence without displaying risk or recommendation text.
- Real loopback listener coverage runs on supported Linux hosts and reports a clear skip on unsupported hosts.
- Existing scan, diff, watch, notification, history, and exit-code behavior remains unchanged when `--raw` is absent.
