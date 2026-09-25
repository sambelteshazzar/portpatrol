"""Command line interface: scan and explain commands."""

from __future__ import annotations

import argparse
import sys
import time
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

from portpatrol import diff, knowledge, listeners, scanner
from portpatrol.defaults import TOP_PORTS
from portpatrol.notifier import notify, summary_message
from portpatrol.report import append_history, console_table, to_json

HISTORY_PATH = Path.home() / ".portpatrol" / "history.json"
STATE_PATH = Path.home() / ".portpatrol" / "state.json"
ALLOWLIST_PATH = Path.home() / ".portpatrol" / "allowlist.json"

ScanOutcome = namedtuple("ScanOutcome", ("exit_code", "result", "changes", "baseline"))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="portpatrol",
        description="Scan this machine for open ports and classify the risk.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan localhost and report open ports")
    scan.add_argument("--ports", default="top1000",
                      help="top50 | top100 | top1000 | all | 80,443 | 8000-8100")
    scan.add_argument("--json", action="store_true", help="machine-readable output on stdout")
    scan.add_argument("--kev", action="store_true", help="cross-reference CISA KEV catalog")
    scan.add_argument("--no-notify", action="store_true", help="suppress desktop notifications")
    scan.add_argument("--verbose", action="store_true", help="log skipped enrichments and probe failures")
    scan.add_argument("--diff", action="store_true",
                      help="compare with the last scan; alert only on changes")
    scan.set_defaults(func=cmd_scan)

    watch = sub.add_parser("watch", help="continuously scan and alert only on changes")
    watch.add_argument("--interval", type=int, default=60,
                       help="seconds between scans (default 60, min 1)")
    watch.add_argument("--ports", default="top1000",
                       help="top50 | top100 | top1000 | all | 80,443 | 8000-8100")
    watch.add_argument("--kev", action="store_true",
                       help="cross-reference CISA KEV catalog")
    watch.add_argument("--no-notify", action="store_true",
                       help="suppress desktop notifications")
    watch.add_argument("--verbose", action="store_true",
                       help="log one status line per cycle to stderr")
    watch.set_defaults(func=cmd_watch)

    explain = sub.add_parser("explain", help="print the knowledge base entry for a port")
    explain.add_argument("port", type=int)
    explain.set_defaults(func=cmd_explain)
    return parser


def run_scan(args):
    """Run one full scan pipeline. No table/JSON print, no notify, no history."""
    try:
        ports = knowledge.parse_port_spec(args.ports, TOP_PORTS)
    except ValueError as exc:
        print(f"portpatrol: {exc}", file=sys.stderr)
        return ScanOutcome(2, None, None, False)

    kb = knowledge.load_knowledge_base()
    svc_index = knowledge.service_index(kb)

    open_ports = scanner.sweep(ports)
    if args.verbose:
        print(f"portpatrol: {len(open_ports)} open of {len(ports)} scanned", file=sys.stderr)

    findings = [scanner.identify(p, knowledge.get_entry(kb, p), svc_index) for p in open_ports]

    services = scanner.enrich_with_nmap(open_ports)
    if args.verbose and open_ports and not services:
        print("portpatrol: nmap not found; socket probes only", file=sys.stderr)
    for f in findings:
        extra = services.get(f["port"]) or {}
        if f["service"] in (None, "unknown") and extra.get("service"):
            f["service"] = extra["service"]
        if extra.get("version") and not f["version"]:
            f["version"] = extra["version"]
        if extra.get("product"):
            f["product"] = extra["product"]

    inv = listeners.collect_listeners()
    if args.verbose and findings and not inv:
        print("portpatrol: listener table unavailable (ss/netstat); "
              "no process attribution", file=sys.stderr)
    for f in findings:
        info = inv.get(f["port"]) or {}
        f["pid"] = info.get("pid")
        f["process"] = info.get("process")
        f["exposure"] = listeners.classify_exposure(info.get("bind"))
        service = f["service"] if f["service"] not in (None, "unknown") else None
        risk = knowledge.classify_port(kb, f["port"], service, svc_index)
        f["risk"] = knowledge.adjust_risk_for_exposure(risk, f["exposure"])
        f["cves"] = []

    if args.kev:
        scanner.enrich_with_kev(findings, kb, Path.home() / ".portpatrol" / "kev.json")

    changes = None
    baseline = False
    if args.diff:
        prev_state = diff.load_state(STATE_PATH)
        baseline = prev_state is None
        allow = diff.load_allowlist(ALLOWLIST_PATH)
        changes = diff.compute_changes(
            [] if prev_state is None else prev_state["open"], findings, allow)
        diff.save_state(STATE_PATH, findings)

    result = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": "127.0.0.1",
        "scanned": len(ports),
        "open": findings,
    }
    if args.diff:
        result["changes"] = changes
        result["baseline"] = baseline
    return ScanOutcome(1 if findings else 0, result, changes, baseline)


def cmd_scan(args):
    outcome = run_scan(args)
    if outcome.result is None:
        return outcome.exit_code
    findings = outcome.result["open"]

    if args.json:
        print(to_json(outcome.result))
    else:
        print(console_table(findings))

    if not args.no_notify:
        if args.diff:
            if outcome.baseline:
                notify("PortPatrol", summary_message(findings))
            elif diff.has_changes(outcome.changes):
                notify("PortPatrol", diff.changes_message(outcome.changes))
                for f in outcome.changes["new"]:
                    if f["risk"] != "critical":
                        continue
                    detail = f.get("service") or "unknown service"
                    notify(
                        f"🚨 Port {f['port']} {detail}",
                        f"Critical: newly open. Run 'portpatrol explain {f['port']}'.",
                    )
        else:
            notify("PortPatrol", summary_message(findings))
            for f in findings:
                if f["risk"] != "critical":
                    continue
                detail = f.get("service") or "unknown service"
                cves = ", ".join(f.get("cves", []))
                suffix = f" ({cves})" if cves else ""
                notify(
                    f"🚨 Port {f['port']} {detail}",
                    f"Critical: open and exploitable{suffix}. Run 'portpatrol explain {f['port']}'.",
                )

    append_history(outcome.result, HISTORY_PATH)
    return outcome.exit_code


def cmd_watch(args):
    if args.interval < 1:
        print("portpatrol: --interval must be >= 1", file=sys.stderr)
        return 2
    try:
        knowledge.parse_port_spec(args.ports, TOP_PORTS)
    except ValueError as exc:
        print(f"portpatrol: {exc}", file=sys.stderr)
        return 2

    args.diff = True
    cycle = 0
    try:
        while True:
            cycle += 1
            try:
                outcome = run_scan(args)
            except Exception as exc:
                print(f"portpatrol: {exc}", file=sys.stderr)
                return 2
            if outcome.result is None:
                return outcome.exit_code
            if outcome.baseline:
                if not args.no_notify:
                    notify("PortPatrol", summary_message(outcome.result["open"]))
            elif outcome.changes and diff.has_changes(outcome.changes):
                msg = diff.changes_message(outcome.changes)
                print(msg)
                if not args.no_notify:
                    notify("PortPatrol", msg)
                    for f in outcome.changes["new"]:
                        if f["risk"] != "critical":
                            continue
                        detail = f.get("service") or "unknown service"
                        notify(
                            f"🚨 Port {f['port']} {detail}",
                            f"Critical: newly open. Run 'portpatrol explain {f['port']}'.",
                        )
                append_history(outcome.result, HISTORY_PATH)
            if args.verbose:
                n_ch = (len(outcome.changes["new"])
                        + len(outcome.changes["removed"])
                        + len(outcome.changes["changed"])) if outcome.changes else 0
                print(f"portpatrol: cycle {cycle} "
                      f"open={len(outcome.result['open'])} changes={n_ch}",
                      file=sys.stderr)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


def cmd_explain(args):
    kb = knowledge.load_knowledge_base()
    entry = knowledge.get_entry(kb, args.port)
    if entry is None:
        print(f"No knowledge base entry for port {args.port}.")
        print("Risk: unknown — not a well-known port. Verify manually what listens on it.")
        return 0
    print(f"Port {entry['port']}/tcp — {entry['service']} — risk: {entry['risk']}")
    print(f"Advice: {entry['advice']}")
    if entry.get("kev_hints"):
        print("KEV hints: " + ", ".join(entry["kev_hints"]))
    return 0


def apply_bare_defaults(args):
    """Fill scan defaults when no subcommand was given, so bare runs scan."""
    if args.command is None:
        args.func = cmd_scan
        args.ports = "top1000"
        args.json = False
        args.kev = False
        args.no_notify = False
        args.verbose = False
        args.diff = False
    return args


def main(argv=None):
    args = apply_bare_defaults(build_parser().parse_args(argv))
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 2
